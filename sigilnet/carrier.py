"""The Carrier seam (Round B): the ONLY thing the protocol layer knows about how bytes reach another agent. Tor is the one implementation (torlink.TorCarrier).

The protocol (events, threads, envelopes, sync, capsule logic, guest/public doors) speaks in four carrier-neutral words:
  * ENDPOINT   {"type": "onion", "addr": "<56>.onion:47200"}   where an agent can be dialed. Same shape as the signed `endpoint` event of thread.py
               (type <= 16 chars, addr <= 256). The carrier that owns a `type` parses and validates its `addr`.
  * DOOR       a named entry point WE offer, with a kind (peer / read / inbox / join / knock, carrier.KINDS): the protocol decides what answers it, the carrier decides how
               it is reached. Every door forwards to a loopback TCP port on which the PROTOCOL layer runs its own guarded server (tcp.py): framing, MAX_REQ/MAX_RESP,
               deadlines and connection caps are NOT carrier business (one guard for every carrier).
  * CREDENTIAL a typed, opaque key: PUBLIC ({"type","key"}: lets its holder reach a door of ours) or SECRET (`Secret`: lets US reach a door of theirs; never printed).
  * TRANSPORT  what `dial` returns: an object with request(req) -> resp (tcp.TcpTransport and friends).
Rules that split local config from the signed network: LOCAL data (peers.json, joins.json, capsules, the join door) refuses an endpoint or credential `type` no carrier
here supports, with a clear error; a signed `endpoint` EVENT keeps accepting unknown types (they are stored, relayed and skipped by dial selection), because refusing
an event when a future carrier appears would split the network.

COMPOSITION ROOT: `noderun.py` (and cli.py, which reaches the Tor carrier only through noderun's lazy `from . import noderun`) is the only protocol-side code that names the Tor
carrier; no other module may import `torlink` (tests/test_carrier_wiring.py scans for every spelling of that import).

A carrier MUST (all checkable, see tests/test_carrier.py): forward a door ONLY to the loopback port open_door returned; never answer a request itself; apply its own
per-door stream cap (Tor: HiddenServiceMaxStreams); let an unauthorized client reach nothing; make a closed or re-keyed door unreachable to the old key; keep
secret material out of every log and repr. The size / deadline / garbage rules (tcp.MAX_REQ, MAX_RESP, header deadline, concurrency cap, no answer to garbage) are the
PROTOCOL's guard (tcp.TcpServer) in front of the loopback port; a carrier is a pipe to it and never needs to re-implement them."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

TYPE_MAX = 16
ADDR_MAX = 256
TYPE_RE = re.compile(r"[a-z0-9_-]{1,16}")
NAME_RE = re.compile(r"[a-z0-9_-]{1,32}")                 # a door name
KINDS = ("peer", "read", "inbox", "join", "knock")
PUBLIC_KINDS = ("read", "inbox", "knock")


class CarrierError(Exception):
    """A carrier-level failure; `retry` says whether trying again later can help (an unauthorized client cannot fix itself by waiting)."""

    def __init__(self, msg: str, retry: bool = True):
        super().__init__(msg)
        self.retry = retry


class NoCarrierUp(CarrierError):
    """Every carrier that could reach the peer is down right now (M1c: a node with several carriers keeps running while one is down). It is NOT a failure of the peer: the node does not put the
    peer into its unreachable backoff for it, the job just waits a few seconds."""

    def __init__(self, msg: str = "no carrier is up"):
        super().__init__(msg, retry=True)


class Secret(dict):
    """A SECRET credential. It is a dict (so it can be stored in 0600 files on purpose via dict(secret)) whose repr/str never show the key."""

    def __repr__(self) -> str:
        return f"<secret {self.get('type', '?')} credential>"

    __str__ = __repr__


# ---------------------------------------------------------------- type registry (a carrier module registers the types it owns)
_ENDPOINT_TYPES: dict = {}       # type -> check(addr: str) -> normalized addr (raises ValueError)
_CREDENTIAL_TYPES: dict = {}     # type -> check(key: str) -> normalized key (raises ValueError)


def register_type(name: str, *, check_addr, check_key) -> None:
    if not TYPE_RE.fullmatch(name):
        raise ValueError("bad type name")
    _ENDPOINT_TYPES[name] = check_addr
    _CREDENTIAL_TYPES[name] = check_key


def supported_types() -> list:
    return sorted(_ENDPOINT_TYPES)


def check_endpoint(e, *, strict: bool = True) -> dict:
    """Validate an endpoint {"type", "addr"} and return it normalized. strict=True (LOCAL config, capsules): the type must be one we carry. strict=False
    (signed endpoint events): shape only, an unknown type is fine."""
    if not isinstance(e, dict) or set(e) != {"type", "addr"}:
        raise ValueError("an endpoint is exactly {type, addr}")
    t, a = e["type"], e["addr"]
    if not isinstance(t, str) or not TYPE_RE.fullmatch(t):
        raise ValueError("bad endpoint type")
    if not isinstance(a, str) or not a or len(a) > ADDR_MAX or any(ord(c) < 32 or ord(c) == 127 for c in a):
        raise ValueError("bad endpoint address")
    check = _ENDPOINT_TYPES.get(t)
    if check is None:
        if strict:
            raise ValueError(f"unsupported endpoint type {t!r} (supported here: {', '.join(supported_types()) or 'none'})")
        return {"type": t, "addr": a}
    return {"type": t, "addr": check(a)}


def endpoints_of(rec) -> list:
    """Every endpoint of a peer record, one per carrier type, the primary first. THE way to read a peer's endpoints (DESIGN_multicarrier.md M1a): a record carries `endpoints`
    (a list); a record with only a single `endpoint` (an old peers.json, a test fake) reads as a list of one."""
    if not isinstance(rec, dict):
        return []
    eps = rec.get("endpoints")
    if isinstance(eps, list):
        return [e for e in eps if isinstance(e, dict)]
    ep = rec.get("endpoint")
    return [ep] if isinstance(ep, dict) else []


def endpoint_of(rec, etype: str):
    """The peer's endpoint of carrier type `etype`, or None."""
    for e in endpoints_of(rec):
        if e.get("type") == etype:
            return e
    return None


def check_credential(c, *, secret: bool = False) -> dict:
    """A credential {"type", "key"}; the key is validated by the carrier that owns the type. secret=True returns a `Secret`."""
    if not isinstance(c, dict) or set(c) != {"type", "key"}:
        raise ValueError("a credential is exactly {type, key}")
    t, k = c["type"], c["key"]
    if not isinstance(t, str) or not TYPE_RE.fullmatch(t) or t not in _CREDENTIAL_TYPES:
        raise ValueError(f"unsupported credential type {t!r}")
    if not isinstance(k, str) or len(k) > ADDR_MAX:
        raise ValueError("bad credential key")
    out = {"type": t, "key": _CREDENTIAL_TYPES[t](k)}
    return Secret(out) if secret else out


class Carrier(ABC):
    """The contract. torlink.TorNode implements it over a private tor process; tests/fake_carrier.py implements it in memory."""

    type: str = ""
    capabilities: frozenset = frozenset()          # e.g. {"hides_ip"}

    # -- lifecycle
    @abstractmethod
    def start(self, wait: bool = True) -> None: ...
    @abstractmethod
    def stop(self) -> None: ...
    @abstractmethod
    def healthy(self) -> bool: ...
    @abstractmethod
    def reconfigure(self) -> bool:
        """Apply door/credential changes made by other processes (the CLI); True if something changed."""

    # -- lifecycle without blocking (M1c: the node loop must never wait for one carrier). The defaults suit a carrier that starts and stops at once (tcp, the in-memory fake).
    def begin_start(self, *, stale: bool = True) -> None:
        """Start the carrier WITHOUT waiting for it to be usable (a restart passes stale=False). Called from the node loop's own thread (a tor child must be forked from the main thread)."""
        self.start(wait=True)

    def poll_ready(self) -> tuple:
        """One non-blocking look: ("ready", "") | ("starting", "") | ("failed", why)."""
        return ("ready", "")

    def stop_nowait(self) -> None:
        """Ask the carrier to stop and return at once; `reaped()` says when it is gone."""
        self.stop()

    def reaped(self, kill_after: float = 10.0) -> bool:
        """Is everything `stop_nowait` asked for finished? (a carrier with a process kills it once `kill_after` seconds have passed)."""
        return True

    def refresh_bind(self) -> None:
        """Before a RESTART: re-resolve whatever the carrier resolved when it was built (an address that may have changed). Default: nothing."""

    def down_reason(self) -> str:
        """Why the carrier is not healthy right now, for `status` (read when the failure is seen: a restart may truncate what this reads)."""
        return "stopped"

    # -- reaching others
    @abstractmethod
    def dial(self, endpoint: dict, *, timeout: float, connect_timeout: float | None = None, agent: str | None = None):
        """-> a transport (request(req) -> resp). Raises CarrierError(retry=...). `agent` (the peer's node id, DESIGN_locator_book.md) tells the carrier whose credential to use: it is
        looked up BY NODE ID first, so a peer whose address changed is still reachable with the key we already hold for it."""
    @abstractmethod
    def new_credential(self) -> tuple:
        """-> (Secret, public credential dict): a fresh key pair of this carrier's type."""
    @abstractmethod
    def use_credential(self, endpoint: dict, secret: Secret, agent: str | None = None) -> None:
        """Hold OUR secret for THEIR door so that we may reach it. With `agent` the secret is also held under that node id (it survives the peer's address changing)."""
    @abstractmethod
    def drop_credential(self, endpoint: dict, agent: str | None = None) -> bool: ...

    # -- locators (DESIGN_locator_book.md): addresses are transient, the node id is the identity
    retry_wait: float = 30.0                        # seconds a node waits after a dial cycle in which EVERY known address of a peer failed, before the next cycle (the first 3 retries)

    def locator_problem(self, addr: str) -> str | None:
        """Why this carrier refuses to dial an address a PEER announced (None = acceptable). Called before anything is dialed."""
        return None

    def has_credential(self, endpoint: dict, agent: str | None = None) -> bool:
        """Do we hold a credential for this peer's door at `endpoint`? Default True (a carrier that cannot tell is treated as holding one, so nothing is ever dropped for it)."""
        return True

    def rebind_credential(self, agent: str, held_endpoints, new_endpoint: dict) -> bool:
        """The peer announced `new_endpoint`: make the credential we hold for it (under any of `held_endpoints`) usable there. True if there is nothing more to do (a carrier that keeps
        credentials by node id has nothing to move)."""
        return True

    # -- being reached
    @abstractmethod
    def open_door(self, name: str, kind: str, *, credential: dict | None = None, agent: str | None = None) -> int:
        """Create (or re-key) a door. Client-authorized kinds (peer, join) need the PUBLIC credential of the one client they admit; public kinds (read, inbox) take none.
        `agent`, if given, is the only agent id the door answers. Returns the loopback port the protocol layer must serve."""
    @abstractmethod
    def close_door(self, name: str) -> bool: ...
    @abstractmethod
    def door_endpoint(self, name: str) -> dict | None:
        """The endpoint others dial for this door, or None while it has none yet."""
    @abstractmethod
    def doors(self) -> dict:
        """name -> {"kind", "agent", "port"}"""
    @abstractmethod
    def door_gone(self, name: str) -> bool:
        """True only if the door is really gone: no entry, no key material left behind (a verified teardown, used for one-time join doors)."""

    def server_limits(self, kind: str) -> dict:
        """Per-door-kind overrides for the guard (tcp.TcpServer) the PROTOCOL layer runs behind a door: {"plain_per_min": int} raises the connections-per-minute cap.
        Default {}: the Tor-sized defaults of tcp.py. A carrier may raise them ONLY for kinds whose visitors it has authenticated itself (peer, join); public kinds
        (read, inbox) keep the defaults, because there the guard is all that stands between a stranger and the handlers."""
        return {}

    def shared_endpoint(self) -> dict | None:
        return None

    def shared_port(self) -> int | None:
        """A carrier that has ONE legacy shared door (no per-peer doors) says on which loopback port the protocol layer must serve it; others: None."""
        return None


from . import onion as _onion   # noqa: E402,F401  (registers the "onion" endpoint and credential type; pure formats, no process management)
