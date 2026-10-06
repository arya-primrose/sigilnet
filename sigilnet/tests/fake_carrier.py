"""An in-memory Carrier for tests: proves the protocol layer has no hidden Tor dependency and that the carrier contract (carrier.py) is implementable by something else.

Doors live in a shared FakeNet; every door forwards to a loopback port on which the PROTOCOL layer runs its guarded TcpServer (exactly as with Tor), and `dial` returns a
plain TcpTransport to that port after the carrier's own admission check (credential held for a client-authorized door, nothing for a public one). No tor, no network."""
from __future__ import annotations

import hashlib
import os
import re
import socket
import threading

from sigilnet import carrier as C
from sigilnet.carrier import Carrier, CarrierError, Secret, check_credential
from sigilnet.keys import AGENT_ID_RE
from sigilnet.tcp import TcpTransport

NAME_RE = re.compile(r"[a-z0-9_-]{1,32}")
ADDR_RE = re.compile(r"[a-z0-9_-]{1,70}\.fake:[1-9][0-9]{0,4}")
ADDR_RE_B = re.compile(r"[a-z0-9_-]{1,70}\.fakeb:[1-9][0-9]{0,4}")
KEY_RE = re.compile(r"[0-9a-f]{64}")


def _check_addr(a: str) -> str:
    a = (a or "").strip().lower()
    if not ADDR_RE.fullmatch(a):
        raise ValueError("a fake endpoint is '<name>.fake:<port>'")
    return a


def _check_addr_b(a: str) -> str:
    a = (a or "").strip().lower()
    if not ADDR_RE_B.fullmatch(a):
        raise ValueError("a fakeb endpoint is '<name>.fakeb:<port>'")
    return a


def _check_key(k: str) -> str:
    k = (k or "").strip().lower()
    if not KEY_RE.fullmatch(k):
        raise ValueError("a fake credential key is 64 hex characters")
    return k


C.register_type("fake", check_addr=_check_addr, check_key=_check_key)
C.register_type("fakeb", check_addr=_check_addr_b, check_key=_check_key)       # a SECOND carrier type, so one node can run two carriers in a test


def _public_of(secret_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(secret_key)).hexdigest()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class FakeNet:
    def __init__(self):
        self.doors: dict = {}                      # addr -> {"port", "kind", "auth" (public key hex or None), "agent"}
        self.mu = threading.Lock()


class FakeCarrier(Carrier):
    type = "fake"
    suffix = ".fake"
    capabilities = frozenset()

    def __init__(self, net: FakeNet, name: str):
        if not NAME_RE.fullmatch(name):
            raise ValueError("bad carrier name")
        self.net, self.name, self.up = net, name, False
        self._doors: dict = {}                     # door name -> {"kind", "agent", "port", "addr", "auth"}
        self._held: dict = {}                      # addr -> Secret we hold for THEIR door
        self._held_agent: dict = {}                # node id -> Secret we hold for THEIR door (DESIGN_locator_book.md: survives their address changing)
        self.retry_wait = 0.0

    # -- lifecycle
    def start(self, wait: bool = True) -> None:
        self.up = True

    def stop(self) -> None:
        self.up = False

    def healthy(self) -> bool:
        return self.up

    def reconfigure(self) -> bool:
        return False

    # -- reaching others
    def dial(self, endpoint: dict, *, timeout: float, connect_timeout: float | None = None, agent: str | None = None):
        try:
            ep = C.check_endpoint(endpoint)
        except ValueError as e:
            raise CarrierError(str(e), retry=False) from None
        if ep["type"] != self.type:
            raise CarrierError(f"this carrier only dials {self.type} endpoints", retry=False)
        with self.net.mu:
            door = self.net.doors.get(ep["addr"])
        if door is None:
            raise CarrierError("no such door (offline or never created)", retry=True)
        if door["auth"] is not None:
            held = (self._held_agent.get(agent) if agent else None) or self._held.get(ep["addr"])
            if held is None:
                raise CarrierError("the door needs authentication (no credential held)", retry=False)
            if _public_of(held["key"]) != door["auth"]:
                raise CarrierError("our credential is not authorized on that door", retry=False)
        return TcpTransport("127.0.0.1", door["port"], None, timeout, connect_timeout)

    def new_credential(self) -> tuple:
        k = os.urandom(32).hex()
        return Secret({"type": self.type, "key": k}), {"type": self.type, "key": _public_of(k)}

    def use_credential(self, endpoint: dict, secret, agent: str | None = None) -> None:
        ep = C.check_endpoint(endpoint)
        self._held[ep["addr"]] = check_credential(secret, secret=True)
        if agent is not None:
            self._held_agent[agent] = self._held[ep["addr"]]

    def drop_credential(self, endpoint: dict, agent: str | None = None) -> bool:
        gone = self._held.pop(C.check_endpoint(endpoint)["addr"], None) is not None
        if agent is not None and self._held_agent.pop(agent, None) is not None:
            gone = True
        return gone

    def move_door(self, name: str, new_addr: str) -> str:
        """Test helper: the door `name` now lives at `new_addr` (its old address stops answering): what a changed IP does."""
        d = self._doors[name]
        new_addr = _check_addr(new_addr)
        with self.net.mu:
            self.net.doors.pop(d["addr"], None)
            self.net.doors[new_addr] = {"port": d["port"], "kind": d["kind"], "auth": d["auth"], "agent": d["agent"]}
        d["addr"] = new_addr
        return new_addr

    # -- being reached
    def open_door(self, name: str, kind: str, *, credential: dict | None = None, agent: str | None = None) -> int:
        if not NAME_RE.fullmatch(name or ""):
            raise ValueError("name: 1-32 characters of a-z 0-9 _ -")
        if kind not in C.KINDS:
            raise ValueError("unknown door kind")
        if kind in C.PUBLIC_KINDS:
            if credential is not None or agent is not None:
                raise ValueError("a public door takes no credential and no agent")
            auth = None
        else:
            if credential is None:
                raise ValueError("a client-authorized door needs the public credential of its client")
            auth = check_credential(credential)["key"]
            if agent is not None and (kind != "peer" or not AGENT_ID_RE.fullmatch(agent)):
                raise ValueError("bad agent id")
        d = self._doors.get(name)
        if d is not None and d["kind"] != kind:
            raise ValueError(f"{name!r} is a {d['kind']} door; it cannot become a {kind} door (remove it first)")
        if d is None:
            d = self._doors[name] = {"kind": kind, "agent": agent, "port": _free_port(), "addr": f"{self.name}-{name}{self.suffix}:1"[:75], "auth": auth}
        d["auth"], d["agent"] = auth, agent if agent is not None else d["agent"]
        with self.net.mu:
            self.net.doors[d["addr"]] = {"port": d["port"], "kind": kind, "auth": auth, "agent": d["agent"]}
        return d["port"]

    def close_door(self, name: str) -> bool:
        d = self._doors.pop(name, None)
        if d is None:
            return False
        with self.net.mu:
            self.net.doors.pop(d["addr"], None)
        return True

    def door_endpoint(self, name: str) -> dict | None:
        d = self._doors.get(name)
        return None if d is None else {"type": self.type, "addr": d["addr"]}

    def doors(self) -> dict:
        return {n: {"kind": d["kind"], "agent": d["agent"], "port": d["port"]} for n, d in self._doors.items()}

    def door_gone(self, name: str) -> bool:
        return name not in self._doors and f"{self.name}-{name}{self.suffix}:1"[:75] not in self.net.doors

    def blackhole(self, on: bool = True) -> None:
        """Test helper: every door of this carrier stops answering (on) / answers again (off): what an unreachable carrier looks like to the dialing side."""
        with self.net.mu:
            for d in self._doors.values():
                if on:
                    self.net.doors.pop(d["addr"], None)
                else:
                    self.net.doors[d["addr"]] = {"port": d["port"], "kind": d["kind"], "auth": d["auth"], "agent": d["agent"]}


class FakeCarrierB(FakeCarrier):
    type = "fakeb"
    suffix = ".fakeb"
