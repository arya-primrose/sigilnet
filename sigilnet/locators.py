"""The locator book (DESIGN_locator_book.md rev 1, S1): node id -> where that node can be dialed NOW, per carrier.

The protocol knows nodes by their id (the key that signs); an address (an IP, an onion) is only where a node currently lives and may change. So:
  * `LocatorBook` (one file per carrier type, `home/locators/<type>.json`): for each peer up to MAX_LOCATORS addresses, each with when it last worked or failed, plus the address WE last
    announced to that peer. Ordered by the last good contact, a locator that failed after its last good contact goes behind the others (the human's last-good-first rule).
  * `PeerDialer`: what the node dials a peer with. It walks the peer's locators in that order and falls back to the next one AT ONCE when one fails (`FallbackTransport`); a success
    moves the locator to the top.
  * `LocatorService`: (a) tells a peer our new address (`announce`: a signed `locator` request over the carrier we already use with that peer, naming only the one door address we
    offer THAT peer: never a list, never another carrier); (b) when a peer tells us its new address, checks it and ADOPTS it only after a fresh dial there answered a signed ping from the
    peer's node id (`verify`): an address that does not pass is dropped and counted.
Nothing here decides validity of events or threads."""
from __future__ import annotations

import fcntl
import json
import os
import threading
import time
import uuid
from pathlib import Path

from . import ping as P
from .carrier import CarrierError, NoCarrierUp, check_endpoint, endpoint_of, endpoints_of
from .keys import AGENT_ID_RE

MAX_LOCATORS = 4                 # per peer per carrier: the newest verified first, the worst dropped
MAX_PEERS = 64
OK_WRITE_EVERY = 60.0            # a locator that is already first and worked is written down at most this often
LOCATOR_RETRIES = 3              # after a dial cycle in which EVERY known address of a peer failed: this many retries, `retry_wait` apart, then the node's ordinary backoff
LOCATOR_MIN_GAP = 60.0           # announcements from one peer: at most one per this many seconds
LOCATOR_FAILS = 3                # verifications that failed for one peer inside LOCATOR_FAIL_WINDOW ...
LOCATOR_FAIL_WINDOW = 3600.0
LOCATOR_BLOCK = 3600.0           # ... and its announcements are ignored for this long
VERIFY_DEADLINE = 30.0
ANNOUNCE_BACKOFF = (15.0, 30.0, 60.0, 120.0, 300.0)
MAX_ADDR = 300
CARRIER_SKIP = 120.0             # seconds a carrier that just failed for a peer is tried LAST (MultiDialer, memory only: a restart tries every carrier again)
FRESH = 900.0                    # a carrier whose last good contact (our dial or the peer reaching us) is at most this old is FRESH: among fresh carriers the NODE's own carrier order decides (tcp before tor), so a working tcp is not abandoned only because tor was used a minute later; recency decides between stale ones and between a fresh and a stale one
CARRIER_RETRY = 900.0            # a carrier the node PREFERS (earlier in its carrier order) that is behind another one is tried FIRST again once per this long per peer (else one failure would keep it unused for ever)
MAX_SKIPS = 512
NO_CREDENTIAL = "no credential for that carrier"      # M4b K2: a notify address on a carrier we hold no credential for at that peer: not dialed, not a failure, not counted towards the mute
NOTIFY_FAILS = 3                 # M4b: consecutive failed uses of a notify address drop it ...
NOTIFY_IGNORE = 3600.0           # ... and the same value, announced again, is ignored for this long (N2)
NOTIFY_MIN_GAP = 30.0            # M4b: at most one notify dial per peer per this many seconds on the notify address (a Tor-reached peer can make us dial an IPv4 it names)


def _num(x, default=None):
    if isinstance(x, bool) or not isinstance(x, (int, float)) or x != x or x in (float("inf"), float("-inf")):
        return default
    return float(x)


def _order_key(loc: dict, pos: int):
    """Sort key: a locator whose most recent attempt failed AFTER its last good contact goes behind the others; then the most recent good contact first; then the order they were added."""
    ok, fail = loc.get("ok"), loc.get("fail")
    failing = 1 if (fail is not None and (ok is None or fail > ok)) else 0
    return (failing, -(ok or 0.0), pos)


class LocatorBook:
    """`home/locators/<carrier type>.json`: {"v": 1, "peers": {agent id: {"locs": [{"addr", "ok", "fail"}], "announced": addr|None, "adopt_ts": int, "in_at": float|None}}}.
    `in_at` (M1b): when a request from that peer last arrived over THIS carrier and passed authentication (the "answer on the last-known-good carrier" rule orders carriers by it).
    `notify` (M4b): the ONE address the peer asked us to tell it about news at ({"addr", "ok", "fail", "nfail"}), apart from `locs`: it is never a pull address and never ordered with them; `ndrop`: the notify
    value we dropped after NOTIFY_FAILS failures and ignore until {"until"} (N2).
    Edited by the node (every dial) and by the CLI (`peer add/move/rm`): every change is read-modify-write under a file lock and written atomically; a damaged file reads as empty."""

    def __init__(self, path, etype: str, *, clock=time.time):
        self.path, self.etype, self.clock = Path(path), etype, clock
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._mu = threading.RLock()
        self._clean: dict = {}                                     # (agent, addr) -> when we last wrote "this one worked": the write throttle
        self._in_clean: dict = {}                                  # agent -> when we last wrote "a request of this peer arrived here": the same throttle for in_at

    # ------------------------------------------------------------ file
    def _norm(self, addr):
        try:
            return check_endpoint({"type": self.etype, "addr": addr}, strict=True)["addr"]
        except (ValueError, TypeError, AttributeError):
            return None

    def _read(self) -> dict:
        try:
            if self.path.stat().st_size > 2 * 1024 * 1024:
                return {}
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError, RecursionError):
            return {}
        peers = raw.get("peers") if isinstance(raw, dict) else None
        out = {}
        for agent, rec in (peers.items() if isinstance(peers, dict) else []):
            if len(out) >= MAX_PEERS or not (isinstance(agent, str) and AGENT_ID_RE.fullmatch(agent) and isinstance(rec, dict)):
                continue
            locs = []
            for l in rec.get("locs", []) if isinstance(rec.get("locs"), list) else []:
                if isinstance(l, dict) and isinstance(l.get("addr"), str):
                    a = self._norm(l["addr"])
                    if a is not None and all(a != x["addr"] for x in locs) and len(locs) < MAX_LOCATORS:
                        locs.append({"addr": a, "ok": _num(l.get("ok")), "fail": _num(l.get("fail"))})
            ann = rec.get("announced")
            nt, nd = rec.get("notify"), rec.get("ndrop")
            notify = None
            if isinstance(nt, dict) and isinstance(nt.get("addr"), str) and self._norm(nt["addr"]) is not None:
                nf = nt.get("nfail")
                notify = {"addr": self._norm(nt["addr"]), "ok": _num(nt.get("ok")), "fail": _num(nt.get("fail")), "nfail": nf if type(nf) is int and 0 <= nf <= NOTIFY_FAILS else 0}
            ndrop = None
            if isinstance(nd, dict) and isinstance(nd.get("addr"), str) and self._norm(nd["addr"]) is not None and _num(nd.get("until")) is not None:
                ndrop = {"addr": self._norm(nd["addr"]), "until": _num(nd.get("until"))}
            out[agent] = {"locs": locs, "announced": self._norm(ann) if isinstance(ann, str) else None,
                          "adopt_ts": int(_num(rec.get("adopt_ts"), 0) or 0), "in_at": _num(rec.get("in_at")), "notify": notify, "ndrop": ndrop}
        return out

    def _write(self, peers: dict) -> None:
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"v": 1, "peers": peers}, f, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _edit(self, fn) -> bool:
        with self._mu:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)       # (it may have been removed under a running node)
            lock = os.open(self.path.with_name(self.path.name + ".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX)
                peers = self._read()
                changed = fn(peers)
                if changed:
                    self._write(peers)
                return bool(changed)
            finally:
                os.close(lock)

    def _dirty(self, agent: str, keep=None) -> None:
        """A write for `agent` can change which of its addresses is first: the "this one was just written down" marks of the OTHERS no longer say anything (else ok A1, ok A2, ok A1 would
        skip the third write as recent while A2 still sorts first)."""
        for k in [k for k in self._clean if k[0] == agent and k != keep]:
            self._clean.pop(k, None)

    @staticmethod
    def _sort(rec: dict) -> None:
        keyed = sorted(enumerate(rec["locs"]), key=lambda t: _order_key(t[1], t[0]))
        rec["locs"] = [l for _, l in keyed]

    # ------------------------------------------------------------ reading
    def ordered(self, agent: str) -> list:
        """The peer's addresses, the one to dial first at the front."""
        with self._mu:
            rec = self._read().get(agent)
        if not rec:
            return []
        self._sort(rec)
        return [l["addr"] for l in rec["locs"]]

    def count(self, agent: str) -> int:
        with self._mu:
            rec = self._read().get(agent)
        return len(rec["locs"]) if rec else 0

    def contact(self, agent: str) -> tuple:
        """(most recent good contact in EITHER direction or None, every address failing?) for the carrier ordering (MultiDialer): `max(good_out of any address, in_at)`. An address counts as
        failing the way the dial order counts it (its last attempt failed after its last good contact); a peer that reached us over this carrier since our last failed dial is alive on it.
        A carrier with no address is empty, not failing."""
        with self._mu:
            rec = self._read().get(agent)
        if not rec:
            return None, False
        times = [l["ok"] for l in rec["locs"] if l["ok"] is not None] + ([rec["in_at"]] if rec.get("in_at") is not None else [])
        failing = bool(rec["locs"]) and all(_order_key(l, 0)[0] == 1 for l in rec["locs"])
        if failing and rec.get("in_at") is not None and rec["in_at"] > max(l["fail"] for l in rec["locs"]):
            failing = False
        return (max(times) if times else None), failing

    def last_fail(self, agent: str):
        """When the most recent failed dial to any address of this peer happened (None: none recorded)."""
        with self._mu:
            rec = self._read().get(agent)
        fails = [l["fail"] for l in rec["locs"] if l["fail"] is not None] if rec else []
        return max(fails) if fails else None

    def announced(self, agent: str):
        with self._mu:
            rec = self._read().get(agent)
        return rec["announced"] if rec else None

    def adopt_ts(self, agent: str) -> int:
        with self._mu:
            rec = self._read().get(agent)
        return rec["adopt_ts"] if rec else 0

    def agents(self) -> list:
        with self._mu:
            return list(self._read())

    def detail(self, agent: str) -> list:
        """[(addr, seconds since the last good contact or None, failing?)] in dial order (for `peer list`)."""
        with self._mu:
            rec = self._read().get(agent)
        if not rec:
            return []
        self._sort(rec)
        now = self.clock()
        return [(l["addr"], None if l["ok"] is None else max(0.0, now - l["ok"]), _order_key(l, 0)[0] == 1) for l in rec["locs"]]

    # ------------------------------------------------------------ changing
    def _put(self, peers: dict, agent: str, addr: str, *, good: bool, ts: int = 0) -> bool:
        if agent not in peers and len(peers) >= MAX_PEERS:
            return False
        rec = peers.setdefault(agent, {"locs": [], "announced": None, "adopt_ts": 0, "in_at": None})
        now = self.clock()
        for l in rec["locs"]:
            if l["addr"] == addr:
                if good:
                    l["ok"], l["fail"] = now, None
                break
        else:
            rec["locs"].append({"addr": addr, "ok": now if good else None, "fail": None})
        if ts > rec["adopt_ts"]:
            rec["adopt_ts"] = int(ts)
        self._sort(rec)
        while len(rec["locs"]) > MAX_LOCATORS:                     # the worst-ordered one goes (never the one that was just made good: it sorts first)
            rec["locs"].pop()
        return True

    def seed(self, agent: str, addr: str, *, front: bool = False) -> bool:
        """Remember an address a human or a capsule gave us. front=True (an explicit `peer add/move`) makes it the one dialed first; otherwise it only joins the list."""
        a = self._norm(addr)
        if a is None or not (isinstance(agent, str) and AGENT_ID_RE.fullmatch(agent)):
            raise ValueError("bad locator")
        if not front and a in self.ordered(agent):
            return False
        self._dirty(agent)
        return self._edit(lambda peers: self._put(peers, agent, a, good=front))

    def adopt(self, agent: str, addr: str, ts: int = 0) -> bool:
        """A VERIFIED address (a dial there answered a signed ping from `agent`): it becomes the first one."""
        a = self._norm(addr)
        if a is None:
            raise ValueError("bad locator")
        self._dirty(agent)
        return self._edit(lambda peers: self._put(peers, agent, a, good=True, ts=ts))

    def note_ok(self, agent: str, addr: str) -> None:
        now = self.clock()
        key = (agent, addr)
        last = self._clean.get(key)
        if last is not None and 0 <= now - last < OK_WRITE_EVERY:
            return                                                  # already first and written down a moment ago

        def fn(peers):
            rec = peers.get(agent)
            if not rec:
                return False
            for l in rec["locs"]:
                if l["addr"] == addr:
                    l["ok"], l["fail"] = now, None
                    self._sort(rec)
                    return True
            return False
        if self._edit(fn):
            self._dirty(agent, keep=key)
            self._clean[key] = now

    def note_fail(self, agent: str, addr: str) -> None:
        now = self.clock()
        self._dirty(agent)

        def fn(peers):
            rec = peers.get(agent)
            if not rec:
                return False
            for l in rec["locs"]:
                if l["addr"] == addr:
                    l["fail"] = now
                    self._sort(rec)
                    return True
            return False
        self._edit(fn)

    def note_inbound(self, agent: str) -> None:
        """A request of `agent` arrived over this carrier and passed authentication (called by the SyncServer): remember when. Written at most every OK_WRITE_EVERY seconds per peer; a peer
        the book does not hold yet gets a record with no address, only the contact."""
        now = self.clock()
        last = self._in_clean.get(agent)
        if last is not None and 0 <= now - last < OK_WRITE_EVERY:
            return

        def fn(peers):
            if agent not in peers and len(peers) >= MAX_PEERS:
                return False
            rec = peers.setdefault(agent, {"locs": [], "announced": None, "adopt_ts": 0, "in_at": None})
            rec["in_at"] = now
            return True
        self._edit(fn)
        self._in_clean[agent] = now                                 # (also when the book is full of other peers and wrote nothing: do not retry on every request)

    def set_announced(self, agent: str, addr: str) -> None:
        a = self._norm(addr)
        if a is None:
            return

        def fn(peers):
            if agent not in peers and len(peers) >= MAX_PEERS:
                return False
            rec = peers.setdefault(agent, {"locs": [], "announced": None, "adopt_ts": 0, "in_at": None})
            if rec["announced"] == a:
                return False
            rec["announced"] = a
            return True
        self._edit(fn)

    # ------------------------------------------------------------ the notify address (M4b)
    def notify_state(self, agent: str):
        """{"addr", "ok", "fail", "nfail"} of the peer's notify address, or None."""
        with self._mu:
            rec = self._read().get(agent)
        return dict(rec["notify"]) if rec and rec.get("notify") else None

    def notify_addr(self, agent: str):
        st = self.notify_state(agent)
        return st["addr"] if st else None

    def notify_dropped(self, agent: str, addr: str) -> bool:
        """Was exactly this notify value dropped less than NOTIFY_IGNORE ago (N2)?"""
        a = self._norm(addr)
        with self._mu:
            rec = self._read().get(agent)
        nd = rec.get("ndrop") if rec else None
        return bool(nd) and nd["addr"] == a and nd["until"] > self.clock()

    def set_notify(self, agent: str, addr: str) -> bool:
        """A VERIFIED notify address (a fresh dial there answered a signed ping from `agent`): it replaces the old one, with a clean failure count."""
        a = self._norm(addr)
        if a is None:
            raise ValueError("bad locator")

        def fn(peers):
            if agent not in peers and len(peers) >= MAX_PEERS:
                return False
            rec = peers.setdefault(agent, {"locs": [], "announced": None, "adopt_ts": 0, "in_at": None})
            cur = rec.get("notify")
            if cur and cur["addr"] == a:
                return False
            rec["notify"] = {"addr": a, "ok": None, "fail": None, "nfail": 0}
            rec["ndrop"] = None
            return True
        return self._edit(fn)

    def note_notify(self, agent: str, addr: str, ok: bool) -> bool:
        """A notify to the notify address worked or failed. True if THIS failure dropped the address (NOTIFY_FAILS in a row): it is forgotten and the same value is ignored for NOTIFY_IGNORE."""
        a, now, dropped = self._norm(addr), self.clock(), []

        def fn(peers):
            rec = peers.get(agent)
            cur = rec.get("notify") if rec else None
            if not cur or cur["addr"] != a:
                return False
            if ok:
                if cur["nfail"] == 0 and cur["ok"] is not None and 0 <= now - cur["ok"] < OK_WRITE_EVERY:
                    return False                                    # (written down a moment ago)
                cur["ok"], cur["fail"], cur["nfail"] = now, None, 0
                return True
            cur["fail"], cur["nfail"] = now, cur["nfail"] + 1
            if cur["nfail"] >= NOTIFY_FAILS:
                rec["ndrop"] = {"addr": a, "until": now + NOTIFY_IGNORE}
                rec["notify"] = None
                dropped.append(a)
            return True
        self._edit(fn)
        return bool(dropped)

    def drop_notify(self, agent: str) -> bool:
        def fn(peers):
            rec = peers.get(agent)
            if rec and rec.get("notify"):
                rec["notify"] = None
                return True
            return False
        return self._edit(fn)

    def remove(self, agent: str) -> bool:
        self._dirty(agent)
        return self._edit(lambda peers: peers.pop(agent, None) is not None)

    def drop(self, agent: str, addr: str) -> bool:
        a = self._norm(addr)
        self._dirty(agent)

        def fn(peers):
            rec = peers.get(agent)
            if not rec:
                return False
            n = len(rec["locs"])
            rec["locs"] = [l for l in rec["locs"] if l["addr"] != a]
            return len(rec["locs"]) != n
        return self._edit(fn)


def open_book(home, etype: str, *, clock=time.time) -> LocatorBook:
    return LocatorBook(Path(home) / "locators" / f"{etype}.json", etype, clock=clock)


# ------------------------------------------------------------------ dialing
class FallbackTransport:
    """`request(req) -> resp` over the peer's locators in order: the first address that answers wins and moves to the top; when one fails the next is tried AT ONCE. If every address
    failed, the first error is raised (with the number of the others), so one address behaves exactly as a plain transport did."""

    def __init__(self, dial_one, book: LocatorBook, agent: str, addrs: list):
        self.dial_one, self.book, self.agent, self.addrs = dial_one, book, agent, list(addrs)

    def _note(self, fn, addr: str) -> None:
        try:
            fn(self.agent, addr)
        except Exception:                                           # noqa: BLE001 - the book is a cache of where the peer lives: never a reason to fail a request
            pass

    def request(self, req: dict) -> dict:
        """One pull or one blob fetch makes MANY requests over ONE transport: what the first request learned (an address that does not answer goes to the end, so the one that
        answered is first) is used by the next, or every chunk would wait for the dead address again."""
        errors = []
        for addr in list(self.addrs):
            try:
                resp = self.dial_one(addr).request(req)
            except (CarrierError, OSError) as e:
                self._note(self.book.note_fail, addr)
                self.addrs.remove(addr)
                self.addrs.append(addr)
                errors.append(e)
                continue
            self._note(self.book.note_ok, addr)
            return resp                                             # (addresses that failed before this one are already at the back, so this one is first)
        if not errors:
            raise CarrierError("no address is known for this peer", retry=False)
        if len(errors) == 1:
            raise errors[0]
        retry = any(getattr(e, "retry", True) for e in errors)
        raise CarrierError(f"{errors[0]} (and {len(errors) - 1} other address(es) failed too)", retry=retry) from errors[0]


class PeerDialer:
    """What the node and the ping service dial a peer with: `dialer(rec, left=None) -> a transport`. `rec` is a peer record of the PeerBook (it carries the node id)."""

    def __init__(self, carrier, book: LocatorBook, *, request_timeout: float, connect_timeout: float):
        self.carrier, self.book = carrier, book
        self.request_timeout, self.connect_timeout = request_timeout, connect_timeout

    def addresses(self, rec: dict) -> list:
        """The addresses to dial, first one first. A peer the book knows nothing about (a home from before the locator book) gets its one endpoint from the peer record, once."""
        agent, ep = rec.get("agent"), endpoint_of(rec, self.carrier.type)
        addrs = self.book.ordered(agent) if agent else []
        if not addrs and ep:
            if agent:
                try:
                    self.book.seed(agent, ep["addr"])
                except (ValueError, OSError):
                    pass
            addrs = [ep["addr"]]
        return addrs

    def __call__(self, rec: dict, left=None):
        agent = rec.get("agent")
        rt = min(self.request_timeout, left or self.request_timeout)
        ct = min(self.connect_timeout, left or self.connect_timeout)
        addrs = self.addresses(rec)
        if not addrs:
            eps = endpoints_of(rec)
            if eps:                                                 # endpoints of other carrier types only: the carrier itself says so
                return self.carrier.dial(eps[0], timeout=rt, connect_timeout=ct, agent=agent)
            raise CarrierError("no address is known for this peer", retry=False)

        def one(addr):
            return self.carrier.dial({"type": self.carrier.type, "addr": addr}, timeout=rt, connect_timeout=ct, agent=agent)
        if len(addrs) == 1 and not agent:
            return one(addrs[0])
        return FallbackTransport(one, self.book, agent, addrs) if agent else one(addrs[0])


class MultiTransport:
    """`request(req) -> resp` over the carriers a peer can be reached on, in the MultiDialer's order: the first carrier that answers wins (and is tried first by the next request of this
    transport); a carrier that fails goes to the back and the next one is tried AT ONCE. Only when EVERY carrier failed is an error raised (the first one, with the count of the others), so
    the node's "unreachable" backoff means "no carrier worked". `via` is the carrier type of the last answer."""

    def __init__(self, md, rec: dict, order: list, left):
        self.md, self.rec, self.order, self.left = md, rec, list(order), left
        self.t0 = md.clock()
        self._tr: dict = {}
        self.via = None

    def _transport(self, ctype: str):
        tr = self._tr.get(ctype)
        if tr is None:
            remaining = None if self.left is None else max(0.1, self.left - (self.md.clock() - self.t0))
            tr = self._tr[ctype] = self.md.dialers[ctype](self.rec, remaining)
        return tr

    def request(self, req: dict) -> dict:
        agent, errors = self.rec.get("agent"), []
        for ctype in list(self.order):
            try:
                resp = self._transport(ctype).request(req)
            except (CarrierError, OSError) as e:
                self.md._failed(agent, ctype, e)
                self.order.remove(ctype)
                self.order.append(ctype)
                errors.append(e)
                continue
            self.md._worked(agent, ctype)
            self.via = ctype
            return resp
        if not errors:
            raise CarrierError("no address is known for this peer", retry=False)
        if len(errors) == 1:
            raise errors[0]
        retry = any(getattr(e, "retry", True) for e in errors)
        raise CarrierError(f"{errors[0]} (and {len(errors) - 1} other carrier(s) failed too)", retry=retry) from errors[0]


class MultiDialer:
    """What the node, the ping service and the blob worker dial a peer with when the node runs SEVERAL carriers (DESIGN_multicarrier.md M1b): `dialer(rec, left=None) -> a transport`.
    `dialers` maps a carrier type to its PeerDialer (each with its own locator book and its own connect timeout), in the node's carrier order. For a peer the carriers that hold an address
    are ordered by the most recent good contact in EITHER direction, `max(good_out, in_at)`, so a peer that just reached us over Tor is answered over Tor; a carrier whose addresses all
    failed, or that failed for this peer in the last CARRIER_SKIP seconds, goes last (the per-(peer, carrier) backoff: memory only, `Node.down` stays per PEER = every carrier failed); ties:
    the order of the peer's endpoints (the primary first), then the node's carrier order. A node with ONE carrier gets that carrier's transport itself, as before."""

    def __init__(self, dialers: dict, *, clock=time.time, log=None, usable=None):
        if not dialers:
            raise ValueError("a MultiDialer needs at least one carrier")
        self.dialers, self.clock, self.log = dict(dialers), clock, log or (lambda *a: None)
        self.usable = usable or (lambda ctype: True)                # callable(carrier type) -> is that carrier UP (M1c: a down carrier is left out of every order and every probe)
        self.books = {t: d.book for t, d in self.dialers.items()}
        self._mu = threading.Lock()                                 # the node's worker threads dial at the same time: the three tables below are touched under it
        self._skip: dict = {}                                       # (agent, carrier type) -> the time until which that carrier is tried last
        self._probed: dict = {}                                     # (agent, carrier type) -> when that carrier was last put first although it was behind (CARRIER_RETRY)
        self._said: set = set()                                     # (agent, carrier type, text) of a failure that waiting cannot fix, already logged

    # -- the combined view the Node asks (it never needs to know which carrier an address belongs to)
    def ordered(self, agent: str) -> list:
        out = []
        for t in self.dialers:
            out += self.books[t].ordered(agent)
        return out

    def count(self, agent: str) -> int:
        return sum(b.count(agent) for b in self.books.values())

    # -- ordering and bookkeeping
    def _order(self, rec: dict) -> list:
        agent, now = rec.get("agent"), self.clock()
        types = [e.get("type") for e in endpoints_of(rec)]
        keyed, behind_of, stale_of = [], {}, {}
        for i, t in enumerate(self.dialers):
            if not self.dialers[t].addresses(rec) or not self.usable(t):
                continue
            last, failing = self.books[t].contact(agent) if agent else (None, False)
            behind = behind_of[t] = failing or self._skip.get((agent, t), 0) > now
            fresh = last is not None and now - last <= FRESH
            stale_of[t] = not fresh
            keyed.append(((1 if behind else 0, 0 if fresh else 1, i if fresh else -(last or 0.0), types.index(t) if t in types else len(types), i), t))
        order = [t for _, t in sorted(keyed)]
        if len(order) > 1:                                          # a re-probe: a preferred carrier (earlier in the node's carrier order than the first one) that is BEHIND (it failed) or STALE (nothing has used it for FRESH seconds: it could never become fresh by itself) is put first once per CARRIER_RETRY after its last failure or probe; a dead one costs one connect timeout, then the failover is as always
            rank = {t: i for i, t in enumerate(self.dialers)}
            with self._mu:
                for t in order[1:]:
                    since = max(self._probed.get((agent, t), -1e18), self.books[t].last_fail(agent) or -1e18)      # (the book's own failure time: a restart does not make every failed carrier due at once)
                    if (behind_of[t] or stale_of[t]) and rank[t] < rank[order[0]] and now - since >= CARRIER_RETRY:
                        if len(self._probed) >= MAX_SKIPS:
                            self._probed = {k: v for k, v in self._probed.items() if now - v < CARRIER_RETRY}
                        self._probed[(agent, t)] = now
                        order.remove(t)
                        order.insert(0, t)
                        break
        return order

    def _failed(self, agent, ctype: str, e: Exception) -> None:
        now = self.clock()
        said = None
        with self._mu:
            if len(self._skip) >= MAX_SKIPS:
                self._skip = {k: v for k, v in self._skip.items() if v > now}
                while len(self._skip) >= MAX_SKIPS:                 # (nothing expired yet: the one that ends soonest goes)
                    self._skip.pop(min(self._skip, key=self._skip.get))
            self._skip[(agent, ctype)] = now + CARRIER_SKIP
            self._probed[(agent, ctype)] = now                      # the re-probe clock starts at a failure (never a retry right behind it)
            if getattr(e, "retry", True) is False and len(self._said) < MAX_SKIPS:
                key = (agent, ctype, str(e)[:200])
                if key not in self._said:                           # a pin mismatch or a refused credential on one carrier must not hide behind a success on the other
                    self._said.add(key)
                    said = f"carrier {ctype}: peer {str(agent)[:8]}: {str(e)[:200]}"
        if said:
            self.log(said)

    def _worked(self, agent, ctype: str) -> None:
        with self._mu:
            self._skip.pop((agent, ctype), None)

    def __call__(self, rec: dict, left=None):
        order = self._order(rec)
        if not order and len(self.dialers) > 1 and any(self.dialers[t].addresses(rec) for t in self.dialers):
            raise NoCarrierUp("no carrier is up that holds an address of this peer")      # (not a failure of the peer, and no confusing "connection refused" from a dead carrier)
        if len(self.dialers) == 1 or len(order) <= 1:
            t = order[0] if order else next(iter(self.dialers))     # one carrier (or one that knows the peer): its own transport, unchanged; none: that carrier's own error ("no address", or the refusal of another type)
            return self.dialers[t](rec, left)
        return MultiTransport(self, rec, order, left)


def route_inbound(books: dict):
    """`on_inbound` for the SyncServer: an authenticated request of a peer arrived over carrier `via`: that carrier's locator book remembers it (`in_at`). Used by noderun and the tests' rig."""
    def on_inbound(agent, via):
        book = books.get(via)
        if book is not None:
            book.note_inbound(agent)
    return on_inbound


def route_locator(locsvcs: dict, default: str, via):
    """`on_locator` for the SyncServer: an announced address belongs to the carrier the announcement ARRIVED over (`via()` is the server's carrier of the request being handled; none: the
    `default` carrier's service). A tcp address is judged by the tcp service, an onion address by the onion one."""
    def on_locator(agent, addr, ts):
        return locsvcs.get(via(), locsvcs[default]).on_locator(agent, addr, ts)
    return on_locator


class _Dead:
    """The transport of a notify address whose dial failed: its first request raises that error."""

    def __init__(self, err):
        self.err = err

    def request(self, req):
        raise self.err


class NotifyPath:
    """The transport of ONE notify to the notify address of a peer (M4b): `request` dials that address; `done(ok)` reports whether it worked (the book counts failures and drops the address
    after NOTIFY_FAILS in a row)."""

    def __init__(self, nd, tr, ctype: str, agent: str, addr: str):
        self.nd, self.tr, self.ctype, self.agent, self.addr = nd, tr, ctype, agent, addr

    def request(self, req: dict) -> dict:
        return self.tr.request(req)

    def done(self, ok: bool) -> None:
        self.nd.report(self.ctype, self.agent, self.addr, ok)


class NotifyDialer:
    """`nd(peer record) -> NotifyPath | None`: the way to tell a peer about news at the address it asked for (M4b). None = none known, or one was dialed less than NOTIFY_MIN_GAP ago (the caller
    uses the peer's pull addresses, exactly as before: the notify address only ADDS a path). Carriers that are down are left out (`usable`)."""

    def __init__(self, dialers: dict, *, clock=time.time, usable=None, log=None):
        self.dialers, self.clock, self.usable, self.log = dict(dialers), clock, usable or (lambda t: True), log or (lambda *a: None)
        self._mu = threading.Lock()
        self._last: dict = {}                                       # (agent, carrier type) -> when the notify address was last dialed

    def __call__(self, rec: dict, left=None):
        agent = rec.get("agent")
        if not agent:
            return None
        now = self.clock()
        for t, d in self.dialers.items():
            if not self.usable(t):
                continue
            addr = d.book.notify_addr(agent)
            if not addr:
                continue
            with self._mu:
                last = self._last.get((agent, t))
                if last is not None and 0 <= now - last < NOTIFY_MIN_GAP:
                    continue
                if len(self._last) >= MAX_SKIPS:
                    self._last = {k: v for k, v in self._last.items() if now - v < NOTIFY_MIN_GAP}
                self._last[(agent, t)] = now
            try:
                tr = d.carrier.dial({"type": t, "addr": addr}, timeout=min(d.request_timeout, left or d.request_timeout), connect_timeout=min(d.connect_timeout, left or d.connect_timeout), agent=agent)
            except (CarrierError, OSError, ValueError) as e:
                tr = _Dead(e)                                       # (uniform with a dial that worked and a request that fails: the caller decides what counts)
            return NotifyPath(self, tr, t, agent, addr)
        return None

    def report(self, ctype: str, agent: str, addr: str, ok: bool) -> None:
        try:
            if self.dialers[ctype].book.note_notify(agent, addr, ok):
                self.log(f"notify address of peer {str(agent)[:8]} dropped after {NOTIFY_FAILS} failures (ignored for an hour if it is announced again)")
        except Exception:                                           # noqa: BLE001 - the book is a cache: never a reason to fail a notify
            pass


def route_notify_at(locsvcs: dict):
    """`on_notify_at` for the SyncServer: the announced `notify_at` goes to the service of the carrier TYPE it names; a type this node does not run is ignored (a Tor-only node never adopts a tcp
    address: it stays anonymous)."""
    def on_notify_at(agent, field):
        t = field.get("type") if isinstance(field, dict) else None
        svc = locsvcs.get(t) if isinstance(t, str) else None
        return svc.on_notify_at(agent, field) if svc is not None else "ignored"
    return on_notify_at


# ------------------------------------------------------------------ announcing and verifying
class LocatorService:
    """Run by the node loop each round (`tick`): announces our own address to peers that do not know it yet, and verifies the addresses peers announced to us. The network work happens in
    ONE worker thread at a time (a dial takes seconds; the loop never waits for it)."""

    def __init__(self, me, peers, carrier, book: LocatorBook, dialer: PeerDialer, *, log=None, clock=time.time, stamp=time.time, sleep=time.sleep, on_adopt=None):
        self.me, self.peers, self.carrier, self.book, self.dialer = me, peers, carrier, book, dialer
        self.on_adopt = on_adopt                                    # callable(agent): a new address was adopted (the node ends the backoff its old address earned)
        self.log, self.clock, self.stamp, self.sleep = log or (lambda *a: None), clock, stamp, sleep
        self._mu = threading.Lock()
        self._pending: dict = {}                                    # agent -> (addr, request ts): one verification per peer
        self._npending: dict = {}                                   # agent -> addr: a notify address announced in a request, waiting for the SAME worker (N1)
        self._nseen: dict = {}                                      # agent -> when we last accepted a notify_at from it
        self._nlog: dict = {}                                       # (agent, addr) -> when we last said "no credential" about it (once per hour)
        self._seen: dict = {}                                       # agent -> when we last accepted an announcement from it
        self._fails: dict = {}                                      # agent -> times of failed verifications
        self._block: dict = {}                                      # agent -> announcements ignored until
        self._ann: dict = {}                                        # agent -> [next attempt time, tries] of our own announcement
        self._busy = False
        self._closed = False

    # -- receiving (called by the SyncServer, which has authenticated the request: `agent` signed it)
    def on_locator(self, agent: str, addr, ts: int) -> str:
        """-> "ok" or a short reason. Cheap and in memory: the dial happens later, in the worker. `ts` is the request's signed timestamp: it is NOT bounded here, the server's
        `_authenticate` refused anything outside SKEW of its own clock before this is called (a far-future ts would otherwise freeze `adopt_ts` and make every later announcement stale)."""
        now = self.clock()
        if agent not in self.peers.all() or agent == self.me.id:
            return "unknown"
        if not isinstance(addr, str) or len(addr) > MAX_ADDR:
            return "bad address"
        try:
            addr = check_endpoint({"type": self.carrier.type, "addr": addr}, strict=True)["addr"]
        except (ValueError, TypeError):
            return "bad address"
        with self._mu:
            if self._block.get(agent, 0) > now:
                return "ignored"
            last = self._seen.get(agent)
            if last is not None and 0 <= now - last < LOCATOR_MIN_GAP:
                return "rate limited"
            if agent in self._pending:
                return "busy"
        why = self.carrier.locator_problem(addr)
        if why:
            return "refused: " + why
        if addr in self.book.ordered(agent):
            return "ok"                                             # nothing new (no churn)
        if type(ts) is not int or ts <= self.book.adopt_ts(agent):
            return "stale"
        with self._mu:
            self._seen[agent] = now                                 # (only peers of the book get here: at most MAX_PEERS entries in any table)
            self._pending[agent] = (addr, ts)
        return "ok"

    def on_notify_at(self, agent: str, field) -> str:
        """M4b: a peer's signed `summary` / `notify` named the address it wants notifies at. Cheap and in memory, like `on_locator`: only a peer of the book, exactly {"type", "addr"} with the type
        of THIS carrier (the router picks the service by type: a carrier we do not run never gets here, so a Tor-only node cannot adopt a tcp address), a well-formed address that passes the carrier's
        own rules, not the one we already hold, not one we dropped lately (N2), at most one new value per LOCATOR_MIN_GAP. The dial that proves it happens later in the worker (N1)."""
        now = self.clock()
        if agent not in self.peers.all() or agent == self.me.id:
            return "unknown"
        if not isinstance(field, dict) or set(field) != {"type", "addr"} or field["type"] != self.carrier.type or not isinstance(field["addr"], str) or len(field["addr"]) > MAX_ADDR:
            return "bad notify_at"
        try:
            addr = check_endpoint({"type": self.carrier.type, "addr": field["addr"]}, strict=True)["addr"]
        except (ValueError, TypeError):
            return "bad address"
        with self._mu:
            if self._block.get(agent, 0) > now:
                return "ignored"
        if addr == self.book.notify_addr(agent):
            return "ok"                                             # nothing new (no churn)
        with self._mu:
            last = self._nseen.get(agent)
            if last is not None and 0 <= now - last < LOCATOR_MIN_GAP:
                return "rate limited"
            if agent in self._npending:
                return "busy"
        why = self.carrier.locator_problem(addr)
        if why:
            return "refused: " + why
        if self.book.notify_dropped(agent, addr):
            return "ignored"
        with self._mu:
            self._nseen[agent] = now
            self._npending[agent] = addr
        return "ok"

    # -- the node loop
    def tick(self) -> None:
        with self._mu:
            if self._busy or self._closed:
                return
            if not self._pending and not self._npending and not self._due():
                return
            self._busy = True
        threading.Thread(target=self._work, daemon=True, name="locators").start()

    def close(self) -> None:
        with self._mu:
            self._closed = True

    def _our_address(self, agent: str):
        """The address of the door we offer THIS peer on this carrier (None = no door bound to it)."""
        try:
            for name, d in self.carrier.doors().items():
                if d.get("kind") == "peer" and d.get("agent") == agent:
                    ep = self.carrier.door_endpoint(name)
                    return ep["addr"] if ep and ep.get("type") == self.carrier.type else None
        except (CarrierError, OSError, KeyError):
            return None
        return None

    def _due(self) -> list:
        """[(agent, our address)] for peers that have an address we can dial and have not been told our current one."""
        now = self.clock()
        out = []
        for agent, rec in self.peers.all().items():
            if agent == self.me.id:
                continue
            if endpoint_of(rec, self.carrier.type) is None and not self.book.count(agent):
                continue                                            # no address of this carrier's type for the peer: nothing to announce over
            addr = self._our_address(agent)
            if addr is None or self.book.announced(agent) == addr:
                continue
            if self._ann.get(agent, [0.0, 0])[0] > now:
                continue
            out.append((agent, addr))
        return out

    def _work(self) -> None:
        try:
            while True:
                with self._mu:
                    if self._closed:
                        return
                    item = next(iter(self._pending.items()), None)
                    if item is not None:
                        del self._pending[item[0]]
                    nitem = None if item is not None else next(iter(self._npending.items()), None)
                    if nitem is not None:
                        del self._npending[nitem[0]]
                if item is not None:
                    self._verify(item[0], item[1][0], item[1][1])
                elif nitem is not None:
                    self._verify(nitem[0], nitem[1], 0, notify=True)
                else:
                    break
            for agent, addr in self._due():
                with self._mu:
                    if self._closed:
                        return
                self._announce(agent, addr)
        except Exception as e:                                      # noqa: BLE001 - housekeeping must never take the node down
            self.log(f"locator service: {type(e).__name__}")
        finally:
            with self._mu:
                self._busy = False

    # -- verifying an address a peer announced
    def verify(self, agent: str, addr: str, ts: int, notify: bool = False) -> tuple:
        """(ok, why): a FRESH dial to `addr` (never the announcing connection) with our credential for `agent`, answered by a signed ping that verifies against `agent` and is
        addressed to us (ping.exchange checks the nonce, the signature and the node id; a pinned address also pins the door). Adopts the address on success: as a PULL address, or, for
        `notify` (M4b, N1: the same worker, the same checks), as the peer's NOTIFY address, which is never dialed for a pull."""
        ep = {"type": self.carrier.type, "addr": addr}
        held_before = self.carrier.has_credential(ep, agent)         # (a rejected candidate must not leave a key for its address behind: Tor copies one for the new onion)
        if notify and not held_before:
            try:
                held_any = any(self.carrier.has_credential({"type": self.carrier.type, "addr": a}, agent) for a in self.book.ordered(agent))
            except Exception:                                       # noqa: BLE001
                held_any = False
            if not held_any:
                return False, NO_CREDENTIAL                         # (a peer's harmless config choice must not cost it anything: nothing was dialed)
        try:
            self.carrier.rebind_credential(agent, [{"type": self.carrier.type, "addr": a} for a in self.book.ordered(agent)], ep)
            tr = self.carrier.dial(ep, timeout=min(self.dialer.request_timeout, VERIFY_DEADLINE), connect_timeout=min(self.dialer.connect_timeout, VERIFY_DEADLINE), agent=agent)
            ok, why, pong, rtt = P.exchange(tr, self.me, agent, self.stamp, deadline=self.stamp() + VERIFY_DEADLINE, sleep=self.sleep)
        except Exception as e:                                      # noqa: BLE001 - the dial is a carrier: anything can come out of it
            ok, why = False, P._why_from(e)
        if ok:
            if notify:
                self.book.set_notify(agent, addr)
            else:
                self.book.adopt(agent, addr, ts)
        elif not held_before:
            try:
                self.carrier.drop_credential(ep)
            except Exception:                                       # noqa: BLE001 - housekeeping
                pass
        return ok, why

    def _verify(self, agent: str, addr: str, ts: int, notify: bool = False) -> None:
        name = (self.peers.all().get(agent) or {}).get("name") or agent[:8]
        ok, why = self.verify(agent, addr, ts, notify=True) if notify else self.verify(agent, addr, ts)
        now = self.clock()
        if notify and not ok and why == NO_CREDENTIAL:
            with self._mu:
                last = self._nlog.get((agent, addr))
                first = last is None or now - last >= 3600.0
                if first:
                    if len(self._nlog) >= MAX_SKIPS:
                        self._nlog = {k: v for k, v in self._nlog.items() if now - v < 3600.0}
                    self._nlog[(agent, addr)] = now
            if first:
                self.log(f"locator {name}: notify address not used: we hold no {self.carrier.type} credential for this peer")
            return                                                  # (no failure is counted: the mute is for peers that announce addresses that do not answer)
        if ok:
            with self._mu:
                self._fails.pop(agent, None)
            self.log(f"locator {name}: new notify address adopted (a dial there was answered by its node id)" if notify else f"locator {name}: new address adopted (a dial there was answered by its node id)")
            if self.on_adopt is not None and not notify:                 # (a notify address changes no pull address: the backoff of the old one stands)
                try:
                    self.on_adopt(agent)
                except Exception:                                   # noqa: BLE001
                    pass
            return
        with self._mu:
            fails = [t for t in self._fails.get(agent, []) if now - t < LOCATOR_FAIL_WINDOW] + [now]
            self._fails[agent] = fails
            if len(fails) >= LOCATOR_FAILS:
                self._block[agent] = now + LOCATOR_BLOCK
                self._fails[agent] = []
        self.log(f"locator {name}: announced notify address discarded ({why})" if notify else f"locator {name}: announced address discarded ({why})")

    # -- announcing ours
    def _announce(self, agent: str, addr: str) -> None:
        rec = self.peers.all().get(agent)
        if not rec:
            return
        now = self.clock()
        tries = self._ann.get(agent, [0.0, 0])[1]
        ok = False
        try:
            from . import sync as S
            req = S.sign_request(self.me, {"t": "locator", "addr": addr}, ts=int(self.stamp()), aud=agent)
            resp = self.dialer(rec).request(req)
            ok = (isinstance(resp, dict) and resp.get("nonce") == req["nonce"] and type(resp.get("r")) is int and resp["r"] == 1
                  and S.response_signed_by(resp, agent) and resp.get("t") == "ok")
        except Exception:                                           # noqa: BLE001
            ok = False
        if ok:
            self.book.set_announced(agent, addr)
            self._ann.pop(agent, None)
            self.log(f"locator {rec.get('name') or agent[:8]}: told our address")
        else:
            self._ann[agent] = [now + ANNOUNCE_BACKOFF[min(tries, len(ANNOUNCE_BACKOFF) - 1)], tries + 1]
