"""Pull-based sync between two mirrors (spec 7.2, step 2). Transport-agnostic: a client talks to a server through any object with
`request(dict) -> dict`; tcp.py provides one (Fernet-encrypted frames over the direct link), tests use a loopback.

  summary  {thread}         -> the peer's admin head and event count
  list     {thread, page}   -> ids of ALL its resolved events, in dependency order (parents, admin_ref, prev_admin first), 1000 per page
  get      {thread, ids}    -> the events it holds (resolved ones only), size-capped; `more` lists ids left out
  notify   {thread, leaves} -> a hint that we have news (optional)
  (M4b: `summary` and `notify` may carry a signed `notify_at` {type, addr}: where the sender wants notifies; a receiver that adopts it dials it first for its notifies)
  push     {thread, events}  -> up to 64 events a member offers (M4a: what the dialer holds and the peer lacks, after a pull); answered per event

The client lists what the peer has, then fetches what it lacks FRONT TO BACK, so every batch's dependencies are already in hand and nothing has to
be parked (a fresh mirror can sync a thread of any length in ~n/64 requests). Every request is SIGNED by the requester's agent key (context
`sigilnet/v1/sync`; fresh nonce, a time window, optionally the audience) and every response echoes the request nonce, so neither can be replayed
into another exchange. The server answers only members of the thread (any role: an observer may read) or anyone for a public thread. Nothing else is
trusted: the client hands every event of the requested thread to `Mirror.ingest` (events of other threads count as junk), stops after 100
rejected events, and bounds pages, ids, requests and events, so a hostile peer can waste little of its time. Sync only moves events; what is valid,
live, voided or lost is decided by the thread rules alone, so peers holding the same events agree.
"""
from __future__ import annotations

import contextlib
import os
import threading
import time
from collections import OrderedDict, deque

from . import canon
from .event import EventError, check_structure, encode, event_id
from .keys import AGENT_ID_RE, Identity, agent_id, is_hex, verify_strict
from .envelope import EnvelopeError, chain_epoch_ids, check_confirmation, looks_like_envelope, open_envelope, seal_event, seal_key, open_key
from .mirror import Mirror
from . import version as V

CTX = b"sigilnet/v1/sync\0"
RESP_CTX = b"sigilnet/v1/sync-response\0"
MAX_IDS = 64                    # ids per get
LIST_PAGE = 1000                # ids per list page
MAX_LIST_PAGES = 200
MAX_LIST_IDS = 60_000           # client: ids accepted in one listing
PULL_DEADLINE = 900.0           # client: seconds one pull may take in total (a slow-drip server cannot hold us for hours)
MAX_RESPONSE_BYTES = 200_000    # events per get response (the rest is listed in `more`)
SKEW = 600                      # accepted age of a request, seconds (receiver's clock): a request may be this far in the PAST
FUTURE_SKEW = 60                # ... but only this far in the FUTURE (a stamp ahead of our clock is how a floor is poisoned: M0, DESIGN_multicarrier.md F1)
NONCES = 1024                   # recently seen request nonces PER KNOWN SENDER (replay guard): one sender's flood can only fill, and lock out, its OWN table (M0b: Sansa's R1, many members chosen by a thread admin)
RATE_PER_MIN = 240              # requests per minute per requester key
GLOBAL_RATE_PER_MIN = 1500      # requests per minute in total from the node's PEERS (peers.json: chosen by the operator)
MEMBER_RATE_PER_MIN = 600       # ... and in total from members that are NOT peers (chosen by a thread's admin): they can never spend what the operator's peers need
MAX_TABLES = 4096               # per-sender replay tables kept at once (idle ones are dropped first)
BLOB_NONCES_PER_MIN = 600       # blob requests (not charged to the pull buckets) a known sender may add to the nonce table per minute: the blob service's own per-peer budget (blobserve.PEER_REQS_PER_MIN), so a legitimate fetch is not slowed
STRANGER_RATE_PER_MIN = 120     # requests per minute in total from senders that are neither a member of a thread we hold nor a peer (blobserve.UNVETTED_PER_MIN is the same idea)
STRANGER_NONCES = 2048          # their own replay table (>= STRANGER_RATE_PER_MIN x the 10-minute window, so a captured request cannot be replayed inside its window): a stranger can mint keys for free, so nothing it sends may touch the table, the floor or the budgets of known senders
MAX_REQUESTS = 3000             # client: requests in one pull
MAX_FETCH = 60_000              # client: events accepted from one peer in one pull
MAX_UNOPENED = 64               # client: envelopes we could not open yet, kept (per pull) to verify a key when it arrives
MAX_JUNK = 100                  # client: rejected or foreign events tolerated from one peer in one pull
RATE_RETRIES = 40               # client: patient retries when the server says "rate limited"
PUSH_MAX_EVENTS = 64            # events in one push request
PUSH_REQ_PER_MIN = 6            # push requests per minute per sender and 24 in all (checked BEFORE the Mirror lock: a push is the one request that writes under it)
PUSH_TOTAL_PER_MIN = 24
PUSH_BURST = 200                # events one (peer, thread) may have ingested at once (accepted, parked or rejected cost 1; duplicates and unopened envelopes cost nothing) ...
PUSH_REFILL = 120 / 3600.0      # ... refilling per second (120 an hour: a catch-up of 200 is fine, a 10k history is a pull)
PUSH_REJECTS = 8                # rejected events tolerated in one request: the rest is deferred
PUSH_BUDGET_S = 3.0             # wall time one push request may spend ingesting under the Mirror lock (the transport deadline is 8 s): the rest is deferred
PUSH_BYTES = 48_000             # client: events per request by size (tcp.MAX_REQ is 64 KiB)
PUSH_REQUESTS_PER_RUN = 4       # client: push requests per exchange; the rest goes next cycle
PUSH_NO_PEER = 6 * 3600.0       # client: a peer that answered a push with a type-level error is not pushed to for this long
PUSH_UNKNOWN = 3600.0           # client: ... one that does not have (or does not let us push to) a thread, for this long, per thread
PUSH_PARKED = 3600.0            # client: events the peer answered parked / rejected / unopened are not pushed again for this long


def _req_bytes(req: dict) -> bytes:
    return CTX + canon.dumps({k: v for k, v in req.items() if k != "sig"})


VER_REQS = frozenset({"summary", "list", "get"})                    # requests that carry our declaration (`ver`): 0.1.x servers ignore the extra field (push/locator/capsule requests are exact sets and never carry it)
VER_CARRY = VER_REQS | {"ping"}                                    # the request types whose `ver` is read and answered
VER_ANSWERS = frozenset({"summary", "list", "events", "pong"})        # answers that carry the server's `ver`, and only to an asker that declared itself (a 0.1.x asker gets the exact old bytes)


def _carries(req: dict) -> bool:
    """Is this a request type that may carry a declaration? (`t` of a hostile request can be any JSON value: an unhashable one must not raise.)"""
    t = req.get("t")
    return isinstance(t, str) and t in VER_CARRY


def sign_request(me: Identity, body: dict, *, ts: int | None = None, aud: str | None = None) -> dict:
    """A signed request: who asked, when, a fresh nonce, the asker's public key (checked against the thread's member list) and, if known,
    the audience (the server's agent id), so a captured request cannot be replayed to a different server."""
    req = {**body, "from": me.id, "pub": me.sign_pub, "ts": int(time.time()) if ts is None else ts, "nonce": os.urandom(8).hex()}
    if aud:
        req["aud"] = aud
    req["sig"] = me.sign(_req_bytes(req))
    return req


def wire_enc(mirror: Mirror, t, tid: str) -> bool:
    """Does this thread travel as envelopes (an encrypted private thread)? Then nothing but its genesis is ever sent or accepted in plaintext."""
    return t.state()["visibility"] == "private" and mirror.codec.is_encrypted(tid)


def wire_item(mirror: Mirror, t, tid: str, i: str, e: dict, enc: bool) -> dict:
    """The form event `e` (id `i`) travels in: itself, or its envelope under the key of its OWN epoch. EnvelopeError if we hold no verified key for that epoch.
    The one place that serves `get` answers and pushes."""
    if enc and i != tid:
        kid, key = mirror.codec.key_for(t, e)
        return seal_event(key, tid, kid, e)
    return e


def open_wire(mirror: Mirror, tid: str, x):
    """One received item of thread `tid` -> ("ok", signed event) | ("need", epoch id as sent: we hold no key for it) | ("junk", None). The one open step of `pull` and of the push server:
    an envelope is opened with the keyring; a plaintext event in a thread we hold as encrypted is a downgrade (junk, the genesis excepted). Nothing is validated here."""
    codec = mirror.codec
    if looks_like_envelope(x):
        ring = codec.ring(tid) if hasattr(codec, "ring") else None
        kid = x.get("ep")
        got = ring.get(kid) if ring is not None and isinstance(kid, str) and len(kid) == 32 else None
        if got is None:
            return "need", kid
        try:
            return "ok", open_envelope(got[0], x, tid)
        except EnvelopeError:
            return "junk", None                                    # a verified key that does not open this envelope: the envelope is junk
    if hasattr(codec, "is_encrypted") and codec.is_encrypted(tid) and not (isinstance(x, dict) and x.get("kind") == "genesis"):
        return "junk", None                                        # downgrade
    return "ok", x


class SyncServer:
    """Answers sync requests from a mirror. Never raises: anything wrong becomes {"t": "error", "why": ...}."""

    def __init__(self, mirror: Mirror, *, clock=time.time, on_notify=None, identity: Identity | None = None, blobs=None, pong=None, ping_log=None, on_locator=None, on_inbound=None, on_push=None, push_timer=time.monotonic, on_notify_at=None, on_peer_ver=None, on_refuse=None):
        self.m, self.clock, self.on_notify, self.identity = mirror, clock, on_notify, identity
        self.on_refuse = on_refuse                                  # callable(peer agent id, the refusal text, the declaration of the refused request or None): a KNOWN peer was refused because its protocol or a thread's format is not served (version.py); a log line, never changes the answer
        self.on_peer_ver = on_peer_ver                              # callable(peer agent id, its checked declaration): a known peer declared its protocol (version.py); a cache write, never changes the answer
        self.on_notify_at = on_notify_at                            # callable(peer agent id, the signed `notify_at` field) (M4b): a peer says where it wants notifies; the node checks and verifies it later; None = ignored
        self.on_push = on_push                                      # callable(peer agent id, thread id, accepted event ids): events a member PUSHED were stored (the node tells the other peers); called after the Mirror lock is released
        self.push_timer = push_timer                                # wall time of the ingest loop of one push request (injectable)
        self.push_hits: dict[str, list] = {}                        # sender -> times of its push requests (PUSH_REQ_PER_MIN)
        self.push_total: deque = deque()                            # all push requests (PUSH_TOTAL_PER_MIN)
        self.push_tokens: dict = {}                                 # (sender, thread) -> [tokens, time]: the events it may still have ingested (PUSH_BURST, PUSH_REFILL)
        self.heard: dict[str, float] = {}                           # peer -> when it last sent us a sync request (not a ping): "did the peer come to pull what we told it?" (Node follow-up of an acked notify)
        self.on_inbound = on_inbound                                # callable(peer agent id, carrier type): an authenticated request of a PEER arrived over that carrier (the locator book's in_at); None = not kept
        self._tls = threading.local()                               # the carrier type of the request being handled in THIS thread (arrived_on)
        self.on_locator = on_locator                                # callable(agent, addr, ts) -> "ok" or a short reason (locators.LocatorService.on_locator); None = this server takes no announcements
        self.pong = pong                                            # callable(requester agent id) -> the pong dict, or None = the stranger's answer (ping.handle_ping over the node's cached snapshot); None = this server answers no pings
        self.ping_log = ping_log                                    # callable(requester, "answered" | "refused"): the node writes one history line (rate limited pings are not logged: a flood must not fill the log)
        self.ping_at: dict[str, float] = {}                         # requester -> when we last answered it a ping (PING_MIN_GAP)
        self.blobs = blobs                                          # blobserve.BlobService or None (this node serves no blobs)
        self.seen: dict = {}                                        # known sender -> OrderedDict nonce -> ts (that sender's own replay table)
        self.floors: dict = {}                                      # known sender -> requests of THIS sender stamped at or before this are refused (its own evicted nonces may be replays)
        self.rate: dict[str, list] = {}
        self.total: deque = deque()                                 # the operator's peers
        self.m_total: deque = deque()                               # members that are not peers
        self.b_rate: dict[str, list] = {}                           # known sender -> times of its uncharged (blob) requests, for BLOB_NONCES_PER_MIN
        self.s_seen: OrderedDict = OrderedDict()                    # the strangers' side: nonces (no floor: what a stranger may ask is read-only and answered like "not here")
        self.s_rate: dict[str, list] = {}
        self.s_total: deque = deque()
        self._peers: frozenset = frozenset()                        # peer ids of the node (set_peers: the node loop refreshes it; reading peers.json per request would be a file read per request)
        self.mu = threading.Lock()                                  # seen / rate / floor are shared between connection threads

    def via(self):
        """The carrier type of the request being handled in this thread (None: not through a door)."""
        return getattr(self._tls, "via", None)

    @contextlib.contextmanager
    def arrived_on(self, via):
        """The door handler says which carrier type the requests it passes in came over; `_handle` tells `on_inbound` after the request authenticated. (A context, not an argument:
        `handle(req)` keeps its one-argument shape for every caller and every test double.)"""
        prev = getattr(self._tls, "via", None)
        self._tls.via = via
        try:
            yield
        finally:
            self._tls.via = prev

    def _reply(self, req, resp: dict) -> dict:
        n = req.get("nonce") if isinstance(req, dict) else None
        if isinstance(n, str) and len(n) == 16:
            resp["nonce"] = n                                       # bound to the request: an old response cannot answer a new question
        if isinstance(req, dict) and _carries(req) and V.parse_decl(req.get("ver")) is not None and isinstance(resp.get("t"), str) and resp["t"] in VER_ANSWERS:
            resp["ver"] = V.decl()                                  # (only to an asker that declared itself, only in a successful answer: a stranger's `unknown` and every 0.1.x asker's answer stay byte-identical)
        resp["r"] = 1                                               # marks a RESPONSE: a reflected request is never mistaken for one
        if self.identity is not None:                               # WHO answered: over tor/plain frames nothing else proves it (the nonce is inside the signed bytes)
            resp["by"] = self.identity.sign_pub
            resp["rsig"] = self.identity.sign(RESP_CTX + canon.dumps(resp))
        return resp

    def refuse(self, req) -> dict:
        """The answer a stranger gets (the same as for a thread that is not here): used by a per-peer service for a request that is not from ITS peer."""
        return self._reply(req, {"t": "unknown"})

    def _err(self, req, why: str) -> dict:
        return self._reply(req, {"t": "error", "why": why})

    def _authenticate(self, req: dict, charge: bool = True) -> str | None:
        """Returns an error string, or None if the request is fresh, signed by its claimed key, not a replay, and inside the rate limits.
        charge=False (blob requests) skips the pull rate buckets: blobs have their own budgets and must neither eat nor hide behind the pull ones."""
        try:
            if not isinstance(req.get("from"), str) or not AGENT_ID_RE.match(req["from"]) or not is_hex(req.get("pub"), 64) \
                    or not is_hex(req.get("sig"), 128) or not isinstance(req.get("nonce"), str) or len(req["nonce"]) != 16 \
                    or type(req.get("ts")) is not int:
                return "malformed request"
            if agent_id(bytes.fromhex(req["pub"])) != req["from"]:
                return "pub does not match from"
            now = self.clock()
            if now - req["ts"] > SKEW:
                return "stale request (check clocks)"
            if req["ts"] - now > FUTURE_SKEW:
                return "stale request (check clocks): stamped ahead of this server's clock"
            if req["ts"] <= self.floors.get(req["from"], 0):
                return "stale request (check clocks)"
            if not verify_strict(req["pub"], req["sig"], _req_bytes(req)):
                return "bad signature"
            if "aud" in req and self.identity is not None and req["aud"] != self.identity.id:
                return "wrong audience"
        except (TypeError, ValueError, canon.CanonError):
            return "malformed request"
        key = (req["from"], req["nonce"])
        if req["nonce"] in self.seen.get(req["from"], ()) or key in self.s_seen:
            return "replayed request"
        peer = req["from"] in self._peers
        if not peer and not self._known(req["from"]):
            return self._charge_stranger(req, key, now)
        if not charge:
            hits = [t for t in self.b_rate.get(req["from"], []) if now - t < 60]
            if len(hits) >= BLOB_NONCES_PER_MIN:
                self.b_rate[req["from"]] = hits
                return "rate limited"
            hits.append(now)
            self.b_rate[req["from"]] = hits
            if len(self.b_rate) > 1024:
                self.b_rate = {k: v for k, v in self.b_rate.items() if v and now - v[-1] < 60}
            self._remember(key, req["ts"], now)
            return None
        q, cap = (self.total, GLOBAL_RATE_PER_MIN) if peer else (self.m_total, MEMBER_RATE_PER_MIN)
        while len(q) and now - q[0] >= 60:
            q.popleft()
        if len(q) >= cap:
            return "rate limited"
        hits = [t for t in self.rate.get(req["from"], []) if now - t < 60]
        if len(hits) >= RATE_PER_MIN:
            self.rate[req["from"]] = hits
            return "rate limited"
        hits.append(now)
        self.rate[req["from"]] = hits
        q.append(now)
        if len(self.rate) > 1024:                                   # the table must not grow with every key ever seen
            self.rate = {k: v for k, v in self.rate.items() if v and now - v[-1] < 60}
        self._remember(key, req["ts"], now)
        return None

    def set_peers(self, ids) -> None:
        """The node loop gives us the peer ids (peers.json) each round; a plain reference swap, no lock."""
        self._peers = frozenset(i for i in ids if isinstance(i, str))

    def _known(self, agent: str) -> bool:
        """Is this requester a peer of the node or a member (any role) of a thread we hold? A lock-free HINT that only chooses WHICH budgets and nonce table a signed request
        is charged to: a wrong 'no' (a member added since the last refresh) costs that one request a place in the small stranger budget, a wrong 'yes' is impossible to exploit
        (the thread gate in `_answer` stays authoritative). The signature was already checked, so `agent` really signed this request."""
        if agent in self._peers:
            return True
        try:
            for t in list(self.m.threads.values()):
                if agent in t.state()["members"]:
                    return True
        except Exception:                                            # noqa: BLE001 - a hint must never fail a request: the mirror changed under us, or is not what we expect: unknown this once
            return False
        return False

    def _charge_stranger(self, req: dict, key, now) -> str | None:
        """A sender nobody knows (a client-auth key holder with throwaway keypairs, a guest, a member not yet seen): its OWN small global budget, its own per-key bucket and its
        own nonce table. Nothing here can raise the floor or spend what known senders need (DESIGN_multicarrier.md F1)."""
        while len(self.s_total) and now - self.s_total[0] >= 60:
            self.s_total.popleft()
        if len(self.s_total) >= STRANGER_RATE_PER_MIN:
            return "rate limited"
        hits = [t for t in self.s_rate.get(req["from"], []) if now - t < 60]
        if len(hits) >= RATE_PER_MIN:
            self.s_rate[req["from"]] = hits
            return "rate limited"
        hits.append(now)
        self.s_rate[req["from"]] = hits
        self.s_total.append(now)
        if len(self.s_rate) > 1024:
            self.s_rate = {k: v for k, v in self.s_rate.items() if v and now - v[-1] < 60}
        self.s_seen[key] = req["ts"]
        while len(self.s_seen) > STRANGER_NONCES:
            self.s_seen.popitem(last=False)
        return None

    def _remember(self, key, ts, now) -> None:
        """Record a nonce in the SENDER's own table. Entries older than the acceptance window are dropped first (they can no longer be replayed); when the table is still full the oldest
        entry goes and the sender's OWN floor rises to it (never ahead of our clock), so a sender that floods can only lock itself out."""
        agent, nonce = key
        t = self.seen.get(agent)
        if t is None:
            if len(self.seen) >= MAX_TABLES:
                self._drop_idle(now)
            t = self.seen[agent] = OrderedDict()
        while t and now - next(iter(t.values())) > SKEW:
            t.popitem(last=False)
        t[nonce] = ts
        while len(t) > NONCES:
            _, old = t.popitem(last=False)
            self.floors[agent] = max(self.floors.get(agent, 0), min(old, now))     # never ahead of our own clock

    def _drop_idle(self, now) -> None:
        """Forget the tables (and floors) of senders with nothing inside the window any more; if that frees nothing, the oldest table goes (its floor stays: nothing it sent can be replayed)."""
        for a in [a for a, t in self.seen.items() if not t or now - max(t.values()) > SKEW]:
            del self.seen[a]
            self.floors.pop(a, None)
        while len(self.seen) >= MAX_TABLES:
            a = next(iter(self.seen))
            del self.seen[a]

    @property
    def floor(self) -> int:
        """The highest per-sender floor (diagnostics and tests only: no request is judged by it)."""
        return max(self.floors.values(), default=0)

    def _may_read(self, t, req: dict) -> bool:
        st = t.state()
        if st["visibility"] == "public":
            return True
        m = st["members"].get(req["from"])                       # any current role, observers included; removed members are out
        return m is not None and m["sign"] == req["pub"]

    def handle(self, req) -> dict:
        try:
            return self._handle(req)
        except Exception as e:                                     # noqa: BLE001 - a malformed request must never take the server down
            return self._err(req, f"internal: {type(e).__name__}")

    def _handle(self, req) -> dict:
        if not isinstance(req, dict):
            return self._err(req, "malformed request")
        is_blob = req.get("t") == "blob"
        with self.mu:
            why = self._authenticate(req, charge=not is_blob)
        if why:
            return self._err(req, why)
        via = getattr(self._tls, "via", None)
        if via is not None and self.on_inbound is not None and req["from"] in self._peers:
            try:
                self.on_inbound(req["from"], via)                   # (cheap, throttled in the book; a failure of the cache never fails a request)
            except Exception:                                       # noqa: BLE001
                pass
        if self.on_peer_ver is not None and "ver" in req and _carries(req) and req["from"] in self._peers:
            d = V.parse_decl(req["ver"])
            if d is not None:
                try:
                    self.on_peer_ver(req["from"], d)
                except Exception:                                   # noqa: BLE001
                    pass
        if _carries(req) and req["t"] in VER_REQS and self._known(req["from"]):
            text = V.refusal(V.decl(), V.parse_decl(req.get("ver")))      # (the declaration of THIS request; undeclared = 0.1.x; never a cache)
            if text:
                self._refused(req["from"], text, V.parse_decl(req.get("ver")))
                return self._err(req, text)
        tid = req.get("thread")
        if is_blob:
            return self._blob(req, tid)
        if req.get("t") == "ping":
            return self._ping(req)                                  # BEFORE the Mirror lock: a ping never waits for (or makes anyone wait for) a refresh
        if req.get("t") == "locator":
            return self._locator(req)                               # likewise: an announcement of a peer's new address is a few checks in memory
        if req["from"] in self._peers:
            self.heard[req["from"]] = self.clock()
            if "notify_at" in req and req.get("t") in ("summary", "notify") and self.on_notify_at is not None:
                try:
                    self.on_notify_at(req["from"], req["notify_at"])    # (cheap, in memory; the answer to the request is never changed by it)
                except Exception:                                   # noqa: BLE001
                    pass
        if req.get("t") == "push":
            wait = self._push_budget(req["from"])                   # BEFORE the Mirror lock too: a push is the one request that writes under it, so its own budget is checked outside
            if wait:
                return self._reply(req, {"t": "error", "why": "rate limited", "retry": wait})
        self._tls.pushed = None
        with self.m._lock():                                       # one consistent view for the whole request (also refreshes from other writers)
            self.m._discover()
            for i in list(self.m.threads):
                self.m._refresh(i)
            resp = self._answer(req, tid)
        note, self._tls.pushed = getattr(self._tls, "pushed", None), None
        if note is not None and self.on_push is not None:           # (outside the lock: the node takes its own lock in there)
            try:
                self.on_push(*note)
            except Exception:                                       # noqa: BLE001 - a relay hint must never fail the answer
                pass
        return resp

    def _push_budget(self, agent: str) -> int:
        """0 if a push request of `agent` may go on, else the seconds it should wait. Per sender PUSH_REQ_PER_MIN, in all PUSH_TOTAL_PER_MIN for senders we know (a stranger can only spend its own)."""
        now = self.clock()
        known = self._known(agent)
        with self.mu:
            hits = [t for t in self.push_hits.get(agent, []) if now - t < 60]
            if len(hits) >= PUSH_REQ_PER_MIN:
                self.push_hits[agent] = hits
                return max(1, int(60 - (now - hits[0])) + 1)
            while self.push_total and now - self.push_total[0] >= 60:
                self.push_total.popleft()
            if known and len(self.push_total) >= PUSH_TOTAL_PER_MIN:
                return max(1, int(60 - (now - self.push_total[0])) + 1)
            hits.append(now)
            self.push_hits[agent] = hits
            if known:
                self.push_total.append(now)
            if len(self.push_hits) > 1024:
                self.push_hits = {k: v for k, v in self.push_hits.items() if v and now - v[-1] < 60}
        return 0

    def _locator(self, req: dict) -> dict:
        """A peer tells us the address of the door we should dial it at (DESIGN_locator_book.md). Only the shape is checked here; the node decides (known peer, the carrier's own rules,
        rate limits) and dials the address LATER, in its own thread, before it believes it."""
        if self.on_locator is None:
            return self.refuse(req)
        if set(req) - {"t", "addr", "from", "pub", "ts", "nonce", "aud", "sig"} or not isinstance(req.get("addr"), str):
            return self._err(req, "malformed request")
        try:
            why = self.on_locator(req["from"], req["addr"], req["ts"])
        except Exception:                                           # noqa: BLE001
            return self._err(req, "internal: locator")
        if why == "unknown":
            return self.refuse(req)                                 # a stranger gets exactly the usual answer
        return self._reply(req, {"t": "ok"}) if why == "ok" else self._err(req, why)

    def _ping(self, req: dict) -> dict:
        from . import ping as P
        try:
            body = self.pong(req["from"]) if self.pong is not None else None
        except Exception:                                           # noqa: BLE001
            body = None
        if body is None:
            self._ping_note(req["from"], "refused")
            return self.refuse(req)                                 # a stranger (or a server that answers no pings) gets exactly the usual answer
        now = self.clock()
        with self.mu:
            last = self.ping_at.get(req["from"])
            if last is not None and 0 <= now - last < P.PING_MIN_GAP:
                return self._err(req, "rate limited")
            self.ping_at[req["from"]] = now
            if len(self.ping_at) > 1024:
                self.ping_at = {k: v for k, v in self.ping_at.items() if now - v < 60}
        self._ping_note(req["from"], "answered")
        return self._reply(req, dict(body))

    def _ping_note(self, who: str, what: str) -> None:
        if self.ping_log is not None:
            try:
                self.ping_log(who, what)
            except Exception:                                       # noqa: BLE001 - a log line must never change the answer
                pass

    def _blob(self, req: dict, tid) -> dict:
        if self.blobs is None or not isinstance(tid, str):
            return self._reply(req, {"t": "unknown"})
        if not self.blobs.charge_request(req["from"]):
            return self._err(req, "rate limited")
        if not self.blobs.vetted(tid, req["from"], req["pub"]) and not self.blobs.charge_unvetted():
            return self._reply(req, {"t": "unknown"})              # classified BEFORE any lock: strangers cannot keep the mirror lock busy beyond a small global budget
        with self.m._lock():                                       # the gate needs a consistent view; the (slow) read below does not
            self.m._discover()
            self.m._refresh(tid)
            t = self.m.threads.get(tid)
            if t is not None:
                self.blobs.note_thread(t)
            cid = self.blobs.gate(t, req) if t is not None else None
        if cid is not None and not self.blobs.admit_member():
            return self._err(req, "rate limited")
        resp = self.blobs.serve(req, cid) if cid is not None else None
        return self._reply(req, resp if resp is not None else {"t": "unknown"})

    def _refused(self, who: str, text: str, decl=None) -> None:
        if self.on_refuse is not None:
            try:
                self.on_refuse(who, text, decl)
            except Exception:                                       # noqa: BLE001 - a log line must never change the answer
                pass

    def _answer(self, req: dict, tid, gate: bool = True) -> dict:
        t = self.m.threads.get(tid) if isinstance(tid, str) else None
        if t is None or not self._may_read(t, req):
            return self._reply(req, {"t": "unknown"})              # the same answer for "not here" and "not yours": no thread enumeration
        if gate and _carries(req) and req["t"] in VER_REQS:
            text = V.refusal(V.decl(), V.parse_decl(req.get("ver")), V.thread_format(t))      # a peer whose software cannot read this thread's format is told why, not served events it would only refuse
            if text:
                self._refused(req["from"], text, V.parse_decl(req.get("ver")))
                return self._err(req, text)
        kind = req.get("t")
        if self.blobs is not None:
            self.blobs.note_thread(t)                              # keep the lock-free member snapshot warm (we hold the lock and the state anyway)
        if kind == "summary":
            return self._reply(req, {"t": "summary", "thread": tid, "head": t.head, "n": len(t.resolved_ids())})
        if kind == "list":
            page = req.get("page", 0)
            if type(page) is not int or not 0 <= page < MAX_LIST_PAGES:
                return self._err(req, "bad page")
            order = t.sync_order()
            return self._reply(req, {"t": "list", "thread": tid, "n": len(order), "pages": max(1, -(-len(order) // LIST_PAGE)),
                                     "ids": order[page * LIST_PAGE:(page + 1) * LIST_PAGE]})
        if kind == "get":
            ids = req.get("ids")
            if not isinstance(ids, list) or len(ids) > MAX_IDS or any(not is_hex(i, 32) for i in ids):
                return self._err(req, "bad ids")
            have, out, size, more = t.resolved_ids(), [], 0, []
            enc = wire_enc(self.m, t, tid)                           # an encrypted thread is NEVER served in plaintext (the genesis excepted)
            for i in ids:
                if i not in have:
                    continue
                e = t.stored[i]
                try:
                    item = wire_item(self.m, t, tid, i, e, enc)
                except EnvelopeError:
                    continue                                        # we lack that epoch's key right now: the event is simply not served (the peer retries later)
                n = len(canon.dumps(item)) if enc else len(encode(e))
                if size + n > MAX_RESPONSE_BYTES and out:
                    more.append(i)
                    continue
                out.append(item)
                size += n
            return self._reply(req, {"t": "events", "events": out, "more": more})
        if kind == "key":
            return self._keys(req, t, tid)
        if kind == "push":
            return self._push(req, t, tid)
        if kind == "notify":
            if self.on_notify is not None:
                self.on_notify(req["from"], tid, [i for i in req.get("leaves", []) if is_hex(i, 32)][:LIST_PAGE])
            return self._reply(req, {"t": "ok"})
        return self._err(req, "unknown request type")


    def _bucket(self, key, now: float) -> list:
        """The (sender, thread) bucket [tokens, time] brought up to `now`; full buckets hold no information and are dropped when the table is big."""
        if len(self.push_tokens) > 4096:
            self.push_tokens = {k: v for k, v in self.push_tokens.items() if v[0] + (now - v[1]) * PUSH_REFILL < PUSH_BURST}
        b = self.push_tokens.get(key)
        if b is None:
            b = [float(PUSH_BURST), now]
        b[0] = min(float(PUSH_BURST), b[0] + max(0.0, now - b[1]) * PUSH_REFILL)
        b[1] = now
        self.push_tokens[key] = b
        return b

    def _push(self, req: dict, t, tid: str) -> dict:
        """A member offers events (M4a). Only a CURRENT owner / admin / member of the thread may push (a guest, an observer, a removed member and a stranger all get the stranger's answer, a public thread
        included); the events must be of THIS thread and are never a genesis; each goes through the same ingest as a pulled event (live=False). Answer: one result per event, in order:
        accepted | duplicate | parked | rejected | unopened (an envelope under an epoch key we lack: nothing is stored, nothing costs a token) | deferred (not looked at: bucket, time or junk cap)."""
        m = t.state()["members"].get(req["from"])
        if m is None or m["sign"] != req["pub"] or m["role"] not in ("owner", "admin", "member"):
            return self._reply(req, {"t": "unknown"})
        evs = req.get("events")
        if set(req) - {"t", "thread", "events", "from", "pub", "ts", "nonce", "aud", "sig"} or not isinstance(evs, list) or not 0 < len(evs) <= PUSH_MAX_EVENTS or not all(isinstance(x, dict) for x in evs):
            return self._err(req, "bad events")
        agent = req["from"]
        enc = wire_enc(self.m, t, tid)
        results, accepted, rejected, retry = [], [], 0, 0
        t0 = self.push_timer()
        with self.mu:
            bucket = self._bucket((agent, tid), self.clock())
        stop = None                                                 # why the rest is deferred
        for x in evs:
            if stop is not None:
                results.append({"s": "deferred"})
                continue
            if self.push_timer() - t0 > PUSH_BUDGET_S:
                stop = "time"
            elif rejected >= PUSH_REJECTS:
                stop = "junk"
            elif bucket[0] < 1.0:
                stop = "bucket"
                retry = max(1, int((1.0 - bucket[0]) / PUSH_REFILL) + 1)
            if stop is not None:
                results.append({"s": "deferred"})
                continue
            if not enc and looks_like_envelope(x):
                kind, ev = "junk", None                             # (an envelope in a thread that is not encrypted; plaintext into an encrypted one is open_wire's "junk": a downgrade)
            else:
                kind, ev = open_wire(self.m, tid, x)
            if kind == "need" and isinstance(ev, str) and len(ev) == 32:
                results.append({"s": "unopened", "why": ev})        # (names the epoch only; nothing is stored, nothing costs a token)
                continue
            status, why, eid, news = self._push_one(t, tid, ev) if kind == "ok" else ("rejected", "downgrade or unreadable envelope", None, [])
            entry = {"s": status}
            if eid:
                entry["id"] = eid
            if why:
                entry["why"] = why
            results.append(entry)
            if status == "duplicate":
                continue                                            # costs nothing
            bucket[0] -= 1.0                                        # accepted, parked and rejected all cost one
            if status == "rejected":
                rejected += 1
            accepted.extend(news)
        out = {"t": "pushed", "results": results}
        if stop is not None:
            out["retry"] = retry or 60
        if accepted:
            self._tls.pushed = (agent, tid, list(dict.fromkeys(accepted)))
        return self._reply(req, out)

    def _push_one(self, t, tid: str, ev) -> tuple:
        """(status, why, event id, ids newly accepted) of one opened pushed event; the Mirror lock is held by the caller."""
        try:
            check_structure(ev, 3 * 65536 + 4096)
            eid = event_id(ev)
        except (EventError, canon.CanonError, TypeError, ValueError):
            return "rejected", "not an event", None, []
        if ev["kind"] == "genesis" or eid == tid:
            return "rejected", "a push never carries the genesis", eid, []
        if ev["thread"] != tid:
            return "rejected", "event of another thread", eid, []
        if eid in t.stored:
            return "duplicate", "", eid, []
        res = self.m._ingest_locked(ev, False)                      # (the lock is ours: Mirror.ingest would take it again)
        if res.status in ("accepted", "voided"):
            return "accepted", "", eid, list(res.accepted or [eid])
        if res.status == "duplicate":
            return "duplicate", "", eid, []
        if res.status in ("pending", "awaiting"):
            return "parked", "", eid, []
        return "rejected", (res.reason or res.status)[:100], eid, []

    def _keys(self, req: dict, t, tid: str) -> dict:
        """Thread keys sealed to a CURRENT non-guest member of an encrypted private thread, for the epochs on OUR derived chain (never an abandoned branch).
        The recipient's kex key comes from the member_add on the chain, never from the request. Every refusal is the stranger's answer."""
        st = t.state()
        m = st["members"].get(req["from"])
        ids = req.get("ids", [])
        if st["visibility"] != "private" or not self.m.codec.is_encrypted(tid) or m is None or m["role"] == "guest" or m["sign"] != req["pub"] \
                or not isinstance(ids, list) or len(ids) > MAX_IDS or any(not is_hex(i, 32) for i in ids):
            return self._reply(req, {"t": "unknown"})
        ring, out = self.m.codec.ring(tid), []
        for kid in chain_epoch_ids(t):
            if ids and kid not in ids:
                continue
            got = ring.get(kid)
            if got is not None and got[1]:
                out.append({"id": kid, "sealed": seal_key(m["kex"], req["from"], tid, kid, got[0]), "conf": ring.conf(kid)})
        return self._reply(req, {"t": "keys", "thread": tid, "keys": out})


def not_a_sync_answer(resp, req) -> str:
    """Why `resp` is not the answer to `req`, in words (this text lands in `peer list`, the history and job errors; it describes what arrived, it does not guess a cause beyond
    the one measured: right after a join the new onion services take minutes to spread). Peer-controlled parts are cut to printable characters."""
    from .convo import sanitize
    base = "response does not answer this request"
    hint = " (also seen for a minute or two after a join, while the new onion services spread)"
    if not isinstance(resp, dict):
        return f"{base}: the peer sent {type(resp).__name__}, not a sync reply{hint}"
    kind = f", its type is '{sanitize(resp.get('t'), 24)}'" if isinstance(resp.get("t"), str) else ""
    if resp.get("nonce") != req.get("nonce"):
        why = "its nonce differs (a reply to another request, or not a sync reply)"
    elif type(resp.get("r")) is not int or resp["r"] != 1:
        why = "it is not marked as a response"
    else:
        why = "it is not signed by the expected peer"
    return f"{base}: {why}{kind}{hint}"


def response_signed_by(resp: dict, peer_id: str) -> bool:
    """Is this response signed by the agent `peer_id` (its signing key must hash to that id)? Never raises."""
    try:
        by, sig = resp.get("by"), resp.get("rsig")
        if not (isinstance(by, str) and isinstance(sig, str) and is_hex(by, 64) and is_hex(sig, 128)) or agent_id(bytes.fromhex(by)) != peer_id:
            return False
        return verify_strict(by, sig, RESP_CTX + canon.dumps({k: v for k, v in resp.items() if k != "rsig"}))     # (`by` is inside the signed bytes)
    except (canon.CanonError, TypeError, ValueError):
        return False


def _clean(x, limit: int = 200) -> str:
    """Peer-supplied text that ends up in a result, a log or a terminal: a string of printable characters only."""
    s = x if isinstance(x, str) else repr(x)
    return "".join(c if c.isprintable() else "?" for c in s)[:limit]


REFUSAL_KEYS = ("format mismatch", "unsupported version", "unknown kind")      # the refusals that mean "this software cannot read what the peer serves": counted by reason for the operator


def _why_refused(r: dict, reason) -> None:
    for k in REFUSAL_KEYS:
        if isinstance(reason, str) and reason.startswith(k):
            d = r.setdefault("refused", {})
            d[k] = d.get(k, 0) + 1
            return


def refused_note(res) -> str:
    """'N events refused: unsupported version (2)' for a pull that met events this software cannot read, or ''."""
    d = res.get("refused") if hasattr(res, "get") else None
    return "" if not d else f"{sum(d.values())} events refused: " + ", ".join(f"{k} ({n})" for k, n in sorted(d.items()))


class PullResult(dict):
    """Counters for one pull; `ok` is False if the peer misbehaved, was cut off, refused, or did not deliver everything it listed."""


def pull(mirror: Mirror, tid: str, transport, me: Identity, *, live: bool = False, peer_id: str | None = None, sleep=time.sleep,
         deadline: float = PULL_DEADLINE, clock=time.time, stamp=time.time, rate_retries: int = RATE_RETRIES, notify_at: dict | None = None, declare: bool = True) -> PullResult:
    """Fetch what the peer has for thread `tid` that we lack, verifying everything. Idempotent and resumable: run it again after a failure.
    `notify_at` (M4b): {"type", "addr"}, the address we want notifies at; it rides in the signed `summary` request only (never in list/get/key).
    `declare` (versioning stage 1): put our declaration (`ver`) in summary/list/get; a pull from a PUBLIC read door passes False (a 0.1.x read door refuses any extra field)."""
    r = PullResult(thread=tid, fetched=0, resolved=0, rejected=0, requests=0, ok=True, why="", need_keys=set(), unopened=[], peer_ids=set(), peer_seen=False, peer_ver=None)
    t_end = clock() + deadline

    def fail(why):
        r["ok"], r["why"] = False, why
        return None

    def ask(body):
        for attempt in range(rate_retries + 1):
            if r["requests"] >= MAX_REQUESTS:
                return fail("too many requests")
            if clock() > t_end:
                return fail("pull deadline exceeded")
            r["requests"] += 1
            req = sign_request(me, {**body, "ver": V.decl()} if declare and body.get("t") in VER_REQS else body, ts=int(stamp()), aud=peer_id)
            try:
                resp = transport.request(req)
            except Exception as e:                                 # noqa: BLE001 - transport failures are just "the peer is unreachable"
                r["retry"] = getattr(e, "retry", True)             # tor says whether waiting can help (an unauthorized client cannot fix itself by waiting)
                r["unreachable"] = True
                return fail(f"transport: {type(e).__name__}" + (f": {str(e)[:150]}" if hasattr(e, "retry") else ""))
            if not isinstance(resp, dict) or resp.get("nonce") != req["nonce"] or type(resp.get("r")) is not int or resp["r"] != 1:
                return fail(not_a_sync_answer(resp, req))
            if peer_id is not None and not response_signed_by(resp, peer_id):
                return fail("response is not signed by the expected peer")
            if resp.get("t") in ("summary", "list", "events") and req.get("t") in VER_REQS:
                r["peer_seen"] = True                                # a signed, successful answer: it either declares its protocol or it is 0.1.x
                d = V.parse_decl(resp.get("ver"))
                if d is not None:
                    r["peer_ver"] = d
            if resp.get("t") == "error" and resp.get("why") == "rate limited" and attempt < rate_retries:
                sleep(1.5)
                continue
            if resp.get("t") in ("error", "unknown"):
                return fail(_clean(resp.get("why", resp.get("t"))))
            return resp
        return fail("rate limited")

    def open_item(x):
        """One item of a `get` answer -> the signed event, or None. Envelopes are opened with the keyring (a key we lack is NOT junk: it is reported in need_keys and the
        ciphertext is kept to verify the key when it arrives); a plaintext event in a thread we hold as encrypted is a downgrade and counts as junk."""
        kind, v = open_wire(mirror, tid, x)
        if kind == "need":
            if isinstance(v, str) and len(v) == 32 and len(r["unopened"]) < MAX_UNOPENED:
                r["need_keys"].add(v)
                if x not in r["unopened"]:                          # refetched stragglers must not inflate the count (it explains `left` below)
                    r["unopened"].append(x)
            return None
        return {} if kind == "junk" else v                         # ({}: junk, counted below)

    def ingest(events, asked) -> bool:
        if isinstance(events, list):
            events = [e for e in (open_item(x) for x in events) if e is not None]
        for ev in events if isinstance(events, list) else []:
            try:
                check_structure(ev, 3 * 65536 + 4096)
                ok = (ev["thread"] == tid or event_id(ev) == tid) and event_id(ev) in asked      # only what we asked for, of the thread we asked about
            except (EventError, canon.CanonError, TypeError, ValueError) as e:
                ok = False
                _why_refused(r, str(e))
            if not ok:
                r["rejected"] += 1                                  # nothing else is ever stored, but it still counts towards the junk cap
                if r["rejected"] > MAX_JUNK:
                    return False
                continue
            r["fetched"] += 1
            before = len(mirror.threads[tid].resolved_ids()) if tid in mirror.threads else 0
            res = mirror.ingest(ev, live=live)
            if res.status == "rejected":
                r["rejected"] += 1
                _why_refused(r, res.reason)
            if tid in mirror.threads:
                r["resolved"] += max(0, len(mirror.threads[tid].resolved_ids()) - before)
            if r["rejected"] > MAX_JUNK or r["fetched"] > MAX_FETCH:
                return False
        return True

    def fetch(queue: list) -> bool:
        """Get the ids in `queue` (in order, MAX_IDS at a time); ids the server held back for size go to the end of the queue."""
        queue = list(queue)
        while queue:
            chunk, queue = queue[:MAX_IDS], queue[MAX_IDS:]
            t = mirror.threads.get(tid)
            chunk = [i for i in chunk if t is None or i not in t.stored]
            if not chunk:
                continue
            resp = ask({"t": "get", "thread": tid, "ids": chunk})
            if resp is None:
                return False
            if not ingest(resp.get("events"), set(chunk)):
                fail("peer sent too much junk")
                return False
            more = [i for i in resp.get("more", []) if is_hex(i, 32)] if isinstance(resp.get("more"), list) else []
            if more and not resp.get("events"):                    # asked again and again for the same ids and nothing ever comes
                fail("peer keeps holding events back")
                return False
            queue += more
        return True

    sm = ask({"t": "summary", "thread": tid, **({"notify_at": notify_at} if notify_at else {})})
    if sm is None:
        return r
    order: list = []
    page, pages = 0, 1
    while page < pages and page < MAX_LIST_PAGES:
        ls = ask({"t": "list", "thread": tid, "page": page})
        if ls is None:
            return r
        if not isinstance(ls.get("ids"), list) or len(ls["ids"]) > LIST_PAGE or type(ls.get("pages")) is not int or ls.get("thread") != tid:
            return fail("bad listing") or r
        order += [i for i in ls["ids"] if is_hex(i, 32)]
        pages = ls["pages"]
        page += 1
        if len(order) > MAX_LIST_IDS:
            return fail("listing too large") or r
    order = list(dict.fromkeys(order))
    r["peer_ids"] = set(order)                                      # what the peer says it holds (M4a: the dialer pushes the difference)
    if tid not in mirror.threads:                                  # the genesis first: its id IS the thread id
        if not fetch([tid]):
            return r
        if tid not in mirror.threads:
            return fail("peer did not send a valid genesis for that thread id") or r
    if not fetch([i for i in order if i not in mirror.threads[tid].stored]):
        return r
    for _ in range(3):                                             # stragglers: ids the events name that the listing did not (or changed meanwhile)
        t = mirror.threads[tid]
        need = [i for i in dict.fromkeys(mirror.missing(tid) + ([sm["head"]] if is_hex(sm.get("head"), 32) else [])) if i not in t.stored]
        if not need or not fetch(need):
            break
    left = [i for i in order if i not in mirror.threads[tid].stored]
    if r["need_keys"]:
        left = left[:max(0, len(left) - len(r["unopened"]))]       # events that arrived as envelopes we cannot open yet are delivered, just locked (need_keys says so)
    if left and r["ok"]:
        fail(f"incomplete: the peer listed {len(left)} event(s) it did not deliver")
    return r


def notify(transport, me: Identity, tid: str, mirror: Mirror, *, peer_id: str | None = None, stamp=time.time, raise_errors: bool = False, detail: bool = False, notify_at: dict | None = None):
    """Tell the peer our leaves so it can decide to pull (a hint; safe to ignore)."""
    t = mirror.threads.get(tid)
    if t is None:
        return None if detail else False
    try:
        req = sign_request(me, {"t": "notify", "thread": tid, "leaves": t.leaves()[-LIST_PAGE:], **({"notify_at": notify_at} if notify_at else {})}, ts=int(stamp()), aud=peer_id)
        resp = transport.request(req)
        if not isinstance(resp, dict) or resp.get("nonce") != req["nonce"] or type(resp.get("r")) is not int or resp["r"] != 1:
            return None if detail else False                      # not an answer to THIS request (a replayed or forged "ok" is no acknowledgement)
        if peer_id is not None and not response_signed_by(resp, peer_id):
            return None if detail else False                      # an impostor behind a wrong address cannot acknowledge for the peer
        kind = resp.get("t")
        return kind if detail else kind == "ok"                    # detail: the answer type ("ok", "unknown" = the peer does not have the thread, ...)
    except Exception:                                              # noqa: BLE001
        if raise_errors:                                           # the node wants to tell "unreachable" from "did not acknowledge"
            raise
        return None if detail else False


class PushResult(dict):
    """What one push exchange did: counters per answer kind, `sent`, `requests`, `retry` (seconds the peer asked us to wait, 0 = none), `unsupported` (the peer answered a type-level error: it does not
    push), `unknown` (it does not have the thread, or does not let us push), `held` (ids the peer answered parked / rejected / unopened: not to be pushed again for a while), `why` when it stopped early."""


def push(mirror: Mirror, tid: str, transport, me: Identity, ids, *, peer_id: str, stamp=time.time, max_requests: int = PUSH_REQUESTS_PER_RUN) -> PushResult:
    """Offer the peer events it lacks (M4a). `ids` = what we hold and the peer's listing did not name; they go in OUR dependency order, genesis never, in requests of at most PUSH_MAX_EVENTS events and
    PUSH_BYTES bytes, at most `max_requests` of them (the rest next cycle). An encrypted thread is pushed as envelopes under each event's own epoch key (events we hold no key for are left out).
    Never raises: a failure is a field of the result, and the pull that came before is untouched."""
    r = PushResult(thread=tid, sent=0, requests=0, accepted=0, duplicate=0, parked=0, rejected=0, unopened=0, deferred=0, retry=0, unsupported=False, unknown=False, held={}, why="")
    t = mirror.threads.get(tid)
    if t is None:
        r["why"] = "thread not held"
        return r
    want = set(ids)
    order = [i for i in t.sync_order() if i in want and i != tid]
    if not order:
        return r
    enc = wire_enc(mirror, t, tid)
    batch, ids_b, size = [], [], 0

    def flush() -> bool:
        """Send the batch; False = stop pushing."""
        nonlocal batch, ids_b, size
        evs, bids, batch, ids_b, size = batch, ids_b, [], [], 0
        if r["requests"] >= max_requests:
            return False
        r["requests"] += 1
        req = sign_request(me, {"t": "push", "thread": tid, "events": evs}, ts=int(stamp()), aud=peer_id)
        try:
            resp = transport.request(req)
        except Exception as e:                                       # noqa: BLE001 - an unreachable peer fails the exchange, never the pull
            r["why"] = f"transport: {type(e).__name__}"
            return False
        if not isinstance(resp, dict) or resp.get("nonce") != req["nonce"] or type(resp.get("r")) is not int or resp["r"] != 1 or not response_signed_by(resp, peer_id):
            r["why"] = not_a_sync_answer(resp, req)
            return False
        kind = resp.get("t")
        if kind == "unknown":
            r["unknown"], r["why"] = True, "the peer does not have this thread or does not take pushes from us"
            return False
        if kind == "error":
            why = _clean(resp.get("why", "error"))
            if why == "rate limited":
                w = resp.get("retry")
                r["retry"], r["why"] = (w if type(w) is int and 0 < w <= 86400 else 60), why
            else:
                r["unsupported"], r["why"] = True, why                # "unknown request type" (an old node) or any other type-level error
            return False
        res = resp.get("results")
        if kind != "pushed" or not isinstance(res, list) or len(res) != len(bids):
            r["unsupported"], r["why"] = True, "bad push answer"
            return False
        r["sent"] += len(bids)
        stopped = False
        for eid, x in zip(bids, res):
            s = x.get("s") if isinstance(x, dict) else None
            if s in ("accepted", "duplicate", "parked", "rejected", "unopened", "deferred"):
                r[s] += 1
                if s in ("parked", "rejected", "unopened"):
                    r["held"][eid] = s
                stopped = stopped or s == "deferred"
        if stopped:
            w = resp.get("retry")
            r["retry"], r["why"] = (w if type(w) is int and 0 < w <= 86400 else 60), "the peer deferred events"
            return False
        return True

    for i in order:
        try:
            item = wire_item(mirror, t, tid, i, t.stored[i], enc)
        except (EnvelopeError, KeyError):
            continue                                                  # no key for that epoch: nothing leaves in plaintext, nothing is sent for it now
        n = len(canon.dumps(item))
        if n > PUSH_BYTES:
            continue                                                  # (cannot travel in one request)
        if batch and (len(batch) >= PUSH_MAX_EVENTS or size + n > PUSH_BYTES):
            if not flush():
                return r
        batch.append(item)
        ids_b.append(i)
        size += n
    if batch:
        flush()
    return r


class Loopback:
    """In-process transport for tests and for two mirrors in one process."""

    def __init__(self, server: SyncServer):
        self.server = server

    def request(self, req: dict) -> dict:
        return canon.loads(canon.dumps(self.server.handle(canon.loads(canon.dumps(req)))))     # through canonical JSON both ways, like a real wire


def fetch_keys(mirror: Mirror, tid: str, transport, me: Identity, *, peer_id: str, need, unopened=(), stamp=time.time) -> dict:
    """Ask `peer_id` for the thread keys we lack (`need` = key ids) and install those that check out. A key is installed only if (a) the answer is signed by the peer we asked,
    (b) that peer is a CURRENT non-guest member in OUR state, (c) its id is an epoch on OUR derived chain, and (d) it carries a confirmation signed by the epoch's creator or an
    owner/admin (opening an envelope would prove nothing: a member can seal under a key of its own). Never raises on a hostile answer."""
    out = {"ok": False, "installed": 0, "rejected": 0, "why": ""}
    t = mirror.threads.get(tid)
    codec = mirror.codec
    if t is None or not hasattr(codec, "ring"):
        out["why"] = "thread unknown or no encrypting codec"
        return out
    ids = sorted(k for k in need if isinstance(k, str) and is_hex(k, 32))[:MAX_IDS]
    if not ids:
        out["why"] = "nothing to ask for"
        return out
    req = sign_request(me, {"t": "key", "thread": tid, "ids": ids}, ts=int(stamp()), aud=peer_id)
    try:
        resp = transport.request(req)
    except Exception as e:                                          # noqa: BLE001
        out["why"] = f"transport: {type(e).__name__}"
        return out
    st = t.state()
    peer = st["members"].get(peer_id)
    if not isinstance(resp, dict) or resp.get("nonce") != req["nonce"] or resp.get("r") != 1 or not response_signed_by(resp, peer_id):
        out["why"] = "answer is not signed by the peer we asked"
        return out
    if peer is None or peer["role"] == "guest":
        out["why"] = "the peer is not a member of the thread in our state"
        return out
    if resp.get("t") != "keys" or resp.get("thread") != tid or not isinstance(resp.get("keys"), list) or len(resp["keys"]) > MAX_IDS:
        out["why"] = _clean(resp.get("why", resp.get("t")))
        return out
    chain = set(chain_epoch_ids(t))
    ring = codec.ring(tid)
    for k in resp["keys"]:
        try:
            kid = k["id"]
            if kid not in chain or kid not in ids:
                out["rejected"] += 1
                continue
            key = open_key(me, tid, kid, k["sealed"])
        except (EnvelopeError, KeyError, TypeError):
            out["rejected"] += 1
            continue
        conf = k.get("conf") if isinstance(k, dict) else None
        if not check_confirmation(t, kid, key, conf):
            out["rejected"] += 1                                    # not signed for this epoch by its creator (or an owner/admin): a member's own key is not the epoch's key
            continue
        try:
            if ring.install(kid, key, verified=True, conf=conf):
                out["installed"] += 1
        except EnvelopeError:
            out["rejected"] += 1
    if out["installed"] and hasattr(codec, "mark"):
        codec.mark(tid)
    out["ok"] = True
    return out
