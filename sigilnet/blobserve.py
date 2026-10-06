"""Serving blobs to members over the signed sync channel (DESIGN_blobs.md rev 1). The op:

    request   {"t": "blob", "thread": tid, "cid": "sha256:..", "offset": int, "n": 1..MAX_CHUNK}      (signed, audience-bound like every sync request)
    response  {"t": "blobdata", "thread": tid, "cid": .., "offset": int, "total": int, "data": base64}   (n may come back shorter; "" at the end)

Gate, in this order, and EVERY failure of it is the stranger's answer `{"t": "unknown"}`: the thread is here, the requester is a CURRENT, non-guest member
whose key is the one on the chain (removed members and observers-who-are-guests are out), the cid is referenced by a resolved NON-voided event of that thread
(BlobIndex), and we hold the bytes. Only after the gate do range errors exist, so a stranger can not tell a missing blob from a blob it may not have.
The read itself happens outside the mirror lock. Blob requests are charged to their OWN request and byte budgets (they never eat the pull budgets, and a
download cannot starve a pull). Per requester the budgets are charged before the gate; the GLOBAL ones only for requests that passed it (a stranger can mint
keys at will and must not be able to spend what members need)."""
from __future__ import annotations

import base64
import threading
from collections import deque

from . import blob as B
from .keys import is_hex

MAX_CHUNK = 256 * 1024
PEER_BYTES_PER_MIN = 64 * 1024 * 1024
GLOBAL_BYTES_PER_MIN = 256 * 1024 * 1024
PEER_REQS_PER_MIN = 600
GLOBAL_REQS_PER_MIN = 3000
MAX_TRACKED = 1024
UNVETTED_PER_MIN = 120                  # requests per minute from requesters not in the member snapshot that may take the mirror lock (members never touch this)


class BlobService:
    def __init__(self, store, index, *, clock=None, peer_bytes=PEER_BYTES_PER_MIN, total_bytes=GLOBAL_BYTES_PER_MIN, peer_reqs=PEER_REQS_PER_MIN,
                 total_reqs=GLOBAL_REQS_PER_MIN, unvetted_per_min=UNVETTED_PER_MIN, log=None):
        import time
        self.store, self.index, self.clock = store, index, clock or time.time
        self.peer_bytes, self.total_bytes, self.peer_reqs, self.total_reqs = peer_bytes, total_bytes, peer_reqs, total_reqs
        self._mu = threading.Lock()
        self._peer_q: dict = {}                  # agent -> deque[t] of requests
        self._peer_b: dict = {}                  # agent -> deque[(t, bytes)] of bytes served
        self._all_q: deque = deque()
        self._all_b: deque = deque()
        self._unvetted: deque = deque()
        self.unvetted_per_min = unvetted_per_min
        self.log = log                           # optional one-line sink (the node's log): the first and the last chunk of each blob served, never content
        self._snap: dict = {}                    # tid -> {agent id: sign pub} of current non-guest members (a lock-free HINT; the gate under the lock stays authoritative)

    # ---------------------------------------------------------------- budgets
    @staticmethod
    def _prune(q: deque, now: float, key=lambda x: x) -> None:
        while q and now - key(q[0]) >= 60:
            q.popleft()

    def charge_request(self, agent: str) -> bool:
        """BEFORE the gate: only the requester's OWN buckets (requests and bytes per minute). A stranger can mint any number of keys, so nothing a stranger does may
        spend the global budgets that members need; False = this requester is rate limited."""
        now = self.clock()
        with self._mu:
            pq, pb = self._peer_q.setdefault(agent, deque()), self._peer_b.setdefault(agent, deque())
            self._prune(pq, now)
            self._prune(pb, now, lambda x: x[0])
            if len(pq) >= self.peer_reqs or sum(n for _, n in pb) >= self.peer_bytes:
                return False
            pq.append(now)
            if len(self._peer_q) > MAX_TRACKED:
                self._peer_q = {k: v for k, v in self._peer_q.items() if v and now - v[-1] < 60}
                self._peer_b = {k: v for k, v in self._peer_b.items() if v and now - v[-1][0] < 60}
            return True

    def note_thread(self, t) -> None:
        """Refresh the member snapshot of thread `t` (call with the thread's state in hand: under the mirror lock, or from a request that already holds it)."""
        self._snap[t.id] = {a: m["sign"] for a, m in t.state()["members"].items() if m["role"] != "guest"}

    def vetted(self, tid, agent, pub) -> bool:
        """Is the requester a member in the LAST snapshot? Reads one dict, takes no lock. A stale 'yes' (since removed) only costs one trip through the real gate."""
        snap = self._snap.get(tid)
        return snap is not None and snap.get(agent) == pub

    def charge_unvetted(self) -> bool:
        """A requester that is not in the snapshot (a stranger, or a member added since) may reach the mirror lock only within this small GLOBAL budget; over it the
        answer is `unknown` without taking any lock. Members in the snapshot never touch it."""
        now = self.clock()
        with self._mu:
            self._prune(self._unvetted, now)
            if len(self._unvetted) >= self.unvetted_per_min:
                return False
            self._unvetted.append(now)
            return True

    def admit_member(self) -> bool:
        """AFTER the gate (members only): the global request and byte budgets. False = the node is busy serving blobs, try again."""
        now = self.clock()
        with self._mu:
            self._prune(self._all_q, now)
            self._prune(self._all_b, now, lambda x: x[0])
            if len(self._all_q) >= self.total_reqs or sum(n for _, n in self._all_b) >= self.total_bytes:
                return False
            self._all_q.append(now)
            return True

    def _charge_bytes(self, agent: str, n: int) -> None:
        now = self.clock()
        with self._mu:
            self._peer_b.setdefault(agent, deque()).append((now, n))
            self._all_b.append((now, n))

    # ---------------------------------------------------------------- the gate (called under the mirror lock) and the read (outside it)
    def gate(self, t, req: dict):
        """(cid) if the requester may have it, else None. Cheap and the same steps for every refusal."""
        st = t.state()
        m = st["members"].get(req["from"])
        cid = req.get("cid")
        ok = m is not None and m["role"] != "guest" and m["sign"] == req["pub"]
        try:
            B.check_cid(cid)
            live = self.index.live(t.id, cid)
        except B.BlobError:
            live = []
        return cid if ok and live else None

    def serve(self, req: dict, cid: str):
        """The response body for a request that passed the gate, or None (we do not hold it: the stranger's answer)."""
        total = self.store.size(cid)
        if total is None:
            return None
        off, n = req.get("offset"), req.get("n")
        if type(off) is not int or type(n) is not int or off < 0 or off > total or not 1 <= n <= MAX_CHUNK:
            return {"t": "error", "why": "bad range"}
        data = self.store.read(cid, off, min(n, MAX_CHUNK))
        if data is None:
            return None
        self._charge_bytes(req["from"], len(data))
        if self.log is not None and (off == 0 or off + len(data) >= total):
            try:
                who = "public" if req["from"] == "public" else str(req["from"])[:8]
                self.log(f"  blob serve {cid[:19]}.. to {who}: offset {off}, {len(data)} of {total} byte(s){' (last chunk)' if off + len(data) >= total else ''}")
            except Exception:                    # noqa: BLE001 - a logging problem never changes an answer
                pass
        return {"t": "blobdata", "thread": req["thread"], "cid": cid, "offset": off, "total": total, "data": base64.b64encode(data).decode("ascii")}
