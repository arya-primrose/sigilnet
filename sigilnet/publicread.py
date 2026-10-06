"""The READ door of a public thread (spec 5.1, revision 1): unsigned, read-only, deterministic, no model behind it.

Anyone who knows the onion address may ask for `summary`, `list` or `get` of a PUBLIC thread. Nothing else is answered (no `notify`, nothing that
writes), there is no nonce store for strangers (every answer is idempotent, so memory does not grow with callers), pages are the normal bounded ones, and
there is a global budget for requests and bytes per minute (Tor hides the client's address, so there is no per-client limit to apply). A thread that is
private and a thread that does not exist get the same answer. Requests may carry sync signature fields (the normal client always sends them): they are
ignored here, not trusted; the answer is only ever public data whose integrity comes from the events' own signatures.
"""
from __future__ import annotations

import threading
import time
from collections import deque

from . import canon
from .sync import SyncServer

READ_TYPES = frozenset({"summary", "list", "get"})
ALLOWED = frozenset({"t", "thread", "page", "ids", "nonce", "from", "pub", "ts", "sig", "aud"})
REQ_PER_MIN = 600
BYTES_PER_MIN = 40_000_000


class PublicRead:
    def __init__(self, srv: SyncServer, *, clock=time.time, req_per_min: int = REQ_PER_MIN, bytes_per_min: int = BYTES_PER_MIN, blobs=None):
        self.srv, self.clock = srv, clock
        self.blobs = blobs                                          # publicblob.PublicBlob or None: blobs have their OWN budgets, they never spend the read ones
        self.req_per_min, self.bytes_per_min = req_per_min, bytes_per_min
        self.hits: deque = deque()
        self.sent: deque = deque()                                  # (time, bytes)
        self.mu = threading.Lock()

    def _budget(self) -> bool:
        now = self.clock()
        with self.mu:
            while self.hits and now - self.hits[0] >= 60:
                self.hits.popleft()
            while self.sent and now - self.sent[0][0] >= 60:
                self.sent.popleft()
            if len(self.hits) >= self.req_per_min or sum(n for _, n in self.sent) >= self.bytes_per_min:
                return False
            self.hits.append(now)
            return True

    def handle(self, req) -> dict:
        try:
            return self._handle(req)
        except Exception:                                            # noqa: BLE001 - a stranger's frame must never take the door down
            return self.srv._err(req, "internal")

    def _handle(self, req) -> dict:
        if isinstance(req, dict) and req.get("t") == "blob":
            return self.blobs.handle(req) if self.blobs is not None else self.srv._err(req, "malformed request")
        if not isinstance(req, dict) or not set(req) <= ALLOWED or req.get("t") not in READ_TYPES or not isinstance(req.get("nonce"), str) \
                or len(req["nonce"]) != 16:
            return self.srv._err(req, "malformed request")
        if not self._budget():
            return self.srv._err(req, "rate limited")
        tid = req.get("thread")
        m = self.srv.m
        with m._lock():
            m._discover()
            for i in list(m.threads):
                m._refresh(i)
            t = m.threads.get(tid) if isinstance(tid, str) else None
            if t is None or t.state()["visibility"] != "public":
                resp = self.srv._reply(req, {"t": "unknown"})         # one answer for "private" and "not here"
            else:
                resp = self.srv._answer(req, tid)
        try:
            n = len(canon.dumps(resp))
        except canon.CanonError:
            n = 0
        with self.mu:
            self.sent.append((self.clock(), n))
        return resp
