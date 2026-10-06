"""Blobs of a PUBLIC thread through the unauthenticated read door (DESIGN_blobs.md rev 1, finding 2). Unsigned requests mean no per-client limit exists (Tor hides
the client), so the door prices and bounds the work instead:

    request   {"t": "blob", "thread", "cid", "offset", "n", "nonce"[, "pow": {"salt": hex, "nonce": int}]}
    no pow    -> {"t": "challenge", "salt", "bits", "expires"}    the same bytes for ANY thread/cid (it says nothing about what exists); bits grow with n
    with pow  -> the chunk (same `blobdata` shape as the member op) or {"t": "unknown"} (private / not here / unreferenced / voided / not held: ONE answer)
The proof binds salt, thread, cid, offset, n and the request nonce, and a bounded set of used proofs refuses an immediate replay. Costs are bounded separately from
summary/list/get: its own request and byte budgets per minute (a download cannot starve reads) and a hard cap on concurrent requests. A proof only slows a flood
down (10..14 bits is milliseconds: one client CAN still saturate the request budget with proofs; the budgets bound the damage, they do not make it fair, and
unauthenticated Tor clients give no per-client key). Challenges are not charged, only proof-bearing requests are, after the proof verified."""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import threading
import time
from collections import OrderedDict, deque

from . import blob as B
from . import canon
from . import pow as P
from .blobserve import MAX_CHUNK

ALLOWED = frozenset({"t", "thread", "cid", "offset", "n", "nonce", "pow"})
PERIOD = 3600
SALT_CTX = b"sigilnet/v1/read-salt\0"
BASE_BITS = 10
MIN_N = 16 * 1024
MAX_BITS = 22                         # what a client is willing to solve; the server never asks for more
REQ_PER_MIN = 300
BYTES_PER_MIN = 24 * 1024 * 1024
MAX_CONCURRENT = 4
MAX_SEEN = 4096


def bits_for(n: int, base: int = BASE_BITS) -> int:
    """10 bits at 16 KiB, +1 per doubling: 256 KiB = 14 bits."""
    return min(MAX_BITS, base + max(0, math.ceil(math.log2(max(n, MIN_N) / MIN_N))))


def binding(cid: str, offset: int, n: int, nonce: str) -> str:
    return f"blob:{cid}:{offset}:{n}:{nonce}"


class PublicBlob:
    def __init__(self, srv, svc, *, clock=time.time, secret: bytes | None = None, base_bits: int = BASE_BITS, req_per_min: int = REQ_PER_MIN,
                 bytes_per_min: int = BYTES_PER_MIN, max_concurrent: int = MAX_CONCURRENT):
        self.srv, self.svc, self.clock = srv, svc, clock
        self.secret = secret or os.urandom(32)                      # per process: a restart only means challenges are fetched again
        self.base_bits, self.req_per_min, self.bytes_per_min = base_bits, req_per_min, bytes_per_min
        self.sem = threading.BoundedSemaphore(max_concurrent)
        self.mu = threading.Lock()
        self.hits: deque = deque()
        self.sent: deque = deque()
        self.seen: OrderedDict = OrderedDict()

    def salt(self, period: int) -> bytes:
        return hmac.new(self.secret, SALT_CTX + str(period).encode(), hashlib.sha256).digest()[:16]

    def period(self) -> int:
        return int(self.clock() // PERIOD)

    def _challenge(self, n: int) -> dict:
        p = self.period()
        return {"t": "challenge", "salt": self.salt(p).hex(), "bits": bits_for(n, self.base_bits), "expires": (p + 2) * PERIOD}

    def _budget(self) -> bool:
        now = self.clock()
        with self.mu:
            while self.hits and now - self.hits[0] >= 60:
                self.hits.popleft()
            while self.sent and now - self.sent[0][0] >= 60:
                self.sent.popleft()
            if len(self.hits) >= self.req_per_min or sum(b for _, b in self.sent) >= self.bytes_per_min:
                return False
            self.hits.append(now)
            return True

    def _used(self, key) -> bool:
        with self.mu:
            if key in self.seen:
                return True
            self.seen[key] = 1
            while len(self.seen) > MAX_SEEN:
                self.seen.popitem(last=False)
            return False

    def handle(self, req: dict) -> dict:
        err = self.srv._err
        if not isinstance(req, dict) or not set(req) <= ALLOWED or not isinstance(req.get("nonce"), str) or len(req["nonce"]) != 16 \
                or not isinstance(req.get("thread"), str) or not isinstance(req.get("cid"), str) or type(req.get("offset")) is not int \
                or type(req.get("n")) is not int or ("pow" in req and not isinstance(req["pow"], dict)):
            return err(req, "malformed request")
        off, n = req["offset"], req["n"]
        if off < 0 or not 1 <= n <= MAX_CHUNK:
            return err(req, "bad range")
        if "pow" not in req:
            return self.srv._reply(req, self._challenge(n))
        pw = req["pow"]
        if set(pw) != {"salt", "nonce"} or not isinstance(pw["salt"], str) or len(pw["salt"]) != 32:
            return err(req, "bad proof")
        try:
            salt = bytes.fromhex(pw["salt"])
        except ValueError:
            return err(req, "bad proof")
        p = self.period()
        if salt not in (self.salt(p), self.salt(p - 1)):
            return self.srv._reply(req, {**self._challenge(n), "t": "stale"})
        bits = bits_for(n, self.base_bits)
        if not P.verify(salt, req["thread"], "", binding(req["cid"], off, n, req["nonce"]), pw["nonce"], bits):
            return err(req, "bad proof")
        if not self._budget():                                      # charged only for a request that SOLVED a proof (a challenge costs us one HMAC and is not charged)
            return err(req, "rate limited")
        if self._used((salt, req["nonce"], pw["nonce"])):
            return err(req, "replayed proof")
        if not self.sem.acquire(blocking=False):
            return err(req, "busy")
        try:
            return self._serve(req)
        finally:
            self.sem.release()

    def _serve(self, req: dict) -> dict:
        m, tid = self.srv.m, req["thread"]
        with m._lock():
            m._discover()
            m._refresh(tid)
            t = m.threads.get(tid)
            ok = False
            if t is not None and t.state()["visibility"] == "public":
                try:
                    ok = bool(B.check_cid(req["cid"]) and self.svc.index.live(tid, req["cid"]))
                except B.BlobError:
                    ok = False
        resp = self.svc.serve({"from": "public", "thread": tid, "offset": req["offset"], "n": req["n"]}, req["cid"]) if ok else None
        if resp is None:
            return self.srv._reply(req, {"t": "unknown"})
        if resp["t"] == "blobdata":
            with self.mu:
                self.sent.append((self.clock(), len(canon.dumps(resp))))
        return self.srv._reply(req, resp)
