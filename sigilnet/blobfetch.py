"""Fetching a blob from peers (DESIGN_blobs.md rev 1): the client side of the `blob` op. Only ever called on purpose (`blob get`), never by an event.

Policy before a single byte moves: the cid must be referenced by a live (resolved, non-voided) event of the thread; its declared stored size must be within
max_blob_bytes; the store must have room (make_room). Then, for each peer in order that is not banned for this cid:

  * every answer must be signed by that peer, bound to our nonce, name our thread/cid/offset, carry the declared `total`, strict base64, and no more bytes than asked;
  * ENCRYPTED threads (private + encrypted at rest here): the first request asks for the header only, so a declared size that cannot be a canonical blob of that
    chunk size is refused before any bulk moves; the blob must parse as a sealed blob (blob.py) whose key id we hold a VERIFIED key for, and EVERY chunk is
    authenticated on arrival; only verified whole chunks are written to the partial, the first bad chunk bans that peer for this cid and the partial survives (it is
    verified data), so the next peer continues from the same offset;
  * PLAIN blobs (public threads) have no per-chunk check in v1: the final sha256 decides; a mismatch deletes the partial and bans the peer;
  * a timeout halves the chunk size (down to MIN_CHUNK) and retries the same offset; "unknown" / no data / transport errors move on to the next peer without a ban;
  * own limits: requests <= size/MIN_CHUNK + slack, a total deadline that scales with the size.
The result lands in the store (published atomically, size and sha256 checked); decrypting to a file is a separate step."""
from __future__ import annotations

import base64
import binascii
import time

import os

from . import blob as B
from . import pow as P
from . import publicblob as PB
from . import sync as S
from .blobserve import MAX_CHUNK
from .blobstore import QuotaError, StoreError, TooBig

DEFAULT_CHUNK = 128 * 1024
MIN_CHUNK = 16 * 1024
SLACK_REQUESTS = 40
BASE_DEADLINE = 120.0
SLOW_BYTES_PER_SEC = 8 * 1024          # the deadline assumes at least this much throughput
MAX_FAILS_AT_MIN = 3


class FetchResult(dict):
    pass


def _timed(res, dt: float) -> None:
    """Per-fetch timing for the node log (live-test gap: a slow door could not be told from halving). ask_secs = time spent waiting for answers, ask_max = the slowest one."""
    res["ask_secs"] += max(0.0, dt)
    res["ask_max"] = max(res["ask_max"], dt)


class _Bad(Exception):
    """The peer served something wrong (ban it for this cid)."""


class _Skip(Exception):
    """This peer cannot serve it right now (no ban)."""


def _decode(data, n: int) -> bytes:
    if not isinstance(data, str) or len(data) > 4 * ((n + 2) // 3) + 4:
        raise _Bad("data too long")
    try:
        raw = base64.b64decode(data.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise _Bad("data is not base64") from None
    if len(raw) > n:
        raise _Bad("more data than asked")
    return raw


class SignedSource:
    """A peer reached over the signed sync channel (members): every answer must be signed by `peer_id` and bound to our nonce."""

    def __init__(self, peer_id: str, transport, me, stamp=time.time):
        self.id, self.transport, self.me, self.stamp = peer_id, transport, me, stamp

    def ask(self, tid, cid, offset, n) -> dict:
        req = S.sign_request(self.me, {"t": "blob", "thread": tid, "cid": cid, "offset": offset, "n": n}, ts=int(self.stamp()), aud=self.id)
        resp = self.transport.request(req)
        if not isinstance(resp, dict) or resp.get("nonce") != req["nonce"] or type(resp.get("r")) is not int or resp["r"] != 1 \
                or not S.response_signed_by(resp, self.id):
            raise _Skip("answer is not signed by the peer we asked")
        return resp


class PublicSource:
    """A read door of a PUBLIC thread: unsigned, so the answer is only bound to our nonce (integrity comes from the final sha256); the door asks for a proof of
    work that grows with the chunk size; the challenge is cached until the door says it went stale."""

    def __init__(self, transport, name: str, max_bits: int = PB.MAX_BITS):
        self.id, self.transport, self.max_bits = name, transport, max_bits
        self._chal: dict = {}

    def _call(self, body: dict) -> dict:
        req = {**body, "nonce": os.urandom(8).hex()}
        resp = self.transport.request(req)
        if not isinstance(resp, dict) or resp.get("nonce") != req["nonce"] or type(resp.get("r")) is not int or resp["r"] != 1:
            raise _Skip("answer does not answer this request")
        return resp

    def _challenge(self, tid, cid, offset, n) -> tuple:
        resp = self._call({"t": "blob", "thread": tid, "cid": cid, "offset": offset, "n": n})
        if resp.get("t") != "challenge" or not isinstance(resp.get("salt"), str) or type(resp.get("bits")) is not int:
            raise _Skip(f"door answered {S._clean(resp.get('t'))} to a challenge request")
        if not 0 <= resp["bits"] <= self.max_bits:
            raise _Skip("the door asks for more proof of work than we will do")
        try:
            return bytes.fromhex(resp["salt"]), resp["bits"]
        except ValueError:
            raise _Skip("bad challenge") from None

    def ask(self, tid, cid, offset, n) -> dict:
        for attempt in range(2):
            if self._chal.get(n) is None:
                self._chal[n] = self._challenge(tid, cid, offset, n)
            salt, bits = self._chal[n]
            nonce = os.urandom(8).hex()
            nonce_int = P.solve(salt, tid, "", PB.binding(cid, offset, n, nonce), bits)
            req = {"t": "blob", "thread": tid, "cid": cid, "offset": offset, "n": n, "nonce": nonce, "pow": {"salt": salt.hex(), "nonce": nonce_int}}
            resp = self.transport.request(req)
            if not isinstance(resp, dict) or resp.get("nonce") != nonce or type(resp.get("r")) is not int or resp["r"] != 1:
                raise _Skip("answer does not answer this request")
            if resp.get("t") == "stale" and attempt == 0:
                self._chal.pop(n, None)                            # the salt rotated: fetch a new challenge once
                continue
            return resp
        raise _Skip("the door keeps calling our proof stale")


def fetch(mirror, store, index, tid: str, cid: str, peers, me, *, referenced, chunk: int = DEFAULT_CHUNK, bans=None, clock=time.time,
          stamp=time.time, sleep=time.sleep) -> FetchResult:
    """peers = [(peer_id, transport)] in the order to try. `bans` (a set kept by the caller across calls) collects (peer_id, cid) pairs. Never raises on a hostile peer."""
    res = FetchResult(ok=False, why="", peer=None, bytes=0, requests=0, halvings=0, ask_secs=0.0, ask_max=0.0)

    def fail(why):
        res["why"] = why
        return res

    try:
        B.check_cid(cid)
    except B.BlobError:
        return fail("bad cid")
    t = mirror.threads.get(tid)
    if t is None:
        return fail("unknown thread")
    sizes = index.live(tid, cid)
    if not sizes:
        return fail("not referenced by a live event of this thread")
    if store.has(cid) and store.size(cid) in sizes:
        res.update(ok=True, why="already held")
        return res
    sizes = [s for s in sizes if s <= store.max_blob]
    if not sizes:
        return fail("declared size exceeds max_blob_bytes")
    if len(sizes) > 1:
        return fail("conflicting declared sizes")                 # two live events disagree: nothing to trust
    size = sizes[0]
    bans = bans if bans is not None else set()
    codec = mirror.codec
    enc = t.state()["visibility"] == "private" and codec.is_encrypted(tid)
    if enc and size < B.HEADER_LEN + B.TAG:
        return fail("declared size is not a valid stored size")
    ring = codec.ring(tid) if enc else None

    def root_for(kid):
        got = ring.get(kid) if ring is not None else None
        return got[0] if got is not None and got[1] else None

    part = store.tmp / (B.cid_hex(cid) + ".part")
    try:
        if not enc:
            part.unlink(missing_ok=True)                           # a plain partial has no verified prefix and unknown provenance: never continued, not even from disk
        kept = part.stat().st_size if part.exists() else 0         # (encrypted: re-verified below) the kept partial is already in usage(): only the rest needs room
        store.make_room(max(0, size - kept), referenced)
        inc = store.begin(cid, size=size, resume=enc)
    except QuotaError:
        return fail("no room in the blob store")
    except (TooBig, StoreError) as e:
        return fail(f"store: {e}")

    deadline_at = clock() + BASE_DEADLINE + size / SLOW_BYTES_PER_SEC
    max_requests = size // MIN_CHUNK + SLACK_REQUESTS
    state = {"opener": None, "buf": b"", "units": 0, "pos": 0, "writer": None}   # pos: where the next byte to ask for starts (verified + buffered)

    def reset_encrypted():
        state.update(opener=None, buf=b"", units=0, pos=inc.offset if inc is not None else 0)

    def drop_unverified():
        """Forget bytes that were received but not yet authenticated (a peer switch, a ban): continue from the last verified byte. A failed AEAD check killed the
        opener, so a new one is built by re-verifying the kept chunks (they are on disk; this costs one pass over them)."""
        nonlocal inc
        state.update(buf=b"", opener=None, units=0, pos=inc.offset)
        if inc.offset and not verify_kept_prefix():
            inc.abort()
            inc = None
            state["pos"] = 0

    def verify_kept_prefix():
        """Resuming an encrypted partial: re-verify every kept chunk (the file is only a claim until it passes AEAD again)."""
        if not enc or inc.offset == 0:
            return True
        try:
            raw = inc.path.read_bytes()[:inc.offset]
            hdr = B.parse_header(raw)
            root = root_for(hdr.kid_hex)
            if root is None:
                return False
            op = B.Opener(hdr, size, root, tid)
            pos = B.HEADER_LEN
            while pos < len(raw):
                ln = op.sealed_len(state["units"])
                op.feed(raw[pos:pos + ln])
                state["units"] += 1
                pos += ln
            if pos != len(raw):
                return False
            state["opener"] = op
            state["pos"] = inc.offset
            return True
        except (B.BlobError, OSError, IndexError):
            return False

    if enc and not verify_kept_prefix():
        inc.abort()
        inc = store.begin(cid, size=size, resume=False)
        reset_encrypted()

    def take(data: bytes, pos: int) -> None:
        """Feed bytes that start at `pos` (== offset + buffered). Plain: write through. Encrypted: verify whole chunks, write only verified ones."""
        if not enc:
            state["writer"] = state["writer"] or cur_peer[0]
            inc.write(data)
            return
        state["buf"] += data
        if state["opener"] is None:
            if len(state["buf"]) < B.HEADER_LEN:
                return
            try:
                hdr = B.parse_header(state["buf"])
            except B.BlobError as e:
                raise _Bad(f"bad header: {e}") from None
            root = root_for(hdr.kid_hex)
            if root is None:
                raise _Skip("no verified key for this blob's key id")
            try:
                state["opener"] = B.Opener(hdr, size, root, tid)
            except B.BlobError as e:                               # the declared size does not fit this header: the author's size or the peer's header is wrong, we cannot tell which
                raise _Skip(f"declared size does not fit the blob header: {e}") from None
            state["head"] = state["buf"][:B.HEADER_LEN]
            state["buf"] = state["buf"][B.HEADER_LEN:]
        op = state["opener"]
        while not op.done:
            ln = op.sealed_len(state["units"])
            if len(state["buf"]) < ln:
                return
            ct, state["buf"] = state["buf"][:ln], state["buf"][ln:]
            try:
                op.feed(ct)
            except B.BlobError as e:
                raise _Bad(f"chunk {state['units']}: {e}") from None
            if state["units"] == 0:
                inc.write(state.pop("head") + ct)                # the header is written together with the chunk that authenticated it
            else:
                inc.write(ct)
            state["units"] += 1
        if state["buf"]:
            raise _Bad("data after the final chunk")

    cur_peer = [None]

    def from_peer(src) -> bool:
        nonlocal chunk
        n_now = max(MIN_CHUNK, min(chunk, MAX_CHUNK))
        fails = 0
        while True:
            have = state["pos"] if enc else inc.offset
            if have >= size:
                return True
            if clock() > deadline_at:
                raise _Skip("deadline exceeded")
            if res["requests"] >= max_requests:
                raise _Skip("too many requests")
            n = min(n_now, size - have)
            if enc and state["opener"] is None and have == 0:
                n = B.HEADER_LEN                                   # header first: the layout is checked against the declared size before any bulk is asked for
            res["requests"] += 1
            t0 = clock()
            try:
                resp = src.ask(tid, cid, have, n)
            except _Skip:
                raise
            except Exception as e:                                 # noqa: BLE001 - a transport failure is just "unreachable / slow"
                _timed(res, clock() - t0)
                fails += 1
                if n_now > MIN_CHUNK:
                    n_now = max(MIN_CHUNK, n_now // 2)             # a timeout: ask for less next time
                    res["halvings"] += 1
                    fails = 0
                    continue
                if fails >= MAX_FAILS_AT_MIN:
                    raise _Skip(f"transport: {type(e).__name__}") from None
                continue
            _timed(res, clock() - t0)
            kind = resp.get("t")
            if kind == "error" and resp.get("why") == "rate limited":
                sleep(1.5)
                fails += 1
                if fails >= MAX_FAILS_AT_MIN * 4:
                    raise _Skip("rate limited")
                continue
            if kind != "blobdata":
                raise _Skip(f"peer answered {S._clean(kind)}")
            if resp.get("thread") != tid or resp.get("cid") != cid or resp.get("offset") != have or type(resp.get("total")) is not int or resp["total"] != size:
                raise _Bad("answer does not match the request")
            data = _decode(resp.get("data"), n)
            if not data:
                raise _Skip("peer returned no data")
            fails = 0
            res["bytes"] += len(data)
            if enc:
                state["pos"] += len(data)
            take(data, have)

    sources = [p if hasattr(p, "ask") else SignedSource(p[0], p[1], me, stamp) for p in peers]
    for src in sources:
        peer_id = src.id
        if (peer_id, cid) in bans:
            continue
        if inc is None:
            try:
                inc = store.begin(cid, size=size, resume=False)
            except StoreError as e:
                return fail(f"store: {e}")
        if enc and (state["buf"] or state["opener"] is not None):
            drop_unverified()                                      # unverified bytes of the previous peer are never blamed on this one
            if inc is None:
                inc = store.begin(cid, size=size, resume=False)
        res["peer"] = peer_id
        cur_peer[0] = peer_id
        if not enc and inc.offset and state["writer"] != peer_id:
            inc.abort()                                            # a partial written by another peer is never continued (it could be garbage we cannot attribute)
            try:
                inc = store.begin(cid, size=size, resume=False)
            except StoreError as e:
                return fail(f"store: {e}")
            state["writer"] = None
        try:
            from_peer(src)
            try:
                if enc:
                    state["opener"].finish()
                got = inc.commit(expect_cid=cid, expect_size=size, referenced=referenced)
            except B.BlobError as e:
                raise _Bad(f"incomplete or invalid: {e}") from None
            except StoreError as e:
                raise _Bad(f"stored bytes do not match the cid: {e}") from None
            res.update(ok=True, why="", cid=got)
            return res
        except _Skip as e:
            res["why"] = str(e)
        except _Bad as e:
            bans.add((peer_id, cid))
            res["why"] = f"banned peer: {e}"
            if enc and not inc._closed:
                drop_unverified()                                  # verified chunks stay in the partial: the next peer continues from there
            else:
                inc.abort()                                        # plain (no per-chunk check): the partial cannot be trusted, start clean
                inc = None
                state["writer"] = None
                reset_encrypted()
        except StoreError as e:
            inc.abort()
            return fail(f"store: {e}")
    if inc is not None and not inc._closed:
        inc.keep() if enc else inc.abort()                         # encrypted partials hold only verified chunks and resume; a plain one is thrown away
    res["why"] = res["why"] or "no peer could serve it"
    return res
