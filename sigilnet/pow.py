"""Proof of work for the guest inbox (spec 5.1). Pure functions, no I/O. The hash binds the proof to one salt, one thread, one guest key and one request,
so a proof cannot be reused for another request, another thread or another salt."""
from __future__ import annotations

import hashlib
import os

MAX_BITS = 40
MAX_NONCE = 2 ** 63
_CTX = b"sigilnet/v1/guest-pow\0"
KNOCK_CTX = b"sigilnet/v1/knock-pow\0"       # a proof made for a guest request is worthless for a knock and the other way round (domain separation)


def _digest(salt: bytes, thread: str, sign_pub: str, event_id: str, nonce: int, ctx: bytes = _CTX) -> bytes:
    h = hashlib.sha256(ctx)
    for part in (salt, thread.encode(), sign_pub.encode(), event_id.encode()):
        h.update(len(part).to_bytes(2, "big"))              # length-prefixed: no two different tuples hash the same bytes
        h.update(part)
    h.update(nonce.to_bytes(8, "big"))
    return h.digest()


def leading_zero_bits(d: bytes) -> int:
    n = int.from_bytes(d, "big")
    return len(d) * 8 - n.bit_length()


def achieved(salt: bytes, thread: str, sign_pub: str, event_id: str, nonce, ctx: bytes = _CTX) -> int:
    """Leading zero bits of this proof, or -1 if the nonce is not a valid one."""
    if type(nonce) is not int or not 0 <= nonce < MAX_NONCE or not isinstance(salt, bytes) or not 8 <= len(salt) <= 64:
        return -1
    return leading_zero_bits(_digest(salt, thread, sign_pub, event_id, nonce, ctx))


def verify(salt: bytes, thread: str, sign_pub: str, event_id: str, nonce, bits: int, ctx: bytes = _CTX) -> bool:
    return 0 <= bits <= MAX_BITS and achieved(salt, thread, sign_pub, event_id, nonce, ctx) >= bits


def solve(salt: bytes, thread: str, sign_pub: str, event_id: str, bits: int, *, start: int | None = None, max_tries: int = 1 << 34, ctx: bytes = _CTX) -> int:
    """Find a nonce with at least `bits` leading zero bits (expected 2**bits hashes). Starts at a random point so two solvers do not repeat work.
    The result always satisfies `verify`: the search stays inside the valid nonce range (it wraps once)."""
    if not 0 <= bits <= MAX_BITS:
        raise ValueError("bits out of range")
    if start is not None and type(start) is not int:
        raise ValueError("start must be an integer")
    n = int.from_bytes(os.urandom(6), "big") if start is None else start % MAX_NONCE
    for k in range(max_tries):
        c = (n + k) % MAX_NONCE
        if leading_zero_bits(_digest(salt, thread, sign_pub, event_id, c, ctx)) >= bits:
            return c
    raise RuntimeError("no proof found within max_tries")
