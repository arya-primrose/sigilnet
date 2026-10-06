"""Blob format (DESIGN_blobs.md rev 1): pure functions, no I/O policy, no network, no store.

cid = "sha256:" + hex(sha256(STORED bytes)); the fetcher checks it before it decrypts or uses anything.
A PUBLIC thread's blob is stored as the file itself (no header). An ENCRYPTED thread's blob is

    header (HEADER_LEN bytes)  +  chunk_0 + ... + chunk_{n-1}          each chunk = ciphertext || 16-byte Poly1305 tag

    header = MAGIC(4) | version(1) | flags(1, must be 0) | chunk(4, big endian: plaintext bytes per full chunk) | salt(16) | nonce_prefix(8) | kid(16)

kid is the raw id of the epoch-creating event (the key id of the keyring), so the reader looks the key up by kid and never infers an epoch.
The chunk key = HKDF-SHA256(epoch key, salt = header salt, info = BLOB_CTX || thread id || 0 || kid). The salt, not the cid, feeds the key: the cid
is the hash of the result, so deriving from it would be circular.
STREAM construction: nonce = nonce_prefix || 4-byte chunk counter; AAD = BLOB_CTX || thread id || 0 || header || 8-byte chunk index || final flag (0/1).
So a truncated blob (the last chunk was not sealed final), two swapped chunks, a changed header, a blob moved to another thread, and any flipped bit all fail.
Chunks 0..n-2 carry exactly `chunk` plaintext bytes; the final chunk carries 1..chunk bytes, except that an EMPTY file is ONE final chunk of 0 bytes
(zero chunks would be indistinguishable from truncation). The encoding is canonical: the chunk count is a function of the stored size alone.
The reader bounds everything from the (untrusted) header and the declared stored size BEFORE it allocates or decrypts anything."""
from __future__ import annotations

import hashlib
import os
import re
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BLOB_CTX = b"sigilnet/v1/blob\0"
MAGIC = b"SGBL"
VERSION = 1
KID_LEN = 16                                          # a key id is an event id: 16 bytes = 32 hex digits
HEADER_LEN = 4 + 1 + 1 + 4 + 16 + 8 + KID_LEN      # 50
TAG = 16
DEFAULT_CHUNK = 65536
MAX_CHUNK = 1 << 20                                  # a header may not ask for more (reader bound)
MIN_CHUNK = 1024
MAX_CHUNKS = 1 << 20                                 # far below the 2^32 counter limit; with MIN_CHUNK it still allows 1 GiB
CID_RE = re.compile(r"sha256:[0-9a-f]{64}")


class BlobError(ValueError):
    pass


# ---------------------------------------------------------------- cid
def cid_of(stored: bytes) -> str:
    return "sha256:" + hashlib.sha256(stored).hexdigest()


def check_cid(cid) -> str:
    """The validated cid, or BlobError. Store paths come ONLY from a cid that passed this."""
    if not isinstance(cid, str) or not CID_RE.fullmatch(cid):
        raise BlobError("bad cid")
    return cid


def cid_hex(cid: str) -> str:
    return check_cid(cid)[7:]


class Hasher:
    """Incremental cid: feed stored bytes as they arrive, compare at the end."""

    def __init__(self):
        self._h = hashlib.sha256()
        self.size = 0

    def update(self, b: bytes) -> None:
        self._h.update(b)
        self.size += len(b)

    def cid(self) -> str:
        return "sha256:" + self._h.hexdigest()


# ---------------------------------------------------------------- header
class Header:
    __slots__ = ("chunk", "salt", "nonce_prefix", "kid", "raw")

    def __init__(self, chunk: int, salt: bytes, nonce_prefix: bytes, kid: bytes):
        self.chunk, self.salt, self.nonce_prefix, self.kid = chunk, salt, nonce_prefix, kid
        self.raw = MAGIC + struct.pack(">BBI", VERSION, 0, chunk) + salt + nonce_prefix + kid

    @property
    def kid_hex(self) -> str:
        return self.kid.hex()


def make_header(kid_hex: str, chunk: int = DEFAULT_CHUNK, rng=os.urandom) -> Header:
    kid = _kid_bytes(kid_hex)
    if not (MIN_CHUNK <= chunk <= MAX_CHUNK):
        raise BlobError("chunk size out of range")
    return Header(chunk, rng(16), rng(8), kid)


def _kid_bytes(kid_hex) -> bytes:
    if not isinstance(kid_hex, str) or len(kid_hex) != 2 * KID_LEN or not re.fullmatch(r"[0-9a-f]+", kid_hex):
        raise BlobError("bad key id")
    return bytes.fromhex(kid_hex)


def parse_header(b: bytes) -> Header:
    """Parse and bound the header; BlobError on anything that is not exactly a version-1 header."""
    if not isinstance(b, (bytes, bytearray)) or len(b) < HEADER_LEN:
        raise BlobError("header truncated")
    b = bytes(b[:HEADER_LEN])
    if b[:4] != MAGIC:
        raise BlobError("bad magic")
    ver, flags, chunk = struct.unpack(">BBI", b[4:10])
    if ver != VERSION:
        raise BlobError("unsupported version")
    if flags != 0:
        raise BlobError("unknown flags")
    if not (MIN_CHUNK <= chunk <= MAX_CHUNK):
        raise BlobError("chunk size out of range")
    return Header(chunk, b[10:26], b[26:34], b[34:50])


# ---------------------------------------------------------------- layout (a function of the stored size alone)
def stored_size(plain_len: int, chunk: int) -> int:
    if plain_len < 0:
        raise BlobError("negative length")
    n = max(1, -(-plain_len // chunk))
    return HEADER_LEN + plain_len + n * TAG


def layout(size: int, chunk: int) -> tuple:
    """(n_chunks, plain_len) for a stored size, or BlobError if no canonical blob has that size."""
    if not isinstance(size, int) or isinstance(size, bool) or size < HEADER_LEN + TAG:
        raise BlobError("stored size too small")
    body = size - HEADER_LEN
    full = chunk + TAG
    n = -(-body // full)
    last = body - (n - 1) * full                      # ciphertext bytes of the final chunk: TAG .. full
    if n > MAX_CHUNKS:
        raise BlobError("too many chunks")
    if last < TAG:
        raise BlobError("final chunk too short")
    if last == TAG and n > 1:
        raise BlobError("empty final chunk after data")   # non-canonical: only an empty FILE is a lone empty chunk
    return n, body - n * TAG


# ---------------------------------------------------------------- crypto
def _check_tid(tid) -> None:
    if not isinstance(tid, str) or not tid.isascii() or not tid:
        raise BlobError("bad thread id")


def _key(root: bytes, tid: str, header: Header) -> bytes:
    _check_tid(tid)
    if not isinstance(root, (bytes, bytearray)) or len(root) != 32:
        raise BlobError("bad epoch key")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=header.salt,
                info=BLOB_CTX + tid.encode() + b"\0" + header.kid).derive(bytes(root))


def _nonce(header: Header, i: int) -> bytes:
    return header.nonce_prefix + struct.pack(">I", i)


def _aad(tid: str, header: Header, i: int, final: bool) -> bytes:
    return BLOB_CTX + tid.encode() + b"\0" + header.raw + struct.pack(">QB", i, 1 if final else 0)


def seal(root: bytes, tid: str, kid_hex: str, plain: bytes, chunk: int = DEFAULT_CHUNK, rng=os.urandom) -> bytes:
    """The stored bytes of an encrypted blob (in memory; seal_iter streams from a file)."""
    if not isinstance(plain, (bytes, bytearray)):
        raise BlobError("plaintext must be bytes")
    return b"".join(seal_iter(root, tid, kid_hex, _pieces(bytes(plain), chunk), chunk, rng))


def _pieces(plain: bytes, chunk: int):
    for off in range(0, len(plain), chunk):
        yield plain[off:off + chunk]


def seal_iter(root: bytes, tid: str, kid_hex: str, pieces, chunk: int = DEFAULT_CHUNK, rng=os.urandom):
    """Yield the header, then each sealed chunk. `pieces` yields plaintext of EXACTLY `chunk` bytes except the last (1..chunk); no pieces at all = empty file."""
    header = make_header(kid_hex, chunk, rng)
    aead = ChaCha20Poly1305(_key(root, tid, header))
    yield header.raw
    it = iter(pieces)
    cur = next(it, None)
    i = 0
    if cur is None:
        yield aead.encrypt(_nonce(header, 0), b"", _aad(tid, header, 0, True))
        return
    while True:
        nxt = next(it, None)
        final = nxt is None
        if not cur and not (final and i == 0):
            raise BlobError("empty piece")
        if (len(cur) != chunk and not final) or len(cur) > chunk:
            raise BlobError("piece size does not match chunk size")
        if i >= MAX_CHUNKS:
            raise BlobError("too many chunks")
        yield aead.encrypt(_nonce(header, i), cur, _aad(tid, header, i, final))
        if final:
            return
        cur, i = nxt, i + 1


class Opener:
    """Decrypt a blob chunk by chunk. Construct it from the first HEADER_LEN bytes, the declared stored size and the epoch key found by header.kid_hex;
    chunks must be fed in order. Any failure raises BlobError and the opener is dead."""

    def __init__(self, header: Header, size: int, root: bytes, tid: str):
        self.header = header
        self.n, self.plain_len = layout(size, header.chunk)
        self._aead = ChaCha20Poly1305(_key(root, tid, header))
        self._tid = tid
        self._i = 0
        self._dead = False
        self._size = size

    @property
    def done(self) -> bool:
        return self._i == self.n

    def sealed_len(self, i: int) -> int:
        """Stored length of chunk i (so a fetcher knows how many bytes to ask for)."""
        if not 0 <= i < self.n:
            raise BlobError("no such chunk")
        if i < self.n - 1:
            return self.header.chunk + TAG
        return self._size - HEADER_LEN - (self.n - 1) * (self.header.chunk + TAG)

    def feed(self, ct: bytes) -> bytes:
        if self._dead:
            raise BlobError("opener is dead")
        try:
            if self._i >= self.n:
                raise BlobError("data after the final chunk")
            if len(ct) != self.sealed_len(self._i):
                raise BlobError("chunk length mismatch")
            final = self._i == self.n - 1
            try:
                pt = self._aead.decrypt(_nonce(self.header, self._i), bytes(ct), _aad(self._tid, self.header, self._i, final))
            except InvalidTag:
                raise BlobError("chunk authentication failed") from None
            self._i += 1
            return pt
        except BaseException as e:                        # any failure (even a wrong argument type) kills the opener
            self._dead = True
            if isinstance(e, (BlobError, KeyboardInterrupt, SystemExit)):
                raise
            raise BlobError("bad chunk") from None

    def finish(self) -> None:
        if self._dead or not self.done:
            raise BlobError("blob truncated")


def open_blob(root_for, tid: str, stored: bytes) -> bytes:
    """Decrypt a whole stored blob. `root_for(kid_hex)` returns the epoch key or None (no key = BlobError). cid and size are the caller's to have checked."""
    header = parse_header(stored)
    try:
        root = root_for(header.kid_hex)
    except Exception:
        raise BlobError("key lookup failed") from None
    if root is None:
        raise BlobError("no key for this blob")
    op = Opener(header, len(stored), root, tid)
    out, pos = [], HEADER_LEN
    for i in range(op.n):
        ln = op.sealed_len(i)
        out.append(op.feed(stored[pos:pos + ln]))
        pos += ln
    op.finish()
    return b"".join(out)
