"""Agent identity: an Ed25519 signing key and an X25519 key-agreement key, generated locally (spec section 3)."""
from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

HEX = re.compile(r"^[0-9a-f]+$")
AGENT_ID_RE = re.compile(r"^[a-z2-7]{32}$")
L = 2 ** 252 + 27742317777372353535851937790883648493       # order of the Ed25519 base point
# the eight small-order points (canonical encodings): a public key like these verifies signatures for many messages
SMALL_ORDER = {bytes.fromhex(h) for h in (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")}


def is_hex(s, n: int) -> bool:
    return isinstance(s, str) and len(s) == n and bool(HEX.match(s))


AGENT_CTX = b"sigilnet/v1/agent\0"     # domain separation: an agent id is a hash of nothing else that this project (or another) could produce


def agent_id(sign_pub: bytes) -> str:
    """First 20 bytes of SHA-256(AGENT_CTX + signing public key), base32 lowercase: 32 characters."""
    return base64.b32encode(hashlib.sha256(AGENT_CTX + sign_pub).digest()[:20]).decode().lower()


P = 2 ** 255 - 19
_D = (-121665 * pow(121666, P - 2, P)) % P
_I = pow(2, (P - 1) // 4, P)


def _decompress(raw: bytes):
    """Curve point from its 32-byte encoding, or None if the encoding is not canonical / not on the curve."""
    y = int.from_bytes(raw, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * _I % P
    if (x * x - x2) % P:
        return None
    if x == 0 and sign:
        return None                     # x = 0 must be encoded with sign bit 0 (01..80 is a non-canonical identity)
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _add(p, q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = p, q
    a, b = (y1 - x1) * (y2 - x2) % P, (y1 + x1) * (y2 + x2) % P
    c, d = t1 * 2 * _D * t2 % P, z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(k, pt):
    r, q = (0, 1, 1, 0), pt
    while k:
        if k & 1:
            r = _add(r, q)
        q = _add(q, q)
        k >>= 1
    return r


@functools.lru_cache(maxsize=4096)
def valid_sign_pub(pub_hex) -> bool:
    """A canonical encoding of a point in the PRIME-ORDER subgroup: rejects small-order points (in any encoding), mixed-order
    (torsion) keys and non-canonical encodings. With such a key a signature could verify for messages its owner never signed."""
    if not is_hex(pub_hex, 64):
        return False
    pt = _decompress(bytes.fromhex(pub_hex))
    if pt is None or bytes.fromhex(pub_hex) in SMALL_ORDER:
        return False
    x, y, z, _ = _mul(L, pt)
    return x % P == 0 and (y - z) % P == 0


@functools.lru_cache(maxsize=4096)
def valid_kex_pub(pub_hex) -> bool:
    """A 32-byte X25519 key that does not produce an all-zero shared secret (low-order points)."""
    if not is_hex(pub_hex, 64):
        return False
    try:
        x25519.X25519PrivateKey.generate().exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)))
        return True
    except ValueError:
        return False


def verify_strict(pub_hex: str, sig_hex: str, message: bytes) -> bool:
    """Ed25519 verification that also rejects: malformed hex, small-order keys, and non-canonical S (S >= L)."""
    if not valid_sign_pub(pub_hex) or not is_hex(sig_hex, 128):
        return False
    sig = bytes.fromhex(sig_hex)
    if int.from_bytes(sig[32:], "little") >= L:
        return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


class Identity:
    def __init__(self, sign_key: ed25519.Ed25519PrivateKey, kex_key: x25519.X25519PrivateKey, name: str = ""):
        self.sign_key, self.kex_key, self.name = sign_key, kex_key, name

    @classmethod
    def generate(cls, name: str = "") -> "Identity":
        return cls(ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate(), name)

    @property
    def sign_pub(self) -> str:
        return self.sign_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()

    @property
    def kex_pub(self) -> str:
        return self.kex_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()

    @property
    def id(self) -> str:
        return agent_id(bytes.fromhex(self.sign_pub))

    def sign(self, message: bytes) -> str:
        return self.sign_key.sign(message).hex()

    def save(self, path) -> None:
        p = Path(path)
        raw = lambda k: k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()).hex()
        blob = json.dumps({"name": self.name, "sign": raw(self.sign_key), "kex": raw(self.kex_key)})
        tmp = p.with_name(p.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
        p.chmod(0o600)

    @classmethod
    def load(cls, path) -> "Identity":
        d = json.loads(Path(path).read_text())
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(d["sign"])),
                   x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(d["kex"])), d.get("name", ""))
