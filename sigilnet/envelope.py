"""Encrypted envelopes for PRIVATE threads (DESIGN_envelopes.md, revision 1). Pure functions and one small file-backed keyring: no network, no thread rules.

An envelope wraps ONE signed event: {"v": 1, "th": thread id, "ep": key id, "n": nonce, "c": ciphertext}. The key id `ep` is the id of the event that created the epoch
(the genesis id for epoch 0, the `member_remove` id for later ones), never a bare integer: two admin branches can both reach "epoch e+1" with different removals,
and a key must never be shared between them. AAD = context || thread || key id: a ciphertext cannot be moved to another thread or epoch.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import struct
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization as ser

from . import canon
from .keys import Identity, is_hex, valid_kex_pub, verify_strict

ENV_CTX = b"sigilnet/v1/env\0"
SEAL_CTX = b"sigilnet/v1/keyseal\0"
BUCKET = 256                        # plaintext is padded to a multiple of this (after a 4-byte length prefix)
MAX_ENV_PLAIN = 3 * 65536 + 4096    # the largest event the mirror accepts (evidence carries two events)
KEY_LEN = 32
CONFIRM_CTX = b"sigilnet/v1/keyconfirm\0"
MAX_KEYS = 4096


class EnvelopeError(ValueError):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s, n: int | None = None) -> bytes:
    if not isinstance(s, str) or len(s) > 4 * MAX_ENV_PLAIN:
        raise EnvelopeError("bad base64")
    try:
        b = base64.b64decode(s.encode(), validate=True)
    except Exception:                                               # noqa: BLE001
        raise EnvelopeError("bad base64") from None
    if n is not None and len(b) != n:
        raise EnvelopeError("bad length")
    return b


# ---------------------------------------------------------------- epochs = the event that created them

def epoch_id_at(t, admin_id: str) -> str:
    """The key id in force at the admin state `admin_id` (an `admin_ref`): the nearest event on its prev_admin path, itself included, whose state has a higher epoch than
    its predecessor's; the thread id if none. Works for states on abandoned branches too (their own epochs)."""
    x, seen = admin_id, 0
    while x != t.id:
        ev = t.stored.get(x)
        st = t.states.get(x)
        if ev is None or st is None or seen > 100000:
            raise EnvelopeError("unknown admin state")
        prev = ev["body"].get("prev_admin")
        pst = t.states.get(prev)
        if pst is None:
            raise EnvelopeError("unknown admin state")
        if pst["epoch"] < st["epoch"]:
            return x
        x, seen = prev, seen + 1
    return t.id


def chain_epoch_ids(t) -> list:
    """Key ids on the CURRENT derived chain, oldest first (what a current member may be given)."""
    out, last = [t.id], 0
    for x in t.chain[1:]:
        e = t.states[x]["epoch"]
        if e > last:
            out.append(x)
            last = e
    return out


# ---------------------------------------------------------------- padding and sealing events

def _pad(plain: bytes) -> bytes:
    body = struct.pack(">I", len(plain)) + plain
    return body + b"\0" * (-len(body) % BUCKET)


def _unpad(padded: bytes) -> bytes:
    if len(padded) < 4 or len(padded) % BUCKET:
        raise EnvelopeError("bad padding")
    (n,) = struct.unpack(">I", padded[:4])
    if n > len(padded) - 4 or len(padded) - 4 - n >= BUCKET or any(padded[4 + n:]):
        raise EnvelopeError("bad padding")
    return padded[4:4 + n]


def _aad(tid: str, key_id: str) -> bytes:
    return ENV_CTX + tid.encode() + b"\0" + key_id.encode()


def seal_event(key: bytes, tid: str, key_id: str, event: dict) -> dict:
    if not isinstance(key, bytes) or len(key) != KEY_LEN:
        raise EnvelopeError("bad key")
    plain = canon.dumps(event)
    if len(plain) > MAX_ENV_PLAIN:
        raise EnvelopeError("event too large")
    nonce = os.urandom(12)
    return {"v": 1, "th": tid, "ep": key_id, "n": _b64(nonce), "c": _b64(ChaCha20Poly1305(key).encrypt(nonce, _pad(plain), _aad(tid, key_id)))}


def looks_like_envelope(x) -> bool:
    return isinstance(x, dict) and x.get("v") == 1 and set(x) == {"v", "th", "ep", "n", "c"}


def envelope_key_id(env) -> str:
    if not looks_like_envelope(env) or not isinstance(env["ep"], str) or not is_hex(env["ep"], 32):
        raise EnvelopeError("not an envelope")
    return env["ep"]


def open_envelope(key: bytes, env: dict, tid: str) -> dict:
    """The signed event inside, or EnvelopeError. The caller still validates the event (signature, rules): decrypting proves nothing about the author."""
    if not looks_like_envelope(env) or env["th"] != tid:
        raise EnvelopeError("not an envelope of this thread")
    key_id = envelope_key_id(env)
    if not isinstance(key, bytes) or len(key) != KEY_LEN:
        raise EnvelopeError("bad key")
    nonce, ct = _unb64(env["n"], 12), _unb64(env["c"])
    if len(ct) > MAX_ENV_PLAIN + 4096:
        raise EnvelopeError("envelope too large")
    try:
        padded = ChaCha20Poly1305(key).decrypt(nonce, ct, _aad(tid, key_id))
    except Exception:                                               # noqa: BLE001 - wrong key, wrong epoch, wrong thread, damaged: one message
        raise EnvelopeError("does not open") from None
    try:
        return canon.loads(_unpad(padded))
    except canon.CanonError:
        raise EnvelopeError("inside is not canonical JSON") from None


# ---------------------------------------------------------------- ECIES: a key sealed to a member's kex key

def _seal_kdf(shared: bytes, eph_pub: bytes, rcpt_pub: bytes, tid: str, key_id: str) -> bytes:
    info = SEAL_CTX + eph_pub + rcpt_pub + tid.encode() + b"\0" + key_id.encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def seal_key(recipient_kex_hex: str, recipient_id: str, tid: str, key_id: str, key: bytes) -> dict:
    """{"e": ephemeral x25519 pub (hex), "n": nonce, "c": ciphertext} openable only by the holder of the recipient's kex private key."""
    if not valid_kex_pub(recipient_kex_hex) or len(key) != KEY_LEN:
        raise EnvelopeError("bad recipient or key")
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    rcpt = bytes.fromhex(recipient_kex_hex)
    shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(rcpt))
    k = _seal_kdf(shared, eph_pub, rcpt, tid, key_id)
    nonce = os.urandom(12)
    aad = SEAL_CTX + tid.encode() + b"\0" + key_id.encode() + b"\0" + recipient_id.encode()
    return {"e": eph_pub.hex(), "n": _b64(nonce), "c": _b64(ChaCha20Poly1305(k).encrypt(nonce, key, aad))}


def open_key(me: Identity, tid: str, key_id: str, sealed: dict) -> bytes:
    if not isinstance(sealed, dict) or set(sealed) != {"e", "n", "c"} or not is_hex(sealed["e"], 64):
        raise EnvelopeError("bad sealed key")
    try:
        eph_pub = bytes.fromhex(sealed["e"])
        shared = me.kex_key.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
        rcpt = bytes.fromhex(me.kex_pub)
        k = _seal_kdf(shared, eph_pub, rcpt, tid, key_id)
        aad = SEAL_CTX + tid.encode() + b"\0" + key_id.encode() + b"\0" + me.id.encode()
        key = ChaCha20Poly1305(k).decrypt(_unb64(sealed["n"], 12), _unb64(sealed["c"], KEY_LEN + 16), aad)
    except EnvelopeError:
        raise
    except Exception:                                               # noqa: BLE001
        raise EnvelopeError("sealed key does not open") from None
    if len(key) != KEY_LEN:
        raise EnvelopeError("bad key length")
    return key


# ---------------------------------------------------------------- the keyring

def _confirm_msg(tid: str, key_id: str, key: bytes) -> bytes:
    return CONFIRM_CTX + tid.encode() + b"\0" + key_id.encode() + b"\0" + hashlib.sha256(key).digest()


def make_confirmation(signer: Identity, tid: str, key_id: str, key: bytes) -> dict:
    return {"by": signer.sign_pub, "sig": signer.sign(_confirm_msg(tid, key_id, key))}


def check_confirmation(t, key_id: str, key: bytes, conf) -> bool:
    """Did the epoch's CREATOR (the author of the event that made the epoch: the genesis author for epoch 0, the member_remove's author after) or a current owner/admin
    sign this key for this thread and key id? Judged against OUR derived thread state. Never raises."""
    try:
        if not isinstance(conf, dict) or set(conf) != {"by", "sig"} or not is_hex(conf["by"], 64) or not is_hex(conf["sig"], 128) or len(key) != KEY_LEN:
            return False
        ev = t.stored.get(key_id)
        allowed = set()
        if ev is not None:
            sk = t.known_keys.get(ev["author"])
            if sk:
                allowed.add(sk)
        for m in t.state()["members"].values():
            if m["role"] in ("owner", "admin"):
                allowed.add(m["sign"])
        return conf["by"] in allowed and verify_strict(conf["by"], conf["sig"], _confirm_msg(t.id, key_id, key))
    except Exception:                                               # noqa: BLE001
        return False


class Keyring:
    """keys/<thread>.json (0600, flocked, atomic): {key id: {"k": base64 key, "ok": bool, "c": confirmation or null}}. `c` = {"by": signer sign key, "sig"}: the
    epoch's CREATOR (or an owner/admin) signed (thread, key id, sha256(key)); a key is VERIFIED (`ok`) when we made it or when that confirmation checked out against
    OUR thread state. Opening an envelope proves nothing about a key's authenticity (a member can seal under a key of its own and call it the epoch's key).
    An unverified key is never used to encrypt and may be replaced; a verified key is never overwritten."""

    def __init__(self, root, tid: str):
        self.dir = Path(root)
        self.tid = tid
        self.path = self.dir / f"{tid}.json"
        self.lockp = self.dir / f"{tid}.json.lock"

    def _lock(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        self.dir.chmod(0o700)
        fd = os.open(self.lockp, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _load(self) -> dict:
        try:
            if self.path.is_symlink():
                return {}
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        out = {}
        if isinstance(raw, dict):
            for kid, v in raw.items():
                try:
                    c = v.get("c") if isinstance(v, dict) else None
                    if is_hex(kid, 32) and isinstance(v, dict) and set(v) in ({"k", "ok"}, {"k", "ok", "c"}) and type(v["ok"]) is bool and len(_unb64(v["k"], KEY_LEN)) == KEY_LEN \
                            and (c is None or (isinstance(c, dict) and set(c) == {"by", "sig"} and is_hex(c["by"], 64) and is_hex(c["sig"], 128))) and len(out) < MAX_KEYS:
                        out[kid] = {"k": v["k"], "ok": v["ok"], "c": c}
                except EnvelopeError:
                    continue
        return out

    def _save(self, d: dict) -> None:
        tmp = self.dir / f".{self.tid}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def exists(self) -> bool:
        return self.path.exists() and not self.path.is_symlink()

    def ids(self) -> list:
        return sorted(self._load())

    def get(self, key_id: str):
        """(key bytes, verified) or None."""
        v = self._load().get(key_id)
        return None if v is None else (_unb64(v["k"]), v["ok"])

    def conf(self, key_id: str):
        v = self._load().get(key_id)
        return None if v is None else v.get("c")

    def create(self, key_id: str, signer=None) -> bytes:
        """A fresh key of our own making (verified by construction), confirmed by `signer` (so that other members can check it). Idempotent: an existing key is returned."""
        fd = self._lock()
        try:
            d = self._load()
            if key_id in d and d[key_id]["ok"]:
                return _unb64(d[key_id]["k"])                       # (an UNVERIFIED entry is replaced by a key of our own making)
            if not is_hex(key_id, 32) or len(d) >= MAX_KEYS:
                raise EnvelopeError("bad key id or too many keys")
            key = os.urandom(KEY_LEN)
            d[key_id] = {"k": _b64(key), "ok": True, "c": make_confirmation(signer, self.tid, key_id, key) if signer is not None else None}
            self._save(d)
            return key
        finally:
            os.close(fd)

    def install(self, key_id: str, key: bytes, *, verified: bool = False, conf=None) -> bool:
        """Keep a received key. Never overwrites a verified key; an unverified one may be replaced. True if the file changed."""
        if not is_hex(key_id, 32) or not isinstance(key, bytes) or len(key) != KEY_LEN:
            raise EnvelopeError("bad key id or key")
        fd = self._lock()
        try:
            d = self._load()
            old = d.get(key_id)
            if old is not None and old["ok"]:
                return False
            if old is None and len(d) >= MAX_KEYS:
                raise EnvelopeError("too many keys")
            new = {"k": _b64(key), "ok": bool(verified), "c": conf}
            if old == new:
                return False
            d[key_id] = new
            self._save(d)
            return True
        finally:
            os.close(fd)

    def discard(self, key_id: str) -> bool:
        """Forget a key we made for an event that was then refused (a removal that did not go through). True if something was removed."""
        fd = self._lock()
        try:
            d = self._load()
            if d.pop(key_id, None) is None:
                return False
            self._save(d)
            return True
        finally:
            os.close(fd)

    def mark_verified(self, key_id: str) -> None:
        fd = self._lock()
        try:
            d = self._load()
            if key_id in d and not d[key_id]["ok"]:
                d[key_id]["ok"] = True
                self._save(d)
        finally:
            os.close(fd)


# ---------------------------------------------------------------- the mirror's codec (at rest) and the wire rules

class PlainCodec:
    """The default: events.jsonl lines are the canonical signed events, as before."""
    wire_encrypted = False

    def is_encrypted(self, tid: str) -> bool:
        return False

    def usable(self, tid: str) -> bool:
        return True

    def sig(self, tid: str):
        return None

    def encode(self, t, ev: dict) -> bytes:
        from .event import encode
        return encode(ev)

    def decode(self, tid: str, raw: bytes) -> dict:
        from .event import decode
        from .mirror import MAX_WIRE
        return decode(raw, MAX_WIRE)



class EnvCodec(PlainCodec):
    """Encrypts every non-genesis line of a thread that has a marker `<keys>/<thread>.enc`. The marker is separate from the keyring: if the keyring is deleted or
    unreadable the thread is LOCKED (not readable, and never starts accepting plaintext). Every event is written under the key of ITS OWN epoch (see key_for)."""
    wire_encrypted = True

    def __init__(self, keys_dir):
        self.dir = Path(keys_dir)

    def ring(self, tid: str) -> Keyring:
        return Keyring(self.dir, tid)

    def _marker(self, tid: str) -> Path:
        return self.dir / f"{tid}.enc"

    def is_encrypted(self, tid: str) -> bool:
        """The marker OR a keyring means encrypted (deleting only the marker must not downgrade the thread: the marker is repaired from the keyring)."""
        if self._marker(tid).exists():
            return True
        if self.ring(tid).exists():
            self.mark(tid, migrating=True)                           # repaired as "migrating": plain lines still readable, the next load re-encrypts and finalises (no event is lost either way)
            return True
        return False

    def mark(self, tid: str, migrating: bool = False) -> None:
        """The marker's content is "migrating" while a plaintext thread is being rewritten (plaintext lines are still accepted then), empty afterwards."""
        self.dir.mkdir(parents=True, exist_ok=True)
        self.dir.chmod(0o700)
        fd = os.open(self._marker(tid), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, b"migrating" if migrating else b"")
        finally:
            os.close(fd)

    def migrating(self, tid: str) -> bool:
        try:
            return self._marker(tid).read_bytes() == b"migrating"
        except OSError:
            return False

    def usable(self, tid: str) -> bool:
        """An encrypted thread is usable only with a readable keyring that holds at least one key."""
        if not self.is_encrypted(tid):
            return True
        r = self.ring(tid)
        return r.exists() and bool(r.ids())

    def sig(self, tid: str):
        try:
            st = os.stat(self.ring(tid).path)
            return (self.is_encrypted(tid), st.st_mtime_ns, st.st_size)
        except OSError:
            return (self.is_encrypted(tid), None, None)

    def key_for(self, t, ev: dict) -> tuple:
        """(key id, key) an event is sealed under: the epoch of its `admin_ref` (what its AUTHOR knew). So the removal that starts epoch e+1 is itself sealed under
        epoch e (a member that holds e learns about e+1 by reading it), and events authored after it use e+1. EnvelopeError if we hold no VERIFIED key for that epoch."""
        kid = epoch_id_at(t, ev["admin_ref"])
        got = self.ring(t.id).get(kid)
        if got is None or not got[1]:
            raise EnvelopeError("no verified key for this epoch")
        return kid, got[0]

    def can_encode(self, t, ev: dict) -> bool:
        if not self.is_encrypted(t.id) or ev.get("kind") == "genesis" or ev.get("admin_ref") not in t.states:
            return True                                              # (an event whose admin state we do not hold yet is PARKED by the thread layer: nothing is written for it now)
        try:
            self.key_for(t, ev)
            return True
        except (EnvelopeError, KeyError):
            return False

    def encode(self, t, ev: dict) -> bytes:
        from .event import encode, event_id
        if t is None or not self.is_encrypted(t.id) or (ev.get("kind") == "genesis" and event_id(ev) == t.id):
            return encode(ev)                                        # the genesis is the thread's name: plaintext by design
        kid, key = self.key_for(t, ev)
        return canon.dumps(seal_event(key, t.id, kid, ev))

    def decode(self, tid: str, raw: bytes) -> dict:
        from .event import EventError, check_structure, decode, event_id
        from .mirror import MAX_WIRE
        if not self.is_encrypted(tid):
            return decode(raw, MAX_WIRE)
        try:
            obj = canon.loads(raw)
        except canon.CanonError as e:
            raise EventError(str(e)) from None
        if not looks_like_envelope(obj):
            ev = decode(raw, MAX_WIRE)
            if (ev.get("kind") == "genesis" and event_id(ev) == tid) or self.migrating(tid):
                return ev                                            # (plain lines are accepted only while the thread is being migrated)
            raise EventError("plaintext line in an encrypted thread")      # otherwise only the genesis may be plain
        got = self.ring(tid).get(envelope_key_id(obj))
        if got is None:
            raise EventError("no key for this epoch")
        try:
            inner = open_envelope(got[0], obj, tid)
        except EnvelopeError as e:
            raise EventError(str(e)) from None
        check_structure(inner, MAX_WIRE)
        return inner
