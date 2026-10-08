"""Capsule join (spec 8, revision 1): an outside agent on another network joins a private thread through ONE paste-able block that a human relays.

Flow (every step on the owner side that changes anything waits for the owner's human). A capsule (v2, M2) lists one JOIN door per carrier the owner chose
(DESIGN_multicarrier.md rev 8): the joiner uses the carriers both sides have, the owner answers with one peer door per carrier the joiner offered.
  owner  `capsule create THREAD [--carrier T ...]`  -> per listed carrier a one-time JOIN door (authorized with a throwaway bootstrap key that goes into the capsule) and a throwaway dial
                                     key, a random token (stored hashed), a capsule block, the owner's fingerprint to read out.
  joiner `capsule accept BLOCK --fingerprint "<owner's, read to you another way>" [--carrier T ...]` -> builds its own door for the owner on each carrier it uses, sends `join_request`
                                     (with an offer per door) over the first carrier that answers, prints ITS fingerprint for the joiner's human to read to the owner's human another way.
  owner  `capsule confirm ID --fingerprint "<joiner's>"` -> member_add, a per-peer door per offered carrier, peer entry; the join doors are torn down after the
                                     joiner has collected the answer (or after a short grace time) and on expiry, reject and at startup.
  joiner polls `join_status` -> gets the owner's per-peer doors, installs its keys, adds the owner as a peer; the normal node loop does the rest.
The capsule's checksum is integrity only, never authenticity: the fingerprint comparison through a SECOND human channel is what stops a forged capsule.
Stranger text (the joiner's name) is length-capped and sanitized and never reaches a wake event: only ids and counts do.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import canon
from .keys import AGENT_ID_RE, Identity, agent_id, is_hex, valid_kex_pub, valid_sign_pub, verify_strict
from .thread import clean_text
from .carrier import NAME_RE, TYPE_RE, CarrierError, Secret, check_credential, check_endpoint

PREFIX = "SIGILNET-CAPSULE-1"                 # (the block prefix; the layout version is `v` inside: 2)
MAX_CAPSULE = 6000
DEFAULT_TTL = 3600
MAX_TTL = 24 * 3600
MAX_OPEN = 8
GRACE = 900                          # after a confirm the join door stays this long so the joiner can collect the answer
KEEP = 24 * 3600                     # finished records are kept this long (for `capsule list`), then dropped
FP_GROUPS = 4                        # the fingerprint a human reads out: the first 16 characters of the agent id (80 bits), in groups of 4
JOIN_CTX = b"sigilnet/v1/join-response\0"
JOINREQ_CTX = b"sigilnet/v1/join-request\0"
NAME_MAX = 64
MAX_BRIDGES = 8
MAX_JOINS = 4                        # join doors (carrier types) in one capsule
ANSWER_WAIT = 60                     # the owner holds the answer this long for an offered carrier whose door has no address yet (R2)
CID_RE = re.compile(r"[0-9a-f]{8}")
RULE_KEY = re.compile(r"[a-z0-9_]{1,40}")
STATES = ("open", "pending", "confirming", "confirmed", "rejected", "expired")
CONFIRMING_STALE = 300               # a confirm that died half way is treated as pending again after this many seconds


class CapsuleError(ValueError):
    pass


def fingerprint(agent: str) -> str:
    if not isinstance(agent, str) or not AGENT_ID_RE.fullmatch(agent):
        raise CapsuleError("bad agent id")
    return " ".join(agent[i:i + 4] for i in range(0, FP_GROUPS * 4, 4))


def same_fingerprint(typed: str, agent: str) -> bool:
    return isinstance(typed, str) and typed.isascii() and hmac.compare_digest("".join(typed.lower().split()), fingerprint(agent).replace(" ", ""))


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- the capsule block

def _wrap_secret(secret: str, passphrase: str) -> dict:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())
    return {"enc": _b64(salt + nonce + ChaCha20Poly1305(key).encrypt(nonce, secret.encode(), b"sigilnet-capsule-boot"))}


def _unwrap_secret(w: dict, passphrase: str) -> str:
    try:
        raw = _unb64(w["enc"])
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())
        return ChaCha20Poly1305(key).decrypt(nonce, ct, b"sigilnet-capsule-boot").decode()
    except Exception:                                               # noqa: BLE001 - wrong passphrase, damaged block: one message
        raise CapsuleError("wrong passphrase, or the capsule is damaged") from None


def encode_capsule(c: dict) -> str:
    raw = canon.dumps(c)
    return f"{PREFIX} {_b64(raw)} {hashlib.sha256(raw).hexdigest()[:8]}"


def decode_capsule(block: str, *, now: float | None = None) -> dict:
    """Validate a capsule completely; raises CapsuleError with a short reason. The checksum is integrity only."""
    if not isinstance(block, str) or len(block) > MAX_CAPSULE:
        raise CapsuleError("not a capsule (too long)")
    parts = block.split()
    if len(parts) != 3 or parts[0] != PREFIX:
        raise CapsuleError("not a capsule")
    try:
        raw = _unb64(parts[1])
        c = canon.loads(raw)
    except Exception:                                               # noqa: BLE001
        raise CapsuleError("the capsule is damaged") from None
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest()[:8], parts[2]):
        raise CapsuleError("the capsule is damaged (checksum)")
    try:
        _check(c, time.time() if now is None else now)
        for j in c["joins"]:
            j["endpoint"] = check_endpoint(j["endpoint"])           # one spelling everywhere (key files, records); a type no carrier here supports is refused
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise CapsuleError(f"invalid capsule: {e}") from None
    return c


def _check(c, now: float) -> None:
    if isinstance(c, dict) and c.get("v") == 1:
        raise ValueError("an old capsule (version 1): ask the owner to issue a new one")
    if not isinstance(c, dict) or set(c) != {"v", "thread", "title", "exp", "owner", "joins", "token", "observers", "rules", "bridges", "enc"} or c["v"] != 2 or type(c["enc"]) is not bool:
        raise ValueError("unknown layout")
    if not is_hex(c["thread"], 32) or not is_hex(c["token"], 32):
        raise ValueError("bad thread or token")
    if not clean_text(c["title"], 80) or type(c["exp"]) is not int or c["exp"] <= now or c["exp"] > now + MAX_TTL + 600:
        raise ValueError("bad title or expiry (expired?)")
    o = c["owner"]
    if not isinstance(o, dict) or set(o) != {"id", "sign", "kex", "name"} or not isinstance(o["id"], str) or not AGENT_ID_RE.fullmatch(o["id"]) \
            or not is_hex(o["sign"], 64) or not valid_sign_pub(o["sign"]) or agent_id(bytes.fromhex(o["sign"])) != o["id"] or not valid_kex_pub(o["kex"]) \
            or not clean_text(o["name"], NAME_MAX):
        raise ValueError("bad owner")
    js = c["joins"]
    if not isinstance(js, list) or not 1 <= len(js) <= MAX_JOINS:
        raise ValueError("bad join doors")
    seen = []
    for j in js:
        if not isinstance(j, dict) or set(j) != {"endpoint", "boot", "dial"}:
            raise ValueError("bad join door")
        jt = check_endpoint(j["endpoint"])["type"]
        if jt in seen:
            raise ValueError("two join doors of one carrier")
        seen.append(jt)
        b = j["boot"]
        if isinstance(b, dict) and set(b) == {"type", "key"}:
            if check_credential(b)["type"] != jt:
                raise ValueError("bad bootstrap key")
        elif not (isinstance(b, dict) and set(b) == {"enc"} and isinstance(b["enc"], str) and len(b["enc"]) < 400):
            raise ValueError("bad bootstrap key")
        if check_credential(j["dial"])["type"] != jt:
            raise ValueError("bad dial key")
    obs = c["observers"]
    if not isinstance(obs, list) or len(obs) > 8 or any(not isinstance(x, dict) or set(x) != {"id", "name"} or not AGENT_ID_RE.fullmatch(str(x["id"])) or not clean_text(x["name"], NAME_MAX) for x in obs):
        raise ValueError("bad observers")
    r = c["rules"]
    if not isinstance(r, dict) or len(r) > 8 or any(not isinstance(k, str) or not RULE_KEY.fullmatch(k) or type(v) is not int for k, v in r.items()):
        raise ValueError("bad rules")
    br = c["bridges"]
    if not isinstance(br, list) or len(br) > MAX_BRIDGES or any(not isinstance(x, str) or not x.startswith("Bridge ") or len(x) > 400 or any(ord(ch) < 32 or ord(ch) == 127 or ch == "\\" for ch in x) for x in br):
        raise ValueError("only plain Bridge lines are allowed in a capsule")     # spec 1.3: never ClientTransportPlugin ... exec from a stranger


def describe(c: dict) -> list:
    """What the joiner's human is shown: generated HERE from structured fields, never the capsule's own prose."""
    o = c["owner"]
    lines = [f"Thread: {c['title']!r} ({c['thread']})", f"Owner: {o['name']!r}  fingerprint: {fingerprint(o['id'])}   <- compare with what the owner's human tells you through ANOTHER channel",
             f"This capsule expires at unix time {c['exp']} (in {max(0, c['exp'] - int(time.time())) // 60} minutes)."]
    lines.append("Join doors, in the owner's order: " + ", ".join(_door_label(j["endpoint"]) for j in c["joins"]) + ".")
    if any(j["endpoint"]["type"] == "tcp" for j in c["joins"]):
        lines.append("WARNING: this capsule names the owner's IP address (a tcp door). Anyone who reads the block learns it, and a tcp door is not hidden.")
    if c["observers"]:
        lines.append("Human observers named in this capsule (they can read EVERYTHING in the thread): " + ", ".join(f"{x['name']!r} ({x['id'][:8]})" for x in c["observers"]))
    else:
        lines.append("No human observer is named in this capsule. (The genesis you will receive is what counts.)")
    lines.append("Events of this thread are ENCRYPTED for members (the thread keys are sent to you inside the owner's signed answer after the owner confirms)." if c["enc"]
                 else "Events of this thread are NOT encrypted: members, observers and anyone who reaches your door see plaintext.")
    lines.append("The thread's title and the member names/keys in its genesis are visible to anyone who holds the genesis (it is plaintext by design).")
    if c["rules"]:
        lines.append("Rules: " + ", ".join(f"{k}={v}" for k, v in sorted(c["rules"].items())))
    return lines


def _door_label(endpoint: dict) -> str:
    return f"tcp {endpoint['addr'].split('#')[0]}" if endpoint["type"] == "tcp" else endpoint["type"]


def _as_list(carriers) -> list:
    return [carriers] if hasattr(carriers, "open_door") else list(carriers.values() if isinstance(carriers, dict) else carriers)


def _carrier_list(carriers) -> list:
    """One carrier, a list of them or a {type: carrier} dict -> a list (distinct types, the order given)."""
    out = _as_list(carriers)
    if not out or len({c.type for c in out}) != len(out):
        raise CapsuleError("capsules need one or more carriers of distinct types")
    return out


# ---------------------------------------------------------------- owner side: the store of open capsules

class Store:
    """capsules.json under home (0600, flocked). Record: {tok (sha256 of the token), thread, exp, door (join-<cid>, the same name on every carrier), types (the carriers it has join doors on, issuer's
    order; the dial key files are cap-<cid>-<type>.priv), state, req (agent, sign, kex, name, offers), owner_door, deadline, door_gone ({type: True}), partial, at}.
    States: open -> pending (one join_request per token) -> confirmed | rejected | expired."""

    def __init__(self, home, clock=time.time, *, name="capsules.json", ok=None):
        self.home, self.clock = Path(home), clock
        self.path = self.home / name
        self.lockp = self.home / (name + ".lock")
        self.ok = ok or _ok_record

    def _locked(self):
        class L:
            def __init__(s, p):
                s.fd = os.open(p, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)

            def __enter__(s):
                fcntl.flock(s.fd, fcntl.LOCK_EX)
                return s

            def __exit__(s, *a):
                os.close(s.fd)
        return L(self.lockp)

    def _raw(self) -> dict:
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def _load(self) -> dict:
        return {k: v for k, v in self._raw().items() if self.ok(k, v)}

    def _save(self, d: dict) -> None:
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, sort_keys=True)
        os.replace(tmp, self.path)

    def all(self) -> dict:
        if not self.path.exists():
            return {}                                                 # nothing to read: no lock to take, so a read-only command never creates the lock file (or any file)
        with self._locked():
            return self._load()

    def edit(self, fn):
        """Read, let `fn` change the records, write. The file is written ONLY when the records differ from what was on disk (records that fail `ok` count as a difference: they are cleaned
        away as before); an edit that changes nothing costs no write, so a periodic sweep on an idle node touches no disk."""
        with self._locked():
            raw = self._raw()
            before = json.dumps(raw, sort_keys=True)                  # (a snapshot: the records below are the same objects, `fn` changes them in place)
            d = {k: v for k, v in raw.items() if self.ok(k, v)}
            out = fn(d)
            if json.dumps(d, sort_keys=True) != before:
                self._save(d)
            return out


def _int(v) -> bool:
    return type(v) is int and 0 <= v < 2 ** 40


def _types_ok(t, limit: int = MAX_JOINS) -> bool:
    return isinstance(t, list) and 1 <= len(t) <= limit and all(isinstance(x, str) and TYPE_RE.fullmatch(x) for x in t) and len(set(t)) == len(t)


def _offers_ok(offers, types) -> bool:
    """1..len(types) offers, distinct carrier types, each in `types`, each endpoint and credential exactly as normalized and of the same type."""
    if not isinstance(offers, list) or not 1 <= len(offers) <= len(types):
        return False
    seen = []
    for o in offers:
        if not isinstance(o, dict) or set(o) != {"endpoint", "credential"}:
            return False
        ep, cr = check_endpoint(o["endpoint"]), check_credential(o["credential"])
        if ep != o["endpoint"] or cr != o["credential"] or ep["type"] != cr["type"] or ep["type"] not in types or ep["type"] in seen:
            return False
        seen.append(ep["type"])
    return True


def _ok_record(k, v) -> bool:
    """A record from capsules.json that is not exactly what we wrote is dropped (its doors, if any, are then orphans and are swept)."""
    try:
        if not (isinstance(k, str) and CID_RE.fullmatch(k) and isinstance(v, dict) and v.get("state") in STATES and _int(v.get("exp")) and is_hex(v.get("tok"), 64)
                and is_hex(v.get("thread"), 32) and v.get("door") == f"join-{k}" and _types_ok(v.get("types")) and all(_int(v[x]) for x in ("at", "deadline") if x in v)):
            return False
        types = v["types"]
        if "owner_door" in v and not (isinstance(v["owner_door"], str) and re.fullmatch(r"peer-[a-z2-7]{27}", v["owner_door"])):
            return False
        if "door_gone" in v and not (isinstance(v["door_gone"], dict) and v["door_gone"] and all(t in types and x is True for t, x in v["door_gone"].items())):
            return False
        if "partial" in v and not (isinstance(v["partial"], list) and all(t in types for t in v["partial"])):
            return False
        if v["state"] in ("pending", "confirming", "confirmed"):
            q = v.get("req")
            if not (isinstance(q, dict) and set(q) == {"agent", "sign", "kex", "name", "offers"} and isinstance(q["agent"], str) and AGENT_ID_RE.fullmatch(q["agent"])
                    and clean_text(q["name"], NAME_MAX) and _offers_ok(q["offers"], types)):
                return False
        return True
    except (TypeError, KeyError, ValueError):
        return False


def _ok_join(k, v) -> bool:
    try:
        o = v["owner"]
        eps = v["endpoints"]
        if not (isinstance(eps, list) and all(isinstance(e, dict) and set(e) == {"endpoint"} and isinstance(e["endpoint"], dict) and check_endpoint(e["endpoint"]) == e["endpoint"] for e in eps)
                and _types_ok([e["endpoint"]["type"] for e in eps])):
            return False
        types = [e["endpoint"]["type"] for e in eps]
        used, offered, mypub = v["used"], v["offered"], v["mypub"]
        if not (_types_ok(used) and all(t in types for t in used) and isinstance(offered, list) and all(t in used for t in offered) and len(set(offered)) == len(offered)
                and isinstance(mypub, dict) and set(mypub) == set(used) and all(check_credential(c) == c and c["type"] == t for t, c in mypub.items())):
            return False
        return bool(isinstance(k, str) and CID_RE.fullmatch(k) and isinstance(v, dict) and v.get("state") in ("door", "requested", "joined", "failed") and is_hex(v["thread"], 32)
                    and is_hex(v["token"], 32) and _int(v["exp"]) and isinstance(o, dict) and isinstance(o.get("id"), str) and AGENT_ID_RE.fullmatch(o["id"]) and is_hex(o.get("sign"), 64)
                    and clean_text(o.get("name"), NAME_MAX)
                    and isinstance(v["door"], str) and NAME_RE.fullmatch(v["door"]) and v.get("key") == f"join-{k}" and clean_text(v.get("name"), NAME_MAX)
                    and all(_int(v[x]) for x in ("at",) if x in v))
    except (TypeError, KeyError, ValueError, AttributeError):
        return False


def _tok_hash(token: str) -> str:
    return hashlib.sha256(bytes.fromhex(token)).hexdigest()


def _dial_file(home: Path, cid: str, etype: str) -> Path:
    return home / "peerkeys" / f"cap-{cid}-{etype}.priv"


def _write_key(path: Path, secret) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(dict(secret)))


def create(home, carriers, me: Identity, m, tid: str, *, ttl: int = DEFAULT_TTL, passphrase: str | None = None, bridges=(), clock=time.time, wait_address=None, all_carriers=None) -> tuple:
    """Open a join door on each of `carriers` (one, a list, or a {type: carrier} dict: the issuer's order) and build the capsule block. Returns (block, capsule id, owner fingerprint).
    `wait_address(carrier, name)` must return the door's endpoint (a running node creates it; the CLI waits for it). The RECORD is written first (atomically with the MAX_OPEN check), then
    the doors: a door without a record is an orphan and the startup sweep deletes it, so a crash between the steps leaves nothing behind. All or nothing: a carrier that fails tears down
    the doors already made and the record. `all_carriers` = every carrier this node runs: the sweep that frees expired capsules first acts on all of them (without it only the listed ones are
    swept and no type counts as gone by absence: an old capsule's door on another carrier is left for the node's own sweep)."""
    home = Path(home)
    cs = _carrier_list(carriers)
    t = m.threads.get(tid)
    if t is None:
        raise CapsuleError("no such thread")
    st = t.state()
    if st["owner"] != me.id:
        raise CapsuleError("only the owner of a thread makes capsules for it")
    if st["visibility"] != "private":
        raise CapsuleError("capsules are for private threads (a public thread takes guests)")
    if not 60 <= ttl <= MAX_TTL:
        raise CapsuleError("ttl: between 60 s and 24 h")
    store = Store(home, clock)
    if all_carriers is not None:
        sweep(home, all_carriers, clock=clock)
    else:
        sweep(home, cs, clock=clock, served=ALL)
    cid = secrets.token_hex(4)
    token = secrets.token_hex(16)
    exp = int(clock()) + ttl

    def claim(d):
        if sum(1 for r in d.values() if r.get("state") in ("open", "pending", "confirming")) >= MAX_OPEN:
            raise CapsuleError(f"{MAX_OPEN} capsules are already open: confirm, reject or wait for them to expire")
        d[cid] = {"tok": _tok_hash(token), "thread": tid, "exp": exp, "door": f"join-{cid}", "types": [c.type for c in cs], "state": "open", "at": int(clock())}
    store.edit(claim)
    try:
        name = f"join-{cid}"
        joins = []
        for c in cs:
            boot_secret, boot_pub = c.new_credential()
            dial_secret, dial_pub = c.new_credential()
            _write_key(_dial_file(home, cid, c.type), dial_secret)
            c.open_door(name, "join", credential=boot_pub)
            endpoint = wait_address(c, name) if wait_address else c.door_endpoint(name)
            if not endpoint:
                raise CapsuleError(f"the {c.type} join door has no address yet: start `node run` (the carrier creates it), then run this again")
            joins.append({"endpoint": endpoint, "boot": _wrap_secret(boot_secret["key"], passphrase) if passphrase else dict(boot_secret), "dial": dial_pub})
        me_pub = {"id": me.id, "sign": me.sign_pub, "kex": me.kex_pub, "name": (me.name or me.id[:8])[:NAME_MAX]}
        obs = [{"id": a, "name": (x["name"] or a[:8])[:NAME_MAX]} for a, x in st["members"].items() if x["role"] == "observer"][:8]
        rules = {k: v for k, v in st["rules"].items() if type(v) is int}
        cap = {"v": 2, "thread": tid, "title": st["title"][:80], "exp": exp, "owner": me_pub, "joins": joins, "token": token, "observers": obs, "rules": rules,
               "bridges": [b for b in bridges if isinstance(b, str) and b.startswith("Bridge ")][:MAX_BRIDGES],
               "enc": bool(getattr(m.codec, "is_encrypted", lambda _: False)(tid))}
        block = encode_capsule(cap)
        decode_capsule(block, now=clock())                          # what we built must pass what the joiner checks
    except Exception:
        _teardown(home, cs, cid)
        store.edit(lambda d: d.pop(cid, None))                      # a capsule that was never handed out leaves no record (and no slot taken)
        raise
    return block, cid, fingerprint(me.id)


def _teardown(home: Path, carriers, cid: str, skip=()) -> set:
    """Delete the join door (and with it the bootstrap key) on every carrier except the types in `skip`, and the dial key files; idempotent. Returns the set of types whose door is REALLY gone."""
    gone = set()
    cs = _as_list(carriers)
    for c in cs:
        if c.type in skip:
            continue
        try:
            c.close_door(f"join-{cid}")
        except (ValueError, OSError):
            continue
        if c.door_gone(f"join-{cid}"):
            gone.add(c.type)
    for c in cs:
        _drop_dial_key(home, cid, c.type)
    return gone


def _drop_dial_key(home: Path, cid: str, etype: str) -> None:
    try:
        _dial_file(home, cid, etype).unlink()
    except OSError:
        pass


ALL = "all"                          # sweep(served=ALL): no type counts as gone because its carrier is absent from the call


def sweep(home, carriers, *, clock=time.time, skip=(), served=None) -> list:
    """Expiry and grace teardown, orphan doors, and forgetting old records, on EVERY carrier given. Safe to run at any time (the node runs it at startup and every tick).
    A type is marked in the record's `door_gone` only when its door really is gone (a failed removal, or a carrier in `skip`, is retried on the next sweep); a type no carrier of this node
    serves any more counts as gone (there is nothing we could close): `served` = the types this node runs (default: the types of `carriers`; ALL: none counts as absent). A carrier that
    runs but is not among `carriers` of THIS call is left alone, neither torn down nor marked. The record is forgotten only when every type is gone. Returns ids torn down."""
    home = Path(home)
    cs = _carrier_list(carriers)
    have = {c.type for c in cs} if served is None else (None if served == ALL else set(served))
    store = Store(home, clock)
    now = clock()
    gone = []
    recs = store.all()
    for cid, rec in recs.items():
        st = rec["state"]
        if st == "confirming" and now - rec.get("at", 0) > CONFIRMING_STALE:
            store.edit(lambda d, cid=cid: d[cid].update(state="pending", at=int(now)) if cid in d else None)     # the confirm died half way: the owner decides again
            continue
        expired = st in ("open", "pending") and now > rec["exp"]
        grace_over = st == "confirmed" and now > rec.get("deadline", 0)
        if expired:
            store.edit(lambda d, cid=cid: d[cid].update(state="expired", at=int(now)) if cid in d else None)
        done = set(rec.get("door_gone") or {})
        if (expired or grace_over or st in ("rejected", "expired")) and not done >= set(rec["types"]):
            now_gone = _teardown(home, [c for c in cs if c.type in rec["types"]], cid, skip=tuple(skip) + tuple(done))
            if have is not None:
                now_gone |= {t for t in rec["types"] if t not in have}
            if now_gone - done:
                store.edit(lambda d, cid=cid, ng=now_gone: d[cid].update(door_gone={t: True for t in sorted(ng | set(d[cid].get("door_gone") or {}))}) if cid in d else None)
            if set(rec["types"]) <= (done | now_gone):
                gone.append(cid)
                for t in rec["types"]:
                    _drop_dial_key(home, cid, t)
        elif set(rec.get("door_gone") or {}) >= set(rec["types"]) and st in ("rejected", "expired", "confirmed") and now - rec.get("at", 0) > KEEP:
            store.edit(lambda d, cid=cid: d.pop(cid, None))
    known = {f"join-{c}" for c in store.all()}
    for c in cs:
        if c.type in skip:
            continue
        for name, svc in c.doors().items():                          # a join door with no record (a crash between the steps, a damaged file) is an orphan
            if svc.get("kind") == "join" and name not in known:
                try:
                    c.close_door(name)
                    gone.append(name)
                except (ValueError, OSError):
                    pass
    return gone


def offers_problem(by_type: dict, offers, types) -> str | None:
    """Why a list of offers (the joiner's doors) is refused: shape, distinct carrier types of THIS capsule that we run (`by_type`: {type: carrier}), and each address passes the carrier's own rules
    (R1: loopback, link-local, our own door... since any IPv4 or IPv6 address may be dialed now). None = fine."""
    if not isinstance(offers, list) or not 1 <= len(offers) <= len(types):
        return "the number of offers"
    seen = []
    for o in offers:
        if not isinstance(o, dict) or set(o) != {"endpoint", "credential"}:
            return "an offer is not {endpoint, credential}"
        try:
            ep, cr = check_endpoint(o["endpoint"]), check_credential(o["credential"])
        except ValueError as e:
            return str(e)
        if ep["type"] != cr["type"] or ep["type"] not in types or ep["type"] not in by_type or ep["type"] in seen:
            return "an offer's carrier"
        why = by_type[ep["type"]].locator_problem(ep["addr"])
        if why:
            return f"the {ep['type']} address: {why}"
        seen.append(ep["type"])
    return None


def sealed_keys(m, tid: str, req: dict):
    """[] for a plaintext thread; for an encrypted one the key of every epoch on the current chain, each sealed to the JOINER's kex key (`req`: {kex, agent}, from its SIGNED request);
    None if we cannot provide them (then the answer waits)."""
    from .envelope import chain_epoch_ids, seal_key
    t = m.threads.get(tid)
    codec = m.codec
    if t is None or not getattr(codec, "is_encrypted", lambda _: False)(t.id):
        return []
    ring, out = codec.ring(t.id), []
    for kid in chain_epoch_ids(t)[:64]:
        got = ring.get(kid)
        if got is not None and got[1]:
            out.append({"id": kid, "sealed": seal_key(req["kex"], req["agent"], t.id, kid, got[0]), "conf": ring.conf(kid)})
    return out or None


# ---------------------------------------------------------------- owner side: what the join door answers

class JoinServer:
    """The handler of the `join` doors (one instance behind every carrier's join door): ONLY `join_request` and `join_status`. Anything else is refused without detail."""

    def __init__(self, home, carriers, me: Identity, m, clock=time.time):
        self.home, self.carriers, self.me, self.m, self.clock = Path(home), _carrier_list(carriers), me, m, clock
        self.by_type = {c.type: c for c in self.carriers}
        self.store = Store(home, clock)

    def _sign(self, body: dict) -> dict:
        body = {**body, "by": self.me.sign_pub}
        body["rsig"] = self.me.sign(JOIN_CTX + canon.dumps(body))
        return body

    def handle(self, req) -> dict:
        try:
            return self._handle(req)
        except Exception:                                           # noqa: BLE001
            return {"t": "refused"}

    def _handle(self, req) -> dict:
        if not isinstance(req, dict) or not isinstance(req.get("token"), str) or not is_hex(req["token"], 32):
            return {"t": "refused"}
        th = _tok_hash(req["token"])
        cid = next((k for k, v in self.store.all().items() if hmac.compare_digest(v.get("tok", ""), th)), None)
        if cid is None:
            return {"t": "refused"}
        if req.get("t") == "join_request":
            return self._request(cid, req)
        if req.get("t") == "join_status" and set(req) == {"t", "token"}:
            return self._status(cid, req["token"])
        return {"t": "refused"}

    def offers_problem(self, offers, types) -> str | None:
        return offers_problem(self.by_type, offers, types)

    def _request(self, cid: str, req: dict) -> dict:
        if set(req) != {"t", "token", "sign", "kex", "name", "offers", "sig"}:
            return {"t": "refused"}
        try:
            if not is_hex(req["sig"], 128) or not verify_strict(req["sign"], req["sig"], JOINREQ_CTX + canon.dumps({k: v for k, v in req.items() if k != "sig"})):
                return {"t": "refused"}                               # the joiner's kex key is covered by ITS OWN signature: a capsule holder cannot pair a victim's id with another kex key
        except Exception:                                             # noqa: BLE001
            return {"t": "refused"}
        if not (is_hex(req["sign"], 64) and valid_sign_pub(req["sign"]) and isinstance(req["kex"], str) and valid_kex_pub(req["kex"])):
            return {"t": "refused"}
        if not clean_text(req["name"], NAME_MAX) or not req["name"]:
            return {"t": "refused"}
        rec0 = self.store.all().get(cid)
        if rec0 is None or self.offers_problem(req["offers"], rec0["types"]) is not None:
            return {"t": "refused"}                                   # the whole request: a capsule holder cannot get us to dial an address we would never dial
        offers = sorted((dict(o) for o in req["offers"]), key=lambda o: rec0["types"].index(o["endpoint"]["type"]))
        agent = agent_id(bytes.fromhex(req["sign"]))
        result = {}

        def edit(d):
            rec = d.get(cid)
            if rec is not None and rec.get("state") == "pending" and rec["req"]["agent"] == agent and rec["req"]["sign"] == req["sign"] and self.clock() <= rec["exp"]:
                old = {o["endpoint"]["type"]: o for o in rec["req"]["offers"]}
                new = {o["endpoint"]["type"]: o for o in offers}
                if rec["req"]["kex"] == req["kex"] and len(new) > len(old) and all(new.get(t) == o for t, o in old.items()):
                    rec["req"]["offers"] = offers                    # the SAME joiner again with more doors (a slow carrier came up): only types are added, nothing existing changes
                result["r"] = {"t": "pending"}                       # (otherwise idempotent: its first answer may have been lost over tor)
                return
            if rec is None or rec.get("state") != "open" or self.clock() > rec["exp"]:
                result["r"] = {"t": "refused"}                       # one request per token: a second one (or a junk one that burned it) is refused; re-issue
                return
            t = self.m.threads.get(rec["thread"])
            if t is None or agent in t.state()["members"]:
                result["r"] = {"t": "refused"}
                return
            rec.update(state="pending", req={"agent": agent, "sign": req["sign"], "kex": req["kex"], "name": req["name"], "offers": offers}, at=int(self.clock()))
            result["r"] = {"t": "pending"}
        self.store.edit(edit)
        return result["r"]

    def _sealed_keys(self, rec: dict):
        return sealed_keys(self.m, rec["thread"], rec["req"])

    def _status(self, cid: str, token: str) -> dict:
        rec = self.store.all().get(cid, {})
        st = rec.get("state")
        if st in ("open", "pending"):
            return {"t": "wait"}
        if st == "confirmed":
            offered = [o["endpoint"]["type"] for o in rec["req"]["offers"]]
            endpoints, missing = [], []
            for t in rec["types"]:                                    # the issuer's order
                if t in offered and t in self.by_type:
                    ep = self.by_type[t].door_endpoint(rec.get("owner_door", ""))
                    (endpoints if ep else missing).append(ep or t)
            if missing and self.clock() - rec.get("at", 0) < ANSWER_WAIT:
                return {"t": "wait"}                                  # R2: the answer is FINAL (the doors go soon after): a carrier whose door has no address yet gets a minute
            if not endpoints:
                return {"t": "wait"}
            keys = self._sealed_keys(rec)
            if keys is None:
                return {"t": "wait"}                                  # an encrypted thread is never answered without its keys
            body = self._sign({"t": "joined", "token": token, "endpoints": endpoints, "thread": rec["thread"], "owner": self.me.id, "enc": bool(keys), "keys": keys})
            self.store.edit(lambda d: d[cid].update(deadline=min(d[cid].get("deadline", 0), int(self.clock()) + 120), **({"partial": missing} if missing else {})) if cid in d else None)    # collected: the doors go soon (a retry still works)
            return body
        return {"t": "refused"}


# ---------------------------------------------------------------- owner side: decisions (only a human runs these)

def _no_rebind(carrier, door: str, agent: str) -> None:
    """open_door would re-bind an existing door (and replace its key) to whatever agent it is given: never do that to a door that belongs to someone else."""
    have = carrier.doors().get(door)
    if have is not None and have.get("agent") != agent:
        raise CapsuleError(f"a door named {door!r} already belongs to another agent: nothing was changed")


class _Pub:
    def __init__(self, agent, sign, kex, name):
        self.id, self.sign_pub, self.kex_pub, self.name = agent, sign, kex, name


def pending(home, clock=time.time) -> dict:
    return {k: v for k, v in Store(home, clock).all().items() if v.get("state") == "pending" and clock() <= v.get("exp", 0)}


def confirm(home, carriers, me: Identity, m, book, cid: str, typed_fp: str, *, clock=time.time) -> dict:
    """The owner's human read the joiner's fingerprint to us through another channel and typed it: only now does anything change.
    The record is CLAIMED first (pending -> confirming, so a sweep cannot expire it under us), the idempotent steps come before the member_add,
    and a failure puts the record back to pending (a retry works) after closing the peer doors THIS attempt created and removing a peer entry it added (R4)."""
    from .build import Writer
    home = Path(home)
    by_type = {c.type: c for c in _carrier_list(carriers)}
    store = Store(home, clock)
    rec = store.all().get(cid)
    if rec is None or rec.get("state") != "pending" or clock() > rec["exp"]:
        raise CapsuleError("no such pending request (expired, rejected, or already decided)")
    r = rec["req"]
    if not same_fingerprint(typed_fp, r["agent"]):
        raise CapsuleError("the fingerprint does not match the joiner's: nothing was changed. Ask the joiner to read it to you again.")
    offers = [o for o in r["offers"] if o["endpoint"]["type"] in by_type]
    if not offers:
        raise CapsuleError("none of the joiner's offers is on a carrier this node runs: nothing was changed")
    for o in offers:                                                  # (R1 again: the record may be old, the carrier's rules may have changed)
        why = by_type[o["endpoint"]["type"]].locator_problem(o["endpoint"]["addr"])
        if why:
            raise CapsuleError(f"the joiner's {o['endpoint']['type']} address is refused ({why}): nothing was changed")
    claimed = {}

    def claim(d):
        x = d.get(cid)
        if x is not None and x.get("state") == "pending" and clock() <= x["exp"]:
            x.update(state="confirming", at=int(clock()))
            claimed["ok"] = True
    store.edit(claim)
    if not claimed:
        raise CapsuleError("no such pending request (expired, rejected, or already decided)")
    door = f"peer-{r['agent'][:27]}"                                 # 135 bits of the id: nobody grinds an id that collides with another peer's door name
    created, book_had = [], r["agent"] in book.all()
    try:
        t = m.threads.get(rec["thread"])
        if t is None or t.state()["owner"] != me.id:
            raise CapsuleError("thread is gone or not ours")
        dials = {o["endpoint"]["type"]: check_credential(json.loads(_dial_file(home, cid, o["endpoint"]["type"]).read_text()), secret=True) for o in offers}      # fail before anything changes
        for o in offers:
            _no_rebind(by_type[o["endpoint"]["type"]], door, r["agent"])
        for o in offers:
            c = by_type[o["endpoint"]["type"]]
            if c.doors().get(door) is None:
                created.append(c)
            c.open_door(door, "peer", credential=o["credential"], agent=r["agent"])
            c.use_credential(o["endpoint"], dials[c.type], agent=r["agent"])        # held under the joiner's node id too: its address may change (DESIGN_locator_book.md)
            book.add(r["agent"], r["name"], o["endpoint"], [rec["thread"]])
        if r["agent"] not in t.state()["members"]:
            res = m.ingest(Writer(me, t).add_member(_Pub(r["agent"], r["sign"], r["kex"], r["name"]), "member"))
            if not res.ok:
                raise CapsuleError(f"member_add refused: {res.status} {res.reason}")
    except BaseException:
        for c in created:                                            # R4: the doors this attempt opened must not outlive it (a reject would leave a door bound to a non-member)
            try:
                c.close_door(door)
            except (ValueError, OSError):
                pass
        if not book_had:
            try:
                book.remove(r["agent"])
            except Exception:                                        # noqa: BLE001
                pass
        store.edit(lambda d: d[cid].update(state="pending", at=int(clock())) if cid in d else None)
        raise
    for t_ in rec["types"]:
        _drop_dial_key(home, cid, t_)                                # our tor keeps its copy in ClientOnionAuthDir; the capsule's files are no longer needed
    store.edit(lambda d: d[cid].update(state="confirmed", owner_door=door, deadline=int(clock()) + GRACE, at=int(clock())) if cid in d else None)
    return {"agent": r["agent"], "name": r["name"], "door": door, "carriers": [o["endpoint"]["type"] for o in offers]}


def reject(home, carriers, cid: str, *, clock=time.time, book=None) -> bool:
    """Reject an open or pending capsule: the join doors go. With `book`, a peer door bound to the request's agent that the peer book does not hold (left by a failed confirm) goes too."""
    store = Store(home, clock)
    rec = store.all().get(cid)
    if rec is None or rec.get("state") not in ("open", "pending", "confirming"):
        return False
    store.edit(lambda d: d[cid].update(state="rejected", at=int(clock())) if cid in d else None)
    cs = _carrier_list(carriers)
    if book is not None and isinstance(rec.get("req"), dict):
        agent = rec["req"]["agent"]
        if agent not in book.all():
            for c in cs:
                try:
                    for name, d in c.doors().items():
                        if d.get("kind") == "peer" and d.get("agent") == agent:
                            c.close_door(name)
                except (ValueError, OSError):
                    continue
    gone = _teardown(Path(home), [c for c in cs if c.type in rec["types"]], cid)
    gone |= {t for t in rec["types"] if t not in {c.type for c in cs}}
    if gone:
        store.edit(lambda d: d[cid].update(door_gone={t: True for t in sorted(gone | set(d[cid].get("door_gone") or {}))}) if cid in d else None)      # (what is not gone yet, the next sweep retries)
    return True


# ---------------------------------------------------------------- joiner side

class Joins:
    """joins.json: what this agent is in the middle of joining. Record per capsule id: {thread, owner, endpoints (the capsule's join doors, the issuer's order), used (the carriers we use), offered
    (the carriers whose door the owner has been told about), token, exp, door, mypub ({type: credential}), key, state, name, enc}.
    States: door (our doors for the owner exist) -> requested (join_request accepted, waiting for the human) -> joined | failed."""

    def __init__(self, home, clock=time.time):
        self.home, self.clock = Path(home), clock
        self.store = Store(home, clock, name="joins.json", ok=_ok_join)

    def all(self):
        return self.store.all()

    def edit(self, fn):
        return self.store.edit(fn)


def accept(home, carriers, me: Identity, block: str, typed_fp: str, *, passphrase: str | None = None, only=None, clock=time.time, wait_address=None) -> dict:
    """The joiner's human compared the OWNER's fingerprint through a second channel and typed it. Builds our door for the owner on every carrier the capsule and this node have in common
    (`only`: restrict to these types, so a node that also runs tcp can keep its IP out of it) and records the join; the node loop sends the request (poll).
    Returns {cid, fingerprint, doors {type: our door's endpoint or None}, used, bridges}."""
    home = Path(home)
    c = decode_capsule(block, now=clock())
    if not same_fingerprint(typed_fp, c["owner"]["id"]):
        raise CapsuleError("the fingerprint does not match the capsule's owner: do NOT join. Either you typed it wrong or the capsule is not from who you think.")
    if c["owner"]["id"] == me.id:
        raise CapsuleError("this capsule is yours")
    cs = {x.type: x for x in _carrier_list(carriers)}
    entries = c["joins"]
    use = [e for e in entries if e["endpoint"]["type"] in cs and (only is None or e["endpoint"]["type"] in only)]
    if not use:
        raise CapsuleError(f"this capsule needs a carrier of one of {[e['endpoint']['type'] for e in entries]}"
                           + (f" (restricted to {sorted(only)})" if only is not None else "") + f"; this node runs {sorted(cs)}")
    for e in use:                                                     # R1: an address a stranger's block hands us is checked like an announced one
        why = cs[e["endpoint"]["type"]].locator_problem(e["endpoint"]["addr"])
        if why:
            raise CapsuleError(f"the capsule's {e['endpoint']['type']} address is refused ({why}): do not use this capsule")
    boots = {}
    for e in use:
        jt = e["endpoint"]["type"]
        try:
            boots[jt] = check_credential(e["boot"] if "key" in e["boot"] else {"type": jt, "key": _unwrap_secret(e["boot"], passphrase or "")}, secret=True)
        except ValueError:
            raise CapsuleError("bad bootstrap key") from None
    cid = hashlib.sha256(bytes.fromhex(c["token"])).hexdigest()[:8]
    joins = Joins(home, clock)
    if cid in joins.all():
        raise CapsuleError("you already used this capsule")
    door = f"owner-{c['owner']['id'][:26]}"
    for e in use:
        _no_rebind(cs[e["endpoint"]["type"]], door, c["owner"]["id"])
    mypub = {}
    for e in use:
        jt = e["endpoint"]["type"]
        car = cs[jt]
        mysecret, mypub[jt] = car.new_credential()
        car.use_credential(e["endpoint"], boots[jt])                  # so our carrier can reach the join door (Tor: read its descriptor)
        car.open_door(door, "peer", credential=e["dial"], agent=c["owner"]["id"])      # OUR door for the owner on this carrier, authorized with THIS capsule's throwaway dial key of that type
        _write_key(home / "peerkeys" / f"join-{cid}-{jt}.priv", mysecret)
    joins.edit(lambda d: d.__setitem__(cid, {"thread": c["thread"], "owner": c["owner"], "endpoints": [{"endpoint": e["endpoint"]} for e in entries], "used": [e["endpoint"]["type"] for e in use],
                                             "offered": [], "token": c["token"], "exp": c["exp"], "door": door, "mypub": mypub, "key": f"join-{cid}", "state": "door", "at": int(clock()),
                                             "name": (me.name or me.id[:8])[:NAME_MAX], "enc": bool(c["enc"])}))
    addrs = {}
    for e in use:
        jt = e["endpoint"]["type"]
        addrs[jt] = wait_address(cs[jt], door) if wait_address else cs[jt].door_endpoint(door)
    return {"cid": cid, "fingerprint": fingerprint(me.id), "doors": addrs, "used": [e["endpoint"]["type"] for e in use], "bridges": c["bridges"]}


def _verify_joined(resp: dict, rec: dict, carriers=None) -> bool:
    """The owner's signed answer: from the capsule's owner, for this token and thread, and 1..n endpoints of DISTINCT carrier types that we offered a door on (with `carriers`, each also
    passes that carrier's own address rules: R1)."""
    try:
        by, sig = resp.get("by"), resp.get("rsig")
        if by != rec["owner"]["sign"] or not is_hex(sig, 128):
            return False
        if not verify_strict(by, sig, JOIN_CTX + canon.dumps({k: v for k, v in resp.items() if k != "rsig"})):
            return False
        eps = resp["endpoints"]
        if not isinstance(eps, list) or not 1 <= len(eps) <= len(rec["offered"]):
            return False
        seen = []
        for ep in eps:
            ep = check_endpoint(ep)
            if ep["type"] in seen or ep["type"] not in rec["offered"]:
                return False
            if carriers is not None:
                car = carriers.get(ep["type"])
                if car is None or car.locator_problem(ep["addr"]):
                    return False
            seen.append(ep["type"])
        return resp.get("t") == "joined" and resp.get("token") == rec["token"] and resp.get("thread") == rec["thread"] and resp.get("owner") == rec["owner"]["id"]
    except Exception:                                               # noqa: BLE001
        return False


def poll(home, carriers, me: Identity, book, transport_for, *, clock=time.time, codec=None) -> dict:
    """One pass over pending joins (the node loop calls this every ~20 s from a worker). `transport_for(endpoint)` returns an object with .request(dict) (or raises: that carrier is down).
    Requests go to the capsule's join doors in the issuer's order over the carriers we use; the first that answers wins. The request is sent as soon as ONE of our doors has an address and,
    while the owner still holds it pending, sent again with more offers when another door gets its address (a slow Tor). Returns {cid: state} for what changed."""
    home = Path(home)
    cs = {x.type: x for x in _carrier_list(carriers)}
    joins = Joins(home, clock)
    changed = {}

    def ask(rec, body):
        for e in rec["endpoints"]:
            if e["endpoint"]["type"] not in rec["used"] or e["endpoint"]["type"] not in cs:
                continue
            try:
                resp = transport_for(e["endpoint"]).request(body)
            except Exception:                                       # noqa: BLE001 - this carrier is down or the owner is not on it: the next one
                continue
            if isinstance(resp, dict):
                return resp
        return None

    for cid, rec in joins.all().items():
        if rec.get("state") not in ("door", "requested"):
            continue
        if clock() > rec["exp"] + GRACE:
            joins.edit(lambda d, cid=cid: d[cid].update(state="failed", why="expired"))
            _forget_join(home, cs, rec)
            changed[cid] = "failed"
            continue
        mine = {t: cs[t].door_endpoint(rec["door"]) for t in rec["used"] if t in cs}
        ready = [t for t in rec["used"] if mine.get(t)]
        if not ready:
            continue                                                # our own doors have no address yet (the carriers are still creating them)
        try:
            def offers_body(types):
                body = {"t": "join_request", "token": rec["token"], "sign": me.sign_pub, "kex": me.kex_pub, "name": rec["name"],
                        "offers": [{"endpoint": mine[t], "credential": rec["mypub"][t]} for t in types]}
                return {**body, "sig": me.sign(JOINREQ_CTX + canon.dumps(body))}
            if rec["state"] == "door":
                resp = ask(rec, offers_body(ready))
                if resp is not None and resp.get("t") == "pending":
                    joins.edit(lambda d, cid=cid, ready=ready: d[cid].update(state="requested", offered=list(ready)))
                    rec = {**rec, "state": "requested", "offered": list(ready)}
                    changed[cid] = "requested"
                elif resp is not None and resp.get("t") == "refused":
                    joins.edit(lambda d, cid=cid: d[cid].update(state="failed", why="refused (token used, expired, a door of ours the owner cannot take, or already a member)"))
                    _forget_join(home, cs, rec)
                    changed[cid] = "failed"
                continue
            if set(ready) - set(rec["offered"]):                    # a door that came up after the request: tell the owner while it is still pending (refused = it decided already: fine)
                resp = ask(rec, offers_body(ready))
                if resp is not None and resp.get("t") == "pending":
                    joins.edit(lambda d, cid=cid, ready=ready: d[cid].update(offered=list(ready)))
                    rec = {**rec, "offered": list(ready)}
            resp = ask(rec, {"t": "join_status", "token": rec["token"]})
            if resp is None:
                continue
            if resp.get("t") == "refused":
                joins.edit(lambda d, cid=cid: d[cid].update(state="failed", why="the owner refused, or the capsule expired"))
                _forget_join(home, cs, rec)
                changed[cid] = "failed"
            elif resp.get("t") == "joined" and _verify_joined(resp, rec, cs):
                why = _install_keys(resp, rec, me, codec)
                if why:
                    joins.edit(lambda d, cid=cid, why=why: d[cid].update(state="failed", why=why))
                    _forget_join(home, cs, rec)
                    changed[cid] = "failed"
                    continue
                for ep in (check_endpoint(e) for e in resp["endpoints"]):               # (the normalised spelling, like everywhere else)
                    secret = check_credential(json.loads((home / "peerkeys" / f"{rec['key']}-{ep['type']}.priv").read_text()), secret=True)
                    cs[ep["type"]].use_credential(ep, secret, agent=rec["owner"]["id"])
                    book.add(rec["owner"]["id"], rec["owner"]["name"], ep, [rec["thread"]])
                joins.edit(lambda d, cid=cid: d[cid].update(state="joined", at=int(clock())))
                _forget_join(home, cs, rec, keep_key=True)
                changed[cid] = "joined"
        except Exception:                                           # noqa: BLE001 - tor not ready, owner offline: try again next pass
            continue
    return changed


def _install_keys(resp: dict, rec: dict, me: Identity, codec) -> str | None:
    """The thread keys in the owner's SIGNED answer go into the keyring (trusted: the owner's signed answer) and the thread is marked encrypted.
    Returns a reason to refuse the join, or None. A capsule that said `enc` with no keys in the answer is refused; keys in the answer win over `enc`=false."""
    from .envelope import EnvelopeError, open_key
    keys = resp.get("keys")
    if not isinstance(keys, list) or len(keys) > 64:
        return "malformed keys in the owner's answer"
    if not keys:
        return "the capsule says the thread is encrypted but the owner sent no keys" if rec.get("enc") else None
    if codec is None or not hasattr(codec, "ring"):
        return "the owner sent thread keys but this node has no encrypting keyring"
    opened = []
    for k in keys:
        try:
            opened.append((k["id"], open_key(me, rec["thread"], k["id"], k["sealed"])))
        except (EnvelopeError, KeyError, TypeError):
            return "a thread key in the owner's answer does not open"
    ring = codec.ring(rec["thread"])
    for (kid, key), k in zip(opened, keys):
        ring.install(kid, key, verified=True, conf=k.get("conf"))     # the owner's SIGNED answer (human-confirmed capsule) is our trust anchor at join time
    codec.mark(rec["thread"])
    return None


def _forget_join(home: Path, carriers, rec: dict, keep_key: bool = False) -> None:
    """Delete the bootstrap client key of every join door (it must not outlive the join), and unless `keep_key` our own key files."""
    cs = {x.type: x for x in _carrier_list(carriers)}
    for e in rec["endpoints"]:
        c = cs.get(e["endpoint"]["type"])
        if c is None:
            continue
        try:
            c.drop_credential(e["endpoint"])
        except (OSError, ValueError):
            pass
    if not keep_key:
        for t in rec["used"]:
            try:
                (home / "peerkeys" / f"{rec['key']}-{t}.priv").unlink()
            except OSError:
                pass
