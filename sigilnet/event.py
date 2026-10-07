"""The signed event (spec section 4): structure, id, signing, co-signatures. No thread rules here (see thread.py)."""
from __future__ import annotations

import hashlib
import re
import time

from . import canon
from .keys import AGENT_ID_RE, Identity, is_hex

V = 1                                  # the default format (what a thread made without a choice is)
SUPPORTED = (1, 2)                     # thread formats this code reads and writes: the format of a thread is the `v` of its genesis (DESIGN_versioning.md)
ADMIN_KINDS = frozenset({"genesis", "member_add", "member_remove", "revoke", "rules_update", "checkpoint",
                         "owner_transfer", "owner_takeover", "close"})
OTHER_KINDS = frozenset({"post", "digest", "evidence"})
KINDS = ADMIN_KINDS | OTHER_KINDS
X_KIND_RE = re.compile(r"x-[a-z0-9][a-z0-9._-]{0,47}")     # extension kinds (format 2 only): stored, relayed, never interpreted, never an admin kind
REQUIRED = frozenset({"v", "thread", "author", "seq", "parents", "admin_ref", "ts", "kind", "body", "sig"})
OPTIONAL = frozenset({"cosigs"})
MAX_PARENTS = 16
MAX_COSIGS = 16
MAX_SEQ = 2 ** 31
MAX_TS = 2 ** 40


class EventError(ValueError):
    """The event is malformed or not valid (the message says why; used as the rejection reason)."""


def is_ext_kind(kind) -> bool:
    return isinstance(kind, str) and X_KIND_RE.fullmatch(kind) is not None


def signed_bytes(ev: dict) -> bytes:
    """What every signer signs: the canonical bytes of the event WITHOUT `sig` and `cosigs`."""
    return canon.dumps({k: v for k, v in ev.items() if k not in ("sig", "cosigs")})


EVENT_CTX = b"sigilnet/v1/event\0"      # domain separation: a signature made for one purpose can never verify for another
COSIG_CTX = b"sigilnet/v1/cosig\0"
EVENT_ID_CTX = b"sigilnet/v1/eid\0"


def sign_input(ev: dict) -> bytes:
    """What an event's AUTHOR signs."""
    return EVENT_CTX + signed_bytes(ev)


def cosign_input(ev: dict) -> bytes:
    """What a CO-SIGNER (an admin's second signature, a takeover acknowledgement, a new owner's consent) signs."""
    return COSIG_CTX + signed_bytes(ev)


def event_id(ev: dict) -> str:
    """SHA-256 of EVENT_ID_CTX + the signed bytes (so signatures, which may vary, never change identity), first 32 hex characters."""
    return hashlib.sha256(EVENT_ID_CTX + signed_bytes(ev)).hexdigest()[:32]


def encode(ev: dict) -> bytes:
    return canon.dumps(ev)


def check_structure(ev, max_bytes: int = 16384) -> None:
    """Shape and types only. Raises EventError."""
    if not isinstance(ev, dict):
        raise EventError("event is not an object")
    keys = set(ev)
    if not REQUIRED <= keys or not keys <= REQUIRED | OPTIONAL:
        raise EventError("wrong set of fields")
    if type(ev["v"]) is not int or ev["v"] not in SUPPORTED:
        raise EventError("unsupported version")
    kind = ev["kind"]
    if not (kind in KINDS if isinstance(kind, str) else False) and not (ev["v"] >= 2 and is_ext_kind(kind)):
        raise EventError("unknown kind")
    genesis = kind == "genesis"
    if genesis:
        if ev["thread"] != "" or ev["admin_ref"] != "" or ev["parents"] != [] or ev["seq"] != 0:
            raise EventError("genesis must have empty thread/admin_ref/parents and seq 0")
    else:
        if not is_hex(ev["thread"], 32) or not is_hex(ev["admin_ref"], 32):
            raise EventError("thread and admin_ref must be 32 hex characters")
    if not isinstance(ev["author"], str) or not AGENT_ID_RE.match(ev["author"]):
        raise EventError("bad author id")
    if type(ev["seq"]) is not int or not 0 <= ev["seq"] < MAX_SEQ:
        raise EventError("bad seq")
    if type(ev["ts"]) is not int or not 0 <= ev["ts"] < MAX_TS:
        raise EventError("bad ts")
    p = ev["parents"]
    if not isinstance(p, list) or len(p) > MAX_PARENTS or (not genesis and not p):
        raise EventError("bad parents")
    if not all(is_hex(x, 32) for x in p) or p != sorted(set(p)):
        raise EventError("parents must be 32-hex ids, sorted, without duplicates")
    if not isinstance(ev["body"], dict):
        raise EventError("body must be an object")
    if not is_hex(ev["sig"], 128):
        raise EventError("bad signature encoding")
    if "cosigs" in ev:
        cs = ev["cosigs"]
        if not isinstance(cs, list) or len(cs) > MAX_COSIGS:
            raise EventError("bad cosigs")
        authors = []
        for c in cs:
            if not isinstance(c, dict) or set(c) != {"author", "sig"} or not isinstance(c["author"], str) \
                    or not AGENT_ID_RE.match(c["author"]) or not is_hex(c["sig"], 128):
                raise EventError("bad cosig")
            authors.append(c["author"])
        if authors != sorted(set(authors)) or ev["author"] in authors:
            raise EventError("cosigs must be sorted, unique, and not include the author")
    try:
        size = len(canon.dumps(ev))
    except canon.CanonError as e:
        raise EventError(f"not representable as canonical json: {e}") from e
    if size > max_bytes:
        raise EventError("event larger than the size cap")


def decode(raw: bytes, max_bytes: int = 16384) -> dict:
    """Bytes off the wire -> a structurally valid event dict. Accepts only canonical bytes."""
    try:
        ev = canon.loads(raw)
    except canon.CanonError as e:
        raise EventError(f"not canonical json: {e}") from e
    check_structure(ev, max_bytes)
    return ev


def make_event(identity: Identity, *, thread: str, kind: str, body: dict, parents=(), seq: int, admin_ref: str,
               ts: int | None = None, v: int = V) -> dict:
    ev = {"v": v, "thread": thread, "author": identity.id, "seq": seq, "parents": sorted(set(parents)),
          "admin_ref": admin_ref, "ts": int(time.time()) if ts is None else ts, "kind": kind, "body": body}
    ev["sig"] = identity.sign(sign_input(ev))
    return ev


def add_cosig(ev: dict, identity: Identity) -> dict:
    """Return a copy of ev with identity's co-signature (same signed bytes) added, cosigs kept sorted by author."""
    out = dict(ev)
    cs = [c for c in ev.get("cosigs", []) if c["author"] != identity.id]
    cs.append({"author": identity.id, "sig": identity.sign(cosign_input(ev))})
    out["cosigs"] = sorted(cs, key=lambda c: c["author"])
    return out
