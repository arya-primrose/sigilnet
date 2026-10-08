"""Open invitation (DESIGN_open_invitation.md rev 1): a JOIN CARD and a KNOCK, so that a newcomer who knows only a URL can ask to join without anybody carrying a capsule.

  owner  `card create THREAD`   -> a public knock door (an onion service with no client authorization) and a CARD: one reusable line with no secret in it (owner id and signing key, thread,
                                   the door's address, the PUBLIC half of one dial key, the proof-of-work cost, an expiry).
  joiner `join CARD`            -> builds its own door for the owner (authorized with the card's dial key), then KNOCKS: `challenge` (a salt and the number of bits), a proof of work bound to
                                   the knock, a request signed by the joiner's key. The knock waits in a bounded pool on the owner's node.
  owner  `knock accept ID --fingerprint "..."` -> the typed fingerprint is mandatory; member_add, a per-peer door, the SAME steps as `capsule confirm`.
  joiner polls `status` (signed by its key) -> the owner's answer, sealed whole to the joiner's key; then everything is as after a capsule join.

Everything a stranger wrote (name, note) is data: length-capped, checked for printable characters, never given to a wake event (ids and counts only). Every refusal is the same bytes
(`{"t":"refused"}`): an unknown card, a bad signature and a wrong key are indistinguishable. The capsule flow is untouched (capsule.py only gained two module functions that both flows use).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import canon
from . import pow as P
from .capsule import CapsuleError, Store, _b64, _carrier_list, _int, _no_rebind, _offers_ok, _Pub, _unb64, _write_key, fingerprint, offers_problem, same_fingerprint, sealed_keys
from .carrier import CarrierError, check_credential, check_endpoint
from .keys import AGENT_ID_RE, Identity, agent_id, is_hex, valid_kex_pub, valid_sign_pub, verify_strict
from .thread import clean_text

PREFIX = "SIGILNET-CARD-1"
MAX_CARD = 2000
CARD_TTL = 7 * 24 * 3600
MAX_CARD_TTL = 30 * 24 * 3600
MAX_OPEN_CARDS = 4
POW_MIN, POW_MAX, POW_DEFAULT = 8, 24, 20   # a python solver does about a million hashes a second: 20 bits is a second or two, 24 about 16 s, 28 (the adaptive ceiling) minutes
ADAPT = 4                            # up to this many extra bits as the pool fills
POOL_CAP = 20                        # live knocks (pending + confirming) in the whole pool
KNOCK_TTL = 24 * 3600
KEEP = 24 * 3600                     # finished knocks (confirmed, rejected, evicted) stay this long, then go
MAX_FINISHED = 1000                  # the table of finished knocks is capped (oldest out)
SKEW = 600
MAX_KNOCK_BYTES = 4096
NAME_MAX = 32
NOTE_MAX = 512
GRACE = 7200                         # an ended card's door stays this long (at most) for a confirmed knock to collect its answer: two hours cover many failed polls at the joiner's longest backoff
CID_RE_LEN = 8
KNOCK_CTX = b"sigilnet/v1/knock-request\0"
STATUS_CTX = b"sigilnet/v1/knock-status\0"
ANSWER_CTX = b"sigilnet/v1/knock-answer\0"
BOX_CTX = b"sigilnet/v1/knock-box\0"
SALT_CTX = b"sigilnet/v1/knock-salt\0"
CARD_STATES = ("open", "closed", "burned", "expired")
KNOCK_STATES = ("pending", "confirming", "confirmed", "rejected", "evicted")
REFUSED = {"t": "refused"}           # THE refusal: one object, so every refusal is the same bytes


class KnockError(CapsuleError):
    pass


# ---------------------------------------------------------------- the card

def encode_card(c: dict) -> str:
    raw = canon.dumps(c)
    return f"{PREFIX} {_b64(raw)} {hashlib.sha256(raw).hexdigest()[:8]}"


def decode_card(block: str, *, now: float | None = None) -> dict:
    """Validate a card completely (the checksum is integrity only: the OWNER ID in it is what the joiner pins)."""
    if not isinstance(block, str) or len(block) > MAX_CARD:
        raise KnockError("not a card (too long)")
    parts = block.split()
    if len(parts) != 3 or parts[0] != PREFIX:
        raise KnockError("not a card")
    try:
        raw = _unb64(parts[1])
        c = canon.loads(raw)
    except Exception:                                               # noqa: BLE001
        raise KnockError("the card is damaged") from None
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest()[:8], parts[2]):
        raise KnockError("the card is damaged (checksum)")
    try:
        _check_card(c, time.time() if now is None else now)
        c["door"] = check_endpoint(c["door"])
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise KnockError(f"invalid card: {e}") from None
    return c


def _check_card(c, now: float) -> None:
    if not isinstance(c, dict) or set(c) != {"v", "card", "owner", "thread", "door", "dial", "pow", "exp"} or c["v"] != 1:
        raise ValueError("unknown layout")
    if not is_hex(c["card"], 8) or not is_hex(c["thread"], 32):
        raise ValueError("bad card or thread id")
    o = c["owner"]
    if not isinstance(o, dict) or set(o) != {"id", "sign"} or not isinstance(o["id"], str) or not AGENT_ID_RE.fullmatch(o["id"]) or not is_hex(o["sign"], 64) \
            or not valid_sign_pub(o["sign"]) or agent_id(bytes.fromhex(o["sign"])) != o["id"]:
        raise ValueError("bad owner")
    if type(c["pow"]) is not int or not POW_MIN <= c["pow"] <= POW_MAX:
        raise ValueError("bad proof-of-work cost")
    if type(c["exp"]) is not int or c["exp"] <= now or c["exp"] > now + MAX_CARD_TTL + 600:
        raise ValueError("bad expiry (expired?)")
    if check_credential(c["dial"])["type"] != check_endpoint(c["door"])["type"]:
        raise ValueError("the dial key and the door are of different carriers")


def describe_card(c: dict) -> list:
    """What the joiner's human is shown: generated HERE from structured fields."""
    o = c["owner"]
    left = max(0, c["exp"] - int(time.time())) // 3600
    lines = [f"Thread: {c['thread']}", f"Owner: {o['id']}  fingerprint: {fingerprint(o['id'])}",
             f"This card is valid for about {left} more hours; a knock costs about {2 ** c['pow']:,} hashes of work (a second or so).",
             "The owner must approve your request by typing YOUR fingerprint; nothing changes until then."]
    if c["door"]["type"] != "onion":
        lines.append(f"WARNING: the knock door is a {c['door']['type']} door: it names the owner's address, which is not hidden.")
    return lines


# ---------------------------------------------------------------- a sealed box (the answer to a status poll is readable by the joiner only)

def seal_to(kex_hex: str, aad: bytes, plaintext: bytes) -> dict:
    if not valid_kex_pub(kex_hex):
        raise KnockError("bad recipient key")
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    rcpt = bytes.fromhex(kex_hex)
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=BOX_CTX + eph_pub + rcpt).derive(eph.exchange(x25519.X25519PublicKey.from_public_bytes(rcpt)))
    nonce = os.urandom(12)
    return {"e": eph_pub.hex(), "n": _b64(nonce), "c": _b64(ChaCha20Poly1305(k).encrypt(nonce, plaintext, BOX_CTX + aad))}


def open_box(me: Identity, aad: bytes, box) -> bytes:
    try:
        if not isinstance(box, dict) or set(box) != {"e", "n", "c"} or not is_hex(box["e"], 64) or not isinstance(box["n"], str) or not isinstance(box["c"], str) or len(box["c"]) > 60000:
            raise ValueError
        eph_pub, rcpt = bytes.fromhex(box["e"]), bytes.fromhex(me.kex_pub)
        k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=BOX_CTX + eph_pub + rcpt).derive(me.kex_key.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub)))
        return ChaCha20Poly1305(k).decrypt(_unb64(box["n"]), _unb64(box["c"]), BOX_CTX + aad)
    except Exception:                                               # noqa: BLE001
        raise KnockError("the box does not open") from None


# ---------------------------------------------------------------- the stores

def _ok_card(k, v) -> bool:
    try:
        return bool(isinstance(k, str) and is_hex(k, CID_RE_LEN) and isinstance(v, dict) and v.get("state") in CARD_STATES and _int(v.get("exp")) and is_hex(v.get("thread"), 32)
                    and v.get("door") == f"knock-{k}" and isinstance(v.get("type"), str) and is_hex(v.get("salt_key"), 64) and type(v.get("pow")) is int and POW_MIN <= v["pow"] <= POW_MAX
                    and _int(v.get("bad")) and _int(v.get("at")) and type(v.get("max_pending")) is int and 1 <= v["max_pending"] <= POOL_CAP and all(_int(v[x]) for x in ("closed_at",) if x in v))
    except (TypeError, KeyError, ValueError):
        return False


def finish(v: dict, state: str, now: int) -> None:
    """A knock leaves the pool's live set (evicted, rejected, confirmed): what a stranger wrote that nobody needs any more goes (the note, the offers; for a confirmed one the carrier types of
    the offers stay, the answer needs them), so the file a stranger can inflate stays small and a rewrite stays cheap."""
    if "offers" in v:
        v["types"] = [o["endpoint"]["type"] for o in v["offers"]]
        del v["offers"]
    v["note"] = ""
    v.update(state=state, at=int(now), pinned=False)


def _ok_knock(k, v) -> bool:
    try:
        if not (isinstance(k, str) and is_hex(k, CID_RE_LEN) and isinstance(v, dict) and v.get("state") in KNOCK_STATES and is_hex(v.get("card"), CID_RE_LEN)
                and isinstance(v.get("agent"), str) and AGENT_ID_RE.fullmatch(v["agent"]) and is_hex(v.get("sign"), 64) and is_hex(v.get("kex"), 64)
                and clean_text(v.get("name"), NAME_MAX) and v["name"] and isinstance(v.get("note"), str) and clean_text(v["note"], NOTE_MAX) and type(v.get("bits")) is int
                and 0 <= v["bits"] <= P.MAX_BITS and _int(v.get("at")) and _int(v.get("exp")) and type(v.get("pinned")) is bool):
            return False
        if v["state"] in ("pending", "confirming"):
            types = [o["endpoint"]["type"] for o in v.get("offers", []) if isinstance(o, dict) and isinstance(o.get("endpoint"), dict)]
            if not types or not _offers_ok(v["offers"], types):
                return False
        elif "offers" in v or not (isinstance(v.get("types"), list) and v["types"] and all(isinstance(x, str) and len(x) <= 16 for x in v["types"]) and v["note"] == ""):
            return False                                                # a finished knock keeps no offers and no note, only the carrier types
        if "owner_door" in v and not (isinstance(v["owner_door"], str) and v["owner_door"].startswith("peer-")):
            return False
        return all(_int(v[x]) for x in ("collected",) if x in v)
    except (TypeError, KeyError, ValueError, AttributeError):
        return False


def cards_store(home, clock=time.time) -> Store:
    return Store(home, clock, name="cards.json", ok=_ok_card)


def pool_store(home, clock=time.time) -> Store:
    return Store(home, clock, name="knocks.json", ok=_ok_knock)


def _dial_file(home: Path, cid: str, etype: str) -> Path:
    return Path(home) / "peerkeys" / f"card-{cid}-{etype}.priv"


def salt_for(salt_key: str, period: int) -> bytes:
    return hmac.new(bytes.fromhex(salt_key), SALT_CTX + period.to_bytes(8, "big"), hashlib.sha256).digest()[:16]


def bits_for(card: dict, pending: int) -> int:
    """The cost of a knock right now: the card's base cost plus up to ADAPT bits as the pool fills (adaptive, never below the card's own)."""
    return min(POW_MAX + ADAPT, card["pow"] + min(ADAPT, (ADAPT * pending) // POOL_CAP))


def body_hash(req: dict) -> str:
    """What the proof of work is bound to: the knock WITHOUT its proof and signature."""
    return hashlib.sha256(canon.dumps({k: v for k, v in req.items() if k not in ("pow", "sig")})).hexdigest()


def live(pool: dict, card: str | None = None) -> list:
    return [k for k, v in pool.items() if v["state"] in ("pending", "confirming") and (card is None or v["card"] == card)]


# ---------------------------------------------------------------- owner side: the door's program

class KnockServer:
    """The handler behind the `knock` doors (one instance for every open card; the card is named in the request). ONLY `challenge`, `knock` and `status`; anything else, and every
    failure, is the same `{"t": "refused"}`. `notify(knock_id, thread_id)` is called (ids only) when a knock enters the pool."""

    def __init__(self, home, carriers, me: Identity, m, clock=time.time, notify=None):
        self.home, self.me, self.m, self.clock, self.notify = Path(home), me, m, clock, notify
        self.by_type = {c.type: c for c in _carrier_list(carriers)}
        self.cards, self.pool = cards_store(home, clock), pool_store(home, clock)
        self.bad: dict = {}                                         # card id -> junk requests seen since the node started (memory only: junk must never cost a disk write)

    def handle(self, req) -> dict:
        try:
            return self._handle(req)
        except Exception:                                           # noqa: BLE001
            return REFUSED

    def _card(self, cid, t):
        """The card record this request may use: an open one for everything; for `status` also a card that ended less than GRACE ago (a confirmed knock collects its answer, a
        rejected one learns it)."""
        c = self.cards.all().get(cid) if isinstance(cid, str) else None
        if c is None:
            return None
        now = self.clock()
        if c["state"] == "open" and now <= c["exp"]:
            return c
        ended = c.get("closed_at", c["exp"]) if c["state"] != "open" else c["exp"]
        return c if t == "status" and now - ended < GRACE else None

    def _bad(self, cid: str) -> dict:
        """Count a request that was not a well-formed, well-proven one. Only a counter in memory: a card is NEVER closed because of what strangers send (its id is public, so that would
        hand everybody a cheap way to close it); the owner closes a card with `card close`."""
        self.bad[cid] = self.bad.get(cid, 0) + 1
        return REFUSED

    def _handle(self, req) -> dict:
        if not isinstance(req, dict) or req.get("t") not in ("challenge", "knock", "status"):
            return REFUSED
        card = self._card(req.get("card"), req["t"])
        if card is None:
            return REFUSED
        cid = req["card"]
        try:
            out = {"challenge": self._challenge, "knock": self._knock, "status": self._status}[req["t"]](cid, card, req)
        except Exception:                                           # noqa: BLE001
            out = None
        return out if out is not None else self._bad(cid)

    def _pending_count(self, cid: str) -> int:
        return len(live(self.pool.all(), cid))

    def _challenge(self, cid, card, req):
        if set(req) != {"t", "card"}:
            return None
        now = int(self.clock())
        return {"t": "challenge", "salt": salt_for(card["salt_key"], now // 3600).hex(), "bits": bits_for(card, self._pending_count(cid)), "now": now}

    def _knock(self, cid, card, req):
        if set(req) != {"t", "card", "owner", "thread", "ts", "sign", "kex", "name", "note", "offers", "salt", "pow", "sig"} or len(canon.dumps(req)) > MAX_KNOCK_BYTES:
            return None
        now = self.clock()
        if req["owner"] != self.me.id or req["thread"] != card["thread"]:
            return None
        salts = [salt_for(card["salt_key"], int(now) // 3600 - back) for back in (0, 1)]
        if not isinstance(req["salt"], str) or not any(hmac.compare_digest(req["salt"], s.hex()) for s in salts):
            return None
        if not (is_hex(req["sign"], 64) and valid_sign_pub(req["sign"]) and valid_kex_pub(req["kex"]) and type(req["ts"]) is int and is_hex(req["sig"], 128)):
            return None
        pending = self._pending_count(cid)
        need = bits_for(card, pending)
        got = P.achieved(bytes.fromhex(req["salt"]), req["thread"], req["sign"], body_hash(req), req["pow"], ctx=P.KNOCK_CTX)
        if got < need:
            return {"t": "harder", "bits": need}                   # (the same number the challenge gives: nothing new is revealed)
        if not verify_strict(req["sign"], req["sig"], KNOCK_CTX + canon.dumps({k: v for k, v in req.items() if k != "sig"})):
            return None
        if abs(now - req["ts"]) > SKEW:
            return {"t": "clock", "now": int(now)}                 # a stranger whose clock is off is told, plainly (the request was signed by a key it holds)
        if not (clean_text(req["name"], NAME_MAX) and req["name"] and clean_text(req["note"], NOTE_MAX)):
            return None
        if offers_problem(self.by_type, req["offers"], [card["type"]]) is not None:
            return None
        agent = agent_id(bytes.fromhex(req["sign"]))
        t = self.m.threads.get(card["thread"])
        if t is None or agent in t.state()["members"] or agent == self.me.id:
            return None
        offers = [dict(o) for o in req["offers"]]
        result = {}

        def edit(d):
            cards = self.cards.all().get(cid)
            if cards is None or cards["state"] != "open":
                result["r"] = None
                return
            mine = next((k for k, v in d.items() if v["sign"] == req["sign"] and v["card"] == cid), None)
            if mine is not None:
                v = d[mine]
                if v["state"] == "rejected":
                    result["r"] = {"t": "rejected"}
                    return
                if v["state"] in ("pending", "confirming", "confirmed"):
                    if v["state"] == "pending" and v["kex"] == req["kex"] and len(offers) > len(v["offers"]) and all(o in offers for o in v["offers"]):
                        v["offers"] = offers                       # the SAME joiner again with more doors: only additions
                    result["r"] = {"t": "pending"}
                    return
                del d[mine]                                         # evicted: it may knock again
            n = live(d, cid)
            card_full = len(n) >= min(card["max_pending"], POOL_CAP)
            if card_full or len(live(d)) >= POOL_CAP:
                cands = [(d[k]["bits"], d[k]["at"], k) for k in (n if card_full else live(d)) if d[k]["state"] == "pending" and not d[k]["pinned"]]       # (a full CARD displaces its own knocks, never another card's)
                if not cands:
                    result["r"] = {"t": "full", "bits": min(POW_MAX + ADAPT, need)}
                    return
                weakest = min(cands)
                if min(got, P.MAX_BITS) <= weakest[0]:
                    result["r"] = {"t": "full", "bits": min(POW_MAX + ADAPT, weakest[0] + 1)}
                    return
                finish(d[weakest[2]], "evicted", now)
                result["evicted"] = weakest[2]
            kid = secrets.token_hex(4)
            while kid in d:
                kid = secrets.token_hex(4)
            d[kid] = {"card": cid, "agent": agent, "sign": req["sign"], "kex": req["kex"], "name": req["name"], "note": req["note"], "offers": offers, "bits": min(got, P.MAX_BITS),
                      "state": "pending", "at": int(now), "exp": int(now) + KNOCK_TTL, "pinned": False}
            result["r"], result["new"] = {"t": "pending"}, kid
            finished = sorted((v["at"], k) for k, v in d.items() if v["state"] in ("rejected", "evicted", "confirmed"))
            for _, k in finished[:max(0, len(finished) - MAX_FINISHED)]:
                del d[k]
        self.pool.edit(edit)
        if result.get("new") and self.notify is not None:
            try:
                self.notify(result["new"], card["thread"])
            except Exception:                                       # noqa: BLE001 - a wake that fails never fails the knock
                pass
        return result["r"]

    def _status(self, cid, card, req):
        if set(req) != {"t", "card", "owner", "thread", "ts", "sign", "sig"} or req["owner"] != self.me.id or req["thread"] != card["thread"]:
            return None
        if not (is_hex(req["sign"], 64) and is_hex(req["sig"], 128) and type(req["ts"]) is int and valid_sign_pub(req["sign"])):
            return None
        if not verify_strict(req["sign"], req["sig"], STATUS_CTX + canon.dumps({k: v for k, v in req.items() if k != "sig"})) or abs(self.clock() - req["ts"]) > SKEW:
            return None                                             # unknown key, bad signature, old timestamp: the SAME bytes
        kid, rec = next(((k, v) for k, v in self.pool.all().items() if v["card"] == cid and v["sign"] == req["sign"]), (None, None))
        if rec is None:
            return None
        st = rec["state"]
        if st in ("pending", "confirming"):
            return {"t": "pending"}
        if st == "rejected":
            return {"t": "rejected"}
        if st == "evicted":
            return {"t": "evicted", "bits": bits_for(card, self._pending_count(cid))}
        return self._answer(cid, kid, rec)

    def _answer(self, cid: str, kid: str, rec: dict):
        offered = list(rec["types"])
        endpoints, missing = [], []
        for t in offered:
            c = self.by_type.get(t)
            ep = c.door_endpoint(rec.get("owner_door", "")) if c is not None else None
            (endpoints if ep else missing).append(ep or t)
        if not endpoints or (missing and self.clock() - rec["at"] < 60):
            return {"t": "pending"}
        keys = sealed_keys(self.m, self.cards.all()[cid]["thread"], {"kex": rec["kex"], "agent": rec["agent"]})
        if keys is None:
            return {"t": "pending"}                                  # an encrypted thread is never answered without its keys
        body = {"t": "joined", "card": cid, "thread": self.cards.all()[cid]["thread"], "owner": self.me.id, "name": (self.me.name or self.me.id[:8])[:NAME_MAX], "to": rec["agent"],
                "endpoints": endpoints, "enc": bool(keys), "keys": keys, "by": self.me.sign_pub}
        body["rsig"] = self.me.sign(ANSWER_CTX + canon.dumps(body))
        box = seal_to(rec["kex"], ANSWER_CTX + cid.encode() + rec["agent"].encode(), canon.dumps(body))
        self.pool.edit(lambda d: d[kid].update(collected=int(self.clock())) if kid in d and "collected" not in d[kid] else None)
        return {"t": "box", "box": box}


# ---------------------------------------------------------------- owner side: cards

HISTORY_NOTICE = 10                  # a thread with more events than this has history a new member would read (every epoch key is handed over)


def create_card(home, carriers, me: Identity, m, tid: str, *, ttl: int = CARD_TTL, pow_bits: int = POW_DEFAULT, max_pending: int = POOL_CAP, yes_history: bool = False,
                clock=time.time, wait_address=None) -> tuple:
    """Open a knock door on the first carrier that hides this host's address and build the card. Returns (card block, card id, owner fingerprint).
    The RECORD is written first (atomically with the MAX_OPEN_CARDS check), then the door: a door without a record is an orphan and the sweep deletes it; a failure undoes everything."""
    home = Path(home)
    cs = _carrier_list(carriers)
    car = next((c for c in cs if "hides_ip" in c.capabilities), None)
    if car is None:
        raise KnockError("a knock door is public: it needs a carrier that hides this host's address (tor)")
    t = m.threads.get(tid)
    if t is None:
        raise KnockError("no such thread")
    st = t.state()
    if st["owner"] != me.id:
        raise KnockError("only the owner of a thread makes cards for it")
    if st["visibility"] != "private" or st.get("closed"):
        raise KnockError("cards are for open private threads (a public thread takes guests)")
    if not 3600 <= ttl <= MAX_CARD_TTL:
        raise KnockError("ttl: between 1 hour and 30 days")
    if not POW_MIN <= pow_bits <= POW_MAX or not 1 <= max_pending <= POOL_CAP:
        raise KnockError(f"pow: {POW_MIN}-{POW_MAX} bits; max-pending: 1-{POOL_CAP}")
    if len(t.order) > HISTORY_NOTICE and not yes_history:
        raise KnockError(f"this thread has {len(t.order)} events, and a new member receives EVERY epoch key, so reads all of it. `rotate` the thread first for a clean slate, or "
                         f"repeat with --yes-history if the newcomer may read it all.")
    sweep(home, cs, clock=clock)
    store = cards_store(home, clock)
    cid = secrets.token_hex(4)
    exp = int(clock()) + ttl

    def claim(d):
        if sum(1 for r in d.values() if r["state"] == "open") >= MAX_OPEN_CARDS:
            raise KnockError(f"{MAX_OPEN_CARDS} cards are already open: close one (`card close`) or wait for it to expire")
        d[cid] = {"thread": tid, "exp": exp, "door": f"knock-{cid}", "type": car.type, "state": "open", "salt_key": secrets.token_hex(32), "pow": pow_bits, "bad": 0,
                  "at": int(clock()), "max_pending": max_pending}
    store.edit(claim)
    try:
        secret, pub = car.new_credential()
        _write_key(_dial_file(home, cid, car.type), secret)
        car.open_door(f"knock-{cid}", "knock")
        endpoint = wait_address(car, f"knock-{cid}") if wait_address else car.door_endpoint(f"knock-{cid}")
        if not endpoint:
            raise KnockError(f"the {car.type} knock door has no address yet: start `node run` (the carrier creates it), then run this again")
        card = {"v": 1, "card": cid, "owner": {"id": me.id, "sign": me.sign_pub}, "thread": tid, "door": endpoint, "dial": pub, "pow": pow_bits, "exp": exp}
        block = encode_card(card)
        decode_card(block, now=clock())                              # what we built must pass what the joiner checks
    except BaseException:
        try:
            car.close_door(f"knock-{cid}")
        except (ValueError, OSError):
            pass
        _drop_dial_keys(home, cid, [car.type])
        store.edit(lambda d: d.pop(cid, None))
        raise
    return block, cid, fingerprint(me.id)


def _drop_dial_keys(home, cid: str, types) -> None:
    for t in types:
        try:
            _dial_file(home, cid, t).unlink()
        except OSError:
            pass


def close_card(home, carriers, cid: str, *, clock=time.time) -> bool:
    """Close an open card: no more knocks are taken, the pending ones are rejected, the door goes when nobody still has an answer to collect (see `sweep`)."""
    store = cards_store(home, clock)
    done = {}

    def edit(d):
        c = d.get(cid)
        if c is not None and c["state"] == "open":
            c.update(state="closed", closed_at=int(clock()))
            done["ok"] = True
    store.edit(edit)
    if not done:
        return False
    def pending_off(d):
        for v in d.values():
            if v["card"] == cid and v["state"] == "pending":
                finish(v, "rejected", clock())
    pool_store(home, clock).edit(pending_off)
    sweep(home, carriers, clock=clock)
    return True


def sweep(home, carriers, *, clock=time.time) -> list:
    """Expire cards, close the doors of finished cards (once no confirmed knock still has its answer to collect, or GRACE after the card ended), drop their dial keys, forget old records,
    expire old knocks, and close orphan knock doors. Safe at any time (the node runs it every tick). Returns the ids whose door was closed."""
    home = Path(home)
    cs = _carrier_list(carriers)
    cards, pool = cards_store(home, clock), pool_store(home, clock)
    now = clock()
    closed = []
    if not ((home / "cards.json").exists() or (home / "knocks.json").exists()):
        return _orphan_doors(cs, set())                              # a node that never made a card touches no file here

    def knocks(d):                                                    # knocks that waited too long, and finished ones nobody needs any more
        for k in [k for k, v in d.items() if (v["state"] == "pending" and now > v["exp"]) or (v["state"] in ("rejected", "evicted", "confirmed") and now - v["at"] > KEEP)]:
            if d[k]["state"] == "pending":
                finish(d[k], "evicted", now)
            else:
                del d[k]
    pool.edit(knocks)
    recs = cards.all()
    for cid, c in recs.items():
        if c["state"] == "open" and now > c["exp"]:
            cards.edit(lambda d, cid=cid: d[cid].update(state="expired", closed_at=int(now)) if cid in d and d[cid]["state"] == "open" else None)
            c = {**c, "state": "expired", "closed_at": int(now)}
        if c["state"] == "open":
            continue
        pool.edit(lambda d, cid=cid: [finish(v, "rejected", now) for v in d.values() if v["card"] == cid and v["state"] == "pending"] and None)     # an ended card takes no decisions
        ended = c.get("closed_at", c["exp"])
        waiting = any(v["card"] == cid and v["state"] == "confirmed" and "collected" not in v and now - v["at"] < GRACE for v in pool.all().values())
        if waiting and now - ended < GRACE:
            continue
        ok = False                                                   # (a carrier that is not among `cs` right now is retried at the next sweep)
        for car in cs:
            if car.type == c["type"]:
                try:
                    car.close_door(c["door"])
                except (ValueError, OSError):
                    pass
                ok = car.door_gone(c["door"])
        if ok:
            _drop_dial_keys(home, cid, [c["type"]])
            closed.append(cid)
            if now - ended > KEEP:
                cards.edit(lambda d, cid=cid: d.pop(cid, None))
    return closed + _orphan_doors(cs, {c["door"] for c in cards.all().values()})


def _orphan_doors(cs, known: set) -> list:
    """A knock door with no card record (a crash, a damaged file) is an orphan: closed."""
    closed = []
    for car in cs:
        try:
            doors = car.doors()
        except Exception:                                            # noqa: BLE001 - a carrier that cannot list its doors has none to close
            continue
        for name, svc in doors.items():
            if svc.get("kind") == "knock" and name not in known:
                try:
                    car.close_door(name)
                    closed.append(name)
                except (ValueError, OSError):
                    pass
    return closed


# ---------------------------------------------------------------- owner side: decisions (only a human runs these)

def pending(home, clock=time.time) -> dict:
    return {k: v for k, v in pool_store(home, clock).all().items() if v["state"] == "pending" and clock() <= v["exp"]}


def pin(home, kid: str, *, clock=time.time) -> bool:
    """`knock show` pins the entry: it is not evicted while the owner is looking at it."""
    done = {}
    pool_store(home, clock).edit(lambda d: (d[kid].update(pinned=True), done.setdefault("ok", True)) if kid in d and d[kid]["state"] == "pending" else None)
    return bool(done)


def accept(home, carriers, me: Identity, m, book, kid: str, typed_fp: str, *, clock=time.time) -> dict:
    """The owner's human typed the fingerprint of the newcomer. The same steps, in the same order, as `capsule.confirm` (claim, idempotent steps first, member_add last, undo on failure)."""
    from .build import Writer
    home = Path(home)
    by_type = {c.type: c for c in _carrier_list(carriers)}
    pool = pool_store(home, clock)
    rec = pool.all().get(kid)
    if rec is None or rec["state"] != "pending" or clock() > rec["exp"]:
        raise KnockError("no such pending knock (expired, rejected, or already decided)")
    if not same_fingerprint(typed_fp, rec["agent"]):
        raise KnockError("the fingerprint does not match the newcomer's: nothing was changed. Ask them to read it to you again.")
    card = cards_store(home, clock).all().get(rec["card"])
    if card is None or card["state"] != "open" or clock() > card["exp"]:
        raise KnockError("the card of this knock is closed or expired: nothing was changed")
    offers = [o for o in rec["offers"] if o["endpoint"]["type"] in by_type]
    if not offers:
        raise KnockError("none of the newcomer's offers is on a carrier this node runs: nothing was changed")
    for o in offers:
        why = by_type[o["endpoint"]["type"]].locator_problem(o["endpoint"]["addr"])
        if why:
            raise KnockError(f"the newcomer's {o['endpoint']['type']} address is refused ({why}): nothing was changed")
    claimed = {}

    def claim(d):
        x = d.get(kid)
        if x is not None and x["state"] == "pending" and clock() <= x["exp"]:
            x.update(state="confirming", at=int(clock()))
            claimed["ok"] = True
    pool.edit(claim)
    if not claimed:
        raise KnockError("no such pending knock (expired, rejected, or already decided)")
    door = f"peer-{rec['agent'][:27]}"
    created, book_had = [], rec["agent"] in book.all()
    try:
        t = m.threads.get(card["thread"])
        if t is None or t.state()["owner"] != me.id:
            raise KnockError("thread is gone or not ours")
        dials = {o["endpoint"]["type"]: check_credential(json.loads(_dial_file(home, rec["card"], o["endpoint"]["type"]).read_text()), secret=True) for o in offers}
        for o in offers:
            _no_rebind(by_type[o["endpoint"]["type"]], door, rec["agent"])
        for o in offers:
            c = by_type[o["endpoint"]["type"]]
            if c.doors().get(door) is None:
                created.append(c)
            c.open_door(door, "peer", credential=o["credential"], agent=rec["agent"])
            c.use_credential(o["endpoint"], dials[c.type], agent=rec["agent"])
            book.add(rec["agent"], rec["name"], o["endpoint"], [card["thread"]])
        if rec["agent"] not in t.state()["members"]:
            res = m.ingest(Writer(me, t).add_member(_Pub(rec["agent"], rec["sign"], rec["kex"], rec["name"]), "member"))
            if not res.ok:
                raise KnockError(f"member_add refused: {res.status} {res.reason}")
    except BaseException:
        for c in created:
            try:
                c.close_door(door)
            except (ValueError, OSError):
                pass
        if not book_had:
            try:
                book.remove(rec["agent"])
            except Exception:                                        # noqa: BLE001
                pass
        pool.edit(lambda d: d[kid].update(state="pending", at=int(clock())) if kid in d else None)
        raise
    pool.edit(lambda d: (finish(d[kid], "confirmed", clock()), d[kid].update(owner_door=door)) if kid in d else None)
    return {"agent": rec["agent"], "name": rec["name"], "door": door, "carriers": [o["endpoint"]["type"] for o in offers]}


def reject(home, carriers, kid: str, *, clock=time.time, book=None) -> bool:
    """Reject a pending or half-confirmed knock; with `book`, a peer door bound to its agent that the peer book does not hold (left by a failed accept) goes too."""
    pool = pool_store(home, clock)
    rec = pool.all().get(kid)
    if rec is None or rec["state"] not in ("pending", "confirming"):
        return False
    pool.edit(lambda d: finish(d[kid], "rejected", clock()) if kid in d else None)
    if book is not None and rec["agent"] not in book.all():
        for c in _carrier_list(carriers):
            try:
                for name, d in c.doors().items():
                    if d.get("kind") == "peer" and d.get("agent") == rec["agent"]:
                        c.close_door(name)
            except (ValueError, OSError):
                continue
    return True


# ---------------------------------------------------------------- joiner side

OUT_STATES = ("door", "knocking", "pending", "joined", "failed")
OUT_TTL = KNOCK_TTL + 3600           # how long a joiner keeps knocking/polling (the owner's pool keeps a knock this long)
POLL_MIN, POLL_MAX = 15, 600
MAX_REFUSALS = 6                     # this many refusals in a row to a challenge/knock: the card is closed, expired or not ours


def _ok_out(k, v) -> bool:
    try:
        c = v["card"]
        _check_card(c, c["exp"] - 1)                                # (shape only; expiry is judged by the poll)
        return bool(isinstance(k, str) and is_hex(k, CID_RE_LEN) and k == c["card"] and v.get("state") in OUT_STATES and clean_text(v.get("name"), NAME_MAX) and v["name"]
                    and isinstance(v.get("note"), str) and clean_text(v["note"], NOTE_MAX) and isinstance(v.get("door"), str) and v.get("key") == f"knock-{k}"
                    and isinstance(v.get("mypub"), dict) and all(check_credential(x) == x for x in v["mypub"].values()) and _int(v.get("at")) and _int(v.get("next", 0))
                    and _int(v.get("tries", 0)) and _int(v.get("refused", 0)) and _int(v.get("deadline")))
    except (TypeError, KeyError, ValueError, AttributeError):
        return False


def outbox(home, clock=time.time) -> Store:
    """outknocks.json under home: what this agent is in the middle of joining by card."""
    return Store(home, clock, name="outknocks.json", ok=_ok_out)


def waiting_knocks(home, clock=time.time) -> int:
    """How many newcomers wait for the owner's decision. 0, reading nothing, on a node that never made a card."""
    if not (Path(home) / "knocks.json").exists():
        return 0
    return len(pending(home, clock))


def waiting_joins(home) -> bool:
    """Is there a card join in progress? Reads nothing (and so creates no lock file) on a node that never joined by card."""
    p = Path(home) / "outknocks.json"
    if not p.exists():
        return False
    return any(r["state"] in ("door", "knocking", "pending") for r in outbox(home).all().values())


def join(home, carriers, me: Identity, block: str, *, fingerprint_typed: str | None = None, name: str | None = None, note: str = "", clock=time.time, wait_address=None) -> dict:
    """Record a join by card and build OUR door for the owner (authorized with the card's dial key). The node loop (`poll`) does the knocking. `fingerprint_typed`, if given, must be the
    owner's fingerprint as the person who handed over the card said it. Returns {cid, fingerprint (OURS: tell it to the owner), owner_fingerprint, door (our endpoint or None)}."""
    home = Path(home)
    card = decode_card(block, now=clock())
    if fingerprint_typed is not None and not same_fingerprint(fingerprint_typed, card["owner"]["id"]):
        raise KnockError("the fingerprint does not match the card's owner: do NOT join. Either you typed it wrong or the card is not from who you think.")
    if card["owner"]["id"] == me.id:
        raise KnockError("this card is yours")
    name = name if name is not None else (me.name or me.id[:8])[:NAME_MAX]
    if not (clean_text(name, NAME_MAX) and name and clean_text(note, NOTE_MAX)):
        raise KnockError(f"name: at most {NAME_MAX} printable characters; note: at most {NOTE_MAX}, one line")
    cs = {c.type: c for c in _carrier_list(carriers)}
    car = cs.get(card["door"]["type"])
    if car is None:
        raise KnockError(f"this card's knock door is a {card['door']['type']} door; this node runs {sorted(cs)}")
    why = car.locator_problem(card["door"]["addr"])
    if why:
        raise KnockError(f"the card's {card['door']['type']} address is refused ({why}): do not use this card")
    cid = card["card"]
    out = outbox(home, clock)
    old = out.all().get(cid)
    if old is not None and old["state"] != "failed":
        raise KnockError("you already used this card" if old["state"] == "joined" else "you are already knocking with this card (`join status`)")
    door = f"owner-{card['owner']['id'][:26]}"
    _no_rebind(car, door, card["owner"]["id"])
    secret, pub = car.new_credential()
    car.open_door(door, "peer", credential=card["dial"], agent=card["owner"]["id"])
    _write_key(Path(home) / "peerkeys" / f"knock-{cid}-{car.type}.priv", secret)
    out.edit(lambda d: d.__setitem__(cid, {"card": card, "state": "door", "name": name, "note": note, "door": door, "key": f"knock-{cid}", "mypub": {car.type: pub}, "at": int(clock()),
                                          "next": 0, "tries": 0, "refused": 0, "deadline": int(clock()) + OUT_TTL}))
    mine = wait_address(car, door) if wait_address else car.door_endpoint(door)
    return {"cid": cid, "fingerprint": fingerprint(me.id), "owner_fingerprint": fingerprint(card["owner"]["id"]), "door": mine}


def _fail(out: Store, cid: str, why: str, clock) -> None:
    out.edit(lambda d: d[cid].update(state="failed", why=why[:200], at=int(clock())) if cid in d else None)


def _sign_status(me: Identity, card: dict, now: int) -> dict:
    body = {"t": "status", "card": card["card"], "owner": card["owner"]["id"], "thread": card["thread"], "ts": int(now), "sign": me.sign_pub}
    return {**body, "sig": me.sign(STATUS_CTX + canon.dumps(body))}


def polite_solve(salt: bytes, thread: str, sign_pub: str, event_id: str, bits: int, *, ctx: bytes = P.KNOCK_CTX, chunk: int = 1 << 17, pause: float = 0.02) -> int:
    """The proof of work in slices with a short sleep between them: a node that also serves doors must not hold the interpreter for the minutes a 28-bit proof can take."""
    start = int.from_bytes(os.urandom(6), "big")
    while True:
        try:
            return P.solve(salt, thread, sign_pub, event_id, bits, start=start, max_tries=chunk, ctx=ctx)
        except RuntimeError:
            start += chunk
            time.sleep(pause)


def build_knock(me: Identity, rec: dict, mine: dict, salt: bytes, bits: int, now: int, *, solve=P.solve) -> dict:
    card = rec["card"]
    body = {"t": "knock", "card": card["card"], "owner": card["owner"]["id"], "thread": card["thread"], "ts": int(now), "sign": me.sign_pub, "kex": me.kex_pub, "name": rec["name"],
            "note": rec["note"], "offers": [{"endpoint": mine, "credential": rec["mypub"][mine["type"]]}], "salt": salt.hex()}
    nonce = solve(salt, card["thread"], me.sign_pub, hashlib.sha256(canon.dumps(body)).hexdigest(), bits, ctx=P.KNOCK_CTX)
    body["pow"] = nonce
    return {**body, "sig": me.sign(KNOCK_CTX + canon.dumps(body))}


def verify_answer(resp: dict, rec: dict, me: Identity, carriers: dict) -> dict | None:
    """Open and verify the owner's sealed answer. Returns the signed body, or None if anything is wrong (from the card's owner, for this card/thread/us, endpoints of the carrier we
    offered, each passing that carrier's address rules)."""
    card = rec["card"]
    try:
        raw = open_box(me, ANSWER_CTX + card["card"].encode() + me.id.encode(), resp.get("box"))
        body = canon.loads(raw)
        if body.get("by") != card["owner"]["sign"] or not is_hex(body.get("rsig"), 128) or not verify_strict(body["by"], body["rsig"], ANSWER_CTX + canon.dumps({k: v for k, v in body.items() if k != "rsig"})):
            return None
        if set(body) != {"t", "card", "thread", "owner", "name", "to", "endpoints", "enc", "keys", "by", "rsig"} or body["t"] != "joined" or body["card"] != card["card"] \
                or body["thread"] != card["thread"] or body["owner"] != card["owner"]["id"] or body["to"] != me.id or not clean_text(body["name"], NAME_MAX) or not body["name"]:
            return None
        eps = body["endpoints"]
        if not isinstance(eps, list) or not 1 <= len(eps) <= len(rec["mypub"]):
            return None
        seen = []
        for ep in eps:
            ep = check_endpoint(ep)
            car = carriers.get(ep["type"])
            if ep["type"] in seen or ep["type"] not in rec["mypub"] or car is None or car.locator_problem(ep["addr"]):
                return None
            seen.append(ep["type"])
        body["endpoints"] = [check_endpoint(e) for e in eps]
        return body
    except Exception:                                               # noqa: BLE001
        return None


def poll(home, carriers, me: Identity, book, transport_for, *, clock=time.time, codec=None, solve=polite_solve, rnd=None) -> dict:
    """One pass over this agent's card joins (the node loop calls it every ~15 s from a worker). Per join: challenge -> proof of work -> signed knock -> signed status polls (backoff
    15 s growing to 10 min with jitter) -> the sealed answer. `transport_for(endpoint)` returns an object with .request(dict). Returns {cid: state} for what changed."""
    import random
    from .capsule import _install_keys
    rnd = rnd or random
    home = Path(home)
    cs = {x.type: x for x in _carrier_list(carriers)}
    out = outbox(home, clock)
    changed = {}
    prune = [cid for cid, rec in out.all().items() if rec["state"] in ("failed", "joined") and clock() - rec["at"] > KEEP]
    if prune:
        out.edit(lambda d: [d.pop(c, None) for c in prune] and None)       # finished joins are forgotten after a day (a failed one may be retried before that)
    for cid, rec in out.all().items():
        if rec["state"] not in ("door", "knocking", "pending") or clock() < rec.get("next", 0):
            continue
        card = rec["card"]
        if clock() > rec["deadline"]:
            _fail(out, cid, "gave up: no answer in time", clock)
            changed[cid] = "failed"
            continue
        car = cs.get(card["door"]["type"])
        mine = car.door_endpoint(rec["door"]) if car is not None else None
        if mine is None:
            continue                                                # our own door has no address yet
        tries = rec.get("tries", 0)

        def later(**kw):
            wait = min(POLL_MAX, POLL_MIN * (1.5 ** min(tries, 12))) * (0.8 + 0.4 * rnd.random())
            out.edit(lambda d: d[cid].update(next=int(clock() + wait), tries=tries + 1, **kw) if cid in d else None)

        def ask(body):
            return transport_for(card["door"]).request(body)
        try:
            if rec["state"] == "pending":
                resp = ask(_sign_status(me, card, clock()))
                t = resp.get("t") if isinstance(resp, dict) else None
                if t == "box":
                    body = verify_answer(resp, rec, me, cs)
                    if body is None:
                        _fail(out, cid, "the owner's answer did not verify", clock)
                        changed[cid] = "failed"
                        continue
                    why = _install_keys(body, {"thread": card["thread"], "enc": False}, me, codec)
                    if why:
                        _fail(out, cid, why, clock)
                        changed[cid] = "failed"
                        continue
                    for ep in body["endpoints"]:
                        secret = check_credential(json.loads((home / "peerkeys" / f"{rec['key']}-{ep['type']}.priv").read_text()), secret=True)
                        cs[ep["type"]].use_credential(ep, secret, agent=card["owner"]["id"])
                        book.add(card["owner"]["id"], body["name"], ep, [card["thread"]])
                    out.edit(lambda d: d[cid].update(state="joined", at=int(clock())))
                    changed[cid] = "joined"
                    try:
                        car.drop_credential(card["door"])
                    except (OSError, ValueError):
                        pass
                elif t == "rejected":
                    _fail(out, cid, "the owner rejected the request", clock)
                    changed[cid] = "failed"
                elif t == "evicted":
                    out.edit(lambda d: d[cid].update(state="knocking", next=0, tries=0))     # the pool was full: knock again (the challenge asks for the new cost)
                    changed[cid] = "knocking"
                else:
                    later(refused=rec.get("refused", 0) + (1 if t != "pending" else 0))
                    if t != "pending" and rec.get("refused", 0) + 1 >= MAX_REFUSALS:
                        _fail(out, cid, "the owner no longer knows this request (the card was closed, or the knock expired)", clock)
                        changed[cid] = "failed"
                continue
            ch = ask({"t": "challenge", "card": cid})
            if not (isinstance(ch, dict) and ch.get("t") == "challenge" and is_hex(ch.get("salt"), 32) and type(ch.get("bits")) is int and card["pow"] <= ch["bits"] <= POW_MAX + ADAPT):
                n = rec.get("refused", 0) + 1
                if n >= MAX_REFUSALS:
                    _fail(out, cid, "the knock door refuses us (the card is closed or expired, or it is not the owner's)", clock)
                    changed[cid] = "failed"
                else:
                    later(refused=n)
                continue
            bits = ch["bits"]
            for _ in range(3):                                      # 'harder': the pool filled while we worked: redo with the number it names
                req = build_knock(me, rec, mine, bytes.fromhex(ch["salt"]), min(bits, P.MAX_BITS), clock(), solve=solve)
                resp = ask(req)
                t = resp.get("t") if isinstance(resp, dict) else None
                if t == "harder" and type(resp.get("bits")) is int and bits < resp["bits"] <= POW_MAX + ADAPT:
                    bits = resp["bits"]
                    continue
                break
            if t == "pending":
                out.edit(lambda d: d[cid].update(state="pending", next=int(clock() + POLL_MIN), tries=0, refused=0))
                changed[cid] = "pending"
            elif t == "rejected":
                _fail(out, cid, "the owner rejected the request", clock)
                changed[cid] = "failed"
            elif t == "clock":
                _fail(out, cid, f"your clock is off: the owner's clock says {resp.get('now')}, yours {int(clock())}; fix the clock and join again", clock)
                changed[cid] = "failed"
            elif t in ("full", "harder"):
                later()                                              # the pool is full of stronger knocks: try again later
            else:
                n = rec.get("refused", 0) + 1
                if n >= MAX_REFUSALS:
                    _fail(out, cid, "the knock door refuses our knock", clock)
                    changed[cid] = "failed"
                else:
                    later(refused=n)
        except Exception:                                           # noqa: BLE001 - tor not ready, owner offline: try again next pass
            later()
    return changed
