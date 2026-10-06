"""The guest inbox (spec 5.1, revision 1): a write-only door for strangers to submit a guest request to a PUBLIC thread.

Deterministic, no model. Answers only `challenge` and `submit`; it never reveals the queue, other threads, or whether a non-public thread exists
("not public" and "not here" are the same bytes). The waiting pool is the mirror's own awaiting.jsonl (one source of truth, reloaded at startup by the
mirror); this module only adds (a) a stateless proof-of-work challenge, (b) admission to a bounded pool that evicts the WEAKEST proof first (never by
author count: keys are free), (c) a small sidecar remembering the bits each waiting request solved (a lost sidecar means bits 0: evicted first, never unsafe).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import threading
import time
from collections import deque
from pathlib import Path

from . import pow as P
from .event import check_structure, encode, event_id, sign_input
from .migrate import check_layout
from .keys import agent_id, valid_kex_pub, valid_sign_pub, verify_strict
from .mirror import Mirror
from .thread import MAX_AWAITING_HARD, MAX_AWAITING_PER_AUTHOR, clean_text

PERIOD = 3600                       # salt period (seconds); the current and the previous one are accepted
GUEST_POSTS_PER_HOUR = 12           # an admitted guest's posts through the inbox door (the thread's own posts_per_author_per_hour still applies)
BITS_SPAN = 6                       # adaptive bits may rise at most this far above the thread's pow_bits ...
BITS_CEILING = 26                   # ... and never above this unless the thread itself asks for more
PRESSURE_WINDOW = 600               # raise when this many "pool nearly full / refused" signals arrived in this many seconds
PRESSURE_N = 10
RAISE_EVERY = 60
QUIET_TO_LOWER = 1800
MAX_FRAME_FIELDS = {"t", "thread", "event", "pow"}
REFUSED = {"t": "refused", "why": "no"}         # the ONE answer for not public / not here / malformed thread: no enumeration


def _hex(s, n) -> bool:
    return isinstance(s, str) and len(s) == n and all(c in "0123456789abcdef" for c in s)


WAKE_GAP = 300                      # `requests wait` returns at most once per this many seconds (a stranger's flood must not wake the session in a loop)


class Inbox:
    def __init__(self, mirror: Mirror, home, *, clock=time.time, on_wake=None):
        self.m, self.home, self.clock, self.on_wake = mirror, Path(home), clock, on_wake     # on_wake(thread, count): ids and counts only, never stranger text
        if on_wake is None and getattr(mirror, "inbox", None) is not None:
            self.on_wake = lambda tid, n: mirror.note_guest(tid)          # a guest request that waits for the owner = one line in inbox.jsonl (collapsed per thread by inboxlog.GUEST_GAP)
        check_layout(self.home)
        self.dir = self.home / "guest"
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.secret = self._secret()
        self.mu = threading.Lock()
        self.bits: dict = {}                # thread -> [current bits, last change time]
        self.pressure: dict = {}            # thread -> deque of signal times
        self.stats = {"submitted": 0, "admitted": 0, "dropped": 0}
        self._dcache: dict = {}
        self._quota_loaded = False
        self._guest_posts: dict = {}          # (thread, guest) -> times of recent posts through this door

    # ---------- stateless salt ----------
    def _secret(self) -> bytes:
        p = self.dir / "secret"
        try:
            b = p.read_bytes()
            if len(b) == 32:
                return b
        except OSError:
            pass
        b = os.urandom(32)
        tmp = self.dir / f".secret.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(b)
        os.replace(tmp, p)
        return b

    def period(self, now=None) -> int:
        return int((self.clock() if now is None else now) // PERIOD)

    def salt(self, period: int) -> bytes:
        return hmac.new(self.secret, b"sigilnet/v1/inbox-salt\0" + str(period).encode(), hashlib.sha256).digest()[:16]

    # ---------- policy ----------
    def _policy(self, t) -> dict:
        return t.state()["guest_policy"]

    def bounds(self, t) -> tuple:
        lo = self._policy(t)["pow_bits"]
        return lo, max(lo, min(BITS_CEILING, lo + BITS_SPAN))

    def current_bits(self, t) -> int:
        lo, hi = self.bounds(t)
        b = self.bits.get(t.id)
        if b is None:
            return lo
        if not lo <= b[0] <= hi:                 # the policy changed under us
            b[0] = min(max(b[0], lo), hi)
        return b[0]

    def _signal(self, t) -> None:
        self.pressure.setdefault(t.id, deque(maxlen=PRESSURE_N * 4)).append(self.clock())

    def _adapt(self, t) -> None:
        now, lo, hi = self.clock(), *self.bounds(t)
        cur = self.current_bits(t)
        q = self.pressure.setdefault(t.id, deque(maxlen=PRESSURE_N * 4))
        while q and now - q[0] > PRESSURE_WINDOW:
            q.popleft()
        changed = self.bits.get(t.id, [cur, 0])[1]
        if len(q) >= PRESSURE_N and cur < hi and now - changed >= RAISE_EVERY:
            self.bits[t.id] = [cur + 1, now]
            q.clear()
        elif not q and cur > lo and now - changed >= QUIET_TO_LOWER:
            self.bits[t.id] = [cur - 1, now]
        else:
            self.bits.setdefault(t.id, [cur, changed])

    def _public(self, tid):
        t = self.m.threads.get(tid) if isinstance(tid, str) else None
        return t if t is not None and t.state()["visibility"] == "public" else None

    # ---------- sidecar: bits per waiting request ----------
    def _side(self, tid: str) -> Path:
        return self.dir / f"{tid}.bits.json"

    def _load_bits(self, tid: str) -> dict:
        try:
            d = json.loads(self._side(tid).read_text())
            return {k: v for k, v in d.items() if _hex(k, 32) and type(v) is int and 0 <= v <= P.MAX_BITS} if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_bits(self, tid: str, d: dict) -> None:
        tmp = self.dir / f".{tid}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
        os.replace(tmp, self._side(tid))

    # ---------- requests ----------
    def handle(self, req) -> dict:
        try:
            with self.mu:
                return self._handle(req)
        except Exception as e:                                       # noqa: BLE001 - a stranger's frame must never take the door down
            return {"t": "refused", "why": "internal"}

    def _handle(self, req) -> dict:
        if not isinstance(req, dict) or not isinstance(req.get("t"), str) or not set(req) <= MAX_FRAME_FIELDS:
            return dict(REFUSED)
        self.m.refresh()
        t = self._public(req.get("thread"))
        if t is None:
            return dict(REFUSED)
        self._adapt(t)
        if req["t"] == "challenge":
            if set(req) != {"t", "thread"}:
                return dict(REFUSED)
            return self._challenge(t)
        if req["t"] == "submit":
            if set(req) != {"t", "thread", "event", "pow"}:
                return dict(REFUSED)
            return self._submit(t, req)
        return dict(REFUSED)

    def _challenge(self, t) -> dict:
        p = self.period()
        return {"t": "challenge", "thread": t.id, "salt": self.salt(p).hex(), "bits": self.current_bits(t), "expires": (p + 2) * PERIOD}

    def _limit(self, t, owner_reply: bool) -> int:
        gp = self._policy(t)
        return min(MAX_AWAITING_HARD, gp["queue_max"] if owner_reply else max(gp["queue_max"] - gp["reserved_reply_slots"], 1))

    def _submit(self, t, req) -> dict:
        self.stats["submitted"] += 1
        ev, pw = req["event"], req["pow"]
        if not isinstance(ev, dict) or not isinstance(pw, dict) or set(pw) != {"salt", "nonce"} or not _hex(pw["salt"], 32):
            return self._drop("malformed")
        try:
            body_size = len(encode(ev))
        except Exception:                                            # noqa: BLE001 - not canonical JSON at all
            return self._drop("malformed")
        if body_size > self._policy(t)["max_bytes"]:
            return self._drop("too large")
        salt = bytes.fromhex(pw["salt"])
        p = self.period()
        if salt not in (self.salt(p), self.salt(p - 1)):
            return {**self._challenge(t), "t": "stale", "why": "salt"}
        author = ev.get("author")
        member = t.state()["members"].get(author) if isinstance(author, str) else None
        if member is None and isinstance(author, str) and author in t.state()["removed"]:
            return self._drop("removed key")                          # a removed key can never be re-added: its requests would only clog the queue
        if member is not None:
            return self._member_post(t, ev, pw, salt, member)              # an ADMITTED guest posting again (step 4a option b)
        g = ev.get("body", {}).get("guest") if isinstance(ev.get("body"), dict) else None
        if ev.get("thread") != t.id or ev.get("kind") != "post" or not isinstance(g, dict) or not _hex(g.get("sign"), 64):
            return self._drop("malformed")
        try:
            eid = event_id(ev)
        except Exception:                                            # noqa: BLE001
            return self._drop("malformed")
        cur = self.current_bits(t)
        got = P.achieved(salt, t.id, g["sign"], eid, pw["nonce"])
        if got < max(cur - 1, 0):                                    # a guest who fetched a challenge just before a raise is not refused
            return {**self._challenge(t), "t": "stale", "why": "bits"}
        if eid in t.stored:
            return {"t": "ok", "id": eid}                             # idempotent
        if eid in self._dropped(t.id):
            return self._drop("rejected earlier")                     # a rejected or evicted request cannot be replayed with the same proof
        ref_id = ev["body"].get("reply_to")
        ref = t.events.get(ref_id) if isinstance(ref_id, str) else None     # a RESOLVED event: replying to another waiting request would build chains nobody can evict
        if ref is None:
            return self._drop("unknown reply_to")
        why = self._precheck(ev, g, eid)                              # everything an attacker can fake for free is checked BEFORE anything is evicted
        if why:
            return self._drop(why)
        owner_reply = ref["author"] == t.state()["owner"]
        gp = self._policy(t)
        qmax = min(MAX_AWAITING_HARD, gp["queue_max"])
        limit = self._limit(t, owner_reply)
        waiting = list(t.awaiting)
        pool = [i for i in waiting if t._is_owner_reply(t.stored[i]) == owner_reply]
        if len(pool) >= max(1, limit * 3 // 4):
            self._signal(t)
        side = self._load_bits(t.id)
        while len(pool) >= limit or len(waiting) >= qmax:
            # the lane is full, or the TOTAL is (queue_max is one budget): a newcomer may only displace a waiting request of its own lane, or,
            # if it replies to an owner event, one of the general lane; never an owner-reply one if it is a general request
            src = pool if len(pool) >= limit else ([i for i in waiting if not t._is_owner_reply(t.stored[i])] if owner_reply else [])
            cand = [i for i in src if not t._has_dependents(i)]
            if not cand:
                self._signal(t)
                return self._drop("queue full")
            victim = min(cand, key=lambda i: (side.get(i, 0), t.arrived_at.get(i, 0)))
            if side.get(victim, 0) >= got:                            # the newcomer must be strictly stronger than the weakest waiting one
                self._signal(t)
                return self._drop("queue full")
            if not self.m.drop_awaiting(t.id, victim):
                return self._drop("queue full")
            waiting.remove(victim)
            if victim in pool:
                pool.remove(victim)
            side.pop(victim, None)
        mine = sorted((i for i in t.awaiting if t.stored[i]["author"] == ev["author"] and not t._has_dependents(i)), key=lambda i: t.arrived_at.get(i, 0))
        while len(mine) >= MAX_AWAITING_PER_AUTHOR:                   # the thread layer would forget the oldest silently (no replay block): do it here, recorded
            old = mine.pop(0)
            self.m.drop_awaiting(t.id, old)
            side.pop(old, None)
        res = self.m.ingest(ev, live=True)
        if res.status not in ("awaiting", "accepted", "duplicate"):
            return self._drop(res.reason[:80] or res.status)
        if res.status == "awaiting":
            side[eid] = got
            self.stats["admitted"] += 1
        live = set(t.awaiting)
        self._save_bits(t.id, {k: v for k, v in side.items() if k in live})
        if owner_reply and res.status == "awaiting" and self.on_wake is not None:
            try:
                self.on_wake(t.id, 1)
            except Exception:                                        # noqa: BLE001 - a failing wake must not turn an admitted request into a refusal
                pass
        return {"t": "ok", "id": eid}

    def _member_post(self, t, ev: dict, pw: dict, salt: bytes, member: dict) -> dict:
        """A post from a key that is already in the thread. Only role GUEST may use this door (members, admins and the owner have their own doors: sync);
        the post costs the same proof of work as a request, is capped per author per hour here on top of the thread's own rate rule, and is appended
        directly to the thread (it is a normal signed post; nothing waits). Write-only: the answer says ok or why not, nothing of the thread."""
        if member["role"] != "guest":
            return self._drop("members use their own door")
        b = ev.get("body")
        if ev.get("thread") != t.id or ev.get("kind") != "post" or not isinstance(b, dict) or not set(b) <= {"text", "reply_to", "to"}:      # no refs: a guest cannot upload, so its attachment could never be fetched
            return self._drop("malformed")
        try:
            eid = event_id(ev)
        except Exception:                                            # noqa: BLE001
            return self._drop("malformed")
        got = P.achieved(salt, t.id, member["sign"], eid, pw["nonce"])
        if got < max(self.current_bits(t) - 1, 0):
            return {**self._challenge(t), "t": "stale", "why": "bits"}
        if eid in t.events:
            return {"t": "ok", "id": eid}                             # idempotent (only for an event that really is part of the thread)
        if ev.get("admin_ref") not in t.states:
            return self._drop("unknown admin_ref")                     # would be PARKED by the thread layer (pending pool shared with everyone): never for a stranger's frame
        if not ev.get("parents") or not isinstance(ev["parents"], list) or any(not isinstance(x, str) or x not in t.events for x in ev["parents"]):
            return self._drop("unknown parent")                       # nothing is parked for strangers: every parent must already be resolved here
        if not isinstance(ev.get("sig"), str) or not verify_strict(member["sign"], ev["sig"], sign_input(ev)):
            return self._drop("bad signature")
        self._load_quota()
        q = self._guest_posts.setdefault((t.id, ev["author"]), deque())
        now = self.clock()
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) >= GUEST_POSTS_PER_HOUR:
            return self._drop("guest post quota")
        res = self.m.ingest(ev, live=True)
        if res.status not in ("accepted", "duplicate") or eid not in t.events:
            return self._drop(res.reason[:80] or res.status)
        q.append(now)
        self._save_quota()
        if len(self._guest_posts) > 4096:                             # a table, not state: bounded
            self._guest_posts = {k: v for k, v in self._guest_posts.items() if v and now - v[-1] < 3600}
        return {"t": "ok", "id": eid}

    def _quota_file(self) -> Path:
        return self.dir / "guest_quota.json"

    def _load_quota(self) -> None:
        """The per-guest post times survive a restart of the node (a restart must not reset the cap)."""
        if self._quota_loaded:
            return
        self._quota_loaded = True
        try:
            raw = json.loads(self._quota_file().read_text())
            for k, v in (raw.items() if isinstance(raw, dict) else []):
                tid, _, who = k.partition("|")
                if _hex(tid, 32) and isinstance(v, list) and len(self._guest_posts) < 4096:
                    self._guest_posts[(tid, who)] = deque(x for x in v[-GUEST_POSTS_PER_HOUR:] if isinstance(x, (int, float)) and not isinstance(x, bool))
        except (OSError, ValueError):
            pass

    def _save_quota(self) -> None:
        now = self.clock()
        data = {f"{tid}|{who}": [x for x in q if now - x < 3600] for (tid, who), q in self._guest_posts.items() if q and now - q[-1] < 3600}
        tmp = self.dir / f".quota.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self._quota_file())

    def _precheck(self, ev: dict, g: dict, eid: str) -> str | None:
        """The cheap, free-to-fake failures of a guest request (shape, keys, signature): a forged request must never cost a real one its place."""
        try:
            check_structure(ev, self._policy_max)
            if "refs" in ev["body"]:
                return "guests may not attach files"                 # guests never push bytes: such a ref could never be fetched (and would pin disk on every reader's wish)
            if set(g) != {"name", "sign", "kex"} or not clean_text(g["name"], 64) or not g["name"] or not valid_sign_pub(g["sign"]) or not valid_kex_pub(g["kex"]) \
                    or agent_id(bytes.fromhex(g["sign"])) != ev["author"]:
                return "bad guest keys"
            if not isinstance(ev.get("sig"), str) or not verify_strict(g["sign"], ev["sig"], sign_input(ev)):
                return "bad signature"
        except Exception:                                            # noqa: BLE001
            return "malformed"
        return None

    _policy_max = 65536

    def _dropped(self, tid: str) -> set:
        """Ids of requests rejected or evicted for this thread (the mirror's dropped.jsonl), cached by file size."""
        path = self.m._dir(tid) / "dropped.jsonl"
        try:
            st = path.stat()
            size = (st.st_size, st.st_ino, self.m.drop_generation(path))
        except OSError:
            return set()
        c = self._dcache.get(tid)
        if c is None or c[0] != size:
            try:
                ids = {l.split()[0] for l in path.read_text().splitlines() if l.strip()}
            except OSError:
                ids = set()
            c = self._dcache[tid] = (size, ids)
        return c[1]

    def _drop(self, why: str) -> dict:
        self.stats["dropped"] += 1
        return {"t": "refused", "why": why}

    # ---------- the owner's side (local; nothing here is reachable from the door) ----------
    def waiting(self, tid: str) -> list:
        """[(event id, bits, arrived_at, owner_reply)] for a thread, weakest last sorted newest first. Stranger text is NOT included."""
        self.m.refresh()
        t = self.m.threads.get(tid)
        if t is None:
            return []
        side = self._load_bits(tid)
        out = [(i, side.get(i, 0), t.arrived_at.get(i, 0), t._is_owner_reply(t.stored[i])) for i in t.awaiting]
        return sorted(out, key=lambda r: (-r[3], -r[1], r[2]))

    def reject(self, tid: str, eid: str) -> bool:
        with self.mu:
            ok = self.m.drop_awaiting(tid, eid)
            side = self._load_bits(tid)
            if eid in side:
                side.pop(eid)
                self._save_bits(tid, side)
            return ok
