"""Thread state and the rules that decide whether an event is valid (spec sections 4-6). DERIVATION MODEL (0.8).

A Thread is built from a genesis event and grows by `accept`. Every rule is a deterministic function of the SET of events, not of
arrival order:
  * membership is judged as of an event's `admin_ref` (the admin-chain head its author had seen);
  * a removal carries `last_seq` (and a close carries a `cut`): the author's events with a higher seq are VOIDED everywhere, whether
    they arrived before or after (voided events stay as tombstones, so replies to them still resolve);
  * competing admin events on the same `prev_admin` are resolved by rank: a valid owner_takeover beats anything else, an earlier
    successor beats a later one, otherwise the lower event id wins; the losing branch (and events citing it) is voided (`_reorg`).
The only receiver-local things left are recorded separately (`conflicts`, `awaiting`, the rate limit in mirror.py).

Nothing here touches disk or the network (see mirror.py). `accept` never raises: anything odd becomes a `rejected` Result.
"""
from __future__ import annotations

import copy
import time
import unicodedata
from dataclasses import dataclass, field

from . import canon
from .event import ADMIN_KINDS, EventError, check_structure, cosign_input, encode, event_id, is_ext_kind, sign_input
from .keys import AGENT_ID_RE, agent_id, is_hex, valid_kex_pub, valid_sign_pub, verify_strict

ROLES = ("owner", "admin", "member", "guest", "observer")
WRITER_ROLES = frozenset({"owner", "admin", "member", "guest"})       # may post
VOTER_ROLES = frozenset({"admin", "member"})                          # count in takeover quorums
K_KINDS = frozenset({"member_add", "member_remove", "rules_update", "owner_transfer", "close"})   # need k admin signatures
COSIG_KINDS = frozenset({"member_add", "member_remove", "revoke", "rules_update", "owner_transfer", "owner_takeover", "close"})
RULE_LIMITS = {"max_event_bytes": (1024, 65536), "posts_per_author_per_hour": (1, 10000), "max_members": (2, 256),
               "checkpoint_every": (1, 100000), "owner_silence_hours": (1, 24 * 365)}
GUEST_LIMITS = {"pow_bits": (0, 40), "queue_max": (1, 100000), "reserved_reply_slots": (0, 100000),
                "request_ttl_hours": (1, 24 * 30), "max_bytes": (256, 65536)}
CEILING = 65536                       # no single event may exceed this whatever the thread rules say (evidence gets extra room)
MAX_AWAITING_HARD = 200               # in-memory bound on guest requests waiting for admission (the inbox spool comes in step 4a)
MAX_AWAITING_PER_AUTHOR = 4
MAX_VOID = 1000                        # voided events kept as tombstones per thread (events beyond this are dropped on arrival)
MAX_EQUIV_PER_AUTHOR = 8               # equivocation losers kept per author (evidence, not bulk)
MAX_SIG_CACHE = 200000                 # caches, not state: junk must not grow them without bound
MAX_ADMIN_CACHE = 50000
MAX_STORED = 20000                     # events held per thread (resolved + waiting + parked)
MAX_ADMIN_SIBLINGS = 3                 # admin events one author may have on one prev_admin
MAX_UNVERIFIED_PENDING = 64            # parked events whose admin_ref we do not have: cannot be verified, so a small separate pool
MAX_PENDING_PER_AUTHOR = 64
MAX_PENDING_TOTAL = 1000
MAX_GAPS = 1000
_BAD_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def default_rules() -> dict:
    return {"max_event_bytes": 16384, "posts_per_author_per_hour": 60, "max_members": 16, "checkpoint_every": 50,
            "owner_silence_hours": 72, "retention": "forever"}


def default_guest_policy() -> dict:
    return {"mode": "moderated", "pow_bits": 20, "queue_max": 200, "reserved_reply_slots": 100, "request_ttl_hours": 72,
            "max_bytes": 4096}


@dataclass
class Result:
    status: str                     # accepted | voided | duplicate | pending | awaiting | conflict | rejected
    reason: str = ""
    missing: list = field(default_factory=list)     # ids to fetch (pending)
    accepted: list = field(default_factory=list)    # every event id newly accepted by this call (incl. admitted guest events)
    reorg: bool = False                             # the admin chain was rebuilt (a takeover or lower-ranked branch won a fork)

    @property
    def ok(self) -> bool:
        return self.status == "accepted"


def _int_in(v, lo, hi) -> bool:
    return type(v) is int and lo <= v <= hi


def _eq_int(v, n) -> bool:
    return type(v) is int and v == n          # `False == 0` must not pass as epoch 0


def _seq_list(v, last) -> bool:
    """Sorted, distinct seqs below `last`: the gaps in what the remover had seen (at most 64 of them)."""
    return isinstance(v, list) and len(v) <= 64 and all(type(x) is int and 0 <= x < last for x in v) and v == sorted(set(v))


X_MAX_BYTES = 4096


def _x_ok(x) -> bool:
    """The extension key: a JSON object (the signature and the event size cap cover it; this bounds it on its own too)."""
    if not isinstance(x, dict):
        return False
    try:
        return len(canon.dumps(x)) <= X_MAX_BYTES
    except canon.CanonError:
        return False


def _is_id(x) -> bool:
    return isinstance(x, str) and bool(AGENT_ID_RE.match(x))


def clean_text(s, maxlen: int) -> bool:
    """Names and titles: NFC, no control/format/private/unassigned characters, no line or paragraph separators, no exotic spaces."""
    if not isinstance(s, str) or len(s) > maxlen or unicodedata.normalize("NFC", s) != s:
        return False
    for c in s:
        cat = unicodedata.category(c)
        if cat in _BAD_CATEGORIES or (cat == "Zs" and c != " "):
            return False
    return True


def _check_rules(rules, *, partial=False) -> str | None:
    if not isinstance(rules, dict):
        return "rules must be an object"
    allowed = set(RULE_LIMITS) | {"retention"}
    if set(rules) - allowed or (not partial and set(rules) != allowed):
        return "unknown or missing rules"
    for k, (lo, hi) in RULE_LIMITS.items():
        if k in rules and not _int_in(rules[k], lo, hi):
            return f"rule {k} out of range"
    if "retention" in rules and rules["retention"] != "forever":
        return "unsupported retention"
    return None


def _check_guest_policy(gp, *, partial=False) -> str | None:
    if not isinstance(gp, dict):
        return "guest_policy must be an object"
    allowed = set(GUEST_LIMITS) | {"mode"}
    if set(gp) - allowed or (not partial and set(gp) != allowed):
        return "unknown or missing guest_policy fields"
    if "mode" in gp and gp["mode"] != "moderated":
        return "only moderated guest mode exists"
    for k, (lo, hi) in GUEST_LIMITS.items():
        if k in gp and not _int_in(gp[k], lo, hi):
            return f"guest_policy {k} out of range"
    if "reserved_reply_slots" in gp and "queue_max" in gp and gp["reserved_reply_slots"] > gp["queue_max"]:
        return "reserved_reply_slots exceeds queue_max"
    return None


def _member_rec(m) -> str | None:
    if not isinstance(m, dict) or set(m) != {"role", "name", "sign", "kex"}:
        return "bad member record"
    if m["role"] not in ROLES or not clean_text(m["name"], 64):
        return "bad role or name"
    if not valid_sign_pub(m["sign"]) or not valid_kex_pub(m["kex"]):
        return "bad member keys"
    return None


def _pair(members: dict) -> bool:
    return sum(1 for m in members.values() if m["role"] in ("owner", "admin", "member")) == 2



class Thread:
    """One thread as a PURE FUNCTION of the set of events held (`stored`). `add` stores an event and re-derives everything, so
    the derived view (`events`, `void_ids`, `head`, `states`, ...) cannot depend on arrival order, and replaying the stored set
    from disk gives the same view."""

    def __init__(self, genesis: dict, clock=time.time):
        try:
            why = self._genesis_problem(genesis)
        except (TypeError, KeyError, ValueError, AttributeError, IndexError, OverflowError) as e:
            why = f"malformed genesis ({type(e).__name__})"
        if why:
            raise EventError(why)
        self.clock = clock
        self.genesis = genesis
        self.format = genesis["v"]                             # the format of the whole thread: every event carries the genesis's `v` (a newer format is a NEW thread, reached by rotate)
        self.id = event_id(genesis)
        b = genesis["body"]
        members = {}
        for m in b["members"]:
            members[m["id"]] = {"role": m["role"], "name": m["name"], "sign": b["keys"][m["id"]]["sign"], "kex": b["keys"][m["id"]]["kex"]}
        self._st0 = {"admin_id": self.id, "title": b["title"], "owner": b["owner"], "owner_epoch": 0, "epoch": 0, "members": members,
                     "removed": [], "successors": list(b["successors"]), "rules": dict(b["rules"]), "guest_policy": dict(b["guest_policy"]),
                     "admin_threshold": b["admin_threshold"]["k"], "visibility": b["visibility"], "closed": False, "cp_count": 0,
                     "cut": {}, "cut_missing": {}, "closed_cut": None, "closed_cut_missing": {}, "last_cp": self.id, "pair": _pair(members)}
        self._by_prev: dict[str, list] = {}
        self.stored: dict[str, dict] = {self.id: genesis}      # every event we hold: resolved, waiting, or parked
        self.arrival: list[str] = [self.id]
        self.arrived_at: dict[str, float] = {self.id: clock()}
        self.awaiting_at = self.arrived_at                     # the arrival time of a waiting request is its `awaiting_at`
        self._sig: dict[tuple, bool] = {}
        self._admin_cache: dict[str, tuple] = {}
        self._missing_ids: set = set()
        self._seq_all: dict[tuple, int] = {}
        self._children: dict[str, set] = {}
        self._derive()

    # ---------- storing ----------
    def add_many(self, evs, times: dict | None = None) -> None:
        """Bulk load (from disk): structurally valid events are stored, then ONE derivation runs. Nothing is reported per event."""
        for ev in evs:
            try:
                check_structure(ev, CEILING * 3)
            except EventError:
                continue
            if ev["kind"] == "genesis" or ev["thread"] != self.id or ev["v"] != self.format:
                continue
            eid = event_id(ev)
            if eid not in self.stored and len(self.stored) < MAX_STORED:
                self.stored[eid] = ev
                self.arrival.append(eid)
                self.arrived_at[eid] = (times or {}).get(eid, self.clock())
        self._gen = getattr(self, "_gen", 0) + 1
        self._derive()
        self._purge_invalid()
        self._gen += 1

    def _purge_invalid(self) -> None:
        """Events that turned out invalid (bad signature, non-member, ...) are not kept: they can never become valid."""
        for eid in [i for i in self.stored if self.status.get(i) == "invalid"]:
            self._forget(eid)

    def _forget(self, eid: str) -> None:
        e = self.stored.pop(eid, None)
        self.arrived_at.pop(eid, None)
        if eid in self.arrival:
            self.arrival.remove(eid)
        for d in (self.status, self.why, self.miss, self.awaiting):
            d.pop(eid, None)
        self.unverified.discard(eid)
        if e is not None:
            for p in e["parents"]:
                kids = self._children.get(p)
                if kids is not None:
                    kids.discard(eid)
                    if not kids:
                        del self._children[p]
        if e is not None and e["kind"] not in ADMIN_KINDS:
            k = (e["author"], e["seq"])
            if self._seq_all.get(k, 0) > 1:
                self._seq_all[k] -= 1
            else:
                self._seq_all.pop(k, None)
        self._missing_ids = {x for ms in self.miss.values() for x in ms}

    def accept(self, ev: dict) -> Result:
        self._gen = getattr(self, "_gen", 0) + 1                 # generation: any change of the stored set invalidates derived caches (sync_order)
        try:
            return self._accept(ev)
        except (TypeError, KeyError, ValueError, AttributeError, IndexError, OverflowError, RecursionError) as e:
            return Result("rejected", f"malformed ({type(e).__name__})")
        finally:
            self._gen += 1

    add = accept

    def _accept(self, ev: dict) -> Result:
        try:
            check_structure(ev, CEILING * 3)
        except EventError as e:
            return Result("rejected", str(e))
        if ev["kind"] == "genesis":
            return Result("duplicate") if event_id(ev) == self.id else Result("rejected", "a second genesis")
        if ev["thread"] != self.id:
            return Result("rejected", "wrong thread")
        if ev["v"] != self.format:
            return Result("rejected", f"format mismatch (this thread is format {self.format}, the event is format {ev['v']})")
        eid = event_id(ev)
        if eid in self.stored:
            if ev.get("cosigs") and self._merge_cosigs(eid, ev):
                self._derive()
                if self.status.get(eid) in ("admin", "live"):
                    return Result("accepted", accepted=[eid])
                return Result("duplicate")
            st = self.status.get(eid)
            if st == "awaiting":
                return Result("awaiting", "already waiting for admission")
            if st == "pending":
                return Result("pending", self.why.get(eid, ""), missing=list(self.miss.get(eid, [])))
            return Result("duplicate")
        if "cosigs" in ev and ev["kind"] not in COSIG_KINDS:
            return Result("rejected", "cosigs are not allowed on this kind")
        if len(self.stored) >= MAX_STORED:
            return Result("rejected", "thread is full")
        if ev["kind"] in ADMIN_KINDS:
            same = sum(1 for e in self.stored.values() if e["kind"] in ADMIN_KINDS and e["author"] == ev["author"]
                       and e["body"].get("prev_admin") == ev["body"].get("prev_admin"))
            if same >= MAX_ADMIN_SIBLINGS:
                return Result("rejected", "too many admin events by this author on one prev_admin")
        if ev["kind"] not in ADMIN_KINDS and (ev["author"], ev["seq"]) not in self._seq_all and (ev["author"], ev["seq"]) not in self.by_author_seq \
                and eid not in self._missing_ids:
            fast = self._fast_store(eid, ev)                      # live, waiting or parked: classified alone, no full re-derivation
            if fast is not None:
                return fast
        elif ev["kind"] in ADMIN_KINDS and eid not in self._missing_ids:
            prev = ev["body"].get("prev_admin")
            if isinstance(prev, str) and is_hex(prev, 32) and prev not in self.stored:
                return self._park_admin(eid, ev, prev)            # its parent has not arrived: unverifiable, parked in the small pool
        before_resolved, before_head, before_chain = self.resolved_ids(), self.head, set(self.chain)
        self.stored[eid] = ev
        self.arrival.append(eid)
        self.arrived_at[eid] = self.clock()
        self._derive()
        st = self.status.get(eid)
        why = self.why.get(eid, "invalid")
        self._enforce_awaiting_bound()
        self._purge_invalid()
        if st == "invalid":
            return Result("rejected", why)
        if st == "void" and len(self.void_ids) > MAX_VOID:
            self._forget(eid)
            self._derive()
            return Result("rejected", "too many voided events")
        by_author: dict[str, list] = {}
        for i in self.arrival:
            if i in self.equiv:
                by_author.setdefault(self.equiv[i]["author"], []).append(i)
        over = [i for ids in by_author.values() for i in ids[:-MAX_EQUIV_PER_AUTHOR]] if any(len(v) > MAX_EQUIV_PER_AUTHOR for v in by_author.values()) else []
        if over:                                                   # equivocation evidence, not bulk: keep the newest few per author
            for i in over:
                self._forget(i)
            self._derive()
            if eid not in self.stored:
                return Result("rejected", "too many equivocation losers from this author")
        self._enforce_pools(eid)
        st = self.status.get(eid, "gone")
        if eid not in self.stored:
            return Result("rejected", "evicted: too many events parked or waiting from this author")
        resolved_now = self.resolved_ids()                       # once: it builds a set of every event (O(n)); per arrival this made an admin event O(n^2)
        newly = [i for i in self.arrival if i in resolved_now and i not in before_resolved]
        reorg = before_head not in set(self.chain)
        if st == "live" or st == "admin":
            return Result("accepted", accepted=newly, reorg=reorg)
        if st == "void":
            return Result("voided", self.why.get(eid, ""), accepted=newly)
        if st == "awaiting":
            return Result("awaiting", "waiting for a member_add that names this event")
        if st == "pending":
            return Result("pending", self.why.get(eid, ""), missing=list(self.miss.get(eid, [])))
        return Result("conflict", self.why.get(eid, st), accepted=newly)         # lost fork / equivocation loser

    def _merge_cosigs(self, eid: str, ev: dict) -> bool:
        """The same event (same id) arrived with co-signatures the stored copy lacks (a relay may strip them). Adopt the ones that verify."""
        mine = self.stored[eid]
        have = {c["author"]: c for c in mine.get("cosigs", [])}
        changed = False
        for c in ev["cosigs"]:
            key = self.known_keys.get(c["author"])
            cur = have.get(c["author"])
            if key is None or not verify_strict(key, c["sig"], cosign_input(mine)):
                continue
            if cur is None or (cur["sig"] != c["sig"] and not verify_strict(key, cur["sig"], cosign_input(mine))):
                have[c["author"]] = c
                changed = True
        if changed:
            self.stored[eid] = dict(mine, cosigs=sorted(have.values(), key=lambda c: c["author"]))
        return changed

    def _fast_store(self, eid: str, ev: dict) -> Result | None:
        """A new non-admin event that nothing else depends on changes nothing else, whether it turns out live, waiting for admission or
        parked: classify just it. Anything else (void, equivocation, ...) returns None and takes the full derivation, which is the
        reference (a differential test compares the two on random histories). This also keeps junk cheap: a parked or waiting event
        costs one classification, not an O(events) re-derivation."""
        for d in (self.status, self.why, self.miss):
            d.pop(eid, None)
        self._classify_one(eid, ev, self.states, self._on_chain, self._admitted_pairs, ("live", "void", "awaiting", "equiv"))
        st = self.status.get(eid)
        if st == "invalid":
            why = self.why.get(eid, "invalid")
            for d in (self.status, self.why, self.miss):
                d.pop(eid, None)
            self.unverified.discard(eid)
            return Result("rejected", why)
        if st not in ("live", "awaiting", "pending"):
            for d in (self.status, self.why, self.miss):
                d.pop(eid, None)
            self.unverified.discard(eid)
            return None
        self.stored[eid] = ev
        self.arrival.append(eid)
        self.arrived_at[eid] = self.clock()
        self._seq_all[(ev["author"], ev["seq"])] = 1
        for p in ev["parents"]:
            self._children.setdefault(p, set()).add(eid)
        if st == "live":
            self.events[eid] = ev
            self.by_author_seq[(ev["author"], ev["seq"])] = eid
            self._order = None
            return Result("accepted", accepted=[eid])
        if st == "awaiting":
            self.awaiting[eid] = ev
        else:
            self._missing_ids |= set(self.miss.get(eid, []))
        self._enforce_pools(eid)
        if eid not in self.stored:
            return Result("rejected", "evicted: too many events parked or waiting from this author")
        if st == "awaiting":
            return Result("awaiting", "waiting for a member_add that names this event")
        return Result("pending", self.why.get(eid, ""), missing=list(self.miss.get(eid, [])))

    def _park_admin(self, eid: str, ev: dict, prev: str) -> Result:
        self.stored[eid] = ev
        self.arrival.append(eid)
        self.arrived_at[eid] = self.clock()
        self.status[eid], self.why[eid], self.miss[eid] = "pending", "unknown prev_admin", [prev]
        self.unverified.add(eid)
        self._missing_ids.add(prev)
        for p in ev["parents"]:
            self._children.setdefault(p, set()).add(eid)
        self._enforce_pools(eid)
        if eid not in self.stored:
            return Result("rejected", "evicted: too many events parked or waiting from this author")
        return Result("pending", "unknown prev_admin", missing=[prev])

    def resolved_ids(self) -> set:
        """Everything worth persisting: live, voided, chain and lost admin events, equivocation losers (not waiting/parked events)."""
        return set(self.events) | set(self.lost_admin) | set(self.equiv)

    # ---------- guests waiting for admission, and parked events: bounded pools ----------
    def _has_dependents(self, eid: str) -> bool:
        return bool(self._children.get(eid))

    def _is_owner_reply(self, ev: dict) -> bool:
        e = self.stored.get(ev["body"].get("reply_to"))
        return e is not None and e["author"] == self._head_state["owner"]

    def prune_awaiting(self) -> list:
        """Drop unadmitted guest requests older than request_ttl_hours (receiver clock) unless something already replies to them."""
        ttl = self._head_state["guest_policy"]["request_ttl_hours"] * 3600
        now = self.clock()
        gone = [i for i in self._awaiting_ids() if now - self.arrived_at.get(i, now) > ttl and not self._has_dependents(i)]
        for i in gone:
            self._forget(i)
        if gone:
            self._derive()
        return gone

    def _awaiting_ids(self) -> list:
        return [i for i in self.arrival if self.status.get(i) == "awaiting" and i in self.stored]

    def _enforce_awaiting_bound(self) -> None:
        """Requests can be promoted from parked to waiting in bulk (when their parent arrives): hold the queue bounds after every derivation."""
        if not self.awaiting:
            return
        gp = self._head_state["guest_policy"]
        general = max(gp["queue_max"] - gp["reserved_reply_slots"], 1)
        for owner_reply, lim in ((True, min(MAX_AWAITING_HARD, gp["queue_max"])), (False, min(MAX_AWAITING_HARD, general))):
            while True:
                pool = [i for i in self._awaiting_ids() if self._is_owner_reply(self.stored[i]) == owner_reply]
                cand = [i for i in pool if not self._has_dependents(i)]
                if len(pool) <= lim or not cand:
                    break
                counts: dict[str, int] = {}
                for i in cand:
                    counts[self.stored[i]["author"]] = counts.get(self.stored[i]["author"], 0) + 1
                heavy = max(counts, key=lambda a: counts[a])
                self._forget(min((i for i in cand if self.stored[i]["author"] == heavy), key=lambda i: self.arrived_at[i]))

    def _enforce_pools(self, eid: str) -> None:
        """Receiver-local resource limits on events that are NOT part of the thread yet. They only ever remove waiting/parked
        events (never one that something already replies to), so the derived thread is unaffected."""
        changed = False
        gp = self._head_state["guest_policy"]
        if self.status.get(eid) == "awaiting":
            now, ttl = self.clock(), gp["request_ttl_hours"] * 3600
            for i in self._awaiting_ids():
                if now - self.arrived_at.get(i, now) > ttl and not self._has_dependents(i):
                    self._forget(i); changed = True
            author = self.stored[eid]["author"] if eid in self.stored else None
            mine = [i for i in self._awaiting_ids() if self.stored[i]["author"] == author]
            while len(mine) > MAX_AWAITING_PER_AUTHOR:
                victim = next((i for i in mine if i != eid and not self._has_dependents(i)), None)
                if victim is None:
                    break
                mine.remove(victim); self._forget(victim); changed = True
            owner_reply = eid in self.stored and self._is_owner_reply(self.stored[eid])
            limit = min(MAX_AWAITING_HARD, gp["queue_max"] if owner_reply else max(gp["queue_max"] - gp["reserved_reply_slots"], 1))
            while True:
                pool = [i for i in self._awaiting_ids() if self._is_owner_reply(self.stored[i]) == owner_reply]
                cand = [i for i in pool if i != eid and not self._has_dependents(i)]
                if len(pool) <= limit or not cand:
                    break
                counts: dict[str, int] = {}
                for i in cand:
                    counts[self.stored[i]["author"]] = counts.get(self.stored[i]["author"], 0) + 1
                heavy = max(counts, key=lambda a: counts[a])
                self._forget(min((i for i in cand if self.stored[i]["author"] == heavy), key=lambda i: self.arrived_at[i]))
                changed = True
        # parked events: those whose admin_ref we do not have cannot even be verified, so they get their own small pool
        unverified = [i for i in self.arrival if self.status.get(i) == "pending" and i in self.unverified]
        while len(unverified) > MAX_UNVERIFIED_PENDING:
            self._forget(unverified.pop(0)); changed = True
        by_author: dict[str, list] = {}
        for i in self.arrival:
            if self.status.get(i) == "pending" and i not in self.unverified:
                by_author.setdefault(self.stored[i]["author"], []).append(i)
        for ids in by_author.values():
            while len(ids) > MAX_PENDING_PER_AUTHOR:
                self._forget(ids.pop(0)); changed = True
        parked = [i for i in self.arrival if self.status.get(i) == "pending"]
        while len(parked) > MAX_PENDING_TOTAL:
            self._forget(parked.pop(0)); changed = True
        # parked and waiting events do not take part in the derivation, so evicting them needs no re-derivation

    # ---------- the derivation ----------
    def state(self, admin_id: str | None = None) -> dict:
        return self.states[admin_id or self.head]

    @staticmethod
    def admin_set(st: dict) -> set:
        return {a for a, m in st["members"].items() if m["role"] in ("owner", "admin")}

    def _sig_ok(self, ev: dict, eid: str, pub: str | None, ctx=sign_input) -> bool:
        if pub is None:
            return False
        k = (eid, ev["sig"], pub, ctx is sign_input)
        if len(self._sig) > MAX_SIG_CACHE:
            self._sig.clear()                                   # a cache, not state: junk must not grow it without bound
        if k not in self._sig:
            self._sig[k] = verify_strict(pub, ev["sig"], ctx(ev))
        return self._sig[k]

    @staticmethod
    def _rank(ev: dict, prev_st: dict) -> tuple:
        """Fork winner = lowest tuple. A takeover by a listed successor beats anything (earlier successor first); otherwise the owner's
        event beats an admin's (a removed admin cannot grind a lower id to undo the owner removing them); a self-revoke ranks last
        (it needs a single signature, so even a plain member could otherwise displace a k-signature admin event); then the lower id."""
        a = ev["author"]
        if ev["kind"] == "owner_takeover" and a in prev_st["successors"]:
            return (0, prev_st["successors"].index(a), event_id(ev))
        if ev["kind"] == "revoke" and ev["body"].get("agent") == a:
            return (3, 0, event_id(ev))                # a self-revoke needs one signature: it must never displace an admin's event
        if a == prev_st["owner"]:
            return (1, 0, event_id(ev))
        return (2, 0, event_id(ev))

    def _admin_valid(self, ev: dict, eid: str, prev_st: dict) -> tuple:
        """Is this admin event valid on top of the state `prev_st`? Depends on nothing else, so the answer is cached for good."""
        # a takeover is judged against the branch it would displace, which can change as events arrive: that branch's head is part of the key
        disp = self._displaced(ev["body"].get("prev_admin"), prev_st)[0] if ev["kind"] == "owner_takeover" else ""
        key = (eid, ev["sig"], tuple((c["author"], c["sig"]) for c in ev.get("cosigs", [])), disp)
        if len(self._admin_cache) > MAX_ADMIN_CACHE:
            self._admin_cache.clear()
        if key not in self._admin_cache:
            self._admin_cache[key] = self._admin_valid_uncached(ev, eid, prev_st)
        return self._admin_cache[key]

    def _displaced(self, prev_id, prev_st: dict) -> tuple:
        """(head id, head state) of the greedy NON-takeover chain from `prev_id`: what an owner's side of a fork would build.
        A takeover's voters must still be members at that head, or removed members could take a thread back with their old votes."""
        cur_id, cur = prev_id, prev_st
        while True:
            cands = []
            for c in sorted(self._by_prev.get(cur_id, [])):
                e = self.stored[c]
                if e["kind"] == "owner_takeover":
                    continue
                new, _ = self._admin_valid(e, c, cur)
                if new is not None:
                    cands.append((c, new))
            if not cands:
                return cur_id, cur
            cur_id, cur = min(cands, key=lambda x: self._rank(self.stored[x[0]], cur))

    def _admin_valid_uncached(self, ev: dict, eid: str, prev_st: dict) -> tuple:
        b, kind, author = ev["body"], ev["kind"], ev["author"]
        prev = b.get("prev_admin")
        if ev["admin_ref"] != prev:
            return None, "prev_admin must equal admin_ref"
        if prev_st["closed"]:
            return None, "thread is closed"
        m = prev_st["members"].get(author)
        if m is None:
            return None, "author is not a member as of prev_admin"
        if not self._sig_ok(ev, eid, m["sign"]):
            return None, "bad signature"
        self_revoke = kind == "revoke" and b.get("agent") == author
        if not self_revoke and not (author in self.admin_set(prev_st) or (kind == "owner_takeover" and author in prev_st["successors"])):
            return None, "author may not write admin events"
        cap = prev_st["rules"]["max_event_bytes"]
        if len(encode(ev)) > min(cap, CEILING * 3):
            return None, "event larger than the size cap as of prev_admin"
        new, why = self._transition(ev, eid, prev_st)
        if why:
            return None, why
        new["admin_id"] = eid
        return new, None

    def _derive(self) -> None:
        E = self.stored
        self.status, self.why, self.miss, self.unverified = {}, {}, {}, set()
        # ---- 1. the admin tree: every valid admin event has a state (its own prefix decides it, nothing else)
        by_prev: dict[str, list] = {}
        for i, e in E.items():
            if e["kind"] in ADMIN_KINDS and i != self.id:
                p = e["body"].get("prev_admin")
                by_prev.setdefault(p if isinstance(p, str) else "", []).append(i)
        self._by_prev = by_prev
        states = {self.id: self._st0}
        stack = [self.id]
        while stack:
            p = stack.pop()
            for c in sorted(by_prev.get(p, [])):
                new, why = self._admin_valid(E[c], c, states[p])
                if new is None:
                    self.status[c], self.why[c] = "invalid", why
                else:
                    states[c] = new
                    stack.append(c)
        stuck = [i for ids in by_prev.values() for i in ids if i not in states and i not in self.status]
        waiting, frontier = set(), []
        for c in stuck:
            p = E[c]["body"].get("prev_admin")
            if not isinstance(p, str) or not is_hex(p, 32):
                self.status[c], self.why[c] = "invalid", "bad prev_admin"
            elif p not in E:
                waiting.add(c); frontier.append(c)                       # its parent has not arrived yet
        while frontier:
            x = frontier.pop()
            for c in by_prev.get(x, []):
                if c not in states and c not in self.status and c not in waiting:
                    waiting.add(c); frontier.append(c)
        for c in stuck:
            if c in self.status:
                continue
            if c in waiting:
                self.status[c], self.why[c], self.miss[c] = "pending", "unknown prev_admin", [E[c]["body"]["prev_admin"]]
                self.unverified.add(c)
            else:
                self.status[c], self.why[c] = "invalid", "prev_admin is not a valid admin event"
        # ---- 2. the winning chain, chosen greedily by rank at every fork
        head, chain, forks = self.id, [self.id], []
        while True:
            cands = [c for c in sorted(by_prev.get(head, [])) if c in states]
            if not cands:
                break
            win = min(cands, key=lambda c: self._rank(E[c], states[head]))
            forks.append((head, win, [c for c in cands if c != win]))
            head = win
            chain.append(win)
        on_chain = set(chain)
        self.head, self.chain, self.states = head, chain, states
        self._head_state = states[head]
        self._on_chain = on_chain
        self.lost_admin = {i: E[i] for i in states if i not in on_chain}
        self.admin_children = {chain[k]: chain[k + 1] for k in range(len(chain) - 1)}
        self.known_keys = {}
        for st in states.values():
            for a, m in st["members"].items():
                self.known_keys[a] = m["sign"]
        for i in chain:
            self.status[i] = "admin" if i != self.id else "genesis"
        for i in self.lost_admin:
            self.status[i], self.why[i] = "lost", "admin event on a branch that lost a fork"
        # ---- 3. everything else, parents first
        admitted = {}
        self.admitted = {}
        self._admitted_pairs = admitted
        for c in chain:
            if E[c]["kind"] == "member_add":
                for x in E[c]["body"].get("admits", []):
                    agent = E[c]["body"]["agent"]
                    admitted.setdefault((x, agent), c)         # (request id, agent): naming someone else's request admits nothing
                    self.admitted.setdefault(x, agent)
        cand = [i for i in self.arrival if i in E and i != self.id and E[i]["kind"] not in ADMIN_KINDS]
        RESOLVED = ("live", "void", "awaiting", "equiv")
        for root in cand:
            if root in self.status:
                continue
            todo = [root]
            while todo:
                i = todo[-1]
                if i in self.status:
                    todo.pop()
                    continue
                deps = [p for p in E[i]["parents"] if p in E and p not in states and E[p]["kind"] not in ADMIN_KINDS and p not in self.status]
                if deps:
                    todo.extend(deps)
                    continue
                self._classify_one(i, E[i], states, on_chain, admitted, RESOLVED)
                todo.pop()
        # ---- 4. one event per (author, seq): if an author signed two, NONE of them is live (an author must not be able to rewrite a
        #         message others already answered by grinding a lower id); they stay as evidence. An admin event always keeps its seq.
        fixed = {}
        for i in chain:
            fixed[(E[i]["author"], E[i]["seq"])] = i
        groups: dict[tuple, list] = {}
        for i in cand:
            if self.status.get(i) in ("live", "void"):
                groups.setdefault((E[i]["author"], E[i]["seq"]), []).append(i)
        conflicts = []
        for key, ids in sorted(groups.items()):
            ids = sorted(ids)
            if key in fixed:
                for i in ids:
                    self.status[i], self.why[i] = "equiv", "same author and seq as an admin event (equivocation)"
                    conflicts.append({"kind": "seq", "a": E[fixed[key]], "b": E[i]})
            elif len(ids) > 1:
                for i in ids:
                    self.status[i], self.why[i] = "equiv", "same author and seq as another event (equivocation): none of them is live"
                for i in ids[1:]:
                    conflicts.append({"kind": "seq", "a": E[ids[0]], "b": E[i]})
        self.owner_equivocated = False
        for prev, win, losers in forks:
            for l in losers:
                conflicts.append({"kind": "admin_fork", "a": E[win], "b": E[l]})
                if E[l]["author"] == E[win]["author"] == states[prev]["owner"]:
                    self.owner_equivocated = True
            same = [c for c in sorted(by_prev.get(prev, [])) if c in states and E[c]["author"] == states[prev]["owner"]]
            if len(same) > 1:
                self.owner_equivocated = True
        self.conflicts = conflicts
        # ---- 5. views
        self.events = {i: E[i] for i in self.arrival if i in E and self.status.get(i) in ("live", "void", "admin", "genesis")}
        self.events.setdefault(self.id, self.genesis)
        self.void_ids = {i for i in self.events if self.status.get(i) == "void"}
        self._order = None                                                # reading order is computed lazily (a function of the set, so reload-stable)
        self._missing_ids = {x for ms in self.miss.values() for x in ms}
        self._seq_all: dict[tuple, int] = {}
        self._children = {}
        for i, e in E.items():
            if e["kind"] not in ADMIN_KINDS:
                self._seq_all[(e["author"], e["seq"])] = self._seq_all.get((e["author"], e["seq"]), 0) + 1
            for p in e["parents"]:
                self._children.setdefault(p, set()).add(i)
        self.equiv = {i: E[i] for i in E if self.status.get(i) == "equiv"}
        self.awaiting = {i: E[i] for i in E if self.status.get(i) == "awaiting"}
        self.by_author_seq = {(e["author"], e["seq"]): i for i, e in self.events.items()}

    @property
    def order(self) -> list:
        if self._order is None:
            self._order = self.topo(include_void=True)
        return self._order

    def _void_reason(self, ev: dict, head: dict) -> str | None:
        """Is this (non-admin) event beyond a cut declared by a removal or a close? A pure function of the event and the head state."""
        a, sq = ev["author"], ev["seq"]
        if a in head["cut"] and (sq > head["cut"][a] or sq in head["cut_missing"].get(a, ())):
            return "beyond the last_seq (or in a gap) declared when its author was removed"
        if head["closed"] and head["closed_cut"] is not None and (sq > head["closed_cut"].get(a, -1) or sq in head["closed_cut_missing"].get(a, ())):
            return "beyond the cut (or in a gap) declared when the thread was closed"
        return None

    def _classify_one(self, i: str, e: dict, states: dict, on_chain: set, admitted: dict, RESOLVED: tuple) -> None:
        E = self.stored
        ref = e["admin_ref"]
        if ref not in states:
            if ref in E and (E[ref]["kind"] in ADMIN_KINDS):
                if self.status.get(ref) == "pending":
                    self.status[i], self.why[i], self.miss[i] = "pending", "admin_ref is itself waiting", [ref]
                    self.unverified.add(i)
                else:
                    self.status[i], self.why[i] = "invalid", "admin_ref names an invalid admin event"
            elif ref in E:
                self.status[i], self.why[i] = "invalid", "admin_ref must name an admin event"
            else:
                self.status[i], self.why[i], self.miss[i] = "pending", "unknown admin_ref", [ref]
                self.unverified.add(i)
            return
        st_ref = states[ref]
        author, kind = e["author"], e["kind"]
        cap = st_ref["rules"]["max_event_bytes"]
        cap = 3 * cap + 2048 if kind == "evidence" else cap
        if len(encode(e)) > min(cap, CEILING * 3):
            self.status[i], self.why[i] = "invalid", "event larger than the size cap as of admin_ref"
            return
        m = st_ref["members"].get(author)
        guest = None
        waiting = False
        st_body = st_ref
        if m is None:
            g = e["body"].get("guest") if kind == "post" else None
            # cheap checks first: a junk key costs a subgroup check (~1 ms)
            if not isinstance(g, dict) or set(g) != {"name", "sign", "kex"} or not clean_text(g["name"], 64) or not is_hex(g["sign"], 64) \
                    or agent_id(bytes.fromhex(g["sign"])) != author or not valid_sign_pub(g["sign"]) or not valid_kex_pub(g["kex"]):
                self.status[i], self.why[i] = "invalid", "author is not a member as of admin_ref"
                return
            if not self._sig_ok(e, i, g["sign"]):
                self.status[i], self.why[i] = "invalid", "bad signature"
                return
            guest = g
            if len(encode(e)) > st_ref["guest_policy"]["max_bytes"]:
                self.status[i], self.why[i] = "invalid", "guest request larger than guest_policy.max_bytes"
                return
            why = self._body_problem(e, st_ref, admitting=True)
            if why:
                self.status[i], self.why[i] = "invalid", why
                return
            adm = admitted.get((i, author))
            if adm is None:
                waiting = True                                           # decided after the parents check: a request with unknown parents is parked
            else:
                st_body = states[adm]
                mm = st_body["members"].get(author)
                if mm is None or mm["sign"] != g["sign"] or mm["kex"] != g["kex"]:
                    self.status[i], self.why[i] = "invalid", "the admitted member does not match the request's keys"
                    return
        elif not self._sig_ok(e, i, m["sign"]):
            self.status[i], self.why[i] = "invalid", "bad signature"
            return
        missing = []
        for p in e["parents"]:
            if p == self.id or p in states:
                continue
            if p in E and self.status.get(p) in RESOLVED:
                continue
            missing.append(p)
        if missing:
            self.status[i], self.why[i], self.miss[i] = "pending", "unknown parents", missing
            return
        if waiting:
            self.status[i] = "awaiting"
            return
        self_revoke = kind == "revoke" and e["body"].get("agent") == author
        role = st_body["members"].get(author, {}).get("role")
        if role == "observer" and not self_revoke:
            self.status[i], self.why[i] = "invalid", "observers may not write"
            return
        why = self._body_problem(e, st_body, admitting=guest is not None, self_revoke=self_revoke)
        if why:
            self.status[i], self.why[i] = "invalid", why
            return
        if st_ref["closed"]:
            self.status[i], self.why[i] = "invalid", "thread is closed (its author had already seen the close)"
            return
        if ref not in on_chain:
            self.status[i], self.why[i] = "void", "cites an admin event that lost a fork"
            return
        why = self._void_reason(e, self._head_state)
        if why:
            self.status[i], self.why[i] = "void", why
            return
        self.status[i] = "live"

    # ---------- views ----------
    def leaves(self) -> list:
        """Resolved events (live, voided, lost admin, equivocation losers) nobody else names as a parent, oldest first, plus the admin head:
        a peer that fetches these and then whatever is missing walks the whole DAG (sync.py)."""
        res = self.resolved_ids()
        named = set()
        for i in res:
            named.update(self.stored[i]["parents"])
        out = [i for i in self.arrival if i in res and i not in named and i != self.id]
        if self.head != self.id and self.head not in out:
            out.append(self.head)
        return out

    def sync_order(self) -> list:
        """Every resolved event id in a dependency order (parents, admin_ref and prev_admin first; ties by arrival): what a peer should fetch,
        front to back, so each batch's dependencies are already in hand and nothing has to be parked. Cached per state of the thread."""
        key = (getattr(self, "_gen", 0), len(self.stored), self.head, len(self.arrival), len(self.lost_admin), len(self.equiv))
        if getattr(self, "_sync_key", None) == key:
            return self._sync_cache
        res = self.resolved_ids()
        index = {i: n for n, i in enumerate(self.arrival)}
        deps: dict[str, set] = {}
        kids: dict[str, list] = {}
        for i in res:
            e = self.stored[i]
            d = {p for p in e["parents"] if p in res}
            for x in (e.get("admin_ref"), e["body"].get("prev_admin")):
                if isinstance(x, str) and x in res and x != i:
                    d.add(x)
            deps[i] = d
            for p in d:
                kids.setdefault(p, []).append(i)
        import heapq
        heap = [(index.get(i, 0), i) for i, d in deps.items() if not d]
        heapq.heapify(heap)
        out, left = [], {i: len(d) for i, d in deps.items()}
        while heap:
            _, i = heapq.heappop(heap)
            out.append(i)
            for k in kids.get(i, []):
                left[k] -= 1
                if left[k] == 0:
                    heapq.heappush(heap, (index.get(k, 0), k))
        out += [i for i in res if i not in set(out)]                  # (cannot happen: hashes cannot form a cycle) never lose an id
        self._sync_key, self._sync_cache = key, out
        return out

    def missing(self) -> list:
        """Ids worth fetching: parents/admin heads of parked events, guest requests an admission names, checkpoint heads."""
        need = {p for p in self._children if p not in self.stored}          # parents named by any held event (admin events do not need them to be valid)
        for i, ms in self.miss.items():
            need |= {x for x in ms if x not in self.stored}
        for x in self.admitted:
            if x not in self.stored:
                need.add(x)
        for i in self.chain:
            if self.stored[i]["kind"] == "checkpoint":
                need |= {h for h in self.stored[i]["body"]["heads"] if h not in self.stored}
        return sorted(need)

    @staticmethod
    def _genesis_problem(g) -> str | None:
        check_structure(g, CEILING)
        if g["kind"] != "genesis":
            return "not a genesis"
        b = g["body"]
        need = {"title", "owner", "keys", "members", "successors", "rules", "visibility", "guest_policy", "admin_threshold", "owner_epoch", "epoch"}
        if set(b) != need:
            return "genesis body has the wrong fields"
        if not clean_text(b["title"], 200) or not b["title"]:
            return "bad title"
        if not _is_id(b["owner"]) or g["author"] != b["owner"]:
            return "the owner must author the genesis"
        keys = b["keys"]
        if not isinstance(keys, dict) or not keys or len(keys) > 256:
            return "bad keys"
        for a, k in keys.items():
            if not _is_id(a) or not isinstance(k, dict) or set(k) != {"sign", "kex"} or not valid_sign_pub(k["sign"]) or not valid_kex_pub(k["kex"]):
                return "bad key record"
            if agent_id(bytes.fromhex(k["sign"])) != a:
                return "agent id does not match its signing key"
        if b["owner"] not in keys:
            return "owner key missing"
        if not verify_strict(keys[b["owner"]]["sign"], g["sig"], sign_input(g)):
            return "genesis signature does not verify"
        ms = b["members"]
        if not isinstance(ms, list) or not ms:
            return "bad members"
        ids = []
        for m in ms:
            if not isinstance(m, dict) or set(m) != {"id", "name", "role"} or not _is_id(m["id"]) or m["id"] not in keys \
                    or m["role"] not in ROLES or not clean_text(m["name"], 64):
                return "bad member entry"
            ids.append(m["id"])
        if len(ids) != len(set(ids)) or set(ids) != set(keys):
            return "members and keys must list the same agents"
        if [m["id"] for m in ms if m["role"] == "owner"] != [b["owner"]]:
            return "exactly one member must be the owner"
        if b["visibility"] not in ("private", "public"):
            return "bad visibility"
        if b["visibility"] == "public" and g["v"] != 1:
            return "a public thread must be format 1 (its read door serves anyone, including software that cannot read a newer format)"
        why = _check_rules(b["rules"]) or _check_guest_policy(b["guest_policy"])
        if why:
            return why
        if len(ms) > b["rules"]["max_members"]:
            return "more members than max_members"
        if not _eq_int(b["owner_epoch"], 0) or not _eq_int(b["epoch"], 0):
            return "genesis epochs must be 0"
        roles = {m["id"]: m["role"] for m in ms}
        s = b["successors"]
        if not isinstance(s, list) or any(not _is_id(x) for x in s) or len(s) != len(set(s)) or any(roles.get(x) != "member" for x in s):
            return "successors must be distinct plain members (an admin successor could be removed by the owner alone, which would veto a takeover)"
        if sum(1 for m in ms if m["role"] in ("owner", "admin", "member")) <= 2 and s:
            return "a two-party thread has no successors (it ends if either party leaves)"
        at = b["admin_threshold"]
        if not isinstance(at, dict) or set(at) != {"k"} or not _int_in(at["k"], 1, 16):
            return "bad admin_threshold"
        if at["k"] > sum(1 for m in ms if m["role"] in ("owner", "admin")):
            return "admin_threshold exceeds the size of the admin set"
        if s and at["k"] < 2:
            return "a thread with successors needs admin_threshold k >= 2 (with k = 1 a single admin could veto a takeover by releasing a pre-signed removal)"
        return None

    def _body_problem(self, ev: dict, st: dict, admitting: bool = False, self_revoke: bool = False) -> str | None:
        kind, b, author = ev["kind"], ev["body"], ev["author"]
        role = st["members"].get(author, {}).get("role")
        xs = {"x"} if self.format >= 2 else set()              # the extension key (format 2 only; never in admin bodies)
        if "x" in b and not is_ext_kind(kind) and (not xs or kind not in ("post", "digest", "evidence") or "guest" in b or not _x_ok(b["x"])):     # (an extension kind's body is free-form)
            return "bad extension key x"
        if kind == "post":
            allowed = {"text", "reply_to", "refs", "to", "guest"} | xs
            if not isinstance(b.get("text"), str) or set(b) - allowed:
                return "bad post body"
            if "reply_to" in b and (not is_hex(b["reply_to"], 32) or b["reply_to"] not in ev["parents"]):
                return "reply_to must be one of the parents"
            if "refs" in b:
                r = b["refs"]
                if not isinstance(r, list) or len(r) > 16 or any(
                        not isinstance(x, dict) or set(x) != {"kind", "cid", "size"} or x["kind"] != "file" or not isinstance(x["cid"], str)
                        or not x["cid"].startswith("sha256:") or not is_hex(x["cid"][7:], 64) or not _int_in(x["size"], 0, 2 ** 40) for x in r):
                    return "bad refs"
            if "to" in b and (not isinstance(b["to"], list) or len(b["to"]) > 16 or any(not _is_id(x) for x in b["to"])):
                return "bad to"
            if "guest" in b and not admitting:
                return "the guest field is only for admission requests"
            if role is not None and role not in WRITER_ROLES:
                return "role may not post"
            return None
        if role is None:
            return "author is not a member"
        if self_revoke:
            return None                                       # any member may revoke itself, whatever its role
        if role not in ("owner", "admin", "member"):
            return "role may not write this kind"
        if kind == "digest":
            if set(b) - {"text", "covers", "pinned"} - xs or not isinstance(b.get("text"), str) or not isinstance(b.get("covers"), list) \
                    or len(b["covers"]) > 64 or any(not is_hex(x, 32) for x in b["covers"]):
                return "bad digest"
            if "pinned" in b:
                if type(b["pinned"]) is not bool:
                    return "pinned must be a boolean"
                if b["pinned"] and author != st["owner"]:
                    return "only the owner can pin a digest"
            return None
        if kind == "evidence":
            return self._evidence_problem(b, role)
        return None       # admin kinds (and extension kinds: a plain leaf event, never interpreted) are judged in _accept_admin (they need the whole event: cosigs)

    def _in_thread(self, e: dict) -> bool:
        return e["thread"] == self.id or event_id(e) == self.id       # the genesis itself is part of the thread

    def _evidence_problem(self, b: dict, role) -> str | None:
        if role not in ("owner", "admin", "member"):
            return "role may not file evidence"
        if set(b) - {"a", "b", "reason", "x"} or not isinstance(b.get("a"), dict) or not isinstance(b.get("b"), dict):
            return "bad evidence"
        if "reason" in b and (not isinstance(b["reason"], str) or len(b["reason"]) > 500):
            return "bad evidence reason"
        a, c = b["a"], b["b"]
        try:
            check_structure(a, CEILING); check_structure(c, CEILING)
        except EventError as e:
            return f"evidence event malformed: {e}"
        if a["v"] != self.format or c["v"] != self.format:
            return "evidence events must have this thread's format"
        if not self._in_thread(a) or not self._in_thread(c) or a["author"] != c["author"] or event_id(a) == event_id(c):
            return "evidence must be two different events by one author in this thread"
        key = self.known_keys.get(a["author"])
        if key is None or not verify_strict(key, a["sig"], sign_input(a)) or not verify_strict(key, c["sig"], sign_input(c)):
            return "evidence signatures do not verify"
        same_seq = a["seq"] == c["seq"]
        pa, pc = a["body"].get("prev_admin"), c["body"].get("prev_admin")
        same_prev = a["kind"] in ADMIN_KINDS and c["kind"] in ADMIN_KINDS and pa is not None and pa == pc
        if not (same_seq or same_prev):
            return "the two events do not conflict"
        return None

    def _signers_ok(self, ev: dict, st: dict, need: int, pool: set) -> str | None:
        """author + cosigners: at least `need` distinct valid signatures from `pool` (author must be in the pool)."""
        if ev["author"] not in pool:
            return "author is not allowed to write this kind"
        signed = cosign_input(ev)
        good = {ev["author"]}
        for c in ev.get("cosigs", []):
            m = st["members"].get(c["author"])
            if c["author"] in pool and m and verify_strict(m["sign"], c["sig"], signed):
                good.add(c["author"])
        if len(good) < need:
            return f"needs {need} valid signatures, has {len(good)}"
        return None

    def _transition(self, ev: dict, eid: str, st: dict) -> tuple[dict | None, str | None]:
        kind, b, author = ev["kind"], ev["body"], ev["author"]
        new = copy.deepcopy(st)
        allowed_common = {"prev_admin", "owner_epoch"}
        if kind not in ("owner_transfer", "owner_takeover") and not _eq_int(b.get("owner_epoch"), st["owner_epoch"]):
            return None, "owner_epoch does not match the current owner_epoch"
        aset = self.admin_set(st)
        if kind == "member_add":
            if set(b) - allowed_common - {"agent", "name", "role", "sign", "kex", "admits"} or set(b) < allowed_common | {"agent", "name", "role", "sign", "kex"}:
                return None, "bad member_add body"
            why = self._signers_ok(ev, st, st["admin_threshold"], aset)
            if why:
                return None, why
            rec = {"role": b["role"], "name": b["name"], "sign": b["sign"], "kex": b["kex"]}
            if _member_rec(rec) or b["role"] == "owner":
                return None, "bad member record"
            if not _is_id(b["agent"]) or b["agent"] != agent_id(bytes.fromhex(b["sign"])):
                return None, "agent id does not match its signing key"
            if b["agent"] in st["members"] or b["agent"] in st["removed"]:
                return None, "already a member, or removed (rejoin with a new key)"
            if len(st["members"]) + 1 > st["rules"]["max_members"]:
                return None, "max_members reached"
            ad = b.get("admits", [])
            if not isinstance(ad, list) or len(ad) > 16 or any(not is_hex(x, 32) for x in ad):
                return None, "bad admits"
            new["members"][b["agent"]] = rec
            new["pair"] = _pair(new["members"])
        elif kind in ("member_remove", "revoke"):
            if not (allowed_common | {"agent", "last_seq"} <= set(b) <= allowed_common | {"agent", "last_seq", "missing"}) or not _is_id(b.get("agent")) \
                    or not _int_in(b["last_seq"], -1, 2 ** 31) or not _seq_list(b.get("missing", []), b["last_seq"]):
                return None, f"bad {kind} body (needs agent and last_seq; optional sorted `missing` seqs below it)"
            target = b["agent"]
            if target not in st["members"] or target == st["owner"]:
                return None, "cannot remove that agent"
            if kind == "revoke" and author == target:
                pass                                              # an agent may revoke itself with just its own signature
            elif target in aset:
                # removing an ADMIN: the target's own signature does not count and cannot be required, else an admin who refuses could never
                # be removed; the other admins must still reach k, but never more than all of them
                why = self._signers_ok(ev, st, min(st["admin_threshold"], len(aset) - 1), aset - {target})
                if why:
                    return None, why
            else:
                why = self._signers_ok(ev, st, st["admin_threshold"], aset)
                if why:
                    return None, why
            target_role = st["members"][target]["role"]
            del new["members"][target]
            if st["successors"] and len(self.admin_set(new)) < 2:
                # shrinking the admin set to a lone admin would clear the successors (the owner could then strip the takeover away): it needs
                # acknowledgements from more than half of the non-owner members, like a takeover does (the target does not vote)
                voters = {a for a, m in st["members"].items() if m["role"] in VOTER_ROLES and a != st["owner"] and a != target}
                signed = cosign_input(ev)
                acks = {author} & voters
                for c in ev.get("cosigs", []):
                    if c["author"] in voters and verify_strict(st["members"][c["author"]]["sign"], c["sig"], signed):
                        acks.add(c["author"])
                if len(acks) * 2 <= len(voters):
                    return None, (f"leaving a lone admin while the thread has successors needs acknowledgements from more than half of the "
                                  f"{len(voters)} other non-owner members (has {len(acks)})")
            new["removed"] = sorted(set(st["removed"]) | {target})
            new["epoch"] = st["epoch"] + 1
            new["successors"] = [s for s in st["successors"] if s != target]
            if len(self.admin_set(new)) < new["admin_threshold"]:
                # the last admins must be able to leave or be removed: k comes down with the admin set (a lone admin cannot back a takeover)
                new["admin_threshold"] = max(1, len(self.admin_set(new)))
            if new["admin_threshold"] < 2:
                new["successors"] = []
            if st["pair"] and target_role in ("owner", "admin", "member"):
                new["closed"] = True                              # a two-party thread ends if either party leaves
            new["pair"] = _pair(new["members"])
            new["cut"][target] = b["last_seq"]
            new["cut_missing"][target] = list(b.get("missing", []))
        elif kind == "rules_update":
            if set(b) - allowed_common - {"rules", "guest_policy", "successors", "admin_threshold"} or not ({"rules", "guest_policy", "successors", "admin_threshold"} & set(b)):
                return None, "bad rules_update body"
            why = self._signers_ok(ev, st, st["admin_threshold"], aset)
            if why:
                return None, why
            if "rules" in b:
                why = _check_rules(b["rules"], partial=True)
                if why:
                    return None, why
                new["rules"].update(b["rules"])
            if "guest_policy" in b:
                why = _check_guest_policy(b["guest_policy"], partial=True)
                if why:
                    return None, why
                new["guest_policy"].update(b["guest_policy"])
                if new["guest_policy"]["reserved_reply_slots"] > new["guest_policy"]["queue_max"]:
                    return None, "reserved_reply_slots exceeds queue_max"
            if len(new["members"]) > new["rules"]["max_members"]:
                return None, "max_members below the current member count"
            if "successors" in b:
                s = b["successors"]
                if not isinstance(s, list) or any(not _is_id(x) for x in s) or len(s) != len(set(s)) \
                        or any(st["members"].get(x, {}).get("role") != "member" for x in s):
                    return None, "successors must be distinct plain members (an admin successor could be removed by the owner alone, which would veto a takeover)"
                if s and st["pair"]:
                    return None, "a two-party thread has no successors"
                new["successors"] = list(s)
            if "admin_threshold" in b:
                if not _int_in(b["admin_threshold"], 1, 16) or b["admin_threshold"] > len(self.admin_set(new)):
                    return None, "admin_threshold must be between 1 and the size of the admin set"
                new["admin_threshold"] = b["admin_threshold"]
            if new["successors"] and new["admin_threshold"] < 2:
                return None, "a thread with successors needs admin_threshold k >= 2"
        elif kind == "checkpoint":
            if set(b) != allowed_common | {"count", "heads", "epoch"} or not isinstance(b.get("heads"), list) or not b["heads"] \
                    or len(b["heads"]) > 16 or any(not is_hex(h, 32) for h in b["heads"]):
                return None, "bad checkpoint body"
            if author != st["owner"] or not _eq_int(b["epoch"], st["epoch"]) or not _int_in(b["count"], 0, 2 ** 40):
                return None, "bad checkpoint (owner only, current epoch, sane count)"
            if b["count"] < st["cp_count"]:
                return None, "checkpoint count went backwards"
            new["cp_count"] = b["count"]
            new["last_cp"] = eid
        elif kind == "close":
            c, cm = b.get("cut"), b.get("cut_missing", {})
            if not (allowed_common | {"cut"} <= set(b) <= allowed_common | {"cut", "cut_missing"}) or author != st["owner"] or not isinstance(c, dict) \
                    or len(c) > 256 or any(not _is_id(k) or not _int_in(v, -1, 2 ** 31) for k, v in c.items()) or not isinstance(cm, dict) or len(cm) > 256 \
                    or any(k not in c or not _seq_list(v, c[k]) for k, v in cm.items()):
                return None, "only the owner can close, with a cut {agent: last_seq} (and optional cut_missing {agent: [seqs]})"
            why = self._signers_ok(ev, st, st["admin_threshold"], aset)
            if why:
                return None, why
            new["closed"] = True
            new["closed_cut"] = dict(c)
            new["closed_cut_missing"] = {k: list(v) for k, v in cm.items()}
        elif kind == "owner_transfer":
            if set(b) != allowed_common | {"new_owner"} or not _eq_int(b["owner_epoch"], st["owner_epoch"] + 1) or not _is_id(b["new_owner"]) \
                    or b["new_owner"] not in st["members"]:
                return None, "bad owner_transfer body"
            no = b["new_owner"]
            if no == st["owner"] or st["members"][no]["role"] not in ("admin", "member"):
                return None, "new owner must be another admin or member"
            why = self._signers_ok(ev, st, st["admin_threshold"], aset)
            if why:
                return None, why
            if author != st["owner"]:
                return None, "only the owner transfers ownership"
            if not any(c["author"] == no and verify_strict(st["members"][no]["sign"], c["sig"], cosign_input(ev)) for c in ev.get("cosigs", [])):
                return None, "the new owner must co-sign"
            new["members"][st["owner"]]["role"] = "admin"
            new["members"][no]["role"] = "owner"
            new["owner"], new["owner_epoch"] = no, st["owner_epoch"] + 1
            new["successors"] = [s for s in st["successors"] if s != no]
        elif kind == "owner_takeover":
            return self._takeover(ev, eid, st, new)
        else:
            return None, "unhandled admin kind"
        return new, None

    def _takeover(self, ev: dict, eid: str, st: dict, new: dict) -> tuple[dict | None, str | None]:
        b, author = ev["body"], ev["author"]
        if set(b) != {"prev_admin", "owner_epoch", "last_checkpoint"} or not _eq_int(b["owner_epoch"], st["owner_epoch"] + 1):
            return None, "bad owner_takeover body (owner_epoch must be current + 1)"
        if st["pair"]:
            return None, "a two-party thread has no takeover"
        if author not in st["successors"] or author not in st["members"]:
            return None, "only a listed successor may take over (an earlier successor outranks a later one if both do)"
        if b["last_checkpoint"] != st["last_cp"]:
            return None, "last_checkpoint is not the latest checkpoint (or the genesis if none)"
        _, dstate = self._displaced(b["prev_admin"], st)
        if author not in dstate["members"]:
            return None, "the successor was removed on the branch this takeover would displace"
        voters = {a for a, m in st["members"].items() if m["role"] in VOTER_ROLES and a != st["owner"] and a in dstate["members"]}
        signed = cosign_input(ev)
        acks = {author} & voters
        for c in ev.get("cosigs", []):
            if c["author"] in voters and verify_strict(st["members"][c["author"]]["sign"], c["sig"], signed):
                acks.add(c["author"])
        if len(acks) * 2 <= len(voters):
            return None, f"takeover needs acknowledgements from more than half of the {len(voters)} non-owner members (has {len(acks)})"
        old = st["owner"]
        new["members"][old]["role"] = "member"
        new["members"][author]["role"] = "owner"
        new["owner"], new["owner_epoch"] = author, st["owner_epoch"] + 1
        new["successors"] = [s for s in st["successors"] if s != author]
        # a majority just chose this owner: if the demoted old owner leaves the admin set below k, k comes down with it (never below 1)
        new["admin_threshold"] = max(1, min(st["admin_threshold"], len(self.admin_set(new))))
        if new["admin_threshold"] < 2:
            new["successors"] = []                     # a lone admin cannot back a takeover (k >= 2 is required for successors)
        new["pair"] = _pair(new["members"])
        return new, None

    def missing_seqs(self, author: str) -> list:
        """Gaps in an author's seq numbers (bounded: at most MAX_GAPS reported, and only the first 100000 positions scanned)."""
        seqs = {s for (a, s) in self.by_author_seq if a == author}
        if not seqs:
            return []
        out = []
        for i in range(min(max(seqs), 100000)):
            if i not in seqs:
                out.append(i)
                if len(out) >= MAX_GAPS:
                    break
        return out

    def topo(self, include_void: bool = False) -> list:
        """Event ids, parents before children, ties by (ts, id): the deterministic reading order. Voided events are left out
        unless asked for (they are tombstones: replies to them still name them as parents)."""
        import heapq
        ids = [i for i in self.events if include_void or i not in self.void_ids]
        idset = set(ids)
        indeg = {i: sum(1 for p in self.events[i]["parents"] if p in idset) for i in ids}
        kids: dict[str, list] = {}
        for i in ids:
            for p in self.events[i]["parents"]:
                if p in idset:
                    kids.setdefault(p, []).append(i)
        heap = [(self.events[i]["ts"], i) for i, n in indeg.items() if n == 0]
        heapq.heapify(heap)
        out = []
        while heap:
            _, i = heapq.heappop(heap)
            out.append(i)
            for k in kids.get(i, []):
                indeg[k] -= 1
                if indeg[k] == 0:
                    heapq.heappush(heap, (self.events[k]["ts"], k))
        return out

    def tips(self) -> list:
        """Live events nobody has replied to yet (the natural `parents` for a new event). Voided events are never suggested."""
        seen = {p for e in self.events.values() for p in e["parents"]}
        return sorted(i for i in self.events if i not in seen and i not in self.void_ids)
