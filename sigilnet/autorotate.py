"""Automatic rotation (DESIGN_autorotate.md rev 0 + rev 1; Sansa's review 58025c1e and her two clarifications): the node rotates a thread by itself near the size wall (OWNER side) and follows the
owner's pointer to the new thread by itself (MEMBER side). Both are OPT-IN (`node auto-rotate on`, `node follow-rotation on`, read at node start); nothing here runs a rotation or adds a follow otherwise,
except the VERIFICATION and the EXPIRY of automatic follows that already exist.

OWNER (auto_rotate): a private thread we own, not closed, at 80 % of the wall (`rotate.near_wall`), without a `[ROTATED-TO]` pointer of ours: `rotate_thread` (what the CLI runs), never with `--close`.
ONE attempt, plus ONE retry an hour later when the first failed before the new thread existed (`RotateError` without `partial`); a half-done rotation (the new thread exists) or a crash in the middle
(state "started") is NEVER retried: the owner finishes by hand.

MEMBER (follow_rotation): in a private thread we hold and belong to, the FIRST resolved (not voided) post of the thread's CURRENT OWNER (derived state, not text) that starts with
`[ROTATED-TO] <32 hex>` names the new thread. It is added to the follow list of EVERY peer that follows the old thread (a member with no direct door to the owner must still get it): one pointer counts
once toward the limit of 4 per day. Only the first pointer per old thread is ever acted on. The follow is marked AUTOMATIC in the peer record (`PeerBook.follow_auto`); a hand `peer invite` for the same
thread flips it to manual.
VERIFY (also when the old thread is gone): when the new thread has arrived, its owner must be the old thread's owner AND we must be a member of it, else the automatic follows are removed (the thread's data
stays in the mirror, inert; an invitation by hand is never touched); otherwise they become ordinary invitations. A follow whose thread never arrives expires after 7 days.

PRIVACY: thread ids are kept only in `peers.json` (the follow list) and `rotation.json` (0600, this module's table); the history line carries counts and steps, never an id.
The tick runs at most every ROT_TICK seconds, skips (and tries again soon) while the mirror lock is held, never raises."""
from __future__ import annotations

import os
import re
import time

from .node import _atomic, _load
from .rotate import RotateError, already_rotated, near_wall, rotate_thread

ROT_TICK = float(os.environ.get("SIGILNET_ROT_TICK", 600.0))      # seconds between two rounds (the environment variable is a TEST hook: the real-node tests cannot wait ten minutes)
BUSY_RETRY = 30.0             # the mirror was busy: look again after this
RETRY_AFTER = 3600.0          # one retry of an attempt that failed before the new thread existed
FOLLOW_PER_DAY = 4            # POINTERS acted on per day (one pointer adds the new thread to all N peer records and counts once)
FOLLOW_EXPIRY = 7 * 86400.0   # an automatic follow whose thread never arrived is removed
MAX_RECORDS = 256
POINTER_RE = re.compile(r"\[ROTATED-TO\] ([0-9a-f]{32})")      # rotate.py writes `[ROTATED-TO] <id> "<title>": ...`: only the id is read


def find_pointer(t, owner: str):
    """The id named by the FIRST resolved `[ROTATED-TO]` post of `owner` in thread `t`, or None. (Voided events do not count.)"""
    for i in t.order:
        e = t.events.get(i)
        if e is None or e["kind"] != "post" or e["author"] != owner or i in t.void_ids:
            continue
        m = POINTER_RE.match(str(e["body"].get("text", "")))
        if m:
            return m.group(1)
    return None


class AutoRotator:
    def __init__(self, mirror, me, peers, path, *, clock=time.time, log=None, auto_rotate: bool = False, follow_rotation: bool = False):
        self.m, self.me, self.peers, self.path = mirror, me, peers, path
        self.clock, self.log = clock, log or (lambda *a: None)
        self.auto_rotate, self.follow_rotation = auto_rotate, follow_rotation
        self._next = 0.0
        self.last_error = None                  # optional callable (peer id, thread id) -> the last job error text for a pull of that thread from that peer (noderun wires it)

    # ------------------------------------------------------------ the table (rotation.json)
    def _load(self) -> dict:
        d = _load(self.path)
        for k in ("attempts", "pointers", "days"):
            if not isinstance(d.get(k), dict):
                d[k] = {}
        return d

    def _save(self, d: dict) -> None:
        for k in ("attempts", "pointers"):
            while len(d[k]) > MAX_RECORDS:
                del d[k][next(iter(d[k]))]
        _atomic(self.path, d)

    # ------------------------------------------------------------ the round
    def tick(self, now: float, plan: dict) -> None:
        if now < self._next:
            return
        try:
            if self.m.busy():
                self._next = now + BUSY_RETRY
                return
            self._next = now + ROT_TICK
            self._verify(now)
            if self.follow_rotation:
                self._pointers(now, plan)
            if self.auto_rotate:
                self._owner(now)
        except Exception as e:                                      # noqa: BLE001  (a slow tick must never stop the node)
            self.log(f"auto-rotate: round failed ({type(e).__name__})")

    # ------------------------------------------------------------ owner side
    def _owner(self, now: float) -> None:
        for tid, t in list(self.m.threads.items()):
            st = t.state()
            if st["owner"] != self.me.id or st["visibility"] != "private" or st["closed"] or not near_wall(len(t.stored)) or already_rotated(t, self.me.id):
                continue
            d = self._load()
            a = d["attempts"].get(tid)
            if isinstance(a, dict):
                if a.get("state") != "failed" or int(a.get("tries", 0)) >= 2 or now - float(a.get("at", 0)) < RETRY_AFTER:
                    continue
            tries = int(a.get("tries", 0)) + 1 if isinstance(a, dict) else 1
            d["attempts"][tid] = {"at": now, "tries": tries, "state": "started"}      # written BEFORE the attempt: a crash in the middle is not retried
            self._save(d)
            try:
                rotate_thread(self.m, self.me, tid)
                state = "done"
            except RotateError as e:
                state = "partial" if e.partial else "failed"
            d = self._load()
            d["attempts"][tid] = {"at": now, "tries": tries, "state": state}
            self._save(d)
            self.log("auto-rotate: rotated a thread (all 4 steps)" if state == "done" else f"auto-rotate: a rotation {state} (try {tries}); see `sigilnet list` and finish by hand if it is partial")
            return                                                  # one thread per round: the mirror lock is taken per step, not for long, and the next round continues

    # ------------------------------------------------------------ member side
    def _pointers(self, now: float, plan: dict) -> None:
        day = time.strftime("%Y-%m-%d", time.localtime(now))
        for tid, t in list(self.m.threads.items()):
            st = t.state()
            if st["owner"] == self.me.id or st["visibility"] != "private" or self.me.id not in st["members"]:
                continue
            d = self._load()
            if tid in d["pointers"]:
                continue
            new = find_pointer(t, st["owner"])
            if new is None:
                continue
            if new == tid or new in self.m.threads:                   # nothing to follow (itself, or we already hold it): decided
                d["pointers"][tid] = new
                self._save(d)
                continue
            if int(d["days"].get(day, 0)) >= FOLLOW_PER_DAY:
                self.log("auto-follow: the daily limit of pointers is reached; the rest waits for tomorrow")
                return
            targets = [aid for aid, p in plan.items() if tid in p["threads"]]
            added = self.peers.follow_auto(targets, new, st["owner"], tid, now) if targets else []
            if not added:
                continue                                              # nobody to ask yet (or everybody already has it): not decided, look again next round
            d["pointers"][tid] = new
            d["days"] = {day: int(d["days"].get(day, 0)) + 1}         # (only today is kept)
            self._save(d)
            self.log(f"auto-follow: a rotated thread is now asked for from {len(added)} peer(s)")

    # ------------------------------------------------------------ verification and expiry
    def _verify(self, now: float) -> None:
        by: dict = {}
        who: dict = {}
        for aid, tid, info in self.peers.auto_entries():
            by.setdefault(tid, []).append(info)
            who.setdefault(tid, []).append(aid)
        for tid, infos in by.items():
            owner = infos[0]["owner"]
            t = self.m.threads.get(tid)
            if t is not None:
                st = t.state()
                if st["owner"] == owner and self.me.id in st["members"] and st["visibility"] == "private":
                    self.peers.settle_auto(tid, True)
                    self.log("auto-follow: a rotated thread arrived and was verified")
                else:
                    self.peers.settle_auto(tid, False)
                    self.log("auto-follow: removed a follow (the new thread's owner or our membership did not match)")
            elif now - min(i["at"] for i in infos) > FOLLOW_EXPIRY:
                self.peers.settle_auto(tid, False)
                errs = [str(self.last_error(a, tid) or "") for a in who.get(tid, [])] if self.last_error else []
                if any(e.startswith("thread uses format") for e in errs):
                    self.log("auto-follow: a follow expired (refused: the new thread needs a newer thread format than this software reads; upgrade sigilnet)")
                else:
                    self.log("auto-follow: a follow expired (the thread never arrived)")
