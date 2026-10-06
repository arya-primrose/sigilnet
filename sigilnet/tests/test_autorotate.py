"""Automatic rotation (autorotate.py, DESIGN_autorotate.md rev 0 + 1; Sansa's review 58025c1e): the owner's trigger, the member's follow of the owner's pointer, verification, expiry, the
PeerBook marks, the config switches, the privacy rule (no thread id in any log line this module writes)."""
import contextlib
import fcntl
import io
import json
import os
import shutil
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import autorotate as AR, cli, noderun, rotate as R
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.home import open_mirror
from sigilnet.keys import Identity
from sigilnet.node import Node, PeerBook

T0 = 1_800_000_000.0                      # a fixed "now" (2027-01-15, midday UTC: the same calendar day in every time zone near it)
DAY = 86400.0


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write("" if isinstance(e.code, int) or e.code is None else str(e.code))
    return rc, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ids = {n: Identity.generate(n) for n in ("arya", "sansa", "hu", "dave")}
        self.logs: list = []

    def mirror(self, who="arya", name=None):
        return open_mirror(self.tmp / (name or who), self.ids[who].id, poke=False)

    def thread(self, m, *, owner="arya", members=(("sansa", "member"), ("hu", "observer")), encrypt=False, title="coordination", **kw):
        g = make_genesis(self.ids[owner], title, [(self.ids[n], r) for n, r in members], **kw)
        self.assertTrue(m.ingest(g).ok)
        tid = event_id(g)
        if encrypt:
            m.enable_encryption(tid, self.ids[owner])
        return tid

    def copy(self, src, dst, tid):
        """What a sync does: every stored event of one thread into another mirror."""
        for e in list(src.threads[tid].stored.values()):
            dst.ingest(e, live=False)

    def rot(self, m, who, peers=None, **flags):
        peers = peers or PeerBook(self.tmp / f"peers_{who}.json")
        return AR.AutoRotator(m, self.ids[who], peers, self.tmp / f"rotation_{who}.json", log=lambda *a: self.logs.append(" ".join(map(str, a))), **flags), peers

    def book_with(self, who, names):
        peers = PeerBook(self.tmp / f"peers_{who}.json")
        for n in names:
            peers.add(self.ids[n].id, n, None, [])
        return peers

    def plan(self, peers, tids_by_name):
        recs = peers.all()
        return {self.ids[n].id: {"rec": recs[self.ids[n].id], "threads": set(tids)} for n, tids in tids_by_name.items()}

    def rotated_pair(self, encrypt=False):
        """Arya's mirror with a rotated thread, and Sansa's mirror holding the OLD thread with its pointer. -> (ma, ms, old, new)"""
        ma, ms = self.mirror("arya"), self.mirror("sansa")
        tid = self.thread(ma, encrypt=encrypt)
        res = R.rotate_thread(ma, self.ids["arya"], tid)
        self.copy(ma, ms, tid)
        return ma, ms, tid, res["new"]


class Pointer(Base):
    def test_the_first_resolved_pointer_of_the_owner(self):
        ma, ms, tid, new = self.rotated_pair()
        self.assertEqual(AR.find_pointer(ms.threads[tid], self.ids["arya"].id), new)

    def test_a_pointer_by_somebody_else_is_not_one(self):
        ma, ms = self.mirror("arya"), self.mirror("sansa")
        tid = self.thread(ma)
        self.copy(ma, ms, tid)
        self.assertTrue(ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("hello")).ok)
        self.copy(ma, ms, tid)
        self.assertTrue(ms.ingest(Writer(self.ids["sansa"], ms.threads[tid]).post("[ROTATED-TO] " + "a" * 32)).ok)
        self.assertIsNone(AR.find_pointer(ms.threads[tid], self.ids["arya"].id))

    def test_only_the_exact_shape_counts(self):
        ma = self.mirror("arya")
        tid = self.thread(ma)
        w = lambda text: ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post(text))        # noqa: E731
        for bad in ("see [ROTATED-TO] " + "a" * 32, "[ROTATED-TO] " + "A" * 32, "[ROTATED-TO] " + "a" * 31, "[ROTATED-TO]" + "a" * 32, "[rotated-to] " + "a" * 32, "[ROTATED-TO] zz" + "a" * 30):
            self.assertTrue(w(bad).ok)
            self.assertIsNone(AR.find_pointer(ma.threads[tid], self.ids["arya"].id), bad)
        self.assertTrue(w("[ROTATED-TO] " + "b" * 32 + ' "title": more').ok)
        self.assertEqual(AR.find_pointer(ma.threads[tid], self.ids["arya"].id), "b" * 32)

    def test_the_first_pointer_wins(self):
        ma = self.mirror("arya")
        tid = self.thread(ma)
        for c in "cd":
            self.assertTrue(ma.insert if False else ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("[ROTATED-TO] " + c * 32)).ok)
        self.assertEqual(AR.find_pointer(ma.threads[tid], self.ids["arya"].id), "c" * 32)

    def test_a_voided_pointer_does_not_count(self):
        ma, ms, tid, new = self.rotated_pair()
        t = ms.threads[tid]
        pid = next(i for i in t.order if t.events[i]["kind"] == "post" and t.events[i]["body"]["text"].startswith("[ROTATED-TO]"))
        t.void_ids = set(t.void_ids) | {pid}
        self.assertIsNone(AR.find_pointer(t, self.ids["arya"].id))


class OwnerSide(Base):
    WALL = 6                                          # a thread of at least this many events counts as "near the wall" here (a rotated thread starts with 2, so it never does)

    def near(self):
        return mock.patch.object(AR, "near_wall", lambda n: n >= self.WALL)

    def big(self, m, who="arya", **kw):
        tid = self.thread(m, owner=who, **kw)
        for i in range(self.WALL):
            self.assertTrue(m.ingest(Writer(self.ids[who], m.threads[tid]).post(f"p{i}")).ok)
        return tid

    def test_off_by_default(self):
        m = self.mirror()
        self.big(m)
        r, _ = self.rot(m, "arya")
        with self.near():
            r.tick(T0, {})
        self.assertEqual(len(m.threads), 1)
        self.assertFalse((self.tmp / "rotation_arya.json").exists())

    def test_rotates_once_near_the_wall(self):
        m = self.mirror()
        tid = self.big(m, encrypt=True)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        with self.near():
            r.tick(T0, {})
            self.assertEqual(len(m.threads), 2)
            new = next(i for i in m.threads if i != tid)
            self.assertIsNotNone(R.already_rotated(m.threads[tid], self.ids["arya"].id))
            self.assertTrue(m.codec.is_encrypted(new))
            self.assertFalse(m.threads[tid].state()["closed"])                                   # never --close
            r.tick(T0 + AR.ROT_TICK + 1, {})
            r.tick(T0 + 3 * AR.ROT_TICK, {})
        self.assertEqual(len(m.threads), 2)                                                      # one rotation, however often it ticks
        d = json.loads((self.tmp / "rotation_arya.json").read_text())
        self.assertEqual(d["attempts"][tid]["state"], "done")
        self.assertEqual(len(self.logs), 1)

    def test_below_the_wall_nothing_happens(self):
        m = self.mirror()
        self.big(m)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        r.tick(T0, {})
        self.assertEqual(len(m.threads), 1)

    def test_not_the_owner_public_or_closed(self):
        ma, ms = self.mirror("arya"), self.mirror("sansa")
        tid = self.big(ma)
        self.copy(ma, ms, tid)
        rs, _ = self.rot(ms, "sansa", auto_rotate=True)
        pub = self.mirror("dave")
        self.big(pub, who="dave", members=(), visibility="public")
        rd, _ = self.rot(pub, "dave", auto_rotate=True)
        closed = self.mirror("hu")
        ct = self.big(closed, who="hu", members=())
        self.assertTrue(closed.ingest(Writer(self.ids["hu"], closed.threads[ct]).admin("close", {})).ok)
        rh, _ = self.rot(closed, "hu", auto_rotate=True)
        with self.near():
            for r in (rs, rd, rh):
                r.tick(T0, {})
        self.assertEqual((len(ms.threads), len(pub.threads), len(closed.threads)), (1, 1, 1))
        for who in ("sansa", "dave", "hu"):                                                      # not even an attempt was made (rotate_thread would have refused each: the table would say "failed")
            self.assertFalse((self.tmp / f"rotation_{who}.json").exists(), who)

    def test_a_thread_rotated_by_hand_is_left_alone(self):
        m = self.mirror()
        tid = self.big(m)
        R.rotate_thread(m, self.ids["arya"], tid)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        with self.near():
            r.tick(T0, {})
        self.assertEqual(len(m.threads), 2)
        self.assertFalse((self.tmp / "rotation_arya.json").exists())                             # no attempt was made

    def test_ticks_inside_the_interval_do_nothing(self):
        m = self.mirror()
        self.thread(m)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        with mock.patch.object(r, "_verify") as v:
            r.tick(T0, {})
            r.tick(T0 + 1, {})
            r.tick(T0 + AR.ROT_TICK - 1, {})
            self.assertEqual(v.call_count, 1)
            r.tick(T0 + AR.ROT_TICK + 1, {})
            self.assertEqual(v.call_count, 2)

    def test_a_failure_before_the_new_thread_exists_is_retried_once_after_an_hour(self):
        m = self.mirror()
        tid = self.big(m)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        calls = []

        def boom(*a, **k):
            calls.append(1)
            raise R.RotateError("no")
        with self.near(), mock.patch.object(AR, "rotate_thread", boom):
            r.tick(T0, {})
            self.assertEqual(len(calls), 1)
            r.tick(T0 + AR.ROT_TICK + 1, {})                                                     # 10 minutes later: not yet
            self.assertEqual(len(calls), 1)
            r.tick(T0 + AR.RETRY_AFTER + 1, {})                                                  # an hour later: the one retry
            self.assertEqual(len(calls), 2)
            r.tick(T0 + 5 * AR.RETRY_AFTER, {})
            r.tick(T0 + 9 * AR.RETRY_AFTER, {})
            self.assertEqual(len(calls), 2)                                                      # and never again
        self.assertEqual(json.loads((self.tmp / "rotation_arya.json").read_text())["attempts"][tid]["state"], "failed")

    def test_a_retry_that_works_ends_it(self):
        m = self.mirror()
        self.big(m)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        real = AR.rotate_thread
        calls = []

        def flaky(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise R.RotateError("no")
            return real(*a, **k)
        with self.near(), mock.patch.object(AR, "rotate_thread", flaky):
            r.tick(T0, {})
            r.tick(T0 + AR.RETRY_AFTER + 1, {})
            r.tick(T0 + 3 * AR.RETRY_AFTER, {})
        self.assertEqual((len(calls), len(m.threads)), (2, 2))

    def test_a_half_done_rotation_is_never_retried(self):
        m = self.mirror()
        tid = self.big(m)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        calls = []

        def half(*a, **k):
            calls.append(1)
            raise R.RotateError("pointer refused", {"new": "f" * 32})
        with self.near(), mock.patch.object(AR, "rotate_thread", half):
            r.tick(T0, {})
            r.tick(T0 + 9 * AR.RETRY_AFTER, {})
            r.tick(T0 + 99 * AR.RETRY_AFTER, {})
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads((self.tmp / "rotation_arya.json").read_text())["attempts"][tid]["state"], "partial")
        self.assertIn("partial", self.logs[-1])

    def test_a_crash_in_the_middle_is_not_retried(self):
        m = self.mirror()
        tid = self.big(m)
        (self.tmp / "rotation_arya.json").write_text(json.dumps({"attempts": {tid: {"at": T0 - 10 * DAY, "tries": 1, "state": "started"}}}))     # what a killed node leaves behind
        r, _ = self.rot(m, "arya", auto_rotate=True)
        with self.near():
            r.tick(T0, {})
        self.assertEqual(len(m.threads), 1)

    def test_the_attempt_is_written_before_it_is_made(self):
        m = self.mirror()
        tid = self.big(m)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        seen = []

        def look(*a, **k):
            seen.append(json.loads((self.tmp / "rotation_arya.json").read_text())["attempts"][tid]["state"])
            raise R.RotateError("x")
        with self.near(), mock.patch.object(AR, "rotate_thread", look):
            r.tick(T0, {})
        self.assertEqual(seen, ["started"])

    def test_one_thread_per_round(self):
        m = self.mirror()
        t1 = self.big(m)
        g = make_genesis(self.ids["arya"], "second", [(self.ids["sansa"], "member")])
        self.assertTrue(m.ingest(g).ok)
        t2 = event_id(g)
        for i in range(self.WALL):
            self.assertTrue(m.ingest(Writer(self.ids["arya"], m.threads[t2]).post(f"q{i}")).ok)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        with self.near():
            r.tick(T0, {})
            self.assertEqual(len(m.threads), 3)
            r.tick(T0 + AR.ROT_TICK + 1, {})
        self.assertEqual(len(m.threads), 4)

    def test_the_round_waits_for_nobody_a_busy_mirror_is_skipped(self):
        m = self.mirror()
        self.big(m)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        fd = os.open(m.lockf, os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            with self.near():
                t0 = time.time()
                r.tick(T0, {})
                self.assertLess(time.time() - t0, 1.0)
                self.assertEqual(len(m.threads), 1)
                r.tick(T0 + 1, {})                                                               # still inside the short retry wait: not even a look
                self.assertEqual(len(m.threads), 1)
        finally:
            os.close(fd)
        with self.near():
            r.tick(T0 + AR.BUSY_RETRY + 1, {})                                                   # free again: it goes on after the SHORT wait, not after ten minutes
        self.assertEqual(len(m.threads), 2)

    def test_a_round_never_raises(self):
        m = self.mirror()
        self.big(m)
        r, _ = self.rot(m, "arya", auto_rotate=True, follow_rotation=True)
        with mock.patch.object(r, "_verify", side_effect=RuntimeError("boom")):
            r.tick(T0, {})
        self.assertIn("round failed (RuntimeError)", self.logs[-1])

    def test_mirror_busy_is_a_try_lock(self):
        m = self.mirror()
        self.assertFalse(m.busy())
        with m._lock():
            self.assertTrue(m.busy())
        self.assertFalse(m.busy())


class MemberSide(Base):
    def setUp(self):
        super().setUp()
        self.ma, self.ms, self.old, self.new = self.rotated_pair()
        self.sid, self.aid = self.ids["sansa"].id, self.ids["arya"].id

    def sansa(self, names=("arya", "hu", "dave"), **flags):
        r, peers = self.rot(self.ms, "sansa", **flags)
        for n in names:
            peers.add(self.ids[n].id, n, None, [])
        return r, peers

    def test_off_by_default(self):
        r, peers = self.sansa()
        r.tick(T0, self.plan(peers, {"arya": {self.old}}))
        self.assertEqual(peers.all()[self.aid]["threads"], [])

    def test_every_peer_that_follows_the_old_thread_is_asked_not_only_the_owner(self):
        r, peers = self.sansa(follow_rotation=True)
        r.tick(T0, self.plan(peers, {"arya": {self.old}, "hu": {self.old}, "dave": set()}))      # dave does not follow the old thread
        recs = peers.all()
        self.assertEqual(recs[self.aid]["threads"], [self.new])
        self.assertEqual(recs[self.ids["hu"].id]["threads"], [self.new])
        self.assertEqual(recs[self.ids["dave"].id]["threads"], [])
        self.assertEqual(sorted(a for a, t, i in peers.auto_entries()), sorted([self.aid, self.ids["hu"].id]))
        self.assertEqual(self.logs, ["auto-follow: a rotated thread is now asked for from 2 peer(s)"])

    def test_the_owner_node_itself_does_not_follow(self):
        r, peers = self.rot(self.ma, "arya", follow_rotation=True)
        peers.add(self.sid, "sansa", None, [])
        r.tick(T0, self.plan(peers, {"sansa": {self.old}}))
        self.assertEqual(peers.all()[self.sid]["threads"], [])

    def test_a_pointer_by_a_member_who_is_not_the_owner_is_ignored(self):
        ma, ms = self.mirror("arya", "a2"), self.mirror("sansa", "s2")
        tid = self.thread(ma)
        self.copy(ma, ms, tid)
        self.assertTrue(ms.ingest(Writer(self.ids["sansa"], ms.threads[tid]).post("[ROTATED-TO] " + "e" * 32)).ok)
        r, peers = self.rot(ms, "sansa", follow_rotation=True)
        peers.add(self.aid, "arya", None, [])
        r.tick(T0, self.plan(peers, {"arya": {tid}}))
        self.assertEqual(peers.all()[self.aid]["threads"], [])

    def test_a_second_pointer_is_not_acted_on(self):
        r, peers = self.sansa(follow_rotation=True)
        plan = self.plan(peers, {"arya": {self.old}})
        r.tick(T0, plan)
        self.assertTrue(self.ma.ingest(Writer(self.ids["arya"], self.ma.threads[self.old]).post("[ROTATED-TO] " + "9" * 32)).ok)
        self.copy(self.ma, self.ms, self.old)
        r.tick(T0 + AR.ROT_TICK + 1, plan)
        self.assertEqual(peers.all()[self.aid]["threads"], [self.new])

    def test_a_public_old_thread_is_never_followed(self):
        ma, ms = self.mirror("arya", "a3"), self.mirror("sansa", "s3")
        tid = self.thread(ma, members=(), visibility="public")
        self.assertTrue(ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("[ROTATED-TO] " + "7" * 32)).ok)
        self.copy(ma, ms, tid)
        r, peers = self.rot(ms, "sansa", follow_rotation=True)
        peers.add(self.aid, "arya", None, [])
        r.tick(T0, self.plan(peers, {"arya": {tid}}))
        self.assertEqual(peers.all()[self.aid]["threads"], [])

    def test_a_public_thread_even_with_us_as_a_member_is_not_followed(self):
        ma, ms = self.mirror("arya", "a4"), self.mirror("sansa", "s4")
        tid = self.thread(ma, members=(("sansa", "member"),), visibility="public")
        self.assertTrue(ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("[ROTATED-TO] " + "7" * 32)).ok)
        self.copy(ma, ms, tid)
        self.assertIn(self.sid, ms.threads[tid].state()["members"])
        r, peers = self.rot(ms, "sansa", follow_rotation=True)
        peers.add(self.aid, "arya", None, [])
        r.tick(T0, self.plan(peers, {"arya": {tid}}))
        self.assertEqual(peers.all()[self.aid]["threads"], [])

    def test_a_member_who_was_removed_does_not_follow(self):
        ma, ms = self.mirror("arya", "a5"), self.mirror("sansa", "s5")
        tid = self.thread(ma, members=(("sansa", "member"), ("dave", "member"), ("hu", "observer")), title="removal")
        self.assertTrue(ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).admin("member_remove", {"agent": self.sid})).ok)
        self.assertTrue(ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("[ROTATED-TO] " + "8" * 32)).ok)
        self.copy(ma, ms, tid)
        self.assertNotIn(self.sid, ms.threads[tid].state()["members"])
        r, peers = self.rot(ms, "sansa", follow_rotation=True)
        peers.add(self.aid, "arya", None, [])
        r.tick(T0, self.plan(peers, {"arya": {tid}}))
        self.assertEqual(peers.all()[self.aid]["threads"], [])

    def test_the_owner_node_does_not_act_on_its_own_pointer_even_without_the_new_thread(self):
        ma = self.mirror("arya", "a6")
        tid = self.thread(ma, title="mine")
        self.assertTrue(ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("[ROTATED-TO] " + "6" * 32)).ok)
        r, peers = self.rot(ma, "arya", follow_rotation=True)
        peers.add(self.sid, "sansa", None, [])
        r.tick(T0, self.plan(peers, {"sansa": {tid}}))
        self.assertEqual(peers.auto_entries(), [])

    def test_a_pointer_counts_once_however_many_peers_it_asks(self):
        peers = PeerBook(self.tmp / "peers_many.json")
        for n in ("arya", "hu", "dave"):
            peers.add(self.ids[n].id, n, None, [])
        ma, ms = self.mirror("arya", "ma_m"), self.mirror("sansa", "ms_m")
        olds = []
        for i in range(4):
            tid = self.thread(ma, title=f"many {i}")
            R.rotate_thread(ma, self.ids["arya"], tid)
            self.copy(ma, ms, tid)
            olds.append(tid)
        r = AR.AutoRotator(ms, self.ids["sansa"], peers, self.tmp / "rotation_many.json", log=lambda *a: None, follow_rotation=True)
        r.tick(T0, self.plan(peers, {n: set(olds) for n in ("arya", "hu", "dave")}))
        self.assertEqual(len(peers.auto_entries()), 12)                                          # 4 pointers x 3 peers: all four fit in the day's limit of 4

    def test_a_thread_we_already_hold_is_not_followed_but_the_pointer_is_decided(self):
        self.copy(self.ma, self.ms, self.new)
        r, peers = self.sansa(follow_rotation=True)
        r.tick(T0, self.plan(peers, {"arya": {self.old}}))
        self.assertEqual(peers.all()[self.aid]["threads"], [])
        self.assertEqual(json.loads((self.tmp / "rotation_sansa.json").read_text())["pointers"], {self.old: self.new})

    def test_nobody_to_ask_is_not_decided_and_is_tried_again(self):
        r, peers = self.sansa(follow_rotation=True)
        r.tick(T0, self.plan(peers, {"arya": set()}))
        self.assertEqual(peers.auto_entries(), [])
        r.tick(T0 + AR.ROT_TICK + 1, self.plan(peers, {"arya": {self.old}}))
        self.assertEqual(len(peers.auto_entries()), 1)

    def test_four_pointers_a_day(self):
        peers = PeerBook(self.tmp / "peers_s.json")
        peers.add(self.aid, "arya", None, [])
        ma, ms = self.mirror("arya", "ma_all"), self.mirror("sansa", "ms_all")
        olds = []
        for i in range(5):
            tid = self.thread(ma, title=f"thread {i}")
            R.rotate_thread(ma, self.ids["arya"], tid)
            self.copy(ma, ms, tid)
            olds.append(tid)
        r = AR.AutoRotator(ms, self.ids["sansa"], peers, self.tmp / "rotation_s.json", log=lambda *a: self.logs.append(" ".join(map(str, a))), follow_rotation=True)
        plan = self.plan(peers, {"arya": set(olds)})
        r.tick(T0, plan)
        self.assertEqual(len(peers.auto_entries()), 4)                                           # the fifth waits
        self.assertTrue(any("daily limit" in l for l in self.logs))
        r.tick(T0 + 2 * DAY, plan)
        self.assertEqual(len(peers.auto_entries()), 5)

    def test_a_peer_invited_by_hand_stays_manual(self):
        r, peers = self.sansa(follow_rotation=True)
        peers.invite(self.aid, [self.new])
        r.tick(T0, self.plan(peers, {"arya": {self.old}, "hu": {self.old}}))
        self.assertEqual([a for a, t, i in peers.auto_entries()], [self.ids["hu"].id])           # only hu got an automatic follow

    def test_a_hand_invitation_after_the_automatic_one_flips_it(self):
        r, peers = self.sansa(follow_rotation=True)
        r.tick(T0, self.plan(peers, {"arya": {self.old}}))
        self.assertEqual(len(peers.auto_entries()), 1)
        self.assertTrue(peers.invite(self.aid, [self.new]))                                      # a change: it is manual now
        self.assertEqual(peers.auto_entries(), [])
        self.assertFalse(peers.invite(self.aid, [self.new]))                                     # (and a repeat is a no-op)
        self.assertEqual(peers.settle_auto(self.new, False), 0)                                  # nothing automatic is left to remove
        self.assertEqual(peers.all()[self.aid]["threads"], [self.new])


class Verify(Base):
    def setUp(self):
        super().setUp()
        self.ma, self.ms, self.old, self.new = self.rotated_pair()
        self.aid, self.hid = self.ids["arya"].id, self.ids["hu"].id
        self.r, self.peers = self.rot(self.ms, "sansa", follow_rotation=True)
        for n in ("arya", "hu"):
            self.peers.add(self.ids[n].id, n, None, [])
        self.r.tick(T0, self.plan(self.peers, {"arya": {self.old}, "hu": {self.old}}))
        self.assertEqual(len(self.peers.auto_entries()), 2)
        self.logs.clear()

    def test_the_new_thread_arrives_with_the_right_owner_and_us_in_it_the_follows_become_ordinary(self):
        self.copy(self.ma, self.ms, self.new)
        self.r.tick(T0 + AR.ROT_TICK + 1, {})
        self.assertEqual(self.peers.auto_entries(), [])
        self.assertEqual([self.peers.all()[a]["threads"] for a in (self.aid, self.hid)], [[self.new], [self.new]])
        self.assertEqual(self.logs, ["auto-follow: a rotated thread arrived and was verified"])
        self.assertTrue(json.loads((self.tmp / "peers_sansa.json").read_text())["peers"][self.aid].get("auto") is None)

    def test_the_owner_of_the_new_thread_is_somebody_else_the_automatic_follows_go(self):
        other = self.mirror("dave", "d")
        g = make_genesis(self.ids["dave"], "not what the pointer said", [(self.ids["sansa"], "member")])
        self.assertTrue(other.ingest(g).ok)
        bad = event_id(g)
        self.peers.settle_auto(self.new, False)
        self.peers.follow_auto([self.aid], bad, self.aid, self.old, T0)
        self.copy(other, self.ms, bad)
        self.logs.clear()
        self.r.tick(T0 + 2 * AR.ROT_TICK, {})
        self.assertEqual(self.peers.auto_entries(), [])
        self.assertEqual(self.peers.all()[self.aid]["threads"], [])
        self.assertTrue(any("did not match" in l for l in self.logs))

    def test_a_removed_follow_is_not_made_again_next_round(self):
        ma, ms = self.mirror("arya", "a7"), self.mirror("sansa", "s7")
        tid = self.thread(ma, title="lure")
        other = self.mirror("dave", "d7")
        g = make_genesis(self.ids["dave"], "not the owner's", [(self.ids["sansa"], "member")])
        self.assertTrue(other.ingest(g).ok)
        bad = event_id(g)
        self.assertTrue(ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("[ROTATED-TO] " + bad)).ok)       # the owner's pointer names a thread somebody else made
        self.copy(ma, ms, tid)
        peers = PeerBook(self.tmp / "peers_lure.json")
        peers.add(self.aid, "arya", None, [])
        r = AR.AutoRotator(ms, self.ids["sansa"], peers, self.tmp / "rotation_lure.json", log=lambda *a: self.logs.append(" ".join(map(str, a))), follow_rotation=True)
        plan = self.plan(peers, {"arya": {tid}})
        r.tick(T0, plan)
        self.assertEqual(len(peers.auto_entries()), 1)
        self.copy(other, ms, bad)                                                                # it arrives (a peer served it)
        r.tick(T0 + AR.ROT_TICK + 1, plan)
        self.assertEqual((peers.auto_entries(), peers.all()[self.aid]["threads"]), ([], []))
        for k in range(1, 4):
            r.tick(T0 + k * 2 * AR.ROT_TICK, plan)                                               # and it stays removed: the pointer was decided once
        self.assertEqual((peers.auto_entries(), peers.all()[self.aid]["threads"]), ([], []))
        self.assertEqual(sum("is now asked for" in l for l in self.logs), 1)

    def test_we_are_not_a_member_of_the_new_thread(self):
        other = self.mirror("arya", "a9")
        g = make_genesis(self.ids["arya"], "no sansa here", [(self.ids["hu"], "observer")])
        self.assertTrue(other.ingest(g).ok)
        nom = event_id(g)
        self.peers.settle_auto(self.new, False)
        self.peers.follow_auto([self.aid], nom, self.aid, self.old, T0)
        self.copy(other, self.ms, nom)
        self.r.tick(T0 + 2 * AR.ROT_TICK, {})
        self.assertEqual(self.peers.auto_entries(), [])
        self.assertEqual(self.peers.all()[self.aid]["threads"], [])

    def test_a_hand_invitation_is_never_removed_by_a_failed_verification(self):
        other = self.mirror("dave", "d2")
        g = make_genesis(self.ids["dave"], "wrong owner", [(self.ids["sansa"], "member")])
        self.assertTrue(other.ingest(g).ok)
        bad = event_id(g)
        self.peers.follow_auto([self.aid], bad, self.aid, self.old, T0)
        self.peers.invite(self.hid, [bad])                                                       # by hand for hu
        self.copy(other, self.ms, bad)
        self.r.tick(T0 + 2 * AR.ROT_TICK, {})
        self.assertIn(bad, self.peers.all()[self.hid]["threads"])
        self.assertNotIn(bad, self.peers.all()[self.aid]["threads"])

    def test_it_also_verifies_when_the_old_thread_is_gone_from_the_mirror(self):
        fresh = self.mirror("sansa", "s_fresh")                                                  # a mirror that never held the old thread
        self.copy(self.ma, fresh, self.new)
        r, _ = self.rot(fresh, "sansa", follow_rotation=True, peers=self.peers)
        r.tick(T0 + AR.ROT_TICK + 1, {})
        self.assertEqual(self.peers.auto_entries(), [])
        self.assertEqual(self.peers.all()[self.aid]["threads"], [self.new])

    def test_an_unresolved_follow_expires_after_seven_days_and_not_before(self):
        self.r.tick(T0 + 7 * DAY - 1000, {})
        self.assertEqual(len(self.peers.auto_entries()), 2)
        self.r.tick(T0 + 7 * DAY + 10, {})
        self.assertEqual(self.peers.auto_entries(), [])
        self.assertEqual(self.peers.all()[self.aid]["threads"], [])
        self.assertEqual(self.logs, ["auto-follow: a follow expired (the thread never arrived)"])

    def test_an_expired_follow_is_not_made_again(self):
        plan = self.plan(self.peers, {"arya": {self.old}, "hu": {self.old}})
        self.r.tick(T0 + 7 * DAY + 10, plan)
        self.assertEqual(self.peers.auto_entries(), [])
        for k in range(1, 4):
            self.r.tick(T0 + 7 * DAY + 10 + k * 2 * AR.ROT_TICK, plan)                          # the pointer was decided once: it is not acted on again
        self.assertEqual((self.peers.auto_entries(), self.peers.all()[self.aid]["threads"]), ([], []))

    def test_the_expiry_counts_from_the_oldest_follow_of_a_thread(self):
        self.peers.settle_auto(self.new, False)
        dave = self.ids["dave"].id
        self.peers.add(dave, "dave", None, [])
        self.peers.follow_auto([self.aid], self.new, self.aid, self.old, T0)                    # the oldest, at T0
        self.peers.follow_auto([dave], self.new, self.aid, self.old, T0 + 6.5 * DAY)             # a younger one of the same thread
        self.r.tick(T0 + 7 * DAY + 10, {})
        self.assertEqual(self.peers.auto_entries(), [])

    def test_the_expiry_does_not_touch_a_follow_made_by_hand(self):
        self.peers.invite(self.aid, [self.new])
        self.r.tick(T0 + 8 * DAY, {})
        self.assertEqual(self.peers.all()[self.aid]["threads"], [self.new])
        self.assertEqual(self.peers.all()[self.hid]["threads"], [])

    def test_verification_runs_with_both_switches_off(self):
        self.copy(self.ma, self.ms, self.new)
        r, _ = self.rot(self.ms, "sansa", peers=self.peers)
        r.tick(T0 + 2 * AR.ROT_TICK, {})
        self.assertEqual(self.peers.auto_entries(), [])


class Table(Base):
    def test_rotation_json_is_private_and_a_damaged_one_is_an_empty_table(self):
        m = self.mirror()
        self.thread(m)
        r, _ = self.rot(m, "arya", auto_rotate=True)
        with mock.patch.object(AR, "near_wall", lambda n: n == 1):
            r.tick(T0, {})
        p = self.tmp / "rotation_arya.json"
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        p.write_text("{not json")
        self.assertEqual(r._load(), {"attempts": {}, "pointers": {}, "days": {}})
        p.write_text(json.dumps({"attempts": [], "pointers": "x", "days": 5}))
        self.assertEqual(r._load(), {"attempts": {}, "pointers": {}, "days": {}})

    def test_the_table_is_bounded(self):
        m = self.mirror()
        r, _ = self.rot(m, "arya")
        d = {"attempts": {f"{i:032x}": {} for i in range(AR.MAX_RECORDS + 50)}, "pointers": {f"{i:032x}": "a" * 32 for i in range(AR.MAX_RECORDS + 50)}, "days": {}}
        r._save(d)
        got = json.loads((self.tmp / "rotation_arya.json").read_text())
        self.assertEqual((len(got["attempts"]), len(got["pointers"])), (AR.MAX_RECORDS, AR.MAX_RECORDS))


class Privacy(Base):
    def ids_in(self, text, *tids):
        return [t for t in tids if t in text or t[:8] in text]

    def test_no_log_line_carries_a_thread_id(self):
        ma, ms, old, new = self.rotated_pair()
        peers = PeerBook(self.tmp / "peers_sansa.json")
        peers.add(self.ids["arya"].id, "arya", {"type": "onion", "addr": "a" * 56 + ".onion:47200"}, [])
        node = Node(ms, self.ids["sansa"], peers, self.tmp / "node_sansa.json", lambda rec: None, clock=lambda: T0, log=lambda *a: None)             # (the node's own lines name threads today, per job: not what is checked here)
        node.rot = AR.AutoRotator(ms, self.ids["sansa"], peers, self.tmp / "rotation_sansa.json", clock=lambda: T0, log=lambda *a: self.logs.append(" ".join(map(str, a))), follow_rotation=True)
        peers.invite(self.ids["arya"].id, [old])
        node.tick()
        self.assertTrue(peers.auto_entries())                                                    # it did follow
        # the owner side too
        mo = self.mirror("arya", "owner2")
        t = self.thread(mo, title="the owner's own thread")
        for i in range(6):
            self.assertTrue(mo.ingest(Writer(self.ids["arya"], mo.threads[t]).post(f"p{i}")).ok)
        ro = AR.AutoRotator(mo, self.ids["arya"], PeerBook(self.tmp / "peers_o.json"), self.tmp / "rotation_o.json", log=lambda *a: self.logs.append(" ".join(map(str, a))), auto_rotate=True)
        with mock.patch.object(AR, "near_wall", lambda n: n >= 6):
            ro.tick(T0, {})
        self.assertEqual(len(mo.threads), 2)
        self.assertTrue(self.logs)
        # (node.json's job keys and the pull lines of history.log name threads TODAY, for every thread: not something this module adds; what it adds is the log lines below and two files of its own)
        self.assertEqual(self.ids_in("\n".join(self.logs), old, new, t), [])
        self.assertEqual(sorted(p.name for p in self.tmp.glob("*.json") if p.name.startswith("rotation")), ["rotation_o.json", "rotation_sansa.json"])
        # (the ids ARE in the follow list and in rotation.json, which is where they belong)
        self.assertIn(new, (self.tmp / "peers_sansa.json").read_text())
        self.assertIn(old, (self.tmp / "rotation_sansa.json").read_text() + (self.tmp / "peers_sansa.json").read_text())


class NodeHook(Base):
    def test_tick_calls_the_rotator_with_the_plan(self):
        m = self.mirror("sansa")
        peers = PeerBook(self.tmp / "p.json")
        peers.add(self.ids["arya"].id, "arya", {"type": "onion", "addr": "a" * 56 + ".onion:47200"}, [])
        node = Node(m, self.ids["sansa"], peers, self.tmp / "n.json", lambda rec: None, clock=lambda: T0, log=lambda *a: None)
        seen = []
        node.rot = mock.Mock(tick=lambda now, plan: seen.append((now, sorted(plan))))
        node.tick()
        self.assertEqual(seen, [(T0, [self.ids["arya"].id])])

    def test_a_node_without_a_rotator_ticks_as_before(self):
        m = self.mirror("sansa")
        node = Node(m, self.ids["sansa"], PeerBook(self.tmp / "p.json"), self.tmp / "n.json", lambda rec: None, clock=lambda: T0)
        self.assertIsNone(node.rot)
        node.tick()


class PeerBookMarks(Base):
    def setUp(self):
        super().setUp()
        self.book = PeerBook(self.tmp / "p.json")
        self.a, self.h = self.ids["arya"].id, self.ids["hu"].id
        self.book.add(self.a, "arya", {"type": "onion", "addr": "a" * 56 + ".onion:47200"}, ["1" * 32])
        self.book.add(self.h, "hu", None, [])

    def test_follow_auto_marks_and_changes_nothing_else(self):
        done = self.book.follow_auto([self.a, self.h, "z" * 32], "2" * 32, self.a, "1" * 32, T0)
        self.assertEqual(sorted(done), sorted([self.a, self.h]))                                 # (an unknown agent is skipped)
        rec = self.book.all()[self.a]
        self.assertEqual((rec["threads"], rec["name"], rec["endpoint"]), (sorted(["1" * 32, "2" * 32]), "arya", {"type": "onion", "addr": "a" * 56 + ".onion:47200"}))
        self.assertEqual({t: i["owner"] for a, t, i in self.book.auto_entries() if a == self.a}, {"2" * 32: self.a})
        self.assertEqual(self.book.follow_auto([self.a], "2" * 32, self.a, "1" * 32, T0), [])    # again: nothing

    def test_a_thread_already_followed_by_hand_is_not_marked(self):
        self.assertEqual(self.book.follow_auto([self.a], "1" * 32, self.a, "0" * 32, T0), [])
        self.assertEqual(self.book.auto_entries(), [])

    def test_settle_keep_and_remove(self):
        self.book.follow_auto([self.a, self.h], "2" * 32, self.a, "1" * 32, T0)
        self.assertEqual(self.book.settle_auto("2" * 32, True), 2)
        self.assertEqual((self.book.auto_entries(), self.book.all()[self.a]["threads"]), ([], sorted(["1" * 32, "2" * 32])))
        self.book.follow_auto([self.h], "3" * 32, self.a, "1" * 32, T0)
        self.assertEqual(self.book.settle_auto("3" * 32, False), 1)
        self.assertEqual(self.book.all()[self.h]["threads"], ["2" * 32])                         # (the kept one stays, the removed one is gone)
        self.assertEqual(self.book.settle_auto("4" * 32, False), 0)

    def test_the_64_invitation_limit_holds(self):
        self.book.invite(self.h, ["%032x" % i for i in range(64)])
        self.assertEqual(self.book.follow_auto([self.h], "f" * 32, self.a, "1" * 32, T0), [])

    def test_a_manual_add_replaces_the_record_and_its_marks(self):
        self.book.follow_auto([self.a], "2" * 32, self.a, "1" * 32, T0)
        self.book.add(self.a, "arya", None, ["2" * 32])
        self.assertEqual(self.book.auto_entries(), [])

    def test_junk_in_the_marks_is_ignored(self):
        raw = json.loads((self.tmp / "p.json").read_text())
        raw["peers"][self.a]["auto"] = {"nothex": {"owner": "x"}, "2" * 32: "str", "3" * 32: {"owner": 5}, "4" * 32: {"owner": self.a, "at": "x"}}
        (self.tmp / "p.json").write_text(json.dumps(raw))
        self.assertEqual([(t, i["at"]) for a, t, i in self.book.auto_entries()], [("4" * 32, 0.0)])


class Config(Base):
    def test_defaults_and_validation(self):
        home = self.tmp / "h"
        home.mkdir()
        self.assertEqual((noderun.load_config(home)["auto_rotate"], noderun.load_config(home)["follow_rotation"]), (False, False))
        (home / "node_config.json").write_text(json.dumps({"auto_rotate": True, "follow_rotation": False}))
        cfg = noderun.load_config(home)
        self.assertEqual((cfg["auto_rotate"], cfg["follow_rotation"]), (True, False))
        for bad in ("yes", 1, None, []):
            (home / "node_config.json").write_text(json.dumps({"auto_rotate": bad}))
            with self.assertRaisesRegex(ValueError, "auto_rotate must be true or false"):
                noderun.load_config(home)

    def test_the_cli_switches(self):
        home = self.tmp / "h2"
        rc, out, err = run_cli("--home", str(home), "init", "arya", "--carrier", "tcp", "--bind", "127.0.0.2", "--tcp-port-base", "47000")
        self.assertEqual(rc, 0, err)
        for action, key in (("auto-rotate", "auto_rotate"), ("follow-rotation", "follow_rotation")):
            rc, out, err = run_cli("--home", str(home), "node", action)
            self.assertEqual((rc, out.strip()), (0, f"{key}: off"))
            rc, out, err = run_cli("--home", str(home), "node", action, "on")
            self.assertEqual(rc, 0, err)
            self.assertIn(f"{key} set to on", out)
            rc, out, err = run_cli("--home", str(home), "node", action)
            self.assertEqual(out.strip(), f"{key}: on")
            rc, out, err = run_cli("--home", str(home), "node", action, "off")
            self.assertEqual(rc, 0, err)
            self.assertEqual(noderun.load_config(home / ".sigilnet" if (home / ".sigilnet").is_dir() else home)[key], False)
        for args in (("auto-rotate", "maybe"), ("follow-rotation", "on", "off")):
            rc, out, err = run_cli("--home", str(home), "node", *args)
            self.assertNotEqual(rc, 0)
            self.assertIn("[on|off]", err)
        cfgp = (home / ".sigilnet" / "node_config.json") if (home / ".sigilnet").is_dir() else (home / "node_config.json")
        self.assertEqual(stat.S_IMODE(cfgp.stat().st_mode), 0o600)


class Golden(Base):
    def test_the_rotate_output_bytes_are_unchanged(self):
        """The pointer and the first post of the new thread keep their exact text (the design keeps rotate.py's bytes)."""
        m = self.mirror()
        tid = self.thread(m)
        t = m.threads[tid]
        n, head = len(t.stored), t.head
        res = R.rotate_thread(m, self.ids["arya"], tid)
        nt, ot = m.threads[res["new"]], m.threads[tid]
        first = [nt.events[i]["body"]["text"] for i in nt.order if nt.events[i]["kind"] == "post"]
        self.assertEqual(first, [f"[ROTATED-FROM] {tid} {head} {n}"])
        ptr = [ot.events[i]["body"]["text"] for i in ot.order if ot.events[i]["kind"] == "post"][-1]
        self.assertEqual(ptr, (f"[ROTATED-TO] {res['new']} \"coordination (2)\": this thread continues there (nothing was deleted). It nears the {R.MAX_STORED}-event wall. "
                               f"A node pulls only threads it was told about: on every other node run `sigilnet peer invite {self.ids['arya'].id} --thread {res['new']}` "
                               f"(the owner's id; your peer book may name the owner differently), then post in the new thread."))


if __name__ == "__main__":
    unittest.main()
