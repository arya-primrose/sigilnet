"""The Mirror hook (section 13 points 1, 4, 8; section 14): WHEN a line is written, by WHOM, and in which ORDER. The wake rule is the `unread` predicate."""
import fcntl
import json
import os
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import event as E
from sigilnet import inboxlog
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.inboxlog import InboxLog
from sigilnet.mirror import Mirror

from .h import ENTRY_KEYS, Clock, Env, entries, raw_gen


class WhenALineIsWritten(unittest.TestCase):
    def test_a_peer_post_writes_one_line_for_its_thread(self):
        for vis in ("public", "private"):
            env = Env(vis)
            self.assertEqual(env.lines(), [])                                            # genesis (and enable_encryption) write nothing
            env.post("sansa", "hello")
            got = env.lines()
            self.assertEqual([(d["seq"], d["thread"]) for d in got], [(1, env.tid)], vis)
            self.assertTrue(set(got[0]) == {"seq", "t", "thread"}, vis)

    def test_my_own_events_write_no_line(self):
        env = Env("public", me="sansa")
        env.post("sansa", "mine")
        self.assertEqual(env.lines(), [])
        env.post("carol", "theirs")
        self.assertEqual(len(env.lines()), 1)

    def test_fyi_and_done_posts_always_write_a_line_whatever_their_length(self):
        env = Env("public")
        env.post("sansa", "[FYI] progress")
        env.post("sansa", "[DONE] " + "x" * 3000)
        env.post("sansa", "[FYI] nothing to ask, no question, short")
        self.assertEqual(len(env.lines()), 3)

    def test_each_unread_kind_of_event_writes_a_line(self):
        env = Env("public", extra_members=[("dave", "member")])
        env.post("sansa", "p")
        n1 = len(env.lines())
        env.admin("arya", "member_remove", {"agent": env.ids["carol"].id})
        self.assertEqual((n1, len(env.lines())), (1, 2))                                  # a member_remove is in UNREAD_KINDS

    def test_genesis_writes_no_line(self):
        """Derived from the rule ('UNREAD_KINDS' has no genesis, section 5/14): a thread appearing is not a wake by itself. If the design wants one, say so."""
        env = Env("public")
        self.assertEqual(env.lines(), [])

    def test_a_duplicate_ingest_writes_no_second_line(self):
        env = Env("public")
        ev = env.world.w("sansa").post("once")
        env.world.add(ev)
        self.assertEqual(env.m.ingest(ev).status, "accepted")
        self.assertEqual(env.m.ingest(ev).status, "duplicate")
        self.assertEqual(len(env.lines()), 1)

    def test_a_rejected_event_writes_no_line(self):
        env = Env("public")
        ev = E.make_event(env.ids["eve"], thread=env.tid, kind="post", body={"text": "outsider"}, parents=[env.tid], seq=0, admin_ref=env.world.t.head)
        self.assertEqual(env.m.ingest(ev).status, "rejected")
        self.assertEqual(env.lines(), [])

    def test_an_event_that_arrives_voided_writes_no_line(self):
        env = Env("public")
        pre = env.world.w("carol").post("signed before her removal, never seen by the owner")
        rm = env.world.w("arya").admin("member_remove", {"agent": env.ids["carol"].id, "last_seq": -1})
        env.world.add(rm)
        env.m.ingest(rm)
        before = len(env.lines())
        self.assertEqual(env.m.ingest(pre).status, "voided")
        self.assertEqual(len(env.lines()), before)

    def test_an_event_voided_later_keeps_its_line_and_unread_shows_nothing(self):
        """Accepted: 'an occasional empty wake' (section 5). The file is a hint."""
        env = Env("public")
        pre = env.world.w("carol").post("p")
        env.m.ingest(pre)
        self.assertEqual(len(env.lines()), 1)
        rm = env.world.w("arya").admin("member_remove", {"agent": env.ids["carol"].id, "last_seq": -1})
        env.world.add(rm)
        env.m.ingest(rm)
        self.assertEqual(len(env.lines()), 2)                                            # +1 for the removal itself, none removed
        self.assertNotIn(event_id(pre), [event_id(e) for e in env.unread()])

    def test_a_voided_event_that_becomes_live_again_gets_its_line(self):
        """Section 13 point 4: P live -> a removal voids it -> a competing admin event with a LOWER id wins the fork -> P is live and unread again, with no
        fresh event to hang a line on. Without the 'void set changed -> full diff' it shows in `unread` and nobody is told."""
        env = Env("public")
        w = env.world
        P = w.w("carol").post("p")
        A = w.w("arya").admin("member_remove", {"agent": env.ids["carol"].id, "last_seq": -1})
        for ts in range(1, 300):
            B = w.w("arya").add_member(env.ids["dave"], ts=ts)
            if event_id(B) < event_id(A):
                break
        else:
            self.fail("no lower-id competitor found")
        self.assertEqual(env.m.ingest(P).status, "accepted")
        self.assertEqual(env.m.ingest(A).status, "accepted")
        self.assertIn(event_id(P), env.m.threads[env.tid].void_ids)
        n = len(env.lines())
        env.m.ingest(B)
        self.assertNotIn(event_id(P), env.m.threads[env.tid].void_ids)                 # (the scenario itself: revived)
        self.assertIn(event_id(P), [event_id(e) for e in env.m.unread(env.tid, env.ids["hu"].id)])
        self.assertEqual(len(env.lines()), n + 2, "B itself (a member_add) AND P, unread again, each get one line")

    @unittest.skipIf(os.environ.get("ADV12_SKIP_OPEN_FINDINGS") == "1", "open finding P2-3: a READ event that is revived gets a line (the hook ignores the read set)")
    def test_a_read_event_that_is_revived_gets_no_line(self):
        env = Env("public")
        w = env.world
        P = w.w("carol").post("p")
        A = w.w("arya").admin("member_remove", {"agent": env.ids["carol"].id, "last_seq": -1})
        for ts in range(1, 300):
            B = w.w("arya").add_member(env.ids["dave"], ts=ts)
            if event_id(B) < event_id(A):
                break
        env.m.ingest(P); env.m.ingest(A)
        env.m.mark_read(env.tid)                                                          # the agent handled everything so far
        n = len(env.lines())
        env.m.ingest(B)
        self.assertNotIn(event_id(P), [event_id(e) for e in env.m.unread(env.tid, env.ids["hu"].id)])
        new = env.lines()[n:]
        self.assertLessEqual(len(new), 1)                                                 # at most B itself (member_add is unread); NOT a line for P


class WhoWrites(unittest.TestCase):
    def test_a_process_that_only_reads_another_processes_lines_writes_none(self):
        env = Env("public")
        m2 = env.open()                                                                   # a second handle (the CLI next to the node)
        env.post("sansa", "one")
        env.post("carol", "two")
        self.assertEqual(len(env.lines()), 2)
        m2.refresh()                                                                      # picks up both through _refresh
        m2.refresh()
        self.assertEqual(len(m2.unread(env.tid, env.ids["hu"].id)), 2)
        self.assertEqual(len(env.lines()), 2)
        m3 = env.open()                                                                   # a handle opened later loads them from disk
        m3.refresh()
        self.assertEqual(len(env.lines()), 2)

    def test_ingest_through_either_handle_writes_exactly_one_line_each(self):
        env = Env("public")
        m2 = env.open()
        env.post("sansa", "via 1")
        env.post("carol", "via 2", m=m2)                                                  # m2 sees sansa's line first (refresh under the lock), writes its own
        self.assertEqual([d["seq"] for d in env.lines()], [1, 2])

    def test_a_mirror_without_me_and_inbox_writes_nothing_and_says_it_is_off(self):
        env = Env("public")
        m = env.open(with_inbox=False)
        self.assertTrue(m.inbox_off)
        self.assertFalse(env.m.inbox_off)
        ev = env.world.w("sansa").post("offline tool")
        env.world.add(ev)
        self.assertEqual(m.ingest(ev).status, "accepted")
        self.assertEqual(env.lines(), [])

    def test_me_and_inbox_go_together(self):
        env = Env("public")
        with self.assertRaises(ValueError):
            Mirror(env.home / "m2", me=env.ids["hu"].id)
        with self.assertRaises(ValueError):
            Mirror(env.home / "m3", inbox=InboxLog(env.home))
        with self.assertRaises(TypeError):
            Mirror(env.home / "m4", None, 256, time.time, True, None, env.ids["hu"].id, InboxLog(env.home))         # keyword-only


class SkippedThenPersisted(unittest.TestCase):
    def _scenario(self):
        env = Env("private")
        w = env.world
        R = w.w("arya").admin("member_remove", {"agent": env.ids["carol"].id})
        w.add(R)
        rid = event_id(R)
        C = w.w("sansa").post("epoch 1 post, key not here yet")
        w.add(C)
        self.assertEqual(C["admin_ref"], rid)
        self.assertEqual(env.m.ingest(C).status, "pending")                              # the child arrives before the removal that makes its epoch
        return env, rid, C

    def test_the_skipped_event_gets_its_line_when_it_reaches_the_disk_not_before(self):
        env, rid, C = self._scenario()
        r = env.m.ingest(next(e for e in [env.world.t.events[rid]]))
        self.assertTrue(r.ok)
        self.assertGreaterEqual(env.m.skipped.get(env.tid, 0), 1)                          # C is in memory, NOT on disk (no key for epoch 1)
        self.assertEqual(len(env.lines()), 1, "only the removal itself: nothing is on disk for C yet")
        env.codec.ring(env.tid).create(rid)                                                # the epoch key arrives
        D = env.world.w("sansa").post("trigger a persist")
        env.world.add(D)
        env.m.ingest(D)
        self.assertEqual(len(env.lines()), 3, "removal + C (retried) + D")
        texts = sorted(e["body"].get("text") for e in env.open(False).threads[env.tid].events.values() if e["kind"] == "post")
        self.assertEqual(texts, ["epoch 1 post, key not here yet", "trigger a persist"])
        again = env.open()
        again.refresh()
        self.assertEqual(len(env.lines()), 3)                                              # reopening announces nothing again

    def test_the_skipped_event_is_announced_once_even_after_more_persists(self):
        env, rid, C = self._scenario()
        env.m.ingest(env.world.t.events[rid])
        env.codec.ring(env.tid).create(rid)
        for k in range(3):
            D = env.world.w("sansa").post(f"t{k}")
            env.world.add(D)
            env.m.ingest(D)
        self.assertEqual(len(env.lines()), 1 + 1 + 3)


class Order(unittest.TestCase):
    def test_the_line_is_written_before_the_events_append(self):
        env = Env("public")
        seen = []
        real = Mirror._append

        def spy(self_, path, evs, t=None):
            if str(path).endswith("events.jsonl"):
                seen.append(len(entries(env.home)))
            return real(self_, path, evs, t)

        with mock.patch.object(Mirror, "_append", spy):
            env.post("sansa", "x")
        self.assertEqual(seen, [1], "at the moment events.jsonl is appended the line must already be there")

    def test_a_crash_between_the_two_leaves_a_spurious_wake_never_a_lost_one(self):
        env = Env("public")
        real = Mirror._append

        def boom(self_, path, evs, t=None):
            if str(path).endswith("events.jsonl"):
                raise OSError("disk full")
            return real(self_, path, evs, t)

        ev = env.world.w("sansa").post("lost?")
        env.world.add(ev)
        with mock.patch.object(Mirror, "_append", boom):
            with self.assertRaises(OSError):
                env.m.ingest(ev)
        self.assertEqual(len(env.lines()), 1)                                              # told about something that is not on disk: harmless
        self.assertEqual(env.open().threads[env.tid].order, [env.tid])
        m2 = env.open()
        self.assertEqual(m2.ingest(ev).status, "accepted")                                 # the event arrives again later (sync retry): readable, announced again at worst
        self.assertIn(event_id(ev), [event_id(e) for e in env.unread(m2)])
        self.assertGreaterEqual(len(env.lines()), 1)

    def test_the_watcher_can_read_the_line_and_unread_then_shows_the_event(self):
        """Section 13 point 8: the writer holds the Mirror lock for BOTH writes, so a reader that goes through refresh() cannot see the line without the event."""
        env = Env("public")
        m_reader = env.open()
        real = Mirror._append
        started = threading.Event()

        def slow(self_, path, evs, t=None):
            if str(path).endswith("events.jsonl"):
                started.set()
                time.sleep(0.6)                                                           # the window between the line and the event
            return real(self_, path, evs, t)

        ev = env.world.w("sansa").post("race")
        env.world.add(ev)
        got = {}

        def reader():
            started.wait(5)
            t0 = time.time()
            while not entries(env.home) and time.time() - t0 < 5:                         # the 'watcher': sees the line
                time.sleep(0.01)
            got["line"] = len(entries(env.home))
            m_reader.refresh()                                                            # ... and runs `unread` at once
            got["unread"] = [event_id(e) for e in m_reader.unread(env.tid, env.ids["hu"].id)]

        th = threading.Thread(target=reader)
        with mock.patch.object(Mirror, "_append", slow):
            th.start()
            env.m.ingest(ev)
        th.join(10)
        self.assertEqual(got.get("line"), 1)
        self.assertEqual(got.get("unread"), [event_id(ev)])


class NotTheMigrate(unittest.TestCase):
    def test_enabling_encryption_on_a_thread_with_history_writes_no_line(self):
        env = Env("private", encrypt=False)
        for k in range(4):
            env.post("sansa", f"old {k}")
        self.assertEqual(len(env.lines()), 4)
        env.m.enable_encryption(env.tid)                                                  # rewrites EVERY line of events.jsonl as an envelope
        self.assertEqual(len(env.lines()), 4)
        self.assertGreaterEqual(len(env.events_file().read_bytes().splitlines()), 5)


class NoteGuest(unittest.TestCase):
    def test_note_guest_writes_a_guest_line_and_collapses(self):
        clk = Clock()
        env = Env("public", inbox_clock=clk)
        env.m.note_guest(env.tid)
        env.m.note_guest(env.tid)
        env.m.note_guest(env.tid)
        got = env.lines()
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].get("guest") is True and got[0]["thread"] == env.tid)
        clk.t += inboxlog.GUEST_GAP + 1
        env.m.note_guest(env.tid)
        self.assertEqual(len(env.lines()), 2)

    def test_note_guest_takes_the_mirror_lock(self):
        env = Env("public")
        fd = os.open(env.home / "mirror" / "mirror.lock", os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)                                                    # another process is inside the Mirror lock
        th = threading.Thread(target=env.m.note_guest, args=(env.tid,))
        th.start()
        time.sleep(0.4)
        blocked = th.is_alive() and not env.lines()
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        th.join(5)
        self.assertTrue(blocked, "note_guest wrote (or finished) while the Mirror lock was held elsewhere")
        self.assertEqual(len(env.lines()), 1)

    def test_a_mirror_without_inbox_ignores_note_guest(self):
        env = Env("public")
        m = env.open(with_inbox=False)
        m.note_guest(env.tid)
        self.assertEqual(env.lines(), [])

    def test_guest_and_peer_lines_share_one_sequence(self):
        env = Env("public")
        env.post("sansa", "a")
        env.m.note_guest(env.tid)
        env.post("sansa", "b")
        self.assertEqual([(d["seq"], bool(d.get("guest"))) for d in env.lines()], [(1, False), (2, True), (3, False)])


class RebuildAndRotation(unittest.TestCase):
    def test_rebuild_keeps_only_events_still_unread_and_changes_the_generation(self):
        env = Env("public")
        for k in range(5):
            env.post("sansa", f"p{k}")
        env.m.mark_read(env.tid, 3)                                                       # the first 3 events of the order (genesis + 2 posts) are handled
        old = raw_gen(env.home)
        new = env.m.rebuild_inbox()
        self.assertNotEqual(new, old)
        self.assertEqual(raw_gen(env.home), new)
        un = env.m.unread(env.tid, env.ids["hu"].id)
        got = env.lines()
        self.assertEqual(len(got), len(un))
        self.assertEqual([d["seq"] for d in got], list(range(1, len(un) + 1)))
        self.assertEqual({d["thread"] for d in got}, {env.tid})
        env.m.mark_read(env.tid)
        env.m.rebuild_inbox()
        self.assertEqual(env.lines(), [])

    def test_rebuild_does_not_resurrect_my_own_or_voided_events(self):
        env = Env("public", me="sansa")
        env.post("sansa", "mine")
        env.post("carol", "theirs")
        env.m.rebuild_inbox()
        self.assertEqual(len(env.lines()), 1)

    def test_a_damaged_file_at_open_is_rebuilt_from_the_events(self):
        env = Env("public")
        env.post("sansa", "a"); env.post("carol", "b")
        old = raw_gen(env.home)
        (env.home / "inbox.jsonl").write_bytes(b"\x00garbage")
        m2 = env.open()                                                                   # 'when the file is missing/damaged at open'
        m2.refresh()
        gen = raw_gen(env.home)
        self.assertNotEqual(gen, old)
        self.assertEqual(len(env.lines()), 2)                                              # replayed under the wake rule

    def test_rotation_when_the_file_passes_max_bytes(self):
        with mock.patch.object(inboxlog, "MAX_BYTES", 1500):
            env = Env("public")
            for k in range(8):
                env.post("sansa", f"old {k}")
            env.m.mark_read(env.tid)                                                      # all handled: they must not survive a rotation
            first_gen = raw_gen(env.home)
            for k in range(40):
                env.post("carol", f"new {k}")
            un = env.m.unread(env.tid, env.ids["hu"].id)
            self.assertEqual(len(un), 40)
            self.assertNotEqual(raw_gen(env.home), first_gen, "the file passed MAX_BYTES and was never rebuilt")
            self.assertEqual(len(env.lines()), 40, "after rotation only the events still unread have a line")
            self.assertLess((env.home / "inbox.jsonl").stat().st_size, 3 * 1500)


if __name__ == "__main__":
    unittest.main()
