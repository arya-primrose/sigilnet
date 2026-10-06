"""P2: the Mirror writes a wake line (inbox.jsonl) exactly for the events `unread` would show, before it appends them to events.jsonl."""
import fcntl
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import inboxlog, mirror as MM
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import PlainCodec
from sigilnet.event import event_id
from sigilnet.inboxlog import InboxLog
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror


def rows(home):
    p = Path(home) / "inbox.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()][1:] if p.exists() else []


class Hook(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.me, self.other = Identity.generate("arya"), Identity.generate("sansa")
        g = make_genesis(self.me, "t", [(self.other, "member")], visibility="private")
        self.tid = event_id(g)
        self.m = Mirror(self.home + "/mirror", rate_limit=False, me=self.me.id, inbox=InboxLog(self.home))
        self.assertEqual(self.m.ingest(g).status, "accepted")
        self.t = self.m.threads[self.tid]

    def post(self, who, text="hi"):
        ev = Writer(who, self.t).post(text)
        r = self.m.ingest(ev)
        self.assertTrue(r.ok, r.reason)
        return event_id(ev)

    def test_genesis_writes_no_line(self):
        self.assertEqual(rows(self.home), [])

    def test_a_post_by_someone_else_writes_one_pointer_line(self):
        self.post(self.other)
        r = rows(self.home)
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["thread"], self.tid)
        self.assertEqual(set(r[0]), {"seq", "t", "thread"})

    def test_my_own_post_writes_no_line(self):
        self.post(self.me)
        self.assertEqual(rows(self.home), [])

    def test_fyi_and_done_posts_are_never_silent(self):
        self.post(self.other, "[FYI] short")
        self.post(self.other, "[DONE] " + "x" * 5000)
        self.assertEqual(len(rows(self.home)), 2)

    def test_a_kind_unread_does_not_count_writes_no_line(self):
        with mock.patch.object(MM, "UNREAD_KINDS", frozenset({"close"})):
            self.post(self.other)
        self.assertEqual(rows(self.home), [])

    def test_no_event_id_kind_or_author_anywhere_in_the_file(self):
        eid = self.post(self.other, "secret text")
        raw = (Path(self.home) / "inbox.jsonl").read_text()
        for needle in (eid, self.other.id, self.me.id, "secret", "post", "member"):
            self.assertNotIn(needle, raw)

    def test_the_line_is_written_before_the_event_reaches_events_jsonl(self):
        order = []
        real_append, real_ia = Mirror._append, Mirror._inbox_append
        Mirror._append = lambda s, path, evs, t=None: (order.append(("events", Path(path).name)), real_append(s, path, evs, t))[1]
        Mirror._inbox_append = lambda s, tid, guest=False: (order.append(("inbox", tid)), real_ia(s, tid, guest))[1]
        try:
            self.post(self.other)
        finally:
            Mirror._append, Mirror._inbox_append = real_append, real_ia
        self.assertEqual([k for k, _ in order], ["inbox", "events"])

    def test_a_crash_between_the_line_and_the_append_leaves_a_spurious_wake_never_a_lost_one(self):
        ev = Writer(self.other, self.t).post("x")
        with mock.patch.object(Mirror, "_append", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                self.m.ingest(ev)
        self.assertEqual(len(rows(self.home)), 1)                                 # woken for an event that is not on disk

    def test_a_process_that_only_reads_another_processs_lines_writes_none(self):
        self.post(self.other)
        self.post(self.other)
        n = len(rows(self.home))
        reader = Mirror(self.home + "/mirror", rate_limit=False, me=self.me.id, inbox=InboxLog(self.home))
        self.assertTrue(reader.refresh() in (True, False))
        self.assertEqual(len(rows(self.home)), n)

    def test_replayed_duplicate_event_writes_no_second_line(self):
        ev = Writer(self.other, self.t).post("x")
        self.m.ingest(ev)
        self.assertEqual(self.m.ingest(ev).status, "duplicate")
        self.assertEqual(len(rows(self.home)), 1)

    def test_a_revived_event_gets_its_line_when_the_void_set_shrinks(self):
        eid = self.post(self.other)
        n = len(rows(self.home))
        t = self.t
        void_before = {eid}
        t.void_ids = set()                                                         # it was voided before this event and is live now
        self.m._persist(t, set(t.awaiting), void_before)
        self.assertEqual(len(rows(self.home)), n + 1)

    def test_a_revived_event_that_is_also_fresh_gets_exactly_one_line(self):
        eid = self.post(self.other)
        n = len(rows(self.home))
        self.m.persisted[self.tid].discard(eid)                                     # not on disk yet: it is "fresh" now, and also in the revived set
        self.t.void_ids = set()
        self.m._persist(self.t, set(self.t.awaiting), {eid})
        self.assertEqual(len(rows(self.home)), n + 1)                               # one line, not two

    def test_a_read_event_that_is_revived_gets_no_line(self):
        eid = self.post(self.other)
        self.m.mark_read(self.tid)
        n = len(rows(self.home))
        self.t.void_ids = set()
        self.m._persist(self.t, set(self.t.awaiting), {eid})                         # revived, but the reader had read it
        self.assertEqual(len(rows(self.home)), n)

    def test_a_newly_voided_event_does_not_write_a_line(self):
        eid = self.post(self.other)
        n = len(rows(self.home))
        self.t.void_ids = {eid}
        self.m._persist(self.t, set(self.t.awaiting), set())
        self.assertEqual(len(rows(self.home)), n)

    def test_a_fresh_event_that_is_already_void_writes_no_line(self):
        eid = self.post(self.other)
        n = len(rows(self.home))
        self.m.persisted[self.tid].discard(eid)                                     # fresh again ...
        self.t.void_ids = {eid}                                                      # ... but voided
        self.m._persist(self.t, set(self.t.awaiting), {eid})
        self.assertEqual(len(rows(self.home)), n)

    def test_the_void_diff_is_not_computed_per_fresh_event(self):
        calls = []
        real = Mirror._wake_kind
        Mirror._wake_kind = lambda s, t, i: (calls.append(i), real(s, t, i))[1]
        try:
            for _ in range(5):
                self.post(self.other)
        finally:
            Mirror._wake_kind = real
        self.assertEqual(len(calls), 5)                                            # exactly the fresh ids: O(1) per event

    def test_me_and_inbox_go_together(self):
        with self.assertRaises(ValueError):
            Mirror(tempfile.mkdtemp(), me="x")
        with self.assertRaises(ValueError):
            Mirror(tempfile.mkdtemp(), inbox=InboxLog(tempfile.mkdtemp()))

    def test_a_mirror_without_them_is_marked_off_and_writes_nothing(self):
        h = tempfile.mkdtemp()
        m = Mirror(h + "/mirror", rate_limit=False)
        self.assertTrue(m.inbox_off)
        self.assertFalse(self.m.inbox_off)
        g = make_genesis(self.me, "t2", [(self.other, "member")])
        m.ingest(g)
        m.ingest(Writer(self.other, m.threads[event_id(g)]).post("x"))
        self.assertFalse((Path(h) / "inbox.jsonl").exists())


class SkippedThenPersisted(unittest.TestCase):
    def test_an_event_without_its_key_gets_its_line_when_it_reaches_the_disk(self):
        from sigilnet.thread import Thread

        class Codec(PlainCodec):
            def __init__(self):
                self.block, self.open, self.calls = None, False, {}

            def can_encode(self, t, ev):                                              # True when the event is ingested, False when it is persisted (its epoch key is missing) until opened
                eid = event_id(ev)
                n = self.calls[eid] = self.calls.get(eid, 0) + 1
                return not (eid == self.block and n >= 2 and not self.open)
        codec = Codec()
        home = tempfile.mkdtemp()
        me, other = Identity.generate("arya"), Identity.generate("sansa")
        g = make_genesis(me, "t", [(other, "member")], visibility="private")
        tid = event_id(g)
        m = Mirror(home + "/mirror", rate_limit=False, codec=codec, me=me.id, inbox=InboxLog(home))
        m.ingest(g)
        a = Writer(other, m.threads[tid]).post("A")
        scratch = Thread(g)
        scratch.accept(a)
        b = Writer(other, scratch).post("B")                                           # a child of A
        codec.block = event_id(b)
        self.assertEqual(m.ingest(b).status, "pending")                                # parked: its parent is missing
        self.assertTrue(m.ingest(a).ok)                                                # A resolves both; B cannot be written yet
        self.assertEqual(len(rows(home)), 1)                                           # only A has its line
        self.assertEqual(m.skipped.get(tid), 1)
        codec.open = True
        m.ingest(Writer(other, m.threads[tid]).post("C"))
        self.assertEqual(len(rows(home)), 3)                                           # B (now persisted) and C: each exactly once


class GuestAndLock(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.m = Mirror(self.home + "/mirror", me="me", inbox=InboxLog(self.home))

    def test_note_guest_writes_a_guest_line_collapsed_per_thread(self):
        self.m.note_guest("t1")
        self.m.note_guest("t1")
        self.m.note_guest("t2")
        r = rows(self.home)
        self.assertEqual([(x["thread"], x.get("guest")) for x in r], [("t1", True), ("t2", True)])

    def test_note_guest_without_an_inbox_is_a_noop(self):
        m = Mirror(tempfile.mkdtemp())
        m.note_guest("t1")

    def test_note_guest_takes_the_mirror_lock(self):
        fd = os.open(self.home + "/mirror/mirror.lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        done = []
        t = threading.Thread(target=lambda: (self.m.note_guest("t1"), done.append(time.time())))
        t0 = time.time()
        t.start()
        time.sleep(0.3)
        self.assertEqual(done, [])                                                  # blocked on the lock
        os.close(fd)
        t.join(timeout=10)
        self.assertEqual(len(done), 1)
        self.assertGreaterEqual(done[0] - t0, 0.3)


class RebuildAndRotation(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.me, self.other = Identity.generate("arya"), Identity.generate("sansa")
        g = make_genesis(self.me, "t", [(self.other, "member")], visibility="private")
        self.tid = event_id(g)
        self.m = Mirror(self.home + "/mirror", rate_limit=False, me=self.me.id, inbox=InboxLog(self.home))
        self.m.ingest(g)
        self.t = self.m.threads[self.tid]

    def post(self, n):
        for i in range(n):
            self.m.ingest(Writer(self.other, self.t).post(f"p{i}"))

    def reopen(self):
        return Mirror(self.home + "/mirror", rate_limit=False, me=self.me.id, inbox=InboxLog(self.home))

    def test_a_missing_file_is_rebuilt_at_open_with_one_line_per_unread_event(self):
        self.post(3)
        os.unlink(self.home + "/inbox.jsonl")
        m2 = self.reopen()
        self.assertEqual(len(rows(self.home)), 3)
        self.assertEqual(m2.unread(self.tid, self.me.id).__len__(), 3)

    def test_a_damaged_file_is_rebuilt_with_a_new_generation(self):
        self.post(2)
        gen = InboxLog(self.home).gen
        Path(self.home, "inbox.jsonl").write_text("junk\n")
        self.reopen()
        self.assertNotEqual(InboxLog(self.home).gen, gen)
        self.assertEqual(len(rows(self.home)), 2)

    def test_a_rebuild_keeps_only_still_unread_events(self):
        self.post(3)
        self.m.mark_read(self.tid)
        self.post(1)
        self.assertEqual(self.m.rebuild_inbox().__len__(), 16)
        self.assertEqual(len(rows(self.home)), 1)

    def test_a_valid_file_is_not_rebuilt_at_open(self):
        self.post(2)
        gen = InboxLog(self.home).gen
        self.reopen()
        self.assertEqual(InboxLog(self.home).gen, gen)

    def test_rotation_rebuilds_when_the_file_passes_max_bytes(self):
        old = inboxlog.MAX_BYTES
        inboxlog.MAX_BYTES = 600
        try:
            self.post(1)
            gen = InboxLog(self.home).gen
            self.m.mark_read(self.tid)
            self.post(12)
        finally:
            inboxlog.MAX_BYTES = old
        self.assertNotEqual(InboxLog(self.home).gen, gen)
        self.assertEqual(len(rows(self.home)), 12)                                  # only the still-unread ones survived
        self.assertLess(os.path.getsize(self.home + "/inbox.jsonl"), 3 * 600)


class OneFactory(unittest.TestCase):
    def test_home_open_mirror_is_the_only_production_site_that_builds_a_mirror(self):
        import re
        pkg = Path(__file__).resolve().parents[1]
        sites = []
        for f in sorted(pkg.glob("*.py")):
            for n, line in enumerate(f.read_text().splitlines(), 1):
                if re.search(r"\bMirror\(", line) and not line.lstrip().startswith("class Mirror"):
                    sites.append(f"{f.name}:{n}")
        self.assertEqual(sites, [s for s in sites if s.startswith("home.py:")])
        self.assertEqual(len(sites), 1, sites)


if __name__ == "__main__":
    unittest.main()
