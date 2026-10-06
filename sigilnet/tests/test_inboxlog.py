"""P2 of DESIGN_node_daemon.md: inbox.jsonl (inboxlog.py), the consumer cursors and `requests wait` (wait_guest)."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sigilnet import cursors, inboxlog
from sigilnet.inboxlog import GUEST_GAP, InboxLog, wait_guest

ROOT = str(Path(__file__).resolve().parents[2])


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def lines(home):
    return [json.loads(l) for l in (Path(home) / "inbox.jsonl").read_text().splitlines()]


class Log(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.clock = Clock()
        self.log = InboxLog(self.home, clock=self.clock)

    def test_first_line_is_the_generation_and_entries_are_pointers_only(self):
        gen = self.log.gen
        self.assertEqual(len(gen), 16)
        self.assertEqual(self.log.append("t1"), 1)
        self.assertEqual(self.log.append("t2", guest=True), 2)
        rows = lines(self.home)
        self.assertEqual(rows[0], {"gen": gen})
        self.assertEqual(set(rows[1]), {"seq", "t", "thread"})                  # no sender, kind, id or text
        self.assertEqual(set(rows[2]), {"seq", "t", "thread", "guest"})
        self.assertEqual(self.log.gen, gen)                                       # stable

    def test_file_mode_is_0600_and_seq_is_strictly_increasing(self):
        for i in range(5):
            self.assertEqual(self.log.append(f"t{i}"), i + 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.log.path).st_mode), 0o600)
        self.assertEqual([r["seq"] for r in lines(self.home)[1:]], [1, 2, 3, 4, 5])
        self.assertEqual(self.log.head(), 5)

    def test_empty_or_missing_head_is_zero_and_valid_is_false_until_written(self):
        self.assertEqual(self.log.head(), 0)
        self.assertFalse(self.log.valid())
        self.log.append("t")
        self.assertTrue(self.log.valid())

    def test_guest_lines_collapse_per_thread_inside_the_gap_only(self):
        self.assertEqual(self.log.append("t1", guest=True), 1)
        self.assertIsNone(self.log.append("t1", guest=True))                      # same thread, inside the gap
        self.assertEqual(self.log.append("t2", guest=True), 2)                    # another thread is independent
        self.assertEqual(self.log.append("t1"), 3)                                # a non-guest line is never collapsed
        self.clock.t += GUEST_GAP - 1
        self.assertIsNone(self.log.append("t1", guest=True))
        self.clock.t += 2
        self.assertEqual(self.log.append("t1", guest=True), 4)                    # the gap has passed

    def test_a_guest_line_from_the_future_never_silences_a_wake(self):
        self.log.append("t1", guest=True)
        self.clock.t -= 10 ** 6                                                   # the clock went back
        self.assertEqual(self.log.append("t1", guest=True), 2)

    def test_gap_constant_is_the_one_used(self):
        old = inboxlog.GUEST_GAP
        inboxlog.GUEST_GAP = 5.0
        try:
            self.log.append("t1", guest=True)
            self.clock.t += 6
            self.assertEqual(self.log.append("t1", guest=True), 2)
        finally:
            inboxlog.GUEST_GAP = old

    def test_a_torn_last_line_is_skipped_by_readers_and_cut_by_the_next_writer(self):
        self.log.append("t1")
        with open(self.log.path, "ab") as f:
            f.write(b'{"seq": 2, "t": 1.0, "thr')
        gen, entries = self.log.read_from(None, 0)
        self.assertEqual([e["seq"] for e in entries], [1])
        self.assertEqual(self.log.head(), 1)
        self.assertEqual(self.log.append("t2"), 2)
        rows = lines(self.home)                                                   # every line parses again
        self.assertEqual([r.get("seq") for r in rows], [None, 1, 2])

    def test_a_damaged_first_line_is_invalid_and_gen_makes_a_fresh_file(self):
        self.log.append("t1")
        old = self.log.gen
        Path(self.log.path).write_text("garbage\n" + '{"seq": 1, "t": 1, "thread": "x"}\n')
        self.assertFalse(self.log.valid())
        new = self.log.gen
        self.assertNotEqual(new, old)
        self.assertTrue(self.log.valid())
        self.assertEqual(self.log.head(), 0)

    def test_read_from_returns_only_newer_entries_for_the_same_generation_and_all_for_another(self):
        for i in range(4):
            self.log.append(f"t{i}")
        gen = self.log.gen
        self.assertEqual([e["seq"] for e in self.log.read_from(gen, 2)[1]], [3, 4])
        self.assertEqual([e["seq"] for e in self.log.read_from("other", 2)[1]], [1, 2, 3, 4])
        self.assertEqual([e["seq"] for e in self.log.read_from(None, 4)[1]], [1, 2, 3, 4])
        self.assertEqual(self.log.read_from(gen, 4)[1], [])

    def test_rebuild_gives_a_new_generation_one_line_per_thread_occurrence_and_no_temp_file(self):
        self.log.append("old")
        old = self.log.gen
        g = self.log.rebuild(["b", "a", "b"])
        self.assertNotEqual(g, old)
        self.assertEqual([r["thread"] for r in lines(self.home)[1:]], ["b", "a", "b"])
        self.assertEqual([r["seq"] for r in lines(self.home)[1:]], [1, 2, 3])
        self.assertEqual(stat.S_IMODE(os.stat(self.log.path).st_mode), 0o600)
        self.assertEqual([n for n in os.listdir(self.home) if n != "inbox.jsonl"], [])
        self.assertEqual(self.log.append("c"), 4)                                 # the scan state followed the rebuild

    def test_another_writer_appending_in_between_is_seen_by_the_cached_scan(self):
        other = InboxLog(self.home, clock=self.clock)
        self.log.append("t1")
        other.append("t2")
        self.assertEqual(self.log.append("t3"), 3)

    def test_the_scan_state_moves_with_our_own_append_and_follows_outside_writes(self):
        for i in range(5):
            self.log.append(f"t{i}")
        ino, off, last, guests = self.log._cache
        self.assertEqual(off, os.path.getsize(self.log.path))                      # no rescan needed at the next append
        self.assertEqual(last, 5)
        self.log.append("g", guest=True)
        self.assertIn("g", self.log._cache[3])
        InboxLog(self.home, clock=self.clock).append("outside")                    # another process appends: the cache is stale, the next scan catches up
        self.assertEqual(self.log.append("after"), 8)

    def test_valid_and_gen_read_only_the_head_of_the_file(self):
        for i in range(2000):
            self.log.append(f"thread-{i}")
        self.assertGreater(os.path.getsize(self.log.path), 8192)
        reads = []
        real = open

        def counting_open(path, mode="r", *a, **k):
            f = real(path, mode, *a, **k)
            if str(path) == str(self.log.path) and "r" in mode:
                orig = f.read
                f.read = lambda n=-1: (reads.append(n), orig(n))[1]
            return f
        import builtins
        builtins.open, saved = counting_open, builtins.open
        try:
            self.assertTrue(self.log.valid())
            self.log.gen
        finally:
            builtins.open = saved
        self.assertTrue(reads and all(n == 4096 for n in reads), reads)               # never read(-1)

    def test_a_generation_line_without_a_newline_in_the_head_is_damaged(self):
        Path(self.log.path).write_bytes(b'{"gen": "' + b"a" * 5000)
        self.assertFalse(self.log.valid())

    def test_stamp_changes_when_the_file_changes_and_is_none_when_missing(self):
        self.assertIsNone(self.log.stamp())
        self.log.append("t1")
        a = self.log.stamp()
        self.log.append("t2")
        self.assertNotEqual(a, self.log.stamp())

    def test_wrongly_typed_lines_are_ignored(self):
        self.log.append("t1")
        with open(self.log.path, "ab") as f:
            for bad in ('{"seq": "2", "t": 1, "thread": "x"}', '{"seq": true, "t": 1, "thread": "x"}', '{"seq": 0, "t": 1, "thread": "x"}',
                        '{"seq": 5, "t": "x", "thread": "x"}', '{"seq": 6, "t": 1, "thread": 3}', '[1]', '"x"'):
                f.write(bad.encode() + b"\n")
        self.assertEqual([e["seq"] for e in self.log.read_from(None, 0)[1]], [1])
        self.assertEqual(self.log.append("t2"), 2)

    def test_concurrent_writers_under_a_shared_lock_keep_seq_unique_and_increasing(self):
        code = ("import fcntl, os, sys\nsys.path.insert(0, %r)\nfrom sigilnet.inboxlog import InboxLog\n"
                "home = sys.argv[1]\nfd = os.open(os.path.join(home, 'x.lock'), os.O_CREAT | os.O_RDWR, 0o600)\nlog = InboxLog(home)\n"
                "for i in range(40):\n    fcntl.flock(fd, fcntl.LOCK_EX)\n    log.append('t%%s' %% sys.argv[2])\n    fcntl.flock(fd, fcntl.LOCK_UN)\n") % ROOT
        InboxLog(self.home).append("seed")
        procs = [subprocess.Popen([sys.executable, "-c", code, self.home, str(k)]) for k in range(4)]
        self.assertEqual([p.wait(timeout=120) for p in procs], [0] * 4)
        seqs = [r["seq"] for r in lines(self.home)[1:]]
        self.assertEqual(seqs, list(range(1, 162)))


class Cursors(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()

    def test_missing_is_none_damaged_is_from_zero_and_save_roundtrips(self):
        self.assertIsNone(cursors.load(self.home, "w"))
        cursors.save(self.home, "w", "g1", 7, at=3.5)
        self.assertEqual(cursors.load(self.home, "w"), {"gen": "g1", "seq": 7, "at": 3.5})
        for bad in ("{", "[]", '{"gen": 1, "seq": 1}', '{"gen": "g", "seq": -1}', '{"gen": "g", "seq": true}', '{"gen": "g"}'):
            (Path(self.home) / "cursors" / "w.json").write_text(bad)
            self.assertEqual(cursors.load(self.home, "w"), {"gen": None, "seq": 0}, bad)

    def test_a_cursor_file_that_is_not_utf8_is_damaged_not_a_traceback(self):
        d = Path(self.home) / "cursors"
        d.mkdir()
        for raw in (b"\x00\xff\xfe garbage", b"\xc3\x28", b""):
            (d / "w.json").write_bytes(raw)
            self.assertEqual(cursors.load(self.home, "w"), {"gen": None, "seq": 0}, raw)

    def test_modes_and_no_temp_file_left(self):
        cursors.save(self.home, "w", "g", 1)
        d = Path(self.home) / "cursors"
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(d / "w.json").st_mode), 0o600)
        self.assertEqual(os.listdir(d), ["w.json"])

    def test_consumer_names_are_validated(self):
        for bad in ("", "../x", "a b", "x" * 33, "a/b"):
            with self.assertRaises(ValueError):
                cursors.save(self.home, bad, "g", 1)
            with self.assertRaises(ValueError):
                cursors.load(self.home, bad)

    def test_two_consumers_are_independent(self):
        cursors.save(self.home, "a", "g", 1)
        cursors.save(self.home, "b", "g", 9)
        self.assertEqual(cursors.load(self.home, "a")["seq"], 1)
        self.assertEqual(cursors.load(self.home, "b")["seq"], 9)


class WaitGuest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.clock = Clock()
        self.log = InboxLog(self.home, clock=self.clock)
        self.sleeps = 0

    def sleep(self, s):
        self.sleeps += 1
        self.clock.t += s

    def wait(self, timeout):
        return wait_guest(self.home, timeout, clock=self.clock, sleep=self.sleep)

    def test_times_out_quietly(self):
        self.assertEqual(self.wait(10), [])

    def test_wakes_with_thread_ids_only_and_not_again_for_the_same_lines(self):
        self.log.append("t1", guest=True)
        self.log.append("t2", guest=True)
        self.assertEqual(self.wait(10), ["t1", "t2"])
        self.assertEqual(self.wait(10), [])

    def test_non_guest_lines_do_not_wake_it(self):
        self.log.append("t1")
        self.assertEqual(self.wait(10), [])
        self.log.append("t1", guest=True)
        self.assertEqual(self.wait(10), ["t1"])

    def test_gap_coalesces_a_flood_into_one_later_wake(self):
        self.log.append("t1", guest=True)
        self.assertEqual(self.wait(10), ["t1"])
        self.log.append("t2", guest=True)
        self.assertEqual(self.wait(GUEST_GAP - 40), [])                          # too soon
        self.assertEqual(self.wait(60), ["t2"])                                   # due now, nothing lost

    def test_a_future_time_in_the_cursor_does_not_silence_the_wake(self):
        self.log.append("t1", guest=True)
        gen = self.log.gen
        cursors.save(self.home, "requests", gen, 0, at=self.clock.t + 10 ** 9)
        self.assertEqual(self.wait(10), ["t1"])
        cursors.save(self.home, "requests", gen, 0, at=float("inf"))
        self.assertEqual(self.wait(10), ["t1"])

    def test_a_damaged_cursor_starts_from_zero(self):
        self.log.append("t1", guest=True)
        d = Path(self.home) / "cursors"
        d.mkdir()
        (d / "requests.json").write_text("{{{")
        self.assertEqual(self.wait(10), ["t1"])

    def test_a_new_generation_announces_again_from_zero(self):
        self.log.append("t1", guest=True)
        self.assertEqual(self.wait(10), ["t1"])
        self.log.rebuild(["t9"])
        self.log.append("t9", guest=True)
        self.clock.t += GUEST_GAP + 1
        self.assertEqual(self.wait(10), ["t9"])

    def test_a_binary_cursor_does_not_crash_the_waiter(self):
        self.log.append("t1", guest=True)
        d = Path(self.home) / "cursors"
        d.mkdir()
        (d / "requests.json").write_bytes(b"\x00\xff\xfe garbage")
        self.assertEqual(self.wait(10), ["t1"])

    def test_non_guest_progress_is_remembered(self):
        self.log.append("t1")
        self.wait(1)
        self.assertEqual(cursors.load(self.home, "requests")["seq"], 1)


if __name__ == "__main__":
    unittest.main()
