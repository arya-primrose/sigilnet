"""InboxLog (section 14) on its own: format, seq, generation, torn/damaged files, the guest collapse, no leaks. Mutation targets are named in the docstrings."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import inboxlog
from sigilnet.inboxlog import InboxLog

from .h import ENTRY_KEYS, Clock, Env, entries, raw_gen, run_authors

T1 = "a" * 32
T2 = "b" * 32


def fresh(clock=None):
    home = Path(tempfile.mkdtemp(prefix="adv12_il_"))
    return home, InboxLog(home, **({"clock": clock} if clock else {}))


class Basics(unittest.TestCase):
    def test_empty_log(self):
        home, log = fresh()
        self.assertEqual(log.head(), 0)
        self.assertRegex(log.gen, r"^[0-9a-f]{16}$")
        self.assertEqual(log.read_from(None, 0), (log.gen, []))

    def test_file_shape_and_mode(self):
        home, log = fresh(Clock())
        self.assertEqual(log.append(T1), 1)
        p = home / "inbox.jsonl"
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        lines = p.read_bytes().split(b"\n")
        self.assertEqual(json.loads(lines[0]), {"gen": log.gen})                        # the FIRST line is the generation
        self.assertEqual(set(json.loads(lines[1])), {"seq", "t", "thread"})            # a normal line has exactly these keys
        self.assertEqual(lines[2:], [b""])
        self.assertEqual(log.path, p)

    def test_seq_strictly_increasing_and_head(self):
        home, log = fresh(Clock())
        got = [log.append(T1 if i % 2 else T2) for i in range(7)]
        self.assertEqual(got, [1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(log.head(), 7)
        self.assertEqual([d["seq"] for d in entries(home)], got)

    def test_a_second_object_continues_the_sequence(self):
        home, log = fresh(Clock())
        log.append(T1); log.append(T1)
        other = InboxLog(home)
        self.assertEqual(other.append(T2), 3)
        self.assertEqual(other.gen, log.gen)

    def test_guest_line_has_the_guest_key_and_nothing_else_extra(self):
        home, log = fresh(Clock())
        log.append(T1, guest=True)
        d = entries(home)[0]
        self.assertEqual(set(d), {"seq", "t", "thread", "guest"})
        self.assertIs(d["guest"], True)

    def test_time_comes_from_the_clock(self):
        clk = Clock(1234.5)
        home, log = fresh(clk)
        log.append(T1)
        self.assertEqual(entries(home)[0]["t"], 1234.5)

    def test_read_from(self):
        home, log = fresh(Clock())
        for _ in range(5):
            log.append(T1)
        gen = log.gen
        g, got = log.read_from(gen, 2)
        self.assertEqual((g, [d["seq"] for d in got]), (gen, [3, 4, 5]))
        self.assertEqual(log.read_from(gen, 5), (gen, []))
        self.assertEqual(log.read_from(gen, 99), (gen, []))
        g, got = log.read_from("0" * 16, 4)                                          # an unknown generation: EVERYTHING, from 0
        self.assertEqual((g, [d["seq"] for d in got]), (gen, [1, 2, 3, 4, 5]))
        g, got = log.read_from(None, 4)
        self.assertEqual([d["seq"] for d in got], [1, 2, 3, 4, 5])


class DamagedFiles(unittest.TestCase):
    def test_torn_last_line_is_skipped_and_the_sequence_goes_on(self):
        home, log = fresh(Clock())
        log.append(T1); log.append(T1)
        with open(home / "inbox.jsonl", "ab") as f:
            f.write(b'{"seq": 3, "t": 1.0, "thr')                                    # a writer died mid-line (no newline)
        g, got = log.read_from(log.gen, 0)
        self.assertEqual([d["seq"] for d in got], [1, 2])
        self.assertEqual(log.head(), 2)
        self.assertEqual(log.append(T2), 3)
        self.assertEqual([d["seq"] for d in entries(home)], [1, 2, 3])
        self.assertEqual([d["seq"] for d in log.read_from(log.gen, 0)[1]], [1, 2, 3])

    def test_a_garbage_line_in_the_middle_does_not_stop_the_reader(self):
        home, log = fresh(Clock())
        log.append(T1)
        with open(home / "inbox.jsonl", "ab") as f:
            f.write(b"not json at all\n")
        log.append(T1)
        self.assertEqual([d["seq"] for d in log.read_from(log.gen, 0)[1]], [1, 2])

    def test_a_damaged_generation_line_makes_a_new_generation(self):
        home, log = fresh(Clock())
        log.append(T1)
        old = log.gen
        (home / "inbox.jsonl").write_bytes(b"\x00\xffgarbage\n")
        new = log.gen
        self.assertRegex(new, r"^[0-9a-f]{16}$")
        self.assertNotEqual(new, old)
        self.assertEqual(raw_gen(home), new)                                           # and the file on disk is valid again
        self.assertEqual(log.append(T1), 1)

    def test_a_first_line_that_is_not_a_generation_makes_a_new_generation(self):
        for first in (b'{"seq": 1, "t": 1.0, "thread": "%s"}' % T1.encode(), b'{"gen": 5}', b'{"gen": null}', b'[]', b'{"generation": "abc"}'):
            home, log = fresh(Clock())
            log.append(T1)
            old = log.gen
            (home / "inbox.jsonl").write_bytes(first + b"\n")
            new = log.gen
            self.assertNotEqual(new, old, first)
            self.assertRegex(new, r"^[0-9a-f]{16}$")
            self.assertEqual(raw_gen(home), new)

    def test_a_missing_file_is_recreated_with_a_new_generation(self):
        home, log = fresh(Clock())
        log.append(T1)
        old = log.gen
        (home / "inbox.jsonl").unlink()
        self.assertNotEqual(log.gen, old)
        self.assertEqual(log.head(), 0)
        self.assertEqual(stat.S_IMODE((home / "inbox.jsonl").stat().st_mode), 0o600)

    def test_an_empty_file_is_a_damaged_file(self):
        home, log = fresh(Clock())
        log.append(T1)
        old = log.gen
        (home / "inbox.jsonl").write_bytes(b"")
        self.assertNotEqual(log.gen, old)
        self.assertEqual(log.append(T1), 1)


class GuestCollapse(unittest.TestCase):
    def test_second_guest_line_within_the_gap_is_collapsed(self):
        clk = Clock()
        home, log = fresh(clk)
        self.assertEqual(log.append(T1, guest=True), 1)
        clk.t += inboxlog.GUEST_GAP - 1
        self.assertIsNone(log.append(T1, guest=True))
        self.assertEqual(len(entries(home)), 1)
        clk.t += 2                                                                     # now past the gap since the FIRST (collapsed lines do not extend it)
        self.assertEqual(log.append(T1, guest=True), 2)

    def test_gap_is_per_thread(self):
        home, log = fresh(Clock())
        self.assertEqual(log.append(T1, guest=True), 1)
        self.assertEqual(log.append(T2, guest=True), 2)
        self.assertIsNone(log.append(T1, guest=True))

    def test_normal_lines_never_collapse_and_do_not_reset_the_gap(self):
        clk = Clock()
        home, log = fresh(clk)
        self.assertEqual(log.append(T1, guest=True), 1)
        for _ in range(5):
            self.assertIsNotNone(log.append(T1))                                       # peer-event lines are never collapsed
        self.assertIsNone(log.append(T1, guest=True))                                  # ... and are not 'the last guest line' either
        clk.t += inboxlog.GUEST_GAP + 1
        self.assertIsNotNone(log.append(T1, guest=True))

    def test_a_guest_line_is_not_blocked_by_a_normal_line(self):
        home, log = fresh(Clock())
        log.append(T1)
        self.assertIsNotNone(log.append(T1, guest=True))

    def test_a_thousand_requests_in_a_few_seconds_leave_a_handful_of_lines(self):
        clk = Clock()
        home, log = fresh(clk)
        for _ in range(1000):
            clk.t += 0.01
            log.append(T1, guest=True)
        self.assertEqual(len(entries(home)), 1)
        for _ in range(1000):                                                          # ... and an hour of one request a second: one line per gap, not per request
            clk.t += 1.0
            log.append(T1, guest=True)
        n = len(entries(home))
        self.assertTrue(3 <= n <= 6, n)                                                # ~1000 s / 300 s + the first line

    def test_gap_constant_is_honoured(self):
        clk = Clock()
        home, log = fresh(clk)
        with mock.patch.object(inboxlog, "GUEST_GAP", 5.0):
            self.assertEqual(log.append(T1, guest=True), 1)
            clk.t += 4.9
            self.assertIsNone(log.append(T1, guest=True))
            clk.t += 0.2
            self.assertEqual(log.append(T1, guest=True), 2)

    def test_a_clock_that_went_back_does_not_silence_guest_lines_for_ever(self):
        clk = Clock(10_000.0)
        home, log = fresh(clk)
        self.assertEqual(log.append(T1, guest=True), 1)
        clk.t = 100.0                                                                 # set back by hours: the last guest line is 'in the future'
        self.assertIsNotNone(log.append(T1, guest=True))


class Rebuild(unittest.TestCase):
    def test_rebuild_makes_a_new_generation_with_one_line_per_thread_occurrence_in_order(self):
        home, log = fresh(Clock())
        for _ in range(3):
            log.append(T1)
        old = log.gen
        new = log.rebuild([T2, T1, T2])
        self.assertNotEqual(new, old)
        self.assertEqual(log.gen, new)
        got = entries(home)
        self.assertEqual([(d["seq"], d["thread"]) for d in got], [(1, T2), (2, T1), (3, T2)])
        self.assertTrue(all(set(d) <= ENTRY_KEYS and "guest" not in d for d in got))
        self.assertEqual(log.head(), 3)
        self.assertEqual(log.append(T1), 4)

    def test_rebuild_of_nothing_is_an_empty_valid_log(self):
        home, log = fresh(Clock())
        log.append(T1)
        new = log.rebuild([])
        self.assertEqual((log.gen, log.head(), entries(home)), (new, 0, []))

    def test_rebuild_is_atomic_for_a_concurrent_reader(self):
        """A reader never sees a half-written file: it is replaced by rename (no truncate-then-write)."""
        home, log = fresh(Clock())
        for _ in range(50):
            log.append(T1)
        ino = (home / "inbox.jsonl").stat().st_ino
        log.rebuild([T1] * 50)
        self.assertNotEqual((home / "inbox.jsonl").stat().st_ino, ino)
        self.assertEqual(stat.S_IMODE((home / "inbox.jsonl").stat().st_mode), 0o600)
        self.assertEqual([p.name for p in home.iterdir() if p.name.startswith("inbox") and p.name != "inbox.jsonl"], [])      # no temp file left behind


class NoLeak(unittest.TestCase):
    """The file names a thread and a time, never who wrote what: after a PUBLIC and a PRIVATE post."""

    def _check(self, env, eid, text):
        raw = (env.home / "inbox.jsonl").read_bytes()
        for needle in (eid, env.ids["sansa"].id, env.ids["sansa"].name, text, "post", "member_add", "kind", "author", "body", "event", "title"):
            self.assertNotIn(needle.encode(), raw, needle)
        for d in env.lines():
            self.assertTrue(set(d) <= ENTRY_KEYS, d)

    def test_public_thread(self):
        env = Env("public")
        eid, _ = env.post("sansa", "the quick brown fox jumps")
        self.assertEqual(len(env.lines()), 1)
        self._check(env, eid, "the quick brown fox")

    def test_private_thread(self):
        env = Env("private")
        eid, _ = env.post("sansa", "the quick brown fox jumps")
        self.assertEqual(len(env.lines()), 1)
        self._check(env, eid, "the quick brown fox")
        for p in env.home.rglob("*"):                                                  # nothing else on disk shows the text either (the envelopes hide it)
            if p.is_file() and p.name != "identity.json":
                self.assertNotIn(b"the quick brown fox", p.read_bytes(), str(p))


class Concurrency(unittest.TestCase):
    def test_four_processes_one_home_every_event_one_line_seq_exact(self):
        env = Env("public", extra_members=[("dave", "member")])
        codes = run_authors(env, ["arya", "sansa", "carol", "dave"], 15)
        self.assertEqual(codes, [0, 0, 0, 0])
        got = env.lines()
        self.assertEqual([d["seq"] for d in got], list(range(1, 61)))                  # strictly increasing, no gap, no duplicate
        self.assertEqual({d["thread"] for d in got}, {env.tid})
        self.assertEqual(len(env.unread()), 60)                                         # exactly one line per unread event: nobody double-announced via refresh
        raw = (env.home / "inbox.jsonl").read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 61)                                          # the gen line + 60 whole lines


if __name__ == "__main__":
    unittest.main()
