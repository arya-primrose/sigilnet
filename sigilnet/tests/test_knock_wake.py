"""The wake line of a newcomer's knock (inboxlog `knock`, Mirror.note_knock, the watch line): ids only, collapsed per thread, and a guest line is unaffected."""
import tempfile
import unittest

from sigilnet import inboxlog
from sigilnet.inboxlog import GUEST_GAP, KNOCK_GAP, InboxLog, wait_guest
from sigilnet.watch import Watcher
from sigilnet.tests.test_inboxlog import Clock, lines


class KnockLines(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.clock = Clock()
        self.log = InboxLog(self.home, clock=self.clock)

    def test_a_knock_line_is_a_pointer_with_a_flag_and_nothing_else(self):
        self.assertEqual(self.log.append("t1", knock=True), 1)
        row = lines(self.home)[1]
        self.assertEqual(set(row), {"seq", "t", "thread", "knock"})
        self.assertIs(row["knock"], True)
        self.assertEqual([e.get("knock") for e in self.log.read_from(self.log.gen, 0)[1]], [True])

    def test_collapsed_per_thread_by_its_own_gap_and_independent_of_guest_lines(self):
        self.assertEqual(self.log.append("t1", knock=True), 1)
        self.assertIsNone(self.log.append("t1", knock=True))                  # inside KNOCK_GAP
        self.assertEqual(self.log.append("t2", knock=True), 2)                # another thread
        self.assertEqual(self.log.append("t1", guest=True), 3)                # a guest line is a different wake
        self.assertEqual(self.log.append("t1"), 4)                            # and a normal one
        self.clock.t += KNOCK_GAP + 1
        self.assertEqual(self.log.append("t1", knock=True), 5)
        self.assertLess(KNOCK_GAP, GUEST_GAP)
        log2 = InboxLog(self.home, clock=self.clock)                          # a fresh object rescans the file: the gap survives a restart
        self.assertIsNone(log2.append("t1", knock=True))

    def test_a_knock_does_not_wake_requests_wait(self):
        self.log.append("t1", knock=True)
        self.assertEqual(wait_guest(self.home, 0, clock=self.clock, sleep=lambda s: None), [])

    def test_the_gap_guards_a_flood(self):
        written = [self.log.append("t1", knock=True) for _ in range(500)]
        self.assertEqual([w for w in written if w], [1])


class WatchLine(unittest.TestCase):
    def test_the_watcher_says_what_to_run(self):
        w = Watcher.__new__(Watcher)                                           # (only the line formatting is under test)
        w.burst_n, w.burst_s = 20, 10.0
        out = w._lines([{"seq": 1, "t": 1.0, "thread": "abcdef0123456789" * 2, "knock": True}, {"seq": 2, "t": 2.0, "thread": "abcdef0123456789" * 2},
                        {"seq": 3, "t": 3.0, "thread": "abcdef0123456789" * 2, "guest": True}])
        self.assertEqual(out[0], "INBOX 1 abcdef01 (knock): a newcomer waits for your approval: run 'sigilnet knock list'")
        self.assertEqual(out[1], "INBOX 2 abcdef01: run sigilnet unread abcdef01")
        self.assertIn("guest request", out[2])
        for l in out:
            self.assertNotIn("carol", l)                                       # no name, no note, ever


if __name__ == "__main__":
    unittest.main()
