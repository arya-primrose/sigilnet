"""#2 DESIGN_node_wake rev 1, from the FROZEN INTERFACE only: wake.poke, wake.Waker, Mirror(poke=), home.open_mirror(poke=), Node.wake / on_notify, the noderun loop."""
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import wake
from sigilnet.wake import Waker, poke


class Clock:
    """Fake monotonic clock; sleep advances it (a Waker never really waits)."""

    def __init__(self, t=1000.0):
        self.t = t
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, d):
        self.slept.append(d)
        self.t += d


def tmpdir():
    return Path(tempfile.mkdtemp(prefix="adv13_"))


def mk(path=None, **kw):
    clk = Clock()
    path = path if path is not None else tmpdir() / "node.poke"
    w = Waker(path, clock=clk, sleep=clk.sleep, poll=kw.pop("poll", 0.05), min_round=kw.pop("min_round", 0.2), tick=kw.pop("tick", 2.0), **kw)
    return w, clk, Path(path)


class Poke(unittest.TestCase):
    def test_creates_the_file_0600_and_appends_one_byte_per_call(self):
        p = tmpdir() / "node.poke"
        poke(p)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(p.stat().st_size, 1)
        poke(p)
        poke(p)
        self.assertEqual(p.stat().st_size, 3)

    def test_the_file_never_grows_past_the_cap(self):
        p = tmpdir() / "node.poke"
        with mock.patch.object(wake, "POKE_CAP", 50):
            for _ in range(500):
                poke(p)
                self.assertLessEqual(p.stat().st_size, 50)
            self.assertGreater(p.stat().st_size, 0)

    def test_every_poke_changes_the_stamp_even_across_the_cap(self):
        p = tmpdir() / "node.poke"
        seen = []
        with mock.patch.object(wake, "POKE_CAP", 20):
            for _ in range(100):
                poke(p)
                st = os.stat(p)
                seen.append((st.st_mtime_ns, st.st_size, st.st_ino))
        self.assertTrue(all(a != b for a, b in zip(seen, seen[1:])), "two consecutive pokes left the same (mtime_ns, size, ino)")

    def test_never_raises(self):
        d = tmpdir()
        poke(d / "no" / "such" / "dir" / "node.poke")                       # missing directory
        poke(d)                                                              # a directory
        os.chmod(d, 0o500)
        try:
            poke(d / "node.poke")                                            # read-only directory (as root this may succeed: both are fine)
        finally:
            os.chmod(d, 0o700)
        poke("")
        poke(None)

    def test_does_not_follow_a_symlink(self):
        d = tmpdir()
        target = d / "target"
        target.write_text("keep")
        os.symlink(target, d / "node.poke")
        poke(d / "node.poke")
        self.assertEqual(target.read_text(), "keep")

    def test_a_file_owned_by_us_with_other_modes_is_still_appended(self):
        p = tmpdir() / "node.poke"
        p.write_text("")
        os.chmod(p, 0o600)
        poke(p)
        self.assertEqual(p.stat().st_size, 1)


class WaiterBasics(unittest.TestCase):
    def test_nothing_happens_returns_timeout_after_exactly_the_timeout(self):
        w, clk, p = mk()
        t0 = clk.t
        self.assertEqual(w.wait(), "timeout")                                 # the default timeout is the TICK
        self.assertGreaterEqual(clk.t - t0, 2.0 - 1e-9)
        self.assertLessEqual(clk.t - t0, 2.0 + 0.05 + 1e-9)

    def test_an_explicit_timeout_is_honoured(self):
        w, clk, p = mk()
        t0 = clk.t
        self.assertEqual(w.wait(0.7), "timeout")
        self.assertLessEqual(clk.t - t0, 0.7 + 0.05 + 1e-9)

    def test_never_waits_longer_than_the_timeout_whatever_the_poll(self):
        w, clk, p = mk(poll=0.3)
        t0 = clk.t
        w.wait(1.0)
        self.assertLessEqual(clk.t - t0, 1.0 + 0.3 + 1e-9)

    def test_an_event_set_returns_wake_but_not_before_min_round(self):
        w, clk, p = mk(min_round=0.2)
        w.round_started()
        t0 = clk.t
        w.event.set()
        self.assertEqual(w.wait(), "wake")
        self.assertGreaterEqual(clk.t - t0, 0.2 - 1e-9)                       # the floor
        self.assertLessEqual(clk.t - t0, 0.2 + 0.05 + 1e-9)                   # and no later than one poll after it

    def test_a_poke_returns_poke_after_min_round(self):
        w, clk, p = mk(min_round=0.2)
        w.round_started()
        poke(p)
        t0 = clk.t
        self.assertEqual(w.wait(), "poke")
        self.assertGreaterEqual(clk.t - t0, 0.2 - 1e-9)
        self.assertLessEqual(clk.t - t0, 0.2 + 0.05 + 1e-9)

    def test_no_poke_file_at_all_is_no_change(self):
        w, clk, p = mk()
        w.round_started()
        self.assertEqual(w.wait(1.0), "timeout")
        self.assertFalse(p.exists())

    def test_an_unreadable_poke_path_is_no_change_not_an_error(self):
        w, clk, p = mk(path="/proc/nope/does/not/exist")
        w.round_started()
        self.assertEqual(w.wait(1.0), "timeout")

    def test_a_directory_in_place_of_the_poke_file_is_no_change(self):
        d = tmpdir()
        (d / "node.poke").mkdir()
        w, clk, p = mk(path=d / "node.poke")
        w.round_started()
        self.assertEqual(w.wait(0.5), "timeout")

    def test_the_event_attribute_is_a_threading_event(self):
        w, clk, p = mk()
        self.assertIsInstance(w.event, threading.Event)


class RoundBoundaries(unittest.TestCase):
    def test_round_started_clears_the_event(self):
        w, clk, p = mk()
        w.event.set()
        w.round_started()
        self.assertFalse(w.event.is_set())
        self.assertEqual(w.wait(1.0), "timeout")

    def test_a_set_during_the_round_makes_the_next_wait_return_at_once(self):
        """W6: the loop clears at the START of a round, so a notify that arrives mid-round is not lost."""
        w, clk, p = mk()
        w.round_started()
        clk.t += 1.5                                                         # the round takes a while
        w.event.set()                                                        # a notify arrives during it
        t0 = clk.t
        self.assertEqual(w.wait(), "wake")
        self.assertEqual(clk.t, t0)                                          # min_round long past: no sleeping at all

    def test_a_poke_before_round_started_does_not_wake_the_next_wait(self):
        w, clk, p = mk()
        poke(p)
        w.round_started()                                                    # records the stamp AFTER that poke
        self.assertEqual(w.wait(1.0), "timeout")

    def test_a_poke_after_round_started_wakes_the_next_wait(self):
        w, clk, p = mk()
        w.round_started()
        clk.t += 1.0
        poke(p)
        self.assertEqual(w.wait(1.0), "poke")

    def test_a_poke_that_arrives_while_waiting_is_seen_within_one_poll(self):
        w, clk, p = mk(min_round=0.0)
        w.round_started()
        calls = []

        def sleeper(d):
            calls.append(d)
            clk.t += d
            if len(calls) == 3:
                poke(p)

        w.sleep = sleeper
        t0 = clk.t
        self.assertEqual(w.wait(5.0), "poke")
        self.assertLessEqual(clk.t - t0, 3 * 0.05 + 0.05 + 1e-9)

    def test_the_file_being_replaced_is_a_change(self):
        w, clk, p = mk()
        poke(p)
        w.round_started()
        clk.t += 1.0
        p.unlink()
        poke(p)                                                              # a new inode (and size 1 again)
        self.assertEqual(w.wait(1.0), "poke")

    def test_a_change_of_size_alone_is_a_change(self):
        """W3: one byte per poke, so two pokes inside one kernel tick (same mtime_ns) are still told apart by the size."""
        w, clk, p = mk()
        poke(p)
        fixed = os.stat(p).st_mtime_ns
        w.round_started()
        clk.t += 1.0
        poke(p)
        os.utime(p, ns=(fixed, fixed))                                       # the same mtime_ns as before; only the size differs
        self.assertEqual(os.stat(p).st_mtime_ns, fixed)
        self.assertEqual(w.wait(1.0), "poke")

    def test_a_change_of_inode_alone_is_a_change(self):
        w, clk, p = mk()
        poke(p)
        st = os.stat(p)
        w.round_started()
        clk.t += 1.0
        tmp = p.with_name("other")
        tmp.write_bytes(b"x")                                                # the same size ...
        os.utime(tmp, ns=(st.st_mtime_ns, st.st_mtime_ns))                   # ... the same mtime_ns ...
        os.replace(tmp, p)                                                   # ... renamed over the old one: a different inode
        self.assertNotEqual(os.stat(p).st_ino, st.st_ino)
        self.assertEqual(w.wait(1.0), "poke")

    def test_the_file_being_deleted_is_not_a_wake(self):
        w, clk, p = mk()
        poke(p)
        w.round_started()
        clk.t += 1.0
        p.unlink()
        self.assertEqual(w.wait(1.0), "timeout")

    def test_a_thousand_pokes_cannot_make_rounds_closer_than_min_round(self):
        """MIN_ROUND floor: simulate 30 seconds of a flood; count rounds."""
        w, clk, p = mk(min_round=0.2)
        rounds, stamps = 0, []
        end = clk.t + 30.0
        while clk.t < end:
            w.round_started()
            stamps.append(clk.t)
            rounds += 1
            for _ in range(3):
                poke(p)                                                      # a poke storm during every round
            w.event.set()
            w.wait(2.0)
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        self.assertTrue(all(g >= 0.2 - 1e-9 for g in gaps), min(gaps))
        self.assertLessEqual(rounds, int(30 / 0.2) + 1)

    def test_idle_rounds_are_one_per_tick(self):
        w, clk, p = mk()
        end = clk.t + 20.0
        rounds = 0
        while clk.t < end:
            w.round_started()
            rounds += 1
            self.assertEqual(w.wait(), "timeout")
        self.assertTrue(9 <= rounds <= 11, rounds)


class Parameters(unittest.TestCase):
    def test_the_constructor_poll_is_the_slice(self):
        w, clk, p = mk(poll=0.3)
        w.round_started()
        w.wait(1.0)
        self.assertTrue(clk.slept and all(d <= 0.3 + 1e-9 for d in clk.slept) and abs(clk.slept[0] - 0.3) < 1e-9, clk.slept)           # slices of the constructor poll (the last one may be shorter)

    def test_the_constructor_tick_is_the_default_timeout(self):
        w, clk, p = mk(tick=0.7)
        t0 = clk.t
        self.assertEqual(w.wait(), "timeout")
        self.assertTrue(0.7 - 1e-9 <= clk.t - t0 <= 0.7 + 0.05 + 1e-9, clk.t - t0)

    def test_the_constructor_min_round_is_the_floor(self):
        w, clk, p = mk(min_round=0.9)
        w.round_started()
        w.event.set()
        t0 = clk.t
        self.assertEqual(w.wait(), "wake")
        self.assertTrue(0.9 - 1e-9 <= clk.t - t0 <= 0.9 + 0.05 + 1e-9, clk.t - t0)


class Constants(unittest.TestCase):
    def test_module_constants_are_the_defaults_resolved_at_call_time(self):
        clk = Clock()
        w = Waker(tmpdir() / "p", clock=clk, sleep=clk.sleep)                  # None for poll / min_round / tick
        with mock.patch.object(wake, "TICK", 0.9), mock.patch.object(wake, "POLL", 0.1), mock.patch.object(wake, "MIN_ROUND", 0.0):
            w.round_started()
            t0 = clk.t
            self.assertEqual(w.wait(), "timeout")
            self.assertTrue(0.9 - 1e-9 <= clk.t - t0 <= 0.9 + 0.1 + 1e-9, clk.t - t0)
            self.assertTrue(all(d <= 0.1 + 1e-9 for d in clk.slept) and any(abs(d - 0.1) < 1e-9 for d in clk.slept), clk.slept)      # slices of POLL (the last one may be shorter)

    def test_defaults_are_the_documented_values(self):
        self.assertEqual((wake.TICK, wake.POLL, wake.MIN_ROUND, wake.POKE_CAP), (2.0, 0.05, 0.2, 4096))


if __name__ == "__main__":
    unittest.main()
