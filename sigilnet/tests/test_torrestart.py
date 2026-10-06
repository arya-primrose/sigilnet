"""S1 (DESIGN_tor_restart.md): `node run` restarts a dead carrier a bounded number of times, then exits loudly."""
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sigilnet import noderun as N
from sigilnet.carrier import CarrierError


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.sleeps = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


class FakeTor:
    def __init__(self, order, tail="tor: boom"):
        self.order, self.tail, self.start_error, self.start_cost, self.clock = order, tail, None, 0.0, None
        self.services = {"a": {"agent": None}}

    def _log_tail(self):
        return self.tail

    def stop(self):
        self.order.append("stop")

    def start(self, wait=True, **kw):
        self.order.append("start")
        self.tail = ""                                   # TorNode.start truncates its log
        if self.clock:
            self.clock.t += self.start_cost
        if self.start_error:
            raise self.start_error

    def doors(self):
        return self.services

    def door_endpoint(self, name):
        return {"addr": "x" * 56 + ".onion:47200"}


class FakeDoors:
    def __init__(self, order):
        self.order = order

    def sync(self):
        self.order.append("sync")


class Rig:
    def __init__(self, **kw):
        self.order, self.out, self.history, self.clock = [], [], [], Clock()
        self.tor, self.doors = FakeTor(self.order, **kw), FakeDoors(self.order)
        self.tor.clock = self.clock

    def recover(self, end=None):
        return N._recover_carrier(self.tor, self.doors, self.out.append, self.history, end, clock=self.clock, sleep=self.clock.sleep)


class Recover(unittest.TestCase):
    def test_a_restart_stops_starts_then_syncs_the_doors_in_that_order_and_says_so(self):
        r = Rig()
        self.assertTrue(r.recover())
        self.assertEqual(r.order, ["stop", "start", "sync"])                       # never doors.sync() while no tor runs (a reload would be a no-op)
        self.assertIn("carrier exited (tor: boom); restart 1/3 in 5 s", r.out[0])
        self.assertTrue(any("carrier restarted (took" in x for x in r.out))
        self.assertTrue(any("door for a: " + "x" * 56 in x for x in r.out))

    def test_the_fourth_exit_inside_the_window_gives_up_without_touching_the_carrier(self):
        r = Rig()
        for _ in range(3):
            self.assertTrue(r.recover())
        r.order.clear()
        self.assertFalse(r.recover())
        self.assertEqual(r.order, [])
        self.assertIn("giving up", r.out[-1])
        self.assertTrue(r.out[-1].startswith("error:"))

    def test_a_successful_restart_does_not_reset_the_budget_and_the_window_only_rolls_by_time(self):
        r = Rig()
        for _ in range(3):
            self.assertTrue(r.recover())
        self.assertEqual(len(r.history), 3)
        self.assertFalse(r.recover())
        r.clock.t += N.TOR_RESTART_WINDOW                                           # the oldest exits fall out of the window
        self.assertTrue(r.recover())
        self.assertEqual(len(r.history), 1)

    def test_backoff_grows_5_30_120_in_slices_of_at_most_one_second(self):
        r = Rig()
        for want in (5, 30, 120):
            r.clock.sleeps.clear()
            self.assertTrue(r.recover())
            self.assertEqual(sum(r.clock.sleeps), want)
            self.assertLessEqual(max(r.clock.sleeps), 1.0)
        self.assertIn("restart 3/3 in 120 s", r.out[-4] if "restart 3/3" in r.out[-4] else " ".join(r.out))

    def test_the_budget_counts_from_the_moment_of_the_exit_not_of_the_successful_start(self):
        r = Rig()
        r.tor.start_cost = 100.0
        t_exit = r.clock.t
        r.recover()
        self.assertEqual(r.history, [t_exit])

    def test_a_failed_start_stops_the_half_started_carrier_skips_the_door_sync_and_uses_the_budget(self):
        r = Rig()
        r.tor.start_error = CarrierError("tor did not bootstrap")
        self.assertTrue(r.recover())
        self.assertEqual(r.order, ["stop", "start", "stop"])                       # the second stop: a tor that did not bootstrap still runs and would look healthy
        self.assertTrue(any("carrier restart failed: CarrierError" in x for x in r.out))
        self.assertEqual(len(r.history), 1)
        for _ in range(2):
            r.recover()
        self.assertFalse(r.recover())

    def test_the_log_tail_is_read_before_start_truncates_it_and_is_cleaned_and_capped(self):
        r = Rig(tail="bad\x1b[31m‮ line\nnext " + "z" * 600)
        r.recover()
        first = r.out[0]
        self.assertNotIn("\x1b", first)
        self.assertNotIn("‮", first)
        self.assertNotIn("\n", first)
        self.assertIn("bad", first)
        self.assertLess(len(first), 420)
        self.assertEqual(N._clean_tail("a​b"), "a b")

    def test_end_reached_during_the_backoff_returns_without_restarting(self):
        r = Rig()
        self.assertTrue(r.recover(end=time.time() - 1))
        self.assertEqual(r.order, [])

    def test_an_interrupt_during_the_backoff_propagates_and_nothing_is_started(self):
        r = Rig()

        def boom(s):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            N._recover_carrier(r.tor, r.doors, r.out.append, r.history, None, clock=r.clock, sleep=boom)
        self.assertEqual(r.order, [])

    def test_a_programming_error_in_start_is_not_swallowed(self):
        r = Rig()
        r.tor.start_error = RuntimeError("TorNode.start() must run in the main thread")
        with self.assertRaises(RuntimeError):
            r.recover()

    def test_tor_start_really_refuses_a_non_main_thread_so_the_restart_must_run_in_the_loops_thread(self):
        import inspect
        self.assertIn("main_thread", inspect.getsource(N.TorNode.start))
        src = inspect.getsource(N.run)
        self.assertIn("_recover_carrier(carriers[dead], doors_by[dead], out, restarts[dead], end)", src)      # called inline in the loop, not from a worker


class DoorAddedWhileDown(unittest.TestCase):
    def test_start_picks_up_a_door_added_while_tor_was_down_and_reconfigure_with_no_tor_is_harmless(self):
        from sigilnet import torlink as T
        n = T.TorNode(tempfile.mkdtemp(), offline=True)
        n.open_door("a", "peer", credential={"type": "onion", "key": T.make_client_key()[1]}, agent=None)     # (what the CLI does: it writes services.json)
        self.assertFalse(n.running())
        n.reconfigure()                                                            # no tor is running: nothing to signal, no error
        self.assertFalse(n.running())
        n.open_door("b", "peer", credential={"type": "onion", "key": T.make_client_key()[1]}, agent=None)
        n.start(wait=True, timeout=60)
        try:
            self.assertTrue(n.service_address("a") and n.service_address("b"))
        finally:
            n.stop()


class SigtermHandler(unittest.TestCase):
    """Sansa r35a: run() must not leak its SIGTERM handler into an in-process caller, and installs none off the main thread."""

    def run_node(self, out):
        from sigilnet.keys import Identity
        home = Path(tempfile.mkdtemp())
        return N.run(home, Identity.generate("me"), offline=True, seconds=1, out=out)

    def test_the_old_handler_is_back_after_run(self):
        mine = lambda *a: None
        old = signal.signal(signal.SIGTERM, mine)
        try:
            self.assertEqual(self.run_node(lambda *a: None), 0)
            self.assertIs(signal.getsignal(signal.SIGTERM), mine)
        finally:
            signal.signal(signal.SIGTERM, old)

    def test_off_the_main_thread_no_handler_is_installed(self):
        seen = {}

        def work():
            before = signal.getsignal(signal.SIGTERM)
            try:
                self.run_node(lambda *a: None)
            except RuntimeError as e:                                  # TorNode.start refuses a non-main thread: expected
                seen["err"] = str(e)
            seen["same"] = signal.getsignal(signal.SIGTERM) is before
        t = threading.Thread(target=work)
        t.start()
        t.join(60)
        self.assertTrue(seen.get("same"))
        self.assertIn("main thread", seen.get("err", ""))


ROOT = str(Path(__file__).resolve().parents[2])


def _tor_child(home):
    return int((Path(home) / "tor" / "tor.pid").read_text())


@unittest.skipIf(os.environ.get("SIGIL_PARALLEL"), "real tor, long windows: tools/runall.sh runs this class alone after the parallel suites")
class RealTorRestart(unittest.TestCase):
    """Real tor (offline carrier): run these ALONE; under the parallel full run the 40 s windows can flake (like the other real-tor tests)."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.base = [sys.executable, "-m", "sigilnet", "--home", str(self.home)]
        subprocess.run([*self.base, "id", "init", "me"], capture_output=True, cwd=ROOT, timeout=180)
        subprocess.run([*self.base, "node", "init", "--service-port-base", "47471"], capture_output=True, cwd=ROOT, timeout=180)
        from sigilnet import torlink as T
        subprocess.run([*self.base, "node", "authorize", "p", T.make_client_key()[1]], capture_output=True, cwd=ROOT, timeout=180)
        self.log = self.home / "node.out"
        with open(self.log, "w") as f:
            self.proc = subprocess.Popen([*self.base, "node", "run", "--offline", "--seconds", "600"], stdout=f, stderr=subprocess.STDOUT, cwd=ROOT)

    def tearDown(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(60)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def until(self, text, secs=90):
        end = time.time() + secs
        while time.time() < end:
            if text in self.log.read_text():
                return True
            time.sleep(0.3)
        return False

    def door_line(self):
        return [x for x in self.log.read_text().splitlines() if "door for p:" in x][0].strip()

    def test_kill9_of_the_tor_child_is_recovered_with_the_same_door_address_and_sigterm_ends_it_cleanly(self):
        self.assertTrue(self.until("serving sync"))
        before = self.door_line()
        os.kill(_tor_child(self.home), signal.SIGKILL)
        self.assertTrue(self.until("carrier restarted"), self.log.read_text())
        self.assertIn("restart 1/3 in 5 s", self.log.read_text())
        lines = [x.strip() for x in self.log.read_text().splitlines() if "door for p:" in x]
        self.assertEqual(lines, [before, before])                                  # the same address after the restart
        self.assertIsNone(self.proc.poll())
        self.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.proc.wait(60), 0)

    def test_sigterm_during_the_backoff_exits_cleanly_and_leaves_no_tor_behind(self):
        self.assertTrue(self.until("serving sync"))
        pid = _tor_child(self.home)
        os.kill(pid, signal.SIGKILL)
        self.assertTrue(self.until("restart 1/3 in 5 s"))
        self.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.proc.wait(30), 0)
        self.assertNotIn("carrier restarted", self.log.read_text())
        time.sleep(1)
        r = subprocess.run(["pgrep", "-af", f"tor -f {self.home}"], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "")

    def test_four_kills_inside_the_window_end_the_node_with_exit_1(self):
        self.assertTrue(self.until("serving sync"))
        for i in range(1, 4):
            os.kill(_tor_child(self.home), signal.SIGKILL)
            self.assertTrue(self.until(f"restart {i}/3 in"), self.log.read_text())
            self.assertTrue(self.until("carrier restarted") and self.log.read_text().count("carrier restarted") == i or self.until("carrier restarted", 150), self.log.read_text())
            end = time.time() + 150
            while time.time() < end and self.log.read_text().count("carrier restarted") < i:
                time.sleep(0.5)
        os.kill(_tor_child(self.home), signal.SIGKILL)
        self.assertEqual(self.proc.wait(150), 1, self.log.read_text())
        self.assertIn("giving up", self.log.read_text())


if __name__ == "__main__":
    unittest.main()
