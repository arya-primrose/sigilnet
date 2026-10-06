"""P1 of DESIGN_node_daemon.md: start / stop / status, with REAL background nodes (tcp carrier on loopback, no network)."""
import contextlib
import fcntl
import io
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path

from sigilnet import cli, daemon

ROOT = str(Path(__file__).resolve().parents[2])


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write(str(e.code) if not isinstance(e.code, int) else "")
    return rc, out.getvalue(), err.getvalue()


def new_home():
    h = Path(os.path.realpath(tempfile.mkdtemp())) / "home"
    base = cli._free_range(random.randint(20000, 55000), 128, ["127.0.0.1"])
    rc, out, err = run_cli("--home", str(h), "init", "arya", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", str(base))
    assert rc == 0, err
    return h


def gone(pid):
    return not daemon.alive(pid)


class Base(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)                     # the detached nodes are Popen objects nobody waits for: that is the point of `start`
        self.h = new_home()
        self.addCleanup(shutil.rmtree, self.h.parent, True)
        self.addCleanup(self.reap)
        self.lines = []

    def reap(self):
        rec = daemon.read_pid(self.h)
        if rec and daemon.alive(rec["pid"]):
            try:
                os.kill(rec["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass

    def out(self, s):
        self.lines.append(s)

    def start(self, **kw):
        return daemon.start(self.h, wait=kw.pop("wait", 60), out=self.out, **kw)


class StartStop(Base):
    def test_start_status_second_start_stop(self):
        self.assertEqual(self.start(), 0, self.lines)
        rec = daemon.read_pid(self.h)
        self.assertTrue(daemon.is_our_node(self.h, rec))
        self.assertTrue(daemon.lock_held(self.h))
        st = json.loads((self.h / "node.status.json").read_text())
        self.assertTrue(st["ready"])
        self.assertEqual(st["carrier"], "tcp")
        self.assertEqual(st["pid"], rec["pid"])
        self.assertEqual(oct(os.stat(self.h / "node.pid").st_mode & 0o777), "0o600")
        self.assertIn("running (pid", daemon.status_lines(self.h)[0])
        hist = (self.h / "history.log").read_text()
        self.assertIn("node  starting the tcp carrier", hist)                  # the node's lines go through history.log (timestamped) ...
        self.assertIn("serving sync", hist)
        self.assertNotIn("serving sync", (self.h / "node.err").read_text())    # ... and not into node.err (tracebacks only)
        pid_before = (self.h / "node.pid").read_text()
        self.lines.clear()
        self.assertEqual(self.start(), 1)                                      # the second start: refused, and the winner's pid file is untouched
        self.assertIn("already running", self.lines[0])
        self.assertEqual((self.h / "node.pid").read_text(), pid_before)
        self.lines.clear()
        self.assertEqual(daemon.stop(self.h, out=self.out), 0)
        self.assertTrue(gone(rec["pid"]))
        self.assertFalse((self.h / "node.pid").exists())
        self.assertFalse((self.h / "node.status.json").exists())
        self.assertFalse(daemon.lock_held(self.h))
        self.assertIn("node: stopped", daemon.status_lines(self.h)[0])

    def test_the_child_command_line_names_the_absolute_home(self):
        self.assertEqual(self.start(), 0, self.lines)
        cmd = daemon.proc_cmdline(daemon.read_pid(self.h)["pid"])
        self.assertIn(str(self.h), cmd)
        self.assertIn("sigilnet", cmd)
        daemon.stop(self.h, out=self.out)

    def test_start_again_after_stop_works(self):
        for _ in range(2):
            self.assertEqual(self.start(), 0, self.lines)
            self.assertEqual(daemon.stop(self.h, out=self.out), 0)

    def test_no_wait_returns_at_once(self):
        t = time.time()
        self.assertEqual(self.start(no_wait=True), 0)
        self.assertLess(time.time() - t, 3)
        for _ in range(100):
            if daemon.read_pid(self.h):
                break
            time.sleep(0.1)
        daemon.stop(self.h, out=self.out)

    def test_a_node_that_dies_at_once_is_reported_with_its_output(self):
        (self.h / "node_config.json").write_text("{not json")                   # load_config -> `node run` starts, prints nothing useful or fails: either way it must not be 'ready'
        (self.h / "node_config.json").write_text(json.dumps({"carrier": "tcp"}))   # a tcp carrier without its section: "needs a tcp section"
        rc = self.start(wait=30)
        self.assertEqual(rc, 1)
        self.assertIn("exited", " ".join(self.lines))
        self.assertIn("tcp section", " ".join(self.lines))

    def test_a_failure_after_the_history_wrapper_shows_its_reason_in_start_output(self):
        from unittest import mock
        site = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, site, True)
        (site / "sitecustomize.py").write_text(                                        # the child's carrier fails to start AFTER the node's `out` wrapper exists
            "import sigilnet.tcplink as T\nfrom sigilnet.carrier import CarrierError\n"
            "def start(self, wait=True):\n    raise CarrierError('cannot bind the door: Address already in use', retry=False)\n"
            "T.TcpCarrier.start = start\n")
        (self.h / "history.log").write_text("2000-01-01 00:00:00 MST  node  an older line\n")      # an earlier run's line must not be mixed in
        with mock.patch.dict(os.environ, {"PYTHONPATH": str(site)}):
            rc = self.start(wait=30)
        self.assertEqual(rc, 1)
        msg = " ".join(self.lines)
        self.assertIn("exited", msg)
        reason = msg.split("before it was ready:", 1)[1].strip()
        self.assertIn("cannot bind the door: Address already in use", reason)         # node.err is empty (history-only): the reason comes from history.log
        self.assertNotIn("an older line", reason)
        self.assertEqual((self.h / "node.err").read_text().strip(), "")

    def test_not_ready_within_wait_says_so_and_leaves_the_node_running(self):
        rc = daemon.start(self.h, wait=0.0, out=self.out)
        self.assertEqual(rc, 1)
        self.assertIn("not ready after", " ".join(self.lines))
        for _ in range(100):
            if daemon.lock_held(self.h):
                break
            time.sleep(0.1)
        self.assertTrue(daemon.lock_held(self.h))
        daemon.stop(self.h, out=self.out)

    def test_start_without_init_is_refused(self):
        empty = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, empty, True)
        self.assertEqual(daemon.start(empty, out=self.out), 1)
        self.assertIn("init", self.lines[0])
        (empty / "identity.json").write_text("{}")
        self.assertEqual(daemon.start(empty, out=self.out), 1)
        self.assertIn("node configuration", self.lines[-1])
        self.assertFalse((empty / "node.err").exists())

    def test_the_cli_commands_work_end_to_end(self):
        h = str(self.h)
        rc, out, err = run_cli("--home", h, "start", "--wait", "60")
        self.assertEqual(rc, 0, err + out)
        rc, out, err = run_cli("--home", h, "status")
        self.assertIn("node: running", out)
        rc, out, err = run_cli("--home", h, "stop")
        self.assertEqual(rc, 0)
        rc, out, err = run_cli("--home", h, "status")
        self.assertIn("node: stopped", out)


def fake_node(home, ignore_term=False, name="sigilnet"):
    """A process whose command line says it is a sigilnet node of `home`, which holds node.lock and has written its pid file (what a real node does)."""
    code = ("import fcntl, os, signal, sys, time\n"
            "sys.path.insert(0, %r)\n"
            "from sigilnet import daemon\n"
            "fd = os.open(os.path.join(sys.argv[2], 'node.lock'), os.O_CREAT | os.O_RDWR, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "daemon.write_self_pid(sys.argv[2])\n"
            "%s\n"
            "print('ready', flush=True)\n"
            "time.sleep(120)\n") % (ROOT, "signal.signal(signal.SIGTERM, signal.SIG_IGN)" if ignore_term else "")
    p = subprocess.Popen([sys.executable, "-c", code, name, str(home)], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "ready"
    return p


class Safety(Base):
    def test_a_hung_node_is_killed_after_the_wait_and_the_cleanup_runs(self):
        p = fake_node(self.h, ignore_term=True)
        self.addCleanup(lambda: (p.kill(), p.wait()))
        cleaned = []
        rc = daemon.stop(self.h, term_wait=1.0, out=self.out, cleanup=lambda home, out: cleaned.append(home))
        self.assertEqual(rc, 0, self.lines)
        self.assertIn("SIGKILL", " ".join(self.lines))
        self.assertEqual(cleaned, [self.h])
        self.assertFalse((self.h / "node.pid").exists())                       # a killed node cannot clear its own files: stop does
        self.assertFalse((self.h / "node.status.json").exists())
        p.wait(timeout=5)
        self.assertIsNotNone(p.returncode)

    def test_a_clean_stop_does_not_run_the_cleanup(self):
        p = fake_node(self.h)
        self.addCleanup(lambda: (p.kill(), p.wait()))
        cleaned = []
        rc = daemon.stop(self.h, term_wait=10.0, out=self.out, cleanup=lambda home, out: cleaned.append(home))
        self.assertEqual(rc, 0, self.lines)
        self.assertEqual(cleaned, [])
        p.wait(timeout=5)

    def test_a_stale_pid_file_is_removed_and_nothing_is_signalled(self):
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        (self.h / "node.pid").write_text(json.dumps({"pid": dead.pid, "start_time": 1, "home": str(self.h)}))
        self.assertEqual(daemon.stop(self.h, out=self.out), 0)
        self.assertFalse((self.h / "node.pid").exists())
        self.assertIn("stale", " ".join(self.lines))
        self.assertIn("not running", " ".join(self.lines))

    def test_a_reused_pid_that_is_not_a_sigilnet_node_is_never_signalled(self):
        victim = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: (victim.kill(), victim.wait()))
        st = daemon.proc_state(victim.pid)
        (self.h / "node.pid").write_text(json.dumps({"pid": victim.pid, "start_time": st[1], "home": str(self.h)}))     # even the start time matches
        self.assertEqual(daemon.stop(self.h, out=self.out), 0)
        self.assertTrue(daemon.alive(victim.pid))
        self.assertFalse((self.h / "node.pid").exists())

    def test_a_process_that_names_the_home_but_is_not_sigilnet_is_never_signalled(self):
        victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", str(self.h)])        # the home path is on its command line, "sigilnet" is not
        self.addCleanup(lambda: (victim.kill(), victim.wait()))
        for _ in range(100):
            if daemon.proc_state(victim.pid):
                break
            time.sleep(0.05)
        st = daemon.proc_state(victim.pid)
        (self.h / "node.pid").write_text(json.dumps({"pid": victim.pid, "start_time": st[1], "home": str(self.h)}))
        self.assertEqual(daemon.stop(self.h, out=self.out), 0)
        self.assertTrue(daemon.alive(victim.pid))

    def test_a_pid_with_the_wrong_start_time_is_never_signalled(self):
        p = fake_node(self.h)
        self.addCleanup(lambda: (p.kill(), p.wait()))
        rec = daemon.read_pid(self.h)
        rec["start_time"] += 1
        (self.h / "node.pid").write_text(json.dumps(rec))
        rc = daemon.stop(self.h, out=self.out)
        self.assertTrue(daemon.alive(p.pid))                                    # not signalled
        self.assertEqual(rc, 1)                                                 # the lock is held but the pid file does not identify it
        self.assertIn("not signalling", " ".join(self.lines))

    def test_a_node_of_another_home_is_never_signalled(self):
        other = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, other, True)
        p = fake_node(other)
        self.addCleanup(lambda: (p.kill(), p.wait()))
        (self.h / "node.pid").write_text((other / "node.pid").read_text())      # a copied pid file: the command line names the other home
        rc = daemon.stop(self.h, out=self.out)
        self.assertTrue(daemon.alive(p.pid))
        self.assertEqual(rc, 0)                                                 # this home's lock is free: nothing to stop

    def test_a_lock_without_a_pid_file_is_reported_and_nothing_signalled(self):
        fd = os.open(self.h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(daemon.stop(self.h, out=self.out), 1)
        self.assertIn("node.pid does not identify", " ".join(self.lines))
        self.assertIn("running, but node.pid", daemon.status_lines(self.h)[0])
        self.assertIn("not started by `start`", daemon.status_lines(self.h)[0])

    def test_a_zombie_lock_holder_does_not_block_a_start(self):
        p = fake_node(self.h)
        os.kill(p.pid, signal.SIGKILL)
        for _ in range(100):
            st = daemon.proc_state(p.pid)
            if st and st[0] == "Z":
                break
            time.sleep(0.05)
        self.assertEqual(daemon.proc_state(p.pid)[0], "Z")                       # killed and not reaped: a zombie, like every dead process in this container
        self.assertFalse(daemon.lock_held(self.h))                              # the kernel dropped its flock at exit
        self.assertFalse(daemon.alive(p.pid))
        self.assertFalse(daemon.is_our_node(self.h, daemon.read_pid(self.h)))
        self.assertEqual(self.start(), 0, self.lines)
        self.assertEqual(daemon.stop(self.h, out=self.out), 0)
        p.wait()

    def test_stop_when_nothing_runs_is_a_quiet_success(self):
        self.assertEqual(daemon.stop(self.h, out=self.out), 0)
        self.assertEqual(self.lines, ["not running"])


class Locks(Base):
    def hold(self, seconds):
        fd = os.open(self.h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)

        def release():
            time.sleep(seconds)
            os.close(fd)
        t = threading.Thread(target=release)
        t.start()
        self.addCleanup(t.join)

    def test_a_node_start_survives_a_probe_holding_the_lock_for_a_moment(self):
        from sigilnet import noderun
        self.hold(0.3)
        fd = noderun._instance_lock(self.h)
        self.assertIsNotNone(fd)
        os.close(fd)

    def test_a_node_lock_held_for_ever_is_still_refused_after_the_retry(self):
        from sigilnet import noderun
        fd = os.open(self.h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        t = time.monotonic()
        self.assertIsNone(noderun._instance_lock(self.h, retry=0.2))
        self.assertGreaterEqual(time.monotonic() - t, 0.2)

    def test_lock_held_is_false_when_the_hold_ends_between_the_tries(self):
        fd = os.open(self.h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.assertTrue(daemon._probe(self.h))

        def release(_):
            os.close(fd)                                                  # the probe that held it lets go during the gap
        self.assertFalse(daemon.lock_held(self.h, sleep=release))

    def test_lock_held_is_true_when_it_stays_held(self):
        fd = os.open(self.h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        calls = []
        self.assertTrue(daemon.lock_held(self.h, sleep=lambda g: calls.append(g)))
        self.assertEqual(len(calls), 2)                                    # three tries, two gaps

    def test_two_simultaneous_starts_one_wins_and_the_loser_says_already_running(self):
        for _ in range(3):
            res = {}

            def go(k):
                lines = []
                res[k] = (daemon.start(self.h, wait=60, out=lines.append), lines)
            ts = [threading.Thread(target=go, args=(k,)) for k in ("a", "b")]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            rcs = sorted(r[0] for r in res.values())
            self.assertEqual(rcs, [0, 1], res)
            loser = [r for r in res.values() if r[0] == 1][0][1]
            self.assertTrue(any("already running" in l for l in loser), loser)       # not the winner's log tail
            rec = daemon.read_pid(self.h)
            self.assertTrue(daemon.is_our_node(self.h, rec))
            self.assertEqual(daemon.stop(self.h, out=self.out), 0)

    def _lose_a_race(self, second_call):
        """A node (fake, with a node.pid) already holds the lock, but the launcher's own checks are made to miss it: the launched child then loses on the flock."""
        from unittest import mock
        winner = fake_node(self.h)
        self.addCleanup(lambda: (winner.kill(), winner.wait()))
        (self.h / "node.err").write_text("winner output\n")
        real, n = daemon.lock_held, []

        def lock_held(home, **kw):
            n.append(1)
            if len(n) == 1:
                return False                                                  # the pre-check misses it
            if len(n) == 2:
                return second_call                                            # the check that decides whether node.err is truncated
            return real(home, **kw)
        lines = []
        with mock.patch.object(daemon, "lock_held", lock_held):
            rc = daemon.start(self.h, wait=60, out=lines.append)
        return rc, lines

    def test_a_launcher_that_loses_the_race_says_already_running_not_the_winners_log(self):
        rc, lines = self._lose_a_race(False)
        self.assertEqual(rc, 1)
        self.assertTrue(any("already running" in l and str(daemon.read_pid(self.h)["pid"]) in l for l in lines), lines)
        self.assertFalse(any("exited" in l for l in lines), lines)

    def test_node_err_is_not_truncated_when_a_node_holds_the_lock(self):
        rc, lines = self._lose_a_race(True)
        self.assertTrue((self.h / "node.err").read_text().startswith("winner output\n"))

    def test_a_status_prober_in_a_loop_never_makes_a_start_fail(self):
        stop = threading.Event()

        def prober():
            while not stop.is_set():
                daemon._probe(self.h)
        t = threading.Thread(target=prober)
        t.start()
        try:
            for _ in range(3):
                self.assertEqual(self.start(), 0, self.lines)
                self.assertEqual(daemon.stop(self.h, out=self.out), 0)
        finally:
            stop.set()
            t.join()


class Proc(unittest.TestCase):
    def test_proc_state_parses_a_name_with_spaces_and_parentheses(self):
        from unittest import mock
        rest = ["S"] + [str(i) for i in range(4, 22)] + ["424242"] + ["0"] * 20                  # fields 3.. of /proc/PID/stat: field 3 is the state, field 22 the start time
        stat = "123 (a b) c) " + " ".join(rest)
        with mock.patch("sigilnet.daemon.Path.read_text", return_value=stat):
            self.assertEqual(daemon.proc_state(123), ("S", 424242))

    def test_proc_state_of_a_missing_process_is_none(self):
        self.assertIsNone(daemon.proc_state(2 ** 22 + 12345))


if __name__ == "__main__":
    unittest.main()
