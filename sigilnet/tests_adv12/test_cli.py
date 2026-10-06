"""`sigilnet watch` as a real process (section 7): flushed lines on a pipe, follows new wakes live, exits 0 at --seconds."""
import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from .h import Env

REPO = str(Path(__file__).resolve().parents[2])


def run_cli(home, *args, timeout=60):
    return subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(home), *args], capture_output=True, text=True, timeout=timeout, cwd=REPO,
                          env={**os.environ, "PYTHONPATH": REPO})


class HasWatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = subprocess.run([sys.executable, "-m", "sigilnet", "watch", "--help"], capture_output=True, text=True, cwd=REPO, env={**os.environ, "PYTHONPATH": REPO})
        if r.returncode != 0:
            raise unittest.SkipTest("no `watch` subcommand yet")


class Watch(HasWatch):
    def test_follows_a_new_wake_live_and_exits_zero(self):
        env = Env("public")
        p = subprocess.Popen([sys.executable, "-u", "-m", "sigilnet", "--home", str(env.home), "watch", "--seconds", "20"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, cwd=REPO, env={**os.environ, "PYTHONPATH": REPO})
        try:
            first = p.stdout.readline()
            self.assertEqual(first.strip(), "WATCH started: 0 unannounced")
            t0 = time.time()
            env.post("sansa", "live")
            line = p.stdout.readline()                                                    # arrives while the process is still running (flushed, not at exit)
            self.assertLess(time.time() - t0, 5.0)
            self.assertEqual(line.strip(), f"INBOX 1 {env.tid[:8]}: run sigilnet unread {env.tid[:8]}")
            self.assertIsNone(p.poll(), "the watcher must keep running after a line")
        finally:
            p.terminate()
            p.wait(10)
            p.stdout.close()
            p.stderr.close()

    def test_seconds_zero_prints_the_start_line_and_returns_zero(self):
        env = Env("public")
        env.post("sansa", "x")
        r = run_cli(env.home, "watch", "--seconds", "0.5")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[0], "WATCH started: 1 unannounced")

    @unittest.skipIf(os.environ.get("ADV12_SKIP_OPEN_FINDINGS") == "1", "open finding P2-2: watch on a home without identity.json is a traceback")
    def test_a_home_without_an_identity_is_an_error_not_a_traceback(self):
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="adv12_cli_"))
        r = run_cli(d, "watch", "--seconds", "0.2")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)

    def test_stdout_closed_early_ends_the_process(self):
        """The Monitor tool going away must not leave a watcher spinning for ever."""
        env = Env("public")
        p = subprocess.Popen([sys.executable, "-u", "-m", "sigilnet", "--home", str(env.home), "watch", "--seconds", "60"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, cwd=REPO, env={**os.environ, "PYTHONPATH": REPO})
        try:
            p.stdout.readline()
            p.stdout.close()
            env.post("sansa", "after the pipe closed")
            try:
                p.wait(15)
            except subprocess.TimeoutExpired:
                self.fail("the watcher kept running with its stdout closed")
        finally:
            if p.poll() is None:
                p.kill()
                p.wait(5)
            p.stderr.close()

class LinesRun(HasWatch):
    def test_every_command_a_line_tells_you_to_run_really_runs(self):
        """F5-1 (live test 5): a wake line that names a command which then prints a usage error is worse than no line."""
        import shlex
        env = Env("public")
        env.post("sansa", "hello there")
        r = run_cli(env.home, "watch", "--seconds", "0.5", "--consumer", "fresh")
        self.assertEqual(r.returncode, 0, r.stderr)
        # a consumer with an old cursor announces the backlog, so seed one at 0 and run again
        (env.home / "cursors").mkdir(mode=0o700, exist_ok=True)
        import json as _j
        from sigilnet.inboxlog import InboxLog
        (env.home / "cursors" / "c2.json").write_text(_j.dumps({"gen": InboxLog(env.home).gen, "seq": 0}))
        r = run_cli(env.home, "watch", "--seconds", "0.5", "--consumer", "c2")
        lines = [l for l in r.stdout.splitlines() if l.startswith("INBOX ")]
        self.assertEqual(len(lines), 1, r.stdout)
        cmd = lines[0].split("run ", 1)[1].strip("'")
        out = run_cli(env.home, *shlex.split(cmd)[1:])
        self.assertEqual(out.returncode, 0, (cmd, out.stderr))
        self.assertIn("hello there", out.stdout)
        lst = run_cli(env.home, "list")                                                  # what burst / REMINDER lines point at
        self.assertEqual(lst.returncode, 0, lst.stderr)
        self.assertIn("unread=1", lst.stdout)


if __name__ == "__main__":
    unittest.main()
