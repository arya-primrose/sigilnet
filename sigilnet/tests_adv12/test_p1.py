"""P1 (home / init / start / stop / status) from the OUTSIDE. Open findings are skipped with ADV12_SKIP_OPEN_FINDINGS=1."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sigilnet import daemon
from sigilnet.home import HomeError, resolve_home

REPO = str(Path(__file__).resolve().parents[2])
SKIP = os.environ.get("ADV12_SKIP_OPEN_FINDINGS") == "1"
PY = sys.executable


def run(cwd, *args, env=None, timeout=120):
    e = {**os.environ, "PYTHONPATH": REPO, "PYTHONDONTWRITEBYTECODE": "1", **(env or {})}
    r = subprocess.run([PY, "-B", "-m", "sigilnet", *args], capture_output=True, text=True, timeout=timeout, cwd=str(cwd), env=e)
    return r.returncode, r.stdout, r.stderr


def mkhome(d):
    s = Path(d) / ".sigilnet"
    s.mkdir(mode=0o700)
    (s / "identity.json").write_text("{}")
    os.chmod(s, 0o700)
    return s


class Walk(unittest.TestCase):
    @unittest.skipIf(SKIP, "open finding F-A (P1): $HOME reached through a symlink")
    def test_home_given_as_a_symlink_still_stops_the_walk_at_home(self):
        base = Path(tempfile.mkdtemp(prefix="adv12_p1_")).resolve()
        real = base / "data" / "home"
        proj = real / "proj"
        proj.mkdir(parents=True)
        link = base / "homelink"
        os.symlink(real, link)
        mkhome(real)                     # a $HOME/.sigilnet at the physical HOME: never to be used
        mkhome(base / "data")            # a stray home ABOVE $HOME: never to be used either
        for h in (str(real), str(link)):
            with self.assertRaises(HomeError, msg=f"HOME={h}"):
                resolve_home(None, {"HOME": h}, proj)
        with self.assertRaises(HomeError):                               # and with HOME written with a trailing slash / dots
            resolve_home(None, {"HOME": str(real) + "/./"}, proj)


class Init(unittest.TestCase):
    @unittest.skipIf(SKIP, "open finding F-B (P1): init follows a .sigilnet symlink")
    def test_init_refuses_a_dot_sigilnet_symlink_and_touches_nothing(self):
        p = Path(tempfile.mkdtemp(prefix="adv12_p1_"))
        proj, other = p / "proj", p / "elsewhere"
        proj.mkdir()
        other.mkdir()
        os.chmod(other, 0o755)
        os.symlink(other, proj / ".sigilnet")
        rc, out, err = run(proj, "init", "victim", env={"HOME": str(p)})
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(sorted(x.name for x in other.iterdir()), [])             # no identity written into the link target
        self.assertEqual(stat.S_IMODE(other.stat().st_mode), 0o755)               # and its mode was not changed

    def test_a_dot_sigilnet_that_is_a_file_is_refused(self):
        p = Path(tempfile.mkdtemp(prefix="adv12_p1_"))
        (p / ".sigilnet").write_text("x")
        rc, out, err = run(p, "init", "a", env={"HOME": str(p / "nohome")})
        self.assertNotEqual(rc, 0)
        self.assertEqual((p / ".sigilnet").read_text(), "x")


def tcp_home(p):
    proj = Path(p) / "proj"
    proj.mkdir()
    rc, out, err = run(proj, "init", "a", "--carrier", "tcp", "--bind", "127.0.0.1", env={"HOME": str(p)})
    assert rc == 0, err
    return proj


class Daemon(unittest.TestCase):
    def tearDown(self):
        for proj in getattr(self, "projs", []):
            run(proj, "stop", env={"HOME": str(proj.parent)})

    def home(self):
        p = Path(tempfile.mkdtemp(prefix="adv12_p1_"))
        proj = tcp_home(p)
        self.projs = getattr(self, "projs", []) + [proj]
        return proj

    def test_two_simultaneous_starts_one_node_and_the_winners_pid_file_intact(self):
        proj = self.home()
        env = {"HOME": str(proj.parent)}
        ps = [subprocess.Popen([PY, "-B", "-m", "sigilnet", "start", "--wait", "60"], cwd=str(proj), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                               env={**os.environ, "PYTHONPATH": REPO, **env}) for _ in range(2)]
        outs = [p.communicate(timeout=90)[0] for p in ps]
        codes = [p.returncode for p in ps]
        self.assertEqual(sorted(codes), [0, 1], outs)
        rec = json.loads((proj / ".sigilnet" / "node.pid").read_text())
        self.assertTrue(daemon.alive(rec["pid"]))
        self.assertTrue(daemon.is_our_node(proj / ".sigilnet", rec))
        winner = [o for o, c in zip(outs, codes) if c == 0][0]
        self.assertIn(f"pid {rec['pid']}", winner)
        nodes = subprocess.run(["pgrep", "-f", f"sigilnet --home {proj / '.sigilnet'} node run"], capture_output=True, text=True).stdout.split()
        live = [int(x) for x in nodes if daemon.alive(int(x))]
        self.assertEqual(live, [rec["pid"]])

    @unittest.skipIf(SKIP, "open finding F-D (P1): the losing start prints the winner's output")
    def test_the_losing_start_says_already_running_not_a_mix_of_the_winners_output(self):
        proj = self.home()
        env = {"HOME": str(proj.parent)}
        ps = [subprocess.Popen([PY, "-B", "-m", "sigilnet", "start", "--wait", "60"], cwd=str(proj), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                               env={**os.environ, "PYTHONPATH": REPO, **env}) for _ in range(2)]
        outs = [p.communicate(timeout=90)[0] for p in ps]
        loser = [o for o, p in zip(outs, ps) if p.returncode != 0][0]
        self.assertIn("already running", loser)
        self.assertNotIn("serving sync", loser)                                    # not the other node's stdout

    @unittest.skipIf(SKIP, "open finding F-C (P1): the status probe takes the node lock")
    def test_a_status_probe_never_makes_a_start_fail(self):
        proj = self.home()
        home = (proj / ".sigilnet").absolute()
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                daemon.lock_held(home)                                            # what `status`, `stop` and `start` do, many times a second

        th = threading.Thread(target=hammer)
        th.start()
        fails = []
        try:
            for i in range(10):
                buf = []
                rc = daemon.start(home, wait=30, out=buf.append)
                if rc != 0:
                    fails.append(buf[-1][:120])
                daemon.stop(home, out=lambda s: None)
        finally:
            stop.set()
            th.join()
        self.assertEqual(fails, [], "a status probe made a real start fail (flock probe vs the node's non-blocking lock)")

    @unittest.skipIf(SKIP, "open finding F-C (P1): the status probe takes the node lock")
    def test_a_running_node_is_never_reported_stopped_or_unknown_by_a_concurrent_probe(self):
        proj = self.home()
        home = (proj / ".sigilnet").absolute()
        self.assertEqual(daemon.start(home, wait=60, out=lambda s: None), 0)
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                daemon.lock_held(home)

        ths = [threading.Thread(target=hammer) for _ in range(3)]
        [t.start() for t in ths]
        bad = []
        try:
            for _ in range(300):
                line = daemon.status_lines(home)[0]
                if not line.startswith("node: running (pid"):
                    bad.append(line[:80])
        finally:
            stop.set()
            [t.join() for t in ths]
        self.assertEqual(bad[:3], [], f"{len(bad)} of 300 status reads said something else than running")


if __name__ == "__main__":
    unittest.main()
