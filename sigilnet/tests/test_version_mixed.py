"""Two REAL background nodes, one running the PARENT tree (the deployed 0.1.x code, tag r49q_merged) and one running this tree, on tcp loopback aliases: the mixed-version case of
a rolling deploy. Posts both ways, both pings, `peer list` on both: the new node records the old one as `legacy`, the old node carries on as before (stage 1 of
DESIGN_versioning.md: nothing is refused, nothing changes on the 0.1.x wire)."""
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sigilnet import cli
from sigilnet import version as V

from .test_version import parent_tree


def until(fn, what, timeout=90.0, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    raise AssertionError("timed out: " + what)


class MixedNodes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = parent_tree()
        if cls.old is None:
            raise unittest.SkipTest("the parent tree is not available (git archive)")
        cls.new = str(Path(__file__).resolve().parents[2])

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "old", None):
            shutil.rmtree(cls.old, True)

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.h = {"o": self.tmp / "old", "n": self.tmp / "new"}          # o = the 0.1.x node, n = this tree's node
        self.tree = {"o": str(self.old), "n": self.new}
        self.ip = {"o": "127.0.0.2", "n": "127.0.0.3"}
        self.addCleanup(self.reap)
        base = {k: cli._free_range(random.randint(20000, 55000), 128, list(self.ip.values())) for k in "on"}
        for k in "on":
            rc, out, err = self.cli(k, "init", "agent" + k, "--carrier", "tcp", "--bind", self.ip[k], "--tcp-port-base", str(base[k]))
            self.assertEqual(rc, 0, err)
        self.id = {k: json.loads(self.cli(k, "id", "show", "--json")[1])["agent"] for k in "on"}
        (self.tmp / "n.pub").write_text(self.cli("n", "id", "show", "--json")[1])
        rc, out, err = self.cli("o", "new", "mixed", "--member", f"member={self.tmp / 'n.pub'}")
        self.assertEqual(rc, 0, err)
        self.tid = re.search(r"thread ([0-9a-f]{32})", out).group(1)
        for me, other in (("o", "n"), ("n", "o")):
            rc, out, err = self.cli(other, "node", "auth", "key" + me)
            self.assertEqual(rc, 0, err)
            pub = out.strip().splitlines()[-1].strip()
            rc, out, err = self.cli(me, "node", "authorize", other, pub, "--agent", self.id[other])
            self.assertEqual(rc, 0, err)
            rc, out, err = self.cli(me, "node", "address", other)
            addr = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+#[0-9a-f]{64})", out).group(1)
            rc, out, err = self.cli(other, "peer", "add", me, self.id[me], "--endpoint", "tcp:" + addr, "--key", "key" + me, "--thread", self.tid)
            self.assertEqual(rc, 0, err)

    def cli(self, k, *args):
        """Every command of node k runs in ITS tree (a subprocess with that tree on the path)."""
        env = dict(os.environ, PYTHONPATH=self.tree[k], PYTHONDONTWRITEBYTECODE="1")
        p = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(self.h[k]), *args], capture_output=True, text=True, env=env, timeout=180, cwd=str(self.tmp))
        return p.returncode, p.stdout, p.stderr

    def reap(self):
        for k in "on":
            try:
                pid = json.loads((self.h[k] / "node.pid").read_text()).get("pid") if (self.h[k] / "node.pid").exists() else None
            except (OSError, ValueError):
                pid = None
            if isinstance(pid, int):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_old_and_new_nodes_sync_ping_and_list_each_other(self):
        for k in "on":
            rc, out, err = self.cli(k, "start")
            self.assertEqual(rc, 0, out + err)
        self.cli("o", "post", self.tid, "from the old node")
        until(lambda: "from the old node" in self.cli("n", "show", self.tid)[1], "the new node pulls the old node's post")
        self.cli("n", "post", self.tid, "from the new node")
        until(lambda: "from the new node" in self.cli("o", "show", self.tid)[1], "the old node gets the new node's post (its pull, or the notify)")
        # the new node recorded what it learned: the old peer declares nothing = legacy
        def legacy():
            try:
                e = json.loads((self.h["n"] / "peerver.json").read_text())["peers"].get(self.id["o"])
            except (OSError, ValueError, KeyError):
                return None
            return e if e and e.get("legacy") is True else None
        until(legacy, "the new node records the old node as legacy")
        rc, out, err = self.cli("n", "peer", "list")
        self.assertEqual(rc, 0, err)
        self.assertIn("wire 0 (0.1.x or older: it declares nothing)", out)
        rc, out, err = self.cli("o", "peer", "list")                       # the old node's own CLI is untouched
        self.assertEqual(rc, 0, err)
        self.assertNotIn("wire", out)
        # both pings work: new -> old (the request carries `ver`, ignored) and old -> new (an old asker gets the exact old pong)
        rc, out, err = self.cli("n", "ping", "o")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("sigilnet", out.split("rtt")[-1])                 # (the old peer declares nothing: no version suffix)
        rc, out, err = self.cli("o", "ping", "n")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("pong from", out)
        # no node logged an error about the other
        for k in "on":
            log = (self.h[k] / "history.log").read_text()
            self.assertNotIn("bad answer", log)
            self.assertNotIn("malformed request", log)


if __name__ == "__main__":
    unittest.main()
