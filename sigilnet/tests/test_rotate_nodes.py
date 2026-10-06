"""`sigilnet rotate` between two REAL background nodes (tcp carrier on loopback aliases): the owner rotates a private (encrypted) thread; the other member's node does NOT get the new
thread until `peer invite` (a node pulls only threads it was told about), and after it gets the thread, its key, the first post and then ordinary traffic both ways."""
import contextlib
import io
import json
import os
import random
import re
import shutil
import signal
import tempfile
import time
import unittest
import warnings
from pathlib import Path

from sigilnet import cli, daemon


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write("" if isinstance(e.code, int) or e.code is None else str(e.code))
    return rc, out.getvalue(), err.getvalue()


def until(fn, what, timeout=90.0, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    raise AssertionError("timed out: " + what)


class RotateBetweenNodes(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.h = {"a": self.tmp / "a", "b": self.tmp / "b"}
        self.ip = {"a": "127.0.0.2", "b": "127.0.0.3"}
        self.addCleanup(self.reap)
        base = {n: cli._free_range(random.randint(20000, 55000), 128, ["127.0.0.2", "127.0.0.3"]) for n in "ab"}
        for n in "ab":
            rc, out, err = run_cli("--home", str(self.h[n]), "init", "agent" + n, "--carrier", "tcp", "--bind", self.ip[n], "--tcp-port-base", str(base[n]))
            self.assertEqual(rc, 0, err)
        self.id = {n: json.loads(self.cli(n, "id", "show", "--json")[1])["agent"] for n in "ab"}
        (self.tmp / "b.pub").write_text(self.cli("b", "id", "show", "--json")[1])
        rc, out, err = self.cli("a", "new", "rotation nodes", "--member", f"member={self.tmp / 'b.pub'}")
        self.assertEqual(rc, 0, err)
        self.tid = re.search(r"thread ([0-9a-f]{32})", out).group(1)
        for me, other in (("a", "b"), ("b", "a")):                       # peering both ways, by hand (the capsule flow is tested elsewhere)
            rc, out, err = self.cli(other, "node", "auth", "key" + me)
            self.assertEqual(rc, 0, err)
            pub = out.strip().splitlines()[-1].strip()
            rc, out, err = self.cli(me, "node", "authorize", other, pub, "--agent", self.id[other])
            self.assertEqual(rc, 0, err)
            rc, out, err = self.cli(me, "node", "address", other)
            addr = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+#[0-9a-f]{64})", out).group(1)
            rc, out, err = self.cli(other, "peer", "add", me, self.id[me], "--endpoint", "tcp:" + addr, "--key", "key" + me, "--thread", self.tid)
            self.assertEqual(rc, 0, err)

    def cli(self, n, *args):
        return run_cli("--home", str(self.h[n]), *args)

    def reap(self):
        for n in "ab":
            rec = daemon.read_pid(self.h[n])
            if rec and daemon.alive(rec["pid"]):
                try:
                    os.kill(rec["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def shows(self, n, tid, text):
        rc, out, err = self.cli(n, "show", tid)
        return rc == 0 and text in out

    def test_the_other_node_follows_the_new_thread_only_after_peer_invite(self):
        self.assertEqual(daemon.start(self.h["a"], wait=60, out=lambda s: None), 0)
        self.assertEqual(daemon.start(self.h["b"], wait=60, out=lambda s: None), 0)
        self.cli("a", "post", self.tid, "before the rotation")
        until(lambda: self.shows("b", self.tid, "before the rotation"), "b receives the old thread")
        rc, out, err = self.cli("a", "rotate", self.tid)
        self.assertEqual(rc, 0, err)
        new = re.search(r"the new thread is ([0-9a-f]{32})", out).group(1)
        self.assertIn(f"sigilnet peer invite {self.id['a']} --thread {new}", out)
        # the pointer reaches b in the OLD thread (it is an ordinary post there)
        until(lambda: self.shows("b", self.tid, "[ROTATED-TO] " + new), "b reads the pointer in the old thread")
        time.sleep(12)                                                                   # several node rounds: without the invitation b must NOT get the new thread
        self.assertNotIn(new[:8], self.cli("b", "list")[1])
        rc, out, err = self.cli("b", "peer", "invite", self.id["a"], "--thread", new)
        self.assertEqual(rc, 0, err)
        until(lambda: self.shows("b", new, "[ROTATED-FROM] " + self.tid), "b fetches the new thread and its key, and can read the first post", timeout=90)
        self.assertIn("ENCRYPTED", self.cli("b", "envelope", "status")[1])
        # ordinary traffic both ways in the new thread; the old one is still readable
        self.cli("b", "post", new, "hello from b in the new thread")
        until(lambda: self.shows("a", new, "hello from b in the new thread"), "a receives b's post in the new thread")
        self.cli("a", "post", new, "hello from a in the new thread")
        until(lambda: self.shows("b", new, "hello from a in the new thread"), "b receives a's post in the new thread")
        rc, out, err = self.cli("b", "unread", new)
        self.assertIn("hello from a", out)
        self.assertTrue(self.shows("b", self.tid, "before the rotation"))


if __name__ == "__main__":
    unittest.main()
