"""Automatic follow of a rotation between three REAL background nodes (tcp on loopback aliases): A owns an ENCRYPTED private thread with members B and C. A has a door to B only, C has a door to B only
(C never talks to A: the third agent's case). A rotates (by hand: the pointer is the same bytes the automatic trigger writes); B and C run `follow-rotation on` and get the new thread, its key and the first post
by themselves, C through B; posts both ways. Without the switch C gets nothing until a hand `peer invite`."""
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
from unittest import mock

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


class ThreeNodes(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        env = mock.patch.dict(os.environ, {"SIGILNET_ROT_TICK": "2"})            # the daemons inherit it: a round every 2 s instead of every 10 minutes
        env.start()
        self.addCleanup(env.stop)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.names = "abc"
        self.h = {n: self.tmp / n for n in self.names}
        self.ip = {"a": "127.0.0.2", "b": "127.0.0.3", "c": "127.0.0.4"}
        self.addCleanup(self.reap)
        base = {n: cli._free_range(random.randint(20000, 55000), 128, list(self.ip.values())) for n in self.names}
        for n in self.names:
            rc, out, err = run_cli("--home", str(self.h[n]), "init", "agent" + n, "--carrier", "tcp", "--bind", self.ip[n], "--tcp-port-base", str(base[n]))
            self.assertEqual(rc, 0, err)
        self.id = {n: json.loads(self.cli(n, "id", "show", "--json")[1])["agent"] for n in self.names}
        for n in "bc":
            (self.tmp / f"{n}.pub").write_text(self.cli(n, "id", "show", "--json")[1])
        rc, out, err = self.cli("a", "new", "three nodes", "--member", f"member={self.tmp / 'b.pub'}", "--member", f"member={self.tmp / 'c.pub'}")
        self.assertEqual(rc, 0, err)
        self.tid = re.search(r"thread ([0-9a-f]{32})", out).group(1)
        for me, other in (("a", "b"), ("b", "a"), ("b", "c"), ("c", "b")):          # who can dial whom: A<->B and B<->C, never A<->C
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
        for n in self.names:
            rec = daemon.read_pid(self.h[n])
            if rec and daemon.alive(rec["pid"]):
                try:
                    os.kill(rec["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def shows(self, n, tid, text):
        rc, out, err = self.cli(n, "show", tid)
        return rc == 0 and text in out

    def start_all(self):
        for n in self.names:
            self.assertEqual(daemon.start(self.h[n], wait=60, out=lambda s: None), 0)

    def rotate(self):
        self.cli("a", "post", self.tid, "before the rotation")
        until(lambda: self.shows("c", self.tid, "before the rotation"), "c gets the old thread through b")
        rc, out, err = self.cli("a", "rotate", self.tid)
        self.assertEqual(rc, 0, err)
        return re.search(r"the new thread is ([0-9a-f]{32})", out).group(1)

    def test_b_and_c_follow_the_rotation_by_themselves_c_through_b(self):
        for n in "bc":
            rc, out, err = self.cli(n, "node", "follow-rotation", "on")
            self.assertEqual(rc, 0, err)
        self.start_all()
        self.assertIn("rotation: auto_rotate off, follow_rotation on", (self.h["b"] / "history.log").read_text())
        self.assertIn("rotation: auto_rotate off, follow_rotation on", (self.h["c"] / "history.log").read_text())
        self.assertIn("rotation: auto_rotate off, follow_rotation off", (self.h["a"] / "history.log").read_text())      # the owner never asked for either
        new = self.rotate()
        until(lambda: self.shows("b", new, "[ROTATED-FROM] " + self.tid), "b follows the pointer, gets the new thread, its key and the first post", timeout=120)
        until(lambda: self.shows("c", new, "[ROTATED-FROM] " + self.tid), "c gets the new thread THROUGH b (it has no door to the owner)", timeout=120)
        self.assertIn("ENCRYPTED", self.cli("c", "envelope", "status")[1])
        self.cli("c", "post", new, "hello from c in the new thread")
        until(lambda: self.shows("a", new, "hello from c in the new thread"), "a receives c's post (through b)")
        self.cli("a", "post", new, "hello from a in the new thread")
        until(lambda: self.shows("c", new, "hello from a in the new thread"), "c receives a's post (through b)")
        # the follows were verified: no automatic mark is left in either peer book, the invitation stays
        def settled(n):
            raw = json.loads((self.h[n] / "peers.json").read_text())["peers"]
            return all("auto" not in rec for rec in raw.values()) and any(new in rec.get("threads", []) for rec in raw.values())
        until(lambda: settled("b") and settled("c"), "the automatic follows were verified and settled", timeout=60)
        self.assertEqual(oct(os.stat(self.h["b"] / "rotation.json").st_mode & 0o777) if (self.h["b"] / "rotation.json").exists() else "0o600", "0o600")
        self.assertTrue(self.shows("c", self.tid, "before the rotation"))                # the old thread is still readable

    def test_without_the_switch_c_gets_nothing_until_a_hand_invitation(self):
        rc, out, err = self.cli("b", "node", "follow-rotation", "on")                     # b follows, c does not
        self.assertEqual(rc, 0, err)
        self.start_all()
        self.assertIn("rotation: auto_rotate off, follow_rotation off", (self.h["c"] / "history.log").read_text())      # c: the defaults
        new = self.rotate()
        until(lambda: self.shows("b", new, "[ROTATED-FROM] " + self.tid), "b follows by itself", timeout=120)
        until(lambda: self.shows("c", self.tid, "[ROTATED-TO] " + new), "c reads the pointer in the old thread")
        time.sleep(10)                                                                    # several rounds
        self.assertNotIn(new[:8], self.cli("c", "list")[1])
        rc, out, err = self.cli("c", "peer", "invite", self.id["b"], "--thread", new)
        self.assertEqual(rc, 0, err)
        until(lambda: self.shows("c", new, "[ROTATED-FROM] " + self.tid), "c gets it after the hand invitation", timeout=120)


if __name__ == "__main__":
    unittest.main()
