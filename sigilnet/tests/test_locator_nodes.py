"""Finding PF-1 as an automated test with REAL background nodes (tcp carrier on loopback aliases): one node gets a new IP, restarts, tells its peer, and the peer follows it with no human
and no hand-edited file. Also `ping` through the locator-aware dialer. (`bind: auto` itself needs a real private address and is covered by the unit tests with injected interfaces.)"""
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


class RealNodes(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.h = {"a": self.tmp / "a", "b": self.tmp / "b"}
        self.ip = {"a": "127.0.0.2", "b": "127.0.0.3"}
        self.addCleanup(self.reap)
        base = {n: cli._free_range(random.randint(20000, 55000), 128, ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]) for n in "ab"}
        self.base = base
        for n in "ab":
            rc, out, err = run_cli("--home", str(self.h[n]), "init", "agent" + n, "--carrier", "tcp", "--bind", self.ip[n], "--tcp-port-base", str(base[n]))
            self.assertEqual(rc, 0, err)
        self.id = {n: self.cli(n, "id", "show", "--json")[1] for n in "ab"}
        self.id = {n: json.loads(v)["agent"] for n, v in self.id.items()}
        (self.tmp / "b.pub").write_text(self.cli("b", "id", "show", "--json")[1])
        rc, out, err = self.cli("a", "new", "locator nodes", "--member", f"member={self.tmp / 'b.pub'}")
        self.assertEqual(rc, 0, err)
        self.tid = re.search(r"thread ([0-9a-f]{32})", out).group(1)
        # peering both ways, by hand (the capsule flow is tested elsewhere): each side authorizes the other's client key at a door of its own
        for me, other in (("a", "b"), ("b", "a")):
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

    def start(self, n):
        return daemon.start(self.h[n], wait=60, out=lambda s: None)

    def stop(self, n):
        return daemon.stop(self.h[n], out=lambda s: None)

    def reap(self):
        for n in "ab":
            rec = daemon.read_pid(self.h[n])
            if rec and daemon.alive(rec["pid"]):
                try:
                    os.kill(rec["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def has(self, n, text):
        return text in self.cli(n, "show", self.tid)[1]

    def history(self, n):
        p = self.h[n] / "history.log"
        return p.read_text() if p.exists() else ""

    def test_a_peer_that_gets_a_new_ip_is_followed_without_a_human(self):
        self.assertEqual(self.start("a"), 0)
        self.assertEqual(self.start("b"), 0)
        self.cli("a", "post", self.tid, "one")
        until(lambda: self.has("b", "one"), "b receives the first post")
        # a told b its address at start: the book of a holds one address for b
        until(lambda: "told our address" in self.history("b"), "b announced its (unchanged) address to a")
        old = json.loads((self.h["a"] / "peers.json").read_text())["peers"][self.id["b"]]["endpoints"][0]["addr"]
        self.assertTrue(old.startswith("127.0.0.3:"))
        # b is restarted with a NEW address (what a container restart with a new IP does)
        self.assertEqual(self.stop("b"), 0)
        cfg = json.loads((self.h["b"] / "node_config.json").read_text())
        cfg["tcp"]["bind"] = "127.0.0.4"
        (self.h["b"] / "node_config.json").write_text(json.dumps(cfg))
        self.assertEqual(self.start("b"), 0)
        self.cli("b", "post", self.tid, "two (after the move)")
        until(lambda: "new address adopted" in self.history("a"), "a adopts the address b announced", timeout=60)
        until(lambda: self.has("a", "two (after the move)"), "a receives the post from the new address", timeout=60)
        rc, out, err = self.cli("a", "peer", "list")
        lines = out.strip().splitlines()
        self.assertTrue(any("127.0.0.4:" in l and "tcp" in l for l in lines[:1]), out)       # the new address is the one dialed first
        self.assertTrue(any("also tcp" in l and "127.0.0.3:" in l for l in lines[1:]), out)    # the old one is kept as a fallback
        self.assertNotIn("127.0.0.4", self.history("a"))                                       # no address in the history log
        rc, out, err = self.cli("a", "ping", self.id["b"][:8], "--timeout", "20")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("pong from", out)

    def test_a_damaged_held_json_does_not_stop_the_node_from_starting(self):
        """Sansa F3: the migration of credentials to node ids must never be what keeps a node down; before the locator book a damaged held.json only broke dials."""
        (self.h["a"] / "tcp" / "held.json").write_text("{broken")
        self.assertEqual(self.start("a"), 0)
        until(lambda: "held.json damaged" in self.history("a"), "the node says so and runs on")
        rc, out, err = self.cli("a", "status")
        self.assertEqual(rc, 0, err)
        self.assertIn("node: running", out)

    def test_both_nodes_moving_needs_the_human_to_relay_the_addresses(self):
        self.assertEqual(self.start("a"), 0)
        self.assertEqual(self.start("b"), 0)
        self.cli("a", "post", self.tid, "one")
        until(lambda: self.has("b", "one"), "b receives the first post")
        self.stop("a")
        self.stop("b")
        newip = {"a": "127.0.0.5", "b": "127.0.0.6"}
        for n in "ab":
            cfg = json.loads((self.h[n] / "node_config.json").read_text())
            cfg["tcp"]["bind"] = newip[n]
            (self.h[n] / "node_config.json").write_text(json.dumps(cfg))
        self.start("a")
        self.start("b")
        self.cli("b", "post", self.tid, "two")
        time.sleep(4)
        self.assertFalse(self.has("a", "two"))                                                # nobody can reach anybody
        for n, other in (("a", "b"), ("b", "a")):
            rc, out, err = self.cli(n, "peer", "move", other, "--ip", newip[other])
            self.assertEqual(rc, 0, err + out)
            self.assertIn("verified", out)
        until(lambda: self.has("a", "two"), "after the two `peer move` commands the posts flow again", timeout=90)


if __name__ == "__main__":
    unittest.main()
