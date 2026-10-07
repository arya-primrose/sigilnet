"""Two REAL background nodes (tcp on loopback aliases): each learns the other's declaration (`ver`) from a pull it makes and from a pull it answers, writes it to peerver.json, and
`peer list` shows it (stage 1 of DESIGN_versioning.md)."""
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
from sigilnet import version as V


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


class TwoNodes(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.names = "ab"
        self.h = {n: self.tmp / n for n in self.names}
        self.ip = {"a": "127.0.0.2", "b": "127.0.0.3"}
        self.addCleanup(self.reap)
        base = {n: cli._free_range(random.randint(20000, 55000), 128, list(self.ip.values())) for n in self.names}
        for n in self.names:
            rc, out, err = run_cli("--home", str(self.h[n]), "init", "agent" + n, "--carrier", "tcp", "--bind", self.ip[n], "--tcp-port-base", str(base[n]))
            self.assertEqual(rc, 0, err)
        self.id = {n: json.loads(self.cli(n, "id", "show", "--json")[1])["agent"] for n in self.names}
        (self.tmp / "b.pub").write_text(self.cli("b", "id", "show", "--json")[1])
        rc, out, err = self.cli("a", "new", "version nodes", "--member", f"member={self.tmp / 'b.pub'}")
        self.assertEqual(rc, 0, err)
        self.tid = re.search(r"thread ([0-9a-f]{32})", out).group(1)
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

    def reap(self):
        for n in self.names:
            rec = daemon.read_pid(self.h[n])
            if rec and daemon.alive(rec["pid"]):
                try:
                    os.kill(rec["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def declared(self, n, other):
        try:
            e = json.loads((self.h[n] / "peerver.json").read_text())["peers"].get(self.id[other])
        except (OSError, ValueError, KeyError):
            return None
        return e if e and not e.get("legacy") else None

    def test_each_node_learns_the_others_declaration_and_peer_list_shows_it(self):
        for n in self.names:
            self.assertEqual(daemon.start(self.h[n], wait=60, out=lambda s: None), 0)
        self.cli("a", "post", self.tid, "hello")
        until(lambda: "hello" in self.cli("b", "show", self.tid)[1], "b pulls the post")
        eb = until(lambda: self.declared("b", "a"), "b recorded what a declared (from its own pull)")
        ea = until(lambda: self.declared("a", "b"), "a recorded what b declared (from the pull it answered: the server hook)")
        for e in (ea, eb):
            self.assertEqual((e["wire"], e["majors"], e["formats"], e["sw"]), (f"{V.WIRE[0]}.{V.WIRE[1]}", list(V.MAJORS), list(V.FORMATS), V.SW))
        self.assertEqual(oct(os.stat(self.h["a"] / "peerver.json").st_mode & 0o777), "0o600")
        for n in self.names:
            rc, out, err = self.cli(n, "peer", "list")
            self.assertEqual(rc, 0, err)
            self.assertIn(f"wire {V.WIRE[0]}.{V.WIRE[1]} sw {V.SW}", out)
        rc, out, err = self.cli("a", "ping", "b")
        self.assertEqual(rc, 0, out + err)
        self.assertIn(f"sigilnet {V.SW} (wire {V.WIRE[0]}.{V.WIRE[1]})", out)

    def test_a_node_that_never_dials_learns_the_declaration_from_the_pulls_it_answers(self):
        """The server hook alone: A has no address for B (the outbound-only case of M4a: B dials A, A keeps the door it gave B), so A never pulls from B and can only
        learn what B declared from B's own requests."""
        rc, out, err = self.cli("a", "peer", "rm", self.id["b"], "--keep-doors")
        self.assertEqual(rc, 0, err)
        rc, out, err = self.cli("a", "peer", "add", "b", self.id["b"], "--thread", self.tid)
        self.assertEqual(rc, 0, err)
        for n in self.names:
            self.assertEqual(daemon.start(self.h[n], wait=60, out=lambda s: None), 0)
        self.cli("a", "post", self.tid, "hello")
        until(lambda: "hello" in self.cli("b", "show", self.tid)[1], "b pulls the post")
        self.assertEqual(self.cli("a", "peer", "list")[1].count("no endpoint"), 1)
        e = until(lambda: self.declared("a", "b"), "a recorded what b declared although a never dialled b")
        self.assertEqual(e["sw"], V.SW)


if __name__ == "__main__":
    unittest.main()
