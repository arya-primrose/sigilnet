"""Addressing between two REAL background nodes (tcp carrier on loopback aliases): a signed `to` crosses the wire and is shown as `-> you` on the other side; a reply gets the default `to`;
a post without `to` is a broadcast; `@name` mentions are rewritten to ids and annotated with the name on the reader's side."""
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


class AddressingBetweenNodes(unittest.TestCase):
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
        rc, out, err = self.cli("a", "new", "addressing nodes", "--member", f"member={self.tmp / 'b.pub'}")
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

    def test_to_crosses_the_wire_and_replies_default_to_the_author(self):
        self.assertEqual(daemon.start(self.h["a"], wait=60, out=lambda s: None), 0)
        self.assertEqual(daemon.start(self.h["b"], wait=60, out=lambda s: None), 0)
        rc, out, err = self.cli("a", "post", self.tid, "plain broadcast")
        self.assertEqual(rc, 0, err)
        rc, out, err = self.cli("a", "post", self.tid, "b, please look at this with @agentb", "--to", "agentb")
        self.assertEqual(rc, 0, err)
        self.assertIn("mention @agentb ->", out)
        until(lambda: self.shows("b", self.tid, "please look at this"), "b receives the addressed post")
        rc, unread, err = self.cli("b", "unread", self.tid)
        lines = {l.split(": ", 1)[1].split("'")[1][:12]: l for l in unread.strip().splitlines() if ": " in l}
        self.assertIn("agenta -> you (post):", lines["b, please lo"])
        self.assertNotIn("->", lines["plain broadc"])
        self.assertIn("(agentb)", lines["b, please lo"])                                 # the mention is annotated with the name on the reader's side
        # b replies to the addressed post: the default `to` is its author (a)
        post = [i for i in self.ids_of("b") if self.text_of("b", i).startswith("b, please")][0]
        rc, out, err = self.cli("b", "post", self.tid, "on it", "--reply-to", post)
        self.assertEqual(rc, 0, err)
        until(lambda: self.shows("a", self.tid, "on it"), "a receives the reply")
        rc, unread, err = self.cli("a", "unread", self.tid)
        self.assertIn("agentb -> you (post):", unread)
        # an observer-style address is refused and nothing is sent
        rc, out, err = self.cli("a", "post", self.tid, "x", "--to", "nobody")
        self.assertNotEqual(rc, 0)

    def ids_of(self, n):
        rc, out, err = self.cli(n, "export", self.tid)
        return [json.loads(l)["body"].get("text") and __import__("sigilnet.event", fromlist=["x"]).event_id(json.loads(l)) for l in out.splitlines() if l.strip() and json.loads(l)["kind"] == "post"]

    def text_of(self, n, eid):
        rc, out, err = self.cli(n, "export", self.tid)
        for l in out.splitlines():
            ev = json.loads(l)
            if ev["kind"] == "post" and __import__("sigilnet.event", fromlist=["x"]).event_id(ev) == eid:
                return ev["body"]["text"]
        return ""


if __name__ == "__main__":
    unittest.main()
