"""Two REAL background nodes sync a format-2 thread (encrypted: the envelopes wrap v 2 events), including `x-` events written through the library, and rotate it into a new format-2 thread
that the other node follows by itself. Stage 3 of DESIGN_versioning.md."""
import json
import re
import unittest

from sigilnet import cli, daemon
from sigilnet import event as E
from sigilnet.build import Writer

from .test_version_nodes import TwoNodes as _Base
from .test_version_nodes import until


class Format2Nodes(_Base):
    def cli(self, n, *args):
        if args[:1] == ("new",):
            args = args + ("--format", "2")
        return super().cli(n, *args)

    def mirror(self, n):
        return cli._mirror(self.h[n], self.id[n])

    def test_a_format_2_thread_syncs_with_x_events_and_stays_quiet(self):
        for n in self.names:
            self.assertEqual(daemon.start(self.h[n], wait=60, out=lambda s: None), 0)
        self.assertIn("format 2", self.cli("a", "list")[1])
        self.cli("a", "post", self.tid, "hello")
        until(lambda: "hello" in self.cli("b", "show", self.tid)[1], "b pulls the post of a format-2 thread")
        self.assertIn("format 2", until(lambda: self.cli("b", "list")[1] if "format 2" in self.cli("b", "list")[1] else None, "b lists the thread as format 2"))
        # an x- event and an `x` key, written by a through the library (nothing in the CLI writes them yet)
        ma = self.mirror("a")
        me = cli._identity(self.h["a"])
        w = Writer(me, ma.threads[self.tid])
        r1 = ma.ingest(w.ext("test.1", {"n": 1, "who": "a"}))
        self.assertTrue(r1.ok, (r1.status, r1.reason))
        r2 = ma.ingest(Writer(me, ma.threads[self.tid]).post("with a key", x={"ns": {"k": 1}}))
        self.assertTrue(r2.ok, (r2.status, r2.reason))
        del ma
        def at_b():
            t = self.mirror("b").threads[self.tid]
            return t if any(e["kind"] == "x-test.1" for e in t.stored.values()) and any("x" in e["body"] for e in t.stored.values()) else None
        t = until(at_b, "b holds the x- event and the post with an x key")
        self.assertEqual({e["v"] for e in t.stored.values()}, {2})
        un = self.mirror("b").unread(self.tid, self.id["b"])
        self.assertNotIn("x-test.1", [e["kind"] for e in un])                            # quiet by construction: an extension kind is never unread
        self.assertIn("with a key", [e["body"].get("text") for e in un])
        # and b writes back: its events are v 2 without being told
        self.cli("b", "post", self.tid, "from b")
        until(lambda: "from b" in self.cli("a", "show", self.tid)[1], "a pulls b's post")
        # the thread verifies clean on both
        for n in self.names:
            rc, out, err = self.cli(n, "verify", self.tid)
            self.assertEqual(rc, 0, out + err)

    def test_rotate_keeps_format_2_and_the_other_node_follows(self):
        for n in self.names:
            self.assertEqual(self.cli(n, "node", "follow-rotation", "on")[0], 0)
            self.assertEqual(daemon.start(self.h[n], wait=60, out=lambda s: None), 0)
        self.cli("a", "post", self.tid, "before")
        until(lambda: "before" in self.cli("b", "show", self.tid)[1], "b has the thread")
        # the node and the CLI both hold the mirror: rotate runs in the CLI under the mirror lock, as it does on a live node
        rc, out, err = self.cli("a", "rotate", self.tid)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("thread format 2", out)
        new = re.search(r"new thread is ([0-9a-f]{32})", out).group(1)
        self.cli("b", "peer", "invite", self.id["a"], "--thread", new)           # (the follow by pointer needs the 600 s tick: the hand invitation is what the pointer post asks for)
        until(lambda: new[:8] in self.cli("b", "list")[1], "b holds the new thread", timeout=120)
        self.assertIn("format 2", [l for l in self.cli("b", "list")[1].splitlines() if l.startswith(new[:8])][0])


del _Base

if __name__ == "__main__":
    unittest.main()
