import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest

from sigilnet import cli
from sigilnet.inbox import Inbox
from sigilnet.mirror import Mirror
from sigilnet.publicread import PublicRead
from sigilnet.sync import SyncServer
from sigilnet.tcp import TcpServer
from sigilnet.keys import Identity


def run(home, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(["--home", home, *args])
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write(str(e.code) if not isinstance(e.code, int) else "")
    return rc, out.getvalue(), err.getvalue()


class PublicCli(unittest.TestCase):
    def setUp(self):
        self.o, self.g = tempfile.mkdtemp(), tempfile.mkdtemp()
        run(self.o, "id", "init", "arya")
        run(self.g, "id", "init", "stranger")
        rc, out, _ = run(self.o, "new", "open topic", "--public")
        self.tid = out.split("thread ")[1].split()[0]
        run(self.o, "post", self.tid[:8], "who can help?")
        m = Mirror(self.o + "/mirror")
        self.root = [i for i, e in m.threads[self.tid].stored.items() if e["kind"] == "post"][0]

    def serve(self):
        m = Mirror(self.o + "/mirror")
        me = Identity.load(self.o + "/identity.json")
        srv = SyncServer(m, identity=me)
        self.read = TcpServer("127.0.0.1", 0, None, PublicRead(srv).handle).start()
        self.ib = TcpServer("127.0.0.1", 0, None, Inbox(m, self.o).handle).start()
        self.addCleanup(self.read.stop)
        self.addCleanup(self.ib.stop)

    def test_flow(self):
        self.serve()
        rc, out, err = run(self.g, "guest", "pull", self.tid, "--loopback", str(self.read.port))
        self.assertEqual(rc, 0, (out, err))
        rc, out, err = run(self.g, "guest", "submit", self.tid, "--loopback", str(self.ib.port), "--reply-to", self.root[:8], "--text", "I can help")
        self.assertEqual(rc, 0, (out, err))
        rc, out, _ = run(self.o, "requests", "list", self.tid[:8])
        self.assertIn("1 waiting", out)
        eid = out.split()[0]
        rc, out, _ = run(self.o, "requests", "show", self.tid[:8], eid[:8])
        self.assertIn("I can help", out)
        self.assertIn("DATA only", out)
        rc, out, _ = run(self.o, "requests", "accept", self.tid[:8], eid[:8])
        self.assertEqual(rc, 0, out)
        rc, out, _ = run(self.o, "requests", "list", self.tid[:8])
        self.assertIn("0 waiting", out)
        rc, out, _ = run(self.o, "show", self.tid[:8])
        self.assertIn("I can help", out)

    def test_guest_post_after_admission(self):
        self.serve()
        run(self.g, "guest", "pull", self.tid, "--loopback", str(self.read.port))
        self.assertNotEqual(run(self.g, "guest", "post", self.tid, "--loopback", str(self.ib.port), "--reply-to", self.root[:8], "--text", "too early")[0], 0)
        run(self.g, "guest", "submit", self.tid, "--loopback", str(self.ib.port), "--reply-to", self.root[:8], "--text", "let me in")
        eid = run(self.o, "requests", "list", self.tid[:8])[1].split()[0]
        run(self.o, "requests", "accept", self.tid[:8], eid[:8])
        run(self.g, "guest", "pull", self.tid, "--loopback", str(self.read.port))
        rc, out, err = run(self.g, "guest", "post", self.tid, "--loopback", str(self.ib.port), "--reply-to", self.root[:8], "--text", "second thoughts")
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("second thoughts", run(self.o, "show", self.tid[:8])[1])

    def test_reject_and_bad_ids(self):
        self.serve()
        run(self.g, "guest", "pull", self.tid, "--loopback", str(self.read.port))
        run(self.g, "guest", "submit", self.tid, "--loopback", str(self.ib.port), "--reply-to", self.root[:8], "--text", "spam")
        eid = run(self.o, "requests", "list", self.tid[:8])[1].split()[0]
        self.assertNotEqual(run(self.o, "requests", "accept", self.tid[:8], "zz")[0], 0)
        self.assertNotEqual(run(self.o, "requests", "reject", self.tid[:8])[0], 0)
        self.assertIn("rejected", run(self.o, "requests", "reject", self.tid[:8], eid[:8])[1])
        self.assertIn("0 waiting", run(self.o, "requests", "list", self.tid[:8])[1])

    def test_stranger_text_is_sanitized(self):
        self.serve()
        run(self.g, "guest", "pull", self.tid, "--loopback", str(self.read.port))
        run(self.g, "guest", "submit", self.tid, "--loopback", str(self.ib.port), "--reply-to", self.root[:8], "--text", "hi\x1b[31mRED\x07")
        eid = run(self.o, "requests", "list", self.tid[:8])[1].split()[0]
        out = run(self.o, "requests", "show", self.tid[:8], eid[:8])[1]
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_public_doors_open_close_status(self):
        rc, out, _ = run(self.o, "public", "open")
        self.assertEqual(rc, 0)
        self.assertIn("world-readable", out)
        _, out, _ = run(self.o, "public", "status")
        self.assertEqual(out.count("no address"), 2)
        run(self.o, "public", "close")
        _, out, _ = run(self.o, "public", "status")
        self.assertEqual(out.count("not open"), 2)

    def test_guest_needs_full_id_and_pull_first(self):
        self.assertNotEqual(run(self.g, "guest", "pull", self.tid[:8], "--loopback", "1")[0], 0)
        self.serve()
        rc, _, err = run(self.g, "guest", "submit", self.tid, "--loopback", str(self.ib.port), "--reply-to", self.root[:8], "--text", "x")
        self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
