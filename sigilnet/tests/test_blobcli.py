"""`post --attach`, `blob ls|get|rm`, the want queue and the node's blob worker, in-process (no tor, no sockets)."""
import contextlib
import io
import os
import random
import stat
import tempfile
import unittest
from pathlib import Path

from sigilnet import blob as B
from sigilnet import blobauthor  # noqa: F401  (imported before any test patches envelope.epoch_id_at: it binds the name at import)
from sigilnet import blobfetch as F
from sigilnet import cli
from sigilnet import sync as S
from sigilnet.blobindex import BlobIndex
from sigilnet.blobserve import BlobService
from sigilnet.blobstore import BlobStore
from sigilnet.blobwant import MAX_WANTS, Wants
from sigilnet.blobworker import BlobWorker
from sigilnet.envelope import EnvCodec
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror


def run(home, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(["--home", home, *args])
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write(str(e.code) if not isinstance(e.code, int) else "")
    return rc, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    public = False

    def setUp(self):
        self.h = tempfile.mkdtemp()
        self.d = Path(tempfile.mkdtemp())
        run(self.h, "id", "init", "arya")
        rc, out, _ = run(self.h, "new", "notes", *(["--public"] if self.public else []))
        self.tid = out.split("thread ")[1].split()[0]

    def f(self, data, name="a.bin"):
        p = self.d / name
        p.write_bytes(data)
        return str(p)


class Encrypted(Cli):
    def test_attach_show_ls_get_rm(self):
        data = os.urandom(150000)
        rc, out, err = run(self.h, "post", self.tid[:8], "see file", "--attach", self.f(data))
        self.assertEqual(rc, 0, err)
        cid = B.cid_of(Path(self.h, "blobs", "objects", "x").parent.parent.parent.joinpath("x").name.encode()) if False else out.split("attached ")[1].split()[0]
        _, shown, _ = run(self.h, "show", self.tid[:8])
        self.assertIn("[attachment " + cid[:15], shown)
        self.assertNotIn(cid, shown, "only a prefix is shown")
        rc, ls, _ = run(self.h, "blob", "ls", self.tid[:8])
        self.assertIn(cid, ls)
        self.assertIn("HELD", ls)
        self.assertIn("authored", ls)
        outp = str(self.d / "got.bin")
        rc, out, err = run(self.h, "blob", "get", self.tid[:8], cid[:20], "--out", outp)
        self.assertEqual(rc, 0, err)
        self.assertEqual(Path(outp).read_bytes(), data)
        self.assertEqual(stat.S_IMODE(os.stat(outp).st_mode), 0o600)
        rc, _, err = run(self.h, "blob", "get", self.tid[:8], cid, "--out", outp)
        self.assertNotEqual(rc, 0)
        self.assertIn("already exists", err)
        self.assertEqual(run(self.h, "blob", "rm", cid)[1].strip(), "removed")
        self.assertEqual(run(self.h, "blob", "rm", cid)[1].strip(), "not in the store")
        self.assertIn("not fetched", run(self.h, "blob", "ls", self.tid[:8])[1])

    def test_get_of_a_blob_we_do_not_hold_queues_a_want_and_fails_with_the_workers_reason(self):
        rc, out, _ = run(self.h, "post", self.tid[:8], "x", "--attach", self.f(b"abc" * 100))
        cid = out.split("attached ")[1].split()[0]
        run(self.h, "blob", "rm", cid)
        outp = str(self.d / "o")
        rc, out, err = run(self.h, "blob", "get", self.tid[:8], cid, "--out", outp)
        self.assertEqual(rc, 0)
        self.assertIn("queued", out)
        w = Wants(Path(self.h) / "blobs")
        self.assertEqual([d["cid"] for d in w.pending()], [cid])
        import threading
        threading.Timer(1.0, lambda: w.finish(cid, False, "no peer shares this thread")).start()
        rc, out, err = run(self.h, "blob", "get", self.tid[:8], cid, "--out", outp, "--wait", "10")
        self.assertNotEqual(rc, 0)
        self.assertIn("no peer shares", err)

    def test_a_failure_on_the_second_file_says_the_first_stays_stored(self):
        rc, out, err = run(self.h, "post", self.tid[:8], "x", "--attach", self.f(b"one"), "--attach", str(self.d / "missing"))
        self.assertNotEqual(rc, 0)
        self.assertIn("already stored", err)

    def test_attach_errors_post_nothing(self):
        for args, msg in (((self.d / "missing",), "cannot open"), ((self.d,), "not a regular file")):
            rc, out, err = run(self.h, "post", self.tid[:8], "x", "--attach", str(args[0]))
            self.assertNotEqual(rc, 0)
            self.assertIn(msg, err)
        self.assertEqual(len(run(self.h, "show", self.tid[:8])[1].splitlines()), 1, "nothing was posted")
        rc, _, err = run(self.h, "post", self.tid[:8], "x", *sum((["--attach", self.f(b"1", f"{i}")] for i in range(17)), []))
        self.assertNotEqual(rc, 0)
        self.assertIn("at most 16", err)

    def test_a_key_rotation_while_sealing_is_caught_before_posting(self):
        import sigilnet.envelope as V
        real = V.epoch_id_at
        V.epoch_id_at = lambda tt, a: "ab" * 16                      # (blobauthor sealed under the real epoch; the CLI's re-check sees another one)
        try:
            rc, out, err = run(self.h, "post", self.tid[:8], "x", "--attach", self.f(b"abc"))
        finally:
            V.epoch_id_at = real
        self.assertNotEqual(rc, 0)
        self.assertIn("epoch changed", err)
        self.assertEqual(len(run(self.h, "show", self.tid[:8])[1].splitlines()), 1, "nothing was posted")

    def test_blob_get_refuses_unknown_and_ambiguous_cids(self):
        rc, out, _ = run(self.h, "post", self.tid[:8], "x", "--attach", self.f(b"one"))
        rc, _, err = run(self.h, "blob", "get", self.tid[:8], B.cid_of(b"never"), "--out", str(self.d / "o"))
        self.assertNotEqual(rc, 0)
        self.assertIn("not referenced", err)
        rc, _, err = run(self.h, "blob", "get", self.tid[:8], "sha256:", "--out", str(self.d / "o"))
        self.assertNotEqual(rc, 0)

    def test_multiple_attachments_and_an_empty_file(self):
        rc, out, err = run(self.h, "post", self.tid[:8], "two", "--attach", self.f(b""), "--attach", self.f(b"data", "b"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.count("attached "), 2)
        self.assertEqual(run(self.h, "blob", "ls", self.tid[:8])[1].count("HELD"), 2)


class Public(Cli):
    public = True

    def test_public_attachment_is_the_plain_file(self):
        data = b"public package bytes" * 50
        rc, out, err = run(self.h, "post", self.tid[:8], "pkg", "--attach", self.f(data))
        self.assertEqual(rc, 0, err)
        cid = out.split("attached ")[1].split()[0]
        self.assertEqual(cid, B.cid_of(data))
        outp = str(self.d / "p")
        self.assertEqual(run(self.h, "blob", "get", self.tid[:8], cid, "--out", outp)[0], 0)
        self.assertEqual(Path(outp).read_bytes(), data)


class GuestBlob(unittest.TestCase):
    """`guest blob`: a stranger fetches a public thread's attachment through the read door (real TCP on loopback, real proof of work)."""

    def setUp(self):
        from sigilnet.publicblob import PublicBlob
        from sigilnet.publicread import PublicRead
        from sigilnet.tcp import TcpServer
        self.o, self.g = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.d = Path(tempfile.mkdtemp())
        run(self.o, "id", "init", "owner")
        run(self.g, "id", "init", "stranger")
        self.tid = run(self.o, "new", "pkg", "--public")[1].split("thread ")[1].split()[0]
        self.data = os.urandom(300000)
        (self.d / "pkg.bin").write_bytes(self.data)
        rc, out, err = run(self.o, "post", self.tid[:8], "the package", "--attach", str(self.d / "pkg.bin"))
        self.assertEqual(rc, 0, err)
        self.cid = out.split("attached ")[1].split()[0]
        m = Mirror(self.o + "/mirror")
        me = Identity.load(self.o + "/identity.json")
        srv = S.SyncServer(m, identity=me)
        svc = BlobService(BlobStore(Path(self.o) / "blobs"), BlobIndex(m))
        self.read = TcpServer("127.0.0.1", 0, None, PublicRead(srv, blobs=PublicBlob(srv, svc)).handle).start()
        self.addCleanup(self.read.stop)
        self.assertEqual(run(self.g, "guest", "pull", self.tid, "--loopback", str(self.read.port))[0], 0)

    def test_stranger_fetches_the_public_attachment(self):
        out = str(self.d / "got")
        rc, o, err = run(self.g, "guest", "blob", self.tid, "--cid", self.cid[:20], "--out", out, "--loopback", str(self.read.port))
        self.assertEqual(rc, 0, (o, err))
        self.assertEqual(Path(out).read_bytes(), self.data)
        self.assertEqual(B.cid_of(self.data), self.cid)
        self.assertIn("request(s)", o)

    def test_the_prefix_rule_needs_12_characters_and_a_full_cid_works(self):
        """Sansa's optional test: the 12-character floor applies on the guest path too."""
        rc, o, err = run(self.g, "guest", "blob", self.tid, "--cid", self.cid[:11], "--out", str(self.d / "short"), "--loopback", str(self.read.port))
        self.assertNotEqual(rc, 0)
        self.assertIn("not referenced", err)
        self.assertFalse((self.d / "short").exists())
        rc, o, err = run(self.g, "guest", "blob", self.tid, "--cid", self.cid[:12], "--out", str(self.d / "p12"), "--loopback", str(self.read.port))
        self.assertEqual(rc, 0, (o, err))
        rc, o, err = run(self.g, "guest", "blob", self.tid, "--cid", self.cid, "--out", str(self.d / "full"), "--loopback", str(self.read.port))
        self.assertEqual(rc, 0, (o, err))
        self.assertEqual((self.d / "full").read_bytes(), self.data)

    def test_errors(self):
        for args, msg in ((("--cid", B.cid_of(b"zzz"), "--out", str(self.d / "a")), "not referenced"), (("--out", str(self.d / "b")), "guest blob THREAD_ID --cid")):
            rc, o, err = run(self.g, "guest", "blob", self.tid, *args, "--loopback", str(self.read.port))
            self.assertNotEqual(rc, 0)
            self.assertIn(msg, err)
        rc, o, err = run(self.g, "guest", "blob", "a" * 32, "--cid", self.cid, "--out", str(self.d / "c"), "--loopback", str(self.read.port))
        self.assertNotEqual(rc, 0)


class WantQueue(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.w = Wants(self.root)
        self.tid = "ab" * 16

    def test_add_pending_finish_status(self):
        c = B.cid_of(b"x")
        self.assertTrue(self.w.add(self.tid, c))
        self.assertTrue(self.w.queued(c))
        self.assertEqual([d["cid"] for d in self.w.pending()], [c])
        self.assertTrue(self.w.add(self.tid, c), "idempotent")
        self.assertEqual(len(self.w.pending()), 1)
        self.w.finish(c, True, "ok")
        self.assertEqual((self.w.pending(), self.w.status(c)["ok"], self.w.queued(c)), ([], True, False))
        self.w.add(self.tid, c)
        self.assertIsNone(self.w.status(c), "a new request clears the old status")
        self.assertEqual(oct(os.stat(self.w._p(c, ".want")).st_mode & 0o777), "0o600")

    def test_validation_bounds_and_junk(self):
        for tid, cid in (("zz", B.cid_of(b"x")), (self.tid, "sha256:zz"), (None, B.cid_of(b"x"))):
            with self.assertRaises((ValueError, B.BlobError)):
                self.w.add(tid, cid)
        for i in range(MAX_WANTS):
            self.assertTrue(self.w.add(self.tid, B.cid_of(bytes([i, 1]))))
        self.assertFalse(self.w.add(self.tid, B.cid_of(b"one too many")))
        self.assertTrue(self.w.add(self.tid, B.cid_of(bytes([0, 1]))), "re-adding an existing one is fine")
        (self.w.dir / ("0" * 64 + ".want")).write_text("not json")
        (self.w.dir / ("1" * 64 + ".want")).write_text('{"thread":"zz","cid":"sha256:' + "1" * 64 + '","at":1}')
        (self.w.dir / ("2" * 64 + ".want")).write_text('{"thread":"' + self.tid + '","cid":"sha256:' + "3" * 64 + '","at":1}')       # name does not match the cid
        self.assertEqual(len(self.w.pending()), MAX_WANTS)
        self.assertEqual([n for n in ("0" * 64, "1" * 64, "2" * 64) if (self.w.dir / (n + ".want")).exists()], [])

    def test_expiry(self):
        c = B.cid_of(b"old")
        self.w.add(self.tid, c)
        old = os.stat(self.w._p(c, ".want")).st_mtime - 2 * 86400
        os.utime(self.w._p(c, ".want"), (old, old))
        self.assertEqual(self.w.pending(), [])
        self.w.finish(c, False, "x")
        os.utime(self.w._p(c, ".status"), (old, old))
        self.w.expire()
        self.assertIsNone(self.w.status(c))


class FakeNode:
    def __init__(self, m, plan, tr):
        self.m, self._plan_, self.tr = m, plan, tr

    def _plan(self):
        return self._plan_

    def transport_for(self, rec):
        return self.tr


class Worker(unittest.TestCase):
    def setUp(self):
        self.a, self.b = Identity.generate("a"), Identity.generate("b")
        ra, rb = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.ha, self.hb = Path(ra), Path(rb)
        from sigilnet.build import make_genesis
        from sigilnet.event import event_id
        self.ma = Mirror(ra + "/m", codec=EnvCodec(ra + "/keys"), rate_limit=False)
        self.mb = Mirror(rb + "/m", codec=EnvCodec(rb + "/keys"), rate_limit=False)
        g = make_genesis(self.a, "t", [(self.b, "member")])
        self.ma.ingest(g)
        self.tid = event_id(g)
        self.ma.enable_encryption(self.tid, self.a)
        self.mb.ingest(g)
        from sigilnet.blobauthor import attach
        from sigilnet.build import Writer
        self.sa, self.sb = BlobStore(self.ha / "blobs"), BlobStore(self.hb / "blobs")
        self.data = os.urandom(20000)
        p = Path(tempfile.mkdtemp()) / "f"
        p.write_bytes(self.data)
        ref = attach(self.sa, self.ma, self.ma.threads[self.tid], p, referenced=set())
        self.cid = ref["cid"]
        self.assertTrue(self.ma.ingest(Writer(self.a, self.ma.threads[self.tid]).post("see", refs=[ref])).ok)
        self.srv = S.SyncServer(self.ma, identity=self.a, blobs=BlobService(self.sa, BlobIndex(self.ma)))
        self.tr = S.Loopback(self.srv)
        r = S.pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id)
        S.fetch_keys(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, need=r["need_keys"], unopened=r["unopened"])
        S.pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id)
        self.wants = Wants(self.hb / "blobs")
        self.out = []
        self.plan = {self.a.id: {"rec": {}, "threads": {self.tid}}}
        self.worker = BlobWorker(FakeNode(self.mb, self.plan, self.tr), self.sb, BlobIndex(self.mb), self.wants, self.b, self.out.append, rng=random.Random(1))

    def test_a_want_is_fetched_and_the_status_says_so(self):
        self.wants.add(self.tid, self.cid)
        self.worker.run_once()
        self.assertTrue(self.sb.has(self.cid), self.out)
        self.assertEqual((self.wants.pending(), self.wants.status(self.cid)["ok"]), ([], True))
        self.assertTrue(any("halved" in l and "slowest answer" in l and "waiting" in l for l in self.out), self.out)      # live-test gap L1
        from sigilnet.blobout import export
        o = Path(tempfile.mkdtemp()) / "o"
        self.assertEqual(export(self.sb, self.mb, self.tid, self.cid, o), len(self.data))
        self.assertEqual(o.read_bytes(), self.data)

    def test_no_peer_for_the_thread_fails_with_a_reason(self):
        self.plan.clear()
        self.wants.add(self.tid, self.cid)
        self.worker.run_once()
        st = self.wants.status(self.cid)
        self.assertFalse(st["ok"])
        self.assertIn("no peer shares", st["why"])
        self.assertFalse(self.sb.has(self.cid))

    def test_only_peers_that_share_the_thread_are_asked_and_the_throttle_holds(self):
        asked = []

        class Rec:
            def __init__(s, tag): s.tag = tag
            def request(s, req):
                asked.append(s.tag)
                return self_tr.request(req)
        self_tr = self.tr
        other = Identity.generate("o")
        node = FakeNode(self.mb, {self.a.id: {"rec": "A", "threads": {self.tid}}, other.id: {"rec": "O", "threads": {"cd" * 16}}}, None)
        node.transport_for = lambda rec: Rec(rec)
        w = BlobWorker(node, self.sb, BlobIndex(self.mb), self.wants, self.b, self.out.append, rng=random.Random(1))
        self.wants.add(self.tid, self.cid)
        w.run_once()
        self.assertTrue(asked and set(asked) == {"A"}, asked)
        self.wants.add(self.tid, B.cid_of(b"other"))
        w.last = w.clock()
        w.tick()
        self.assertFalse(w.busy.is_set(), "a pass within EVERY seconds of the last is not started")

    def test_G1_overlapping_passes_are_not_started(self):
        import threading
        gate, started = threading.Event(), []
        self.worker.fetch = lambda *a, **k: (started.append(1), gate.wait(5), {"ok": False, "why": "x"})[2]
        self.wants.add(self.tid, self.cid)
        self.worker.last = 0
        self.worker.tick()
        for _ in range(100):
            if started:
                break
            import time
            time.sleep(0.02)
        self.assertEqual(started, [1])
        self.worker.last = 0
        self.worker.tick()
        self.worker.tick()
        import time
        time.sleep(0.3)                                               # long enough for a wrongly started second pass to reach the fetch
        gate.set()
        for _ in range(100):
            if not self.worker.busy.is_set():
                break
            import time
            time.sleep(0.02)
        self.assertEqual(started, [1], "a second pass was not started while the first was running")

    def test_bans_do_not_outlive_their_want(self):
        self.worker.bans.add(("someone", self.cid))
        self.worker.bans.add(("someone", B.cid_of(b"other")))
        self.worker.fetch = lambda *a, **k: {"ok": False, "why": "x", "requests": 0, "bytes": 0}
        self.wants.add(self.tid, self.cid)
        self.worker.run_once()
        self.assertEqual(self.worker.bans, {("someone", B.cid_of(b"other"))})

    def test_a_failing_fetch_is_reported_and_the_worker_survives(self):
        self.worker.fetch = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        self.wants.add(self.tid, self.cid)
        self.worker.run_once()
        self.assertFalse(self.worker.busy.is_set())
        self.assertTrue(any("RuntimeError" in o for o in self.out))

    def test_tick_runs_a_pass_in_a_thread_only_when_something_is_pending(self):
        self.worker.tick()
        self.assertFalse(self.worker.busy.is_set())
        self.wants.add(self.tid, self.cid)
        self.worker.last = 0
        self.worker.tick()
        for _ in range(100):
            if self.sb.has(self.cid):
                break
            import time
            time.sleep(0.05)
        self.assertTrue(self.sb.has(self.cid))

    def test_already_held_counts_as_done_and_nothing_is_requested(self):
        self.sb.put(self.sa.read(self.cid, 0, 10 ** 7), referenced=set())
        self.wants.add(self.tid, self.cid)
        calls = []
        self.worker.fetch = lambda *a, **k: calls.append(1)
        self.worker.run_once()
        self.assertEqual((calls, self.wants.status(self.cid)["ok"]), ([], True))




class NodeWarmUp(unittest.TestCase):
    """Sansa's optional test: after a restart the members are in the blob service's snapshot (they are not charged to the strangers' budget)."""

    def test_members_are_vetted_right_after_the_warm_up_and_strangers_are_not(self):
        from sigilnet.build import make_genesis
        from sigilnet.event import event_id
        from sigilnet.noderun import warm_blob_snapshot
        a, b, stranger = Identity.generate("a"), Identity.generate("b"), Identity.generate("s")
        m = Mirror(tempfile.mkdtemp() + "/m", rate_limit=False)
        g = make_genesis(a, "t", [(b, "member")])
        m.ingest(g)
        tid = event_id(g)
        svc = BlobService(BlobStore(Path(tempfile.mkdtemp()) / "b"), BlobIndex(m))
        self.assertFalse(svc.vetted(tid, b.id, b.sign_pub), "cold: nobody is vetted")
        warm_blob_snapshot(m, svc)
        self.assertTrue(svc.vetted(tid, b.id, b.sign_pub))
        self.assertTrue(svc.vetted(tid, a.id, a.sign_pub))
        self.assertFalse(svc.vetted(tid, stranger.id, stranger.sign_pub))
        self.assertFalse(svc.vetted(tid, b.id, stranger.sign_pub), "the key must match too")


if __name__ == "__main__":
    unittest.main()
