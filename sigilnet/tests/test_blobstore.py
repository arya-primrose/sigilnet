"""Blob store + index (DESIGN_blobs.md rev 1): atomic visible-only-when-verified publication, quota and eviction, partials (resume, re-hash, expiry, limit),
GC with grace, damaged meta, path safety; and the serving index (live vs voided vs unknown, refs memoised, reorg)."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from sigilnet import blob as B
from sigilnet import blobstore as S
from sigilnet.blobindex import BlobIndex
from sigilnet.mirror import Mirror
from sigilnet.tests.util import World


def cid(b):
    return B.cid_of(b)


class Clock:
    def __init__(self):
        self.t = 1000000.0

    def __call__(self):
        return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.root = Path(tempfile.mkdtemp()) / "blobs"
        self.s = S.BlobStore(self.root, quota=1000, max_blob=400, grace=100, partial_ttl=50, max_partials=2, clock=self.clock)

    def put(self, data, **kw):
        kw.setdefault("referenced", ())
        return self.s.put(data, **kw)


class Store(Base):
    def test_put_read_has_size(self):
        data = os.urandom(150)
        c = self.put(data)
        self.assertEqual(c, cid(data))
        self.assertTrue(self.s.has(c))
        self.assertEqual(self.s.size(c), 150)
        self.assertEqual(self.s.read(c, 0, 1000), data)
        self.assertEqual(self.s.read(c, 100, 10), data[100:110])
        self.assertEqual(self.s.read(c, 150, 10), b"")
        self.assertIsNone(self.s.read(cid(b"other"), 0, 10))
        self.assertEqual(self.put(data), c)                         # idempotent
        self.assertEqual(self.s.usage(), 150)
        self.assertEqual(oct((self.s._path(c)).stat().st_mode & 0o777), "0o600")

    def test_nothing_visible_until_commit_and_bad_hash_or_size_leaves_nothing(self):
        data = os.urandom(100)
        inc = self.s.begin(cid(data), size=100)
        inc.write(data[:60])
        self.assertFalse(self.s.has(cid(data)))
        inc.write(data[60:])
        self.assertFalse(self.s.has(cid(data)))
        self.assertEqual(inc.commit(referenced=(), expect_size=100), cid(data))
        self.assertTrue(self.s.has(cid(data)))
        bad = self.s.begin(cid(data), size=100)
        bad.write(os.urandom(100))
        with self.assertRaises(S.StoreError):
            bad.commit(referenced=())
        self.assertEqual([f for f in self.s.tmp.iterdir()], [])
        wrong = self.s.begin(None, size=100)
        wrong.write(b"x" * 10)
        with self.assertRaises(S.StoreError):
            wrong.commit(referenced=(), expect_size=11)
        self.assertEqual(self.s.usage(), 100)

    def test_more_bytes_than_declared_stops(self):
        inc = self.s.begin(None, size=10)
        inc.write(b"x" * 10)
        with self.assertRaises(S.TooBig):
            inc.write(b"y")
        self.assertEqual(list(self.s.tmp.iterdir()), [])

    def test_declared_size_over_policy_refused_before_any_write(self):
        with self.assertRaises(S.TooBig):
            self.s.begin(None, size=401)
        for bad in (-1, True, None, 1.5):
            with self.assertRaises(S.StoreError, msg=bad):
                self.s.begin(None, size=bad)
        self.assertEqual(list(self.s.tmp.iterdir()), [])

    def test_commit_over_max_blob(self):
        s = S.BlobStore(Path(tempfile.mkdtemp()), quota=10 ** 6, max_blob=50, clock=self.clock)
        inc = s.begin(None, size=50)
        inc.write(b"a" * 50)
        s.max_blob = 10
        with self.assertRaises(S.TooBig):
            inc.commit(referenced=())

    def test_cid_is_validated_before_it_is_a_path(self):
        for bad in ("../../etc/passwd", "sha256:" + "../" * 21 + "a", "sha256:" + "A" * 64, "", None, "sha256:" + "a" * 64 + "/x"):
            fns = [self.s.has, self.s.size, self.s.remove, lambda c: self.s.read(c, 0, 1)] + ([lambda c: self.s.begin(c, size=1)] if bad is not None else [])
            for fn in fns:
                with self.assertRaises(B.BlobError, msg=repr(bad)):
                    fn(bad)

    def test_planted_partial_symlink_fifo_and_dir_fail_cleanly(self):
        c = cid(b"p" * 10)
        p = self.s.tmp / (B.cid_hex(c) + ".part")
        for plant in (lambda: os.symlink("/etc/passwd", p), lambda: os.mkfifo(p), lambda: p.mkdir()):
            plant()
            with self.assertRaises(OSError):
                self.s.begin(c, size=10)
            if p.is_dir() and not p.is_symlink():
                p.rmdir()
            else:
                p.unlink()
        self.assertEqual(Path("/etc/passwd").read_text()[:4] != "", True)

    def test_read_clamps_a_peer_chosen_n_and_a_symlink_is_just_not_held(self):
        c = self.put(b"abc")
        self.assertEqual(self.s.read(c, 0, 1 << 40), b"abc")
        self.assertEqual(self.s.read(c, 0, 1 << 70), b"abc")
        with self.assertRaises(S.StoreError):
            self.s.read(c, 1 << 70, 1)
        big = S.BlobStore(Path(tempfile.mkdtemp()), quota=10 ** 8, max_blob=10 ** 7, clock=self.clock)
        c2 = big.put(b"z" * (S.MAX_READ + 5), referenced=())
        self.assertEqual(len(big.read(c2, 0, 1 << 40)), S.MAX_READ)
        p = self.s._path(c)
        p.unlink()
        os.symlink("/etc/passwd", p)
        self.assertIsNone(self.s.read(c, 0, 10))

    def test_a_failed_write_leaves_nothing(self):
        inc = self.s.begin(None, size=100)
        real = os.write
        os.write = lambda fd, b: (_ for _ in ()).throw(OSError(28, "No space left on device"))
        try:
            with self.assertRaises(S.StoreError):
                inc.write(b"x")
        finally:
            os.write = real
        self.assertEqual(list(self.s.tmp.iterdir()), [])

    def test_read_bad_range_and_symlink(self):
        c = self.put(b"abc")
        for a in ((-1, 1), (0, -1), ("0", 1), (0, None)):
            with self.assertRaises(S.StoreError):
                self.s.read(c, *a)
        p = self.s._path(c)
        p.unlink()
        os.symlink("/etc/passwd", p)                                    # a planted symlink is neither held nor readable
        self.assertFalse(self.s.has(c))
        self.assertIsNone(self.s.size(c))
        self.assertIsNone(self.s.read(c, 0, 10))


class Quota(Base):
    def test_quota_refuses_and_authored_counts(self):
        self.put(b"a" * 400, authored=True)
        self.put(b"b" * 400, authored=True)
        with self.assertRaises(S.QuotaError):
            self.put(b"c" * 300)                                      # authored blobs are never evicted
        self.assertEqual(self.s.usage(), 800)
        self.assertEqual(len(self.s.listing()), 2)

    def test_eviction_order_unreferenced_first_then_oldest_fetched(self):
        a = self.put(b"a" * 300)
        self.clock.t += 1
        b = self.put(b"b" * 300)
        self.clock.t += 1
        c = self.put(b"c" * 300)
        self.clock.t += 1
        self.put(b"d" * 300, referenced={a, b})                      # c is unreferenced: it goes, a and b stay
        self.assertEqual({k for k in self.s.listing()}, {a, b, cid(b"d" * 300)})
        self.assertFalse(self.s.has(c))
        self.clock.t += 1
        self.put(b"e" * 300, referenced={a, b, cid(b"d" * 300)})     # all referenced: the OLDEST fetched (a) goes
        self.assertFalse(self.s.has(a))
        self.assertTrue(self.s.has(b))

    def test_partials_count_toward_the_quota(self):
        inc = self.s.begin(None, size=400)
        inc.write(b"p" * 400)
        inc.keep()
        self.assertEqual(self.s.usage(), 400)
        self.put(b"a" * 400, authored=True)
        with self.assertRaises(S.QuotaError):
            self.put(b"b" * 300, authored=True)

    def test_publishing_a_partial_does_not_count_it_twice(self):
        inc = self.s.begin(None, size=400)
        inc.write(b"p" * 400)
        self.put(b"a" * 400, authored=True)
        inc.commit(referenced=(), authored=True)                                       # 400 + 400 <= 1000 although the partial was already in usage
        self.assertEqual(self.s.usage(), 800)


class Partials(Base):
    def test_resume_rehashes_the_kept_prefix(self):
        data = os.urandom(200)
        c = cid(data)
        inc = self.s.begin(c, size=200)
        inc.write(data[:120])
        inc.keep()
        again = self.s.begin(c, size=200, resume=True)
        self.assertEqual(again.offset, 120)
        again.write(data[120:])
        self.assertEqual(again.commit(referenced=()), c)
        # a tampered kept prefix is caught by the final hash, never published
        inc = self.s.begin(cid(b"z" * 200), size=200)
        inc.write(b"z" * 100)
        inc.keep()
        p = self.s.tmp / (B.cid_hex(cid(b"z" * 200)) + ".part")
        p.write_bytes(b"Y" * 100)
        again = self.s.begin(cid(b"z" * 200), size=200, resume=True)
        again.write(b"z" * 100)
        with self.assertRaises(S.StoreError):
            again.commit(referenced=())
        self.assertFalse(self.s.has(cid(b"z" * 200)))

    def test_non_resume_starts_over(self):
        c = cid(b"q" * 100)
        inc = self.s.begin(c, size=100)
        inc.write(b"q" * 50)
        inc.keep()
        self.assertEqual(self.s.begin(c, size=100).offset, 0)

    def test_oversized_kept_partial_is_discarded(self):
        c = cid(b"q" * 100)
        (self.s.tmp / (B.cid_hex(c) + ".part")).write_bytes(b"x" * 300)
        self.assertEqual(self.s.begin(c, size=100, resume=True).offset, 0)

    def test_limit_and_expiry(self):
        for i in range(2):
            inc = self.s.begin(cid(bytes([i])), size=10)
            inc.write(b"x")
            inc.keep()
        with self.assertRaises(S.PartialLimit):
            self.s.begin(cid(b"new"), size=10)
        self.s.begin(cid(bytes([0])), size=10, resume=True).keep()      # resuming an existing one is not a new partial
        self.clock.t += 0                                                # mtime is real time: age the files by hand
        for f, _, _ in self.s.partials():
            os.utime(f, (self.clock.t - 51, self.clock.t - 51))
        inc = self.s.begin(cid(b"new"), size=10)                        # the old ones expired
        inc.write(b"x")
        inc.keep()
        self.assertEqual(len(self.s.partials()), 1)

    def test_an_empty_partial_is_not_kept_and_does_not_count(self):
        """Live-test finding F1: failed fetches left 0-byte partials that filled max_partials and locked the home out for 24 h."""
        for i in range(5):                                               # max_partials is 2 here
            self.s.begin(cid(bytes([i])), size=10).keep()
        self.assertEqual(self.s.partials(), [], "keep() of an empty partial deletes it")
        for i in range(2):                                               # files left by an OLDER version still must not block
            (self.s.tmp / (B.cid_hex(cid(bytes([100 + i]))) + ".part")).write_bytes(b"")
        inc = self.s.begin(cid(b"real"), size=10)
        inc.write(b"x")
        inc.keep()
        inc2 = self.s.begin(cid(b"real2"), size=10)
        inc2.write(b"x")
        inc2.keep()
        with self.assertRaises(S.PartialLimit):                          # real (non-empty) partials still count
            self.s.begin(cid(b"third"), size=10)

    def test_sweep_at_start(self):
        (self.s.tmp / "junk.txt").write_text("x")
        old = self.s.tmp / ("a" * 64 + ".part")
        old.write_bytes(b"x")
        os.utime(old, (self.clock.t - 1000, self.clock.t - 1000))
        S.BlobStore(self.root, partial_ttl=50, clock=self.clock)
        self.assertEqual(list(self.s.tmp.iterdir()), [])


class Gc(Base):
    def test_grace_then_removal_and_a_new_reference_resets(self):
        c = self.put(b"a" * 50)
        self.assertEqual(self.s.gc({c}), [])
        self.assertEqual(self.s.gc(set()), [])                          # first unreferenced pass starts the clock
        self.clock.t += 99
        self.assertEqual(self.s.gc(set()), [])
        self.assertEqual(self.s.gc({c}), [])                            # referenced again: reset
        self.assertEqual(self.s.gc(set()), [])
        self.clock.t += 99
        self.assertEqual(self.s.gc(set()), [])
        self.clock.t += 2
        self.assertEqual(self.s.gc(set()), [c])
        self.assertFalse(self.s.has(c))

    def test_authored_blob_is_collected_too_when_nothing_references_it(self):
        c = self.put(b"mine", authored=True)                          # the post was refused: the unreferenced authored blob goes after the grace
        self.s.gc(set())
        self.clock.t += 101
        self.assertEqual(self.s.gc(set()), [c])

    def test_remove(self):
        c = self.put(b"a")
        self.assertTrue(self.s.remove(c))
        self.assertFalse(self.s.remove(c))
        self.assertFalse(self.s.has(c))
        self.assertEqual(self.s.usage(), 0)


class Meta(Base):
    def test_every_field_of_a_meta_entry_is_validated_and_a_bad_one_rebuilds(self):
        a = self.put(b"a" * 20, authored=True)
        h = a[7:]
        good = {"size": 20, "authored": True, "added": 5.0, "unref": None}
        bad = [dict(good, unref="x"), dict(good, unref=float("nan")), dict(good, unref=True), dict(good, size=-10 ** 12), dict(good, size=True),
               dict(good, size=2 ** 41), dict(good, size=1.5), dict(good, authored="yes"), dict(good, authored=1), dict(good, added="1"), dict(good, added=None),
               dict(good, added=float("inf")), {k: v for k, v in good.items() if k != "unref"}, dict(good, extra=1), "str", None, 7]
        import json
        for entry in bad:
            (self.root / "meta.json").write_text(json.dumps({"v": 1, "blobs": {h: entry}}, allow_nan=True))
            s = S.BlobStore(self.root, clock=self.clock)
            self.assertEqual(s.listing(), {a: {"size": 20, "authored": False, "added": self.clock(), "unref": self.clock()}}, entry)
            self.assertEqual(s.gc(set()), [], "gc() does not raise")
            self.assertEqual(s.usage(), 20)
        (self.root / "meta.json").write_text(json.dumps({"v": 1, "blobs": {"../x": good}}))
        self.assertEqual(set(S.BlobStore(self.root, clock=self.clock).listing()), {a})

    def test_sweep_takes_the_size_from_the_file(self):
        a = self.put(b"a" * 20)
        import json
        m = json.loads((self.root / "meta.json").read_text())
        m["blobs"][a[7:]]["size"] = 1
        (self.root / "meta.json").write_text(json.dumps(m))
        self.assertEqual(S.BlobStore(self.root, clock=self.clock).usage(), 20)

    def test_damaged_meta_is_rebuilt_from_the_object_files(self):
        a, b = self.put(b"a" * 20, authored=True), self.put(b"b" * 30)
        for junk in ("not json", "{}", '{"v":1,"blobs":{"x":5}}', '{"v":2,"blobs":{}}', ""):
            (self.root / "meta.json").write_text(junk)
            s = S.BlobStore(self.root, clock=self.clock)
            self.assertEqual(set(s.listing()), {a, b}, junk)
            self.assertEqual(s.usage(), 50)
        (self.root / "meta.json").unlink()
        self.assertEqual(set(S.BlobStore(self.root, clock=self.clock).listing()), {a, b})

    def test_meta_entry_without_a_file_and_stray_file_are_reconciled(self):
        a = self.put(b"a" * 20)
        self.s._path(a).unlink()
        h = hashlib.sha256(b"stray").hexdigest()
        (self.s.objects / h[:2]).mkdir(exist_ok=True)
        (self.s.objects / h[:2] / h).write_bytes(b"stray")
        self.assertEqual(set(S.BlobStore(self.root, clock=self.clock).listing()), {"sha256:" + h})

    def test_survives_restart_with_flags(self):
        a = self.put(b"a" * 20, authored=True)
        self.assertTrue(S.BlobStore(self.root, clock=self.clock).listing()[a]["authored"])


class Index(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.root = tempfile.mkdtemp()
        self.m = Mirror(self.root, rate_limit=False)
        self.m.ingest(self.w.genesis)
        self.tid = self.w.t.id
        self.ix = BlobIndex(self.m)

    def post(self, who, refs):
        ev = self.w.w(who).post("with attachment", refs=refs)
        self.w.add(ev)
        self.assertTrue(self.m.ingest(ev).ok)
        return ev

    def ref(self, data):
        return {"kind": "file", "cid": cid(data), "size": len(data)}

    def test_live_unknown_and_malformed(self):
        d = b"hello" * 10
        self.post("sansa", [self.ref(d)])
        self.assertEqual(self.ix.live(self.tid, cid(d)), [len(d)])
        self.assertEqual(self.ix.live(self.tid, cid(b"other")), [])
        self.assertEqual(self.ix.live("0" * 64, cid(d)), [])
        for bad in (None, "x", "sha256:" + "A" * 64):
            self.assertEqual(self.ix.live(self.tid, bad), [])
        self.assertEqual(self.ix.referenced(), {cid(d)})
        self.assertEqual(self.ix.servable_in(cid(d)), [self.tid])

    def test_a_ref_in_a_new_event_appears_without_rebuilding_old_ones(self):
        self.post("sansa", [self.ref(b"one")])
        self.assertEqual(self.ix.referenced(), {cid(b"one")})
        from sigilnet import blobindex
        calls = []
        real = blobindex._refs_of
        blobindex._refs_of = lambda ev: calls.append(1) or real(ev)
        try:
            n_events = len(self.m.threads[self.tid].events)
            self.post("carol", [self.ref(b"two")])
            self.assertEqual(self.ix.referenced(), {cid(b"one"), cid(b"two")})
            self.assertLessEqual(len(calls), 1 + 1, "only the new event(s) were read, not every event again")
            calls.clear()
            self.assertEqual(self.ix.referenced(), {cid(b"one"), cid(b"two")})
            self.assertEqual(calls, [], "a second lookup with nothing new reads no event")
        finally:
            blobindex._refs_of = real

    def test_voided_referrer_is_not_served_but_is_kept_for_gc(self):
        d = b"secret"
        pre = self.w.w("carol").post("pre removal", refs=[self.ref(d)])
        rm = self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id})
        self.w.add(rm)
        self.assertTrue(self.m.ingest(rm).ok)
        self.assertEqual(self.m.ingest(pre).status, "voided")
        self.assertEqual(self.ix.live(self.tid, cid(d)), [], "a voided event's blob is never served")
        self.assertEqual(self.ix.referenced(), {cid(d)}, "but GC keeps it (a reorg can revive the event)")
        self.assertEqual(self.ix.servable_in(cid(d)), [])

    def test_same_cid_from_two_events_survives_the_void_of_one(self):
        d = b"shared"
        self.post("sansa", [self.ref(d)])
        pre = self.w.w("carol").post("pre", refs=[self.ref(d)])
        rm = self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id})
        self.w.add(rm)
        self.m.ingest(rm)
        self.m.ingest(pre)
        self.assertEqual(self.ix.live(self.tid, cid(d)), [len(d)])

    def test_non_post_and_refless_events_and_declared_size_conflict(self):
        self.post("sansa", [])
        self.w.w("sansa")
        d = b"x" * 5
        self.post("sansa", [{"kind": "file", "cid": cid(d), "size": 5}])
        self.post("carol", [{"kind": "file", "cid": cid(d), "size": 9}])
        self.assertEqual(self.ix.live(self.tid, cid(d)), [5, 9])

    def test_two_threads_and_a_writer_on_one_index_raise_nothing(self):
        """Sansa REQUIRED 1: the node's GC (referenced()) and serve threads (live()) share one index."""
        import threading
        import time
        import sys
        errors, stop = [], threading.Event()
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)                                   # many more thread switches: makes an unlocked index fail reliably
        self.addCleanup(sys.setswitchinterval, old)

        def hammer(fn):
            while not stop.is_set():
                try:
                    fn()
                except Exception as e:                                    # noqa: BLE001
                    errors.append(repr(e))
                    return
        d0 = b"seed"
        self.post("sansa", [self.ref(d0)])
        ths = [threading.Thread(target=hammer, args=(f,)) for f in (lambda: self.ix.referenced(), lambda: self.ix.live(self.tid, cid(d0)), lambda: self.ix.refs(self.tid))]
        for th in ths:
            th.start()
        end = time.time() + 1.0
        i = 0
        while time.time() < end:
            self.post("sansa" if i % 2 else "carol", [self.ref(bytes([i % 250, 7]))])
            i += 1
        stop.set()
        for th in ths:
            th.join(5)
        self.assertEqual(errors, [])

    def test_every_public_method_waits_for_the_index_lock(self):
        """Deterministic version of the race test: while one thread holds the index lock, the others must block (a data race cannot be provoked reliably)."""
        import threading
        d = b"locked"
        self.post("sansa", [self.ref(d)])
        for call in (lambda: self.ix.live(self.tid, cid(d)), lambda: self.ix.refs(self.tid), lambda: self.ix.referenced(), lambda: self.ix.servable_in(cid(d))):
            done = threading.Event()
            th = threading.Thread(target=lambda: (call(), done.set()))
            with self.ix._mu:
                th.start()
                self.assertFalse(done.wait(0.3), "ran while the lock was held")
            self.assertTrue(done.wait(5))
            th.join(5)

    def test_G3_refs_excludes_voided_references(self):
        d = b"voided one"
        pre = self.w.w("carol").post("pre", refs=[self.ref(d)])
        self.post("sansa", [self.ref(b"live one")])
        rm = self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id})
        self.w.add(rm)
        self.assertTrue(self.m.ingest(rm).ok)
        self.assertEqual(self.m.ingest(pre).status, "voided")
        self.assertEqual(set(self.ix.refs(self.tid)), {cid(b"live one")})
        self.assertIn(cid(d), self.ix.referenced(), "GC still keeps it")

    def test_unknown_thread_dropped_from_cache(self):
        self.ix.live(self.tid, cid(b"x"))
        self.m.threads.pop(self.tid)
        self.assertEqual(self.ix.live(self.tid, cid(b"x")), [])
        self.assertNotIn(self.tid, self.ix._cache)


if __name__ == "__main__":
    unittest.main()
