"""Fetching blobs (DESIGN_blobs.md rev 1): encrypted thread (per-chunk AEAD, bans, resume, key rules) and public thread (final hash), hostile and flaky peers."""
import base64
import os
import tempfile
import unittest
from pathlib import Path

from sigilnet import blob as B
from sigilnet import blobfetch as F
from sigilnet import canon
from sigilnet import sync as S
from sigilnet.blobindex import BlobIndex
from sigilnet.blobserve import BlobService
from sigilnet.blobstore import BlobStore
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror

CH = B.MIN_CHUNK


class Clock:
    def __init__(self):
        import time
        self.t = time.time()

    def __call__(self):
        return self.t


class Liar:
    """A peer with its own key that answers blob requests from a given stored blob, optionally corrupted, and signs whatever it says."""

    def __init__(self, ident, stored, tid, cid, mutate=None):
        self.id, self.stored, self.tid, self.cid, self.mutate = ident, stored, tid, cid, mutate
        self.requests = 0

    def request(self, req):
        self.requests += 1
        off, n = req["offset"], req["n"]
        resp = {"t": "blobdata", "thread": self.tid, "cid": self.cid, "offset": off, "total": len(self.stored),
                "data": base64.b64encode(self.stored[off:off + n]).decode(), "nonce": req["nonce"], "r": 1}
        if self.mutate:
            resp = self.mutate(resp, self)
        resp["by"] = self.id.sign_pub
        resp["rsig"] = self.id.sign(S.RESP_CTX + canon.dumps(resp))
        return resp


class Flaky:
    """Wraps a transport: raises for the first `fail` requests."""

    def __init__(self, inner, fail=0, exc=TimeoutError, skip=0):
        self.inner, self.fail, self.exc, self.skip = inner, fail, exc, skip
        self.seen, self.offsets = [], []

    def request(self, req):
        self.seen.append(req["n"])
        self.offsets.append(req["offset"])
        if self.skip > 0:
            self.skip -= 1
            return self.inner.request(req)
        if self.fail > 0:
            self.fail -= 1
            raise self.exc("slow")
        return self.inner.request(req)


class Small(unittest.TestCase):
    """The module's MIN_CHUNK (16 KiB) is far above these test blobs: shrink it so that several requests per blob happen and request/chunk boundaries do not align."""

    def setUp(self):
        self._min = F.MIN_CHUNK
        F.MIN_CHUNK = 1000
        self.addCleanup(setattr, F, "MIN_CHUNK", self._min)


class EncBase(Small):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.a, self.b, self.c, self.m3 = (Identity.generate(n) for n in "abcm")
        ra, rb = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.ca, self.cb = EnvCodec(ra + "/keys"), EnvCodec(rb + "/keys")
        self.ma = Mirror(ra + "/m", codec=self.ca, rate_limit=False, clock=self.clock)
        self.mb = Mirror(rb + "/m", codec=self.cb, rate_limit=False, clock=self.clock)
        g = make_genesis(self.a, "secret", [(self.b, "member"), (self.c, "member")])
        self.ma.ingest(g)
        self.tid = event_id(g)
        self.ma.enable_encryption(self.tid, self.a)
        self.mb.ingest(g)
        self.store_a = BlobStore(Path(tempfile.mkdtemp()) / "a", clock=self.clock)
        self.store_b = BlobStore(Path(tempfile.mkdtemp()) / "b", clock=self.clock)
        self.svc = BlobService(self.store_a, BlobIndex(self.ma))
        self.srv = S.SyncServer(self.ma, identity=self.a, blobs=self.svc)
        self.tr = S.Loopback(self.srv)
        self.plain = os.urandom(5 * CH + 123)
        self.root = self.ca.ring(self.tid).get(self.tid)[0]
        self.stored = B.seal(self.root, self.tid, self.tid, self.plain, CH)
        self.cid = B.cid_of(self.stored)
        self.store_a.put(self.stored, authored=True, referenced=())
        ev = Writer(self.a, self.ma.threads[self.tid]).post("see attachment", refs=[{"kind": "file", "cid": self.cid, "size": len(self.stored)}])
        self.assertTrue(self.ma.ingest(ev).ok)
        self.sync_b()
        self.ix_b = BlobIndex(self.mb)

    def sync_b(self):
        r = S.pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id)
        if r["need_keys"]:
            got = S.fetch_keys(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, need=r["need_keys"], unopened=r["unopened"])
            self.assertTrue(got["ok"], got)
        r = S.pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id)
        self.assertTrue(r["ok"] and not r["need_keys"], r)

    def go(self, peers=None, **kw):
        kw.setdefault("referenced", {self.cid})
        kw.setdefault("sleep", lambda s: None)
        kw.setdefault("clock", self.clock)
        return F.fetch(self.mb, self.store_b, self.ix_b, self.tid, self.cid, peers if peers is not None else [(self.a.id, self.tr)], self.b, **kw)

    def liar(self, mutate=None, stored=None):
        return Liar(self.m3, stored if stored is not None else self.stored, self.tid, self.cid, mutate)


class EncryptedFetch(EncBase):
    def test_fetch_happy_path_stores_verified_ciphertext_and_decrypts(self):
        r = self.go(chunk=F.MIN_CHUNK)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.stored)
        self.assertEqual(B.open_blob(lambda k: self.root, self.tid, self.store_b.read(self.cid, 0, 10 ** 6)), self.plain)
        self.assertEqual(list(self.store_b.tmp.iterdir()), [])
        again = self.go()
        self.assertEqual((again["ok"], again["why"]), (True, "already held"))

    def test_default_chunk_whole_blob_in_one_request(self):
        r = self.go()
        self.assertTrue(r["ok"] and r["requests"] == 2, r)                  # the header, then everything else in one request

    def test_F1_failed_fetches_leave_no_empty_partial_and_do_not_lock_the_home_out(self):
        """Live-test finding: a fetch that ends in a skip with 0 bytes kept an empty .part; max_partials of them blocked every new fetch for 24 h."""
        empty = BlobService(BlobStore(Path(tempfile.mkdtemp()) / "e", clock=self.clock), BlobIndex(self.ma))      # a member that does not hold the blob
        none = S.Loopback(S.SyncServer(self.ma, identity=self.a, blobs=empty))
        r = self.go([(self.a.id, none)])
        self.assertFalse(r["ok"], r)
        self.assertEqual(self.store_b.partials(), [], "a fetch that received nothing leaves nothing behind")
        for i in range(self.store_b.max_partials + 1):                                  # empty files left by an older version
            (self.store_b.tmp / (B.cid_hex(B.cid_of(bytes([i]))) + ".part")).write_bytes(b"")
        r = self.go()
        self.assertTrue(r["ok"], r)                                                      # a good fetch still works
        self.assertEqual(self.store_b.read(self.cid, 0, 10), self.stored[:10])

    def test_unreferenced_unknown_and_oversize_are_refused_before_any_request(self):
        t = F.Flaky = None
        peer = self.liar()
        for cid in (B.cid_of(b"never"), "sha256:zz"):
            r = F.fetch(self.mb, self.store_b, self.ix_b, self.tid, cid, [(self.m3.id, peer)], self.b, referenced=())
            self.assertFalse(r["ok"])
        self.assertEqual(peer.requests, 0)
        self.store_b.max_blob = 10
        r = self.go([(self.m3.id, peer)])
        self.assertEqual((r["ok"], r["why"]), (False, "declared size exceeds max_blob_bytes"))
        self.assertEqual(peer.requests, 0)

    def test_no_verified_key_means_no_download(self):
        self.cb.ring(self.tid)._save({}) if hasattr(self.cb.ring(self.tid), "_save") else None
        import json
        p = self.cb.ring(self.tid).path
        p.write_text("{}")
        peer = self.liar()
        r = self.go([(self.m3.id, peer)])
        self.assertFalse(r["ok"], r)
        self.assertFalse(self.store_b.has(self.cid))

    def test_bit_flip_in_a_chunk_bans_that_peer_and_the_next_peer_finishes(self):
        def flip(resp, me):
            raw = bytearray(base64.b64decode(resp["data"]))
            if resp["offset"] >= B.HEADER_LEN + CH:               # corrupt something after chunk 0
                raw[len(raw) // 2] ^= 1
            resp["data"] = base64.b64encode(bytes(raw)).decode()
            return resp
        bad, bans, honest = self.liar(flip), set(), Flaky(self.tr)
        r = self.go([(self.m3.id, bad), (self.a.id, honest)], chunk=F.MIN_CHUNK, bans=bans)
        self.assertGreater(honest.offsets[0], B.HEADER_LEN + CH, "the verified chunks survived the ban: the next peer continued, it did not restart")
        self.assertTrue(r["ok"], r)
        self.assertEqual(bans, {(self.m3.id, self.cid)})
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.stored)
        # the banned peer is not asked again for this cid
        before = bad.requests
        self.store_b.remove(self.cid)
        self.go([(self.m3.id, bad), (self.a.id, self.tr)], bans=bans)
        self.assertEqual(bad.requests, before)

    def test_garbage_everywhere_ends_with_nothing_published(self):
        bad = self.liar(lambda resp, me: dict(resp, data=base64.b64encode(os.urandom(CH)).decode()))
        r = self.go([(self.m3.id, bad)], chunk=F.MIN_CHUNK)
        self.assertFalse(r["ok"])
        self.assertIn("banned", r["why"])
        self.assertFalse(self.store_b.has(self.cid))

    def test_a_peer_serving_a_different_valid_blob_for_the_cid_is_caught_by_the_chunk_check(self):
        other = B.seal(self.root, self.tid, self.tid, os.urandom(len(self.plain)), CH)
        other = other[:len(self.stored)] if len(other) >= len(self.stored) else other
        r = self.go([(self.m3.id, self.liar(stored=other))], chunk=F.MIN_CHUNK)
        self.assertFalse(r["ok"])
        self.assertFalse(self.store_b.has(self.cid))

    def test_a_peer_holding_a_truncated_blob_is_caught_by_the_declared_size(self):
        bans = set()
        r = self.go([(self.m3.id, self.liar(stored=self.stored[:-CH]))], chunk=F.MIN_CHUNK, bans=bans)
        self.assertFalse(r["ok"])
        self.assertEqual(bans, {(self.m3.id, self.cid)})
        self.assertFalse(self.store_b.has(self.cid))

    def test_a_peer_that_trickles_honest_bytes_still_completes_it_within_the_request_budget(self):
        small = self.liar(lambda resp, me: dict(resp, data=base64.b64encode(base64.b64decode(resp["data"])[:CH // 2]).decode()))
        self.assertTrue(self.go([(self.m3.id, small)], chunk=F.MIN_CHUNK)["ok"])

    def test_answer_rules(self):
        cases = {
            "wrong offset": lambda resp, me: dict(resp, offset=resp["offset"] + 1),
            "wrong total": lambda resp, me: dict(resp, total=resp["total"] + 1),
            "wrong cid": lambda resp, me: dict(resp, cid=B.cid_of(b"x")),
            "wrong thread": lambda resp, me: dict(resp, thread="0" * 32),
            "not base64": lambda resp, me: dict(resp, data="@@@@"),
            "data not a string": lambda resp, me: dict(resp, data=5),
            "more than asked": lambda resp, me: dict(resp, data=base64.b64encode(os.urandom(F.DEFAULT_CHUNK * 2)).decode()),
            "one byte more than asked": lambda resp, me: dict(resp, data=base64.b64encode(base64.b64decode(resp["data"]) + b"x").decode()),
        }
        for what, mut in cases.items():
            bans = set()
            r = self.go([(self.m3.id, self.liar(mut))], bans=bans)
            self.assertFalse(r["ok"], what)
            self.assertEqual(bans, {(self.m3.id, self.cid)}, what)
            self.assertFalse(self.store_b.has(self.cid), what)

    def test_unsigned_wrong_signer_wrong_nonce_unknown_empty_and_error_answers_skip_without_ban(self):
        class Raw:
            def __init__(s, fn): s.fn = fn
            def request(s, req): return s.fn(req)
        impostor = Identity.generate("imp")
        cases = {
            "unsigned": lambda req: {"t": "blobdata", "nonce": req["nonce"], "r": 1},
            "unknown": lambda req: self.srv.refuse(req) if False else {"t": "unknown", "nonce": req["nonce"], "r": 1},
            "not a dict": lambda req: "hello",
        }
        for what, fn in cases.items():
            bans = set()
            r = self.go([(self.m3.id, Raw(fn))], bans=bans)
            self.assertFalse(r["ok"], what)
            self.assertEqual(bans, set(), what)
        # signed by someone else than the peer we asked
        liar = self.liar()
        wrong = Liar(impostor, self.stored, self.tid, self.cid)
        bans = set()
        self.assertFalse(self.go([(self.m3.id, wrong)], bans=bans)["ok"])
        self.assertEqual(bans, set())
        # empty data
        empty = self.liar(lambda resp, me: dict(resp, data=""))
        r = self.go([(self.m3.id, empty)], bans=bans)
        self.assertFalse(r["ok"])
        self.assertEqual(empty.requests, 1, "an empty answer ends that peer at once")
        self.assertEqual(bans, set())
        # a nonce that is not ours
        stale = self.liar(lambda resp, me: dict(resp, nonce="0" * 16))
        self.assertFalse(self.go([(self.m3.id, stale)], bans=bans)["ok"])
        self.assertEqual(bans, set())

    def test_timeouts_halve_the_chunk_and_succeed(self):
        slow = Flaky(self.tr, fail=2, skip=1)                               # (the first request is the header)
        r = self.go([(self.a.id, slow)], chunk=4000)
        self.assertTrue(r["ok"], r)
        self.assertEqual(slow.seen[:4], [B.HEADER_LEN, 4000, 2000, 1000], "each timeout halves the request, down to MIN_CHUNK")
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.stored)

    def test_the_result_reports_halvings_and_answer_times(self):
        """Live-test gap L1: only the request count was logged, so a slow door could not be told from chunk halving."""
        class Timed:
            def __init__(s, inner, clock):
                s.inner, s.clock, s.n = inner, clock, 0

            def request(s, req):
                s.n += 1
                s.clock.t += 2.5 if s.n == 3 else 0.5
                if s.n in (2, 3):
                    raise TimeoutError("slow")
                return s.inner.request(req)
        r = self.go([(self.a.id, Timed(self.tr, self.clock))], chunk=4000)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["halvings"], 2)
        self.assertAlmostEqual(r["ask_max"], 2.5)
        self.assertGreaterEqual(r["ask_secs"], 2.5 + 0.5 * 2)

    def test_a_peer_that_never_answers_is_skipped_after_a_few_tries_and_the_next_serves(self):
        dead = Flaky(self.tr, fail=10 ** 6)
        r = self.go([(self.a.id, dead), (self.a.id, self.tr)], chunk=F.MIN_CHUNK)
        self.assertTrue(r["ok"], r)
        self.assertLessEqual(len(dead.seen), F.MAX_FAILS_AT_MIN + 1)

    def test_resume_continues_from_verified_chunks_and_rejects_a_tampered_partial(self):
        # first peer serves chunk 0 and 1 then dies
        class Dies:
            def __init__(s, inner, after): s.inner, s.after, s.n = inner, after, 0
            def request(s, req):
                s.n += 1
                if s.n > s.after:
                    raise OSError("gone")
                return s.inner.request(req)
        first = self.go([(self.a.id, Dies(self.tr, 4))], chunk=F.MIN_CHUNK)
        self.assertFalse(first["ok"])
        parts = self.store_b.partials()
        self.assertEqual(len(parts), 1)
        kept = parts[0][1]
        self.assertGreater(kept, B.HEADER_LEN)
        self.assertEqual((kept - B.HEADER_LEN) % (CH + B.TAG), 0, "only whole verified chunks are kept")
        counting = Flaky(self.tr)
        r = self.go([(self.a.id, counting)], chunk=F.MIN_CHUNK)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.stored)
        # tampered partial: flip a byte in the kept prefix -> discarded, restart, still correct
        self.store_b.remove(self.cid)
        self.go([(self.a.id, Dies(self.tr, 4))], chunk=F.MIN_CHUNK)
        p = self.store_b.partials()[0][0]
        raw = bytearray(p.read_bytes())
        raw[B.HEADER_LEN + 5] ^= 1
        p.write_bytes(bytes(raw))
        r = self.go([(self.a.id, self.tr)], chunk=F.MIN_CHUNK)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.stored)

    def test_request_budget_bounds_a_trickling_peer(self):
        trickle = self.liar(lambda resp, me: dict(resp, data=base64.b64encode(base64.b64decode(resp["data"])[:1]).decode()))
        bans = set()
        r = self.go([(self.m3.id, trickle)], chunk=F.MIN_CHUNK, bans=bans)
        self.assertFalse(r["ok"])
        self.assertLessEqual(trickle.requests, len(self.stored) // F.MIN_CHUNK + F.SLACK_REQUESTS)

    def test_deadline_scales_and_stops(self):
        class Slow:
            def __init__(s, inner, clock): s.inner, s.clock = inner, clock
            def request(s, req):
                resp = s.inner.request(req)
                s.clock.t += 10 ** 6                                   # the answer arrives after the deadline
                return resp
        r = self.go([(self.a.id, Slow(self.tr, self.clock))], chunk=F.MIN_CHUNK)
        self.assertFalse(r["ok"])
        self.assertIn("deadline", r["why"])

    def test_quota_refusal(self):
        self.store_b.quota = 10
        r = self.go()
        self.assertEqual((r["ok"], r["why"]), (False, "no room in the blob store"))

    def test_header_is_asked_first_and_an_impossible_declared_size_stops_before_any_bulk(self):
        peer = Flaky(self.tr)
        self.assertTrue(self.go([(self.a.id, peer)])["ok"])
        self.assertEqual(peer.seen[0], B.HEADER_LEN)
        self.assertEqual(peer.offsets[:2], [0, B.HEADER_LEN])
        bad = self.stored[:-(len(self.plain) % CH + B.TAG)] + b"x"            # a layout no canonical blob has: the last chunk is 1 byte (< tag)
        with self.assertRaises(B.BlobError):
            B.layout(len(bad), CH)
        cid2 = B.cid_of(bad)
        ev = Writer(self.a, self.ma.threads[self.tid]).post("odd one", refs=[{"kind": "file", "cid": cid2, "size": len(bad)}])
        self.assertTrue(self.ma.ingest(ev).ok)
        self.sync_b()
        liar = Liar(self.m3, bad, self.tid, cid2)
        bans = set()
        r = F.fetch(self.mb, self.store_b, BlobIndex(self.mb), self.tid, cid2, [(self.m3.id, liar)], self.b, referenced=set(), sleep=lambda s: None, clock=self.clock,
                    bans=bans)
        self.assertFalse(r["ok"])
        self.assertEqual(liar.requests, 1, "only the header was ever asked for")
        self.assertEqual(bans, set(), "an author's wrong size is not the peer's fault: no ban")
        self.assertIn("does not fit the blob header", r["why"])
        r = F.fetch(self.mb, self.store_b, BlobIndex(self.mb), self.tid, cid2, [(self.m3.id, liar)], self.b, referenced=set(), clock=self.clock)
        tiny = Writer(self.a, self.ma.threads[self.tid]).post("too small", refs=[{"kind": "file", "cid": B.cid_of(b"t"), "size": 3}])
        self.assertTrue(self.ma.ingest(tiny).ok)
        self.sync_b()
        r = F.fetch(self.mb, self.store_b, BlobIndex(self.mb), self.tid, B.cid_of(b"t"), [(self.m3.id, liar)], self.b, referenced=set(), clock=self.clock)
        self.assertEqual(r["why"], "declared size is not a valid stored size")

    def test_resume_works_when_the_quota_equals_the_blob_size(self):
        """Sansa FIX B: the kept partial was counted twice (usage + full size), so a retry could never complete when room was tight."""
        class Dies:
            def __init__(s, inner, after): s.inner, s.after, s.n = inner, after, 0
            def request(s, req):
                s.n += 1
                if s.n > s.after:
                    raise OSError("gone")
                return s.inner.request(req)
        self.store_b.quota = len(self.stored)
        self.assertFalse(self.go([(self.a.id, Dies(self.tr, 4))], chunk=F.MIN_CHUNK)["ok"])
        self.assertTrue(self.store_b.partials())
        r = self.go([(self.a.id, self.tr)], chunk=F.MIN_CHUNK)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.stored)

    def test_two_live_events_declaring_different_sizes_are_not_trusted(self):
        ev = Writer(self.c, self.ma.threads[self.tid]).post("same cid, other size", refs=[{"kind": "file", "cid": self.cid, "size": len(self.stored) + 1}])
        self.assertTrue(self.ma.ingest(ev).ok)
        self.sync_b()
        peer = self.liar()
        r = self.go([(self.m3.id, peer)])
        self.assertEqual((r["ok"], r["why"], peer.requests), (False, "conflicting declared sizes", 0))

    def test_an_unverified_key_is_not_used(self):
        import json
        p = self.cb.ring(self.tid).path
        d = json.loads(p.read_text())
        for v in d.values():
            v["ok"] = False
        p.write_text(json.dumps(d))
        peer = self.liar()
        r = self.go([(self.m3.id, peer)])
        self.assertFalse(r["ok"])
        self.assertFalse(self.store_b.has(self.cid))

    def test_a_voided_or_removed_reference_cannot_be_fetched(self):
        rm = Writer(self.a, self.ma.threads[self.tid]).admin("member_remove", {"agent": self.b.id})
        self.ma.codec.ring(self.tid).create(event_id(rm), self.a)
        self.assertTrue(self.ma.ingest(rm).ok)
        S.pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id)
        r = self.go()
        self.assertFalse(r["ok"])                                      # the removed member is the stranger: the server says unknown, nothing is stored
        self.assertFalse(self.store_b.has(self.cid))


class PublicFetch(Small):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.a, self.b, self.m3 = (Identity.generate(n) for n in "abm")
        self.ma = Mirror(tempfile.mkdtemp(), rate_limit=False, clock=self.clock)
        self.mb = Mirror(tempfile.mkdtemp(), rate_limit=False, clock=self.clock)
        g = make_genesis(self.a, "public notes", [(self.b, "member")], visibility="public")
        self.ma.ingest(g)
        self.mb.ingest(g)
        self.tid = event_id(g)
        self.data = os.urandom(3 * 1000 + 7)
        self.cid = B.cid_of(self.data)
        self.store_a = BlobStore(Path(tempfile.mkdtemp()) / "a", clock=self.clock)
        self.store_b = BlobStore(Path(tempfile.mkdtemp()) / "b", clock=self.clock)
        self.store_a.put(self.data, authored=True, referenced=())
        ev = Writer(self.a, self.ma.threads[self.tid]).post("pkg", refs=[{"kind": "file", "cid": self.cid, "size": len(self.data)}])
        self.assertTrue(self.ma.ingest(ev).ok)
        self.srv = S.SyncServer(self.ma, identity=self.a, blobs=BlobService(self.store_a, BlobIndex(self.ma)))
        self.tr = S.Loopback(self.srv)
        S.pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id)
        self.ix = BlobIndex(self.mb)

    def go(self, peers, **kw):
        return F.fetch(self.mb, self.store_b, self.ix, self.tid, self.cid, peers, self.b, referenced={self.cid}, sleep=lambda s: None, clock=self.clock, **kw)

    def test_plain_blob_fetch_verifies_the_final_hash(self):
        r = self.go([(self.a.id, self.tr)], chunk=F.MIN_CHUNK)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.data)

    def test_an_empty_public_file_is_a_valid_blob_without_any_request(self):
        empty = B.cid_of(b"")
        ev = Writer(self.a, self.ma.threads[self.tid]).post("empty", refs=[{"kind": "file", "cid": empty, "size": 0}])
        self.assertTrue(self.ma.ingest(ev).ok)
        S.pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id)
        peer = Flaky(self.tr)
        r = F.fetch(self.mb, self.store_b, BlobIndex(self.mb), self.tid, empty, [(self.a.id, peer)], self.b, referenced={empty}, clock=self.clock)
        self.assertTrue(r["ok"], r)
        self.assertEqual((peer.seen, self.store_b.size(empty)), ([], 0))

    def test_wrong_bytes_with_the_right_length_are_caught_at_the_end_and_ban_the_peer(self):
        bad = Liar(self.m3, os.urandom(len(self.data)), self.tid, self.cid)
        bans = set()
        r = self.go([(self.m3.id, bad), (self.a.id, self.tr)], chunk=F.MIN_CHUNK, bans=bans)
        self.assertTrue(r["ok"], r)                                    # the honest second peer finished it from scratch
        self.assertEqual(bans, {(self.m3.id, self.cid)})
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.data)

    def test_a_poisoned_plain_partial_is_never_continued_by_another_peer(self):
        """Sansa FIX A: peer m3 serves one garbage chunk then goes away; the next peer must not resume from it (and so must not be banned for it)."""
        sent = []

        def poison_then_unknown(req):
            out = self.door_handle(req)
            return out
        calls = {"n": 0}
        good = Liar(self.m3, self.data, self.tid, self.cid)

        class Poison:
            def request(s, req):
                calls["n"] += 1
                if calls["n"] == 1:
                    resp = Liar(self_m3, os.urandom(len(self_data)), self_tid, self_cid).request(req)
                    return resp
                return {"t": "unknown", "nonce": req["nonce"], "r": 1, "by": self_m3.sign_pub,
                        "rsig": self_m3.sign(S.RESP_CTX + canon.dumps({"t": "unknown", "nonce": req["nonce"], "r": 1, "by": self_m3.sign_pub}))}
        self_m3, self_data, self_tid, self_cid = self.m3, self.data, self.tid, self.cid
        bans = set()
        r = self.go([(self.m3.id, Poison()), (self.a.id, self.tr)], chunk=F.MIN_CHUNK, bans=bans)
        self.assertTrue(r["ok"], r)
        self.assertEqual(bans, set(), "no honest peer was banned")
        self.assertEqual(self.store_b.read(self.cid, 0, 10 ** 6), self.data)

    def test_G2_a_plain_fetch_that_ends_in_a_skip_leaves_no_partial(self):
        calls = {"n": 0}
        m3 = self.m3
        data, tid, cid = self.data, self.tid, self.cid

        class OneChunkThenUnknown:
            def request(s, req):
                calls["n"] += 1
                if calls["n"] == 1:
                    return Liar(m3, data, tid, cid).request(req)
                resp = {"t": "unknown", "nonce": req["nonce"], "r": 1, "by": m3.sign_pub}
                resp["rsig"] = m3.sign(S.RESP_CTX + canon.dumps(resp))
                return resp
        r = self.go([(self.m3.id, OneChunkThenUnknown())], chunk=F.MIN_CHUNK)
        self.assertFalse(r["ok"])
        self.assertEqual(self.store_b.partials(), [])

    def test_a_plain_partial_on_disk_from_an_earlier_call_is_not_trusted_either(self):
        c = self.cid
        (self.store_b.tmp / (B.cid_hex(c) + ".part")).write_bytes(b"\0" * 1000)
        r = self.go([(self.a.id, self.tr)], chunk=F.MIN_CHUNK)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.store_b.read(c, 0, 10 ** 6), self.data)

    def test_only_wrong_bytes_publishes_nothing_and_deletes_the_partial(self):
        bad = Liar(self.m3, os.urandom(len(self.data)), self.tid, self.cid)
        r = self.go([(self.m3.id, bad)], chunk=F.MIN_CHUNK)
        self.assertFalse(r["ok"])
        self.assertFalse(self.store_b.has(self.cid))
        self.assertEqual(self.store_b.partials(), [])


if __name__ == "__main__":
    unittest.main()
