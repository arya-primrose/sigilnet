"""Blobs of a PUBLIC thread through the unauthenticated read door: stateless PoW scaled to the chunk, one answer for everything the stranger may not have,
own budgets (never the read budgets), a concurrency cap, replay refusal, and the client (PublicSource) end to end."""
import base64
import os
import tempfile
import threading
import unittest
from pathlib import Path

from sigilnet import blob as B
from sigilnet import blobfetch as F
from sigilnet import pow as P
from sigilnet import publicblob as PB
from sigilnet import sync as S
from sigilnet.blobindex import BlobIndex
from sigilnet.blobserve import MAX_CHUNK, BlobService
from sigilnet.blobstore import BlobStore
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.publicread import PublicRead


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


class Door:
    """The read door as a transport (what tcp would carry)."""

    def __init__(self, handle):
        self.handle, self.calls = handle, []

    def request(self, req):
        self.calls.append(req)
        return self.handle(req)


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.a = Identity.generate("a")
        self.m = Mirror(tempfile.mkdtemp(), rate_limit=False, clock=self.clock)
        g = make_genesis(self.a, "public notes", [], visibility="public")
        self.m.ingest(g)
        self.tid = event_id(g)
        self.store = BlobStore(Path(tempfile.mkdtemp()) / "b", clock=self.clock)
        self.data = os.urandom(5000)
        self.cid = self.store.put(self.data, referenced=())
        ev = Writer(self.a, self.m.threads[self.tid]).post("pkg", refs=[{"kind": "file", "cid": self.cid, "size": len(self.data)}])
        self.assertTrue(self.m.ingest(ev).ok)
        self.srv = S.SyncServer(self.m, identity=self.a, clock=self.clock)
        self.svc = BlobService(self.store, BlobIndex(self.m), clock=self.clock)
        self.pb = PB.PublicBlob(self.srv, self.svc, clock=self.clock)
        self.door = PublicRead(self.srv, clock=self.clock, blobs=self.pb)

    def nonce(self):
        return os.urandom(8).hex()

    def chal(self, n=1000, door=None):
        return (door or self.door).handle({"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": n, "nonce": self.nonce()})

    def req(self, cid=None, offset=0, n=1000, thread=None, ch=None, nonce=None, bits=None, door=None):
        ch = ch or self.chal(n, door)
        nonce = nonce or self.nonce()
        cid = cid or self.cid
        salt = bytes.fromhex(ch["salt"])
        pw = P.solve(salt, thread or self.tid, "", PB.binding(cid, offset, n, nonce), ch["bits"] if bits is None else bits)
        return {"t": "blob", "thread": thread or self.tid, "cid": cid, "offset": offset, "n": n, "nonce": nonce, "pow": {"salt": salt.hex(), "nonce": pw}}


class Challenge(Base):
    def test_challenge_bits_grow_with_the_chunk(self):
        bits = [self.chal(n)["bits"] for n in (1, PB.MIN_N, 2 * PB.MIN_N, 128 * 1024, MAX_CHUNK)]
        self.assertEqual(bits, [10, 10, 11, 13, 14])
        self.assertTrue(all(b <= PB.MAX_BITS for b in bits))

    def test_the_challenge_says_nothing_about_what_exists(self):
        priv = make_genesis(self.a, "private", [], visibility="private")
        self.m.ingest(priv)
        outs = []
        for thread, cid in ((self.tid, self.cid), (event_id(priv), self.cid), ("0" * 32, B.cid_of(b"nope")), ("junk", "junk")):
            r = self.door.handle({"t": "blob", "thread": thread, "cid": cid, "offset": 0, "n": 1000, "nonce": self.nonce()})
            outs.append({k: v for k, v in r.items() if k not in ("nonce", "rsig")})
        self.assertTrue(all(o == outs[0] for o in outs), outs)

    def test_a_valid_proof_gets_the_chunk(self):
        r = self.door.handle(self.req(offset=100, n=500))
        self.assertEqual((r["t"], r["offset"], r["total"]), ("blobdata", 100, 5000))
        self.assertEqual(base64.b64decode(r["data"]), self.data[100:600])


class OneAnswer(Base):
    def test_private_unknown_unreferenced_and_voided_are_all_unknown(self):
        priv = make_genesis(self.a, "private", [], visibility="private")
        self.m.ingest(priv)
        ptid = event_id(priv)
        other = self.store.put(b"held but unreferenced", referenced=())
        cases = {
            "private thread": self.req(thread=ptid),
            "unknown thread": self.req(thread="0" * 32),
            "unreferenced cid we hold": self.req(cid=other),
            "unknown cid": self.req(cid=B.cid_of(b"zz")),
        }
        for what, r in cases.items():
            out = self.door.handle(r)
            self.assertEqual({k: v for k, v in out.items() if k not in ("nonce", "r", "by", "rsig")}, {"t": "unknown"}, what)

    def test_a_private_thread_that_references_a_held_cid_is_still_unknown(self):
        priv = make_genesis(self.a, "private with refs", [], visibility="private")
        self.m.ingest(priv)
        ptid = event_id(priv)
        ev = Writer(self.a, self.m.threads[ptid]).post("secret attachment", refs=[{"kind": "file", "cid": self.cid, "size": len(self.data)}])
        self.assertTrue(self.m.ingest(ev).ok)
        self.assertEqual(self.pb.svc.index.live(ptid, self.cid), [len(self.data)], "the index knows it (members are served through the signed op)")
        out = self.door.handle(self.req(thread=ptid))
        self.assertEqual({k: v for k, v in out.items() if k not in ("nonce", "r", "by", "rsig")}, {"t": "unknown"})

    def test_a_voided_reference_is_not_served(self):
        w = World2(self)
        self.assertEqual(w.serve_voided()["t"], "unknown")


class World2:
    """A public thread with a member whose pre-removal post carries the ref and ends up voided."""

    def __init__(self, t):
        self.t = t

    def serve_voided(self):
        t = self.t
        carol = Identity.generate("carol")
        a = Identity.generate("a2")
        m = Mirror(tempfile.mkdtemp(), rate_limit=False, clock=t.clock)
        g = make_genesis(a, "pub2", [(carol, "member")], visibility="public")
        m.ingest(g)
        tid = event_id(g)
        d = b"voided data"
        store = BlobStore(Path(tempfile.mkdtemp()) / "v", clock=t.clock)
        cid = store.put(d, referenced=())
        pre = Writer(carol, m.threads[tid]).post("pre", refs=[{"kind": "file", "cid": cid, "size": len(d)}])
        rm = Writer(a, m.threads[tid]).admin("member_remove", {"agent": carol.id})
        assert m.ingest(rm).ok
        assert m.ingest(pre).status == "voided"
        srv = S.SyncServer(m, identity=a, clock=t.clock)
        pb = PB.PublicBlob(srv, BlobService(store, BlobIndex(m), clock=t.clock), clock=t.clock)
        door = PublicRead(srv, clock=t.clock, blobs=pb)
        ch = door.handle({"t": "blob", "thread": tid, "cid": cid, "offset": 0, "n": 10, "nonce": os.urandom(8).hex()})
        nonce = os.urandom(8).hex()
        salt = bytes.fromhex(ch["salt"])
        pw = P.solve(salt, tid, "", PB.binding(cid, 0, 10, nonce), ch["bits"])
        return door.handle({"t": "blob", "thread": tid, "cid": cid, "offset": 0, "n": 10, "nonce": nonce, "pow": {"salt": salt.hex(), "nonce": pw}})


class Proofs(Base):
    def test_proof_is_bound_to_cid_offset_n_nonce_thread(self):
        good = self.req(offset=10, n=100)
        for field, value in (("cid", B.cid_of(b"x")), ("offset", 11), ("n", 101), ("nonce", self.nonce()), ("thread", "0" * 32)):
            bad = dict(good, **{field: value})
            out = self.door.handle(bad)
            self.assertEqual((out["t"], out.get("why")), ("error", "bad proof"), field)

    def test_too_few_bits_bad_nonce_types_and_shape(self):
        self.assertEqual(self.door.handle(self.req(bits=0))["why"], "bad proof")
        r = self.req()
        for pw in ({"salt": r["pow"]["salt"]}, {"salt": r["pow"]["salt"], "nonce": "5"}, {"salt": "zz" * 16, "nonce": 1}, {"salt": "ab", "nonce": 1},
                   {"salt": r["pow"]["salt"], "nonce": -1}, {"salt": r["pow"]["salt"], "nonce": 2 ** 70}, {"salt": r["pow"]["salt"], "nonce": 1, "x": 1}, 5, None):
            self.assertIn(self.door.handle(dict(r, pow=pw))["t"], ("error",), pw)

    def test_replay_of_a_proof_is_refused(self):
        r = self.req()
        self.assertEqual(self.door.handle(r)["t"], "blobdata")
        self.assertEqual(self.door.handle(r)["why"], "replayed proof")

    def test_salt_current_and_previous_then_stale_with_a_fresh_challenge(self):
        r = self.req()
        self.clock.t += PB.PERIOD
        self.assertEqual(self.door.handle(r)["t"], "blobdata")
        r2 = self.req()
        self.clock.t += 2 * PB.PERIOD
        out = self.door.handle(r2)
        self.assertEqual(out["t"], "stale")
        self.assertIn("salt", out)

    def test_restart_means_new_challenges_not_a_crash(self):
        r = self.req()
        pb2 = PB.PublicBlob(self.srv, self.svc, clock=self.clock)                  # a new process: new secret
        out = PublicRead(self.srv, clock=self.clock, blobs=pb2).handle(r)
        self.assertEqual(out["t"], "stale")

    def test_the_replay_set_is_bounded(self):
        self.pb.seen.clear()
        for i in range(PB.MAX_SEEN + 50):
            self.pb._used((b"s", str(i), i))
        self.assertEqual(len(self.pb.seen), PB.MAX_SEEN)

    def test_malformed_requests(self):
        base = {"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 10, "nonce": self.nonce()}
        for bad in (dict(base, extra=1), {k: v for k, v in base.items() if k != "n"}, dict(base, n="10"), dict(base, offset=True), dict(base, nonce="short"),
                    dict(base, thread=5), dict(base, cid=None), dict(base, pow=5), dict(base, **{"from": "x"})):
            out = self.door.handle(bad)
            self.assertEqual((out["t"], out["why"]), ("error", "malformed request"), bad)
        for bad in (dict(base, n=0), dict(base, n=MAX_CHUNK + 1), dict(base, offset=-1)):
            self.assertEqual(self.door.handle(bad)["why"], "bad range", bad)

    def test_a_door_without_blobs_does_not_answer(self):
        out = PublicRead(self.srv, clock=self.clock).handle({"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 10, "nonce": self.nonce()})
        self.assertEqual((out["t"], out["why"]), ("error", "malformed request"))


class Budgets(Base):
    def test_blob_budgets_are_not_the_read_budgets(self):
        ch = self.chal()
        reqs = [self.req(ch=ch) for _ in range(5)]
        self.pb.hits.clear()
        self.pb.req_per_min = 3
        door = PublicRead(self.srv, clock=self.clock, blobs=self.pb, req_per_min=3)
        for r in reqs[:3]:
            self.assertEqual(door.handle(r)["t"], "blobdata")
        self.assertEqual(door.handle(reqs[3])["why"], "rate limited")
        summary = {"t": "summary", "thread": self.tid, "nonce": self.nonce()}
        self.assertEqual(door.handle(summary)["t"], "summary", "reads still work although blobs are rate limited")
        # and the other way round: spend the read budget, blobs still work
        self.clock.t += 61
        door2 = PublicRead(self.srv, clock=self.clock, blobs=PB.PublicBlob(self.srv, self.svc, clock=self.clock), req_per_min=2)
        for _ in range(2):
            door2.handle({"t": "summary", "thread": self.tid, "nonce": self.nonce()})
        self.assertEqual(door2.handle({"t": "summary", "thread": self.tid, "nonce": self.nonce()})["why"], "rate limited")
        ch = door2.handle({"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 100, "nonce": self.nonce()})
        self.assertEqual(ch["t"], "challenge", "blob requests do not spend (or hide behind) the read budget")

    def test_challenges_are_free_and_only_verified_proofs_spend_the_budget(self):
        """Sansa REQUIRED 2: one client must not burn the budget with free challenge requests or with bad proofs."""
        self.pb.req_per_min = 3
        for _ in range(50):
            self.assertEqual(self.door.handle({"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 100, "nonce": self.nonce()})["t"], "challenge")
        ch = self.chal(100)
        for _ in range(20):
            bad = self.req(n=100, ch=ch, bits=0)
            while P.verify(bytes.fromhex(ch["salt"]), self.tid, "", PB.binding(self.cid, 0, 100, bad["nonce"]), bad["pow"]["nonce"], ch["bits"]):
                bad = self.req(n=100, ch=ch, bits=0)                           # a proof of 0 bits is valid by chance about once in 2**bits: draw again, so the test is deterministic
            self.assertEqual(self.door.handle(bad).get("why"), "bad proof")
        for _ in range(3):
            self.assertEqual(self.door.handle(self.req(n=100, ch=ch))["t"], "blobdata")
        self.assertEqual(self.door.handle(self.req(n=100, ch=ch))["why"], "rate limited")

    def test_byte_budget(self):
        c1500, c10 = self.chal(1500), self.chal(10)
        reqs = [self.req(n=1500, ch=c1500), self.req(n=1500, ch=c1500), self.req(n=10, ch=c10)]
        self.pb.bytes_per_min = 3000
        self.assertEqual(self.door.handle(reqs[0])["t"], "blobdata")
        self.assertEqual(self.door.handle(reqs[1])["t"], "blobdata")           # 3000+ spent by now: the NEXT one is refused
        self.assertEqual(self.door.handle(reqs[2])["why"], "rate limited")
        self.clock.t += 61
        self.assertEqual(self.door.handle(self.req(n=10))["t"], "blobdata")

    def test_concurrency_cap(self):
        pb = PB.PublicBlob(self.srv, self.svc, clock=self.clock, max_concurrent=1)
        door = PublicRead(self.srv, clock=self.clock, blobs=pb)
        gate, entered = threading.Event(), threading.Event()
        real = self.store.read

        def slow(cid, off, n):
            entered.set()
            gate.wait(5)
            return real(cid, off, n)
        self.store.read = slow
        out = {}
        ch = self.chal(door=door)
        first, second, third = self.req(ch=ch, door=door), self.req(ch=ch, door=door), self.req(ch=ch, door=door)
        th = threading.Thread(target=lambda: out.update(first=door.handle(first)))
        th.start()
        self.assertTrue(entered.wait(5))
        busy = door.handle(second)
        gate.set()
        th.join(5)
        self.assertEqual((busy["t"], busy["why"]), ("error", "busy"))
        self.assertEqual(out["first"]["t"], "blobdata")
        self.store.read = real
        self.assertEqual(door.handle(third)["t"], "blobdata", "the slot was released")


class Client(Base):
    def setUp(self):
        super().setUp()
        self._min = F.MIN_CHUNK
        F.MIN_CHUNK = 1000
        self.addCleanup(setattr, F, "MIN_CHUNK", self._min)

    def go(self, source, **kw):
        mb = Mirror(tempfile.mkdtemp(), rate_limit=False, clock=self.clock)
        S.pull(mb, self.tid, S.Loopback(self.srv), Identity.generate("reader"), peer_id=self.a.id) if False else None
        for e in [self.m.threads[self.tid].stored[i] for i in self.m.threads[self.tid].order]:
            mb.ingest(e, live=False)
        store = BlobStore(Path(tempfile.mkdtemp()) / "c", clock=self.clock)
        r = F.fetch(mb, store, BlobIndex(mb), self.tid, self.cid, [source], Identity.generate("reader"), referenced={self.cid}, sleep=lambda s: None, clock=self.clock, **kw)
        return r, store

    def test_public_fetch_end_to_end_with_a_cached_challenge(self):
        door = Door(self.door.handle)
        src = F.PublicSource(door, "door-1")
        r, store = self.go(src, chunk=F.MIN_CHUNK)
        self.assertTrue(r["ok"], r)
        self.assertEqual(store.read(self.cid, 0, 10 ** 6), self.data)
        challenges = [c for c in door.calls if "pow" not in c]
        self.assertEqual(len(challenges), 1, "one challenge per chunk size, then cached")
        self.assertGreater(len(door.calls), 3)

    def test_the_client_refuses_an_unreasonable_proof_demand(self):
        class Greedy:
            def request(s, req):
                return {"t": "challenge", "salt": "00" * 16, "bits": 40, "expires": 1, "nonce": req["nonce"], "r": 1}
        r, store = self.go(F.PublicSource(Greedy(), "greedy"))
        self.assertFalse(r["ok"])
        self.assertIn("proof of work", r["why"])

    def test_stale_mid_transfer_refetches_the_challenge_once(self):
        door = Door(self.door.handle)
        src = F.PublicSource(door, "door-1")
        r1, _ = self.go(src, chunk=F.MIN_CHUNK)
        self.assertTrue(r1["ok"])
        self.clock.t += 3 * PB.PERIOD                                           # the cached salt is now too old
        r2, store = self.go(src, chunk=F.MIN_CHUNK)
        self.assertTrue(r2["ok"], r2)
        self.assertEqual(store.read(self.cid, 0, 10 ** 6), self.data)

    def test_a_door_serving_wrong_bytes_is_caught_by_the_final_hash_and_banned(self):
        def evil(req):
            out = self.door.handle(req)
            if out.get("t") == "blobdata":
                out["data"] = base64.b64encode(os.urandom(len(base64.b64decode(out["data"])))).decode()
            return out
        bans = set()
        r, store = self.go(F.PublicSource(Door(evil), "evil-door"), bans=bans)
        self.assertFalse(r["ok"])
        self.assertEqual(bans, {("evil-door", self.cid)})
        self.assertFalse(store.has(self.cid))

    def test_an_answer_to_another_request_is_refused(self):
        class Replayer:
            def __init__(s): s.saved = None
            def request(s, req):
                if s.saved is None:
                    s.saved = Door(self_door.handle).request(req)
                return dict(s.saved)
        self_door = self.door
        r, _ = self.go(F.PublicSource(Replayer(), "replay"))
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
