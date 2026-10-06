"""The `blob` sync op (DESIGN_blobs.md rev 1): the gate (members only, non-guests, non-voided referenced cids, held bytes) with ONE answer for every refusal,
range handling, budgets that are separate from pull's, replay/signature rules still apply, and the server never reads under the mirror lock."""
import base64
import os
import tempfile
import unittest
from pathlib import Path

from sigilnet import blob as B
from sigilnet import sync as S
from sigilnet.blobindex import BlobIndex
from sigilnet.blobserve import MAX_CHUNK, BlobService
from sigilnet.blobstore import BlobStore
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.tests.util import World


class Clock:
    def __init__(self):
        self.t = 2000000.0

    def __call__(self):
        return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.w = World(extra_members=[("dave", "guest")])
        self.m = Mirror(tempfile.mkdtemp(), rate_limit=False, clock=self.clock)
        self.m.ingest(self.w.genesis)
        self.tid = self.w.t.id
        self.store = BlobStore(Path(tempfile.mkdtemp()) / "b", clock=self.clock)
        self.svc = BlobService(self.store, BlobIndex(self.m), clock=self.clock)
        self.srv = S.SyncServer(self.m, clock=self.clock, identity=self.w.ids["arya"], blobs=self.svc)
        self.data = os.urandom(1000)
        self.cid = self.store.put(self.data, referenced=())
        self.post("sansa", [self.cid, len(self.data)])

    def post(self, who, ref=None, **kw):
        refs = [{"kind": "file", "cid": ref[0], "size": ref[1]}] if ref else []
        ev = self.w.w(who).post("attachment", refs=refs)
        self.w.add(ev)
        self.assertTrue(self.m.ingest(ev).ok)
        return ev

    def ask(self, who, cid=None, offset=0, n=400, thread=None, aud=True, **extra):
        body = {"t": "blob", "thread": thread or self.tid, "cid": cid or self.cid, "offset": offset, "n": n, **extra}
        req = S.sign_request(self.w.ids[who], body, ts=int(self.clock()), aud=self.w.ids["arya"].id if aud else None)
        return self.srv.handle(req)


class Gate(Base):
    def test_member_gets_data_with_offsets(self):
        got = b""
        while len(got) < len(self.data):
            r = self.ask("carol", offset=len(got), n=300)
            self.assertEqual((r["t"], r["total"], r["cid"], r["thread"]), ("blobdata", 1000, self.cid, self.tid), r)
            got += base64.b64decode(r["data"])
        self.assertEqual(got, self.data)
        end = self.ask("carol", offset=1000)
        self.assertEqual((end["t"], end["data"]), ("blobdata", ""))

    def test_every_refusal_is_the_same_unknown(self):
        other = self.store.put(b"unreferenced blob", referenced=())
        removed = self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id})
        self.w.add(removed)
        self.m.ingest(removed)
        cases = {
            "stranger (not a member)": self.ask("eve"),
            "removed member": self.ask("carol"),
            "unreferenced cid we hold": self.ask("sansa", cid=other),
            "unknown cid": self.ask("sansa", cid=B.cid_of(b"never seen")),
            "unknown thread": self.ask("sansa", thread="0" * 64),
            "malformed cid": self.ask("sansa", cid="sha256:zz"),
            "non-string cid": self.ask("sansa", cid=5),
        }
        for what, r in cases.items():
            self.assertEqual({k: v for k, v in r.items() if k not in ("nonce", "r", "by", "rsig")}, {"t": "unknown"}, what)

    def test_observer_is_a_member_reader_but_a_guest_is_not(self):
        self.assertEqual(self.w.t.state()["members"][self.w.ids["dave"].id]["role"], "guest")
        self.assertEqual(self.ask("hu")["t"], "blobdata")                # observers are current non-guest members and may read
        self.assertEqual(self.ask("dave")["t"], "unknown")               # a guest on the roster is still not a member for blobs

    def test_voided_referrer_stops_serving(self):
        d = os.urandom(50)
        c = self.store.put(d, referenced=())
        pre = self.w.w("carol").post("pre", refs=[{"kind": "file", "cid": c, "size": 50}])
        rm = self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id})
        self.w.add(rm)
        self.m.ingest(rm)
        self.assertEqual(self.m.ingest(pre).status, "voided")
        self.assertEqual(self.ask("sansa", cid=c, n=50)["t"], "unknown")

    def test_referenced_but_not_held_is_unknown(self):
        ghost = B.cid_of(b"ghost")
        self.post("sansa", [ghost, 5])
        self.assertEqual(self.ask("sansa", cid=ghost)["t"], "unknown")

    def test_a_node_without_blobs_says_unknown(self):
        srv = S.SyncServer(self.m, clock=self.clock, identity=self.w.ids["arya"])
        req = S.sign_request(self.w.ids["sansa"], {"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 10}, ts=int(self.clock()))
        self.assertEqual(srv.handle(req)["t"], "unknown")


class Logging(Base):
    """Live-test gap L1: the serving node logged nothing about blob requests."""

    def setUp(self):
        super().setUp()
        self.lines = []
        self.svc.log = self.lines.append

    def test_the_first_and_last_chunk_are_logged_without_content_and_middles_are_not(self):
        for off in (0, 300, 600, 900):
            self.assertEqual(self.ask("carol", offset=off, n=300)["t"], "blobdata")
        self.assertEqual(len(self.lines), 2, self.lines)
        self.assertIn("offset 0, 300 of 1000", self.lines[0])
        self.assertIn("(last chunk)", self.lines[1])
        self.assertIn(self.cid[:19], self.lines[0])
        self.assertNotIn(base64.b64encode(self.data[:30]).decode()[:20], " ".join(self.lines))
        self.assertTrue(all(self.w.ids["carol"].id[:8] in l for l in self.lines))

    def test_refusals_log_nothing(self):
        self.ask("dave", n=100)                                                   # a guest
        self.ask("carol", cid="sha256:" + "0" * 64)                                # unknown
        self.assertEqual(self.lines, [])

    def test_a_failing_log_never_changes_the_answer(self):
        def boom(_):
            raise RuntimeError("disk full")
        self.svc.log = boom
        self.assertEqual(self.ask("carol", n=300)["t"], "blobdata")


class Fresh(Base):
    def test_a_reference_appended_by_another_process_is_served_at_once(self):
        other = Mirror(self.m.root, rate_limit=False, clock=self.clock)          # another handle on the same directory (the CLI process)
        d = os.urandom(30)
        c = self.store.put(d, referenced=())
        ev = self.w.w("sansa").post("new attachment", refs=[{"kind": "file", "cid": c, "size": 30}])
        self.w.add(ev)
        self.assertTrue(other.ingest(ev).ok)
        self.assertNotIn(ev["seq"] and __import__("sigilnet.event", fromlist=["event_id"]).event_id(ev), self.m.threads[self.tid].events)
        self.assertEqual(self.ask("carol", cid=c, n=30)["t"], "blobdata")


class Ranges(Base):
    def test_bad_ranges_only_after_the_gate(self):
        for kw in (dict(offset=-1), dict(offset=1001), dict(n=0), dict(n=-5), dict(n=MAX_CHUNK + 1), dict(offset="0"), dict(n="5"), dict(offset=True)):
            r = self.ask("sansa", **kw)
            self.assertEqual((r["t"], r.get("why")), ("error", "bad range"), kw)
            self.assertEqual(self.ask("eve", **kw)["t"], "unknown", kw)    # a stranger never learns the range rules
        self.assertEqual(self.ask("sansa", offset=1000, n=MAX_CHUNK)["data"], "")
        r = self.ask("sansa", n=MAX_CHUNK)
        self.assertEqual(len(base64.b64decode(r["data"])), 1000)

    def test_max_chunk_roundtrip_size(self):
        big = os.urandom(MAX_CHUNK + 5)
        c = self.store.put(big, referenced=())
        self.post("sansa", [c, len(big)])
        r = self.ask("sansa", cid=c, n=MAX_CHUNK)
        self.assertEqual(len(base64.b64decode(r["data"])), MAX_CHUNK)
        self.assertLess(len(S.canon.dumps(r)), 1024 * 1024, "fits tcp.MAX_RESP")


class Budgets(Base):
    def test_blob_requests_do_not_use_the_pull_budgets(self):
        for _ in range(S.RATE_PER_MIN + 20):
            self.assertEqual(self.ask("sansa", n=10)["t"], "blobdata")
        req = S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid}, ts=int(self.clock()), aud=self.w.ids["arya"].id)
        self.assertEqual(self.srv.handle(req)["t"], "summary", "a download did not starve a pull")

    def test_an_exhausted_pull_budget_does_not_block_blobs(self):
        req = lambda: S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid}, ts=int(self.clock()), aud=self.w.ids["arya"].id)
        for _ in range(S.RATE_PER_MIN + 1):
            r = self.srv.handle(req())
        self.assertEqual(r.get("why"), "rate limited", "the pull budget is spent")
        self.assertEqual(self.ask("sansa", n=10)["t"], "blobdata")

    def test_per_peer_request_limit_then_recovery_and_other_peers_unaffected(self):
        self.srv.blobs = BlobService(self.store, BlobIndex(self.m), clock=self.clock, peer_reqs=3)
        for _ in range(3):
            self.assertEqual(self.ask("sansa", n=10)["t"], "blobdata")
        r = self.ask("sansa", n=10)
        self.assertEqual((r["t"], r["why"]), ("error", "rate limited"))
        self.assertEqual(self.ask("carol", n=10)["t"], "blobdata")
        self.clock.t += 61
        self.assertEqual(self.ask("sansa", n=10)["t"], "blobdata")

    def test_byte_budgets_per_peer_and_global(self):
        self.srv.blobs = BlobService(self.store, BlobIndex(self.m), clock=self.clock, peer_bytes=1500, total_bytes=2500)
        self.assertEqual(self.ask("sansa", n=1000)["t"], "blobdata")
        self.assertEqual(self.ask("sansa", n=1000)["t"], "blobdata")     # 2000 >= 1500: the NEXT one is refused
        self.assertEqual(self.ask("sansa", n=1000)["why"], "rate limited")
        self.assertEqual(self.ask("carol", n=1000)["t"], "blobdata")     # 3000 >= 2500 globally now
        self.assertEqual(self.ask("hu", n=10)["why"], "rate limited")
        self.clock.t += 61
        self.assertEqual(self.ask("hu", n=10)["t"], "blobdata")


class Sybil(Base):
    def test_strangers_with_fresh_keys_cannot_spend_what_members_need(self):
        self.srv.blobs = BlobService(self.store, BlobIndex(self.m), clock=self.clock, total_reqs=50, total_bytes=10 ** 6)
        for i in range(120):                                              # 120 throwaway identities, each within its own per-peer limit
            ghost = Identity.generate(f"g{i}")
            self.w.ids[f"g{i}"] = ghost
            self.assertEqual(self.ask(f"g{i}")["t"], "unknown")
        self.assertEqual(self.ask("carol", n=10)["t"], "blobdata", "a member is still served")

    def test_global_budgets_do_bind_members(self):
        self.srv.blobs = BlobService(self.store, BlobIndex(self.m), clock=self.clock, total_reqs=2)
        self.assertEqual(self.ask("carol", n=10)["t"], "blobdata")
        self.assertEqual(self.ask("sansa", n=10)["t"], "blobdata")
        self.assertEqual(self.ask("hu", n=10)["why"], "rate limited")
        self.assertEqual(self.ask("eve", n=10)["t"], "unknown", "a stranger is not told anything about the budget")
        self.clock.t += 61
        self.assertEqual(self.ask("hu", n=10)["t"], "blobdata")


class Unvetted(Base):
    """Sansa DESIGN FLAG C: requesters outside the lock-free member snapshot may reach the mirror lock only within a small global budget."""

    def count_locks(self):
        n = {"locks": 0}
        real = self.m._lock

        def counting():
            n["locks"] += 1
            return real()
        self.m._lock = counting
        return n

    def test_strangers_are_cut_off_before_the_lock_once_the_unvetted_budget_is_spent(self):
        self.srv.blobs = BlobService(self.store, BlobIndex(self.m), clock=self.clock, unvetted_per_min=5)
        n = self.count_locks()
        for i in range(60):
            ghost = Identity.generate(f"u{i}")
            self.w.ids[f"u{i}"] = ghost
            self.assertEqual(self.ask(f"u{i}")["t"], "unknown")
        self.assertEqual(n["locks"], 5, "only the first five strangers reached the mirror lock")

    def test_snapshot_members_never_touch_the_unvetted_budget_and_pass_the_gate(self):
        self.srv.blobs = BlobService(self.store, BlobIndex(self.m), clock=self.clock, unvetted_per_min=1)
        self.assertEqual(self.ask("carol", n=10)["t"], "blobdata")             # the first request is unvetted (empty snapshot) and uses the one slot
        self.assertEqual(self.ask("eve")["t"], "unknown")                      # a stranger: the slot is gone, no lock
        for _ in range(20):
            self.assertEqual(self.ask("carol", n=10)["t"], "blobdata", "a vetted member is not limited by the stranger budget")
        self.assertEqual(self.ask("sansa", n=10)["t"], "blobdata", "the snapshot holds every non-guest member of the thread, not just the requester")

    def test_a_removed_member_in_the_snapshot_still_meets_the_real_gate(self):
        self.assertEqual(self.ask("carol", n=10)["t"], "blobdata")
        rm = self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id})
        self.w.add(rm)
        self.m.ingest(rm)
        self.assertTrue(self.srv.blobs.vetted(self.tid, self.w.ids["carol"].id, self.w.ids["carol"].sign_pub), "the stale snapshot says yes")
        self.assertEqual(self.ask("carol", n=10)["t"], "unknown", "the gate under the lock refuses")

    def test_a_normal_pull_request_refreshes_the_snapshot(self):
        self.assertFalse(self.srv.blobs.vetted(self.tid, self.w.ids["sansa"].id, self.w.ids["sansa"].sign_pub))
        req = S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid}, ts=int(self.clock()), aud=self.w.ids["arya"].id)
        self.assertEqual(self.srv.handle(req)["t"], "summary")
        self.assertTrue(self.srv.blobs.vetted(self.tid, self.w.ids["sansa"].id, self.w.ids["sansa"].sign_pub))
        self.assertFalse(self.srv.blobs.vetted(self.tid, self.w.ids["dave"].id, self.w.ids["dave"].sign_pub), "guests are not in the snapshot")


class Authentication(Base):
    def test_replay_wrong_audience_unsigned_and_bad_signature(self):
        req = S.sign_request(self.w.ids["sansa"], {"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 10}, ts=int(self.clock()),
                             aud=self.w.ids["arya"].id)
        self.assertEqual(self.srv.handle(req)["t"], "blobdata")
        self.assertEqual(self.srv.handle(req)["why"], "replayed request")
        wrong = S.sign_request(self.w.ids["sansa"], {"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 10}, ts=int(self.clock()),
                               aud=self.w.ids["carol"].id)
        self.assertEqual(self.srv.handle(wrong)["why"], "wrong audience")
        bad = S.sign_request(self.w.ids["sansa"], {"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 10}, ts=int(self.clock()))
        bad["offset"] = 1
        self.assertEqual(self.srv.handle(bad)["why"], "bad signature")
        old = S.sign_request(self.w.ids["sansa"], {"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 10}, ts=int(self.clock()) - 5000)
        self.assertEqual(self.srv.handle(old)["why"], "stale request (check clocks)")

    def test_response_is_signed_and_bound_to_the_nonce(self):
        req = S.sign_request(self.w.ids["sansa"], {"t": "blob", "thread": self.tid, "cid": self.cid, "offset": 0, "n": 10}, ts=int(self.clock()),
                             aud=self.w.ids["arya"].id)
        r = self.srv.handle(req)
        self.assertEqual(r["nonce"], req["nonce"])
        self.assertTrue(S.response_signed_by(r, self.w.ids["arya"].id))
        r["data"] = base64.b64encode(b"tampered").decode()
        self.assertFalse(S.response_signed_by(r, self.w.ids["arya"].id))


class Locking(Base):
    def test_the_read_is_outside_the_mirror_lock(self):
        seen = []
        real = self.store.read

        def spy(cid, off, n):
            import fcntl
            fd = os.open(self.m.lockf, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)         # would raise BlockingIOError if the mirror lock were held by this process's other fd
                seen.append("free")
            except BlockingIOError:
                seen.append("held")
            finally:
                os.close(fd)
            return real(cid, off, n)
        self.store.read = spy
        self.assertEqual(self.ask("sansa", n=10)["t"], "blobdata")
        self.assertEqual(seen, ["free"])


if __name__ == "__main__":
    unittest.main()
