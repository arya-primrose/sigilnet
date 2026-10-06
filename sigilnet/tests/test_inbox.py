import tempfile
import unittest

from sigilnet import pow as P
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.inbox import Inbox, PERIOD, REFUSED
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror


class Clock:
    def __init__(self): self.t = 1_800_000_000.0
    def __call__(self): return self.t


def policy(**kw):
    return {"mode": "moderated", "pow_bits": 4, "queue_max": 6, "reserved_reply_slots": 2, "request_ttl_hours": 72, "max_bytes": 4096, **kw}


class Base(unittest.TestCase):
    def setUp(self, vis="public", **gp):
        self.clock = Clock()
        self.home = tempfile.mkdtemp()
        self.m = Mirror(self.home + "/mirror", clock=self.clock, rate_limit=False)
        self.owner = Identity.generate("arya")
        g = make_genesis(self.owner, "open topic", [], visibility=vis, guest_policy=policy(**gp), ts=int(self.clock()))
        self.tid = event_id(g)
        self.assertEqual(self.m.ingest(g).status, "accepted")
        self.t = self.m.threads[self.tid]
        self.root = Writer(self.owner, self.t).post("hello world")
        self.assertTrue(self.m.ingest(self.root).ok)
        self.rid = event_id(self.root)
        self.inbox = Inbox(self.m, self.home, clock=self.clock)

    def chal(self):
        return self.inbox.handle({"t": "challenge", "thread": self.tid})

    def req(self, who=None, text="please", reply_to=None, bits=None, salt=None):
        who = who or Identity.generate("g")
        ch = self.chal()
        ev = Writer(who, self.t).guest_request(text, reply_to or self.rid, ts=int(self.clock()))
        s = bytes.fromhex(salt or ch["salt"])
        n = P.solve(s, self.tid, who.sign_pub, event_id(ev), ch["bits"] if bits is None else bits)
        return {"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": s.hex(), "nonce": n}}, ev


class Basics(Base):
    def test_challenge_and_submit(self):
        ch = self.chal()
        self.assertEqual(ch["t"], "challenge")
        self.assertEqual(ch["bits"], 4)
        r, ev = self.req()
        self.assertEqual(self.inbox.handle(r), {"t": "ok", "id": event_id(ev)})
        self.assertIn(event_id(ev), self.t.awaiting)
        self.assertEqual(self.inbox.waiting(self.tid)[0][0], event_id(ev))

    def test_a_guest_request_with_refs_is_refused(self):
        who = Identity.generate("g")
        ch = self.chal()
        ref = {"kind": "file", "cid": "sha256:" + "ab" * 32, "size": 5}
        g = {"name": "g", "sign": who.sign_pub, "kex": who.kex_pub}
        from sigilnet import event as E
        ev = E.make_event(who, thread=self.tid, kind="post", body={"text": "see file", "reply_to": self.rid, "guest": g, "refs": [ref]}, parents=[self.rid], seq=0,
                          admin_ref=self.t.head, ts=int(self.clock()))
        s = bytes.fromhex(ch["salt"])
        n = P.solve(s, self.tid, who.sign_pub, event_id(ev), ch["bits"])
        out = self.inbox.handle({"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": s.hex(), "nonce": n}})
        self.assertEqual(out, {"t": "refused", "why": "guests may not attach files"})
        self.assertNotIn(event_id(ev), self.t.awaiting)

    def test_idempotent_resubmit(self):
        r, ev = self.req()
        self.inbox.handle(r)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertEqual(len(self.t.awaiting), 1)

    def test_stateless_salt_survives_restart(self):
        r, ev = self.req()
        inbox2 = Inbox(self.m, self.home, clock=self.clock)       # same secret file, no memory of the challenge
        self.assertEqual(inbox2.handle(r)["t"], "ok")

    def test_salt_current_and_previous_only(self):
        r, ev = self.req()
        self.clock.t += PERIOD
        self.assertEqual(self.inbox.handle(r)["t"], "ok")         # previous period still valid
        r2, _ = self.req()
        self.clock.t += 2 * PERIOD
        out = self.inbox.handle(r2)
        self.assertEqual((out["t"], out["why"]), ("stale", "salt"))
        self.assertIn("salt", out)                                # the answer carries a fresh challenge

    def test_wrong_proof_and_bits(self):
        r, _ = self.req(bits=0)
        r["pow"]["nonce"] = 0
        bad = 0
        for n in range(64):
            r["pow"]["nonce"] = n
            if self.inbox.handle(r)["t"] == "stale":
                bad += 1
        self.assertGreater(bad, 40)                               # a nonce of 0..63 at 4 bits usually fails

    def test_proof_bound_to_event_and_key(self):
        r, ev = self.req()
        r2, ev2 = self.req()
        r2["pow"] = r["pow"]                                      # proof of another request
        out = self.inbox.handle(r2)
        self.assertIn(out["t"], ("stale", "ok"))                  # 1 in 16 can pass by luck at 4 bits; raise bits to make it certain below
        self.inbox.bits[self.tid] = [16, self.clock.t]
        self.clock.t += 10
        r3, _ = self.req(bits=16)
        r4, _ = self.req(bits=16)
        r4["pow"] = r3["pow"]
        self.assertEqual(self.inbox.handle(r4)["t"], "stale")

    def test_stranger_cannot_read_or_do_anything_else(self):
        for q in ({"t": "list", "thread": self.tid}, {"t": "get", "thread": self.tid, "ids": [self.rid]}, {"t": "summary", "thread": self.tid},
                  {"t": "notify", "thread": self.tid}, {"t": "challenge"}, {"t": "submit"}, [], None, "x", {"t": 1}, {"t": "challenge", "thread": self.tid, "x": 1}):
            self.assertEqual(self.inbox.handle(q), REFUSED, q)

    def test_non_public_and_missing_identical(self):
        Base.setUp(self, vis="private")
        self.assertEqual(self.inbox.handle({"t": "challenge", "thread": self.tid}), REFUSED)
        self.assertEqual(self.inbox.handle({"t": "challenge", "thread": "0" * 64}), REFUSED)
        r = {"t": "submit", "thread": self.tid, "event": {}, "pow": {}}
        self.assertEqual(self.inbox.handle(r), REFUSED)

    def test_size_cap(self):
        Base.setUp(self, max_bytes=256)
        r, _ = self.req(text="x" * 400)
        out = self.inbox.handle(r)
        self.assertEqual(out["t"], "refused")
        self.assertEqual(len(self.t.awaiting), 0)

    def test_unknown_reply_to(self):
        r, _ = self.req(reply_to="a" * 64)
        self.assertEqual(self.inbox.handle(r)["t"], "refused")
        self.assertEqual(len(self.t.awaiting), 0)

    def test_forged_signature_not_queued(self):
        r, ev = self.req()
        ev["body"]["text"] = "tampered"
        out = self.inbox.handle(r)                                 # the id changed, so the proof no longer matches: stale, not queued
        self.assertNotEqual(out["t"], "ok")
        self.assertEqual(len(self.t.awaiting), 0)

    def test_malformed_never_raises(self):
        for junk in ({"t": "submit", "thread": self.tid, "event": 5, "pow": {}}, {"t": "submit", "thread": self.tid, "event": {"a": 1}, "pow": {"salt": "zz", "nonce": 1}},
                     {"t": "submit", "thread": self.tid, "event": {}, "pow": {"salt": "0" * 32, "nonce": 1}}, {"t": "submit", "thread": self.tid, "event": {"body": 1}, "pow": {"salt": "0" * 32, "nonce": "x"}}):
            self.assertIn(self.inbox.handle(junk)["t"], ("refused", "stale"))   # never "ok", never an exception


class Queue(Base):
    def test_weakest_proof_evicted_not_by_author(self):
        general = 4                                                # queue_max 6 - 2 reserved
        # replies to a guest request (not an owner event) are general-pool; here all requests reply to the owner root -> owner pool (limit 6)
        for _ in range(6):
            r, _ = self.req(bits=6)
            self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertEqual(len(self.t.awaiting), 6)
        floor = min(b for _, b, _, _ in self.inbox.waiting(self.tid))
        while True:                                                    # a newcomer that is not strictly stronger than the weakest waiting one
            weak, wev = self.req(bits=4)
            if P.achieved(bytes.fromhex(weak["pow"]["salt"]), self.tid, wev["body"]["guest"]["sign"], event_id(wev), weak["pow"]["nonce"]) <= floor:
                break
        out = self.inbox.handle(weak)
        self.assertEqual(out, {"t": "refused", "why": "queue full"})
        self.inbox.bits[self.tid] = [9, 0]
        strong, sev = self.req(bits=9)
        self.assertEqual(self.inbox.handle(strong)["t"], "ok")
        self.assertEqual(len(self.t.awaiting), 6)
        self.assertIn(event_id(sev), self.t.awaiting)

    def test_sybil_flood_keeps_reserved_reply_slots(self):
        # general pool = guest-to-guest replies (not an owner reply): flood it with many keys
        first, fev = self.req()
        self.inbox.handle(first)
        for _ in range(12):
            r, _ = self.req(reply_to=event_id(fev))
            self.inbox.handle(r)
        general = [i for i in self.t.awaiting if not self.t._is_owner_reply(self.t.stored[i])]
        self.assertLessEqual(len(general), 4)
        owner = [i for i in self.t.awaiting if self.t._is_owner_reply(self.t.stored[i])]
        self.assertGreaterEqual(len(owner), 1)                     # the flood did not take the owner-reply slot

    def test_bits_sidecar_recorded_and_pruned(self):
        r, ev = self.req(bits=7)
        self.inbox.handle(r)
        self.assertGreaterEqual(self.inbox.waiting(self.tid)[0][1], 7)
        self.assertTrue(self.inbox.reject(self.tid, event_id(ev)))
        self.assertEqual(self.inbox.waiting(self.tid), [])
        self.assertEqual(self.inbox._load_bits(self.tid), {})

    def test_lost_sidecar_means_bits_zero_not_error(self):
        r, ev = self.req()
        self.inbox.handle(r)
        self.inbox._side(self.tid).unlink()
        self.assertEqual(self.inbox.waiting(self.tid)[0][1], 0)

    def test_pool_survives_restart_single_source(self):
        r, ev = self.req()
        self.inbox.handle(r)
        m2 = Mirror(self.home + "/mirror", clock=self.clock, rate_limit=False)
        self.assertIn(event_id(ev), m2.threads[self.tid].awaiting)
        self.assertEqual(Inbox(m2, self.home, clock=self.clock).waiting(self.tid)[0][0], event_id(ev))

    def test_reject_unknown_is_false(self):
        self.assertFalse(self.inbox.reject(self.tid, "a" * 64))


class Adaptive(Base):
    def test_raise_under_pressure_and_cap_and_lower(self):
        Base.setUp(self, queue_max=4, reserved_reply_slots=1, pow_bits=4)
        lo, hi = self.inbox.bounds(self.t)
        self.assertEqual((lo, hi), (4, 10))
        for _ in range(3):
            self.inbox.handle(self.req()[0])
        for step in range(40):                                     # sustained refusals
            self.clock.t += 61
            r, _ = self.req()
            self.inbox.handle(r)
            for _ in range(10):
                self.inbox._signal(self.t)
            self.inbox.handle({"t": "challenge", "thread": self.tid})
        self.assertEqual(self.inbox.current_bits(self.t), hi)     # rose, and stopped at the cap
        self.clock.t += 2 * 1800 + 10
        self.inbox.handle({"t": "challenge", "thread": self.tid})
        self.assertEqual(self.inbox.current_bits(self.t), hi - 1)  # lowers one step per quiet period

    def test_bits_minus_one_tolerance(self):
        self.inbox.bits[self.tid] = [8, self.clock.t]
        ch = self.chal()
        self.assertEqual(ch["bits"], 8)
        r, ev = self.req(bits=7)
        if P.achieved(bytes.fromhex(r["pow"]["salt"]), self.tid, ev["body"]["guest"]["sign"], event_id(ev), r["pow"]["nonce"]) >= 7:
            self.assertEqual(self.inbox.handle(r)["t"], "ok")

    def test_ceiling_respected_when_policy_is_higher(self):
        Base.setUp(self, pow_bits=30)
        self.assertEqual(self.inbox.bounds(self.t), (30, 30))


class Wake(Base):
    def test_wake_only_for_owner_reply_and_no_text(self):
        seen = []
        self.inbox.on_wake = lambda tid, n: seen.append((tid, n))
        r, ev = self.req()
        self.inbox.handle(r)
        self.assertEqual(seen, [(self.tid, 1)])
        r2, _ = self.req(reply_to=event_id(ev))
        self.inbox.handle(r2)
        self.assertEqual(len(seen), 1)


if __name__ == "__main__":
    unittest.main()


class PerAuthorReplay(Base):
    def test_per_author_cap_drop_is_recorded_so_no_replay(self):
        """Sansa round 15 F1: the thread layer forgets a key's oldest waiting request past the per-author cap without recording it; the forgotten one must not be resubmittable."""
        who = Identity.generate("one")
        reqs = []
        for k in range(5):
            r, ev = self.req(who=who, text=f"r{k}")
            reqs.append((r, ev))
            self.assertEqual(self.inbox.handle(r)["t"], "ok")
            self.clock.t += 1
        first_id = event_id(reqs[0][1])
        self.assertNotIn(first_id, self.t.awaiting)
        self.assertEqual(self.inbox.handle(reqs[0][0]), {"t": "refused", "why": "rejected earlier"})


class AlreadyMember(Base):
    def test_admitted_key_cannot_queue_a_second_request(self):
        """Live test 4a (Sansa 6b): a key that was already admitted sent a second REQUEST and it queued; it must be refused (it posts with `guest post` now)."""
        who = Identity.generate("g")
        r, ev = self.req(who=who)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        r2, ev2 = self.req(who=who, text="again")                      # built BEFORE the admission (same admin_ref), still a guest-REQUEST shape
        who_pub = type("P", (), {"id": who.id, "sign_pub": who.sign_pub, "kex_pub": who.kex_pub, "name": "g"})()
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).add_member(who_pub, "guest", admits=[event_id(ev)])).ok)
        out = self.inbox.handle(r2)
        self.assertEqual(out["t"], "refused")
        self.assertNotIn(event_id(ev2), self.t.awaiting)


class GuestPosts(Base):
    """Step 4a option (b), human decision 17:5x MDT: an ADMITTED guest posts through the inbox door."""

    def admit(self, who):
        r, ev = self.req(who=who)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        who_pub = type("P", (), {"id": who.id, "sign_pub": who.sign_pub, "kex_pub": who.kex_pub, "name": "g"})()
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).add_member(who_pub, "guest", admits=[event_id(ev)])).ok)
        return event_id(ev)

    def post(self, who, text="later post", parents=None, bits=None, mutate=None):
        ch = self.chal()
        ev = Writer(who, self.t).post(text, self.rid, ts=int(self.clock()))
        if parents is not None:
            ev = dict(ev, parents=parents)
        if mutate:
            ev = mutate(ev)
        salt = bytes.fromhex(ch["salt"])
        n = P.solve(salt, self.tid, who.sign_pub, event_id(ev), ch["bits"] if bits is None else bits)
        return {"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": salt.hex(), "nonce": n}}, ev

    def test_admitted_guest_posts_and_it_is_a_normal_thread_event(self):
        who = Identity.generate("g")
        self.admit(who)
        r, ev = self.post(who)
        self.assertEqual(self.inbox.handle(r), {"t": "ok", "id": event_id(ev)})
        self.assertIn(event_id(ev), self.t.events)
        self.assertEqual(self.t.events[event_id(ev)]["author"], who.id)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")                    # idempotent

    def test_an_admitted_guest_cannot_attach_files(self):
        """Blobs: a guest never pushes bytes, so a ref from a guest could never be fetched (DESIGN_blobs.md rev 1, finding 1)."""
        who = Identity.generate("g")
        self.admit(who)
        ref = {"kind": "file", "cid": "sha256:" + "ab" * 32, "size": 5}
        r, ev = self.post(who, mutate=lambda e: __import__("sigilnet.event", fromlist=["make_event"]).make_event(
            who, thread=self.tid, kind="post", body={"text": "x", "reply_to": self.rid, "refs": [ref]}, parents=e["parents"], seq=e["seq"], admin_ref=e["admin_ref"], ts=e["ts"]))
        self.assertEqual(self.inbox.handle(r), {"t": "refused", "why": "malformed"})
        self.assertNotIn(event_id(ev), self.t.events)

    def test_not_admitted_cannot_post_this_way(self):
        stranger = Identity.generate("s")
        r, ev = self.post(stranger)
        self.assertEqual(self.inbox.handle(r)["t"], "refused")
        self.assertNotIn(event_id(ev), self.t.stored)

    def test_members_and_owner_use_their_own_door(self):
        out = self.inbox.handle(self.post(self.owner)[0])
        self.assertEqual(out, {"t": "refused", "why": "members use their own door"})

    def test_removed_guest_refused(self):
        who = Identity.generate("g")
        self.admit(who)
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).admin("member_remove", {"agent": who.id})).ok)
        r, ev = self.post(who)
        self.assertEqual(self.inbox.handle(r)["t"], "refused")
        self.assertNotIn(event_id(ev), self.t.events)

    def test_needs_proof_of_work_bound_to_the_event(self):
        who = Identity.generate("g")
        self.admit(who)
        self.inbox.bits[self.tid] = [16, self.clock.t]
        r1, _ = self.post(who, "one", bits=16)
        r2, ev2 = self.post(who, "two", bits=16)
        r2["pow"] = r1["pow"]
        self.assertEqual(self.inbox.handle(r2)["t"], "stale")
        self.assertNotIn(event_id(ev2), self.t.stored)

    def test_forged_signature_and_unknown_parents_refused(self):
        who = Identity.generate("g")
        self.admit(who)
        r, ev = self.post(who, mutate=lambda e: dict(e, sig="0" * 128))
        self.assertEqual(self.inbox.handle(r), {"t": "refused", "why": "bad signature"})
        r, ev = self.post(who, parents=["a" * 32])
        self.assertEqual(self.inbox.handle(r), {"t": "refused", "why": "unknown parent"})
        r, ev = self.post(who, parents=[])
        self.assertEqual(self.inbox.handle(r)["t"], "refused")
        self.assertNotIn(event_id(ev), self.t.stored)

    def test_only_plain_post_bodies(self):
        who = Identity.generate("g")
        self.admit(who)
        for extra in ({"guest": {"name": "x", "sign": who.sign_pub, "kex": who.kex_pub}}, {"evil": 1}):
            r, ev = self.post(who, mutate=lambda e: __import__("sigilnet.event", fromlist=["x"]).make_event(who, thread=self.tid, kind="post", body={**e["body"], **extra},
                                                                                                     parents=e["parents"], seq=e["seq"], admin_ref=e["admin_ref"], ts=e["ts"]))
            self.assertEqual(self.inbox.handle(r), {"t": "refused", "why": "malformed"})

    def test_guest_quota_per_hour(self):
        from sigilnet.inbox import GUEST_POSTS_PER_HOUR
        who = Identity.generate("g")
        self.admit(who)
        outs = []
        for k in range(GUEST_POSTS_PER_HOUR + 3):
            r, ev = self.post(who, f"p{k}")
            outs.append(self.inbox.handle(r))
            self.clock.t += 1
        self.assertEqual([o["t"] for o in outs].count("ok"), GUEST_POSTS_PER_HOUR)
        self.assertEqual(outs[-1], {"t": "refused", "why": "guest post quota"})
        self.clock.t += 3700                                               # the window moves on (fresh salt period too)
        r, ev = self.post(who, "after an hour")
        self.assertEqual(self.inbox.handle(r)["t"], "ok")

    def test_read_door_and_inbox_still_separate(self):
        who = Identity.generate("g")
        self.admit(who)
        self.assertEqual(self.inbox.handle({"t": "list", "thread": self.tid}), {"t": "refused", "why": "no"})
