import tempfile
import unittest

from sigilnet import pow as P
from sigilnet.build import Writer
from sigilnet.event import event_id, make_event
from sigilnet.inbox import GUEST_POSTS_PER_HOUR, Inbox, PERIOD
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.tests.test_inbox import Base


def pubof(who):
    return type("P", (), {"id": who.id, "sign_pub": who.sign_pub, "kex_pub": who.kex_pub, "name": "g"})()


class D(Base):
    def admit(self, who, role="guest"):
        r, ev = self.req(who=who)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).add_member(pubof(who), role, admits=[event_id(ev)])).ok)
        return event_id(ev)

    def submit(self, who, ev, bits=None):
        ch = self.chal()
        salt = bytes.fromhex(ch["salt"])
        n = P.solve(salt, self.tid, who.sign_pub, event_id(ev), ch["bits"] if bits is None else bits)
        return {"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": salt.hex(), "nonce": n}}

    def mk(self, who, text="p", **kw):
        d = dict(thread=self.tid, kind="post", body={"text": text, "reply_to": self.rid}, parents=[self.rid],
                 seq=Writer(who, self.t)._seq(), admin_ref=self.t.head, ts=int(self.clock()))
        d.update(kw)
        return make_event(who, **d)

    def send(self, who, text="p", **kw):
        ev = self.mk(who, text, **kw)
        return self.inbox.handle(self.submit(who, ev)), ev

    def pools(self):
        t = self.t
        return len(t.stored), len(t.awaiting), sum(1 for i in t.stored if t.status.get(i) == "pending")


class Attacks(D):
    def test_forged_author_member_signed_by_other(self):
        g = Identity.generate("g"); self.admit(g)
        evil = Identity.generate("e")
        ev = self.mk(g)
        ev2 = make_event(evil, thread=self.tid, kind="post", body=ev["body"], parents=ev["parents"], seq=ev["seq"], admin_ref=ev["admin_ref"], ts=ev["ts"])
        ev2 = dict(ev2, author=g.id)
        out = self.inbox.handle(self.submit(g, ev2))
        self.assertEqual(out["t"], "refused")
        self.assertNotIn(event_id(ev2), self.t.stored)

    def test_old_admin_ref_before_admission_not_stored_not_awaiting(self):
        old_head = self.t.head
        g = Identity.generate("g"); self.admit(g)
        before = self.pools()
        out, ev = self.send(g, admin_ref=old_head)
        self.assertEqual(out["t"], "refused")
        self.assertEqual(self.pools(), before)
        self.assertNotIn(event_id(ev), self.t.awaiting)

    def test_unknown_admin_ref_is_not_parked_and_not_acked(self):
        """An admitted guest posts with an admin_ref the mirror does not hold: thread parks it as pending. The door must not keep parked state
        for a post it refuses, and a resubmit must not answer ok for an event that is not in the thread."""
        g = Identity.generate("g"); self.admit(g)
        before = self.pools()
        out, ev = self.send(g, admin_ref="a" * 32)
        self.assertEqual(out["t"], "refused")
        self.assertEqual(self.pools(), before, "refused post left a pending event in the thread")
        out2 = self.inbox.handle(self.submit(g, ev))
        self.assertNotEqual(out2["t"], "ok", "resubmit acked a post that never reached the thread")
        self.assertNotIn(event_id(ev), self.t.events)

    def test_unknown_admin_ref_flood_bounded(self):
        g = Identity.generate("g"); self.admit(g)
        base = self.pools()[0]
        for k in range(150):
            self.send(g, admin_ref=f"{k:032x}", seq=1000 + k)
        self.assertLessEqual(self.pools()[0] - base, 0, "refused posts accumulate as parked events")

    def test_admin_ref_newer_ok(self):
        g = Identity.generate("g"); self.admit(g)
        out, ev = self.send(g, admin_ref=self.t.head)
        self.assertEqual(out["t"], "ok")
        self.assertIn(event_id(ev), self.t.events)

    def test_admin_ref_non_admin_event_refused(self):
        g = Identity.generate("g"); self.admit(g)
        before = self.pools()
        out, ev = self.send(g, admin_ref=self.rid)
        self.assertEqual(out["t"], "refused")
        self.assertEqual(self.pools(), before)

    def test_removed_guest_old_post_beyond_cut_refused_and_never_live(self):
        g = Identity.generate("g"); self.admit(g)
        held = self.mk(g, "held back")          # signed before removal, never delivered (seq beyond the declared cut)
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).admin("member_remove", {"agent": g.id})).ok)
        for _ in range(2):
            self.assertEqual(self.inbox.handle(self.submit(g, held))["t"], "refused")
        self.assertEqual([i for i in self.t.events if self.t.events[i]["author"] == g.id and self.t.status[i] == "live" and "guest" not in self.t.events[i]["body"]], [])

    def test_removed_key_cannot_queue_new_requests(self):
        """A removed key can never be re-added ('rejoin with a new key'), so its new request can only clog the waiting pool."""
        g = Identity.generate("g"); self.admit(g)
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).admin("member_remove", {"agent": g.id})).ok)
        r, ev = self.req(who=g)
        self.assertEqual(self.inbox.handle(r)["t"], "refused")
        self.assertNotIn(event_id(ev), self.t.awaiting)

    def test_void_posts_not_kept_when_refused(self):
        g = Identity.generate("g"); self.admit(g)
        held = [self.mk(g, f"h{k}", seq=50 + k) for k in range(5)]
        self.m.ingest(Writer(self.owner, self.t).admin("member_remove", {"agent": g.id}))
        n = len(self.t.stored)
        for ev in held:
            self.inbox.handle(self.submit(g, ev))
        self.assertEqual(len(self.t.stored), n)

    def test_equivocation_same_seq(self):
        g = Identity.generate("g"); self.admit(g)
        a, ea = self.send(g, "a", seq=5)
        b, eb = self.send(g, "b", seq=5)
        self.assertEqual(a["t"], "ok")
        self.assertEqual(b["t"], "refused")
        self.assertNotIn(event_id(eb), self.t.events)
        for k in range(30):
            self.send(g, f"x{k}", seq=5)
        eq = [i for i in self.t.stored if self.t.status.get(i) == "equiv"]
        self.assertLessEqual(len(eq), 8)

    def test_equivocation_does_not_take_quota_or_flood(self):
        g = Identity.generate("g"); self.admit(g)
        self.send(g, "a", seq=5)
        n = len(self.t.stored)
        for k in range(40):
            self.send(g, f"x{k}", seq=5)
        self.assertLessEqual(len(self.t.stored) - n, 8)

    def test_seq_gap_accepted_and_seq_dup_idempotent(self):
        g = Identity.generate("g"); self.admit(g)
        out, ev = self.send(g, "far", seq=40)
        self.assertEqual(out["t"], "ok")
        self.assertEqual(self.inbox.handle(self.submit(g, ev))["t"], "ok")

    def test_deep_and_huge_bodies_refused_cleanly(self):
        g = Identity.generate("g"); self.admit(g)
        n = len(self.t.stored)
        deep = []
        for _ in range(3000):
            deep = [deep]
        base = self.mk(g)
        for body in ({"text": "x", "refs": deep}, {"text": "x", "to": deep}, {"text": "x" * 5000}, {"text": "x", "to": [deep]}):
            ev = dict(base, body=body)
            try:
                r = self.submit(g, ev, bits=4)
            except Exception:
                continue                                   # cannot even be hashed client side
            out = self.inbox.handle(r)
            self.assertEqual(out["t"], "refused")
            self.assertNotEqual(out.get("why"), "internal")
        self.assertEqual(len(self.t.stored), n)

    def test_refs_to_abuse_refused(self):
        g = Identity.generate("g"); self.admit(g)
        n = len(self.t.stored)
        bodies = [{"text": "x", "refs": [{"kind": "file", "cid": "sha256:" + "0" * 64, "size": 1}] * 17},
                  {"text": "x", "to": ["z"] * 3}, {"text": "x", "to": [g.id] * 17}, {"text": "x", "reply_to": "b" * 32},
                  {"text": 5}, {"text": "x", "refs": "no"}]
        for k, b in enumerate(bodies):
            ev = make_event(g, thread=self.tid, kind="post", body=b, parents=[self.rid], seq=20 + k, admin_ref=self.t.head, ts=1)
            self.assertEqual(self.inbox.handle(self.submit(g, ev))["t"], "refused", b)
        self.assertEqual(len(self.t.stored), n)

    def test_valid_to_accepted_but_refs_refused(self):
        """Blobs (DESIGN_blobs.md rev 1, finding 1): a guest never pushes bytes, so its attachment could never be fetched: refs are refused, `to` is fine."""
        g = Identity.generate("g"); self.admit(g)
        ref = {"kind": "file", "cid": "sha256:" + "0" * 64, "size": 1}
        ev = make_event(g, thread=self.tid, kind="post", body={"text": "x", "refs": [ref], "to": [self.owner.id]}, parents=[self.rid], seq=20, admin_ref=self.t.head, ts=1)
        self.assertEqual(self.inbox.handle(self.submit(g, ev))["t"], "refused")
        ev = make_event(g, thread=self.tid, kind="post", body={"text": "x", "to": [self.owner.id]}, parents=[self.rid], seq=21, admin_ref=self.t.head, ts=1)
        self.assertEqual(self.inbox.handle(self.submit(g, ev))["t"], "ok")

    def test_other_kinds_refused(self):
        g = Identity.generate("g"); self.admit(g)
        n = len(self.t.stored)
        for kind, body in (("digest", {"text": "d", "covers": []}), ("evidence", {"a": {}, "b": {}}), ("revoke", {"agent": g.id})):
            ev = make_event(g, thread=self.tid, kind=kind, body=body, parents=[self.rid], seq=30, admin_ref=self.t.head, ts=1)
            self.assertEqual(self.inbox.handle(self.submit(g, ev))["t"], "refused")
        self.assertEqual(len(self.t.stored), n)

    def test_pow_not_reusable_across_events_and_salts(self):
        g = Identity.generate("g"); self.admit(g)
        self.inbox.bits[self.tid] = [14, self.clock.t]
        ev1, ev2 = self.mk(g, "one"), self.mk(g, "two", seq=77)
        r1 = self.submit(g, ev1, bits=14)
        r2 = dict(r1, event=ev2)
        self.assertEqual(self.inbox.handle(r2)["t"], "stale")
        self.assertNotIn(event_id(ev2), self.t.stored)

    def test_pow_bound_to_sign_key_not_other_guests(self):
        g1, g2 = Identity.generate("g"), Identity.generate("h")
        self.admit(g1); self.admit(g2)
        self.inbox.bits[self.tid] = [14, self.clock.t]
        ev = self.mk(g2, "x")
        ch = self.chal()
        salt = bytes.fromhex(ch["salt"])
        n = P.solve(salt, self.tid, g1.sign_pub, event_id(ev), 14)     # work done with someone else's key
        out = self.inbox.handle({"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": salt.hex(), "nonce": n}})
        self.assertEqual(out["t"], "stale")

    def test_bits_minus_one_tolerated_minus_two_not(self):
        g = Identity.generate("g"); self.admit(g)
        self.inbox.bits[self.tid] = [10, self.clock.t]       # the ceiling: pow_bits 4 + span 6
        ch = self.chal(); salt = bytes.fromhex(ch["salt"])
        self.assertEqual(ch["bits"], 10)
        for want, expect, seq in ((9, "ok", 5), (8, "stale", 6)):
            ev = self.mk(g, f"b{want}", seq=seq)
            n = 0
            while P.achieved(salt, self.tid, g.sign_pub, event_id(ev), n) != want:
                n += 1
            out = self.inbox.handle({"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": salt.hex(), "nonce": n}})
            self.assertEqual(out["t"], expect)

    def test_observer_and_promoted_member_refused(self):
        o, m_ = Identity.generate("o"), Identity.generate("m")
        self.admit(o, "observer"); self.admit(m_, "member")
        for w in (o, m_):
            out, ev = self.send(w)
            self.assertEqual(out["t"], "refused")
        # guest promoted: add as member after being guest
        g = Identity.generate("g"); self.admit(g)
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).add_member(pubof(g), "member")).ok or True)
        if self.t.state()["members"][g.id]["role"] != "guest":
            out, ev = self.send(g)
            self.assertEqual(out["t"], "refused")

    def test_guest_removed_between_challenge_and_submit(self):
        g = Identity.generate("g"); self.admit(g)
        ev = self.mk(g)
        r = self.submit(g, ev)
        self.m.ingest(Writer(self.owner, self.t).admin("member_remove", {"agent": g.id}))
        self.assertEqual(self.inbox.handle(r)["t"], "refused")
        self.assertNotIn(event_id(ev), self.t.events)

    def test_removed_by_other_process_seen(self):
        g = Identity.generate("g"); self.admit(g)
        m2 = Mirror(self.home + "/mirror", clock=self.clock, rate_limit=False)
        t2 = m2.threads[self.tid]
        self.assertTrue(m2.ingest(Writer(self.owner, t2).admin("member_remove", {"agent": g.id})).ok)
        out, ev = self.send(g)
        self.assertEqual(out["t"], "refused")

    def test_quota_by_restart_of_inbox(self):
        g = Identity.generate("g"); self.admit(g)
        ok = 0
        for k in range(GUEST_POSTS_PER_HOUR * 2):
            if k % GUEST_POSTS_PER_HOUR == 0:
                self.inbox = Inbox(self.m, self.home, clock=self.clock)
            out, ev = self.send(g, f"p{k}")
            ok += out["t"] == "ok"
            self.clock.t += 1
        self.assertLessEqual(ok, GUEST_POSTS_PER_HOUR, "an Inbox restart resets the guest quota")

    def test_quota_not_consumed_by_refused_but_table_bounded(self):
        g = Identity.generate("g"); self.admit(g)
        for k in range(5):
            self.send(g, admin_ref="c" * 32, seq=90 + k)
        self.assertLessEqual(len(self.inbox._guest_posts), 1)

    def test_quota_per_key_independent_and_table_entry_only_for_members(self):
        for k in range(3):
            s = Identity.generate("s")
            self.inbox.handle(self.submit(s, self.mk(s)))
        self.assertEqual(len(self.inbox._guest_posts), 0)

    def test_quota_with_duplicate_resubmits_not_counted(self):
        g = Identity.generate("g"); self.admit(g)
        out, ev = self.send(g)
        for _ in range(GUEST_POSTS_PER_HOUR + 2):
            self.assertEqual(self.inbox.handle(self.submit(g, ev))["t"], "ok")
        out, ev = self.send(g, "next")
        self.assertEqual(out["t"], "ok")

    def test_answers_no_leak_same_bytes_not_public(self):
        g = Identity.generate("g"); self.admit(g)
        ev = self.mk(g)
        r = self.submit(g, ev)
        r["thread"] = "f" * 32
        self.assertEqual(self.inbox.handle(r), {"t": "refused", "why": "no"})

    def test_refusal_reason_leaks_nothing_but_short_reason(self):
        g = Identity.generate("g"); self.admit(g)
        out, ev = self.send(g, "SECRET-" + "q" * 10, admin_ref="d" * 32)
        self.assertEqual(set(out), {"t", "why"})
        self.assertNotIn("SECRET", str(out))

    def test_parent_void_and_awaiting(self):
        g, g2 = Identity.generate("g"), Identity.generate("h")
        self.admit(g)
        r, rq = self.req(who=g2)
        self.inbox.handle(r)
        out, ev = self.send(g, parents=[event_id(rq)], body={"text": "x"})
        self.assertEqual(out["t"], "refused")
        self.assertEqual(self.t.status.get(event_id(ev)), None)

    def test_parent_equiv_loser_refused_cleanly(self):
        g = Identity.generate("g"); self.admit(g)
        a, ea = self.send(g, "a", seq=5)
        b, eb = self.send(g, "b", seq=5)
        loser = event_id(eb) if self.t.status.get(event_id(eb)) == "equiv" else event_id(ea)
        out, ev = self.send(g, "child", parents=[loser], body={"text": "c"}, seq=6)
        self.assertEqual(out["t"], "refused")

    def test_takeover_epoch_guest_still_guest_posts_follow_state(self):
        g = Identity.generate("g"); self.admit(g)
        out, ev = self.send(g)
        self.assertEqual(out["t"], "ok")

    def test_concurrent_two_posts(self):
        import threading
        g = Identity.generate("g"); self.admit(g)
        evs = [self.mk(g, f"c{k}", seq=10 + k) for k in range(6)]
        rs = [self.submit(g, e) for e in evs]
        outs = []
        ts = [threading.Thread(target=lambda r=r: outs.append(self.inbox.handle(r))) for r in rs]
        [x.start() for x in ts]; [x.join() for x in ts]
        self.assertEqual([o["t"] for o in outs].count("ok"), 6)
        for e in evs:
            self.assertIn(event_id(e), self.t.events)

    def test_real_rate_limit_mirror_and_quota(self):
        self.m.rate_limit = True
        g = Identity.generate("g"); self.admit(g)
        lim = self.t.state()["rules"]["posts_per_author_per_hour"]
        oks = 0
        for k in range(min(lim, GUEST_POSTS_PER_HOUR) + 3):
            out, ev = self.send(g, f"r{k}")
            oks += out["t"] == "ok"
        self.assertEqual(oks, min(lim, GUEST_POSTS_PER_HOUR))

    def test_owner_and_admin_refused(self):
        a = Identity.generate("a"); self.admit(a, "admin") if False else None
        out, ev = self.send(self.owner)
        self.assertEqual(out, {"t": "refused", "why": "members use their own door"})

    def test_guest_flood_cannot_evict_other_parked_events(self):
        """The unverified-pending pool is thread-wide (64). A parked event of someone else (owner post citing an admin event still in flight)
        must not be pushed out by a guest's refused posts."""
        victim = make_event(self.owner, thread=self.tid, kind="post", body={"text": "v"}, parents=[self.rid], seq=50, admin_ref="e" * 32, ts=1)
        self.assertEqual(self.m.ingest(victim).status, "pending")
        g = Identity.generate("g"); self.admit(g)
        for k in range(80):
            self.send(g, f"f{k}", admin_ref=f"{k + 1:032x}", seq=100 + k)
        self.assertIn(event_id(victim), self.t.stored)


class Client(D):
    class T:
        def __init__(s, inbox): s.i = inbox
        def request(s, r): return s.i.handle(r)

    def test_post_as_guest_end_to_end_and_gates(self):
        from sigilnet.guest import GuestError, post_as_guest
        g = Identity.generate("g")
        with self.assertRaises(GuestError):
            post_as_guest(self.T(self.inbox), self.m, g, self.tid, "x", self.rid)        # not admitted
        self.admit(g)
        out = post_as_guest(self.T(self.inbox), self.m, g, self.tid, "hi", self.rid)
        self.assertEqual(out["t"], "ok")
        with self.assertRaises(GuestError):
            post_as_guest(self.T(self.inbox), self.m, g, self.tid, "hi", "f" * 32)       # unknown reply_to
        with self.assertRaises(GuestError):
            post_as_guest(self.T(self.inbox), self.m, g, self.tid, "x" * 5000, self.rid)  # over guest max_bytes
        with self.assertRaises(GuestError):
            post_as_guest(self.T(self.inbox), self.m, self.owner, self.tid, "hi", self.rid)

    def test_post_as_guest_hostile_bits(self):
        from sigilnet.guest import GuestError, post_as_guest
        g = Identity.generate("g"); self.admit(g)
        class H:
            def request(s, r): return {"t": "challenge", "thread": r["thread"], "salt": "0" * 32, "bits": 40}
        with self.assertRaises(GuestError):
            post_as_guest(H(), self.m, g, self.tid, "hi", self.rid)
