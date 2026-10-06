"""Tests that pin down the derivation-model rules that a mutation check showed were not covered by the fast suite."""
import tempfile
import unittest

from sigilnet import event as E
from sigilnet import thread as T
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread

from .util import World


def grind(make, target, tries=4000):
    """An event built by make(ts) whose id sorts below `target` (what a rogue admin does)."""
    for ts in range(tries):
        ev = make(ts)
        if event_id(ev) < target:
            return ev
    raise AssertionError("could not grind a lower id")


class Rank(unittest.TestCase):
    def test_owner_removal_cannot_be_undone_by_a_removed_admin_grinding_a_lower_id(self):
        w = World()
        w.ids["x"] = Identity.generate("x")
        gw = World.__new__(World)
        gw.ids = w.ids
        # sansa is an ADMIN here
        from sigilnet.build import make_genesis
        i = w.ids
        g = make_genesis(i["arya"], "t", [(i["sansa"], "admin"), (i["carol"], "member"), (i["dave"], "member")])
        base = Thread(g)
        rem = Writer(i["arya"], base).admin("member_remove", {"agent": i["sansa"].id})
        atk = grind(lambda ts: Writer(i["sansa"], base).add_member(i["x"], "member", ts=ts), event_id(rem))
        self.assertLess(event_id(atk), event_id(rem))                       # the attacker really has the lower id
        for order in ((rem, atk), (atk, rem)):
            t = Thread(g)
            for ev in order:
                t.accept(ev)
            self.assertNotIn(i["sansa"].id, t.state()["members"], order)      # the owner's removal wins in either order
            self.assertNotIn(i["x"].id, t.state()["members"])
        # admin-vs-admin still falls to the lower id (documented): the same attack by a plain admin against another admin's removal
        rem2 = Writer(i["sansa"], base).admin("member_remove", {"agent": i["carol"].id})
        t = Thread(g); t.accept(rem2)
        self.assertNotIn(i["carol"].id, t.state()["members"])


class Cosigs(unittest.TestCase):
    def test_cosigs_stripped_in_transit_do_not_lock_out_the_valid_copy(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        full = w.w("arya").add_member(w.ids["eve"], cosigners=[w.ids["dave"]])
        stripped = {k: v for k, v in full.items() if k != "cosigs"}
        self.assertEqual(event_id(stripped), event_id(full))
        self.assertEqual(w.t.accept(stripped).status, "rejected")               # not enough signatures on its own
        self.assertTrue(w.t.accept(full).ok)                                    # ...and the full copy is still welcome

    def test_cosigs_arriving_on_a_duplicate_of_a_parked_event_are_merged(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        a = w.w("arya").add_member(w.ids["eve"], cosigners=[w.ids["dave"]])
        w.add(a)
        newbie = Identity.generate("newbie")
        b_full = w.w("arya").add_member(newbie, cosigners=[w.ids["dave"]])              # built on top of `a`
        b_stripped = {k: v for k, v in b_full.items() if k != "cosigs"}
        t = Thread(w.genesis)
        self.assertEqual(t.accept(b_stripped).status, "pending")                          # parked: its parent `a` has not arrived
        t.accept(b_full)                                                                  # the same event, this time with its cosigs: merged
        t.accept(a)
        self.assertIn(newbie.id, t.state()["members"])                                    # without the merge b would resolve invalid and vanish

    def test_a_duplicate_with_more_valid_cosigs_is_merged(self):
        w = World(k=3, extra_members=[("dave", "admin"), ("eve", "admin")])
        ev = w.w("arya").add_member(Identity.generate("new"), cosigners=[w.ids["dave"]])   # 2 of 3: waiting? no: invalid, so not stored
        self.assertEqual(w.t.accept(ev).status, "rejected")
        full = E.add_cosig(ev, w.ids["eve"])
        self.assertTrue(w.t.accept(full).ok)


class Guests(unittest.TestCase):
    def test_first_admission_naming_the_request_for_its_author_decides(self):
        w = World(visibility="public")
        root = w.post("arya", "hi")
        d, e = w.ids["dave"], w.ids["eve"]
        rq = Writer(d, w.t).guest_request("mine", root)
        w.t.accept(rq)
        w.add(w.w("arya").add_member(e, "guest", admits=[event_id(rq)]))       # names dave's request for EVE: admits nothing
        self.assertNotIn(event_id(rq), w.t.events)
        w.add(w.w("arya").add_member(d, "guest", admits=[event_id(rq)]))       # names it for its author: admitted
        self.assertIn(event_id(rq), w.t.events)
        self.assertEqual(list(w.t.events).count(event_id(rq)), 1)

    def test_waiting_requests_survive_a_restart_and_expire(self):
        w = World(visibility="public")
        root = w.post("arya", "hi")
        now = [1000.0]
        m = Mirror(tempfile.mkdtemp(), clock=lambda: now[0])
        m.ingest(w.genesis)
        for e in list(w.t.events.values())[1:]:
            m.ingest(e)
        rq = Writer(w.ids["dave"], w.t).guest_request("please admit me", root)
        self.assertEqual(m.ingest(rq).status, "awaiting")
        m2 = Mirror(m.root, clock=lambda: now[0])
        self.assertIn(event_id(rq), m2.thread(w.t.id).awaiting)                  # persisted
        now[0] += 73 * 3600                                                     # past request_ttl_hours (72)
        m3 = Mirror(m.root, clock=lambda: now[0])
        self.assertNotIn(event_id(rq), m3.thread(w.t.id).awaiting)               # aged out on load


class Forks(unittest.TestCase):
    def test_events_citing_a_lost_branch_are_void_in_every_order(self):
        w = World(successors=("sansa",), extra_members=[("dave", "member")])
        cp = w.w("arya").admin("checkpoint", {"count": 1, "heads": [w.t.id], "epoch": 0})
        post_on_cp = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "signed against the checkpoint"}, parents=[w.t.id],
                                  seq=0, admin_ref=event_id(cp), ts=5)
        tk = w.w("sansa").admin("owner_takeover", {"last_checkpoint": w.t.id}, cosigners=[w.ids["carol"]], epoch_delta=1)
        for order in ((cp, post_on_cp, tk), (tk, cp, post_on_cp), (tk, post_on_cp, cp), (post_on_cp, tk, cp)):
            t = Thread(w.genesis)
            for _ in range(2):
                for ev in order:
                    t.accept(ev)
            self.assertEqual(t.state()["owner"], w.ids["sansa"].id, [e["kind"] for e in order])
            self.assertIn(event_id(post_on_cp), t.void_ids, [e["kind"] for e in order])
            self.assertNotIn(event_id(post_on_cp), set(t.events) - t.void_ids)


class Caps(unittest.TestCase):
    def test_voided_events_are_capped(self):
        old, T.MAX_VOID = T.MAX_VOID, 5
        try:
            w = World()
            old_head = w.t.head
            w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id}))
            res = []
            for n in range(10):
                ev = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=n, admin_ref=old_head, ts=n)
                res.append(w.t.accept(ev).status)
            self.assertEqual(res.count("voided"), 5)
            self.assertEqual(res.count("rejected"), 5)
        finally:
            T.MAX_VOID = old

    def test_admin_siblings_per_author_are_capped(self):
        w = World()
        forks = [E.make_event(w.ids["arya"], thread=w.t.id, kind="rules_update", parents=[w.t.id], seq=50 + n, admin_ref=w.t.head, ts=n,
                              body={"prev_admin": w.t.head, "owner_epoch": 0, "rules": {"max_members": 30 + n}}) for n in range(8)]
        statuses = [w.t.accept(f).status for f in forks]
        self.assertEqual(statuses.count("rejected"), 8 - T.MAX_ADMIN_SIBLINGS)      # at most MAX_ADMIN_SIBLINGS per author on one prev

    def test_thread_storage_cap(self):
        old, T.MAX_STORED = T.MAX_STORED, 6
        try:
            w = World()
            res = [w.t.accept(w.w("carol").post(str(n))).status for n in range(10)]
            self.assertEqual(res.count("rejected"), 10 - 5)
        finally:
            T.MAX_STORED = old


if __name__ == "__main__":
    unittest.main()


class TakeoverBranch(unittest.TestCase):
    def _world(self):
        from sigilnet.build import make_genesis
        i = {n: Identity.generate(n) for n in ("o", "s", "m1", "m2", "h")}
        # a thread with successors needs k >= 2: h is an admin who co-signs the owner's removals
        g = make_genesis(i["o"], "t", [(i["s"], "member"), (i["m1"], "member"), (i["m2"], "member"), (i["h"], "admin")], successors=[i["s"].id], k=2)
        return i, g

    def test_a_successor_removed_on_the_displaced_branch_cannot_take_over(self):
        i, g = self._world()
        t = Thread(g)
        assert t.accept(Writer(i["o"], t).admin("member_remove", {"agent": i["s"].id}, cosigners=[i["h"]])).ok           # only the successor is removed
        tk = Writer(i["s"], Thread(g)).admin("owner_takeover", {"last_checkpoint": event_id(g)}, cosigners=[i["m1"], i["m2"]], epoch_delta=1)
        self.assertNotEqual(t.accept(tk).status, "accepted")                                          # live voters M1, M2, H would suffice: the AUTHOR is gone
        self.assertEqual(t.state()["owner"], i["o"].id)

    def test_members_removed_on_the_displaced_branch_do_not_count_as_voters(self):
        i, g = self._world()
        t = Thread(g)
        for who in ("m1", "m2"):
            assert t.accept(Writer(i["o"], t).admin("member_remove", {"agent": i[who].id}, cosigners=[i["h"]])).ok
        tk = Writer(i["s"], Thread(g)).admin("owner_takeover", {"last_checkpoint": event_id(g)}, cosigners=[i["m1"], i["m2"]], epoch_delta=1)
        self.assertNotEqual(t.accept(tk).status, "accepted")                                          # 3 acks of 4 old voters, but only S is still a member of {S, H}

    def test_a_takeover_that_was_valid_becomes_invalid_when_the_owner_side_removes_its_voters(self):
        i, g = self._world()
        tk = Writer(i["s"], Thread(g)).admin("owner_takeover", {"last_checkpoint": event_id(g)}, cosigners=[i["m1"], i["m2"]], epoch_delta=1)
        t = Thread(g)
        self.assertTrue(t.accept(tk).ok)                                                              # valid: nothing displaced yet
        self.assertEqual(t.state()["owner"], i["s"].id)
        # the owner's two removals form a chain on the same prev (built independently, so chain them explicitly)
        base = Thread(g)
        r1 = Writer(i["o"], base).admin("member_remove", {"agent": i["m1"].id}, cosigners=[i["h"]]); base.accept(r1)
        r2 = Writer(i["o"], base).admin("member_remove", {"agent": i["m2"].id}, cosigners=[i["h"]]); base.accept(r2)
        t.accept(r1); t.accept(r2)
        self.assertEqual(t.state()["owner"], i["o"].id, "a stale cached validity kept a takeover whose voters were removed")


class Pools(unittest.TestCase):
    def test_unverifiable_parked_events_are_bounded_in_the_thread(self):
        w = World()
        junk = Identity.generate("junk")
        for n in range(T.MAX_UNVERIFIED_PENDING + 40):
            w.t.accept(E.make_event(junk, thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=n, admin_ref=f"{n:032x}"))
        parked = [i for i, s in w.t.status.items() if s == "pending"]
        self.assertLessEqual(len(parked), T.MAX_UNVERIFIED_PENDING)

    def test_parked_admin_events_do_not_trigger_a_derivation(self):
        w = World()
        calls = []
        real = w.t._derive
        w.t._derive = lambda: (calls.append(1), real())[1]
        for n in range(20):
            ev = E.make_event(w.ids["arya"], thread=w.t.id, kind="rules_update", parents=[w.t.id], seq=100 + n, admin_ref=f"{n + 1:032x}",
                              body={"prev_admin": f"{n + 1:032x}", "owner_epoch": 0, "rules": {"max_members": 20}})
            self.assertEqual(w.t.accept(ev).status, "pending")
        self.assertEqual(calls, [])

    def test_caches_are_bounded(self):
        old = (T.MAX_SIG_CACHE, T.MAX_ADMIN_CACHE)
        T.MAX_SIG_CACHE, T.MAX_ADMIN_CACHE = 50, 5
        try:
            w = World()
            for n in range(120):
                w.w("carol").post(str(n))
                w.t.accept(w.w("carol").post(f"p{n}"))
            self.assertLessEqual(len(w.t._sig), 51)
            for n in range(20):
                w.t.accept(w.w("arya").admin("checkpoint", {"count": n, "heads": [w.t.id], "epoch": 0}))
            self.assertLessEqual(len(w.t._admin_cache), 6 + 2)
        finally:
            T.MAX_SIG_CACHE, T.MAX_ADMIN_CACHE = old


class SyncOrderCache(unittest.TestCase):
    def test_a_listing_is_never_stale_after_an_eviction_and_an_arrival_between_two_calls(self):
        from .util import World
        w = World()
        e1, e2 = w.w("carol").post("one"), w.w("sansa").post("two")      # siblings: both hang off the genesis
        w.add(e1)
        t = w.t
        before = t.sync_order()
        self.assertIn(event_id(e1), before)
        t._forget(event_id(e1)); t._derive()                       # an eviction (as the pools do it) ...
        t.accept(e2)                                               # ... and an arrival: the sizes are the same as before
        after = t.sync_order()
        self.assertIn(event_id(e2), after)
        self.assertNotIn(event_id(e1), after)
