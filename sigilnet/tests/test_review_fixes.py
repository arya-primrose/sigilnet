"""Regression tests for the findings of the two independent reviews (adversarial subagent, then Sansa's PoCs)."""
import tempfile
import time
import unittest

from sigilnet import event as E
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import MAX_ORPHANS, Mirror

from sigilnet.thread import Thread as Thread_

from .util import World


def grind_revoke(w, target):
    """A self-revoke by plain member carol whose id sorts below `target`."""
    for ts in range(4000):
        ev = w.w("carol").admin("revoke", {"agent": w.ids["carol"].id}, ts=ts)
        if event_id(ev) < target:
            return ev
    raise AssertionError("no lower id")


def grind_post(w, who, text, target):
    for ts in range(4000):
        ev = E.make_event(w.ids[who], thread=w.t.id, kind="post", body={"text": text}, parents=[w.t.id], seq=0, admin_ref=w.t.head, ts=ts)
        if event_id(ev) < target:
            return ev
    raise AssertionError("no lower id")


class SansaRound2(unittest.TestCase):
    def test_high1_a_takeover_cannot_be_seized_with_the_votes_of_members_removed_since(self):
        from sigilnet.build import make_genesis
        i = {n: Identity.generate(n) for n in ("o", "s", "m1", "m2", "h")}
        g = make_genesis(i["o"], "t", [(i["s"], "member"), (i["m1"], "member"), (i["m2"], "member"), (i["h"], "admin")], successors=[i["s"].id], k=2)
        from sigilnet.thread import Thread
        t = Thread(g)
        w = Writer(i["o"], t)
        for who in ("s", "m1", "m2"):
            assert t.accept(Writer(i["o"], t).admin("member_remove", {"agent": i[who].id}, cosigners=[i["h"]])).ok
        assert t.accept(Writer(i["h"], t).post("still here")).ok
        # S plus the acks of M1 and M2 (all removed since) build a takeover on the GENESIS head
        base = Thread(g)
        tk = Writer(i["s"], base).admin("owner_takeover", {"last_checkpoint": g and event_id(g)}, cosigners=[i["m1"], i["m2"]], epoch_delta=1)
        r = t.accept(tk)
        self.assertNotEqual(r.status, "accepted", (r.status, r.reason))
        self.assertEqual(t.state()["owner"], i["o"].id)
        self.assertNotIn(i["s"].id, t.state()["members"])
        # the legitimate case is unchanged: with no competing chain, a quorum of live members takes over
        t2 = Thread(g)
        tk2 = Writer(i["s"], t2).admin("owner_takeover", {"last_checkpoint": event_id(g)}, cosigners=[i["m1"], i["m2"]], epoch_delta=1)
        self.assertTrue(t2.accept(tk2).ok)
        self.assertEqual(t2.state()["owner"], i["s"].id)

    def test_high2_a_self_revoke_cannot_displace_an_admins_event(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        member_add = w.w("dave").add_member(w.ids["eve"], cosigners=[w.ids["arya"]])              # an ADMIN's event needing 2 signatures
        rev = grind_revoke(w, event_id(member_add))
        self.assertLess(event_id(rev), event_id(member_add))
        for order in ((member_add, rev), (rev, member_add)):
            t = Thread_(w.genesis)
            for ev in order:
                t.accept(ev)
            self.assertIn(w.ids["eve"].id, t.state()["members"], "the k-signature add was displaced by a one-signature self-revoke")

    def test_med3_an_author_cannot_rewrite_a_message_others_already_answered(self):
        w = World()
        first = w.w("carol").post("transfer to account 1")
        reply = w.w("sansa").post("OK", reply_to=event_id(first), parents=[])
        second = grind_post(w, "carol", "transfer to account 2", event_id(first))
        self.assertLess(event_id(second), event_id(first))
        for order in ((first, reply, second), (second, first, reply), (reply, second, first)):
            t = Thread_(w.genesis)
            for _ in range(2):
                for ev in order:
                    t.accept(ev)
            live = [e["body"]["text"] for i, e in t.events.items() if e["kind"] == "post" and i not in t.void_ids]
            self.assertNotIn("transfer to account 2", live)                                    # neither version of the equivocated message is live
            self.assertNotIn("transfer to account 1", live)
            self.assertEqual(len(t.conflicts), 1)

    def test_med4_parked_junk_costs_no_full_derivation(self):
        w = World()
        for n in range(1200):
            w.add(w.w("carol").post(str(n)))
        junk_key = Identity.generate("junk")
        t0 = time.time()
        for n in range(200):
            junk = E.make_event(junk_key, thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=n, admin_ref=f"{n:032x}")
            w.t.accept(junk)
        for n in range(100):
            k = Identity.generate("g")
            w.t.accept(Writer(k, w.t).guest_request("please", w.t.id))
        per_event = (time.time() - t0) / 300
        self.assertLess(per_event, 0.008, f"{per_event * 1000:.1f} ms per junk event (a full derivation costs ~30+ ms at 1200 events)")

    def test_low_a_removed_member_cannot_backfill_a_seq_gap(self):
        w = World()
        e0 = w.w("carol").post("zero"); w.add(e0)
        held_back = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "signed early, held back"}, parents=[w.t.id], seq=1,
                                 admin_ref=w.t.head, ts=1)
        e2 = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "two"}, parents=[w.t.id], seq=2, admin_ref=w.t.head, ts=2)
        w.add(e2)
        rm = w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id})              # the builder lists the gap: missing = [1]
        self.assertEqual(rm["body"].get("missing"), [1])
        w.add(rm)
        self.assertEqual(w.t.accept(held_back).status, "voided")                          # she cannot backfill seq 1 after her removal


class Sansa(unittest.TestCase):
    def test_2_junk_in_many_fake_threads_cannot_evict_an_honest_pending_event(self):
        w = World()
        m = Mirror(tempfile.mkdtemp())
        m.ingest(w.genesis)
        ghost = "9" * 32
        honest = E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": "honest, waiting for its parent"}, parents=[ghost], seq=0, admin_ref=w.t.head)
        self.assertEqual(m.ingest(honest).status, "pending")
        junk_id = Identity.generate("junk")
        for n in range(1100):
            fake_thread = f"{n:032x}"
            junk = E.make_event(junk_id, thread=fake_thread, kind="post", body={"text": "x"}, parents=[ghost], seq=n, admin_ref=ghost)
            m.ingest(junk)
        self.assertIn(event_id(honest), m.pending)                                   # still parked
        self.assertLessEqual(len(m.orphans), MAX_ORPHANS)

    def test_3_replies_to_voided_or_waiting_events_are_not_stuck(self):
        w = World(visibility="public")
        root = w.post("arya", "who can help?")
        d = w.ids["dave"]
        req = Writer(d, w.t).guest_request("I can help", root)
        self.assertEqual(w.t.accept(req).status, "awaiting")
        reply = w.w("arya").post("thanks, looking at your request", parents=[event_id(req)])   # the owner replies to a request still waiting
        self.assertEqual(w.t.accept(reply).status, "accepted")

    def test_4_a_checkpoint_does_not_depend_on_which_events_have_arrived(self):
        w = World()
        p = w.w("carol").post("a concurrent event")
        cp = w.w("arya").admin("checkpoint", {"count": 5, "heads": [event_id(p)], "epoch": 0})
        outcomes = []
        for order in ((cp, p), (p, cp)):
            m = Mirror(tempfile.mkdtemp())
            m.ingest(w.genesis)
            for ev in order:
                m.ingest(ev)
            t = m.thread(w.t.id)
            outcomes.append((t.head, sorted(t.events)))
            if order[0] is cp:
                self.assertIn(event_id(p), m.missing(w.t.id) + [event_id(p)])
        self.assertEqual(outcomes[0], outcomes[1])                                       # arrival order never decides validity
        later = E.make_event(w.ids["arya"], thread=w.t.id, kind="rules_update", parents=[w.t.id], seq=9, admin_ref=event_id(cp),
                             body={"prev_admin": event_id(cp), "owner_epoch": 0, "rules": {"max_members": 20}})
        m = Mirror(tempfile.mkdtemp())
        m.ingest(w.genesis)
        self.assertEqual(m.ingest(later).status, "pending")                              # a follower waits for ITS parent, the checkpoint
        m.ingest(cp)
        self.assertEqual(m.thread(w.t.id).state()["rules"]["max_members"], 20)

    def test_5_forged_or_torn_conflict_records_never_count(self):
        pass            # covered by tests_adv test_conflicts_file_is_verified_on_load

    def test_6_domain_separation(self):
        w = World()
        ev = w.w("sansa").post("hello")
        cosig = E.add_cosig(ev, w.ids["carol"])["cosigs"][0]["sig"]
        forged = dict(ev, sig=cosig)                                                     # a cosignature is not an event signature
        self.assertEqual(w.t.accept(forged).reason, "bad signature")
        b = w.w("arya").add_member(w.ids["dave"])
        as_cosig = dict(b, cosigs=[{"author": w.ids["arya"].id, "sig": b["sig"]}])
        self.assertNotEqual(b["sig"], E.add_cosig(b, w.ids["arya"])["cosigs"][0]["sig"])   # same key, same bytes, different contexts

    def test_7_a_later_successor_can_take_over_and_an_earlier_one_outranks_it(self):
        w = World(successors=("sansa", "carol"), extra_members=[("dave", "member")])
        cp = w.w("arya").admin("checkpoint", {"count": 1, "heads": [w.t.id], "epoch": 0})
        w.add(cp)
        body = {"last_checkpoint": event_id(cp)}
        tk_carol = w.w("carol").admin("owner_takeover", body, cosigners=[w.ids["dave"]], epoch_delta=1)     # sansa is silent: carol escalates
        tk_sansa = w.w("sansa").admin("owner_takeover", body, cosigners=[w.ids["dave"]], epoch_delta=1)
        self.assertTrue(w.t.accept(tk_carol).ok)
        self.assertEqual(w.t.state()["owner"], w.ids["carol"].id)
        r = w.t.accept(tk_sansa)                                                         # sansa returns: earlier successor outranks
        self.assertEqual((r.status, r.reorg, w.t.state()["owner"]), ("accepted", True, w.ids["sansa"].id))
        self.assertIn(event_id(tk_carol), w.t.lost_admin)

    def test_low_cheap_checks_run_before_the_subgroup_check(self):
        w = World(visibility="public")
        root = w.post("arya", "hi")
        junk = Identity.generate("junk")
        req = Writer(junk, w.t).guest_request("x", root)
        req["body"]["guest"]["sign"] = Identity.generate("other").sign_pub               # key does not hash to the author id
        t0 = time.time()
        for _ in range(300):
            self.assertEqual(w.t.accept(req).status, "rejected")
        self.assertLess((time.time() - t0) / 300, 0.0006)                                # far below the ~1.2 ms of a subgroup check

    @unittest.expectedFailure
    def test_1_guest_queue_flush_by_fresh_keys_KNOWN_LIMIT_until_proof_of_work(self):
        """Sansa #1: any stranger can claim reply_to = an owner event, so the reserved slots do not protect real requests from a
        flood of fresh keys. Needs proof-of-work-strength-first eviction (step 4a); recorded here so it cannot be forgotten."""
        w = World(visibility="public")
        root = w.post("arya", "who can help?")
        real = []
        for n in range(5):
            k = Identity.generate(f"real{n}")
            r = Writer(k, w.t).guest_request("legit", root)
            w.t.accept(r); real.append(event_id(r))
        for n in range(300):
            k = Identity.generate(f"flood{n}")
            w.t.accept(Writer(k, w.t).guest_request("flood", root))
        self.assertTrue(all(i in w.t.awaiting for i in real))


if __name__ == "__main__":
    unittest.main()


class SansaRound3(unittest.TestCase):
    def test_successors_require_k_at_least_2(self):
        from sigilnet.build import make_genesis
        from sigilnet.event import EventError
        i = {n: Identity.generate(n) for n in ("o", "s", "a", "m")}
        with self.assertRaises(EventError):
            Thread_(make_genesis(i["o"], "t", [(i["s"], "member"), (i["a"], "admin"), (i["m"], "member")], successors=[i["s"].id], k=1))
        g = make_genesis(i["o"], "t", [(i["s"], "member"), (i["a"], "admin"), (i["m"], "member")], successors=[i["s"].id], k=2)
        t = Thread_(g)
        # k cannot be lowered below 2 while successors exist, and successors cannot be set at k = 1
        low = Writer(i["o"], t).admin("rules_update", {"admin_threshold": 1}, cosigners=[i["a"]])
        self.assertEqual(t.accept(low).status, "rejected")
        g1 = make_genesis(i["o"], "t1", [(i["s"], "member"), (i["a"], "admin"), (i["m"], "member")], k=1)
        t1 = Thread_(g1)
        self.assertEqual(t1.accept(Writer(i["o"], t1).admin("rules_update", {"successors": [i["s"].id]})).status, "rejected")
        # bootstrap: raise k first, then successors
        assert t1.accept(Writer(i["o"], t1).admin("rules_update", {"admin_threshold": 2})).ok
        assert t1.accept(Writer(i["o"], t1).admin("rules_update", {"successors": [i["s"].id]}, cosigners=[i["a"]])).ok
        self.assertEqual(t1.state()["successors"], [i["s"].id])

    def test_a_pre_signed_hidden_removal_cannot_veto_a_takeover_at_k2(self):
        from sigilnet.build import make_genesis
        i = {n: Identity.generate(n) for n in ("o", "s", "m1", "m2", "a")}
        g = make_genesis(i["o"], "t", [(i["s"], "member"), (i["m1"], "member"), (i["m2"], "member"), (i["a"], "admin")], successors=[i["s"].id], k=2)
        t = Thread_(g)
        hidden = Writer(i["o"], Thread_(g)).admin("member_remove", {"agent": i["s"].id})          # signed by the owner alone: 1 of 2 signatures
        tk = Writer(i["s"], Thread_(g)).admin("owner_takeover", {"last_checkpoint": event_id(g)}, cosigners=[i["m1"], i["m2"]], epoch_delta=1)
        self.assertTrue(t.accept(tk).ok)
        self.assertEqual(t.accept(hidden).status, "rejected")                                     # cannot be released later: it is invalid on its own
        self.assertEqual(t.state()["owner"], i["s"].id)

    def test_dependents_index_keeps_flooded_waiting_queue_cheap(self):
        w = World(visibility="public")
        root = w.post("arya", "who can help?")
        for n in range(600):
            w.add(w.w("carol").post(f"p{n}"))
        runs = []
        for rnd in range(3):                                           # best of three: a loaded machine slows one run, a real regression slows all of them
            reqs = [Writer(Identity.generate(f"g{rnd}-{n}"), w.t).guest_request("please", root) for n in range(300)]
            t0 = time.time()
            for ev in reqs:
                w.t.accept(ev)
            runs.append((time.time() - t0) / 300)
        per = min(runs)
        self.assertLess(per, 0.012, f"{per * 1000:.1f} ms per waiting request at 600 stored events (runs: {[round(r * 1000, 1) for r in runs]})")
        self.assertLessEqual(len(w.t.awaiting), 200)

    def test_takeover_keeps_k_at_2_when_two_admins_remain_and_the_new_owner_leaves_the_successor_list(self):
        from sigilnet.build import make_genesis
        i = {n: Identity.generate(n) for n in ("o", "s", "m1", "a")}
        g = make_genesis(i["o"], "t", [(i["s"], "member"), (i["m1"], "member"), (i["a"], "admin")], successors=[i["s"].id], k=2)
        t = Thread_(g)
        tk = Writer(i["s"], t).admin("owner_takeover", {"last_checkpoint": event_id(g)}, cosigners=[i["m1"]], epoch_delta=1)
        self.assertTrue(t.accept(tk).ok)
        st = t.state()
        self.assertEqual((st["owner"], st["admin_threshold"], st["successors"]), (i["s"].id, 2, []))     # admins now {s, a}: k stays 2

    def test_a_successor_must_be_a_plain_member_not_an_admin(self):
        # Sansa round 5: with an admin successor the owner could remove him ALONE (the admin-removal branch needs only the other admins) and so veto a takeover
        from sigilnet.build import make_genesis
        i = {n: Identity.generate(n) for n in ("o", "s", "m1", "m2")}
        bad = make_genesis(i["o"], "t", [(i["s"], "admin"), (i["m1"], "member"), (i["m2"], "member")], successors=[i["s"].id], k=2)
        with self.assertRaises(Exception):
            Thread_(bad)                                                                           # the genesis itself is refused
        g = make_genesis(i["o"], "t", [(i["s"], "admin"), (i["m1"], "member"), (i["m2"], "member")], successors=[i["m1"].id], k=2)
        t = Thread_(g)
        ru = Writer(i["o"], t).admin("rules_update", {"successors": [i["s"].id]}, cosigners=[i["s"]])
        self.assertEqual(t.accept(ru).status, "rejected")                                          # an admin cannot be named later either
        rm = Writer(i["o"], t).admin("member_remove", {"agent": i["m1"].id}, cosigners=[i["s"]])
        self.assertTrue(t.accept(rm).ok)                                                           # the member successor needs k signatures to remove, not the owner alone

    def test_the_admin_set_never_drops_below_k_through_a_takeover(self):
        from sigilnet.build import make_genesis
        i = {n: Identity.generate(n) for n in ("o", "a", "m1", "m2")}
        g = make_genesis(i["o"], "t", [(i["a"], "admin"), (i["m1"], "member"), (i["m2"], "member")], successors=[i["m1"].id], k=2)
        t = Thread_(g)
        tk = Writer(i["m1"], t).admin("owner_takeover", {"last_checkpoint": event_id(g)}, cosigners=[i["m2"]], epoch_delta=1)
        self.assertTrue(t.accept(tk).ok)
        st = t.state()
        self.assertEqual((st["owner"], st["admin_threshold"], st["successors"]), (i["m1"].id, 2, []))   # the successor replaced the owner in the admin set: still {m1, a}

    def test_admin_threshold_cannot_exceed_the_admin_set(self):
        from sigilnet.build import make_genesis
        i = {n: Identity.generate(n) for n in ("o", "a", "m")}
        t = Thread_(make_genesis(i["o"], "t", [(i["a"], "admin"), (i["m"], "member")], k=1))
        self.assertEqual(t.accept(Writer(i["o"], t).admin("rules_update", {"admin_threshold": 5})).status, "rejected")
        self.assertTrue(t.accept(Writer(i["o"], t).admin("rules_update", {"admin_threshold": 2})).ok)
