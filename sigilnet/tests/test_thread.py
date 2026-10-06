import copy
import unittest

from sigilnet import event as E
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.thread import Thread, default_guest_policy, default_rules

from .util import World


def status(w, ev):
    return w.t.accept(ev)


def old_endpoint_event(w, who):
    """A validly signed event of the removed kind `endpoint`, as a build that still had it would make it (a post, re-kinded and signed again)."""
    ev = w.w(who).post("x")
    ev["kind"], ev["body"] = "endpoint", {"transports": [{"type": "onion", "addr": "x.onion"}]}
    ev["sig"] = w.ids[who].sign(E.sign_input(ev))
    return ev


class Genesis(unittest.TestCase):
    def test_valid_and_thread_id_is_genesis_id(self):
        w = World()
        self.assertEqual(w.t.id, event_id(w.genesis))
        self.assertEqual(w.t.state()["owner"], w.ids["arya"].id)

    def test_rejections(self):
        i = World().ids
        base = lambda **kw: make_genesis(i["arya"], "t", [(i["sansa"], "member"), (i["carol"], "member")], **kw)
        Thread(base())
        with self.assertRaises(E.EventError):
            Thread(base(successors=[i["dave"].id]))                                  # successor not a member
        with self.assertRaises(E.EventError):
            Thread(make_genesis(i["arya"], "t", [(i["sansa"], "member")], successors=[i["sansa"].id]))   # two-party thread with successor
        with self.assertRaises(E.EventError):
            Thread(base(k=2))                                                        # threshold above the admin set
        with self.assertRaises(E.EventError):
            Thread(base(rules={**default_rules(), "max_members": 2}))                # 3 members > 2
        with self.assertRaises(E.EventError):
            Thread(base(guest_policy={**default_guest_policy(), "reserved_reply_slots": 999}))
        with self.assertRaises(E.EventError):
            Thread(base(visibility="secret"))
        g = base()
        for mut in (lambda b: b.update(owner=i["sansa"].id), lambda b: b["keys"][i["sansa"].id].update(sign=i["dave"].sign_pub),
                    lambda b: b["members"][1].update(role="owner"), lambda b: b.update(epoch=1), lambda b: b.update(title=""),
                    lambda b: b.update(extra=1), lambda b: b["rules"].update(max_event_bytes=10)):
            e = copy.deepcopy(g); mut(e["body"])
            e["sig"] = i["arya"].sign(E.sign_input(e))                             # correctly signed, still invalid
            with self.assertRaises(E.EventError):
                Thread(e)


class Posts(unittest.TestCase):
    def test_member_post_reply_and_structure(self):
        w = World()
        p = w.post("arya", "hello")
        r = w.post("sansa", "answer", reply_to=p)
        self.assertEqual(w.t.topo()[-1], r)
        bad = w.w("sansa").post("x", parents=[p])
        bad["body"]["reply_to"] = w.t.id                                             # reply_to not among parents
        bad["sig"] = w.ids["sansa"].sign(E.sign_input(bad))
        self.assertEqual(status(w, bad).status, "rejected")

    def test_observer_and_stranger_cannot_write(self):
        w = World()
        self.assertEqual(status(w, w.w("hu").post("hi")).status, "rejected")
        self.assertEqual(status(w, w.w("dave").post("hi")).status, "rejected")       # not a member, no guest block
        self.assertEqual(status(w, old_endpoint_event(w, "hu")).status, "rejected")    # the `endpoint` kind is gone: not even an observer may write it

    def test_the_endpoint_kind_is_forbidden_for_everybody(self):
        """DECISION (the human, 2026-10-03: "yes, forbid it"): a thread never carries a list of ways to reach an author. An event of kind `endpoint`, correctly signed (what an old build
        would send), is refused as an unknown kind whoever the author is, and nothing of it is stored."""
        w = World()
        for who in ("arya", "sansa", "carol", "hu", "dave"):                           # owner, member, member, observer, stranger
            ev = old_endpoint_event(w, who)
            r = status(w, ev)
            self.assertEqual((r.status, r.reason), ("rejected", "unknown kind"), who)
            self.assertNotIn(event_id(ev), w.t.stored)
        self.assertNotIn("endpoint", E.KINDS)

    def test_bad_signature_and_wrong_thread(self):
        w = World()
        ev = w.w("sansa").post("x")
        ev["sig"] = w.ids["carol"].sign(E.sign_input(ev))
        self.assertEqual(status(w, ev).reason, "bad signature")
        other = World()
        self.assertEqual(status(w, other.w("sansa").post("x")).status, "rejected")

    def test_duplicate_is_idempotent(self):
        w = World()
        ev = w.w("sansa").post("x")
        self.assertTrue(status(w, ev).ok)
        self.assertEqual(status(w, ev).status, "duplicate")
        self.assertEqual(len(w.t.events), 2)

    def test_pending_on_unknown_parent_or_admin_ref(self):
        w = World()
        p = w.w("arya").post("a")
        child = Writer(w.ids["sansa"], w.t).post("b", reply_to=event_id(p))
        r = status(w, child)
        self.assertEqual((r.status, r.missing), ("pending", [event_id(p)]))
        self.assertTrue(status(w, p).ok)
        self.assertIn(event_id(child), w.t.events)                                        # the parked child resolved when its parent arrived
        self.assertEqual(status(w, child).status, "duplicate")
        ghost = dict(child, admin_ref="9" * 32)
        self.assertEqual(status(w, ghost).status, "pending")

    def test_post_field_rules(self):
        w = World()
        p = w.post("arya")
        tests = [{"refs": [{"kind": "file", "cid": "sha256:" + "a" * 64, "size": 10}]}, {"to": [w.ids["sansa"].id]}]
        for extra in tests:
            self.assertTrue(status(w, w.w("carol").post("ok", **extra)).ok, extra)
        for extra in ({"refs": [{"kind": "file", "cid": "md5:x", "size": 1}]}, {"to": ["NOPE"]}, {"refs": "x"}, {"unknown": 1}, {"guest": {"name": "x"}}):
            self.assertEqual(status(w, w.w("carol").post("bad", **extra)).status, "rejected", extra)
        ev = w.w("carol").post("t")
        ev["body"]["text"] = 5
        ev["sig"] = w.ids["carol"].sign(E.sign_input(ev))
        self.assertEqual(status(w, ev).status, "rejected")

    def test_size_cap_from_rules(self):
        w = World(rules={**default_rules(), "max_event_bytes": 1024})
        self.assertEqual(status(w, w.w("arya").post("x" * 2000)).status, "rejected")
        self.assertTrue(status(w, w.w("arya").post("x" * 100)).ok)


class Equivocation(unittest.TestCase):
    def test_same_author_and_seq_is_a_conflict_and_evidence_is_accepted(self):
        w = World()
        a = w.w("sansa").post("one", ts=5)
        self.assertTrue(status(w, a).ok)
        b = Writer(w.ids["sansa"], w.t).post("two", ts=6)
        b2 = E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": "two"}, parents=[w.t.id], seq=a["seq"], admin_ref=w.t.head, ts=7)
        r = status(w, b2)
        # deterministic: the LOWER id is the live event, the other is an equivocation loser, whichever arrived first
        # deterministic and grind-proof: when an author signs two events for one seq, NEITHER is live (both are evidence)
        self.assertEqual(r.status, "conflict")
        self.assertNotIn(E.event_id(a), w.t.events)
        self.assertNotIn(E.event_id(b2), w.t.events)
        self.assertIn(E.event_id(a), w.t.equiv)
        self.assertIn(E.event_id(b2), w.t.equiv)
        self.assertEqual(len(w.t.conflicts), 1)
        ev = w.w("carol").event("evidence", {"a": a, "b": b2, "reason": "same seq"})
        self.assertTrue(status(w, ev).ok)
        # bad evidence: identical events, forged signature, unrelated events, different authors
        for body in ({"a": a, "b": a}, {"a": a, "b": dict(b2, sig="0" * 128)}, {"a": a, "b": E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": "next"}, parents=[w.t.id], seq=5, admin_ref=w.t.head, ts=9)},
                     {"a": a, "b": E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "z"}, parents=[w.t.id], seq=a["seq"], admin_ref=w.t.head)}):
            self.assertEqual(status(w, w.w("carol").event("evidence", body)).status, "rejected", body.keys())
        self.assertEqual(status(w, w.w("hu").event("evidence", {"a": a, "b": b2})).status, "rejected")      # an observer files nothing

    def test_seq_gap_is_visible(self):
        w = World()
        first = w.w("sansa").post("0")
        w.add(first)
        skipped = E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": "2"}, parents=[w.t.id], seq=3, admin_ref=w.t.head)
        w.add(skipped)
        self.assertEqual(w.t.missing_seqs(w.ids["sansa"].id), [1, 2])


class Membership(unittest.TestCase):
    def test_removal_cut_is_deterministic(self):
        w = World()
        seen = w.w("carol").post("carol event the owner has seen")
        w.add(seen)
        unseen = w.w("carol").post("carol event the owner never saw")                   # seq 1, signed before the removal
        old_head = w.t.head
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id}))          # last_seq = 0 (what the owner had)
        self.assertEqual(w.t.state()["epoch"], 1)
        self.assertEqual(w.t.state()["cut"][w.ids["carol"].id], 0)
        self.assertNotIn(w.ids["carol"].id, w.t.state()["members"])
        r = status(w, unseen)
        self.assertEqual(r.status, "voided")                                              # beyond last_seq: void, wherever it arrives
        self.assertIn(event_id(unseen), w.t.void_ids)
        self.assertNotIn(event_id(unseen), w.t.tips())
        self.assertIn(event_id(seen), w.t.events)                                         # within last_seq: valid
        self.assertNotIn(event_id(seen), w.t.void_ids)
        after = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=5, admin_ref=w.t.head)
        self.assertEqual(status(w, after).status, "rejected")                            # against the new head she is simply not a member
        self.assertEqual(w.t.states[old_head]["epoch"], 0)

    def test_late_event_within_last_seq_is_accepted_whenever_it_arrives(self):
        w = World()
        late = w.w("carol").post("delivered late but legitimate")                         # seq 0
        rm = w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id, "last_seq": 0})   # the owner declares she reached seq 0
        w.add(rm)
        self.assertEqual(status(w, late).status, "accepted")
        self.assertNotIn(event_id(late), w.t.void_ids)

    def test_event_accepted_before_the_removal_is_voided_retroactively(self):
        w = World()
        e0 = w.w("carol").post("one"); w.add(e0)
        e1 = w.w("carol").post("two"); w.add(e1)
        self.assertEqual(w.t.void_ids, set())
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id, "last_seq": 0}))
        self.assertEqual(w.t.void_ids, {event_id(e1)})                                    # e1 was accepted, then swept by the cut

    def test_close_cut(self):
        w = World()
        a = w.w("carol").post("seen before close"); w.add(a)
        b = w.w("carol").post("signed before close, never seen by the owner")            # seq 1
        w.add(w.w("arya").admin("close", {"cut": {w.ids["carol"].id: 0, w.ids["arya"].id: 0}}))
        self.assertEqual(status(w, b).status, "voided")
        self.assertEqual(status(w, w.w("sansa").post("no cut entry for sansa")).status, "rejected")   # she had seen the close: closed
        early = E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": "sansa, pre-close"}, parents=[w.t.id], seq=0, admin_ref=w.t.id)
        self.assertEqual(status(w, early).status, "voided")                               # not in the cut (-1): void

    def test_removed_cannot_rejoin_with_same_key(self):
        w = World()
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id}))
        self.assertEqual(status(w, w.w("arya").add_member(w.ids["carol"], "member")).status, "rejected")
        again = Identity.generate("carol2")
        self.assertTrue(status(w, w.w("arya").add_member(again, "member")).ok)

    def test_member_add_validation(self):
        w = World()
        d = w.ids["dave"]
        self.assertEqual(status(w, w.w("sansa").add_member(d)).status, "rejected")                    # not an admin
        bad = w.w("arya").add_member(d)
        bad["body"]["agent"] = w.ids["eve"].id
        bad["sig"] = w.ids["arya"].sign(E.sign_input(bad))
        self.assertEqual(status(w, bad).reason, "agent id does not match its signing key")
        self.assertEqual(status(w, w.w("arya").add_member(w.ids["sansa"])).status, "rejected")        # already a member
        self.assertEqual(status(w, w.w("arya").add_member(d, "owner")).status, "rejected")
        self.assertEqual(status(w, w.w("arya").admin("member_add", {"agent": d.id})).status, "rejected")
        self.assertTrue(status(w, w.w("arya").add_member(d, "member")).ok)

    def test_max_members(self):
        w = World(rules={**default_rules(), "max_members": 4})
        self.assertEqual(status(w, w.w("arya").add_member(w.ids["dave"])).status, "rejected")

    def test_cannot_remove_owner_and_stale_prev_admin(self):
        w = World()
        self.assertEqual(status(w, w.w("arya").admin("member_remove", {"agent": w.ids["arya"].id})).status, "rejected")
        stale = w.w("arya").admin("member_add", {"agent": w.ids["dave"].id, "name": "d", "role": "member", "sign": w.ids["dave"].sign_pub, "kex": w.ids["dave"].kex_pub})
        stale["seq"] = 40                                                                               # a different seq, so it is the admin fork rule that fires
        stale["sig"] = w.ids["arya"].sign(E.sign_input(stale))
        good = w.w("arya").add_member(w.ids["eve"])
        w.add(good)
        r = status(w, stale)                                                                            # prev_admin no longer the head: a fork
        # deterministic rank: the LOWER event id wins the fork, whichever arrived first (a reorg if the late one is lower)
        if event_id(stale) < event_id(good):
            self.assertEqual((r.status, r.reorg), ("accepted", True))
            self.assertIn(w.ids["dave"].id, w.t.state()["members"])
        else:
            self.assertEqual(r.status, "conflict")
            self.assertIn(w.ids["eve"].id, w.t.state()["members"])
        self.assertEqual(w.t.conflicts[-1]["kind"], "admin_fork")
        self.assertTrue(w.t.owner_equivocated)                                                          # same author (the owner) signed both

    def test_admin_fork_by_a_non_admin_is_not_evidence(self):
        w = World()
        w.add(w.w("arya").add_member(w.ids["eve"]))
        fake = E.make_event(w.ids["carol"], thread=w.t.id, kind="member_add", body={"prev_admin": w.t.id, "owner_epoch": 0, "agent": w.ids["dave"].id,
                            "name": "d", "role": "member", "sign": w.ids["dave"].sign_pub, "kex": w.ids["dave"].kex_pub}, parents=[w.t.id], seq=0, admin_ref=w.t.id)
        self.assertEqual(status(w, fake).status, "rejected")
        self.assertEqual(w.t.conflicts, [])

    def test_pair_thread_closes_when_a_party_leaves(self):
        i = World().ids
        t = Thread(make_genesis(i["arya"], "pair", [(i["sansa"], "member"), (i["hu"], "observer")]))
        wr = Writer(i["arya"], t)
        self.assertTrue(t.accept(wr.admin("member_remove", {"agent": i["hu"].id})).ok)        # removing an observer does not end it
        self.assertFalse(t.state()["closed"])
        self.assertTrue(t.accept(Writer(i["sansa"], t).admin("revoke", {"agent": i["sansa"].id})).ok)   # a party leaves itself
        self.assertTrue(t.state()["closed"])
        self.assertEqual(t.accept(Writer(i["arya"], t).post("anyone there")).status, "rejected")

    def test_close(self):
        w = World()
        self.assertEqual(status(w, w.w("sansa").admin("close", {})).status, "rejected")
        w.add(w.w("arya").admin("close", {}))
        self.assertEqual(status(w, w.w("sansa").post("late")).status, "rejected")

    def test_rules_update(self):
        w = World()
        w.add(w.w("arya").admin("rules_update", {"rules": {"max_members": 32}, "guest_policy": {"pow_bits": 24}}))
        self.assertEqual(w.t.state()["rules"]["max_members"], 32)
        self.assertEqual(w.t.state()["guest_policy"]["pow_bits"], 24)
        for body in ({"rules": {"max_members": 1}}, {"rules": {"bogus": 1}}, {"guest_policy": {"reserved_reply_slots": 10 ** 6}}, {}, {"rules": {"max_members": 2}}):
            self.assertEqual(status(w, w.w("arya").admin("rules_update", body)).status, "rejected", body)


class KOfN(unittest.TestCase):
    def test_two_signatures_required(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        d = w.ids["eve"]
        self.assertEqual(status(w, w.w("arya").add_member(d)).status, "rejected")                    # one signature
        self.assertEqual(status(w, w.w("arya").add_member(d, cosigners=[w.ids["sansa"]])).status, "rejected")   # sansa is not an admin
        stranger = Identity.generate("z")
        self.assertEqual(status(w, w.w("arya").add_member(d, cosigners=[stranger])).status, "rejected")
        self.assertTrue(status(w, w.w("arya").add_member(d, cosigners=[w.ids["dave"]])).ok)
        # a forged cosignature over other bytes does not count
        ev = w.w("arya").add_member(w.ids["hu"] if False else Identity.generate("q"))
        ev = E.add_cosig(ev, w.ids["dave"])
        ev["cosigs"][0]["sig"] = w.ids["dave"].sign(b"something else")
        self.assertEqual(status(w, ev).status, "rejected")

    def test_an_admin_who_refuses_can_still_be_removed_by_the_others(self):
        w = World(k=2, extra_members=[("dave", "admin")])                         # admins: arya (owner) and dave
        ev = w.w("arya").admin("member_remove", {"agent": w.ids["dave"].id})     # no cosignature from dave: his signature neither counts nor is required
        w.add(ev)
        st = w.t.state()
        self.assertNotIn(w.ids["dave"].id, st["members"])
        self.assertEqual(st["admin_threshold"], 1)
        w2 = World(k=2, extra_members=[("dave", "admin")])
        ev = w2.w("dave").admin("member_remove", {"agent": w2.ids["arya"].id})  # the owner can never be removed this way
        self.assertEqual(status(w2, ev).status, "rejected")

    def test_leaving_a_lone_admin_while_there_are_successors_needs_a_member_majority(self):
        # Sansa round 6: with the admin-removal rule the owner alone could strip the takeover away (remove the only other admin, k -> 1, successors cleared)
        def world():
            return World(k=2, successors=("carol",), extra_members=[("dave", "admin")])      # admins: arya (owner) + dave; voters besides them: sansa, carol
        w = world()
        alone = w.w("arya").admin("member_remove", {"agent": w.ids["dave"].id})
        self.assertEqual(status(w, alone).status, "rejected")
        half = w.w("arya").admin("member_remove", {"agent": w.ids["dave"].id}, cosigners=[w.ids["sansa"]])
        self.assertEqual(status(w, half).status, "rejected")                                # 1 of 2 voters is not more than half
        self_leave = w.w("dave").admin("revoke", {"agent": w.ids["dave"].id})
        self.assertEqual(status(w, self_leave).status, "rejected")                          # an admin cannot strip the takeover on his own either
        full = w.w("arya").admin("member_remove", {"agent": w.ids["dave"].id}, cosigners=[w.ids["sansa"], w.ids["carol"]])
        w.add(full)
        st = w.t.state()
        self.assertEqual((st["admin_threshold"], st["successors"]), (1, []))                # the majority chose this: the takeover is gone, knowingly
        w3 = World(k=2, successors=("carol",), extra_members=[("dave", "admin"), ("eve", "admin")])
        w3.add(w3.w("arya").admin("member_remove", {"agent": w3.ids["eve"].id}, cosigners=[w3.ids["dave"]]))   # 3 admins -> 2: no acks needed
        self.assertEqual(w3.t.state()["successors"], [w3.ids["carol"].id])

    def test_removing_an_admin_still_needs_k_of_the_others(self):
        w = World(k=3, extra_members=[("dave", "admin"), ("eve", "admin")])
        ev = w.w("arya").admin("member_remove", {"agent": w.ids["eve"].id})     # only 1 of the 2 other admins needed? no: min(k, 3-1) = 2
        self.assertEqual(status(w, ev).status, "rejected")
        ev = w.w("arya").admin("member_remove", {"agent": w.ids["eve"].id}, cosigners=[w.ids["eve"]])   # the target's own signature does not count
        self.assertEqual(status(w, ev).status, "rejected")
        ev = w.w("arya").admin("member_remove", {"agent": w.ids["eve"].id}, cosigners=[w.ids["dave"]])
        self.assertTrue(status(w, ev).ok)

    def test_removal_lowers_the_threshold_instead_of_starving_it(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        ev = w.w("arya").admin("member_remove", {"agent": w.ids["dave"].id}, cosigners=[w.ids["dave"]])
        w.add(ev)                                                    # allowed: k drops to the size of the admin set instead of becoming unreachable
        st = w.t.state()
        self.assertEqual(st["admin_threshold"], 1)
        self.assertNotIn(w.ids["dave"].id, st["members"])


class Ownership(unittest.TestCase):
    def test_owner_transfer_needs_the_new_owners_cosignature(self):
        w = World()
        no = w.ids["sansa"]
        self.assertEqual(status(w, w.w("arya").admin("owner_transfer", {"new_owner": no.id}, epoch_delta=1)).status, "rejected")
        w.add(w.w("arya").admin("owner_transfer", {"new_owner": no.id}, cosigners=[no], epoch_delta=1))
        st = w.t.state()
        self.assertEqual((st["owner"], st["owner_epoch"], st["members"][w.ids["arya"].id]["role"]), (no.id, 1, "admin"))
        self.assertEqual(status(w, w.w("arya").admin("close", {})).status, "rejected")           # the old owner cannot close any more
        w.add(w.w("sansa").admin("close", {}))

    def test_stale_owner_epoch_rejected(self):
        w = World()
        w.add(w.w("arya").admin("owner_transfer", {"new_owner": w.ids["sansa"].id}, cosigners=[w.ids["sansa"]], epoch_delta=1))
        ev = w.w("sansa").admin("rules_update", {"rules": {"max_members": 20}})
        ev["body"]["owner_epoch"] = 0
        ev["sig"] = w.ids["sansa"].sign(E.sign_input(ev))
        self.assertEqual(status(w, ev).status, "rejected")

    def _checkpoint(self, w):
        heads = w.t.tips()
        return w.w("arya").admin("checkpoint", {"count": len(w.t.events), "heads": heads, "epoch": w.t.state()["epoch"]})

    def test_checkpoint_rules(self):
        w = World()
        w.post("carol", "x")
        self.assertTrue(status(w, self._checkpoint(w)).ok)
        bad = w.w("arya").admin("checkpoint", {"count": 1, "heads": ["9" * 32], "epoch": 0})
        self.assertEqual(status(w, bad).status, "rejected")
        fresh = World()                                                        # heads we have not seen do NOT decide validity (arrival must not)
        r = status(fresh, fresh.w("arya").admin("checkpoint", {"count": 1, "heads": ["9" * 32], "epoch": 0}))
        self.assertTrue(r.ok)
        self.assertIn("9" * 32, fresh.t.missing())                                        # ...they are just hints of what to fetch
        self.assertEqual(status(w, w.w("carol").admin("checkpoint", {"count": 1, "heads": w.t.tips(), "epoch": 0})).status, "rejected")

    def test_takeover_quorum(self):
        w = World(extra_members=[("dave", "member")], successors=("sansa", "carol"))
        w.post("carol", "x")
        w.add(self._checkpoint(w))
        nxt = lambda who, cos, **kw: w.w(who).admin("owner_takeover", {"last_checkpoint": kw.get("cp", w.t.state()["last_cp"])}, cosigners=cos, epoch_delta=1)
        s, c, d = (w.ids[n] for n in ("sansa", "carol", "dave"))
        # voters = sansa, carol, dave (3 non-owner voters): need 2 acks; the author counts as one
        self.assertEqual(status(w, nxt("sansa", [])).status, "rejected")
        self.assertEqual(status(w, nxt("sansa", [w.ids["hu"]])).status, "rejected")             # an observer's ack does not count
        self.assertEqual(status(w, nxt("dave", [c])).status, "rejected")                        # dave is not a listed successor
        self.assertEqual(status(w, nxt("sansa", [c], cp=w.t.id)).status, "rejected")           # not the latest checkpoint
        forged = E.add_cosig(nxt("sansa", []), c); forged["cosigs"][0]["sig"] = c.sign(b"other")
        self.assertEqual(status(w, forged).status, "rejected")
        # ESCALATION (Sansa #7): a later successor may take over when the first is silent...
        tk_carol, tk_sansa = nxt("carol", [d]), nxt("sansa", [c])                                 # both built on the same prev_admin
        w.add(tk_carol)
        self.assertEqual(w.t.state()["owner"], c.id)
        # ...but an earlier successor outranks it on the same prev_admin, wherever it arrives: sansa's takeover replaces carol's
        r = status(w, tk_sansa)
        self.assertEqual((r.status, r.reorg), ("accepted", True))
        st = w.t.state()
        self.assertEqual((st["owner"], st["owner_epoch"], st["members"][w.ids["arya"].id]["role"]), (s.id, 1, "member"))
        self.assertEqual(status(w, w.w("arya").admin("close", {})).status, "rejected")           # the old owner is out

    def test_takeover_outranks_the_owners_checkpoint_on_the_same_prev(self):
        w = World(successors=("sansa",), extra_members=[("dave", "member")])
        w.post("carol", "x")
        w.add(self._checkpoint(w))
        cp = w.t.state()["last_cp"]
        take = w.w("sansa").admin("owner_takeover", {"last_checkpoint": cp}, cosigners=[w.ids["carol"]], epoch_delta=1)
        w.add(self._checkpoint(w))                                                              # the owner returns first
        r = status(w, take)
        # RULE (Sansa #2): a takeover with valid acks beats the owner's later event on the same prev_admin, wherever it arrives
        self.assertEqual((r.status, r.reorg), ("accepted", True))
        self.assertFalse(w.t.owner_equivocated)                                                 # different authors: a competing proposal, not owner equivocation
        self.assertEqual(w.t.state()["owner"], w.ids["sansa"].id)

    def test_pair_thread_has_no_takeover(self):
        i = World().ids
        t = Thread(make_genesis(i["arya"], "pair", [(i["sansa"], "member")]))
        self.assertEqual(t.accept(Writer(i["sansa"], t).admin("owner_takeover", {"last_checkpoint": t.id}, epoch_delta=1)).status, "rejected")


class Guests(unittest.TestCase):
    def setUp(self):
        self.w = World(visibility="public")
        self.root = self.w.post("arya", "who can help?")

    def test_full_admission_flow(self):
        w, d = self.w, self.w.ids["dave"]
        req = Writer(d, w.t).guest_request("I can help", self.root)
        self.assertEqual(status(w, req).status, "awaiting")
        self.assertNotIn(event_id(req), w.t.events)
        twin = Writer(d, w.t).guest_request("another", self.root, ts=9, seq=req["seq"])                 # same seq, different event
        self.assertEqual(status(w, twin).status, "awaiting")
        r = status(w, w.w("arya").add_member(d, "guest", admits=[event_id(req), event_id(twin)]))
        self.assertEqual(len({event_id(req), event_id(twin)} & set(w.t.events)), 0)                     # one seq, two events: neither is live
        self.assertTrue(r.ok)
        self.assertEqual(w.t.state()["members"][d.id]["role"], "guest")
        self.assertTrue(status(w, Writer(d, w.t).post("follow up", reply_to=self.root)).ok)
        self.assertEqual(status(w, Writer(d, w.t).admin("close", {})).status, "rejected")               # a guest cannot do admin things
        self.assertEqual(status(w, Writer(d, w.t).event("digest", {"text": "x", "covers": []})).status, "rejected")

    def test_request_arriving_after_the_member_add_is_still_admitted(self):
        w, d = self.w, self.w.ids["dave"]
        req = Writer(d, w.t).guest_request("late but named", self.root)
        w.add(w.w("arya").add_member(d, "guest", admits=[event_id(req)]))
        self.assertTrue(status(w, req).ok)

    def test_unnamed_requests_and_wrong_agent_stay_out(self):
        w, d, e = self.w, self.w.ids["dave"], self.w.ids["eve"]
        rd = Writer(d, w.t).guest_request("from dave", self.root)
        re_ = Writer(e, w.t).guest_request("from eve", self.root)
        status(w, rd); status(w, re_)
        r = status(w, w.w("arya").add_member(d, "guest", admits=[event_id(rd), event_id(re_)]))       # eve's request named for dave
        self.assertIn(event_id(rd), r.accepted)
        self.assertNotIn(event_id(re_), r.accepted)
        self.assertNotIn(event_id(re_), w.t.events)
        self.assertEqual(status(w, re_).status, "awaiting")

    def test_guest_key_mismatch_and_forged_request(self):
        w, d, e = self.w, self.w.ids["dave"], self.w.ids["eve"]
        req = Writer(d, w.t).guest_request("hi", self.root)
        forged = copy.deepcopy(req); forged["body"]["guest"]["sign"] = e.sign_pub                        # someone else's key under dave's id
        forged["sig"] = e.sign(E.sign_input(forged))
        self.assertEqual(status(w, forged).status, "rejected")
        rewrite = copy.deepcopy(req); rewrite["body"]["text"] = "owner edited this"
        self.assertEqual(status(w, rewrite).status, "rejected")                                          # the owner cannot alter a guest's words
        w.add(w.w("arya").add_member(d, "guest", admits=[event_id(req)]))
        again = Writer(d, w.t).guest_request("second", self.root)
        self.assertEqual(status(w, again).status, "rejected")                                           # guest block only for non-members

    def test_awaiting_is_bounded_per_author(self):
        w, d = self.w, self.w.ids["dave"]
        results = []
        for n in range(6):
            ev = E.make_event(d, thread=w.t.id, kind="post", body={"text": str(n), "reply_to": self.root, "guest": {"name": "d", "sign": d.sign_pub, "kex": d.kex_pub}},
                              parents=[self.root], seq=n, admin_ref=w.t.head)
            results.append(status(w, ev).status)
        self.assertEqual(results, ["awaiting"] * 6)                                       # a flooder is never refused...
        mine = [e for e in w.t.awaiting.values() if e["author"] == d.id]
        self.assertEqual(sorted(e["seq"] for e in mine), [2, 3, 4, 5])                  # ...but keeps only its 4 newest: it evicts ITS OWN oldest


class Digests(unittest.TestCase):
    def test_pinning_is_owner_only(self):
        w = World()
        p = w.post("arya", "x")
        self.assertTrue(status(w, w.w("carol").event("digest", {"text": "sum", "covers": [p]})).ok)
        self.assertEqual(status(w, w.w("carol").event("digest", {"text": "sum", "covers": [p], "pinned": True})).status, "rejected")
        self.assertTrue(status(w, w.w("arya").event("digest", {"text": "sum", "covers": [p], "pinned": True})).ok)


if __name__ == "__main__":
    unittest.main()
