"""Who may change authority, signature domains, closed threads, admin-set invariants, resource bounds."""
import copy
import unittest

from sigilnet import event as E
from sigilnet.build import make_genesis
from sigilnet.event import cosign_input, event_id, sign_input
from sigilnet.thread import Thread, MAX_ADMIN_SIBLINGS, MAX_EQUIV_PER_AUTHOR
MAX_CONFLICTS = 64            # conflicts are derived now: bounded by what may be stored (siblings and equivocation losers per author)

from .test_scenarios import owner_cp, takeover
from .util2 import Net, deliver, rules


def raw_admin(net, view, who, kind, body, cos=(), seq=None, ts=1):
    st = view.state()
    b = {"prev_admin": view.head, "owner_epoch": st["owner_epoch"], **body}
    ev = E.make_event(net.ids[who], thread=net.tid, kind=kind, body=b, parents=[net.tid],
                      seq=net.w(who, view)._seq() if seq is None else seq, admin_ref=view.head, ts=ts)
    for c in cos:
        ev = E.add_cosig(ev, net.ids[c])
    return ev


def bodies(net, view):
    """One well-formed body per admin kind (as if signed by an admin), so that ONLY the author's standing decides."""
    x = net.ids["x"]
    return {
        "member_add": {"agent": x.id, "name": "x", "role": "member", "sign": x.sign_pub, "kex": x.kex_pub},
        "member_remove": {"agent": net.ids["dave"].id, "last_seq": -1},
        "revoke": {"agent": net.ids["sansa"].id, "last_seq": -1},
        "rules_update": {"rules": {"checkpoint_every": 7}},
        "checkpoint": {"count": 1, "heads": [net.tid], "epoch": 0},
        "close": {"cut": {}},
        "owner_transfer": {"new_owner": net.ids["carol"].id, "owner_epoch": 1},
        "owner_takeover": {"owner_epoch": 1, "last_checkpoint": net.tid},
    }


class WhoMayWrite(unittest.TestCase):
    def test_non_admins_cannot_write_any_admin_kind(self):
        net = Net(roles={"sansa": "admin", "carol": "member", "dave": "member", "hu": "observer"}, successors=("carol",), visibility="public")
        base = net.snap()
        for who in ("hu", "dave", "erin"):                # observer, plain member, stranger (a would-be guest)
            for kind, body in bodies(net, base).items():
                if who == "carol":
                    continue
                ev = raw_admin(net, base, who, kind, body, cos=["sansa", "carol"] if kind != "owner_takeover" else ())
                t = copy.deepcopy(base)
                if who == "erin":
                    ev["body"].pop("guest", None)
                r = t.accept(ev)
                self.assertNotEqual(r.status, "accepted", f"{who} wrote {kind}")
                self.assertEqual(t.head, base.head)

    def test_successor_may_only_write_takeover(self):
        net = Net(successors=("carol",))
        base = net.snap()
        for kind, body in bodies(net, base).items():
            if kind == "owner_takeover":
                continue
            r = copy.deepcopy(base).accept(raw_admin(net, base, "carol", kind, body, cos=["sansa", "dave"]))
            self.assertNotEqual(r.status, "accepted", f"successor wrote {kind}")

    def test_takeover_acks_must_come_from_current_non_owner_voters(self):
        net = Net(roles={"sansa": "member", "carol": "member", "dave": "member", "hu": "observer"}, successors=("carol",))
        base = net.snap()
        st = base.state()
        for cos, label in ((["hu"], "observer ack"), (["arya"], "owner ack"), ([], "no acks")):
            self.assertNotEqual(copy.deepcopy(base).accept(takeover(net, "carol", base, cos)).status, "accepted", label)
        # 4 non-owner voters would need 3, but hu is an observer -> voters are sansa, carol, dave: 2 of 3 is enough, 1 is not
        self.assertNotEqual(copy.deepcopy(base).accept(takeover(net, "carol", base, ["hu", "arya"])).status, "accepted")
        # (the fixture adds an admin, erin, as a fourth voter: three acks including the author are needed)
        self.assertEqual(copy.deepcopy(base).accept(takeover(net, "carol", base, ["sansa", "dave"])).status, "accepted")

    def test_cosig_and_event_signatures_are_not_interchangeable(self):
        net = Net(successors=("carol",))
        base = net.snap()
        good = takeover(net, "carol", base, ["sansa", "dave"])
        self.assertEqual(copy.deepcopy(base).accept(good).status, "accepted")
        # acks made with the EVENT domain (sign_input) instead of the cosig domain
        forged = dict(good)
        forged["cosigs"] = sorted([{"author": net.ids[n].id, "sig": net.ids[n].sign(sign_input(good))} for n in ("sansa", "dave")], key=lambda c: c["author"])
        self.assertNotEqual(copy.deepcopy(base).accept(forged).status, "accepted")
        # an author signature made in the cosig domain
        forged2 = dict(good)
        forged2["sig"] = net.ids["carol"].sign(cosign_input(good))
        self.assertNotEqual(copy.deepcopy(base).accept(forged2).status, "accepted")

    def test_no_replay_of_an_event_or_its_acks_into_another_thread(self):
        net = Net(successors=("carol",))
        other = make_genesis(net.ids["arya"], "twin", [(net.ids[n], "member") for n in ("sansa", "carol", "dave")] + [(net.ids["erin"], "admin")],
                             successors=[net.ids["carol"].id], k=2, rules=rules())
        twin = Thread(other)
        tk = takeover(net, "carol", net.snap(), ["sansa", "dave"])
        self.assertEqual(twin.accept(tk).status, "rejected")
        moved = dict(tk); moved["thread"] = twin.id
        self.assertNotEqual(twin.accept(moved).status, "accepted")
        # re-signed by the author for the new thread, but with the old thread's acks
        moved = E.make_event(net.ids["carol"], thread=twin.id, kind="owner_takeover", body=tk["body"], parents=[twin.id], seq=tk["seq"],
                             admin_ref=twin.head, ts=tk["ts"])
        moved["body"] = dict(tk["body"], prev_admin=twin.head, last_checkpoint=twin.id)
        moved = E.make_event(net.ids["carol"], thread=twin.id, kind="owner_takeover", body=moved["body"], parents=[twin.id], seq=tk["seq"],
                             admin_ref=twin.head, ts=tk["ts"])
        moved["cosigs"] = tk["cosigs"]
        self.assertNotEqual(twin.accept(moved).status, "accepted", "acks made for another thread counted")


class ClosedThread(unittest.TestCase):
    def test_closed_thread_accepts_nothing_new_and_cannot_be_reopened(self):
        net = Net(successors=("carol",))
        p = net.w("carol").post("before"); net.take(p)
        close = net.w("arya").admin("close", {}); net.take(close)
        t = net.ref
        self.assertTrue(t.state()["closed"])
        for kind, body in bodies(net, t).items():
            for who in ("arya", "carol", "sansa"):
                r = copy.deepcopy(t).accept(raw_admin(net, t, who, kind, body, cos=["sansa", "dave"]))
                self.assertNotEqual(r.status, "accepted", f"{who} {kind} on a closed thread")
        late = net.w("carol", t).post("citing the closed state")
        self.assertEqual(copy.deepcopy(t).accept(late).status, "rejected")

    def test_events_beyond_the_cut_are_void_whenever_they_arrive(self):
        net = Net()
        p0 = net.w("carol").post("seen"); net.take(p0)
        base = net.snap()
        p1 = net.w("carol", base).post("unseen by the closer")
        close = net.w("arya", base).admin("close", {})
        for order in ([p1, close], [close, p1]):
            t = deliver(net.genesis, [p0] + order)
            self.assertIn(event_id(p1), t.void_ids)
            self.assertNotIn(event_id(p0), t.void_ids)


class AdminSetInvariants(unittest.TestCase):
    def test_k_cannot_become_unreachable_by_removal_or_revoke(self):
        net = Net(roles={"sansa": "admin", "carol": "member", "dave": "member"}, k=2, successors=())      # (with successors, leaving a lone admin also needs a member majority: tests/test_thread.py)
        base = net.snap()
        for kind in ("member_remove", "revoke"):
            ev = raw_admin(net, base, "arya", kind, {"agent": net.ids["sansa"].id, "last_seq": -1}, cos=["sansa"])
            t = copy.deepcopy(base)
            self.assertEqual(t.accept(ev).status, "accepted", kind)
            self.assertEqual(t.state()["admin_threshold"], 1, kind)          # lowered to the remaining admin set, never unreachable
        ev = raw_admin(net, base, "sansa", "revoke", {"agent": net.ids["sansa"].id, "last_seq": -1})
        t = copy.deepcopy(base)
        if t.accept(ev).status == "accepted":
            self.assertLessEqual(t.state()["admin_threshold"], len({a for a, m in t.state()["members"].items() if m["role"] in ("owner", "admin")}))

    def test_owner_transfer_rules(self):
        net = Net(roles={"sansa": "admin", "carol": "member", "hu": "observer", "dave": "member"}, k=2, successors=("carol",))
        base = net.snap()
        def tr(new, cos):
            return raw_admin(net, base, "arya", "owner_transfer", {"new_owner": net.ids[new].id, "owner_epoch": 1}, cos=cos)
        self.assertNotEqual(copy.deepcopy(base).accept(tr("hu", ["sansa", "hu"])).status, "accepted", "observer as owner")
        self.assertNotEqual(copy.deepcopy(base).accept(tr("carol", ["sansa"])).status, "accepted", "no consent from the new owner")
        self.assertNotEqual(copy.deepcopy(base).accept(tr("arya", ["sansa"])).status, "accepted", "to itself")
        self.assertNotEqual(copy.deepcopy(base).accept(tr("erin", ["sansa", "erin"])).status, "accepted", "to a non-member")
        self.assertNotEqual(copy.deepcopy(base).accept(tr("carol", ["carol"])).status, "accepted", "k=2 needs a second admin signature")
        ok = copy.deepcopy(base)
        self.assertEqual(ok.accept(tr("carol", ["sansa", "carol"])).status, "accepted")
        st = ok.state()
        self.assertEqual(st["owner"], net.ids["carol"].id)
        self.assertEqual(st["members"][net.ids["arya"].id]["role"], "admin")
        self.assertNotIn(net.ids["carol"].id, st["successors"])

    def test_removed_agent_cannot_come_back_or_write(self):
        net = Net()
        rem = net.w("arya").admin("member_remove", {"agent": net.ids["dave"].id}); net.take(rem)
        t = net.ref
        x = net.ids["dave"]
        self.assertNotEqual(copy.deepcopy(t).accept(net.w("arya", t).add_member(x)).status, "accepted")
        late = net.w("dave", t).post("still here")
        self.assertNotEqual(copy.deepcopy(t).accept(late).status, "accepted")

    def test_rules_update_cannot_make_observers_or_guests_successors(self):
        net = Net(roles={"sansa": "member", "carol": "member", "hu": "observer"}, successors=("carol",))
        for bad in ("hu", "arya"):
            ev = net.w("arya").admin("rules_update", {"successors": [net.ids[bad].id]})
            self.assertNotEqual(copy.deepcopy(net.ref).accept(ev).status, "accepted", bad)

    def test_takeover_never_leaves_k_above_the_admin_set(self):
        net = Net(roles={"sansa": "admin", "carol": "member", "dave": "member"}, k=2, successors=("carol",))
        t = copy.deepcopy(net.ref)
        self.assertEqual(t.accept(takeover(net, "carol", net.ref, ["sansa", "dave"])).status, "accepted")
        st = t.state()
        self.assertLessEqual(st["admin_threshold"], len(Thread.admin_set(st)))
        self.assertGreaterEqual(st["admin_threshold"], 1)


class GuestGate(unittest.TestCase):
    def test_guest_cannot_use_the_request_to_do_anything_but_ask(self):
        net = Net(visibility="public")
        op = net.w("arya").post("hi"); net.take(op)
        g = net.ids["g1"]
        guest = {"name": "g1", "sign": g.sign_pub, "kex": g.kex_pub}
        for kind, body in (("checkpoint", {"prev_admin": net.tid, "owner_epoch": 0, "count": 0, "heads": [net.tid], "epoch": 0, "guest": guest}),
                           ("member_add", {"prev_admin": net.tid, "owner_epoch": 0, "guest": guest}),
                           ("digest", {"text": "x", "covers": [], "guest": guest}),
                           ("evidence", {"a": {}, "b": {}, "guest": guest})):
            ev = E.make_event(g, thread=net.tid, kind=kind, body=body, parents=[event_id(op)], seq=0, admin_ref=net.tid, ts=1)
            r = copy.deepcopy(net.ref).accept(ev)
            self.assertNotIn(r.status, ("accepted", "awaiting"), kind)

    def test_member_cannot_carry_a_guest_field_and_key_must_match_author(self):
        net = Net(visibility="public")
        op = net.w("arya").post("hi"); net.take(op)
        g, h = net.ids["g1"], net.ids["g2"]
        mism = E.make_event(g, thread=net.tid, kind="post", body={"text": "x", "reply_to": event_id(op), "guest": {"name": "g", "sign": h.sign_pub, "kex": h.kex_pub}},
                            parents=[event_id(op)], seq=0, admin_ref=net.tid, ts=1)
        self.assertEqual(copy.deepcopy(net.ref).accept(mism).status, "rejected")
        m = E.make_event(net.ids["carol"], thread=net.tid, kind="post", body={"text": "x", "guest": {"name": "c", "sign": net.ids["carol"].sign_pub, "kex": net.ids["carol"].kex_pub}},
                         parents=[event_id(op)], seq=0, admin_ref=net.tid, ts=1)
        self.assertNotEqual(copy.deepcopy(net.ref).accept(m).status, "accepted")

    def test_admission_names_the_agent_it_admits(self):
        net = Net(visibility="public")
        op = net.w("arya").post("hi"); net.take(op)
        G = net.w("g1").guest_request("please", event_id(op))
        net.take(G)
        h = net.ids["g2"]
        # admit a DIFFERENT agent while naming g1's request: g1's request must not become live
        ev = net.w("arya").add_member(h, "guest", admits=[event_id(G)])
        net.take(ev)
        self.assertNotIn(event_id(G), net.ref.events)
        self.assertNotIn(net.ids["g1"].id, net.ref.state()["members"])


class Bounds(unittest.TestCase):
    def test_lost_branch_tombstones_are_bounded(self):
        # BUG (medium): _on_lost_branch stores every signed admin-kind event by ANY known key into lost_admin (no cap, no membership or
        # body check, not persisted): a removed member can grow it without limit once one admin branch has lost a fork
        net = Net()
        base = net.snap()
        T = takeover(net, "carol", base, ["sansa", "dave"])
        C = owner_cp(net, base, 3, seq=1)
        t = deliver(net.genesis, [T, C])
        self.assertIn(event_id(C), t.lost_admin)
        x = net.ids["dave"]
        for i in range(1500):
            ev = E.make_event(x, thread=net.tid, kind="checkpoint", body={"junk": i}, parents=[net.tid], seq=i, admin_ref=event_id(C), ts=i)
            t.accept(ev)
        self.assertLess(len(t.lost_admin), 1000, f"{len(t.lost_admin)} junk 'lost' admin events retained in memory")

    def test_equivocation_records_are_bounded(self):
        net = Net()
        for i in range(200):
            a = E.make_event(net.ids["carol"], thread=net.tid, kind="post", body={"text": "a"}, parents=[net.tid], seq=i, admin_ref=net.tid, ts=1)
            b = E.make_event(net.ids["carol"], thread=net.tid, kind="post", body={"text": "b"}, parents=[net.tid], seq=i, admin_ref=net.tid, ts=2)
            net.ref.accept(a); net.ref.accept(b)
        self.assertLessEqual(len(net.ref.conflicts), MAX_CONFLICTS)

    def test_a_flood_of_forks_by_a_non_owner_admin_is_bounded(self):
        # BUG (medium): every lower-id fork of the head by an admin (k=1) costs a full O(events) rebuild; see test_scenarios too
        net = Net(roles={"sansa": "admin", "carol": "member", "dave": "member"})
        t = Thread(net.genesis)
        for i in range(200):
            t.accept(net.w("carol", t).post(f"p{i}", ts=i))
        base = copy.deepcopy(t)
        x = net.ids["x"]
        forks = sorted((raw_admin(net, base, "sansa", "member_add", bodies(net, base)["member_add"], seq=i, ts=i) for i in range(1, 30)), key=event_id, reverse=True)
        n = sum(t.accept(f).reorg for f in forks)
        self.assertLess(n, 5, f"{n} rebuilds of a 200-event thread caused by one admin's sibling events")


if __name__ == "__main__":
    unittest.main()
