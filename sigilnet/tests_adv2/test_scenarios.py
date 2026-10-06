"""Targeted scenarios. Each test that fails is a real library bug (marked # BUG:)."""
import copy
import tempfile
import time
import unittest

from sigilnet import event as E
from sigilnet.event import event_id
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread

from .util2 import Net, deliver, diff, fingerprint, grind, mirror_with, rules


def owner_cp(net, view, ts, seq=None):
    """Owner checkpoint on `view`'s head."""
    st = view.state()
    return E.make_event(net.ids["arya"], thread=net.tid, kind="checkpoint", parents=[net.tid], seq=view.by_author_seq and
                        (max(s for (a, s) in view.by_author_seq if a == net.ids["arya"].id) + 1 if seq is None else seq),
                        admin_ref=view.head, ts=ts,
                        body={"prev_admin": view.head, "owner_epoch": st["owner_epoch"], "count": 0, "heads": [net.tid], "epoch": st["epoch"]})


def takeover(net, who, view, cosigners, ts=5, seq=None):
    st = view.state()
    w = net.w(who, view)
    ev = E.make_event(net.ids[who], thread=net.tid, kind="owner_takeover", parents=[net.tid], seq=w._seq() if seq is None else seq, admin_ref=view.head, ts=ts,
                      body={"prev_admin": view.head, "owner_epoch": st["owner_epoch"] + 1, "last_checkpoint": st["last_cp"]})
    for c in cosigners:
        ev = E.add_cosig(ev, net.ids[c])
    return ev


class ReloadDropsEvents(unittest.TestCase):
    """Mirror.__init__ replays events.jsonl BEFORE loading conflicts.jsonl / awaiting.jsonl, and a few pieces of consensus state are memory only."""

    def _fork_loser_after_winner(self):
        net = Net()
        base = net.snap()
        T = takeover(net, "carol", base, ["sansa", "dave"])
        C = owner_cp(net, base, ts=7)
        return net, T, C

    def test_winner_of_a_reorg_is_not_marked_lost_after_reload(self):
        # BUG: _load_conflicts marks `b` of every admin_fork record lost, but for a reorg the record is (loser, WINNER)
        net, T, C = self._fork_loser_after_winner()
        root = tempfile.mkdtemp()
        m = Mirror(root, rate_limit=False)
        for ev in (net.genesis, C, T):
            m.ingest(ev)
        t = m.thread(net.tid)
        self.assertEqual(t.head, event_id(T))
        self.assertIn(event_id(C), t.lost_admin)
        self.assertNotIn(event_id(T), t.lost_admin)
        t2 = Mirror(root, rate_limit=False).thread(net.tid)
        self.assertEqual(t2.head, event_id(T))
        self.assertNotIn(event_id(T), t2.lost_admin, "the winning takeover is now a lost branch after reload")

    def test_events_on_the_winning_branch_are_not_voided_after_reload(self):
        net, T, C = self._fork_loser_after_winner()
        root = tempfile.mkdtemp()
        m = Mirror(root, rate_limit=False)
        for ev in (net.genesis, C, T):
            m.ingest(ev)
        t = m.thread(net.tid)
        w = net.w("carol", t)
        post_live = w.post("after takeover, before restart")
        self.assertEqual(m.ingest(post_live).status, "accepted")
        m2 = Mirror(root, rate_limit=False)
        t2 = m2.thread(net.tid)
        self.assertNotIn(event_id(post_live), t2.void_ids)
        again = net.w("dave", t2).post("after takeover, after restart")
        res = m2.ingest(again)
        self.assertEqual(res.status, "accepted", f"same event, same head: {res.status} ({res.reason}) after reload")

    def test_void_event_citing_lost_branch_survives_reload(self):
        # BUG: an event whose admin_ref is a fork loser is stored as a voided tombstone; on reload it is replayed before conflicts.jsonl
        # is read, so it is 'pending' and silently dropped
        net = Net()
        base = net.snap()
        T = takeover(net, "carol", base, ["sansa", "dave"])
        C = owner_cp(net, base, ts=7)
        w = net.w("arya", base)
        P = E.make_event(net.ids["arya"], thread=net.tid, kind="post", body={"text": "owner, stale view"}, parents=[net.tid], seq=2,
                         admin_ref=event_id(C), ts=9)
        root = tempfile.mkdtemp()
        m = Mirror(root, rate_limit=False)
        for ev in (net.genesis, T, C, P):
            m.ingest(ev)
        t = m.thread(net.tid)
        self.assertIn(event_id(P), t.void_ids)
        t2 = Mirror(root, rate_limit=False).thread(net.tid)
        self.assertEqual(fingerprint(t)["void"], fingerprint(t2)["void"], "voided event vanished on reload")

    def test_child_of_a_lost_admin_event_is_forgotten_by_reload(self):
        # BUG: lost_admin entries created by _on_lost_branch are neither persisted nor rebuilt; events citing them are dropped on reload
        net = Net()
        base = net.snap()
        T = takeover(net, "carol", base, ["sansa", "dave"])
        C1 = owner_cp(net, base, ts=7)
        v = net.snap(); v.accept(C1)
        C2 = E.make_event(net.ids["arya"], thread=net.tid, kind="checkpoint", parents=[net.tid], seq=2, admin_ref=event_id(C1), ts=8,
                          body={"prev_admin": event_id(C1), "owner_epoch": 0, "count": 0, "heads": [net.tid], "epoch": 0})
        P = E.make_event(net.ids["arya"], thread=net.tid, kind="post", body={"text": "cites C2"}, parents=[net.tid], seq=3,
                         admin_ref=event_id(C2), ts=9)
        root = tempfile.mkdtemp()
        m = Mirror(root, rate_limit=False)
        for ev in (net.genesis, T, C1, C2, P):
            m.ingest(ev)
        t = m.thread(net.tid)
        f1 = fingerprint(t)
        self.assertIn(event_id(C2), f1["lost"])
        f2 = fingerprint(Mirror(root, rate_limit=False).thread(net.tid))
        self.assertEqual(diff(f1, f2), {}, "live mirror and its own reload disagree")

    def test_reply_to_awaiting_guest_request_survives_reload(self):
        # BUG: an event whose parent is an awaiting guest request is accepted and persisted, but on reload it is replayed before
        # awaiting.jsonl is loaded, so it is pending and dropped
        net = Net(visibility="public")
        op = net.w("arya").post("come in")
        net.take(op)
        g = net.w("g1").guest_request("hi, may I join?", event_id(op))
        root = tempfile.mkdtemp()
        m = Mirror(root, rate_limit=False)
        for ev in (net.genesis, op, g):
            m.ingest(ev)
        t = m.thread(net.tid)
        self.assertIn(event_id(g), t.awaiting)
        reply = net.w("arya", t).post("who are you?", parents=[event_id(g)])
        self.assertEqual(m.ingest(reply).status, "accepted")
        t2 = Mirror(root, rate_limit=False).thread(net.tid)
        self.assertIn(event_id(reply), t2.events, "owner's reply to a guest request is gone after restart")


class SameAuthorForkReload(unittest.TestCase):
    def _forks(self):
        net = Net()
        base = net.snap()
        a, b = owner_cp(net, base, 1, seq=1), owner_cp(net, base, 2, seq=2)
        lo, hi = sorted([a, b], key=event_id)
        return net, lo, hi

    def test_winner_of_a_same_author_reorg_is_not_lost_after_reload(self):
        # BUG (high): the conflict record of a reorg is (loser, WINNER); on load, _load_conflicts marks `b` (the winner) as lost. The
        # cross-author case (takeover vs checkpoint) is skipped by the a.author == b.author check, but an owner's own fork is not.
        net, lo, hi = self._forks()
        root = tempfile.mkdtemp()
        m = Mirror(root, rate_limit=False)
        for ev in (net.genesis, hi, lo):
            m.ingest(ev)
        t = m.thread(net.tid)
        self.assertEqual(t.head, event_id(lo))
        self.assertNotIn(event_id(lo), t.lost_admin)
        t2 = Mirror(root, rate_limit=False).thread(net.tid)
        self.assertNotIn(event_id(lo), t2.lost_admin, "the chain head is a lost branch after reload")

    def test_events_citing_the_winner_are_live_after_reload(self):
        net, lo, hi = self._forks()
        root = tempfile.mkdtemp()
        m = Mirror(root, rate_limit=False)
        for ev in (net.genesis, hi, lo):
            m.ingest(ev)
        m2 = Mirror(root, rate_limit=False)
        post = net.w("carol", m2.thread(net.tid)).post("after the reorg and a restart")
        res = m2.ingest(post)
        self.assertEqual(res.status, "accepted", f"{res.status}: {res.reason}")


class KnownKeysOrder(unittest.TestCase):
    def test_event_by_agent_added_on_a_lost_branch_is_voided_in_every_order(self):
        # BUG (medium): _on_lost_branch needs known_keys[author], but a key is learned only when the member_add is TRANSITIONED. On a mirror
        # that saw the losing chain first, erin's key is known (post -> void); on one that saw the winner first, the member_add (child of a
        # lost event) is never transitioned, so the same post is 'rejected: unknown author' and is absent from the set.
        net = Net()
        base = net.snap()
        C1 = owner_cp(net, base, 1, seq=1)
        v = net.snap(); v.accept(C1)
        erin = net.ids["erin"]
        M = net.w("arya", v).add_member(erin, "member")
        P = E.make_event(erin, thread=net.tid, kind="post", body={"text": "hi"}, parents=[net.tid], seq=0, admin_ref=event_id(M), ts=3)
        T = takeover(net, "carol", base, ["sansa", "dave"])
        a = fingerprint(deliver(net.genesis, [C1, M, P, T]))
        b = fingerprint(deliver(net.genesis, [T, C1, M, P]))
        self.assertEqual(diff(a, b), {})


class PendingNotDrained(unittest.TestCase):
    def test_void_or_awaiting_arrival_releases_parked_children(self):
        # BUG (low): Mirror.ingest drains the pending buffer only after an 'accepted' result, but a tombstone / awaiting request /
        # lost branch also counts as a known parent, so children stay parked until some unrelated event arrives
        net = Net(visibility="public")
        op = net.w("arya").post("come in"); net.take(op)
        g = net.w("g1").guest_request("hello", event_id(op))
        child = E.make_event(net.ids["arya"], thread=net.tid, kind="post", body={"text": "re guest"}, parents=[event_id(g)], seq=2,
                             admin_ref=net.tid, ts=5)
        m = mirror_with(net.genesis, [op], passes=1)
        self.assertEqual(m.ingest(child).status, "pending")
        self.assertEqual(m.ingest(g).status, "awaiting")
        self.assertIn(event_id(child), m.thread(net.tid).events, "child of an awaiting guest request stays pending")


class EquivocationDivergence(unittest.TestCase):
    def test_same_seq_admin_forks_converge_on_one_head(self):
        # BUG: the (author, seq) equivocation check runs before fork ranking, so an owner who signs two admin events with the same
        # seq and prev_admin makes every mirror keep whichever arrived first: heads differ per delivery order
        net = Net()
        base = net.snap()
        c1 = owner_cp(net, base, ts=1, seq=1)
        c2 = owner_cp(net, base, ts=2, seq=1)
        a = deliver(net.genesis, [c1, c2]); b = deliver(net.genesis, [c2, c1])
        self.assertEqual(a.head, b.head, "two mirrors that hold the same two events disagree about the admin head")

    def test_same_seq_admin_forks_control_different_seq_converges(self):
        net = Net()
        base = net.snap()
        c1 = owner_cp(net, base, ts=1, seq=1)
        c2 = owner_cp(net, base, ts=2, seq=2)
        a = deliver(net.genesis, [c1, c2]); b = deliver(net.genesis, [c2, c1])
        self.assertEqual(a.head, b.head)

    def test_same_seq_posts_converge_on_one_live_set(self):
        # BUG (medium): a member equivocating on (author, seq) makes the live set depend on arrival order; events that reply to the
        # loser are pending on one mirror and live on the other
        net = Net()
        p1 = E.make_event(net.ids["carol"], thread=net.tid, kind="post", body={"text": "one"}, parents=[net.tid], seq=0, admin_ref=net.tid, ts=1)
        p2 = E.make_event(net.ids["carol"], thread=net.tid, kind="post", body={"text": "two"}, parents=[net.tid], seq=0, admin_ref=net.tid, ts=2)
        r = E.make_event(net.ids["dave"], thread=net.tid, kind="post", body={"text": "re one", "reply_to": event_id(p1)}, parents=[event_id(p1)],
                         seq=0, admin_ref=net.tid, ts=3)
        a = fingerprint(deliver(net.genesis, [p1, p2, r])); b = fingerprint(deliver(net.genesis, [p2, p1, r]))
        self.assertEqual(diff(a, b), {}, "same event set, different live set")


class GuestAdmission(unittest.TestCase):
    def _setup(self):
        net = Net(visibility="public", successors=("carol",))
        op = net.w("arya").post("come in"); net.take(op)
        g1 = net.ids["g1"]
        G0 = net.w("g1").guest_request("hello", event_id(op)); 
        return net, op, g1, G0

    def test_guest_request_arriving_after_admission_and_removal(self):
        # BUG: the 'already admitted' fast path checks the HEAD membership, not membership as of the admission. If the guest was
        # removed meanwhile, the request that arrived late is 'awaiting' forever, though on a mirror that saw it first it is live (seq <= last_seq)
        net, op, g1, G0 = self._setup()
        base = net.snap()
        add = net.w("arya", base).add_member(g1, "guest", admits=[event_id(G0)])
        v = net.snap(); v.accept(op); v.accept(add)
        rem = net.w("arya", v).admin("member_remove", {"agent": g1.id, "last_seq": 0})
        evs = {"G0": G0, "add": add, "rem": rem}
        first = deliver(net.genesis, [op, G0, add, rem])
        late = deliver(net.genesis, [op, add, rem, G0])
        self.assertIn(event_id(G0), first.events)          # sanity: request seen first is admitted and within its cut
        self.assertEqual(diff(fingerprint(first), fingerprint(late)), {})

    def test_admitted_request_on_a_branch_that_lost(self):
        # BUG: _reorg replays the admitted guest request through accept (-> awaiting), then force-commits it as VOID; a later admission on the
        # winning branch is then ignored ((author, seq) taken), whereas a mirror that never saw the loser admits it normally
        net, op, g1, G0 = self._setup()
        base = net.snap(); base.accept(op)
        M1 = net.w("arya", base).add_member(g1, "guest", admits=[event_id(G0)])
        T = takeover(net, "carol", base, ["sansa", "dave"])
        v = copy.deepcopy(base); v.accept(T)
        M2 = net.w("carol", v).add_member(g1, "guest", admits=[event_id(G0)])
        evs = [op, G0, M1, T, M2]
        a = deliver(net.genesis, evs)
        b = deliver(net.genesis, [op, T, M2, G0, M1])
        self.assertIn(event_id(G0), b.events)
        self.assertEqual(diff(fingerprint(a), fingerprint(b)), {}, "same event set: the guest request is live in one, void in the other")


class VoidCap(unittest.TestCase):
    @unittest.expectedFailure      # KNOWN LIMIT: MAX_VOID is a per-thread STORAGE cap; a removed member flooding >1000 events makes the stored void set differ by arrival order (the live set does not)
    def test_void_set_does_not_depend_on_whether_events_beat_the_removal(self):
        # BUG (medium): MAX_VOID=1000 truncates voids for events that arrive after the removal but not for ones swept by it, and rejected
        # events are not stored, so a removed member can make void sets (and stored events) differ by arrival order
        net = Net()
        posts = [E.make_event(net.ids["dave"], thread=net.tid, kind="post", body={"text": str(i)}, parents=[net.tid], seq=i, admin_ref=net.tid, ts=i)
                 for i in range(1010)]
        rem = net.w("arya").admin("member_remove", {"agent": net.ids["dave"].id, "last_seq": -1})
        before = deliver(net.genesis, posts + [rem], passes=1)
        after = deliver(net.genesis, [rem] + posts, passes=1)
        self.assertEqual(len(before.void_ids), len(after.void_ids))
        self.assertEqual(fingerprint(before)["void"], fingerprint(after)["void"])


class RankVeto(unittest.TestCase):
    def test_removed_admin_cannot_undo_own_removal_by_forking_the_removal(self):
        # BUG (high): 'lower id wins' is grindable and a removed admin's own admin events are still valid as of the pre-removal head, so a
        # removed admin (k=1) forks the removal, wins on id and is an admin again; nothing marks the removal as final
        net = Net(roles={"sansa": "admin", "carol": "member", "dave": "member"}, successors=())      # k=1 is only legal without successors (spec 0.9)
        base = net.snap()
        rem = net.w("arya", base).admin("member_remove", {"agent": net.ids["sansa"].id, "last_seq": -1})
        x = net.ids["x"]
        atk = grind(lambda ts: net.w("sansa", base).add_member(x, "member", ts=ts), event_id(rem))
        for order in ([rem, atk], [atk, rem]):
            t = deliver(net.genesis, order)
            st = t.state()
            self.assertNotIn(net.ids["sansa"].id, st["members"], f"removed admin is back as {st['members'].get(net.ids['sansa'].id)} (order {['rem','atk'] if order[0] is rem else ['atk','rem']})")

    def test_repeated_reorgs_are_bounded(self):
        # BUG (medium): each lower-id fork of the same prev_admin triggers a full O(events) rebuild; an owner/admin can force unboundedly many
        # (and lost_admin grows by one per fork, uncapped and not persisted separately)
        net = Net()
        base = net.snap()
        cps = sorted((owner_cp(net, base, ts=i, seq=i) for i in range(1, 41)), key=event_id, reverse=True)
        t = Thread(net.genesis)
        for i in range(300):
            t.accept(net.w("carol", t).post(f"p{i}", ts=i))
        reorgs = 0
        t0 = time.time()
        for ev in cps:
            reorgs += t.accept(ev).reorg
        self.assertLess(reorgs, 10, f"{reorgs} full chain rebuilds for 40 same-prev checkpoints, {len(t.lost_admin)} lost entries, {time.time()-t0:.2f}s")


class DeepReorg(unittest.TestCase):
    @unittest.expectedFailure      # DESIGN DECISION (documented): a quorum takeover outranks the owner's chain at any depth; checkpoints are owner-signed and cannot bind a quorum (else the owner could veto a takeover by publishing two checkpoints)
    def test_takeover_cannot_rewrite_history_below_a_checkpoint(self):
        # BUG (medium, spec 6.2: 'everything at or below a checkpoint as final'): a takeover built on a head older than the latest
        # checkpoint still wins and discards the checkpoints and everything after them
        net = Net()
        cp1 = owner_cp(net, net.snap(), ts=1, seq=1); net.take(cp1)
        cp2 = owner_cp(net, net.snap(), ts=2, seq=2); net.take(cp2)
        T = takeover(net, "carol", Thread(net.genesis), ["sansa", "dave"])
        t = deliver(net.genesis, [cp1, cp2, T])
        self.assertNotIn(event_id(cp2), t.lost_admin, "checkpointed history was rebuilt away by a takeover on the genesis head")

    @unittest.expectedFailure      # DESIGN DECISION (documented): the quorum is the root of trust and may undo an owner's close; agents must only acknowledge a takeover built on the CURRENT head
    def test_closed_thread_cannot_be_reopened_by_a_stale_takeover(self):
        net = Net()
        base = net.snap()
        close = net.w("arya", base).admin("close", {})
        T = takeover(net, "carol", base, ["sansa", "dave"])
        t = deliver(net.genesis, [close, T])
        self.assertTrue(t.state()["closed"], "a closed thread was re-opened by a takeover signed against an earlier head")


class PairThread(unittest.TestCase):
    def test_pair_thread_history_survives_one_party_leaving(self):
        # BUG (high): a pair thread closes when a party leaves and closed_cut is left empty, so _void_reason voids EVERY event
        # of EVERY author (seq > -1), including the whole pre-removal conversation
        net = Net(roles={"sansa": "member"}, successors=())
        for i in range(3):
            net.take(net.w("arya").post(f"a{i}"))
            net.take(net.w("sansa").post(f"s{i}"))
        rev = net.w("sansa").admin("revoke", {"agent": net.ids["sansa"].id})
        net.take(rev)
        t = net.ref
        self.assertTrue(t.state()["closed"])
        live_posts = [i for i in t.events if t.events[i]["kind"] == "post" and i not in t.void_ids]
        self.assertEqual(len(live_posts), 6, f"only {len(live_posts)} of 6 posts remain visible after sansa left")


if __name__ == "__main__":
    unittest.main()
