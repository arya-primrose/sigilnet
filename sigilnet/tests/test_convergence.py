"""Property test for the deterministic-consensus rules: the SAME set of events, delivered in any order, must give the same visible
thread (live events, voided set, admin head, state). Histories include concurrency (events signed from a stale view), removals with a
last_seq cut, closes with a cut, and competing admin events (owner vs takeover, earlier vs later successor)."""
import copy
import random
import tempfile
import unittest

from sigilnet import event as E
from sigilnet.build import make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread, default_rules


def build_history(seed: int):
    rnd = random.Random(seed)
    ids = {n: Identity.generate(n) for n in ("arya", "sansa", "carol", "dave", "eve")}
    g = make_genesis(ids["arya"], "prop", [(ids["sansa"], "member"), (ids["carol"], "member"), (ids["dave"], "admin")],
                     successors=[ids["sansa"].id, ids["carol"].id], k=2, rules={**default_rules(), "posts_per_author_per_hour": 10000})
    ref = Thread(g)                                         # the reference run: events accepted in creation order
    events, seq, snaps = [], {n: 0 for n in ids}, [copy.deepcopy(ref)]
    removed_dave = closed = False
    stale_dave_view = None

    def emit(ev):
        events.append(ev)
        ref.accept(ev)
        snaps.append(copy.deepcopy(ref))

    for step in range(rnd.randint(8, 16)):
        r = rnd.random()
        view = rnd.choice(snaps[-4:])                       # authors act on slightly stale views: real concurrency
        if removed_dave and not closed and rnd.random() < 0.35:
            # carol, unaware of her removal, keeps writing against the pre-removal admin head
            ev = E.make_event(ids["carol"], thread=ref.id, kind="post", body={"text": f"carol after removal {step}"}, parents=[stale_dave_view.id],
                              seq=seq["carol"], admin_ref=stale_dave_view.head, ts=step)
            seq["carol"] += 1
            emit(ev)
            continue
        if r < 0.62 and not closed:
            who = rnd.choice(["arya", "sansa", "carol", "dave"] + ([] if not removed_dave else []))
            known = [i for i in view.order if view.events[i]["kind"] == "post"]
            reply = rnd.choice(known) if known and rnd.random() < .5 else None
            parents = sorted({reply} if reply else set(view.tips()[:2]) or {view.id})
            body = {"text": f"{who} {step}"}
            if reply:
                body["reply_to"] = reply
            if who not in view.state()["members"]:
                who = "arya"
            emit(E.make_event(ids[who], thread=ref.id, kind="post", body=body, parents=parents, seq=seq[who], admin_ref=view.head, ts=step))
            seq[who] += 1
        elif r < 0.72 and not removed_dave:
            head = ref.state()
            last = max([s for (a, s) in ref.by_author_seq if a == ids["carol"].id] or [-1])
            last = max(-1, last - rnd.choice([0, 0, 1]))                     # sometimes the owner had not seen dave's newest event
            pre_removal_view = copy.deepcopy(ref)
            ev = E.make_event(ids["arya"], thread=ref.id, kind="member_remove", parents=ref.tips(), seq=seq["arya"], admin_ref=ref.head, ts=step,
                              body={"prev_admin": ref.head, "owner_epoch": head["owner_epoch"], "agent": ids["carol"].id, "last_seq": last})
            seq["arya"] += 1
            emit(E.add_cosig(ev, ids["dave"]))
            removed_dave = True
            stale_dave_view = pre_removal_view
        elif r < 0.82 and not closed:
            ev = E.make_event(ids["arya"], thread=ref.id, kind="checkpoint", parents=ref.tips(), seq=seq["arya"], admin_ref=ref.head, ts=step,
                              body={"prev_admin": ref.head, "owner_epoch": ref.state()["owner_epoch"], "count": 0, "heads": ref.tips(), "epoch": ref.state()["epoch"]})
            seq["arya"] += 1
            emit(ev)
        elif r < 0.94 and ref.state()["owner"] == ids["arya"].id and not closed:
            # a competing takeover built on a stale admin head, acknowledged by the other voters
            base = rnd.choice(snaps[-5:])
            st = base.state()
            if st["owner"] == ids["arya"].id and not st["closed"]:
                who = rnd.choice(["sansa", "carol"])
                tk = E.make_event(ids[who], thread=ref.id, kind="owner_takeover", parents=[base.id], seq=seq[who], admin_ref=base.head, ts=step,
                                  body={"prev_admin": base.head, "owner_epoch": st["owner_epoch"] + 1, "last_checkpoint": st["last_cp"]})
                seq[who] += 1
                for c in ("sansa", "carol", "dave"):
                    if c != who and c in [ids_n for ids_n in ids if ids[ids_n].id in st["members"]]:
                        tk = E.add_cosig(tk, ids[c])
                emit(tk)
        elif r < 0.97 and not closed and ref.state()["owner"] == ids["arya"].id:
            cut = {a: max(s for (b, s) in ref.by_author_seq if b == a) for a in {a for (a, _) in ref.by_author_seq}}
            ev = E.make_event(ids["arya"], thread=ref.id, kind="close", parents=ref.tips(), seq=seq["arya"], admin_ref=ref.head, ts=step,
                              body={"prev_admin": ref.head, "owner_epoch": ref.state()["owner_epoch"], "cut": cut})
            seq["arya"] += 1
            emit(E.add_cosig(ev, ids["dave"]))
            closed = True
    ref.test_ids = ids                                      # so other tests can act as one of the agents
    return g, events, ref


def visible(t: Thread):
    import json
    return (frozenset(set(t.events) - t.void_ids), frozenset(t.void_ids), t.head, json.dumps(t.state(), sort_keys=True))


class Convergence(unittest.TestCase):
    def test_any_order_same_visible_thread(self):
        interesting = {"reorg": 0, "void": 0, "fork": 0, "closed": 0}
        for seed in range(90):
            g, events, ref = build_history(seed)
            outcomes = []
            for trial in range(6):
                order = events[:]
                random.Random(seed * 100 + trial).shuffle(order)
                m = Mirror(tempfile.mkdtemp(), rate_limit=False)
                m.ingest(g)
                for ev in order:
                    m.ingest(ev, live=False)
                for _ in range(3):                                 # re-offer: anything parked on a parent/admin head that has since arrived
                    for ev in order:
                        m.ingest(ev, live=False)
                t = m.thread(ref.id)
                outcomes.append((visible(t), t))
            first = outcomes[0][0]
            for n, (vis, t) in enumerate(outcomes):
                self.assertEqual(vis, first, f"seed {seed}: delivery order {n} diverged from order 0")
            t0 = outcomes[0][1]
            interesting["void"] += bool(t0.void_ids)
            interesting["fork"] += bool(t0.lost_admin)
            interesting["closed"] += t0.state()["closed"]
            interesting["reorg"] += t0.state()["owner_epoch"] > 0
        print("coverage of the generated histories:", interesting)
        self.assertGreater(interesting["void"], 3)
        self.assertGreater(interesting["fork"], 3)
        self.assertGreater(interesting["reorg"], 3)

    def test_incremental_accept_equals_bulk_derivation(self):
        """`accept` has a fast path for the common case; the full derivation is the reference. They must agree on every view."""
        def view(t):
            return (t.head, frozenset(t.events), frozenset(t.void_ids), frozenset(t.awaiting), frozenset(t.equiv), frozenset(t.lost_admin),
                    len(t.conflicts), tuple(t.order), tuple(sorted(t.status.items())), frozenset(t.states), t.owner_equivocated)
        for seed in range(80):
            g, events, ref = build_history(seed)
            order = events[:]
            random.Random(seed).shuffle(order)
            inc = Thread(g)
            for _ in range(3):
                for ev in order:
                    inc.accept(ev)
            bulk = Thread(g)
            bulk.add_many(order)
            # parked events differ by design (bulk keeps everything, incremental too): compare resolved views only
            self.assertEqual(view(inc), view(bulk), f"seed {seed}: incremental and bulk derivations disagree")

    def test_replay_from_disk_matches_live_state(self):
        for seed in range(15):
            g, events, ref = build_history(seed)
            root = tempfile.mkdtemp()
            m = Mirror(root, rate_limit=False)
            m.ingest(g)
            order = events[:]
            random.Random(seed).shuffle(order)
            for _ in range(3):
                for ev in order:
                    m.ingest(ev, live=False)
            t = m.thread(ref.id)
            t2 = Mirror(root, rate_limit=False).thread(ref.id)
            self.assertEqual(visible(t), visible(t2), f"seed {seed}: reload differs")
            self.assertEqual(t.void_ids, t2.void_ids)


if __name__ == "__main__":
    unittest.main()
