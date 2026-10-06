"""Own history generator (different from tests/test_convergence.py): three mirrors hold arbitrary subsets, pull each other in random order,
and must end with the same visible thread. Also: sync must not get stuck on ids named only by admin events or checkpoints."""
import copy
import random
import tempfile
import unittest

from sigilnet import event as E
from sigilnet import sync as S
from sigilnet.build import make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread

from .h3 import BIG, mirror_with, vis


def history(seed, n_ops=22):
    rnd = random.Random(seed * 7919 + 13)
    ids = {n: Identity.generate(n) for n in ("o", "a", "b", "c", "obs")}
    g = make_genesis(ids["o"], "gen3", [(ids["a"], "member"), (ids["b"], "member"), (ids["c"], "admin"), (ids["obs"], "observer")],
                     successors=[], k=1, rules=BIG)
    ref = Thread(g)
    snaps, evs, seq = [copy.deepcopy(ref)], [], {n: 0 for n in ids}
    live_removed = set()

    def push(ev):
        r = ref.accept(ev)
        evs.append(ev)
        snaps.append(copy.deepcopy(ref))
        return r

    for step in range(n_ops):
        roll = rnd.random()
        view = rnd.choice(snaps[-3:])
        if roll < 0.7:
            who = rnd.choice(["o", "a", "b", "c"])
            known = [i for i in view.order if view.events[i]["kind"] == "post"]
            body = {"text": f"{who}{step}"}
            parents = sorted(set(view.tips()[:2])) or [view.id]
            if known and rnd.random() < 0.5:
                rt = rnd.choice(known)
                body["reply_to"] = rt
                parents = sorted(set(parents) | {rt})
            push(E.make_event(ids[who], thread=ref.id, kind="post", body=body, parents=parents, seq=seq[who], admin_ref=view.head, ts=step))
            seq[who] += 1
        elif roll < 0.8 and "b" not in live_removed:
            last = max([s for (a, s) in ref.by_author_seq if a == ids["b"].id] or [-1])
            body = {"prev_admin": ref.head, "owner_epoch": ref.state()["owner_epoch"], "agent": ids["b"].id, "last_seq": max(-1, last - rnd.choice([0, 0, 1]))}
            push(E.make_event(ids["o"], thread=ref.id, kind="member_remove", parents=ref.tips(), seq=seq["o"], admin_ref=ref.head, ts=step, body=body))
            seq["o"] += 1
            live_removed.add("b")
        elif roll < 0.9:
            body = {"prev_admin": ref.head, "owner_epoch": ref.state()["owner_epoch"], "count": 0, "heads": ref.tips(), "epoch": ref.state()["epoch"]}
            push(E.make_event(ids["o"], thread=ref.id, kind="checkpoint", parents=ref.tips(), seq=seq["o"], admin_ref=ref.head, ts=step, body=body))
            seq["o"] += 1
        else:
            who = "o"
            body = {"prev_admin": ref.head, "owner_epoch": ref.state()["owner_epoch"], "agent": ids["obs"].id, "name": "obs", "role": "observer",
                    "sign": ids["obs"].sign_pub, "kex": ids["obs"].kex_pub}
            r = E.make_event(ids["o"], thread=ref.id, kind="member_add", parents=ref.tips(), seq=seq["o"], admin_ref=ref.head, ts=step, body=body)
            if ref.accept(r).ok:
                evs.append(r); snaps.append(copy.deepcopy(ref)); seq["o"] += 1
    return g, evs, ref, ids


def transports(mirrors):
    return {k: S.Loopback(S.SyncServer(m)) for k, m in mirrors.items()}


class ThreeWay(unittest.TestCase):
    def run_seed(self, seed):
        g, evs, ref, ids = history(seed)
        rnd = random.Random(seed)
        subsets = [[e for e in evs if rnd.random() < p] for p in (0.5, 0.5, 0.5)]
        mirrors = {"m0": mirror_with(g, subsets[0]), "m1": mirror_with(g, subsets[1]), "m2": mirror_with(g, subsets[2])}
        union_ids = set().union(*[{event_id(e) for e in s} for s in subsets])
        union = [e for e in evs if event_id(e) in union_ids]
        want = mirror_with(g, union)
        me = ids["a"]
        for rounds in range(1, 9):
            order = [(x, y) for x in mirrors for y in mirrors if x != y]
            rnd.shuffle(order)
            for x, y in order:
                r = S.pull(mirrors[x], ref.id, S.Loopback(S.SyncServer(mirrors[y])), me)
                self.assertTrue(r["ok"], (seed, dict(r)))
            if all(vis(m, ref.id) == vis(want, ref.id) for m in mirrors.values()):
                break
        self.assertLessEqual(rounds, 6, f"seed {seed}: needed {rounds} all-pairs rounds")
        for k, m in mirrors.items():
            self.assertEqual(vis(m, ref.id), vis(want, ref.id), f"seed {seed}: {k} differs from the union of all events")

    def test_seeds_0_to_39(self):
        for seed in range(40):
            self.run_seed(seed)

    def test_seeds_40_to_79_with_a_removed_member_that_keeps_posting(self):
        for seed in range(40, 80):
            self.run_seed(seed)


class Stuck(unittest.TestCase):
    def test_ids_named_only_by_a_checkpoint_head_are_fetched(self):
        g, evs, ref, ids = history(5, n_ops=30)
        full = mirror_with(g, evs)
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        S.pull(b, ref.id, S.Loopback(S.SyncServer(full)), ids["a"])
        self.assertEqual(vis(b, ref.id), vis(full, ref.id))
        self.assertEqual(b.missing(ref.id), [])

    def test_every_resolved_event_of_the_server_reaches_a_fresh_mirror_when_history_is_wide(self):
        for seed in range(15):
            g, evs, ref, ids = history(seed, n_ops=40)
            full = mirror_with(g, evs)
            b = Mirror(tempfile.mkdtemp(), rate_limit=False)
            r = S.pull(b, ref.id, S.Loopback(S.SyncServer(full)), ids["a"])
            self.assertTrue(r["ok"], (seed, dict(r)))
            self.assertEqual(vis(b, ref.id), vis(full, ref.id), seed)
            self.assertEqual(b.thread(ref.id).resolved_ids(), full.thread(ref.id).resolved_ids(), seed)

    def test_pull_is_idempotent_and_a_second_pull_fetches_nothing(self):
        g, evs, ref, ids = history(3, n_ops=30)
        full = mirror_with(g, evs)
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        S.pull(b, ref.id, S.Loopback(S.SyncServer(full)), ids["a"])
        r = S.pull(b, ref.id, S.Loopback(S.SyncServer(full)), ids["a"])
        self.assertEqual((r["ok"], r["fetched"]), (True, 0))

    def test_removed_member_is_refused_but_an_observer_can_pull_everything(self):
        g, evs, ref, ids = history(11, n_ops=30)
        full = mirror_with(g, evs)
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, ref.id, S.Loopback(S.SyncServer(full)), ids["obs"])
        self.assertTrue(r["ok"], dict(r))
        self.assertEqual(vis(b, ref.id), vis(full, ref.id))


if __name__ == "__main__":
    unittest.main()
