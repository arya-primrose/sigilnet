"""Chains of forks three deep: every delivery order of one fixed event set must give one answer."""
import itertools
import random
import unittest

from sigilnet import event as E
from sigilnet.event import event_id

from .test_scenarios import owner_cp, takeover
from .util2 import Net, deliver, diff, fingerprint


class ThreeDeep(unittest.TestCase):
    def build(self):
        net = Net(successors=("carol", "dave"))
        g = net.snap()
        c1 = owner_cp(net, g, 1, seq=1)
        v1 = net.snap(); v1.accept(c1)
        c2 = owner_cp(net, v1, 2, seq=2)
        v2 = net.snap(); v2.accept(c1); v2.accept(c2)
        c3 = owner_cp(net, v2, 3, seq=3)
        t1 = takeover(net, "dave", g, ["sansa", "carol"], ts=4)              # later successor, on the genesis
        t2 = takeover(net, "carol", v1, ["sansa", "dave"], ts=5)             # earlier successor, on c1
        t3 = takeover(net, "dave", v2, ["sansa", "carol"], ts=6, seq=2)             # on c2
        vt = net.snap(); vt.accept(t1)
        after = net.w("dave", vt).admin("rules_update", {"rules": {"checkpoint_every": 9}})   # new owner's event on t1
        posts = []
        for nm, ref in (("carol", c3), ("sansa", t2), ("sansa", t1), ("carol", c2), ("dave", t3), ("sansa", after)):
            posts.append(E.make_event(net.ids[nm], thread=net.tid, kind="post", body={"text": f"{nm} cites {event_id(ref)[:4]}"}, parents=[net.tid],
                                      seq=len(posts) * 2 + (0 if nm == "sansa" else 20 + len(posts)), admin_ref=event_id(ref), ts=10))
        # unique seq per author
        seen, fixed = {}, []
        for p in posts:
            n = seen.get(p["author"], 10); seen[p["author"]] = n + 1
            q = E.make_event(net.ids[net.name(p["author"])], thread=net.tid, kind="post", body=p["body"], parents=p["parents"], seq=n, admin_ref=p["admin_ref"], ts=10)
            fixed.append(q)
        return net, [c1, c2, c3, t1, t2, t3, after] + fixed

    def test_many_orders_one_answer(self):
        net, evs = self.build()
        base = fingerprint(deliver(net.genesis, evs))
        self.assertTrue(base["lost"], "scenario must contain lost branches")
        rnd = random.Random(5)
        for n in range(400):
            order = evs[:]; rnd.shuffle(order)
            d = diff(base, fingerprint(deliver(net.genesis, order)))
            self.assertEqual(d, {}, f"order {n}: {sorted(d)}")

    def test_winner_is_the_earliest_successor_on_the_deepest_common_prev(self):
        net, evs = self.build()
        t = deliver(net.genesis, evs)
        # t1 (later successor, on genesis), t2 (earlier successor, on c1), t3 (later successor, on c2): the fork at the genesis is
        # c1 vs t1, and a takeover beats the owner's checkpoint, so t1 wins there; c1/c2/c3 and everything after are lost
        self.assertEqual(t.state()["owner"], net.ids["dave"].id)
        self.assertIn(event_id(evs[0]), t.lost_admin)


if __name__ == "__main__":
    unittest.main()
