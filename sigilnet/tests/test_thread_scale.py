"""Cost of an admin event on a long thread (DESIGN_retention.md R0): `Thread._accept` used to call `resolved_ids()` (a set of every event) once PER ARRIVAL,
so one member_add on a 19000-event thread took 22 s. The test counts calls (deterministic), it does not time anything."""
import unittest

from sigilnet import event as E
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.thread import Thread

from .util import World


def long_thread(n):
    w = World()
    names = ["arya", "sansa", "carol"]
    seq = {x: 0 for x in names}
    evs, prev = [], list(w.t.tips())
    for i in range(n):
        who = names[i % 3]
        ev = E.make_event(w.ids[who], thread=w.t.id, kind="post", body={"text": "m%d" % i}, parents=prev, seq=seq[who], admin_ref=w.t.head, ts=1_700_000_000 + i)
        seq[who] += 1
        evs.append(ev)
        prev = [event_id(ev)]
    t = Thread(w.genesis)
    t.add_many(evs)
    return w, t, evs


class AdminCostIsLinear(unittest.TestCase):
    def count_calls(self, t, fn):
        calls, orig = [0], Thread.resolved_ids

        def counting(self):
            calls[0] += 1
            return orig(self)
        Thread.resolved_ids = counting
        try:
            return fn(), calls[0]
        finally:
            Thread.resolved_ids = orig

    def test_a_member_add_calls_resolved_ids_a_constant_number_of_times(self):
        for n in (200, 800):
            w, t, evs = long_thread(n)
            self.assertEqual(len(t.resolved_ids()), n + 1)                 # every event resolved (plus the genesis)
            adm = Writer(w.ids["arya"], t).add_member(w.ids["eve"], "member")
            r, calls = self.count_calls(t, lambda: t.accept(adm))
            self.assertTrue(r.ok, (r.status, r.reason))
            self.assertLessEqual(calls, 6, f"n={n}: resolved_ids() called {calls} times for one admin event (it was one per event)")
            self.assertIn(w.ids["eve"].id, t.state()["members"])

    def test_the_result_is_the_same_as_before_the_hoist(self):
        w, t, evs = long_thread(300)
        adm = Writer(w.ids["arya"], t).add_member(w.ids["eve"], "member")
        r = t.accept(adm)
        self.assertEqual(r.accepted, [event_id(adm)])                      # the admin event is the (only) one newly resolved by this arrival
        late = E.make_event(w.ids["carol"], thread=t.id, kind="post", body={"text": "late"}, parents=[event_id(evs[100])], seq=10 ** 6, admin_ref=t.head, ts=1_700_000_100)
        r2 = t.accept(late)
        self.assertEqual(r2.accepted, [event_id(late)])


if __name__ == "__main__":
    unittest.main()
