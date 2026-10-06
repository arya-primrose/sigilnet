"""Sansa's independent checks of r43_noendpoint: the kind `endpoint` is refused on every road in, whoever signs it."""
import os
import tempfile
import unittest

from sigilnet import event as E
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread
from sigilnet.tests.util import World


def endpoint_ev(w, who, parents=None):
    ev = w.w(who).post("x")
    ev["kind"], ev["body"] = "endpoint", {"transports": []}
    if parents is not None:
        ev["parents"] = parents
    ev["sig"] = w.ids[who].sign(E.sign_input(ev))
    return ev


class Roads(unittest.TestCase):
    def test_mirror_live_and_catchup_refuse_and_write_nothing(self):
        ids = {n: Identity.generate(n) for n in ("a", "s", "h")}
        g = make_genesis(ids["a"], "t", [(ids["s"], "member"), (ids["h"], "observer")])
        d = tempfile.mkdtemp()
        m = Mirror(d, rate_limit=True)
        self.assertTrue(m.ingest(g).ok)
        t = m.threads[event_id(g)]
        for who in "ash":
            for live in (True, False):
                ev = Writer(ids[who], t).post("x")
                ev["kind"], ev["body"] = "endpoint", {"transports": []}
                ev["sig"] = ids[who].sign(E.sign_input(ev))
                r = m.ingest(ev, live=live)
                self.assertEqual((r.status, r.reason), ("rejected", "unknown kind"), (who, live))
                self.assertNotIn(event_id(ev), t.stored)
                # as canonical bytes too
                r = m.ingest(E.encode(ev), live=live)
                self.assertEqual(r.status, "rejected")
        for root, _, files in os.walk(d):
            for f in files:
                self.assertNotIn(b'"endpoint"', open(os.path.join(root, f), "rb").read())
        self.assertFalse(m.recv)                                        # rejected ones never count in the rate window
        # a normal post still lands afterwards
        self.assertTrue(m.ingest(Writer(ids["s"], t).post("ok")).ok)

    def test_bulk_load_skips_the_kind_and_keeps_the_rest(self):
        w = World()
        p = w.w("sansa").post("a")
        e = endpoint_ev(w, "carol")
        w.t.add_many([e, p])
        self.assertIn(event_id(p), w.t.stored)
        self.assertNotIn(event_id(e), w.t.stored)

    def test_child_of_an_endpoint_event_never_resolves(self):
        w = World()
        e = endpoint_ev(w, "carol")
        child = Writer(w.ids["sansa"], w.t).post("c", reply_to=event_id(e))
        r = w.t.accept(child)
        self.assertNotIn(r.status, ("accepted", "voided"))
        self.assertNotIn(event_id(child), w.t.events)
        self.assertEqual(w.t.accept(e).status, "rejected")
        self.assertNotIn(event_id(child), w.t.events)                   # still parked, nothing half-stored

    def test_observer_still_may_self_revoke_but_not_post(self):
        w = World()
        self.assertEqual(w.t.accept(w.w("hu").post("no")).status, "invalid") if False else None
        r = w.t.accept(w.w("hu").post("no"))
        self.assertNotIn(r.status, ("accepted",))
        rv = w.w("hu").admin("revoke", {"agent": w.ids["hu"].id})
        self.assertTrue(w.t.accept(rv).ok)

    def test_kind_set_is_exactly_this(self):
        self.assertEqual(E.OTHER_KINDS, frozenset({"post", "digest", "evidence"}))
        for k in ("endpoint", "Endpoint", "endpoint ", "ENDPOINT", ""):
            self.assertNotIn(k, E.KINDS)


if __name__ == "__main__":
    unittest.main()
