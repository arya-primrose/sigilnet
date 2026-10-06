"""Signed-but-hostile bodies: nothing may raise out of Thread.accept / Mirror.ingest, and no invariant may break."""
import copy
import random
import tempfile
import unittest

from sigilnet import event as E
from sigilnet.event import event_id
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread

from .gen import check_invariants
from .test_authority import bodies, raw_admin
from .util2 import Net

JUNK = [None, True, False, 0, -1, 1, 2 ** 31, 2 ** 70, -2 ** 70, "", "x", "a" * 40, "0" * 32, "f" * 64, [], [1], ["0" * 32], {}, {"a": 1},
        [[[[[]]]]], {"a": {"b": {"c": []}}}, "\u0000", "é", "é", "‮", ["a"] * 40, list(range(300))]


def mutate(rnd, body, ids):
    b = copy.deepcopy(body)
    for _ in range(rnd.randint(1, 3)):
        r = rnd.random()
        keys = list(b)
        if r < 0.5 and keys:
            b[rnd.choice(keys)] = rnd.choice(JUNK + ids)
        elif r < 0.7 and keys:
            del b[rnd.choice(keys)]
        else:
            b[rnd.choice(["extra", "guest", "admits", "cut", "rules", "heads", "successors", "role", "name"])] = rnd.choice(JUNK + ids)
    return b


class SignedJunk(unittest.TestCase):
    def test_hostile_bodies_never_raise_and_never_break_invariants(self):
        rnd = random.Random(1234)
        net = Net(roles={"sansa": "admin", "carol": "member", "dave": "member", "hu": "observer"}, successors=("carol", "dave"), k=2, visibility="public")
        root = tempfile.mkdtemp()
        m = Mirror(root, rate_limit=False)
        m.ingest(net.genesis)
        bare = Thread(net.genesis)
        ids = [i.id for i in net.ids.values()] + [net.tid]
        kinds = {**bodies(net, net.ref), "post": {"text": "t", "reply_to": net.tid}, "digest": {"text": "d", "covers": []},
                 "evidence": {"a": {}, "b": {}}}
        statuses = {}
        for n in range(1500):
            kind = rnd.choice(list(kinds))
            who = rnd.choice(["arya", "sansa", "carol", "dave", "hu", "erin", "arya", "sansa"])
            view = bare
            st = view.state()
            body = mutate(rnd, kinds[kind], ids) if rnd.random() < 0.9 else dict(kinds[kind])
            if kind not in ("post", "digest", "evidence"):
                body = {"prev_admin": rnd.choice([view.head, view.head, view.head, net.tid]), "owner_epoch": rnd.choice([st["owner_epoch"], st["owner_epoch"], 1, 2]), **body}
            parents = [net.tid] if rnd.random() < 0.9 else [net.tid, rnd.choice(list(view.events))]
            try:
                ev = E.make_event(net.ids[who], thread=net.tid, kind=kind, body=body, parents=parents, seq=rnd.randint(0, 6),
                                  admin_ref=view.head if rnd.random() < 0.9 else net.tid, ts=n)
                if kind in ("owner_takeover", "owner_transfer", "member_add", "rules_update", "member_remove") and rnd.random() < 0.7:
                    for c in rnd.sample(["arya", "sansa", "carol", "dave"], 2):
                        if c != who:
                            ev = E.add_cosig(ev, net.ids[c])
            except Exception:
                continue                                   # the builder itself refused (not representable): not the library's problem
            r1 = bare.accept(copy.deepcopy(ev))
            statuses[r1.status] = statuses.get(r1.status, 0) + 1
            try:
                m.ingest(ev)
            except BaseException as e:                     # noqa: BLE001
                self.fail(f"Mirror.ingest raised {type(e).__name__}: {e} on {kind} {body}")
            if r1.status in ("accepted", "voided"):
                p = check_invariants(bare)
                self.assertEqual(p, [], f"after {kind}: {p}")
        print("junk fuzz statuses:", statuses)
        self.assertGreater(statuses.get("accepted", 0), 10)       # only a floor that proves the fuzz is not vacuous (seeded: 18 now; it was above 20 before the `endpoint` kind, which the fuzz could get accepted easily, was removed)
        self.assertEqual(check_invariants(m.thread(net.tid)), [])
        Mirror(root, rate_limit=False)                    # reload must not raise either


if __name__ == "__main__":
    unittest.main()
