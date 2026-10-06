"""Own generators/fuzzers for the determinism claim: same SET of events, any delivery (order, duplicates, two Mirror handles, restarts)."""
import random
import tempfile
import unittest

from sigilnet.event import event_id
from sigilnet.mirror import Mirror

from .gen import build, check_invariants
from .util2 import deliver, diff, fingerprint

SEEDS = range(int(__import__("os").environ.get("ADV2_SEEDS", "80")))


def cover(nets):
    c = {"void": 0, "lost": 0, "closed": 0, "guest_live": 0, "epoch": 0, "removed": 0, "awaiting": 0}
    for net in nets:
        t = deliver(net.genesis, net.events)
        c["void"] += bool(t.void_ids); c["lost"] += bool(t.lost_admin); c["closed"] += t.state()["closed"]
        c["epoch"] += t.state()["owner_epoch"] > 0; c["removed"] += bool(t.state()["removed"]); c["awaiting"] += bool(t.awaiting)
        c["guest_live"] += any(m["role"] == "guest" for m in t.state()["members"].values())
    return c


class FuzzBase:
    GUESTS = False

    def test_generator_is_interesting(self):
        c = cover([build(s, guests_on=self.GUESTS) for s in SEEDS])
        print("generator coverage over", len(SEEDS), "histories:", c)
        for key in ("void", "lost", "epoch", "removed") + (("guest_live",) if self.GUESTS else ()):
            self.assertGreater(c[key], 3, key)

    def test_bare_thread_any_order_with_duplicates(self):
        bad = []
        for seed in SEEDS:
            net = build(seed, guests_on=self.GUESTS)
            base = fingerprint(deliver(net.genesis, net.events))
            for trial in range(6):
                rnd = random.Random(seed * 31 + trial)
                order = net.events[:]
                rnd.shuffle(order)
                order += [rnd.choice(order) for _ in range(rnd.randint(0, 6))]
                rnd.shuffle(order)
                t = deliver(net.genesis, order, passes=200)
                d = diff(base, fingerprint(t))
                if d:
                    bad.append((seed, trial, sorted(d)))
                    break
        self.assertFalse(bad, f"{len(bad)}/{len(SEEDS)} histories diverge: {bad[:8]}")

    def test_structural_invariants_in_every_delivery(self):
        bad = []
        for seed in SEEDS:
            net = build(seed, guests_on=self.GUESTS)
            for trial in range(3):
                order = net.events[:]
                random.Random(seed + trial).shuffle(order)
                t = deliver(net.genesis, order, passes=200)
                p = check_invariants(t)
                if p:
                    bad.append((seed, trial, p))
                    break
        self.assertFalse(bad, f"{bad[:5]}")

    def test_mirror_restarts_do_not_change_the_visible_thread(self):
        bad = []
        for seed in SEEDS:
            net = build(seed, guests_on=self.GUESTS)
            rnd = random.Random(seed)
            order = net.events[:]
            rnd.shuffle(order)
            root = tempfile.mkdtemp()
            m = Mirror(root, rate_limit=False)
            m.ingest(net.genesis)
            for n, ev in enumerate(order):
                m.ingest(ev, live=False)
                if rnd.random() < 0.25:
                    before = fingerprint(m.thread(net.tid))
                    m = Mirror(root, rate_limit=False)
                    after = fingerprint(m.thread(net.tid))
                    d = diff(before, after)
                    if d:
                        bad.append((seed, n, sorted(d)))
                        break
            if bad and bad[-1][0] == seed:
                continue
            for _ in range(3):
                for ev in order:
                    m.ingest(ev, live=False)
            d = diff(fingerprint(deliver(net.genesis, net.events)), fingerprint(m.thread(net.tid)))
            if d:
                bad.append((seed, "final", sorted(d)))
        self.assertFalse(bad, f"{len(bad)} histories: {bad[:8]}")

    def test_two_handles_one_directory_duplicates_and_reload(self):
        bad = []
        for seed in SEEDS:
            net = build(seed, guests_on=self.GUESTS)
            rnd = random.Random(seed + 7)
            order = net.events[:] + [rnd.choice(net.events) for _ in range(5)]
            rnd.shuffle(order)
            root = tempfile.mkdtemp()
            hs = [Mirror(root, rate_limit=False), Mirror(root, rate_limit=False)]
            hs[0].ingest(net.genesis)
            for ev in order:
                rnd.choice(hs).ingest(ev, live=False)
            for _ in range(2):
                for ev in order:
                    for h in hs:
                        h.ingest(ev, live=False)
            base = fingerprint(deliver(net.genesis, net.events))
            for name, h in (("A", hs[0]), ("B", hs[1]), ("reload", Mirror(root, rate_limit=False))):
                d = diff(base, fingerprint(h.thread(net.tid)))
                if d:
                    bad.append((seed, name, sorted(d)))
                    break
        self.assertFalse(bad, f"{len(bad)} histories: {bad[:8]}")

    def test_no_exception_from_ingest_on_generated_events(self):
        for seed in SEEDS:
            net = build(seed, guests_on=self.GUESTS)
            m = Mirror(tempfile.mkdtemp(), rate_limit=False)
            order = net.events[:] + [net.genesis]
            random.Random(seed).shuffle(order)
            for ev in order * 2:
                m.ingest(ev)
                m.ingest(ev, live=False)


class Fuzz(FuzzBase, unittest.TestCase):
    """No guests: admin chains, removals, transfers, takeovers, close, stale writers.
    # BUG: the restart / two-handle tests fail because of the reload bugs in test_scenarios (winner of a same-author reorg marked lost on
    # load; lost_admin and voided events citing lost branches are not rebuilt). Bare-thread convergence passes except for the known_keys bug."""


class FuzzWithGuests(FuzzBase, unittest.TestCase):
    """Same, plus guest requests admitted mid-history (see the GuestAdmission scenarios).
    # BUG: fails because of the guest-admission bugs in test_scenarios.GuestAdmission and the reload bugs."""
    GUESTS = True


if __name__ == "__main__":
    unittest.main()
