"""Helpers for the round-2 adversarial tests (independent of tests/ and tests_adv/ generators)."""
import copy
import json
import random
import tempfile

from sigilnet import event as E
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread, default_rules

NAMES = ("arya", "sansa", "carol", "dave", "erin", "hu", "g1", "g2", "g3", "x")


def idents():
    return {n: Identity.generate(n) for n in NAMES}


def rules(**kw):
    return {**default_rules(), "posts_per_author_per_hour": 10000, **kw}


class Net:
    """A reference thread plus helpers that build events from (possibly stale) snapshots of it."""

    def __init__(self, roles=None, successors=("carol", "dave"), k=1, visibility="private", rule_kw=None):
        self.ids = idents()
        roles = dict(roles or {"sansa": "member", "carol": "member", "dave": "member"})
        # a thread with successors needs k >= 2 (spec 0.9): give it an admin (erin) who co-signs owner admin events by default
        self.auto = bool(successors) and k < 2
        self.cosigner = None
        if self.auto:
            k = 2
            admin = next((n for n, r in roles.items() if r == "admin"), None)
            if admin is None:
                roles["erin"] = admin = "erin"
                roles["erin"] = "admin"
            self.cosigner = admin
        others = [(self.ids[n], r) for n, r in roles.items()]
        self.genesis = make_genesis(self.ids["arya"], "adv2", others, successors=[self.ids[s].id for s in successors], k=k,
                                    visibility=visibility, rules=rules(**(rule_kw or {})))
        self.ref = Thread(self.genesis)
        self.tid = self.ref.id
        self.events = []

    def name(self, agent):
        return next(n for n, i in self.ids.items() if i.id == agent)

    def w(self, who, view=None):
        return Writer(self.ids[who], view or self.ref, cosigners=[self.ids[self.cosigner]] if self.auto else ())

    def take(self, ev, view=None):
        """Feed an event to the reference thread and remember it."""
        self.events.append(ev)
        self.ref.accept(ev)
        return event_id(ev)

    def snap(self):
        return copy.deepcopy(self.ref)


def fingerprint(t: Thread):
    return {"live": frozenset(set(t.events) - t.void_ids), "void": frozenset(t.void_ids), "lost": frozenset(t.lost_admin),
            "head": t.head, "state": json.dumps(t.state(), sort_keys=True), "awaiting": frozenset(t.awaiting)}


def diff(a, b):
    return {k: (a[k], b[k]) for k in a if a[k] != b[k]}


def deliver(genesis, events, *, passes=200, clock=None):
    """Feed events to a bare Thread in the given order, re-offering everything until nothing changes (what a mirror's pending buffer does)."""
    t = Thread(genesis) if clock is None else Thread(genesis, clock=clock)
    for _ in range(passes):
        n = (len(t.events), len(t.lost_admin), len(t.awaiting), len(t.void_ids), t.head)
        for ev in events:
            t.accept(ev)
        if (len(t.events), len(t.lost_admin), len(t.awaiting), len(t.void_ids), t.head) == n:
            break
    return t


def mirror_with(genesis, events, root=None, live=False, passes=3, **kw):
    m = Mirror(root or tempfile.mkdtemp(), rate_limit=False, **kw)
    m.ingest(genesis)
    for _ in range(passes):
        for ev in events:
            m.ingest(ev, live=live)
    return m


def grind(make, below_id, tries=4000):
    """make(ts) -> event; find one whose id is lower than `below_id` (event ids are hashes, so this is cheap)."""
    best = None
    for ts in range(1, tries):
        ev = make(ts)
        if event_id(ev) < below_id:
            return ev
        best = best or ev
    raise AssertionError("could not grind a lower id")
