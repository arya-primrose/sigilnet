"""Thread format 2 (DESIGN_versioning_stage3.md): format 1 plus exactly two extensions, `x-` event kinds and the `x` body key; the format of a thread is the `v` of its genesis and every
event must carry it. Thread and mirror level (no nodes)."""
import copy
import random
import tempfile
import unittest

from sigilnet import canon
from sigilnet import event as E
from sigilnet import thread as T
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread

NAMES = ("arya", "sansa", "carol", "hu", "dave")


def build(fmt=2, rules=None):
    ids = {n: Identity.generate(n) for n in NAMES}
    g = make_genesis(ids["arya"], "format test", [(ids["sansa"], "member"), (ids["carol"], "member"), (ids["hu"], "observer")], fmt=fmt, rules=rules)
    return ids, g, Thread(g)


def resign(ident, ev, **changes):
    ev = {k: v for k, v in ev.items() if k not in ("sig", "cosigs")}
    ev.update(changes)
    ev["sig"] = ident.sign(E.sign_input(ev))
    return ev


def derived(t):
    st = t.state()
    return (t.head, st["owner"], sorted(st["members"]), dict(st["rules"]), st["closed"], st["epoch"], sorted(t.void_ids), list(t.order))


class Basics(unittest.TestCase):
    def test_the_thread_format_is_the_genesis_v(self):
        for fmt in (1, 2):
            ids, g, t = build(fmt)
            self.assertEqual(g["v"], fmt)
            self.assertEqual(t.format, fmt)
            self.assertEqual(Writer(ids["sansa"], t).post("x")["v"], fmt)

    def test_genesis_formats_differ_in_id_and_not_in_anything_else(self):
        ids = {n: Identity.generate(n) for n in NAMES}
        a = make_genesis(ids["arya"], "t", [(ids["sansa"], "member")], ts=5, fmt=1)
        b = make_genesis(ids["arya"], "t", [(ids["sansa"], "member")], ts=5, fmt=2)
        self.assertEqual(a["body"], b["body"])
        self.assertNotEqual(event_id(a), event_id(b))
        self.assertEqual(set(a), set(b))

    def test_default_builders_still_make_format_1(self):
        ids = {n: Identity.generate(n) for n in NAMES}
        self.assertEqual(make_genesis(ids["arya"], "t", [])["v"], 1)
        self.assertEqual(E.make_event(ids["arya"], thread="", kind="genesis", body={}, parents=[], seq=0, admin_ref="")["v"], 1)

    def test_unsupported_formats_are_refused_at_the_structure_level(self):
        ids, g, t = build(2)
        p = Writer(ids["sansa"], t).post("x")
        for bad in (0, 3, -1, True, "2", None):
            self.assertRaises(E.EventError, E.check_structure, resign(ids["sansa"], p, v=bad))
        self.assertRaises(E.EventError, E.check_structure, {**p, "v": 1.0})            # (a float cannot be signed or canonical; the structure check refuses it on its own)
        self.assertRaises(E.EventError, E.check_structure, {**p, "v": 2.0})


class Public(unittest.TestCase):
    def test_a_public_thread_must_be_format_1(self):
        ids = {n: Identity.generate(n) for n in NAMES}
        g1 = make_genesis(ids["arya"], "p", [(ids["sansa"], "member")], visibility="public", fmt=1)
        self.assertEqual(Thread(g1).format, 1)
        g2 = make_genesis(ids["arya"], "p", [(ids["sansa"], "member")], visibility="public", fmt=2)
        self.assertRaises(E.EventError, Thread, g2)
        with tempfile.TemporaryDirectory() as d:
            m = Mirror(d)
            r = m.ingest(g2)
            self.assertEqual((r.status, m.threads), ("rejected", {}))
            self.assertIn("public thread must be format 1", r.reason)
        make_genesis(ids["arya"], "p", [(ids["sansa"], "member")], visibility="private", fmt=2)       # private format 2 stays fine
        Thread(make_genesis(ids["arya"], "p", [(ids["sansa"], "member")], visibility="private", fmt=2))


class ExtKinds(unittest.TestCase):
    def setUp(self):
        self.ids, self.g, self.t = build(2)
        self.w = lambda n: Writer(self.ids[n], self.t)

    def test_an_x_kind_is_stored_and_changes_nothing_that_matters(self):
        before = derived(self.t)
        x = self.w("sansa").ext("reaction.1", {"to": self.t.id, "emoji": "ok"})
        r = self.t.accept(x)
        self.assertTrue(r.ok, (r.status, r.reason))
        self.assertIn(event_id(x), self.t.stored)
        after = derived(self.t)
        self.assertEqual(before[:7], after[:7])                                     # head, owner, members, rules, closed, epoch, void: untouched
        self.assertEqual(after[7], before[7] + [event_id(x)])                       # it IS part of the reading order, nothing else is

    def test_an_x_kind_is_a_plain_leaf_with_no_admin_effect_even_with_admin_looking_fields(self):
        w = self.w("arya")
        x = w.ext("fake-admin", {"prev_admin": self.t.head, "agent": self.ids["dave"].id, "role": "owner", "owner_epoch": 0})
        self.assertTrue(self.t.accept(x).ok)
        st = self.t.state()
        self.assertNotIn(self.ids["dave"].id, st["members"])
        self.assertEqual(st["owner"], self.ids["arya"].id)
        self.assertEqual(self.t.head, self.t.id)                                    # not an admin event: the admin chain did not move

    def test_x_kind_in_a_format_1_thread_is_refused_as_before(self):
        ids, g, t = build(1)
        p = Writer(ids["sansa"], t).post("x")
        for kind in ("x-reaction.1", "x-a"):
            ev = resign(ids["sansa"], p, kind=kind)
            self.assertRaises(E.EventError, E.check_structure, ev)
            self.assertEqual(t.accept(ev).status, "rejected")

    def test_other_unknown_kinds_are_refused_in_format_2(self):
        for kind in ("reaction", "X-reaction", "xreaction", "x_reaction", "member_add2", "x-", "x-A", "x- a", "x-" + "a" * 49, "x-é", "x-a\n"):
            ev = resign(self.ids["sansa"], self.w("sansa").post("x"), kind=kind)
            self.assertEqual(self.t.accept(ev).status, "rejected", kind)

    def test_kind_name_boundaries(self):
        for kind in ("x-a", "x-0", "x-" + "a" * 48, "x-reaction.1", "x-a_b-c.d"):
            ev = resign(self.ids["sansa"], self.w("sansa").post("x"), kind=kind, body={"n": kind})
            self.assertTrue(self.t.accept(ev).ok, kind)

    def test_who_may_write_an_x_kind(self):
        for who, ok in (("arya", True), ("sansa", True), ("carol", True), ("hu", False), ("dave", False)):
            self.assertEqual(self.t.accept(Writer(self.ids[who], self.t).ext("t", {"a": who})).ok, ok, who)

    def test_an_x_kind_body_is_free_form_even_a_key_named_x(self):
        self.assertTrue(self.t.accept(self.w("sansa").ext("t", {"x": 5, "text": "any", "kind": "post"})).ok)

    def test_an_x_kind_never_takes_cosigs(self):
        x = E.add_cosig(self.w("sansa").ext("t", {}), self.ids["carol"])
        self.assertEqual(self.t.accept(x).status, "rejected")

    def test_an_x_kind_is_charged_to_the_size_cap(self):
        big = self.w("sansa").ext("t", {"blob": "a" * 20000})
        self.assertEqual(self.t.accept(big).status, "rejected")

    def test_an_x_kind_takes_a_seq_like_any_event(self):
        a = self.w("sansa").ext("t", {"n": 1})
        self.assertTrue(self.t.accept(a).ok)
        b = self.w("sansa").post("next")
        self.assertEqual(b["seq"], a["seq"] + 1)
        self.assertTrue(self.t.accept(b).ok)
        clash = E.make_event(self.ids["sansa"], thread=self.t.id, kind="x-t", body={"n": 2}, parents=a["parents"], seq=a["seq"], admin_ref=a["admin_ref"], v=2)
        self.t.accept(clash)
        self.assertTrue(self.t.conflicts, "the same author and seq twice is equivocation whatever the kind")


class ExtKey(unittest.TestCase):
    def setUp(self):
        self.ids, self.g, self.t = build(2)
        self.w = lambda n: Writer(self.ids[n], self.t)

    def test_x_on_post_and_digest(self):
        self.assertTrue(self.t.accept(self.w("sansa").post("hi", x={"ns": {"a": 1}})).ok)
        self.assertTrue(self.t.accept(self.w("arya").event("digest", {"text": "d", "covers": [], "x": {"k": [1, 2]}})).ok)

    def test_x_in_format_1_is_refused(self):
        ids, g, t = build(1)
        self.assertEqual(t.accept(Writer(ids["sansa"], t).post("hi", x={"a": 1})).status, "rejected")
        self.assertEqual(t.accept(Writer(ids["arya"], t).event("digest", {"text": "d", "covers": [], "x": {}})).status, "rejected")

    def test_x_must_be_a_small_object(self):
        for bad in ([], "s", 1, None, True, {"a": "b" * 5000}):
            self.assertEqual(self.t.accept(self.w("sansa").post("hi", x=bad)).status, "rejected", repr(bad)[:30])
        self.assertTrue(self.t.accept(self.w("sansa").post("hi", x={"a": "b" * 3000})).ok)

    def test_x_never_rides_in_an_admin_body(self):
        add = self.w("arya").add_member(self.ids["dave"], "member")
        add = resign(self.ids["arya"], add, body={**add["body"], "x": {"a": 1}})
        self.assertEqual(self.t.accept(add).status, "rejected")
        rules = self.w("arya").admin("rules_update", {"rules": {"posts_per_author_per_hour": 30}, "x": {}})
        self.assertEqual(self.t.accept(rules).status, "rejected")

    def test_x_never_rides_in_a_guest_request(self):
        rq = self.w("dave").guest_request("let me in", self.t.id)
        rq = resign(self.ids["dave"], rq, body={**rq["body"], "x": {"a": 1}})
        self.assertEqual(self.t.accept(rq).status, "rejected")

    def test_x_on_evidence_and_admin_events_are_built_in_the_threads_format(self):
        a = self.w("sansa").post("a")
        b = resign(self.ids["sansa"], a, body={"text": "b"})                       # same author, same seq, different event: equivocation
        ev = self.w("arya").event("evidence", {"a": a, "b": b, "reason": "fork", "x": {"k": 1}})
        r = self.t.accept(ev)
        self.assertTrue(r.ok, (r.status, r.reason))
        ev2 = self.w("arya").event("evidence", {"a": a, "b": b, "x": {"k": 2}})
        self.assertEqual(ev["v"], 2)
        # admin events are built with the thread's format too (a v 1 admin event in a v 2 thread would be a mismatch)
        for mk in (lambda: self.w("arya").add_member(self.ids["dave"], "member"),
                      lambda: self.w("arya").admin("rules_update", {"rules": {"posts_per_author_per_hour": 30}}),
                      lambda: self.w("arya").admin("checkpoint", {"count": 1, "heads": self.t.tips(), "epoch": 0})):
            adm = mk()
            self.assertEqual(adm["v"], 2)
            r = self.t.accept(adm)
            self.assertTrue(r.ok, (adm["kind"], r.status, r.reason))
        ids1, g1, t1 = build(1)
        self.assertEqual(Writer(ids1["arya"], t1).add_member(ids1["dave"], "member")["v"], 1)

    def test_other_unknown_body_keys_are_still_refused_in_format_2(self):
        self.assertEqual(self.t.accept(self.w("sansa").post("hi", y={"a": 1})).status, "rejected")

    def test_cross_format_evidence_is_not_evidence(self):
        a = Writer(self.ids["sansa"], self.t).post("a")
        b = resign(self.ids["sansa"], a, body={"text": "b"})
        a1, b1 = resign(self.ids["sansa"], a, v=1), resign(self.ids["sansa"], b, v=1)
        why = self.t._evidence_problem({"a": a1, "b": b1}, "member")
        self.assertEqual(why, "evidence events must have this thread's format")


class Mismatch(unittest.TestCase):
    def test_a_v2_event_in_a_v1_thread_and_the_other_way(self):
        for tf, ef in ((1, 2), (2, 1)):
            ids, g, t = build(tf)
            p = Writer(ids["sansa"], t).post("x")
            r = t.accept(resign(ids["sansa"], p, v=ef))
            self.assertEqual((r.status, "format mismatch" in r.reason), ("rejected", True), (tf, ef, r.reason))
            self.assertEqual(len(t.stored), 1)

    def test_mismatched_events_are_skipped_by_the_bulk_load(self):
        ids, g, t = build(1)
        good = Writer(ids["sansa"], t).post("good")
        bad = resign(ids["sansa"], Writer(ids["sansa"], t).post("bad", ts=9), v=2)
        t2 = Thread(g)
        t2.add_many([good, bad])
        self.assertEqual(sorted(t2.stored), sorted([t2.id, event_id(good)]))

    def test_an_orphan_with_the_wrong_v_is_rechecked_when_its_genesis_arrives(self):
        ids, g, t = build(1)
        p = resign(ids["sansa"], Writer(ids["sansa"], t).post("early"), v=2)
        with tempfile.TemporaryDirectory() as d:
            m = Mirror(d)
            self.assertNotEqual(m.ingest(p).status, "accepted")        # no thread yet: parked as an orphan
            self.assertTrue(m.ingest(g).ok)
            self.assertNotIn(event_id(p), m.threads[t.id].stored)       # re-checked at the genesis: refused
            good = Writer(ids["sansa"], m.threads[t.id]).post("later")
            self.assertTrue(m.ingest(good).ok)

    def test_an_orphan_with_the_right_v_lands_when_its_genesis_arrives(self):
        ids, g, t = build(2)
        x = Writer(ids["sansa"], t).ext("t", {"a": 1})
        with tempfile.TemporaryDirectory() as d:
            m = Mirror(d)
            m.ingest(x)
            self.assertTrue(m.ingest(g).ok)
            self.assertIn(event_id(x), m.threads[t.id].stored)


class Views(unittest.TestCase):
    def events(self):
        ids, g, t = build(2)
        w = lambda n: Writer(ids[n], t)
        evs = []
        for mk in (lambda: w("sansa").post("a", x={"k": 1}), lambda: w("sansa").ext("r", {"n": 1}), lambda: w("carol").post("b"), lambda: w("arya").ext("r", {"n": 2}),
                   lambda: w("carol").ext("s", {})):
            ev = mk()                                                              # built one at a time: each takes the next seq
            assert t.accept(ev).ok
            evs.append(ev)
        return ids, g, t, evs

    def test_every_arrival_order_gives_the_same_view(self):
        ids, g, t, evs = self.events()
        want = derived(t)
        for seed in range(6):
            order = list(evs)
            random.Random(seed).shuffle(order)
            t2 = Thread(g)
            for _ in range(2):
                for e in order:
                    t2.accept(e)
            self.assertEqual(derived(t2), want, seed)

    def test_disk_round_trip_keeps_format_and_events(self):
        ids, g, t, evs = self.events()
        with tempfile.TemporaryDirectory() as d:
            m = Mirror(d)
            m.ingest(g)
            for e in evs:
                self.assertTrue(m.ingest(e).ok)
            m2 = Mirror(d)
            t2 = m2.threads[t.id]
            self.assertEqual(t2.format, 2)
            self.assertEqual(derived(t2), derived(t))
            self.assertEqual([e["v"] for e in map(canon.loads, [canon.dumps(x) for x in t2.stored.values()])], [2] * len(t2.stored))

    def test_x_kinds_are_never_unread(self):
        ids, g, t, evs = self.events()
        with tempfile.TemporaryDirectory() as d:
            m = Mirror(d)
            m.ingest(g)
            for e in evs:
                m.ingest(e)
            un = m.unread(t.id, ids["arya"].id)
            self.assertEqual([e["kind"] for e in un], ["post", "post"])        # sansa's and carol's posts; no x- kind, own events excluded anyway

    def test_x_kinds_are_charged_to_the_rate_limit(self):
        rules = T.default_rules()
        rules["posts_per_author_per_hour"] = 3
        ids, g, t = build(2, rules=rules)
        with tempfile.TemporaryDirectory() as d:
            m = Mirror(d)
            m.ingest(g)
            w = Writer(ids["sansa"], m.threads[t.id])
            seen = []
            for n in range(5):
                ev = w.ext("t", {"n": n}) if n % 2 else w.post(f"p{n}")
                r = m.ingest(ev)
                seen.append(r.ok)
                if not r.ok:
                    self.assertIn("rate limited", r.reason)
            self.assertEqual(seen, [True, True, True, False, False])

    def test_the_stored_limit_counts_x_kinds(self):
        ids, g, t = build(2)
        w = Writer(ids["sansa"], t)
        T.MAX_STORED, old = 6, T.MAX_STORED
        try:
            res = [t.accept(w.ext("t", {"n": n})) for n in range(8)]
        finally:
            T.MAX_STORED = old
        self.assertEqual([r.ok for r in res], [True] * 5 + [False] * 3)


if __name__ == "__main__":
    unittest.main()
