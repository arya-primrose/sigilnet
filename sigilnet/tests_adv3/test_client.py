"""A hostile server against pull(): junk storage, work amplification, foreign threads, lies."""
import os
import random
import tempfile
import threading
import time
import unittest

from sigilnet import sync as S
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror

from .h3 import Fn, all_events, big_world, mirror_with, vis
from sigilnet.tests.util import World


def honest(a):
    return S.Loopback(S.SyncServer(a))


class ForeignData(unittest.TestCase):
    def test_a_peer_cannot_make_us_store_other_threads(self):
        # BUG: pull(tid) hands EVERY event in a response to Mirror.ingest, including genesis events of unrelated threads; those are created
        # on disk (up to max_threads=256) and are not counted as junk.
        w = big_world()
        w.add(w.w("carol").post("x"))
        real = mirror_with(w.genesis, all_events(w))
        foreign = [World().genesis for _ in range(30)]
        inner = honest(real)

        def fn(req):
            r = inner.request(req)
            if r.get("t") == "events":
                r = dict(r, events=r["events"] + foreign)
            return r
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        S.pull(b, w.t.id, Fn(fn), w.ids["sansa"])
        self.assertEqual(set(b.threads), {w.t.id})

    def test_foreign_events_do_not_land_in_the_orphan_pool_or_disk(self):
        w = big_world()
        real = mirror_with(w.genesis, [])
        other = World()
        stray = [other.w("carol").post(str(i)) for i in range(50)]
        inner = honest(real)

        def fn(req):
            r = inner.request(req)
            return dict(r, events=r["events"] + stray) if r.get("t") == "events" else r
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        S.pull(b, w.t.id, Fn(fn), w.ids["sansa"])
        self.assertEqual(len(b.orphans), 0)            # BUG if not: unverifiable events of threads nobody asked about are kept in memory

    def test_a_valid_event_of_our_thread_that_was_never_asked_for_is_not_stored(self):
        w = big_world()
        e1 = w.w("carol").post("one"); w.add(e1)
        e2 = w.w("carol").post("two"); w.add(e2)
        srv_side = mirror_with(w.genesis, [e1])
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        inner = honest(srv_side)

        def fn(req):
            r = inner.request(req)
            return dict(r, events=r["events"] + [e2]) if r.get("t") == "events" else r
        S.pull(b, w.t.id, Fn(fn), w.ids["sansa"])
        self.assertNotIn(event_id(e2), b.thread(w.t.id).resolved_ids())    # a valid event that was not asked for is not stored: only asked ids are ingested


class Amplification(unittest.TestCase):
    def test_huge_leaf_lists_cannot_make_the_client_send_thousands_of_requests(self):
        # BUG: leaves from all (up to 100) pages are accumulated without a cap and fetched 64 at a time, every round
        w = big_world()
        real = mirror_with(w.genesis, [])
        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": w.t.id, "head": w.t.head, "n": 1, "pages": 100, "leaves": [os.urandom(16).hex() for _ in range(2000)]}
            return {"t": "events", "events": [], "more": []}
        tr = Fn(fn)
        b = mirror_with(w.genesis, [])
        t0 = time.time()
        S.pull(b, w.t.id, tr, w.ids["sansa"])
        gets = sum(1 for c in tr.calls if c["t"] == "get")
        self.assertLess(gets, 500, f"{gets} get requests ({time.time() - t0:.1f}s) for a peer that never delivers anything")

    def test_leaf_lists_are_deduplicated_before_fetching(self):
        w = big_world()
        one = os.urandom(16).hex()

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": w.t.id, "head": w.t.head, "n": 1, "pages": 100, "leaves": [one] * 5000}
            return {"t": "events", "events": [], "more": []}
        tr = Fn(fn)
        S.pull(mirror_with(w.genesis, []), w.t.id, tr, w.ids["sansa"])
        self.assertLess(sum(1 for c in tr.calls if c["t"] == "get"), 10)

    def test_same_valid_event_sent_many_times_is_cheap_and_bounded(self):
        w = big_world()
        e = w.w("carol").post("x"); w.add(e)
        real = mirror_with(w.genesis, [e])
        inner = honest(real)

        def fn(req):
            r = inner.request(req)
            return dict(r, events=r["events"] * 3000) if r.get("t") == "events" else r
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        t0 = time.time()
        r = S.pull(b, w.t.id, Fn(fn), w.ids["sansa"])
        self.assertLess(time.time() - t0, 15)
        self.assertEqual(len(open(os.path.join(b.root, "threads", w.t.id, "events.jsonl")).read().splitlines()), 2) if hasattr(b, "root") else None

    def test_more_that_never_shrinks_terminates(self):
        w = big_world()
        e = w.w("carol").post("x"); w.add(e)
        tid = w.t.id

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": tid, "head": w.t.head, "n": 2, "pages": 1, "leaves": [event_id(e)]}
            if req["ids"] == [tid]:
                return {"t": "events", "events": [w.genesis], "more": []}
            return {"t": "events", "events": [], "more": req["ids"]}
        tr = Fn(fn)
        t0 = time.time()
        S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), tid, tr, w.ids["sansa"])
        self.assertLess(len(tr.calls), 20)
        self.assertLess(time.time() - t0, 5)

    def test_head_that_is_not_served_ends_quietly(self):
        w = big_world()
        tid = w.t.id

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": tid, "head": "ab" * 16, "n": 1, "pages": 1, "leaves": []}
            return {"t": "events", "events": [w.genesis] if req["ids"] == [tid] else [], "more": []}
        tr = Fn(fn)
        r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), tid, tr, w.ids["sansa"])
        self.assertLess(len(tr.calls), 12)

    def test_pages_lie_negative_zero_bool_and_float(self):
        w = big_world()
        tid = w.t.id
        for pages in (-1, 0, True, 2 ** 60, "3", None, [1]):
            def fn(req, pages=pages):
                if req["t"] == "summary":
                    return {"t": "summary", "thread": tid, "head": w.t.head, "n": 1, "pages": pages, "leaves": []}
                return {"t": "events", "events": [w.genesis], "more": []}
            tr = Fn(fn)
            S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), tid, tr, w.ids["sansa"])
            self.assertLessEqual(len(tr.calls), S.MAX_LIST_PAGES + 10, pages)

    def test_response_fields_of_wrong_types_never_raise(self):
        w = big_world()
        tid = w.t.id
        junk = [None, 5, "x", [], {}, [None], [[]], [{}], [5], ["a" * 32], [{"v": 1}], {"events": 5}, [True]]
        for j in junk:
            for shape in ("events", "leaves", "head"):
                def fn(req, j=j, shape=shape):
                    if req["t"] == "summary":
                        return {"t": "summary", "thread": tid, "head": j if shape == "head" else w.t.head, "n": j, "pages": 1,
                                "leaves": j if shape == "leaves" else []}
                    return {"t": "events", "events": j if shape == "events" else [w.genesis], "more": j}
                S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), tid, Fn(fn), w.ids["sansa"])

    def test_events_that_reference_ids_the_server_never_serves_do_not_grow_state_without_bound(self):
        # a hostile server feeds valid events (by a real member key it controls) whose parents do not exist: parked, memory only, bounded
        w = big_world()
        tid = w.t.id
        evs = []
        seq = 0
        from sigilnet import event as E
        for i in range(400):
            evs.append(E.make_event(w.ids["carol"], thread=tid, kind="post", body={"text": str(i)}, parents=[os.urandom(16).hex()], seq=i, admin_ref=w.t.head))

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": tid, "head": w.t.head, "n": 1, "pages": 1, "leaves": [event_id(e) for e in evs]}
            if req["ids"] == [tid]:
                return {"t": "events", "events": [w.genesis], "more": []}
            return {"t": "events", "events": [e for e in evs if event_id(e) in req["ids"]], "more": []}
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, tid, Fn(fn), w.ids["sansa"])
        self.assertLessEqual(len(b.thread(tid).stored), 1 + 64 + 1)
        self.assertLess(r["requests"], 40)


class GuestFlood(unittest.TestCase):
    def test_guest_requests_from_a_peer_stay_within_the_awaiting_bound(self):
        # BUG: requests delivered BEFORE their parent are parked, then all promoted to "awaiting" at once when the parent arrives; the awaiting
        # pool limit (MAX_AWAITING_HARD=200) is only enforced one event at a time on direct arrival. Order of delivery changes what is kept.
        w = World(visibility="public")
        root = w.post("arya", "who can help?")
        tid = w.t.id
        reqs = [Writer(Identity.generate(f"g{i}"), w.t).guest_request("hi", root) for i in range(300)]

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": tid, "head": w.t.head, "n": 1, "pages": 1, "leaves": [event_id(e) for e in reqs]}
            if req["ids"] == [tid]:
                return {"t": "events", "events": [w.genesis], "more": []}
            return {"t": "events", "events": [e for e in reqs + [w.t.events[root]] if event_id(e) in req["ids"]], "more": []}
        d = tempfile.mkdtemp()
        b = Mirror(d, rate_limit=False)
        S.pull(b, tid, Fn(fn), w.ids["sansa"])
        self.assertLessEqual(len(b.thread(tid).awaiting), 200)
        size = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(d) for f in fs)
        self.assertLess(size, 300_000, f"{size} bytes on disk from 300 waiting guest requests")


class ConcurrentWriter(unittest.TestCase):
    def test_pull_while_a_local_writer_appends_to_the_same_mirror(self):
        w = big_world()
        for k in range(30):
            w.add(w.w("carol").post(str(k), parents=[w.t.id]))
        a = mirror_with(w.genesis, all_events(w))
        d = tempfile.mkdtemp()
        b = Mirror(d, rate_limit=False)
        local = []
        mine = Identity.generate("local")

        def writer():
            m2 = Mirror(d, rate_limit=False)
            from sigilnet import event as E
            for k in range(25):
                if w.t.id not in m2.threads:
                    time.sleep(0.005)
                    m2._discover()
                    continue
                e = E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": f"local {k}"}, parents=[w.t.id], seq=k, admin_ref=w.t.head)
                local.append(e)
                m2.ingest(e, live=False)
                time.sleep(0.003)
        th = threading.Thread(target=writer); th.start()
        S.pull(b, w.t.id, honest(a), w.ids["sansa"])
        th.join(30)
        fresh = Mirror(d)
        self.assertEqual(fresh.recovered, [])
        want = {event_id(e) for e in all_events(w)} | {event_id(e) for e in local} | {w.t.id}
        self.assertEqual(fresh.thread(w.t.id).resolved_ids(), want)


if __name__ == "__main__":
    unittest.main()
