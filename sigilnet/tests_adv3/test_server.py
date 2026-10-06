"""Attacks on SyncServer: oracles, replay cache, rate table, context and audience confusion, canonical-JSON differentials."""
import json
import tempfile
import threading
import time
import unittest

from sigilnet import canon
from sigilnet import event as E
from sigilnet import sync as S
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror

from .h3 import all_events, big_world, mirror_with
from sigilnet.tests.util import World


class Base(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.add(self.w.w("sansa").post("private talk"))
        self.a = mirror_with(self.w.genesis, all_events(self.w))
        self.now = [int(time.time())]
        self.srv = S.SyncServer(self.a, clock=lambda: self.now[0])
        self.tid = self.w.t.id

    def ask(self, who, body, thread=None, srv=None, **kw):
        b = dict(body)
        b.setdefault("thread", thread or self.tid)
        return (srv or self.srv).handle(S.sign_request(self.w.ids[who] if isinstance(who, str) else who, b, ts=self.now[0], **kw))


class Oracle(Base):
    @staticmethod
    def bare(r):
        return {k: v for k, v in r.items() if k not in ('nonce', 'r')}      # the echoed nonce differs per request and r=1 marks a response, by design

    SHAPES = [{"t": "summary", "page": 0}, {"t": "summary", "page": "x"}, {"t": "summary", "page": -5}, {"t": "get", "ids": "no"},
              {"t": "get", "ids": ["zz"] * 500}, {"t": "get", "ids": []}, {"t": "notify", "leaves": 5}, {"t": "bogus"}, {"t": None}, {}]

    def test_stranger_gets_the_same_bytes_as_for_a_nonexistent_thread_for_every_request_shape(self):
        for shape in self.SHAPES:
            real = canon.dumps(self.bare(self.ask("eve", shape)))
            fake = canon.dumps(self.bare(self.ask("eve", shape, thread="1" * 32)))
            self.assertEqual(real, fake, shape)
            self.assertEqual(json.loads(real), {"t": "unknown"}, shape)

    def test_removed_member_and_stranger_are_indistinguishable(self):
        self.a.ingest(self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id}))
        for shape in self.SHAPES:
            self.assertEqual(self.bare(self.ask("carol", shape)), self.bare(self.ask("eve", shape)), shape)

    def test_member_errors_only_appear_after_the_membership_check(self):
        self.assertEqual(self.ask("sansa", {"t": "get", "ids": "no"})["why"], "bad ids")
        self.assertEqual(self.bare(self.ask("eve", {"t": "get", "ids": "no"})), {"t": "unknown"})

    def test_thread_field_of_odd_types_is_just_unknown(self):
        for tid in (None, 5, [], {}, ["x"], {"a": 1}, True, "", "A" * 32, "é" * 32, "0" * 10000):
            r = self.srv.handle(S.sign_request(self.w.ids["eve"], {"t": "summary", "thread": tid}, ts=self.now[0]))
            self.assertEqual(self.bare(r), {"t": "unknown"}, tid)

    def test_notify_from_strangers_or_removed_members_never_reaches_the_callback(self):
        seen = []
        srv = S.SyncServer(self.a, clock=lambda: self.now[0], on_notify=lambda *a: seen.append(a))
        self.ask("eve", {"t": "notify", "leaves": ["a" * 32]}, srv=srv)
        self.a.ingest(self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id}))
        self.ask("carol", {"t": "notify", "leaves": ["a" * 32]}, srv=srv)
        self.assertEqual(seen, [])
        self.assertEqual(self.ask("sansa", {"t": "notify", "leaves": ["a" * 32, "bad"]}, srv=srv)["t"], "ok")
        self.assertEqual(seen[0][2], ["a" * 32])

    def test_notify_callback_that_raises_or_odd_leaves_do_not_crash_the_server(self):
        def boom(*a):
            raise RuntimeError("x")
        srv = S.SyncServer(self.a, clock=lambda: self.now[0], on_notify=boom)
        self.assertEqual(self.ask("sansa", {"t": "notify", "leaves": []}, srv=srv)["t"], "error")
        for leaves in (5, "abc", {"a": 1}, [[]], [None], [{}]):
            self.assertIn(self.ask("sansa", {"t": "notify", "leaves": leaves})["t"], ("ok", "error"))

    def test_waiting_guest_request_is_invisible_in_summary_counts_and_leaves(self):
        w = World(visibility="public")
        root = w.post("arya", "who can help?")
        m = mirror_with(w.genesis, [w.t.events[root]])
        before = S.SyncServer(m).handle(S.sign_request(w.ids["eve"], {"t": "summary", "thread": w.t.id, "page": 0}))
        rq = Writer(w.ids["dave"], w.t).guest_request("hello", root)
        m.ingest(rq)
        after = S.SyncServer(m).handle(S.sign_request(w.ids["eve"], {"t": "summary", "thread": w.t.id, "page": 0}))
        self.assertEqual(Oracle.bare(before), Oracle.bare(after))
        self.assertNotIn(event_id(rq), json.dumps(after))

    def test_ids_of_another_thread_are_not_served_by_the_thread_they_are_not_in(self):
        other = big_world()
        e = other.w("carol").post("other thread secret")
        other.add(e)
        # one mirror holds both threads; sansa is a member of both worlds' threads only by sharing identity objects: use different ones
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        m.ingest(self.w.genesis); m.ingest(other.genesis); m.ingest(e)
        srv = S.SyncServer(m)
        r = srv.handle(S.sign_request(self.w.ids["sansa"], {"t": "get", "thread": self.tid, "ids": [event_id(e), other.t.id]}))
        self.assertEqual(r["events"], [])

    def test_page_beyond_the_end_and_bad_pages(self):
        self.assertEqual(self.ask("sansa", {"t": "list", "page": 99})["ids"], [])
        for bad in (-1, S.MAX_LIST_PAGES, 2 ** 53 - 1, True, "0", [0], {}):
            r = self.ask("sansa", {"t": "list", "page": bad})
            self.assertIn(r["t"], ("error", "list"), bad)
            self.assertEqual(r["t"], "error", bad)


class Replay(Base):
    def test_replay_after_the_nonce_cache_was_flooded(self):
        # BUG: the replay guard is a bounded LRU of nonces, and ANY key (member or not) can fill it inside the 10-minute window,
        # after which a captured request is accepted again.
        cap = S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid, "page": 0}, ts=self.now[0])
        self.assertEqual(self.srv.handle(cap)["t"], "summary")
        self.assertEqual(self.srv.handle(cap)["why"], "replayed request")
        flood = [Identity.generate(f"f{i}") for i in range((S.NONCES // S.RATE_PER_MIN) + 3)]
        for f in flood:
            for _ in range(S.RATE_PER_MIN):
                self.srv.handle(S.sign_request(f, {"t": "summary", "thread": "0" * 32}, ts=self.now[0]))
        self.assertEqual(self.srv.handle(cap).get("why"), "replayed request", "captured request replayed successfully after cache eviction")

    def test_request_replayed_to_a_second_server_holding_the_same_thread(self):
        # BUG (low): a signed request names no audience, so a hostile peer that receives it can relay it to any other holder of the thread
        # (confused deputy: it reads with the requester's rights).
        b = mirror_with(self.w.genesis, all_events(self.w))
        srv2 = S.SyncServer(b, clock=lambda: self.now[0])
        # FIXED: a request can name its audience (the server's agent id); the same captured request is refused by any other server
        ida, idb = Identity.generate("A"), Identity.generate("B")
        srv1 = S.SyncServer(self.a, clock=lambda: self.now[0], identity=ida)
        srv2 = S.SyncServer(b, clock=lambda: self.now[0], identity=idb)
        req = S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid}, ts=self.now[0], aud=ida.id)
        self.assertEqual(srv1.handle(req)["t"], "summary")
        self.assertEqual(srv2.handle(req).get("why"), "wrong audience")

    def test_cross_thread_and_field_tampering_break_the_signature(self):
        req = S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid, "page": 0}, ts=self.now[0])
        for k, v in (("thread", "1" * 32), ("t", "get"), ("page", 1), ("ts", self.now[0] + 1), ("nonce", "0" * 16)):
            self.assertEqual(self.srv.handle(dict(req, **{k: v}))["why"], "bad signature", k)
        self.assertEqual(self.srv.handle({**req, "extra": 1})["why"], "bad signature")

    def test_signature_from_another_context_is_not_a_sync_signature(self):
        # an event signature / cosignature over the same-looking bytes must not authenticate a request
        me = self.w.ids["sansa"]
        req = S.sign_request(me, {"t": "summary", "thread": self.tid, "page": 0}, ts=self.now[0])
        body = {k: v for k, v in req.items() if k != "sig"}
        for ctx in (E.EVENT_CTX, E.COSIG_CTX, b"", b"sigilnet/v1/sync"):
            forged = dict(req, sig=me.sign(ctx + canon.dumps(body)))
            if ctx == b"sigilnet/v1/sync":
                pass
            self.assertEqual(self.srv.handle(forged)["why"], "bad signature", ctx)

    def test_a_signed_request_is_not_an_acceptable_event(self):
        req = S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid, "page": 0})
        self.assertEqual(self.a.ingest(req).status, "rejected")

    def test_clock_skew_edges(self):
        me = self.w.ids["sansa"]
        for delta, ok in ((0, True), (S.FUTURE_SKEW, True), (-S.SKEW, True), (S.FUTURE_SKEW + 1, False), (S.SKEW, False), (-S.SKEW - 1, False), (10 ** 12, False), (-10 ** 12, False)):       # the past window is SKEW, the future one FUTURE_SKEW (M0)
            r = self.srv.handle(S.sign_request(me, {"t": "summary", "thread": self.tid, "page": 0}, ts=self.now[0] + delta))
            self.assertEqual(r["t"] == "summary", ok, delta)

    def test_malformed_auth_fields(self):
        me = self.w.ids["sansa"]
        good = S.sign_request(me, {"t": "summary", "thread": self.tid, "page": 0}, ts=self.now[0])
        for k, v in (("ts", True), ("ts", 1.5), ("ts", "5"), ("nonce", 5), ("nonce", "x" * 17), ("pub", "zz"), ("sig", None), ("from", ["a"]), ("from", "A" * 32),
                     ("pub", me.sign_pub.upper()), ("sig", good["sig"].upper())):
            r = self.srv.handle(dict(good, **{k: v}))
            self.assertEqual(r["t"], "error", (k, v))
            self.assertNotIn("Error", r["why"].replace("internal", "") if r["why"].startswith("internal") is False else "")

    def test_uppercase_hex_pub_does_not_bypass_the_member_check(self):
        me = self.w.ids["eve"]
        req = S.sign_request(me, {"t": "summary", "thread": self.tid, "page": 0}, ts=self.now[0])
        self.assertEqual({k: v for k, v in self.srv.handle(req).items() if k not in ("nonce", "r")}, {"t": "unknown"})


class RateTable(Base):
    def test_rate_table_does_not_grow_forever(self):
        # BUG (low): one entry per requester key that ever spoke is kept forever; old ones are never pruned, and there is no global limit
        for i in range(1500):
            self.srv.handle(S.sign_request(Identity.generate("k"), {"t": "summary", "thread": "0" * 32}, ts=self.now[0]))
        self.now[0] += 7200
        self.ask("sansa", {"t": "summary", "page": 0})
        self.assertLess(len(self.srv.rate), 50)

    def test_many_keys_share_no_budget(self):
        # BUG (low): see the rate-table finding; the limit is per key, keys are free
        # documents the limit: N keys get N * RATE_PER_MIN requests/min; asserting there is SOME global bound
        ok = 0
        for i in range(40):
            k = Identity.generate("k")
            for _ in range(S.RATE_PER_MIN + 5):
                r = self.srv.handle(S.sign_request(k, {"t": "summary", "thread": self.tid, "page": 0}, ts=self.now[0]))
                ok += r["t"] in ("summary", "unknown")
        self.assertLess(ok, 40 * S.RATE_PER_MIN, "no global rate bound: every fresh key gets its own full budget")

    def test_unauthenticated_junk_does_not_consume_a_members_budget(self):
        me = self.w.ids["sansa"]
        for _ in range(S.RATE_PER_MIN * 2):
            self.srv.handle(dict(S.sign_request(me, {"t": "summary", "thread": self.tid, "page": 0}, ts=self.now[0]), sig="0" * 128))
        self.assertEqual(self.ask("sansa", {"t": "summary", "page": 0})["t"], "summary")

    def test_budget_recovers_after_a_minute(self):
        for _ in range(S.RATE_PER_MIN + 3):
            r = self.ask("hu", {"t": "summary", "page": 0})
        self.assertEqual(r["why"], "rate limited")
        self.now[0] += 61
        self.assertEqual(self.ask("hu", {"t": "summary", "page": 0})["t"], "summary")

    def test_limited_requests_do_not_extend_the_penalty(self):
        for _ in range(S.RATE_PER_MIN + 50):
            self.ask("hu", {"t": "summary", "page": 0})
        self.now[0] += 61
        self.assertEqual(self.ask("hu", {"t": "summary", "page": 0})["t"], "summary")


class CanonDifferentials(unittest.TestCase):
    def test_hostile_encodings_are_rejected(self):
        bad = [b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}', b'{"a":1.0}', b'{"a":1e2}', b'{"a":-0}',
               b' {"a":1}', b'{"a": 1}', b'\xef\xbb\xbf{"a":1}', b'{"b":1,"a":2}', b'{"a":"\\ud800"}', b'{"a":"\xc3\xa9"}', b'{"a":"\\u00E9"}',
               b'{"a":9007199254740992}', b'[' * 18 + b']' * 18, b'[' * 100000 + b']' * 100000, b'{"a":1}{"b":2}', b'{"a":1}\n', b'\xff', b'',
               b'{"a":01}', b'{"a":+1}', b'{"a":"\\/"}', b'{"a":"\\u0000"}'[:0] or b'x']
        for raw in bad:
            with self.assertRaises(canon.CanonError, msg=raw[:40]):
                canon.loads(raw)

    def test_size_limit_is_enforced_before_parsing(self):
        with self.assertRaises(canon.CanonError):
            canon.loads(b'"' + b"a" * canon.MAX_BYTES + b'"')

    def test_utf16_key_order_round_trips(self):
        obj = {"￿": 1, "\U00010000": 2, "a": 3, "é": 4, "퟿": 5, "": 6}
        self.assertEqual(canon.loads(canon.dumps(obj)), obj)
        keys = list(json.loads(canon.dumps(obj)))
        self.assertEqual(keys, sorted(keys, key=lambda k: k.encode("utf-16-be")))

    def test_dumps_refuses_what_loads_would_refuse(self):
        for v in (float("nan"), 1.5, 2 ** 53, {1: 2}, b"x", {"a": {"b": [[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]}}, "\ud800", {"a" * 2: object()}):
            with self.assertRaises(canon.CanonError):
                canon.dumps(v)

    def test_python_json_and_canon_agree_on_the_signed_request(self):
        me = Identity.generate("x")
        req = S.sign_request(me, {"t": "get", "thread": "a" * 32, "ids": ["b" * 32]})
        self.assertEqual(canon.loads(canon.dumps(req)), req)
        # what the server verifies is computed from the PARSED dict, so key order on the wire cannot matter... but must not be accepted
        shuffled = json.dumps(req, separators=(",", ":"), sort_keys=False)
        if shuffled.encode() != canon.dumps(req):
            with self.assertRaises(canon.CanonError):
                canon.loads(shuffled)


class Concurrency(unittest.TestCase):
    def test_parallel_requests_while_another_process_appends(self):
        # a daemon serves from many threads while the CLI (a second Mirror on the same directory) appends events
        w = big_world()
        d = tempfile.mkdtemp()
        m = Mirror(d, rate_limit=False)
        m.ingest(w.genesis)
        for k in range(20):
            w.add(w.w("carol").post(str(k), parents=[w.t.id]))
        evs = all_events(w)
        for e in evs[:10]:
            m.ingest(e, live=False)
        srv = S.SyncServer(m)
        bad, stop = [], threading.Event()

        def writer():
            m2 = Mirror(d, rate_limit=False)
            for k in range(60):
                e = w.w("carol").post("w" + str(k), parents=[w.t.id])
                w.add(e)
                m2.ingest(e, live=False)
                time.sleep(0.002)
            stop.set()

        def reader(who):
            n = 0
            while not stop.is_set() and n < 200:
                n += 1
                r = srv.handle(S.sign_request(w.ids[who], {"t": "summary", "thread": w.t.id, "page": 0}))
                if r["t"] == "error" and r["why"].startswith("internal"):
                    bad.append(r["why"])
                elif r["t"] == "summary":
                    g = srv.handle(S.sign_request(w.ids[who], {"t": "get", "thread": w.t.id, "ids": r["leaves"][:64]}))
                    if g["t"] == "error" and g["why"].startswith("internal"):
                        bad.append(g["why"])
        ts = [threading.Thread(target=writer)] + [threading.Thread(target=reader, args=(n,)) for n in ("sansa", "hu", "arya", "carol")]
        [t.start() for t in ts]
        [t.join(60) for t in ts]
        self.assertEqual(bad, [])
        self.assertEqual(Mirror(d).recovered, [])


if __name__ == "__main__":
    unittest.main()
