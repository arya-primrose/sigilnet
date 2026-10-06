import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sigilnet import event as E
from sigilnet import sync as S
from sigilnet import tcp
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread

from .test_convergence import build_history, visible
from .util import World

ROOT = str(Path(__file__).resolve().parents[2])


def mirror_with(genesis, events, **kw):
    m = Mirror(tempfile.mkdtemp(), rate_limit=False, **kw)
    m.ingest(genesis)
    for _ in range(3):
        for ev in events:
            m.ingest(ev, live=False)
    return m


def vis(m, tid):
    return visible(m.thread(tid))


class Pull(unittest.TestCase):
    def test_empty_mirror_converges_to_the_servers_thread(self):
        w = World()
        evs = [w.w("sansa").post("hello"), ]
        w.add(evs[0])
        w.add(w.w("carol").post("reply", reply_to=event_id(evs[0])))
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id}))
        a = mirror_with(w.genesis, [w.t.events[i] for i in w.t.order[1:]])
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, w.t.id, S.Loopback(S.SyncServer(a)), w.ids["sansa"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(vis(a, w.t.id), vis(b, w.t.id))
        again = S.pull(b, w.t.id, S.Loopback(S.SyncServer(a)), w.ids["sansa"])
        self.assertEqual((again["ok"], again["fetched"]), (True, 0))                       # idempotent: nothing left to fetch

    def test_random_histories_split_between_two_mirrors_converge_both_ways(self):
        for seed in range(25):
            g, events, ref = build_history(seed)
            me = ref.test_ids["sansa"]
            rnd = random.Random(seed)
            a_evs = [e for e in events if rnd.random() < 0.6]
            b_evs = [e for e in events if rnd.random() < 0.6]
            a_evs_ids, b_evs_ids = {event_id(e) for e in a_evs}, {event_id(e) for e in b_evs}
            a, b = mirror_with(g, a_evs), mirror_with(g, b_evs)
            for _ in range(2):
                S.pull(a, ref.id, S.Loopback(S.SyncServer(b)), me)
                S.pull(b, ref.id, S.Loopback(S.SyncServer(a)), me)
            union = [e for e in events if event_id(e) in a_evs_ids or event_id(e) in b_evs_ids]                        # events neither mirror was given cannot be synced
            allm = mirror_with(g, union)
            self.assertEqual(vis(a, ref.id), vis(b, ref.id), f"seed {seed}: the two mirrors disagree")
            self.assertEqual(vis(a, ref.id), vis(allm, ref.id), f"seed {seed}: differs from holding every event")

    def test_a_dropped_connection_mid_pull_resumes(self):
        w = World()
        for n in range(40):
            w.add(w.w("carol").post(str(n)))
        a = mirror_with(w.genesis, [w.t.events[i] for i in w.t.order[1:]])
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        srv = S.SyncServer(a)

        class Flaky:
            def __init__(self): self.n = 0
            def request(self, req):
                self.n += 1
                if self.n > 3:
                    raise ConnectionError("cable pulled")
                return S.Loopback(srv).request(req)
        r = S.pull(b, w.t.id, Flaky(), w.ids["sansa"])
        self.assertFalse(r["ok"])
        r2 = S.pull(b, w.t.id, S.Loopback(srv), w.ids["sansa"])
        self.assertTrue(r2["ok"])
        self.assertEqual(vis(a, w.t.id), vis(b, w.t.id))

    def test_more_than_one_page_of_leaves_and_size_capped_responses(self):
        w = World()
        for n in range(S.LIST_PAGE + 40):                                                  # every post replies to the genesis only: all are leaves
            w.add(w.w("carol").post(str(n), parents=[w.t.id]))
        a = mirror_with(w.genesis, [w.t.events[i] for i in w.t.order[1:]])
        self.assertGreater(len(a.thread(w.t.id).sync_order()), S.LIST_PAGE)                 # two listing pages
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, w.t.id, S.Loopback(S.SyncServer(a)), w.ids["sansa"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(vis(a, w.t.id), vis(b, w.t.id))


class Authorization(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.add(self.w.w("sansa").post("private talk"))
        self.a = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        self.srv = S.SyncServer(self.a)
        self.tid = self.w.t.id

    def ask(self, ident, body=None, **kw):
        return self.srv.handle(S.sign_request(ident, body or {"t": "summary", "thread": self.tid, "page": 0}, **kw))

    def test_a_key_holder_cannot_push_the_replay_floor_ahead_of_the_servers_clock(self):
        now = [1_000_000]
        srv = S.SyncServer(self.a, clock=lambda: now[0])
        for name in ("RATE_PER_MIN", "GLOBAL_RATE_PER_MIN", "MEMBER_RATE_PER_MIN"):         # this test is about the floor, not the rate limit
            self.addCleanup(setattr, S, name, getattr(S, name))
            setattr(S, name, 10 ** 9)
        for _ in range(S.NONCES + 50):                                                      # valid requests dated at the far (future) edge of the window
            srv.handle(S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid, "page": 0}, ts=int(now[0]) + S.FUTURE_SKEW))
        self.assertLessEqual(srv.floor, now[0])
        now[0] += 2                                                                         # the clock moves on: the floor is behind it, not ahead
        r = srv.handle(S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid, "page": 0}, ts=now[0]))
        self.assertEqual(r["t"], "summary")                                                 # a legitimate request is not locked out

    def test_members_and_observers_may_read_strangers_and_removed_members_may_not(self):
        for who in ("sansa", "hu"):                                                        # a member and the observer
            self.assertEqual(self.ask(self.w.ids[who])["t"], "summary", who)
        self.assertEqual(self.ask(self.w.ids["eve"])["t"], "unknown")                      # a stranger: same answer as "no such thread"
        rm = self.w.w("arya").admin("member_remove", {"agent": self.w.ids["carol"].id})
        self.a.ingest(rm)
        self.assertEqual(self.ask(self.w.ids["carol"])["t"], "unknown")                    # removed: out
        self.assertEqual(self.srv.handle(S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": "0" * 32}))["t"], "unknown")

    def test_public_threads_are_readable_by_anyone(self):
        w = World(visibility="public")
        m = mirror_with(w.genesis, [])
        r = S.SyncServer(m).handle(S.sign_request(w.ids["eve"], {"t": "summary", "thread": w.t.id, "page": 0}))
        self.assertEqual(r["t"], "summary")

    def test_forgery_staleness_replay_and_rate(self):
        ok = S.sign_request(self.w.ids["sansa"], {"t": "summary", "thread": self.tid, "page": 0})
        bad = dict(ok, page=1)
        self.assertEqual(self.srv.handle(bad)["why"], "bad signature")
        other = S.sign_request(self.w.ids["eve"], {"t": "summary", "thread": self.tid, "page": 0})
        swapped = dict(other, **{"from": self.w.ids["sansa"].id})                          # eve's key claiming to be sansa
        self.assertEqual(self.srv.handle(swapped)["why"], "pub does not match from")
        borrowed = dict(ok, pub=self.w.ids["eve"].sign_pub)
        self.assertNotEqual(self.srv.handle(borrowed)["t"], "summary")
        self.assertIn("stale", self.ask(self.w.ids["sansa"], ts=int(time.time()) - 3600)["why"])
        self.assertEqual(self.srv.handle(ok)["t"], "summary")
        self.assertEqual(self.srv.handle(ok)["why"], "replayed request")
        old, S.RATE_PER_MIN = S.RATE_PER_MIN, 5
        try:
            res = [self.ask(self.w.ids["hu"])["t"] for _ in range(8)]
        finally:
            S.RATE_PER_MIN = old
        self.assertEqual(res.count("error"), 3)

    def test_garbage_requests_never_raise(self):
        for junk in (None, [], "x", 5, {}, {"t": "get"}, {"from": 1}, {"t": "get", "thread": self.tid, "ids": "no"}, {"t": "summary", "thread": {"a": 1}}):
            self.assertIn(self.srv.handle(junk)["t"], ("error", "unknown"))
        big = S.sign_request(self.w.ids["sansa"], {"t": "get", "thread": self.tid, "ids": ["a" * 32] * (S.MAX_IDS + 1)})
        self.assertEqual(self.srv.handle(big)["why"], "bad ids")
        bad_id = S.sign_request(self.w.ids["sansa"], {"t": "get", "thread": self.tid, "ids": ["../../etc/passwd"]})
        self.assertEqual(self.srv.handle(bad_id)["why"], "bad ids")

    def test_unresolved_and_waiting_events_are_never_served(self):
        w = World(visibility="public")
        root = w.post("arya", "who can help?")
        m = mirror_with(w.genesis, [w.t.events[root]])
        rq = Writer(w.ids["dave"], w.t).guest_request("private guest words", root)
        m.ingest(rq)                                                                       # waiting for admission: the owner's queue, not the thread
        parked = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "parked"}, parents=["9" * 32], seq=0, admin_ref=w.t.head)
        m.ingest(parked)
        srv = S.SyncServer(m)
        r = srv.handle(S.sign_request(w.ids["eve"], {"t": "get", "thread": w.t.id, "ids": [event_id(rq), event_id(parked), root]}))
        self.assertEqual([event_id(e) for e in r["events"]], [root])


class HostilePeer(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.add(self.w.w("sansa").post("x"))
        self.me = self.w.ids["sansa"]

    def transport(self, fn):
        class T:
            def request(self, req):
                resp = fn(req)
                return dict(resp, nonce=req["nonce"], r=1) if isinstance(resp, dict) and "nonce" not in resp else resp
        return T()

    def test_junk_events_stop_the_pull_and_are_not_stored(self):
        w = self.w
        good = w.t.events[w.t.order[1]]
        junk_id = Identity.generate("junk")

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": w.t.id, "head": w.t.head, "n": 999}
            if req["t"] == "list":
                return {"t": "list", "thread": w.t.id, "n": 2, "pages": 1, "ids": [w.t.id, event_id(good)]}
            evs = [w.genesis] if req["ids"] == [w.t.id] else [E.make_event(junk_id, thread=w.t.id, kind="post", body={"text": str(i)}, parents=[w.t.id],
                                                                                seq=i, admin_ref=w.t.head) for i in range(200)]
            return {"t": "events", "events": evs, "more": []}
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, w.t.id, self.transport(fn), self.me)
        self.assertFalse(r["ok"])
        self.assertIn("junk", r["why"])
        self.assertEqual(len(b.thread(w.t.id).stored), 1)                                  # only the (valid) genesis

    def test_responses_must_echo_our_nonce_and_carry_the_response_marker(self):
        w = self.w
        for tweak in ({"nonce": "0" * 32}, {"r": None}, {"r": 2}):
            class T:
                def request(self, req, tweak=tweak):
                    return dict({"t": "summary", "thread": w.t.id, "head": w.t.head, "n": 1, "nonce": req["nonce"], "r": 1}, **tweak)
            b = Mirror(tempfile.mkdtemp(), rate_limit=False)
            r = S.pull(b, w.t.id, T(), self.me)
            self.assertFalse(r["ok"], tweak)
            self.assertIn("does not answer", r["why"], tweak)

    def test_a_foreign_event_whose_id_the_listing_names_is_still_refused(self):
        w, other = self.w, World()
        foreign = other.w("carol").post("x")
        other.add(foreign)

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": w.t.id, "head": w.t.head, "n": 2}
            if req["t"] == "list":
                return {"t": "list", "thread": w.t.id, "n": 2, "pages": 1, "ids": [w.t.id, event_id(foreign)]}
            return {"t": "events", "events": [w.genesis if req["ids"] == [w.t.id] else foreign], "more": []}
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, w.t.id, self.transport(fn), self.me)
        self.assertEqual(r["fetched"], 1)                                                # only the genesis; the foreign event never reached the mirror
        self.assertEqual(len(b.thread(w.t.id).stored), 1)

    def test_total_deadline_and_request_cap_stop_a_pull(self):
        w = self.w
        honest_srv = mirror_with(w.genesis, [w.t.events[i] for i in w.t.order[1:]])
        tr = S.Loopback(S.SyncServer(honest_srv))
        now = [1000.0]

        def clock():
            now[0] += 100.0                                                              # every look at the clock costs 100 s
            return now[0]
        r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), w.t.id, tr, self.me, deadline=250, clock=clock)
        self.assertFalse(r["ok"])
        self.assertIn("deadline", r["why"])
        old, S.MAX_REQUESTS = S.MAX_REQUESTS, 2
        try:
            r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), w.t.id, tr, self.me)
        finally:
            S.MAX_REQUESTS = old
        self.assertFalse(r["ok"])
        self.assertIn("too many requests", r["why"])

    def test_responses_must_be_signed_by_the_peer_we_expect(self):
        w = self.w
        real = mirror_with(w.genesis, [w.t.events[i] for i in w.t.order[1:]])
        arya, impostor = w.ids["arya"], Identity.generate("impostor")

        def pull_from(identity, peer_id, mutate=None):
            srv = S.SyncServer(real, identity=identity)

            class T:
                def request(self_, req):
                    resp = srv.handle(req)
                    return mutate(resp) if mutate else resp
            b = Mirror(tempfile.mkdtemp(), rate_limit=False)
            return S.pull(b, w.t.id, T(), self.me, peer_id=peer_id), b
        r, b = pull_from(arya, arya.id)
        self.assertTrue(r["ok"], r)
        for name, (ident, mutate) in {"wrong key behind the right address": (impostor, None), "unsigned server": (None, None),
                                      "tampered body": (arya, lambda x: {**x, "n": 12345} if x.get("t") == "summary" else x),
                                      "signature stripped": (arya, lambda x: {k: v for k, v in x.items() if k != "rsig"}),
                                      "claims the right key, signs with another": (impostor, lambda x: {**x, "by": arya.sign_pub})}.items():
            r, b = pull_from(ident, arya.id, mutate)
            self.assertFalse(r["ok"], name)
            self.assertIn("not signed by the expected peer", r["why"], name)
            self.assertNotIn(w.t.id, b.threads, name)                                      # nothing from an unverified answerer is ever stored
        r, b = pull_from(None, None)
        self.assertTrue(r["ok"], "without an expected peer id the old behaviour stays")      # (the direct link authenticates by the shared key instead)

    def test_a_captured_signed_response_cannot_be_replayed_to_another_request(self):
        w = self.w
        real = mirror_with(w.genesis, [w.t.events[i] for i in w.t.order[1:]])
        srv = S.SyncServer(real, identity=w.ids["arya"])
        first = srv.handle(S.sign_request(self.me, {"t": "summary", "thread": w.t.id}, aud=w.ids["arya"].id))
        self.assertTrue(S.response_signed_by(first, w.ids["arya"].id))

        class Replay:
            def request(self_, req):
                return first                                                                # an old, genuinely signed answer
        r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), w.t.id, Replay(), self.me, peer_id=w.ids["arya"].id)
        self.assertFalse(r["ok"])
        self.assertIn("does not answer this request", r["why"])

    def test_a_notify_ack_must_answer_this_request(self):
        w = self.w
        b = mirror_with(w.genesis, [w.t.events[i] for i in w.t.order[1:]])
        cases = {"no r": lambda req: {"t": "ok", "nonce": req["nonce"]}, "r is True": lambda req: {"t": "ok", "nonce": req["nonce"], "r": True},
                 "wrong nonce": lambda req: {"t": "ok", "nonce": "0" * 16, "r": 1}, "no nonce": lambda req: {"t": "ok", "r": 1}}
        for name, fn in cases.items():
            class T:
                def request(self_, req, fn=fn):
                    return fn(req)
            self.assertFalse(S.notify(T(), self.me, w.t.id, b), name)
        class Good:
            def request(self_, req):
                return {"t": "ok", "nonce": req["nonce"], "r": 1}
        self.assertTrue(S.notify(Good(), self.me, w.t.id, b))

    def test_text_from_a_peer_reaches_the_result_as_printable_characters_only(self):
        w = self.w
        for why in ("\x1b[2J\x07bell\nFAKE LINE", {"a": "\x1b"}, ["x"], 5, "é" * 500):
            def fn(req, why=why):
                return {"t": "error", "why": why}
            r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), w.t.id, self.transport(fn), self.me)
            self.assertFalse(r["ok"])
            self.assertIsInstance(r["why"], str)
            self.assertTrue(r["why"].isprintable() and len(r["why"]) <= 200, repr(r["why"]))

    def test_the_rate_limited_retry_count_is_a_parameter(self):
        w = self.w
        seen = []

        def fn(req):
            seen.append(req["t"])
            return {"t": "error", "why": "rate limited"}
        r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), w.t.id, self.transport(fn), self.me, rate_retries=2, sleep=lambda s: None)
        self.assertFalse(r["ok"])
        self.assertEqual(len(seen), 3)                                                 # the first try and two retries, not 41

    def test_wrong_genesis_or_other_threads_events_are_refused(self):
        w, other = self.w, World()

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": w.t.id, "head": w.t.head, "n": 1}
            if req["t"] == "list":
                return {"t": "list", "thread": w.t.id, "n": 1, "pages": 1, "ids": [w.t.id]}
            return {"t": "events", "events": [other.genesis], "more": []}                # a genesis, but not the one that was asked for
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, w.t.id, self.transport(fn), self.me)
        self.assertFalse(r["ok"])
        self.assertNotIn(w.t.id, b.threads)

    def test_a_peer_that_lies_about_pages_or_never_delivers_cannot_hang_us(self):
        w = self.w
        b = mirror_with(w.genesis, [])
        calls = []

        def fn(req):
            calls.append(req["t"])
            if req["t"] == "summary":
                return {"t": "summary", "thread": w.t.id, "head": w.t.head, "n": 1}
            if req["t"] == "list":
                return {"t": "list", "thread": w.t.id, "n": 10 ** 9, "pages": 10 ** 9, "ids": ["ab" * 16]}
            return {"t": "events", "events": [], "more": []}                              # promises an event and never sends it
        t0 = time.time()
        r = S.pull(b, w.t.id, self.transport(fn), self.me)
        self.assertLess(time.time() - t0, 10)
        self.assertLessEqual(len(calls), S.MAX_LIST_PAGES + 10)
        self.assertFalse(r["ok"])                                                          # promised events that never came: not a success

    def test_transport_errors_and_malformed_responses_are_just_failures(self):
        b = mirror_with(self.w.genesis, [])
        for fn in (lambda r: (_ for _ in ()).throw(ConnectionError("x")), lambda r: None, lambda r: {"t": "summary"}, lambda r: {"t": "error", "why": "no"},
                   lambda r: {"t": "summary", "thread": self.w.t.id, "pages": "many", "leaves": "nope"}):
            r = S.pull(b, self.w.t.id, self.transport(fn), self.me)
            self.assertFalse(r["ok"])


class Tcp(unittest.TestCase):
    def setUp(self):
        self.w = World()
        for n in range(5):
            self.w.add(self.w.w("carol").post(str(n)))
        self.a = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        self.key = tcp.new_key()
        self.srv = tcp.TcpServer("127.0.0.1", 0, self.key, S.SyncServer(self.a).handle).start()
        self.addCleanup(self.srv.stop)

    def test_pull_over_a_real_socket(self):
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, self.w.t.id, tcp.TcpTransport("127.0.0.1", self.srv.port, self.key), self.w.ids["sansa"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(vis(self.a, self.w.t.id), vis(b, self.w.t.id))

    def test_wrong_key_gets_no_answer(self):
        with self.assertRaises(Exception):
            tcp.TcpTransport("127.0.0.1", self.srv.port, tcp.new_key(), timeout=2).request({"t": "summary"})

    def test_refuses_public_binds_and_oversized_or_slow_peers_do_not_block_others(self):
        with self.assertRaises(ValueError):
            tcp.TcpServer("8.8.8.8", 0, self.key, lambda r: r)
        old, tcp.DEADLINE = tcp.DEADLINE, 1.0
        try:
            slow = socket.create_connection(("127.0.0.1", self.srv.port))               # connects and says nothing
            huge = socket.create_connection(("127.0.0.1", self.srv.port))
            huge.sendall((10 ** 9).to_bytes(4, "big"))
            huge.settimeout(3)
            t0 = time.time()
            self.assertEqual(huge.recv(10), b"")                                         # the oversized frame got the connection closed...
            self.assertLess(time.time() - t0, 0.6)                                       # ...at once (not after waiting for a gigabyte)
            t1 = time.time()
            while self.srv.per_ip.get("127.0.0.1", 0) >= tcp.PER_IP_CONNS and time.time() - t1 < 3:
                time.sleep(0.02)                                                         # its slot is released after the close; the idle one still holds one of the 2
            b = Mirror(tempfile.mkdtemp(), rate_limit=False)
            r = S.pull(b, self.w.t.id, tcp.TcpTransport("127.0.0.1", self.srv.port, self.key), self.w.ids["sansa"])
            self.assertTrue(r["ok"], r)                                                  # served while the idle peer is still there
            slow.close(); huge.close()
        finally:
            tcp.DEADLINE = old

    def test_one_address_cannot_hold_more_than_the_connection_cap(self):
        held = [socket.create_connection(("127.0.0.1", self.srv.port)) for _ in range(tcp.PER_IP_CONNS)]     # idle, never send a header
        try:
            time.sleep(0.3)
            extra = socket.create_connection(("127.0.0.1", self.srv.port))
            extra.settimeout(1.0)
            self.assertEqual(extra.recv(10), b"")                                        # dropped at once, not queued behind the idle ones
            extra.close()
        finally:
            for h in held:
                h.close()

    def test_an_idle_connection_is_dropped_after_the_header_deadline_not_the_full_one(self):
        idle = socket.create_connection(("127.0.0.1", self.srv.port))
        try:
            idle.settimeout(tcp.DEADLINE)
            t0 = time.time()
            self.assertEqual(idle.recv(10), b"")
            self.assertLess(time.time() - t0, tcp.HEADER_DEADLINE + 1.5)
        finally:
            idle.close()

    def test_allowed_ips_restrict_who_is_served(self):
        for allowed, ok in (({"10.9.9.9"}, False), ({"127.0.0.1"}, True)):
            srv = tcp.TcpServer("127.0.0.1", 0, self.key, S.SyncServer(self.a).handle, allowed_ips=allowed).start()
            try:
                b = Mirror(tempfile.mkdtemp(), rate_limit=False)
                r = S.pull(b, self.w.t.id, tcp.TcpTransport("127.0.0.1", srv.port, self.key, timeout=3), self.w.ids["sansa"])
                self.assertEqual(r["ok"], ok, allowed)
            finally:
                srv.stop()

    def test_stale_frames_are_ignored(self):
        from cryptography.fernet import Fernet
        f = Fernet(self.key.encode())
        old = f.encrypt_at_time(b'{"t":"summary"}', int(time.time()) - 3600)
        with socket.create_connection(("127.0.0.1", self.srv.port)) as s:
            s.sendall(len(old).to_bytes(4, "big") + old)
            s.settimeout(3)
            self.assertEqual(s.recv(10), b"")                                             # replayed capture: dropped without an answer


class Cli(unittest.TestCase):
    def run_cli(self, home, *args, **kw):
        return subprocess.run([sys.executable, "-m", "sigilnet", "--home", home, *args], capture_output=True, text=True, cwd=ROOT,
                              env={**os.environ, "PYTHONPATH": ROOT}, **kw)

    def test_two_homes_over_the_direct_link(self):
        d = tempfile.mkdtemp()
        a, b = f"{d}/a", f"{d}/b"
        self.run_cli(a, "id", "init", "arya"); self.run_cli(b, "id", "init", "sansa")
        pub = self.run_cli(b, "id", "show", "--json").stdout
        Path(f"{d}/sansa.json").write_text(pub)
        out = self.run_cli(a, "new", "sync demo", "--member", f"member={d}/sansa.json").stdout
        tid = out.split("thread ")[1].split()[0]
        self.run_cli(a, "post", tid[:8], "hello from arya")
        self.assertEqual(self.run_cli(a, "key", "new", "--file", f"{d}/k").returncode, 0)
        self.assertEqual(oct(os.stat(f"{d}/k").st_mode & 0o777), "0o600")
        srv = subprocess.Popen([sys.executable, "-m", "sigilnet", "--home", a, "sync", "serve", "--host", "127.0.0.1", "--port", "0",
                                "--key-file", f"{d}/k", "--seconds", "25"], stdout=subprocess.PIPE, text=True, cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT})
        try:
            line = srv.stdout.readline()
            port = line.split("127.0.0.1:")[1].split()[0]
            arya_id = json.loads(self.run_cli(a, "id", "show", "--json").stdout)["agent"]
            r = self.run_cli(b, "sync", "pull", f"127.0.0.1:{port}", "--key-file", f"{d}/k", "--thread", tid)
            self.assertNotEqual(r.returncode, 0)                                              # the thread is encrypted (the default): without --peer-id no key can be fetched
            self.assertIn("--peer-id", r.stdout)
            r = self.run_cli(b, "sync", "pull", f"127.0.0.1:{port}", "--key-file", f"{d}/k", "--thread", tid, "--peer-id", arya_id)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            shown = self.run_cli(b, "show", tid[:8]).stdout
            self.assertIn("hello from arya", shown)
            # a second pull finds nothing new; a stranger's home is refused
            self.assertIn("fetched 0", self.run_cli(b, "sync", "pull", f"127.0.0.1:{port}", "--key-file", f"{d}/k", "--thread", tid[:8], "--peer-id", arya_id).stdout)
            self.run_cli(f"{d}/eve", "id", "init", "eve")
            r = self.run_cli(f"{d}/eve", "sync", "pull", f"127.0.0.1:{port}", "--key-file", f"{d}/k", "--thread", tid)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("hello from arya", self.run_cli(f"{d}/eve", "list").stdout)
        finally:
            srv.terminate(); srv.wait(5)


if __name__ == "__main__":
    unittest.main()
