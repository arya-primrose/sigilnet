"""#4 DESIGN_ping rev 1 from the FROZEN INTERFACE: handle_ping, Node.pong_snapshot, SyncServer(pong=), the doors. No node loop here."""
import fcntl
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import doors
from sigilnet import node as N
from sigilnet import ping, sync as S
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.inbox import Inbox
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.publicread import PublicRead
from sigilnet.tests.test_node import Sim

PONG_KEYS = {"t", "up", "unread", "watching", "v"}
ENVELOPE = {"nonce", "r", "by", "rsig"}                                   # what SyncServer._reply adds to every answer


def pong_sim(n=3):
    s = Sim(n)
    for x, nd in s.nodes.items():
        s.servers[x] = S.SyncServer(s.mirrors[x], clock=s.clock, on_notify=nd.on_notify, identity=s.ids[x],
                                    pong=lambda r, nd=nd: ping.handle_ping(nd.pong_snapshot(), r))
    return s


def signed(s, who, **kw):
    return S.sign_request(s.ids[who], {"t": "ping"}, ts=int(s.clock()), **kw)


def ask(s, callee, who, **kw):
    req = signed(s, who, **kw)
    return req, s.servers[callee].handle(json.loads(json.dumps(req)))


def body(resp):
    return {k: v for k, v in resp.items() if k not in ENVELOPE}


class Constants(unittest.TestCase):
    def test_documented_values(self):
        self.assertEqual((ping.PING_MIN_GAP, ping.PING_DEFAULT_TIMEOUT, ping.PING_MAX_TIMEOUT, ping.SNAPSHOT_EVERY, ping.WATCH_BEAT_EVERY, ping.WATCH_FRESH,
                          ping.STALE_FILE_AGE), (1.0, 15.0, 120.0, 2.0, 5.0, 30.0, 600.0))

    def test_result_and_error_types(self):
        self.assertTrue(issubclass(ping.PingError, ValueError))
        r = ping.PingResult(True, None, {}, 1.0, "n", "i")
        self.assertEqual(r._fields, ("ok", "why", "pong", "rtt_ms", "peer_name", "peer_id", "via", "ver"))      # (`ver`: versioning stage 1, the peer's declaration; default None)


class HandlePing(unittest.TestCase):
    A = "a" * 32
    B = "b" * 32
    SNAP = {"unread": {A: 3, B: 0}, "watching": True, "at": 1.0}

    def test_the_pong_has_exactly_the_pinned_keys(self):
        p = ping.handle_ping(self.SNAP, self.A)
        self.assertEqual(set(p), PONG_KEYS)
        self.assertEqual(p, {"t": "pong", "up": True, "unread": 3, "watching": True, "v": 1})
        self.assertIs(p["up"], True)
        self.assertIs(p["watching"], True)
        self.assertIs(type(p["unread"]), int)

    def test_unread_is_the_requesters_own_number(self):
        self.assertEqual(ping.handle_ping(self.SNAP, self.B)["unread"], 0)
        self.assertEqual(ping.handle_ping(self.SNAP, self.A)["unread"], 3)

    def test_a_requester_not_in_the_snapshot_gets_none(self):
        self.assertIsNone(ping.handle_ping(self.SNAP, "c" * 32))
        self.assertIsNone(ping.handle_ping({"unread": {}, "watching": False, "at": 0}, self.A))
        self.assertIsNone(ping.handle_ping({"unread": {}, "watching": True, "at": 0}, ""))

    def test_watching_false(self):
        p = ping.handle_ping({"unread": {self.A: 0}, "watching": False, "at": 0}, self.A)
        self.assertIs(p["watching"], False)

    def test_it_does_not_mutate_the_snapshot_and_returns_a_fresh_dict(self):
        snap = json.loads(json.dumps(self.SNAP))
        p1 = ping.handle_ping(snap, self.A)
        p1["unread"] = 99
        self.assertEqual(snap, json.loads(json.dumps(self.SNAP)))
        self.assertEqual(ping.handle_ping(snap, self.A)["unread"], 3)

    def test_nothing_else_leaks_into_the_pong(self):
        snap = {"unread": {self.A: 1}, "watching": True, "at": 5.0, "threads": ["t1"], "secret": "x"}
        self.assertEqual(set(ping.handle_ping(snap, self.A)), PONG_KEYS)


class Snapshot(unittest.TestCase):
    def test_unread_counts_only_threads_the_requester_is_in(self):
        """THE side channel: a private thread between me and a third agent must never move a number another agent sees."""
        s = pong_sim(3)
        s.post("arya", "one")                                              # thread tid: arya (owner), sansa, carol are members
        for _ in range(8):
            s.step(1.0)
        nd = s.nodes["sansa"]
        a, c = s.ids["arya"].id, s.ids["carol"].id
        base = nd.pong_snapshot()["unread"]
        self.assertGreaterEqual(base[a], 1)
        t2 = make_genesis(s.ids["carol"], "just us", [(s.ids["sansa"], "member")])
        m = s.mirrors["sansa"]
        m.follow = None                                                    # (the node only follows threads it was told about)
        self.assertTrue(m.ingest(t2).ok)
        tid2 = event_id(t2)
        for k in range(4):
            self.assertTrue(m.ingest(Writer(s.ids["carol"], m.threads[tid2]).post(f"secret {k}")).ok)
        s.clock.t += ping.SNAPSHOT_EVERY + 0.5
        snap = nd.pong_snapshot()["unread"]
        self.assertEqual(snap[c], base[c] + 4, "carol shares the new thread: her count moves")
        self.assertEqual(snap[a], base[a], "arya is not in the new thread: her number must not move")

    def test_unread_equals_the_sum_of_mirror_unread_over_the_shared_threads(self):
        s = pong_sim(2)
        for k in range(3):
            s.post("arya", f"p{k}")
        for _ in range(8):
            s.step(1.0)
        nd = s.nodes["sansa"]
        m = s.mirrors["sansa"]
        s.clock.t += ping.SNAPSHOT_EVERY + 0.5
        want = sum(len(m.unread(tid, s.ids["sansa"].id)) for tid, t in m.threads.items() if s.ids["arya"].id in t.state()["members"])
        self.assertEqual(nd.pong_snapshot()["unread"][s.ids["arya"].id], want)
        self.assertGreaterEqual(want, 3)

    def test_reading_lowers_the_number_after_the_snapshot_expires(self):
        s = pong_sim(2)
        s.post("arya", "p")
        for _ in range(8):
            s.step(1.0)
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        s.clock.t += ping.SNAPSHOT_EVERY + 0.5
        self.assertGreaterEqual(nd.pong_snapshot()["unread"][a], 1)
        s.mirrors["sansa"].mark_read(s.tid)
        s.clock.t += ping.SNAPSHOT_EVERY + 0.5
        self.assertEqual(nd.pong_snapshot()["unread"][a], 0)

    def test_the_snapshot_is_cached_for_snapshot_every_seconds(self):
        s = pong_sim(2)
        s.post("arya", "p")
        for _ in range(8):
            s.step(1.0)
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        s.clock.t += ping.SNAPSHOT_EVERY + 0.5
        first = nd.pong_snapshot()
        s.mirrors["sansa"].mark_read(s.tid)
        s.clock.t += ping.SNAPSHOT_EVERY * 0.5
        self.assertEqual(nd.pong_snapshot()["unread"][a], first["unread"][a], "recomputed before SNAPSHOT_EVERY")
        s.clock.t += ping.SNAPSHOT_EVERY * 0.6
        self.assertEqual(nd.pong_snapshot()["unread"][a], 0)

    def test_the_snapshot_shape_and_time(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        snap = nd.pong_snapshot()
        self.assertTrue({"unread", "watching", "at"} <= set(snap))
        self.assertIsInstance(snap["unread"], dict)
        self.assertIsInstance(snap["watching"], bool)
        self.assertAlmostEqual(snap["at"], s.clock(), delta=1.0)

    def test_only_peers_in_the_book_are_in_the_snapshot(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        self.assertEqual(set(nd.pong_snapshot()["unread"]), {s.ids["arya"].id})

    def test_watching_follows_watch_beat(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        home = s.homes["sansa"]
        beat = home / "watch.beat"

        def at(age):
            beat.write_text("x")
            t = s.clock() - age
            os.utime(beat, (t, t))
            s.clock.t += ping.SNAPSHOT_EVERY + 0.5
            return nd.pong_snapshot()["watching"]

        s.clock.t += 10
        self.assertFalse(nd.pong_snapshot()["watching"])                   # no beat file
        self.assertTrue(at(1.0))
        self.assertTrue(at(ping.WATCH_FRESH - 5))
        self.assertFalse(at(ping.WATCH_FRESH + 5))

    def test_a_symlinked_watch_beat_is_not_followed(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        home = s.homes["sansa"]
        target = home / "elsewhere"
        target.write_text("x")                                               # the TARGET is fresh ...
        t = s.clock() - 500
        os.utime(target, (s.clock() - 1, s.clock() - 1))
        os.symlink(target, home / "watch.beat")
        os.utime(home / "watch.beat", (t, t), follow_symlinks=False)          # ... the link itself is old: lstat + mtime only
        s.clock.t += 10
        self.assertFalse(nd.pong_snapshot()["watching"])


class ServerPing(unittest.TestCase):
    def test_a_known_peer_gets_a_pong_with_the_pinned_keys(self):
        s = pong_sim(2)
        req, resp = ask(s, "sansa", "arya")
        self.assertEqual(resp.get("t"), "pong", resp)
        self.assertEqual(set(body(resp)), PONG_KEYS)
        self.assertEqual(resp["nonce"], req["nonce"])
        self.assertEqual(resp.get("r"), 1)

    def test_the_pong_is_signed_by_the_node(self):
        s = pong_sim(2)
        _, resp = ask(s, "sansa", "arya")
        self.assertEqual(resp.get("by"), s.ids["sansa"].sign_pub)
        self.assertTrue(resp.get("rsig"))

    def test_an_unknown_requester_gets_exactly_the_strangers_answer(self):
        s = pong_sim(2)
        eve = Identity.generate("eve")
        req = S.sign_request(eve, {"t": "ping"}, ts=int(s.clock()))
        resp = s.servers["sansa"].handle(json.loads(json.dumps(req)))
        want = s.servers["sansa"].refuse(json.loads(json.dumps(req)))
        self.assertEqual(resp, want)
        self.assertNotIn("up", resp)

    def test_a_server_without_a_pong_callable_gives_the_strangers_answer(self):
        s = Sim(2)                                                           # the stock servers: no pong=
        req = signed(s, "arya")
        resp = s.servers["sansa"].handle(json.loads(json.dumps(req)))
        self.assertEqual(resp, s.servers["sansa"].refuse(json.loads(json.dumps(req))))

    def test_a_bad_signature_is_an_error_like_every_other_request(self):
        s = pong_sim(2)
        req = signed(s, "arya")
        req["sig"] = "0" * 128
        resp = s.servers["sansa"].handle(json.loads(json.dumps(req)))
        self.assertEqual(resp.get("t"), "error")
        self.assertNotEqual(resp.get("t"), "pong")

    def test_a_replayed_ping_is_refused(self):
        s = pong_sim(2)
        req = signed(s, "arya")
        r1 = s.servers["sansa"].handle(json.loads(json.dumps(req)))
        s.clock.t += 2 * ping.PING_MIN_GAP
        r2 = s.servers["sansa"].handle(json.loads(json.dumps(req)))
        self.assertEqual(r1.get("t"), "pong")
        self.assertEqual((r2.get("t"), r2.get("why")), ("error", "replayed request"))

    def test_a_stale_ping_is_refused(self):
        s = pong_sim(2)
        req = S.sign_request(s.ids["arya"], {"t": "ping"}, ts=int(s.clock()) - 100000)
        resp = s.servers["sansa"].handle(json.loads(json.dumps(req)))
        self.assertEqual(resp.get("t"), "error")

    def test_a_ping_for_a_node_with_another_audience_is_refused(self):
        s = pong_sim(2)
        req = S.sign_request(s.ids["arya"], {"t": "ping"}, ts=int(s.clock()), aud=Identity.generate("x").id)
        resp = s.servers["sansa"].handle(json.loads(json.dumps(req)))
        self.assertEqual(resp.get("t"), "error")

    def test_one_answered_ping_per_peer_per_ping_min_gap(self):
        s = pong_sim(3)
        _, r1 = ask(s, "sansa", "arya")
        _, r2 = ask(s, "sansa", "arya")
        self.assertEqual(r1.get("t"), "pong")
        self.assertEqual((r2.get("t"), r2.get("why")), ("error", "rate limited"))
        _, other = ask(s, "sansa", "carol")                                  # the gap is per requester
        self.assertEqual(other.get("t"), "pong")
        s.clock.t += ping.PING_MIN_GAP + 0.01
        _, r3 = ask(s, "sansa", "arya")
        self.assertEqual(r3.get("t"), "pong")

    def test_the_gap_constant_is_read_at_call_time(self):
        s = pong_sim(2)
        with mock.patch.object(ping, "PING_MIN_GAP", 10.0):
            ask(s, "sansa", "arya")
            s.clock.t += 5
            _, r = ask(s, "sansa", "arya")
            self.assertEqual(r.get("why"), "rate limited")
            s.clock.t += 6
            _, r = ask(s, "sansa", "arya")
            self.assertEqual(r.get("t"), "pong")

    def test_a_flood_of_pings_is_bounded_and_the_rest_are_rate_limited(self):
        s = pong_sim(2)
        got = {"pong": 0, "rate limited": 0, "other": 0}
        for i in range(100):
            _, r = ask(s, "sansa", "arya")
            if r.get("t") == "pong":
                got["pong"] += 1
            elif r.get("why") == "rate limited":
                got["rate limited"] += 1
            else:
                got["other"] += 1
        self.assertEqual(got["pong"], 1, got)
        self.assertEqual(got["other"], 0, got)

    def test_a_ping_is_answered_while_another_process_holds_the_mirror_lock(self):
        """P1: the ping path never takes the Mirror lock (and does not refresh every thread)."""
        s = pong_sim(2)
        s.nodes["sansa"].pong_snapshot()                                     # warm the cache like a node round would
        fd = os.open(s.homes["sansa"] / "mirror" / "mirror.lock", os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        out = {}
        th = threading.Thread(target=lambda: out.update(r=ask(s, "sansa", "arya")[1]))
        th.start()
        th.join(3.0)
        alive = th.is_alive()
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        th.join(5)
        self.assertFalse(alive, "the ping blocked on the Mirror lock")
        self.assertEqual(out["r"].get("t"), "pong")

    def test_a_ping_never_refreshes_or_reads_the_mirror(self):
        s = pong_sim(2)
        s.nodes["sansa"].pong_snapshot()
        m = s.mirrors["sansa"]
        with mock.patch.object(Mirror, "refresh", side_effect=AssertionError("refresh")), mock.patch.object(Mirror, "_refresh", side_effect=AssertionError("_refresh")), \
                mock.patch.object(Mirror, "unread", side_effect=AssertionError("unread")):
            _, r = ask(s, "sansa", "arya")
        self.assertEqual(r.get("t"), "pong")


class Doors(unittest.TestCase):
    def setUp(self):
        self.s = pong_sim(3)
        self.srv = self.s.servers["sansa"]

    def req(self, who):
        return json.loads(json.dumps(signed(self.s, who)))

    def test_the_peer_door_bound_to_arya_answers_arya_and_refuses_carol(self):
        h = doors.door_handler("peer", self.s.ids["arya"].id, self.srv, {})
        self.assertEqual(h(self.req("arya")).get("t"), "pong")
        r = self.req("carol")
        self.assertEqual(h(r), self.srv.refuse(r))                          # carol is a known peer too, but THIS door is arya's

    def test_a_peer_door_bound_to_nobody_still_needs_a_known_requester(self):
        h = doors.door_handler("peer", None, self.srv, {})
        eve = S.sign_request(Identity.generate("eve"), {"t": "ping"}, ts=int(self.s.clock()))
        eve = json.loads(json.dumps(eve))
        self.assertEqual(h(eve), self.srv.refuse(eve))
        self.assertEqual(h(self.req("arya")).get("t"), "pong")

    def test_the_read_door_never_answers_a_ping(self):
        pr = PublicRead(self.srv)
        h = doors.door_handler("read", None, self.srv, {"read": pr.handle})
        r = self.req("arya")
        resp = h(r)
        self.assertNotEqual(resp.get("t"), "pong")
        self.assertNotIn("up", resp)

    def test_the_inbox_door_never_answers_a_ping(self):
        ib = Inbox(self.s.mirrors["sansa"], self.s.homes["sansa"])
        h = doors.door_handler("inbox", None, self.srv, {"inbox": ib.handle})
        resp = h(self.req("arya"))
        self.assertNotEqual(resp.get("t"), "pong")
        self.assertNotIn("up", resp)

    def test_a_kind_without_a_handler_answers_nothing_useful(self):
        h = doors.door_handler("join", None, self.srv, {})
        r = self.req("arya")
        self.assertEqual(h(r), self.srv.refuse(r))

    def test_the_read_door_answer_to_a_ping_equals_its_answer_to_any_unknown_type(self):
        pr = PublicRead(self.srv)
        r = self.req("arya")
        other = json.loads(json.dumps(S.sign_request(self.s.ids["arya"], {"t": "frobnicate"}, ts=int(self.s.clock()))))
        a, b = pr.handle(r), pr.handle(other)
        strip = lambda d: {k: v for k, v in d.items() if k not in ENVELOPE}
        self.assertEqual(strip(a), strip(b))


if __name__ == "__main__":
    unittest.main()
