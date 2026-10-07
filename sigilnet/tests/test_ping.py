"""DESIGN_ping.md rev 1: blocking ping answered by the node (handle_ping, SyncServer pong path, Node.pong_snapshot, PingService, ping_peer, CLI, watch beat)."""
import fcntl
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import ping as P
from sigilnet import sync as S
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.tests.test_node import Sim, ep


def wire(s):
    """Every server of the Sim answers pings from its node's cached snapshot."""
    for x in s.nodes:
        s.servers[x].pong = s.nodes[x].pong_for
    return s


class Snap(unittest.TestCase):
    def test_handle_ping_gives_the_five_keys_for_a_known_requester(self):
        snap = {"unread": {"A": 3}, "watching": True, "at": 1.0}
        self.assertEqual(P.handle_ping(snap, "A"), {"t": "pong", "up": True, "unread": 3, "watching": True, "v": 1})

    def test_handle_ping_is_none_for_strangers_and_garbage(self):
        snap = {"unread": {"A": 3}, "watching": False, "at": 1.0}
        self.assertIsNone(P.handle_ping(snap, "B"))
        self.assertIsNone(P.handle_ping(snap, None))
        self.assertIsNone(P.handle_ping(None, "A"))
        self.assertIsNone(P.handle_ping({"unread": []}, "A"))
        self.assertEqual(P.handle_ping({"unread": {"A": -1}, "watching": 1}, "A"), {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1})
        self.assertEqual(P.handle_ping({"unread": {"A": True}}, "A")["unread"], 0)

    def test_constants(self):
        self.assertEqual((P.PING_MIN_GAP, P.PING_DEFAULT_TIMEOUT, P.PING_MAX_TIMEOUT, P.SNAPSHOT_EVERY, P.WATCH_BEAT_EVERY, P.WATCH_FRESH, P.STALE_FILE_AGE),
                         (1.0, 15.0, 120.0, 2.0, 5.0, 30.0, 600.0))

    def test_watching_is_a_fresh_regular_beat_by_its_own_mtime(self):
        d = Path(tempfile.mkdtemp())
        now = time.time()
        self.assertFalse(P.watching(d, now))
        P.beat(d)
        self.assertTrue(P.watching(d, time.time()))
        self.assertTrue(P.watching(d, time.time() + P.WATCH_FRESH - 2))
        self.assertFalse(P.watching(d, time.time() + P.WATCH_FRESH + 2))
        self.assertFalse(P.watching(d, time.time() - P.WATCH_FRESH - 2))             # a beat from the far future is not believed either

    def test_a_symlinked_beat_counts_by_the_links_own_mtime(self):
        d = Path(tempfile.mkdtemp())
        (d / "target").write_bytes(b"x")                                            # fresh target
        os.symlink(d / "target", d / "watch.beat")
        os.utime(d / "watch.beat", ns=(1_000_000_000, 1_000_000_000), follow_symlinks=False)    # old link
        self.assertFalse(P.watching(d, time.time()))

    def test_beat_is_the_safe_writer(self):
        d = Path(tempfile.mkdtemp())
        P.beat(d)
        P.beat(d)
        self.assertEqual((d / "watch.beat").read_bytes(), b"xx")
        self.assertEqual((d / "watch.beat").stat().st_mode & 0o777, 0o600)


class ServerPath(unittest.TestCase):
    def setUp(self):
        self.s = wire(Sim(2))
        self.s.post("arya", "x")
        self.s.step(1, 3)
        self.s.post("sansa", "y")
        self.s.step(1, 3)
        self.a, self.b = self.s.ids["arya"], self.s.ids["sansa"]
        self.srv = self.s.servers["arya"]                                          # arya answers sansa's pings
        self.s.nodes["arya"].pong_snapshot(force=True)

    def ask(self, me=None, srv=None, ts=None):
        me = me or self.b
        req = S.sign_request(me, {"t": "ping"}, ts=int(self.s.clock() if ts is None else ts), aud=self.a.id)
        return req, (srv or self.srv).handle(json.loads(json.dumps(req)))

    def test_a_known_peer_gets_a_signed_pong(self):
        req, r = self.ask()
        self.assertEqual({k: r[k] for k in P.PONG_KEYS}, {"t": "pong", "up": True, "unread": 1, "watching": False, "v": 1})
        ok, why, pong = P.check_pong(r, req["nonce"], self.a.id)
        self.assertTrue(ok, why)
        self.assertEqual(set(pong), P.PONG_KEYS)

    def test_a_stranger_gets_exactly_the_refusal(self):
        eve = Identity.generate("eve")
        req, r = self.ask(me=eve)
        self.assertEqual(r, self.srv.refuse(req))
        self.assertEqual(r["t"], "unknown")

    def test_a_server_without_pong_refuses(self):
        self.srv.pong = None
        req, r = self.ask()
        self.assertEqual(r, self.srv.refuse(req))

    def test_a_pong_callable_that_raises_is_the_refusal(self):
        def boom(who):
            raise RuntimeError("boom")
        self.srv.pong = boom
        req, r = self.ask()
        self.assertEqual(r, self.srv.refuse(req))

    def test_the_usual_checks_come_first(self):
        req = S.sign_request(self.b, {"t": "ping"}, ts=int(self.s.clock()) - 100000, aud=self.a.id)
        self.assertEqual(self.srv.handle(req)["why"], "stale request (check clocks)")
        req = S.sign_request(self.b, {"t": "ping"}, ts=int(self.s.clock()), aud="f" * 32)
        self.assertEqual(self.srv.handle(req)["why"], "wrong audience")
        req = S.sign_request(self.b, {"t": "ping"}, ts=int(self.s.clock()), aud=self.a.id)
        req["sig"] = "0" * 128
        self.assertEqual(self.srv.handle(req)["why"], "bad signature")
        req = S.sign_request(self.b, {"t": "ping"}, ts=int(self.s.clock()) + 1, aud=self.a.id)
        self.assertEqual(self.srv.handle(dict(req))["t"], "pong")
        self.assertEqual(self.srv.handle(dict(req))["why"], "replayed request")

    def test_one_answered_ping_per_second_per_requester(self):
        self.ask()
        _, r = self.ask()
        self.assertEqual(r["why"], "rate limited")
        self.s.clock.t += P.PING_MIN_GAP
        self.assertEqual(self.ask()[1]["t"], "pong")

    def test_the_gap_counter_is_per_requester_and_a_stranger_does_not_use_it_up(self):
        self.ask(me=Identity.generate("eve"))
        self.assertEqual(self.ask()[1]["t"], "pong")

    def test_a_clock_that_stepped_back_does_not_lock_the_requester_out(self):
        self.srv.ping_at[self.b.id] = self.s.clock() + 100
        self.assertEqual(self.ask()[1]["t"], "pong")

    def test_the_pong_callables_dict_is_not_changed_and_carries_no_stale_nonce(self):
        shared = {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1}
        self.srv.pong = lambda who: shared
        req, r = self.ask()
        self.assertEqual(shared, {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1})
        self.s.clock.t += 2
        req2, r2 = self.ask()
        self.assertEqual(r2["nonce"], req2["nonce"])
        self.assertNotEqual(r["nonce"], r2["nonce"])

    def test_a_pong_callable_that_raises_anything_is_the_refusal_not_an_error(self):
        for exc in (RuntimeError("x"), KeyError("k"), ValueError("v")):
            def boom(who, e=exc):
                raise e
            self.srv.pong = boom
            req, r = self.ask()
            self.assertEqual(r, self.srv.refuse(req), repr(exc))
            self.s.clock.t += 2

    def test_the_ping_log_hears_answered_and_refused_but_not_rate_limited(self):
        notes = []
        self.srv.ping_log = lambda who, what: notes.append((who, what))
        self.ask()
        self.ask()                                                                      # rate limited: no note
        self.s.clock.t += 2
        self.ask(me=Identity.generate("eve"))
        self.assertEqual(notes, [(self.b.id, "answered"), (notes[1][0], "refused")])
        self.assertNotEqual(notes[1][0], self.b.id)

    def test_a_ping_log_that_raises_changes_nothing(self):
        def boom(who, what):
            raise RuntimeError("log")
        self.srv.ping_log = boom
        self.assertEqual(self.ask()[1]["t"], "pong")
        self.s.clock.t += 2
        req, r = self.ask(me=Identity.generate("eve"))
        self.assertEqual(r, self.srv.refuse(req))

    def test_no_ping_log_is_fine(self):
        self.srv.ping_log = None
        self.assertEqual(self.ask()[1]["t"], "pong")

    def test_the_gap_constant_is_read_at_call_time(self):
        with mock.patch.object(P, "PING_MIN_GAP", 0.0):
            self.ask()
            self.assertEqual(self.ask()[1]["t"], "pong")

    def test_the_gap_table_stays_bounded(self):
        for i in range(1100):
            self.srv.ping_at[f"{i:032x}"] = self.s.clock() - 1000
        self.ask()
        self.assertLess(len(self.srv.ping_at), 10)

    def test_a_ping_never_takes_the_mirror_lock(self):
        fd = os.open(self.s.mirrors["arya"].lockf, os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)                                              # another process holds the lock
        try:
            done = []
            t = threading.Thread(target=lambda: done.append(self.ask()[1]["t"]), daemon=True)
            t.start()
            t.join(2)
            self.assertEqual(done, ["pong"])
            with mock.patch.object(Mirror, "_refresh", side_effect=AssertionError("refresh")), mock.patch.object(Mirror, "unread", side_effect=AssertionError("unread")):
                self.s.clock.t += 2
                self.assertEqual(self.ask()[1]["t"], "pong")
        finally:
            os.close(fd)

    def test_the_pong_reply_is_bound_to_the_nonce_and_signed(self):
        req, r = self.ask()
        self.assertEqual(r["nonce"], req["nonce"])
        self.assertEqual(r["r"], 1)
        self.assertTrue(S.response_signed_by(r, self.a.id))


class PingLog(unittest.TestCase):
    def test_answered_lines_have_the_id_prefix_and_refused_ones_are_throttled(self):
        lines, t = [], [100.0]
        log = P.make_ping_log(lines.append, clock=lambda: t[0])
        log("abcdefghijklmnop", "answered")
        log("abcdefghijklmnop", "answered")
        log("zzzzzzzzzzzz", "refused")
        t[0] += 59
        log("yyyyyyyyyyyy", "refused")
        t[0] += 2
        log("xxxxxxxxxxxx", "refused")
        self.assertEqual(lines, ["ping from abcdefgh answered", "ping from abcdefgh answered", "ping from zzzzzzzz refused", "ping from xxxxxxxx refused"])

    def test_a_clock_that_stepped_back_does_not_silence_refused_lines(self):
        lines, t = [], [100.0]
        log = P.make_ping_log(lines.append, clock=lambda: t[0])
        log("aaaaaaaaaa", "refused")
        t[0] = 10.0
        log("bbbbbbbbbb", "refused")
        self.assertEqual(len(lines), 2)

    def test_the_gap_is_a_parameter(self):
        lines, t = [], [0.0]
        log = P.make_ping_log(lines.append, clock=lambda: t[0], refused_gap=5.0)
        log("aaaaaaaaaa", "refused")
        t[0] = 6.0
        log("bbbbbbbbbb", "refused")
        self.assertEqual(len(lines), 2)


class CheckPong(unittest.TestCase):
    def setUp(self):
        self.srv_id = Identity.generate("srv")
        self.me = Identity.generate("me")
        self.srv = S.SyncServer(mock.Mock(), identity=self.srv_id)
        self.req = S.sign_request(self.me, {"t": "ping"}, aud=self.srv_id.id)

    def reply(self, **kw):
        body = {"t": "pong", "up": True, "unread": 2, "watching": True, "v": 1}
        body.update(kw)
        return self.srv._reply(self.req, {k: v for k, v in body.items() if v is not ...})

    def check(self, resp):
        return P.check_pong(resp, self.req["nonce"], self.srv_id.id)

    def test_a_good_pong(self):
        ok, why, pong = self.check(self.reply())
        self.assertEqual((ok, why, pong), (True, None, {"t": "pong", "up": True, "unread": 2, "watching": True, "v": 1}))

    def test_bad_shapes(self):
        for kw in ({"up": False}, {"up": 1}, {"unread": -1}, {"unread": True}, {"unread": 10 ** 12}, {"watching": 1}, {"watching": None},
                   {"v": 2}, {"v": True}, {"t": "ok"}, {"extra": "x" * 1000}, {"unread": ...}, {"watching": ...}, {"up": ...}, {"v": ...}):
            ok, why, pong = self.check(self.reply(**kw))
            self.assertEqual((ok, why, pong), (False, "bad answer", None), kw.keys())

    def test_the_bound_and_the_edges(self):
        self.assertTrue(self.check(self.reply(unread=0))[0])
        self.assertTrue(self.check(self.reply(unread=P.MAX_UNREAD))[0])
        self.assertFalse(self.check(self.reply(unread=P.MAX_UNREAD + 1))[0])

    def test_not_a_dict_wrong_nonce_unsigned_or_signed_by_someone_else(self):
        self.assertEqual(self.check("pong")[1], "bad answer")
        self.assertEqual(self.check(None)[1], "bad answer")
        r = self.reply()
        r["nonce"] = "0" * 16
        self.assertEqual(self.check(r)[1], "bad answer")
        r = self.reply()
        r["r"] = 2
        self.assertEqual(self.check(r)[1], "bad answer")
        plain = S.SyncServer(mock.Mock())._reply(self.req, {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1})
        self.assertEqual(self.check(plain)[1], "bad answer")                          # unsigned
        other = S.SyncServer(mock.Mock(), identity=Identity.generate("imp"))._reply(self.req, {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1})
        self.assertEqual(self.check(other)[1], "bad answer")                           # an impostor behind the address

    def test_unknown_from_the_peer_is_not_authorized_but_only_if_it_is_really_the_peer(self):
        self.assertEqual(self.check(self.srv.refuse(self.req))[1], "refused: not authorized")
        imp = S.SyncServer(mock.Mock(), identity=Identity.generate("imp")).refuse(self.req)
        self.assertEqual(self.check(imp)[1], "bad answer")

    def test_a_valid_pong_for_another_request_is_not_ours(self):
        other = S.sign_request(self.me, {"t": "ping"}, aud=self.srv_id.id)
        old = self.srv._reply(other, {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1})        # signed, but bound to ANOTHER nonce (a replay)
        self.assertEqual(self.check(old), (False, "bad answer", None))

    def test_a_signed_answer_that_is_not_marked_as_a_response_is_not_an_answer(self):
        from sigilnet.sync import RESP_CTX
        from sigilnet import canon
        for r in (0, 2, "1", None, True):
            body = {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1, "nonce": self.req["nonce"], "r": r, "by": self.srv_id.sign_pub}
            if r is None:
                del body["r"]
            body["rsig"] = self.srv_id.sign(RESP_CTX + canon.dumps(body))
            self.assertEqual(self.check(body)[1], "bad answer", r)

    def test_error_answers_are_bad_answers(self):
        self.assertEqual(self.check(self.srv._err(self.req, "rate limited"))[1], "bad answer")


class Exchange(unittest.TestCase):
    def setUp(self):
        self.srv_id, self.me = Identity.generate("srv"), Identity.generate("me")

    def tr(self, exc=None, resp=None):
        class T:
            def request(s, req):
                if exc is not None:
                    raise exc
                return resp(req) if callable(resp) else resp
        return T()

    def test_reasons_from_the_dial_exception(self):
        for exc, why in ((ConnectionRefusedError(111, "Connection refused"), "connect refused"), (TimeoutError(), "timed out"), (OSError("timed out"), "timed out"),
                         (RuntimeError("socket.timeout (TimeoutError)"), "timed out"), (OSError("no route"), "connect refused"), (RuntimeError("boom"), "bad answer")):
            ok, w, pong, rtt = P.exchange(self.tr(exc=exc), self.me, self.srv_id.id)
            self.assertEqual((ok, w, pong, rtt), (False, why, None, None), repr(exc))

    def test_carrier_errors(self):
        from sigilnet.carrier import CarrierError
        self.assertEqual(P.exchange(self.tr(exc=CarrierError("tor could not reach the onion service", retry=True)), self.me, self.srv_id.id)[1], "connect refused")

    def test_a_door_that_does_not_know_our_key_is_not_authorized_not_connect_refused(self):
        from sigilnet.carrier import CarrierError
        for text in ("not admitted (or the door went away)", "the door needs a credential and none is held", "onion service needs authentication"):
            for retry in (True, False):
                self.assertEqual(P.exchange(self.tr(exc=CarrierError(text, retry=retry)), self.me, self.srv_id.id)[1], "refused: not authorized", text)

    def test_a_pin_mismatch_or_a_foreign_protocol_is_a_bad_answer(self):
        from sigilnet.carrier import CarrierError
        for text in ("door key does not match the endpoint", "the door did not speak the tcp carrier protocol"):
            self.assertEqual(P.exchange(self.tr(exc=CarrierError(text, retry=False)), self.me, self.srv_id.id)[1], "bad answer", text)

    def test_other_carrier_errors_stay_connect_refused_and_timeouts_win(self):
        from sigilnet.carrier import CarrierError
        for text in ("tcp connect to 10.0.0.1:47600 failed (Connection refused)", "tor could not reach the onion service: descriptor cannot be found", "the credential held for this door is damaged"):
            self.assertEqual(P.exchange(self.tr(exc=CarrierError(text, retry=True)), self.me, self.srv_id.id)[1], "connect refused", text)
        self.assertEqual(P.exchange(self.tr(exc=CarrierError("not admitted: timed out", retry=True)), self.me, self.srv_id.id)[1], "timed out")
        self.assertEqual(P.exchange(self.tr(exc=OSError("not admitted")), self.me, self.srv_id.id)[1], "connect refused")      # (only a CarrierError says it)

    def test_a_good_exchange_has_a_monotonic_rtt(self):
        srv = S.SyncServer(mock.Mock(), identity=self.srv_id, pong=lambda who: {"t": "pong", "up": True, "unread": 4, "watching": False, "v": 1})
        srv.m = mock.Mock()
        ok, why, pong, rtt = P.exchange(self.tr(resp=lambda req: (time.sleep(0.05), srv.handle(json.loads(json.dumps(req))))[1]), self.me, self.srv_id.id)
        self.assertTrue(ok, why)
        self.assertEqual(pong["unread"], 4)
        self.assertGreaterEqual(rtt, 50.0)
        self.assertLess(rtt, 500.0)

    def test_a_failed_exchange_has_no_rtt_even_when_the_peer_answered(self):
        srv = S.SyncServer(mock.Mock(), identity=self.srv_id)
        ok, why, pong, rtt = P.exchange(self.tr(resp=lambda req: srv.refuse(req)), self.me, self.srv_id.id)
        self.assertEqual((ok, why, pong, rtt), (False, "refused: not authorized", None, None))

    def test_a_rate_limited_answer_is_asked_again_once_after_the_gap(self):
        calls, slept = [], []
        srv = S.SyncServer(mock.Mock(), identity=self.srv_id)

        def resp(req):
            calls.append(1)
            if len(calls) == 1:
                return srv._err(req, "rate limited")
            return srv._reply(req, {"t": "pong", "up": True, "unread": 1, "watching": False, "v": 1})
        now = time.time()
        r = P.exchange(self.tr(resp=resp), self.me, self.srv_id.id, deadline=now + 10, sleep=slept.append)
        self.assertTrue(r[0], r)
        self.assertEqual(len(calls), 2)
        self.assertGreaterEqual(slept[0], P.PING_MIN_GAP)

    def test_no_second_try_without_room_before_the_deadline_or_for_other_errors(self):
        srv = S.SyncServer(mock.Mock(), identity=self.srv_id)
        calls = []
        limited = lambda req: (calls.append(1), srv._err(req, "rate limited"))[1]               # noqa: E731
        self.assertEqual(P.exchange(self.tr(resp=limited), self.me, self.srv_id.id, deadline=time.time() + 0.5, sleep=lambda s: None)[1], "rate limited")
        self.assertEqual(len(calls), 1)
        calls.clear()
        self.assertEqual(P.exchange(self.tr(resp=limited), self.me, self.srv_id.id, sleep=lambda s: None)[1], "rate limited")      # no deadline: never retries
        self.assertEqual(len(calls), 1)
        calls.clear()
        self.assertEqual(P.exchange(self.tr(resp=limited), self.me, self.srv_id.id, deadline=time.time() + 10, sleep=lambda s: None)[1], "rate limited")
        self.assertEqual(len(calls), 2)                                                         # still limited after the one retry: that is the end
        other = lambda req: (calls.append(1), srv._err(req, "stale request"))[1]                 # noqa: E731
        calls.clear()
        r = P.exchange(self.tr(resp=other), self.me, self.srv_id.id, deadline=time.time() + 10, sleep=lambda s: None)
        self.assertEqual((len(calls), r[1]), (1, "bad answer"))                                    # any other error answer stays a bad answer

    def test_an_unsigned_rate_limited_answer_is_not_trusted_to_trigger_a_retry(self):
        calls = []
        plain = S.SyncServer(mock.Mock())
        r = P.exchange(self.tr(resp=lambda req: (calls.append(1), plain._err(req, "rate limited"))[1]), self.me, self.srv_id.id, deadline=time.time() + 10, sleep=lambda s: None)
        self.assertEqual((len(calls), r[1]), (1, "bad answer"))                                    # (an unsigned "rate limited" proves nothing)

    def test_the_reasons_are_six_and_rate_limited_and_no_carrier_up_are_two_of_them(self):
        """Five since F6-2; the sixth, `no carrier up` (M1c), is what a node with several carriers answers when every carrier that could reach the peer is down."""
        self.assertEqual(P.WHY, ("connect refused", "timed out", "refused: not authorized", "bad answer", "rate limited", "no carrier up"))

    def test_a_peer_that_keeps_limiting_us_is_reported_as_rate_limited_after_one_retry(self):
        srv = S.SyncServer(mock.Mock(), identity=self.srv_id)
        slept = []
        r = P.exchange(self.tr(resp=lambda req: srv._err(req, "rate limited")), self.me, self.srv_id.id, deadline=time.time() + 30, sleep=slept.append)
        self.assertEqual(r, (False, "rate limited", None, None))
        self.assertEqual(len(slept), 1)

    def test_the_request_is_a_signed_ping_with_the_audience(self):
        seen = []
        P.exchange(self.tr(resp=lambda req: seen.append(req) or {}), self.me, self.srv_id.id)
        self.assertEqual(seen[0]["t"], "ping")
        self.assertEqual(seen[0]["aud"], self.srv_id.id)
        self.assertEqual(seen[0]["from"], self.me.id)


class Snapshot(unittest.TestCase):
    def test_unread_counts_only_the_threads_the_peer_is_in(self):
        s = Sim(3)
        s.post("arya", "one")
        s.step(1, 6)
        s.post("sansa", "two")
        s.step(1, 6)
        a = s.nodes["arya"]
        a.m._discover()
        snap = a.pong_snapshot(force=True)
        self.assertEqual(snap["unread"], {s.ids["sansa"].id: 1, s.ids["carol"].id: 1})     # "two" is unread, "one" is mine
        side = make_genesis(s.ids["arya"], "side", [(s.ids["carol"], "member")], k=1)         # a private thread between arya and carol only
        a.m.follow = None                                                                     # (the node only follows threads it was told about)
        a.m.ingest(side)
        sid = event_id(side)
        a.m.ingest(Writer(s.ids["carol"], a.m.thread(sid)).post("secret"))
        snap = a.pong_snapshot(force=True)
        self.assertEqual(snap["unread"][s.ids["carol"].id], 2)
        self.assertEqual(snap["unread"][s.ids["sansa"].id], 1)                                # sansa's count did not move
        self.assertEqual(set(snap["unread"]), {s.ids["sansa"].id, s.ids["carol"].id})
        self.assertEqual(P.handle_ping(snap, s.ids["sansa"].id)["unread"], 1)

    def test_a_removed_member_is_no_longer_counted(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        a = s.nodes["arya"]
        s.post("sansa", "y")
        s.step(1, 3)
        self.assertEqual(a.pong_snapshot(force=True)["unread"][s.ids["sansa"].id], 1)
        t = a.m.thread(s.tid)
        r = a.m.ingest(Writer(s.ids["arya"], t).remove(s.ids["sansa"].id)) if hasattr(Writer, "remove") else None
        if r is not None and r.ok:
            self.assertEqual(a.pong_snapshot(force=True)["unread"][s.ids["sansa"].id], 0)

    def test_cached_for_snapshot_every_and_forced_on_demand(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        a = s.nodes["arya"]
        s1 = a.pong_snapshot(force=True)
        self.assertIs(a.pong_snapshot(), s1)
        s.clock.t += P.SNAPSHOT_EVERY - 0.5
        self.assertIs(a.pong_snapshot(), s1)
        s.clock.t += 1.0
        self.assertIsNot(a.pong_snapshot(), s1)
        s2 = a.pong_snapshot()
        self.assertIs(a.pong_snapshot(force=False), s2)
        self.assertIsNot(a.pong_snapshot(force=True), s2)

    def test_the_loop_refreshes_only_when_asked_or_old(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        a = s.nodes["arya"]
        sid = s.ids["sansa"].id
        first = a.refresh_snapshot()                                                       # nothing yet: the first one is computed
        self.assertIsNotNone(first)
        with mock.patch.object(Mirror, "unread", side_effect=AssertionError("unread")):
            s.clock.t += P.SNAPSHOT_EVERY + 1
            self.assertIs(a.refresh_snapshot(), first)                                     # nobody asked, not old: no O(events) work under the lock
            self.assertIs(a.refresh_snapshot(), first)
        s.post("sansa", "y")
        s.step(1, 3)
        self.assertEqual(a.pong_for(sid)["unread"], 0)                                     # the ping is answered from the (stale) snapshot ...
        second = a.refresh_snapshot()                                                      # ... and it makes the next round recompute
        self.assertIsNot(second, first)
        self.assertEqual(a.pong_for(sid)["unread"], 1)
        self.assertIs(a.refresh_snapshot(), a.refresh_snapshot())
        s.clock.t += P.SNAPSHOT_EVERY + 1
        with mock.patch.object(Mirror, "unread", side_effect=AssertionError("unread")):
            self.assertIs(a.refresh_snapshot(), a.refresh_snapshot())                      # the question was answered by the refresh: the flag is cleared
        s.clock.t += P.SNAPSHOT_MAX_AGE + 1
        self.assertIsNot(a.refresh_snapshot(), second)                                     # old enough: recomputed anyway

    def test_a_stranger_asking_also_marks_the_snapshot_wanted(self):
        s = Sim(2)
        a = s.nodes["arya"]
        a.refresh_snapshot()
        s.clock.t += 1
        self.assertIsNone(a.pong_for(Identity.generate("eve").id))
        self.assertTrue(a._snap_wanted)

    def test_the_cache_never_takes_the_mirror_lock_and_starts_empty(self):
        s = Sim(2)
        a = s.nodes["arya"]
        self.assertEqual(a.cached_snapshot(), {"unread": {}, "watching": False, "at": 0.0})
        self.assertIsNone(a.pong_for(s.ids["sansa"].id))                                      # (not in the cache yet: the stranger's answer, never a lock)
        a.pong_snapshot(force=True)
        self.assertEqual(a.pong_for(s.ids["sansa"].id)["t"], "pong")

    def test_pong_for_reads_watching_live_not_from_the_snapshot(self):
        s = Sim(2)
        a = s.nodes["arya"]
        sid = s.ids["sansa"].id
        a.pong_snapshot(force=True)                                                        # snapshot: not watching
        s.clock.t = time.time()
        self.assertFalse(a.pong_for(sid)["watching"])
        P.beat(s.homes["arya"])
        self.assertTrue(a.pong_for(sid)["watching"])                                       # the snapshot still says False, the beat says yes
        self.assertFalse(a.cached_snapshot()["watching"])
        s.clock.t += P.WATCH_FRESH + 5                                                     # the beat gets old: no again, with no refresh in between
        self.assertFalse(a.pong_for(sid)["watching"])

    def test_pong_for_live_watching_does_not_change_the_cache_and_strangers_stay_strangers(self):
        s = Sim(2)
        a = s.nodes["arya"]
        snap = a.pong_snapshot(force=True)
        P.beat(s.homes["arya"])
        s.clock.t = time.time()
        self.assertIsNone(a.pong_for(Identity.generate("eve").id))
        self.assertIs(a.cached_snapshot(), snap)
        self.assertFalse(snap["watching"])

    def test_watching_comes_from_the_beat_next_to_node_json(self):
        s = Sim(2)
        a = s.nodes["arya"]
        self.assertFalse(a.pong_snapshot(force=True)["watching"])
        P.beat(s.homes["arya"])
        s.clock.t = time.time()
        self.assertTrue(a.pong_snapshot(force=True)["watching"])

    def test_the_node_itself_is_never_in_the_snapshot(self):
        s = Sim(2)
        a = s.nodes["arya"]
        a.peers.add(s.ids["arya"].id, "me", ep(0))
        self.assertNotIn(s.ids["arya"].id, a.pong_snapshot(force=True)["unread"])
        self.assertIsNone(a.pong_for(s.ids["arya"].id))

    def test_the_pongs_table_is_bounded_in_memory_and_on_load(self):
        from sigilnet import node as N
        s = Sim(2)
        a = s.nodes["arya"]
        agents = [Identity.generate("p").id for _ in range(N.MAX_PEERS + 20)]
        for x in agents:
            a.note_pong(x, {"unread": 1, "watching": False})
        self.assertEqual(len(a.pongs), N.MAX_PEERS)
        table = {x: {"last_pong": 1, "unread": 1, "watching": False} for x in agents}
        (s.homes["arya"] / "node.json").write_text(json.dumps({"pongs": table}))
        self.assertEqual(len(s.restart("arya").pongs), N.MAX_PEERS)

    def test_note_pong_is_saved_and_reloaded(self):
        s = Sim(2)
        a = s.nodes["arya"]
        sid = s.ids["sansa"].id
        a.note_pong(sid, {"unread": 7, "watching": True})
        saved = json.loads((s.homes["arya"] / "node.json").read_text())
        self.assertEqual(saved["pongs"][sid]["unread"], 7)
        self.assertTrue(saved["pongs"][sid]["watching"])
        s.restart("arya")
        self.assertEqual(s.nodes["arya"].pongs[sid]["unread"], 7)

    def test_a_hand_edited_pongs_table_cannot_stop_the_node(self):
        s = Sim(2)
        (s.homes["arya"] / "node.json").write_text(json.dumps({"pongs": {"bad": 1, s.ids["sansa"].id: {"last_pong": "x", "unread": -5, "watching": 1}, "z": []}}))
        n = s.restart("arya")
        self.assertEqual(n.pongs[s.ids["sansa"].id], {"last_pong": 0.0, "unread": 0, "watching": False})
        self.assertEqual(len(n.pongs), 1)


class Service(unittest.TestCase):
    def setUp(self):
        self.s = wire(Sim(2))
        self.s.post("arya", "x")
        self.s.step(1, 3)
        self.home = self.s.homes["arya"]
        self.ids = self.s.ids
        self.dialled = []
        self.now = time.time()
        self.s.clock.t = self.now
        self.s.nodes["sansa"].pong_snapshot(force=True)
        self.svc = P.PingService(self.s.nodes["arya"], self.home, self.dial, clock=lambda: self.now)
        (self.home / "ping").mkdir(mode=0o700)

    def dial(self, rec):
        self.dialled.append(rec)
        return self.s.transport("arya", rec)

    def req(self, ident=None, **kw):
        ident = ident or os.urandom(8).hex()
        body = {"id": ident, "peer": self.ids["sansa"].id, "deadline": self.now + 10}
        body.update(kw)
        p = self.home / "ping" / f"{ident}.req"
        p.write_text(json.dumps({k: v for k, v in body.items() if v is not ...}))
        return ident, p

    def res(self, ident):
        p = self.home / "ping" / f"{ident}.res"
        return json.loads(p.read_text()) if p.exists() else None

    def test_a_valid_request_is_dialled_and_answered(self):
        self.s.clock.t = self.now
        ident, p = self.req()
        self.assertEqual(self.svc.tick(), 1)
        r = self.res(ident)
        self.assertTrue(r["ok"], r)
        self.assertEqual(set(r) - {"ver"}, {"id", "ok", "why", "pong", "rtt_ms"}, "a single-carrier node writes the shape it always did (via only when a carrier answered; `ver` = what the peer declared, stage 1 of DESIGN_versioning.md)")
        self.assertEqual(set(r["pong"]), P.PONG_KEYS)             # (the pong the node keeps stays the five keys: the declaration travels beside it)
        self.assertEqual(set(r["pong"]), P.PONG_KEYS)
        self.assertIsNone(r["why"])
        self.assertGreaterEqual(r["rtt_ms"], 0)
        self.assertEqual((self.home / "ping" / f"{ident}.res").stat().st_mode & 0o777, 0o600)
        self.assertFalse(p.exists())
        self.assertEqual([x for x in os.listdir(self.home / "ping") if x.endswith(".tmp")], [])
        self.assertEqual(len(self.dialled), 1)

    def test_history_and_node_json_record_it(self):
        ident, _ = self.req()
        self.svc.tick()
        hist = (self.home / "history.log").read_text()
        self.assertRegex(hist, r"node  ping sansa: pong \d+ ms")
        saved = json.loads((self.home / "node.json").read_text())
        self.assertIn(self.ids["sansa"].id, saved["pongs"])

    def test_a_failure_is_a_result_with_the_reason(self):
        self.s.up["sansa"] = False
        ident, _ = self.req()
        self.svc.tick()
        r = self.res(ident)
        self.assertEqual((r["ok"], r["why"], r["pong"], r["rtt_ms"]), (False, "connect refused", None, None))
        self.assertIn("ping sansa: no answer (connect refused)", (self.home / "history.log").read_text())

    def test_blocked_peer_is_not_authorized(self):
        self.s.blocked.add(("arya", "sansa"))
        ident, _ = self.req()
        self.svc.tick()
        self.assertEqual(self.res(ident)["ok"], False)

    def test_a_dial_that_raises_is_a_result(self):
        svc = P.PingService(self.s.nodes["arya"], self.home, lambda rec: 1 / 0, clock=lambda: self.now)
        ident, _ = self.req()
        svc.tick()
        self.assertEqual(self.res(ident)["ok"], False)

    def test_invalid_requests_are_deleted_and_never_dialled(self):
        bad = []
        pdir = self.home / "ping"
        for i, body in enumerate(["not json", "[]", '"x"', json.dumps({"id": "a"})]):
            ident = f"{i:016x}"
            (pdir / f"{ident}.req").write_text(body)
            bad.append(pdir / f"{ident}.req")
        for kw in ({"peer": ...}, {"extra": 1}, {"deadline": ...}, {"deadline": True}, {"deadline": "5"}, {"deadline": float("nan")}, {"deadline": float("inf")}, {"deadline": self.now - 1},
                   {"deadline": self.now}, {"deadline": 1e300}, {"deadline": self.now + P.PING_MAX_TIMEOUT + P.DEADLINE_SLACK + 1}, {"peer": "f" * 32}, {"peer": 5}, {"peer": "x"},
                   {"peer": self.ids["arya"].id}, {"id": "b" * 16}):
            bad.append(self.req(**kw)[1])
        bad.append(self.req(ident="zz" * 8)[1])
        big = self.req(ident="c" * 16)[1]
        big.write_text(json.dumps({"id": "c" * 16, "peer": self.ids["sansa"].id, "deadline": self.now + 5, "pad": "x" * 5000}))
        bad.append(big)
        self.svc.tick()
        self.assertEqual(self.dialled, [])
        self.assertEqual([p for p in bad if p.exists()], [])

    def test_a_request_to_ourselves_is_never_dialled_even_if_we_are_in_our_own_book(self):
        self.s.nodes["arya"].peers.add(self.ids["arya"].id, "me", ep(0))
        ident, p = self.req(peer=self.ids["arya"].id)
        self.assertEqual(self.svc.tick(), 0)
        self.assertEqual(self.dialled, [])
        self.assertFalse(p.exists())

    def test_an_invalid_request_leaves_no_result_behind(self):
        ids = []
        for kw in ({"deadline": float("nan")}, {"deadline": self.now}, {"deadline": self.now - 1}, {"peer": self.ids["arya"].id}, {"peer": "x" * 32}):
            ids.append(self.req(**kw)[0])
        self.svc.tick()
        self.assertEqual([i for i in ids if self.res(i) is not None], [])
        self.assertEqual(self.dialled, [])

    def test_a_json_list_with_the_right_names_is_not_a_request_and_does_not_crash_tick(self):
        pdir = self.home / "ping"
        (pdir / ("d" * 16 + ".req")).write_text('["id", "peer", "deadline"]')
        (pdir / ("e" * 16 + ".req")).write_text(json.dumps({"id": "e" * 16, "peer": ["x"], "deadline": [1]}))
        self.assertEqual(self.svc.tick(), 0)
        self.assertEqual(os.listdir(pdir), [])

    def test_a_symlink_to_a_valid_request_is_not_followed(self):
        pdir = self.home / "ping"
        target = Path(tempfile.mkdtemp()) / "t.json"
        ident = "f" * 16
        target.write_text(json.dumps({"id": ident, "peer": self.ids["sansa"].id, "deadline": self.now + 10}))
        os.symlink(target, pdir / f"{ident}.req")
        self.assertEqual(self.svc.tick(), 0)
        self.assertEqual(self.dialled, [])
        self.assertTrue(target.exists())

    def test_a_request_that_expires_between_pickup_and_dial_is_not_dialled(self):
        calls = []

        def clock():
            calls.append(1)
            return self.now if len(calls) == 1 else self.now + 1000
        svc = P.PingService(self.s.nodes["arya"], self.home, self.dial, clock=clock)
        ident, _ = self.req()
        self.assertEqual(svc.tick(), 1)
        for _ in range(100):
            if not svc._active:
                break
            time.sleep(0.02)
        self.assertEqual(self.dialled, [])
        self.assertEqual(self.res(ident)["why"], "timed out")

    def test_an_active_request_is_not_swept_even_when_its_file_is_old(self):
        gate = threading.Event()
        svc = P.PingService(self.s.nodes["arya"], self.home, lambda rec: (gate.wait(5), self.s.transport("arya", rec))[1], clock=lambda: self.now)
        ident, p = self.req()
        with mock.patch.object(P, "GRACE", 0.01):
            svc.tick()
        os.utime(p, (self.now - P.STALE_FILE_AGE - 5, self.now - P.STALE_FILE_AGE - 5))
        svc.tick()
        self.assertTrue(p.exists())
        gate.set()
        svc.close()

    def test_a_deadline_inside_the_allowed_window_is_taken(self):
        ident, _ = self.req(deadline=self.now + P.PING_MAX_TIMEOUT)
        self.assertEqual(self.svc.tick(), 1)
        self.assertIsNotNone(self.res(ident))

    def test_a_request_whose_name_differs_from_its_id_is_dropped(self):
        ident, p = self.req()
        q = p.with_name("0123456789abcdef.req")
        os.rename(p, q)
        self.svc.tick()
        self.assertFalse(q.exists())
        self.assertEqual(self.dialled, [])

    def test_special_files_are_deleted_and_a_fifo_cannot_hang_tick(self):
        pdir = self.home / "ping"
        os.mkfifo(pdir / ("a" * 16 + ".req"))
        os.symlink("/etc/passwd", pdir / ("b" * 16 + ".req"))
        os.mkdir(pdir / ("c" * 16 + ".req"))
        done = []
        t = threading.Thread(target=lambda: done.append(self.svc.tick()), daemon=True)
        t.start()
        t.join(5)
        self.assertEqual(done, [0])
        self.assertEqual([n for n in os.listdir(pdir)], [])
        self.assertTrue(Path("/etc/passwd").exists())

    def test_two_simultaneous_requests_are_both_answered(self):
        a, _ = self.req()
        b, _ = self.req()
        patch = mock.patch.object(type(self.s.clock), "__call__", lambda c: time.time())          # the servers' clock runs in real time here
        patch.start()
        self.addCleanup(patch.stop)
        self.assertEqual(self.svc.tick(), 2)
        for _ in range(200):                                                              # the second one is asked again after the peer's one-per-second gap
            if self.res(a) is not None and self.res(b) is not None:
                break
            time.sleep(0.02)
        self.assertTrue(self.res(a)["ok"], self.res(a))
        self.assertTrue(self.res(b)["ok"], self.res(b))

    def test_stale_files_are_swept_and_fresh_ones_stay(self):
        pdir = self.home / "ping"
        old, fresh = pdir / "old.res", pdir / "fresh.res"
        old.write_text("{}")
        fresh.write_text("{}")
        os.utime(old, (self.now - P.STALE_FILE_AGE - 5, self.now - P.STALE_FILE_AGE - 5))
        os.utime(fresh, (self.now - P.STALE_FILE_AGE + 60, self.now - P.STALE_FILE_AGE + 60))
        (pdir / "x.tmp").write_text("t")
        os.utime(pdir / "x.tmp", (self.now - P.STALE_FILE_AGE - 5, self.now - P.STALE_FILE_AGE - 5))
        self.svc.tick()
        self.assertFalse(old.exists())
        self.assertFalse((pdir / "x.tmp").exists())
        self.assertTrue(fresh.exists())

    def test_a_missing_ping_dir_is_nothing_to_do(self):
        os.rmdir(self.home / "ping")
        self.assertEqual(self.svc.tick(), 0)

    def test_no_result_is_written_when_the_cli_already_gave_up(self):
        ident, p = self.req()
        gate = threading.Event()

        def slow(rec):
            gate.wait(5)
            return self.s.transport("arya", rec)
        svc = P.PingService(self.s.nodes["arya"], self.home, slow, clock=lambda: self.now)
        with mock.patch.object(P, "GRACE", 0.01):
            svc.tick()
        os.unlink(p)                                                                     # the CLI timed out and removed its request
        gate.set()
        for _ in range(100):
            if not svc._active:
                break
            time.sleep(0.02)
        self.assertIsNone(self.res(ident))

    def test_a_request_in_flight_is_not_dialled_twice(self):
        ident, p = self.req()
        gate = threading.Event()
        dials = []

        def slow(rec):
            dials.append(1)
            gate.wait(5)
            return self.s.transport("arya", rec)
        svc = P.PingService(self.s.nodes["arya"], self.home, slow, clock=lambda: self.now)
        with mock.patch.object(P, "GRACE", 0.01):
            self.assertEqual(svc.tick(), 1)
            self.assertEqual(svc.tick(), 0)
        gate.set()
        for _ in range(100):
            if not svc._active:
                break
            time.sleep(0.02)
        self.assertEqual(len(dials), 1)

    def test_the_dial_is_told_how_long_is_left_and_a_one_argument_dial_still_works(self):
        seen = []

        def dial2(rec, left):
            seen.append(left)
            return self.s.transport("arya", rec)
        svc = P.PingService(self.s.nodes["arya"], self.home, dial2, clock=lambda: self.now)
        self.req(deadline=self.now + 7)
        svc.tick()
        self.assertEqual(len(seen), 1)
        self.assertAlmostEqual(seen[0], 7.0, delta=0.01)
        self.req()
        self.svc.tick()                                                                    # setUp's one-argument dial
        self.assertEqual(len(self.dialled), 1)

    def test_a_keyword_default_dial_gets_the_remaining_time_too(self):
        seen = []

        def dial(rec, left=None):
            seen.append(left)
            return self.s.transport("arya", rec)
        svc = P.PingService(self.s.nodes["arya"], self.home, dial, clock=lambda: self.now)
        self.req(deadline=self.now + 3)
        svc.tick()
        self.assertAlmostEqual(seen[0], 3.0, delta=0.01)

    def test_the_time_left_is_never_below_a_tenth_of_a_second(self):
        seen = []

        def dial(rec, left):
            seen.append(left)
            return self.s.transport("arya", rec)
        t = iter([self.now, self.now + 9.99, self.now + 9.99, self.now + 9.99, self.now + 9.99, self.now + 9.99])
        svc = P.PingService(self.s.nodes["arya"], self.home, dial, clock=lambda: next(t, self.now + 9.99))
        self.req(deadline=self.now + 10)
        svc.tick()
        for _ in range(100):
            if not svc._active:
                break
            time.sleep(0.02)
        self.assertTrue(seen and seen[0] >= 0.1, seen)

    def test_pool_limits_the_pings_in_flight(self):
        gate = threading.Event()
        svc = P.PingService(self.s.nodes["arya"], self.home, lambda rec: (gate.wait(5), self.s.transport("arya", rec))[1], clock=lambda: self.now)
        for _ in range(P.POOL + 3):
            self.req()
        with mock.patch.object(P, "GRACE", 0.01):
            self.assertEqual(svc.tick(), P.POOL)
        gate.set()
        svc.close()

    def test_a_peer_removed_from_the_book_is_never_dialled(self):
        ident, p = self.req()
        self.s.nodes["arya"].peers.remove(self.ids["sansa"].id)
        self.svc.tick()
        self.assertEqual(self.dialled, [])
        self.assertFalse(p.exists())


class Cli(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        os.chmod(self.home, 0o700)
        self.me = Identity.generate("me")
        self.peer = Identity.generate("sansa")
        self.other = Identity.generate("sansa")
        from sigilnet.node import PeerBook
        self.book = PeerBook(self.home / "peers.json")
        self.book.add(self.peer.id, "sansa", ep(1))
        self.lock = os.open(self.home / "node.lock", os.O_CREAT | os.O_RDWR)
        fcntl.flock(self.lock, fcntl.LOCK_EX)                                            # "a node runs here"

    def tearDown(self):
        os.close(self.lock)

    def service(self, answer):
        """A thread playing the node: answers every request file with `answer(req) -> res dict or None`."""
        stop = threading.Event()
        done = set()

        def run():
            d = self.home / "ping"
            while not stop.is_set():
                for n in (os.listdir(d) if d.exists() else []):
                    if n.endswith(".req") and n not in done:
                        done.add(n)
                        try:
                            req = json.loads((d / n).read_text())
                        except (OSError, ValueError):
                            continue
                        res = answer(req)
                        if res is not None:
                            tmp = d / (req["id"] + ".tmp")
                            tmp.write_text(json.dumps(dict(res, id=req["id"])))
                            os.replace(tmp, d / (req["id"] + ".res"))
                time.sleep(0.01)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        halt = lambda: (stop.set(), t.join(2))                           # noqa: E731
        self.addCleanup(halt)
        return halt

    def test_errors_before_anything_is_sent(self):
        for args, frag in (((self.home, "nobody"), "no such peer"), ((self.home, ""), "give a peer"), ((self.home, "sansa", 0), "--timeout"), ((self.home, "sansa", -3), "--timeout"),
                           ((self.home, "sansa", 121), "--timeout"), ((self.home, "sansa", True), "--timeout"), ((self.home, "sansa", float("nan")), "--timeout"),
                           ((self.home, "sansa", "5"), "--timeout")):
            with self.assertRaises(P.PingError) as c:
                P.ping_peer(*args)
            self.assertIn(frag, str(c.exception))
        self.assertFalse((self.home / "ping").exists())

    def test_the_node_not_running(self):
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        with self.assertRaises(P.PingError) as c:
            P.ping_peer(self.home, "sansa")
        self.assertIn("start", str(c.exception))
        self.assertFalse((self.home / "ping").exists())

    def test_name_or_id_prefix_and_ambiguity(self):
        self.book.add(self.other.id, "sansa", ep(2))
        with self.assertRaises(P.PingError):
            P.ping_peer(self.home, "sansa")                                              # a name used by two agents
        with self.assertRaises(P.PingError):
            P.ping_peer(self.home, "")
        self.book.remove(self.other.id)
        self.book.add(self.other.id, "dave", ep(3))
        self.assertEqual(P._resolve(self.book.all(), self.peer.id[:10])[0], self.peer.id)
        self.assertEqual(P._resolve(self.book.all(), "dave")[0], self.other.id)
        common = os.path.commonprefix([self.peer.id, self.other.id])
        if common:
            with self.assertRaises(P.PingError):
                P._resolve(self.book.all(), common)

    def test_a_pong_comes_back(self):
        pong = {"t": "pong", "up": True, "unread": 3, "watching": True, "v": 1}
        self.service(lambda req: {"ok": True, "why": None, "pong": pong, "rtt_ms": 47.2})
        r = P.ping_peer(self.home, "sansa", 5)
        self.assertEqual((r.ok, r.why, r.pong, r.rtt_ms, r.peer_name, r.peer_id), (True, None, pong, 47.2, "sansa", self.peer.id))
        self.assertEqual(os.listdir(self.home / "ping"), [])                              # both files removed
        self.assertEqual((self.home / "ping").stat().st_mode & 0o777, 0o700)

    def test_the_request_file_has_the_frozen_shape(self):
        seen = []

        def answer(req):
            seen.append(req)
            return {"ok": False, "why": "timed out", "pong": None, "rtt_ms": None}
        self.service(answer)
        t0 = time.time()
        P.ping_peer(self.home, "sansa", 5)
        req = seen[0]
        self.assertEqual(set(req), {"id", "peer", "deadline"})
        self.assertEqual(req["peer"], self.peer.id)
        self.assertEqual(len(req["id"]), 16)
        self.assertAlmostEqual(req["deadline"], t0 + 5, delta=1.0)

    def test_the_request_appears_whole_or_not_at_all(self):
        """The node reads and deletes any .req it cannot parse, so the CLI must never expose a half-written one: it writes a .tmp and renames."""
        seen = []
        real = os.replace

        def spy(src, dst):
            if str(dst).endswith(".req"):
                seen.append((str(src), json.loads(Path(src).read_text()), Path(dst).exists()))
            return real(src, dst)
        with mock.patch.object(os, "replace", spy):
            P.ping_peer(self.home, "sansa", 0.1)
        self.assertEqual(len(seen), 1)
        src, body, existed = seen[0]
        self.assertTrue(src.endswith(".tmp"))
        self.assertFalse(existed)
        self.assertEqual(set(body), {"id", "peer", "deadline"})
        self.assertEqual(os.listdir(self.home / "ping"), [])

    def test_the_request_is_0600_and_pokes_the_node(self):
        modes = []

        def answer(req):
            modes.append(os.stat(self.home / "ping" / (req["id"] + ".req")).st_mode & 0o777)
            return {"ok": False, "why": "timed out", "pong": None, "rtt_ms": None}
        self.service(answer)
        P.ping_peer(self.home, "sansa", 5)
        self.assertEqual(modes, [0o600])
        self.assertGreaterEqual((self.home / "node.poke").stat().st_size, 1)

    def test_rate_limited_passes_through_and_prints(self):
        halt = self.service(lambda req: {"ok": False, "why": "rate limited", "pong": None, "rtt_ms": None})
        r = P.ping_peer(self.home, "sansa", 5)
        halt()
        self.assertEqual((r.ok, r.why), (False, "rate limited"))
        self.assertTrue(P.format_result(r, 1.2).endswith("after 1.2 s: rate limited"))

    def test_failures_pass_through(self):
        for why in P.WHY:
            halt = self.service(lambda req, w=why: {"ok": False, "why": w, "pong": None, "rtt_ms": None})
            r = P.ping_peer(self.home, "sansa", 5)
            halt()
            self.assertEqual((r.ok, r.why), (False, why))

    def test_a_garbage_result_is_a_bad_answer(self):
        d = self.home / "ping"
        stop = threading.Event()
        done = set()

        def run():
            while not stop.is_set():
                for n in (os.listdir(d) if d.exists() else []):
                    if n.endswith(".req") and n not in done:
                        done.add(n)
                        (d / (n[:-4] + ".res")).write_text("{not json")
                time.sleep(0.01)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        try:
            self.assertEqual(P.ping_peer(self.home, "sansa", 5).why, "bad answer")
        finally:
            stop.set()
            t.join(2)

    def raw_result(self, body):
        d = self.home / "ping"
        stop = threading.Event()
        done = set()

        def run():
            while not stop.is_set():
                for n in (os.listdir(d) if d.exists() else []):
                    if n.endswith(".req") and n not in done:
                        done.add(n)
                        tmp = d / (n[:-4] + ".tmp")                                      # atomic, like the node: a half-written result reads as "bad answer"
                        tmp.write_text(json.dumps(body(n[:-4])))
                        os.replace(tmp, d / (n[:-4] + ".res"))
                time.sleep(0.01)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        try:
            return P.ping_peer(self.home, "sansa", 5)
        finally:
            stop.set()
            t.join(2)

    GOOD = {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1}

    def test_a_result_for_another_id_is_not_ours(self):
        r = self.raw_result(lambda ident: {"id": "0" * 16, "ok": True, "why": None, "pong": self.GOOD, "rtt_ms": 1.0})
        self.assertEqual((r.ok, r.why), (False, "bad answer"))

    def test_a_result_that_says_ok_without_a_proper_pong_is_a_bad_answer(self):
        for pong in (None, "pong", [], {}, {"t": "pong"}, dict(self.GOOD, extra=1)):
            r = self.raw_result(lambda ident, p=pong: {"id": ident, "ok": True, "why": None, "pong": p, "rtt_ms": 1.0})
            self.assertEqual((r.ok, r.why, r.pong), (False, "bad answer", None), pong)

    def test_a_result_with_an_unknown_reason_or_a_wrong_ok_type_is_a_bad_answer(self):
        for body in ({"ok": False, "why": "because", "pong": None}, {"ok": False, "why": None, "pong": None}, {"ok": "yes", "why": "timed out", "pong": None},
                     {"ok": 1, "pong": self.GOOD}, [1, 2]):
            r = self.raw_result(lambda ident, b=body: dict(b, id=ident) if isinstance(b, dict) else b)
            self.assertEqual((r.ok, r.why), (False, "bad answer"), body)

    def test_a_good_result_without_an_rtt_still_formats(self):
        r = self.raw_result(lambda ident: {"id": ident, "ok": True, "why": None, "pong": self.GOOD, "rtt_ms": None})
        self.assertTrue(r.ok)
        self.assertIn("rtt 0 ms", P.format_result(r, 1))
        r = self.raw_result(lambda ident: {"id": ident, "ok": True, "why": None, "pong": self.GOOD, "rtt_ms": True})
        self.assertEqual(r.rtt_ms, 0.0)

    def test_an_existing_ping_dir_with_loose_permissions_is_tightened(self):
        d = self.home / "ping"
        d.mkdir()
        os.chmod(d, 0o755)
        P.ping_peer(self.home, "sansa", 0.1)
        self.assertEqual(d.stat().st_mode & 0o777, 0o700)

    def test_no_answer_times_out_at_the_deadline_and_cleans_up(self):
        t0 = time.monotonic()
        r = P.ping_peer(self.home, "sansa", 0.5)
        dt = time.monotonic() - t0
        self.assertEqual((r.ok, r.why, r.pong, r.rtt_ms), (False, "timed out", None, None))
        self.assertGreaterEqual(dt, 0.5)
        self.assertLess(dt, 0.6)                                                          # within 100 ms
        self.assertEqual(os.listdir(self.home / "ping"), [])

    def test_fake_clock_polls_every_20_ms_and_never_oversleeps(self):
        t = [100.0]
        slept = []

        def sleep(s):
            slept.append(s)
            t[0] += s
        r = P.ping_peer(self.home, "sansa", 1.0, clock=lambda: t[0], sleep=sleep)
        self.assertFalse(r.ok)
        self.assertEqual(slept[0], 0.02)
        self.assertAlmostEqual(sum(slept), 1.0, places=6)
        self.assertLessEqual(max(slept), 0.02 + 1e-9)

    def test_cli_lines_and_exit_codes(self):
        from sigilnet import cli
        import io
        import contextlib
        pong = {"t": "pong", "up": True, "unread": 3, "watching": False, "v": 1}

        def run(res=None, exc=None):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(P, "ping_peer", side_effect=exc) if exc else mock.patch.object(P, "ping_peer", return_value=res), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = cli._ping_cmd(mock.Mock(peer="sansa", timeout=None), self.home)
            return rc, out.getvalue(), err.getvalue()
        with mock.patch.object(P, "ping_peer", return_value=P.PingResult(True, None, pong, 1.0, "sansa", self.peer.id)) as pp, contextlib.redirect_stdout(io.StringIO()):
            cli._ping_cmd(mock.Mock(peer="sansa", timeout=None), self.home)
            cli._ping_cmd(mock.Mock(peer="sansa", timeout=7.5), self.home)
        self.assertEqual([c.args[2] for c in pp.call_args_list], [P.PING_DEFAULT_TIMEOUT, 7.5])
        rc, out, err = run(P.PingResult(True, None, pong, 46.6, "sansa", self.peer.id))
        self.assertEqual((rc, out, err), (0, f"pong from sansa ({self.peer.id[:8]}): up, unread 3, watching no, rtt 47 ms\n", ""))
        rc, out, err = run(P.PingResult(False, "timed out", None, None, "sansa", self.peer.id))
        self.assertEqual(rc, 3)
        self.assertRegex(out, rf"^no answer from sansa \({self.peer.id[:8]}\) after [0-9.]+ s: timed out\n$")
        rc, out, err = run(exc=P.PingError("no such peer: x"))
        self.assertEqual((rc, out, err), (1, "", "error: no such peer: x\n"))

    def test_format_elapsed(self):
        r = P.PingResult(False, "connect refused", None, None, "sansa", self.peer.id)
        self.assertTrue(P.format_result(r, 15.004).endswith("after 15 s: connect refused"))
        self.assertTrue(P.format_result(r, 0.23).endswith("after 0.2 s: connect refused"))
        w = P.PingResult(True, None, {"t": "pong", "up": True, "unread": 0, "watching": True, "v": 1}, 3.0, "s", "a" * 32)
        self.assertIn("watching yes, rtt 3 ms", P.format_result(w, 1))

    def test_peer_list_prints_last_heard(self):
        import subprocess
        import sys
        self.me.save(self.home / "identity.json")
        (self.home / "node.json").write_text(json.dumps({"pongs": {self.peer.id: {"last_pong": time.time() - 200, "unread": 1, "watching": False}}}))
        r = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(self.home), "peer", "list"], capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[2]), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"last heard 3 min ago")

    def test_peer_list_shows_last_heard(self):
        from sigilnet import cli
        (self.home / "node.json").write_text(json.dumps({"pongs": {self.peer.id: {"last_pong": time.time() - 200, "unread": 1, "watching": False}}}))
        self.assertIn(self.peer.id, cli._last_heard(self.home))
        self.assertEqual(cli._ago(30), "30 s")
        self.assertEqual(cli._ago(200), "3 min")
        self.assertEqual(cli._ago(10000), "2 h")
        (self.home / "node.json").write_text("{bad")
        self.assertEqual(cli._last_heard(self.home), {})


class FreshProcess(unittest.TestCase):
    def test_a_tcp_peer_is_found_in_a_fresh_interpreter(self):
        """The CLI process imports no carrier by itself: ping must register the endpoint types or peers.json entries of that type are skipped."""
        import subprocess
        import sys
        home = Path(tempfile.mkdtemp())
        os.chmod(home, 0o700)
        peer = Identity.generate("bob")
        (home / "peers.json").write_text(json.dumps({"peers": {peer.id: {"name": "bob", "endpoint": {"type": "tcp", "addr": "127.0.0.1:47600#" + "ab" * 32}, "threads": []}}}))
        r = subprocess.run([sys.executable, "-c", f"from sigilnet import ping; ping.ping_peer({str(home)!r}, 'bob')"], capture_output=True, text=True,
                           cwd=str(Path(__file__).resolve().parents[2]), timeout=60)
        self.assertIn("PingError", r.stderr)
        self.assertIn("no node is running", r.stderr)
        self.assertNotIn("no such peer", r.stderr)


class EndToEnd(unittest.TestCase):
    """Two nodes in one process: arya pings sansa through the real SyncServer, signatures and files; the loop shape is the one noderun uses."""

    def test_ping_over_files_and_the_server(self):
        s = wire(Sim(2))
        s.post("arya", "hello")
        s.step(1, 3)
        s.post("arya", "again")
        s.step(1, 3)
        s.clock.t = time.time()
        ahome = s.homes["arya"]
        fd = os.open(ahome / "node.lock", os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        s.nodes["sansa"].pong_snapshot(force=True)
        svc = P.PingService(s.nodes["arya"], ahome, lambda rec: s.transport("arya", rec))
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                svc.tick()
                time.sleep(0.02)
        th = threading.Thread(target=loop, daemon=True)
        th.start()
        try:
            r = P.ping_peer(ahome, "sansa", 5)
            self.assertTrue(r.ok, r.why)
            self.assertEqual(r.pong["unread"], 2)
            self.assertFalse(r.pong["watching"])
            P.beat(s.homes["sansa"])
            s.clock.t = time.time() + 2
            s.nodes["sansa"].pong_snapshot(force=True)
            s.clock.t += P.PING_MIN_GAP
            s.servers["sansa"].ping_at.clear()
            r = P.ping_peer(ahome, "sansa", 5)
            self.assertTrue(r.ok, r.why)
            self.assertTrue(r.pong["watching"])
            s.up["sansa"] = False
            r = P.ping_peer(ahome, "sansa", 5)
            self.assertEqual((r.ok, r.why), (False, "connect refused"))
            s.up["sansa"] = True
            s.blocked.add(("arya", "sansa"))
            self.assertFalse(P.ping_peer(ahome, "sansa", 5).ok)
        finally:
            stop.set()
            th.join(2)
            os.close(fd)


class WatchBeat(unittest.TestCase):
    def test_the_watcher_beats_at_start_and_every_interval(self):
        from sigilnet import watch as W
        home = Path(tempfile.mkdtemp())
        os.chmod(home, 0o700)
        me = Identity.generate("me")
        me.save(home / "identity.json")
        t = [1000.0]

        def sleep(s):
            t[0] += s
        w = W.Watcher(home, "wb", out=lambda s: None, clock=lambda: t[0], sleep=sleep, poll=0.25)
        w.run(12.0)
        self.assertEqual((home / "watch.beat").stat().st_size, 3)                          # 0 s, 5 s, 10 s
        with mock.patch.object(P, "WATCH_BEAT_EVERY", 1.0):
            t[0] = 2000.0
            (home / "watch.beat").unlink()
            w.run(5.0)
        self.assertEqual((home / "watch.beat").stat().st_size, 5)


class Wiring(unittest.TestCase):
    def test_noderun_is_wired(self):
        src = (Path(__file__).resolve().parents[1] / "noderun.py").read_text()
        self.assertIn("pong=node.pong_for", src)
        self.assertIn("ping_log=make_ping_log(out)", src)
        self.assertIn("pings.tick()", src)
        self.assertIn("node.refresh_snapshot()", src)
        self.assertIn("pings.close()", src)
        self.assertIn("PingService(node, home, dialer)", src)                                # the ping dials through the locator-book dialer ...
        lsrc = (Path(__file__).resolve().parents[1] / "locators.py").read_text()
        self.assertIn("rt = min(self.request_timeout, left or self.request_timeout)", lsrc)  # ... which stops waiting when the CLI has given up
        self.assertIn("ct = min(self.connect_timeout, left or self.connect_timeout)", lsrc)
        self.assertLess(src.index("node.tick(parallel=True)"), src.index("node.refresh_snapshot()"))

    def test_read_inbox_join_doors_never_say_up(self):
        from sigilnet.doors import door_handler
        s = wire(Sim(2))
        s.post("arya", "x")
        s.step(1, 3)
        s.nodes["arya"].pong_snapshot(force=True)
        srv = s.servers["arya"]
        req = S.sign_request(s.ids["sansa"], {"t": "ping"}, aud=s.ids["arya"].id)
        for kind in ("read", "inbox", "join"):
            r = door_handler(kind, None, srv, {})(json.loads(json.dumps(req)))
            self.assertNotEqual(r.get("t"), "pong", kind)
        from sigilnet.publicread import PublicRead
        r = PublicRead(srv).handle(json.loads(json.dumps(S.sign_request(s.ids["sansa"], {"t": "ping"}, aud=s.ids["arya"].id))))
        self.assertNotEqual(r.get("t"), "pong")

    def test_a_per_peer_door_bound_to_someone_else_refuses(self):
        from sigilnet.doors import service_handler
        s = wire(Sim(3))
        s.post("arya", "x")
        s.step(1, 5)
        s.nodes["arya"].pong_snapshot(force=True)
        srv = s.servers["arya"]
        h = service_handler(srv, s.ids["carol"].id)
        req = S.sign_request(s.ids["sansa"], {"t": "ping"}, aud=s.ids["arya"].id)
        self.assertEqual(h(json.loads(json.dumps(req))), srv.refuse(req))
        req2 = S.sign_request(s.ids["carol"], {"t": "ping"}, aud=s.ids["arya"].id)
        self.assertEqual(h(json.loads(json.dumps(req2)))["t"], "pong")

    def test_a_bound_to_nobody_door_still_refuses_an_unknown_signer(self):
        from sigilnet.doors import service_handler
        s = wire(Sim(2))
        s.step(1, 2)
        s.nodes["arya"].pong_snapshot(force=True)
        srv = s.servers["arya"]
        h = service_handler(srv, None)
        req = S.sign_request(Identity.generate("eve"), {"t": "ping"}, aud=s.ids["arya"].id)
        self.assertEqual(h(json.loads(json.dumps(req))), srv.refuse(req))

    def test_flood_of_pings_is_bounded(self):
        s = wire(Sim(2))
        s.post("arya", "x")
        s.step(1, 3)
        s.nodes["arya"].pong_snapshot(force=True)
        srv = s.servers["arya"]
        pongs = 0
        for i in range(100):
            req = S.sign_request(s.ids["sansa"], {"t": "ping"}, ts=int(s.clock()), aud=s.ids["arya"].id)
            if srv.handle(json.loads(json.dumps(req)))["t"] == "pong":
                pongs += 1
        self.assertEqual(pongs, 1)


if __name__ == "__main__":
    unittest.main()
