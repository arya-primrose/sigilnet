"""The r40 delta (F6-1 'ping from' log lines, F6-2 'rate limited' reason, F6-3 live 'watching'), from the agreed text only."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import ping, sync as S
from sigilnet.carrier import CarrierError
from sigilnet.keys import Identity
from sigilnet.tests.test_node import Sim
from sigilnet.tests_adv13.test_ping_service import RES_KEYS, Svc, read_res, write_req
from sigilnet.tests_adv13.test_ping_unit import ENVELOPE, ask, pong_sim, signed


def logged_sim(n=3, **kw):
    s = Sim(n)
    s.lines = []
    for x, nd in s.nodes.items():
        s.servers[x] = S.SyncServer(s.mirrors[x], clock=s.clock, on_notify=nd.on_notify, identity=s.ids[x], pong=nd.pong_for,
                                    ping_log=(lambda who, what, x=x: s.lines.append((x, who, what))) if x == "sansa" else None)
    return s


class PingLog(unittest.TestCase):
    def test_an_answered_ping_is_noted_once_with_the_requester(self):
        s = logged_sim(2)
        s.nodes["sansa"].pong_snapshot()
        ask(s, "sansa", "arya")
        self.assertEqual(s.lines, [("sansa", s.ids["arya"].id, "answered")])

    def test_a_stranger_is_noted_as_refused_and_gets_the_strangers_answer(self):
        s = logged_sim(2)
        eve = Identity.generate("eve")
        req = json.loads(json.dumps(S.sign_request(eve, {"t": "ping"}, ts=int(s.clock()))))
        resp = s.servers["sansa"].handle(req)
        self.assertEqual(resp, s.servers["sansa"].refuse(req))
        self.assertEqual(s.lines, [("sansa", eve.id, "refused")])

    def test_a_rate_limited_ping_is_not_noted(self):
        s = logged_sim(2)
        s.nodes["sansa"].pong_snapshot()
        ask(s, "sansa", "arya")
        ask(s, "sansa", "arya")                                              # rate limited by the 1/s gap
        ask(s, "sansa", "arya")
        self.assertEqual([w for _, _, w in s.lines], ["answered"])

    def test_a_failing_callback_changes_nothing(self):
        for exc in (ZeroDivisionError, RuntimeError, OSError, KeyError, ValueError):
            with self.subTest(exc=exc.__name__):
                s = Sim(2)

                def boom(who, what, exc=exc):
                    raise exc("log failed")

                s.servers["sansa"] = S.SyncServer(s.mirrors["sansa"], clock=s.clock, identity=s.ids["sansa"], pong=s.nodes["sansa"].pong_for, ping_log=boom)
                s.nodes["sansa"].pong_snapshot()
                _, resp = ask(s, "sansa", "arya")
                self.assertEqual(resp.get("t"), "pong")
                eve = json.loads(json.dumps(S.sign_request(Identity.generate("eve"), {"t": "ping"}, ts=int(s.clock()))))
                self.assertEqual(s.servers["sansa"].handle(eve), s.servers["sansa"].refuse(eve))

    def test_no_callback_is_fine(self):
        s = pong_sim(2)
        s.nodes["sansa"].pong_snapshot()
        self.assertEqual(ask(s, "sansa", "arya")[1].get("t"), "pong")

    def test_make_ping_log_writes_the_documented_lines(self):
        out = []
        log = ping.make_ping_log(out.append, clock=lambda: 0.0)
        log("abcdefgh" + "x" * 24, "answered")
        log("zyxwvuts" + "y" * 24, "refused")
        self.assertEqual(out, ["ping from abcdefgh answered", "ping from zyxwvuts refused"])

    def test_refused_lines_are_throttled_in_all_not_per_requester(self):
        out = []
        t = [0.0]
        log = ping.make_ping_log(out.append, clock=lambda: t[0], refused_gap=60.0)
        for i in range(50):                                                  # fifty DIFFERENT strangers with valid signatures
            t[0] = i * 0.5
            log(f"{i:08d}" + "q" * 24, "refused")
        self.assertEqual(len(out), 1)
        t[0] = 61.0
        log("late" + "q" * 28, "refused")
        self.assertEqual(len(out), 2)

    def test_answered_lines_are_not_throttled_by_the_refused_gap(self):
        out = []
        log = ping.make_ping_log(out.append, clock=lambda: 0.0)
        for _ in range(5):
            log("peer" + "z" * 28, "answered")
        self.assertEqual(len(out), 5)

    def test_the_refused_gap_constant_is_a_parameter(self):
        out = []
        t = [0.0]
        log = ping.make_ping_log(out.append, clock=lambda: t[0], refused_gap=5.0)
        log("a" * 32, "refused")
        t[0] = 4
        log("b" * 32, "refused")
        t[0] = 6
        log("c" * 32, "refused")
        self.assertEqual(len(out), 2)

    def test_only_the_first_eight_characters_of_the_requester_are_written(self):
        out = []
        log = ping.make_ping_log(out.append, clock=lambda: 0.0)
        who = "abcdefgh" + "SECRETSECRETSECRETSECRET"
        log(who, "answered")
        self.assertNotIn("SECRET", out[0])


class RateLimitedReason(unittest.TestCase):
    def test_the_reason_exists_in_why(self):
        self.assertIn("rate limited", ping.WHY)
        self.assertEqual(ping.WHY[:4], ("connect refused", "timed out", "refused: not authorized", "bad answer"))

    def run_svc(self, advance_on):
        t = Svc()
        t.s.servers["arya"].handle(json.loads(json.dumps(S.sign_request(t.s.ids["sansa"], {"t": "ping"}, ts=int(t.s.clock())))))      # uses up our slot at the peer
        real = t.s.transport
        calls = []

        def dial(rec):
            tr = real("sansa", rec)

            class T:
                def request(self_, req):
                    calls.append(1)
                    if len(calls) == advance_on:
                        t.s.clock.t += 2 * ping.PING_MIN_GAP
                    return tr.request(req)
            return T()

        t.dial = dial
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        deadline = time.time() + 6
        while read_res(t.home, rid) is None and time.time() < deadline:
            time.sleep(0.05)
        return read_res(t.home, rid), len(calls)

    def test_a_retry_that_loses_says_rate_limited_not_bad_answer(self):
        res, n = self.run_svc(advance_on=99)                                  # the peer's clock never moves: limited twice
        self.assertEqual(n, 2)
        self.assertEqual(set(res), RES_KEYS)
        self.assertEqual((res["ok"], res["why"], res["pong"], res["rtt_ms"]), (False, "rate limited", None, None))

    def test_a_retry_that_wins_is_a_pong(self):
        res, n = self.run_svc(advance_on=2)
        self.assertEqual(n, 2)
        self.assertTrue(res["ok"], res)

    def test_no_room_for_a_retry_says_rate_limited_at_once(self):
        t = Svc()
        t.s.servers["arya"].handle(json.loads(json.dumps(S.sign_request(t.s.ids["sansa"], {"t": "ping"}, ts=int(t.s.clock())))))
        rid, _ = write_req(t.home, t.a, deadline=t.s.clock() + 0.5, clock=t.s.clock)      # less than PING_MIN_GAP left
        t.tick()
        deadline = time.time() + 3
        while read_res(t.home, rid) is None and time.time() < deadline:
            time.sleep(0.05)
        res = read_res(t.home, rid)
        self.assertEqual((res["ok"], res["why"]), (False, "rate limited"))
        self.assertEqual(len(t.calls), 1)

    def test_an_unsigned_rate_limited_answer_stays_bad_answer(self):
        def dial(rec):
            class T:
                def request(self_, req):
                    return {"t": "error", "why": "rate limited"}               # not signed, not nonce-bound: not believed
            return T()
        t = Svc(dial)
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        self.assertEqual(read_res(t.home, rid)["why"], "bad answer")

    def test_another_signed_error_stays_bad_answer(self):
        t = Svc()
        real = t.s.transport

        def dial(rec):
            tr = real("sansa", rec)

            class T:
                def request(self_, req):
                    r = tr.request(req)
                    return t.s.servers["arya"]._err(req, "internal: Boom")      # a signed error that is not 'rate limited'
            return T()
        t.dial = dial
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        self.assertEqual(read_res(t.home, rid)["why"], "bad answer")

    def test_the_cli_line_carries_the_new_reason(self):
        r = ping.PingResult(False, "rate limited", None, None, "arya", "f5hu2ex4" + "x" * 24)
        text = ping.format_result(r, 1.2) if hasattr(ping, "format_result") else ""
        self.assertIn("rate limited", text)


class LiveWatching(unittest.TestCase):
    def test_pong_for_reads_watch_beat_live_not_from_the_snapshot(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        home = s.homes["sansa"]
        nd.pong_snapshot()                                                    # a snapshot taken while nobody watches
        self.assertIs(nd.pong_for(a)["watching"], False)
        beat = home / "watch.beat"
        beat.write_text("x")
        self.assertIs(nd.pong_for(a)["watching"], True, "a beat younger than WATCH_FRESH must show at once, without a new snapshot")
        old = s.clock() - ping.WATCH_FRESH - 5
        os.utime(beat, (old, old))
        self.assertIs(nd.pong_for(a)["watching"], False, "an old beat must show at once, without a new snapshot")

    def test_the_snapshot_itself_is_unchanged(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        home = s.homes["sansa"]
        nd.pong_snapshot()
        (home / "watch.beat").write_text("x")
        self.assertIs(nd.cached_snapshot()["watching"], False)                # still the old snapshot value
        s.clock.t += ping.SNAPSHOT_EVERY + 0.5
        self.assertIs(nd.pong_snapshot()["watching"], True)

    def test_unread_still_comes_from_the_snapshot_and_only_for_known_peers(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        nd.pong_snapshot()
        self.assertIsNone(nd.pong_for("z" * 32))
        self.assertEqual(set(nd.pong_for(s.ids["arya"].id)), {"t", "up", "unread", "watching", "v"})

    def test_a_symlinked_beat_counts_by_its_own_mtime(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        home = s.homes["sansa"]
        target = home / "elsewhere"
        target.write_text("x")
        os.symlink(target, home / "watch.beat")
        old = s.clock() - 500
        os.utime(home / "watch.beat", (old, old), follow_symlinks=False)
        nd.pong_snapshot()
        self.assertIs(nd.pong_for(s.ids["arya"].id)["watching"], False)

    def test_a_far_future_beat_is_not_believed(self):
        s = pong_sim(2)
        nd = s.nodes["sansa"]
        home = s.homes["sansa"]
        (home / "watch.beat").write_text("x")
        fut = s.clock() + 10 ** 6
        os.utime(home / "watch.beat", (fut, fut))
        nd.pong_snapshot()
        self.assertIs(nd.pong_for(s.ids["arya"].id)["watching"], False)


if __name__ == "__main__":
    unittest.main()
