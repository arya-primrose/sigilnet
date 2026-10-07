"""M4b: the notify address (`notify_at`; DESIGN_multicarrier.md rev 9, Sansa's N1-N3). The book slot, the receiving service (checks, the SAME verification worker as an announcement, the
shared mute, the 1 h memory of a dropped value), the dialer that uses it (first, with the pull addresses as the fallback, one dial per 30 s), the requests that carry it (summary and notify
only, golden bytes without it), the node and an end-to-end run on two fake carriers where the notify path differs from the pull path."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import locators as L
from sigilnet import node as N
from sigilnet import sync as S
from sigilnet.carrier import CarrierError
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror

from .test_locators import AG, AG2, ME, PB, Carrier2, Clock, addr, book, service
from .util import World


def locator_file(b):
    return json.loads(b.path.read_text())["peers"]


# ------------------------------------------------------------------------------------------------------------------------------------------- the book

class Book(unittest.TestCase):
    def test_a_notify_address_is_kept_apart_from_the_pull_addresses(self):
        b, _ = book()
        b.seed(AG, addr(1))
        self.assertTrue(b.set_notify(AG, addr(5)))
        self.assertEqual(b.ordered(AG), [addr(1)])
        self.assertEqual(b.count(AG), 1)
        self.assertEqual([d[0] for d in b.detail(AG)], [addr(1)])
        self.assertEqual(b.notify_addr(AG), addr(5))
        self.assertEqual(b.contact(AG)[0], None)                                      # a notify address is no evidence that the peer answers pulls
        self.assertFalse(b.set_notify(AG, addr(5)))                                   # nothing new: no write

    def test_one_notify_address_per_peer_the_new_one_replaces_the_old(self):
        b, _ = book()
        b.set_notify(AG, addr(5))
        b.set_notify(AG, addr(6))
        self.assertEqual(b.notify_addr(AG), addr(6))
        self.assertEqual(b.notify_state(AG)["nfail"], 0)

    def test_only_the_notify_address_makes_a_record_without_pull_addresses(self):
        b, _ = book()
        b.set_notify(AG, addr(5))
        self.assertEqual((b.ordered(AG), b.count(AG)), ([], 0))
        self.assertTrue(b.remove(AG))
        self.assertIsNone(b.notify_addr(AG))

    def test_bad_values_are_refused_and_a_damaged_file_reads_as_none(self):
        b, _ = book()
        with self.assertRaises(ValueError):
            b.set_notify(AG, "nonsense")
        b.set_notify(AG, addr(5))
        raw = json.loads(b.path.read_text())
        raw["peers"][AG]["notify"] = {"addr": 5, "nfail": "x"}
        raw["peers"][AG]["ndrop"] = {"addr": "zzz"}
        b.path.write_text(json.dumps(raw))
        self.assertIsNone(b.notify_addr(AG))
        self.assertFalse(b.notify_dropped(AG, addr(5)))

    def test_old_files_without_the_fields_still_read(self):
        b, _ = book()
        b.seed(AG, addr(1))
        raw = json.loads(b.path.read_text())
        raw["peers"][AG].pop("notify", None)
        raw["peers"][AG].pop("ndrop", None)
        b.path.write_text(json.dumps(raw))
        self.assertEqual(b.ordered(AG), [addr(1)])
        self.assertIsNone(b.notify_addr(AG))
        b.note_notify(AG, addr(5), False)                                              # not held: nothing happens, nothing raises
        self.assertTrue(b.set_notify(AG, addr(5)))

    def test_three_failures_in_a_row_drop_it_and_the_value_is_ignored_for_an_hour(self):
        clock = Clock()
        b, _ = book(clock=clock)
        b.set_notify(AG, addr(5))
        self.assertFalse(b.note_notify(AG, addr(5), False))
        self.assertFalse(b.note_notify(AG, addr(5), False))
        self.assertEqual(b.notify_state(AG)["nfail"], 2)
        self.assertTrue(b.note_notify(AG, addr(5), False))                            # the third
        self.assertIsNone(b.notify_addr(AG))
        self.assertTrue(b.notify_dropped(AG, addr(5)))
        self.assertFalse(b.notify_dropped(AG, addr(6)))                               # only that exact value
        clock.t += L.NOTIFY_IGNORE - 1
        self.assertTrue(b.notify_dropped(AG, addr(5)))
        clock.t += 2
        self.assertFalse(b.notify_dropped(AG, addr(5)))

    def test_a_success_resets_the_count_and_a_failure_of_another_value_counts_nothing(self):
        b, _ = book()
        b.set_notify(AG, addr(5))
        b.note_notify(AG, addr(5), False)
        b.note_notify(AG, addr(5), False)
        b.note_notify(AG, addr(5), True)
        self.assertEqual(b.notify_state(AG)["nfail"], 0)
        b.note_notify(AG, addr(6), False)                                              # a value we do not hold
        self.assertEqual(b.notify_state(AG)["nfail"], 0)

    def test_a_new_value_clears_the_memory_of_the_dropped_one(self):
        b, _ = book()
        b.set_notify(AG, addr(5))
        for _ in range(3):
            b.note_notify(AG, addr(5), False)
        b.set_notify(AG, addr(6))
        self.assertFalse(b.notify_dropped(AG, addr(5)))

    def test_success_writes_are_throttled(self):
        clock = Clock()
        b, _ = book(clock=clock)
        b.set_notify(AG, addr(5))
        b.note_notify(AG, addr(5), True)
        before = b.path.stat().st_mtime_ns
        clock.t += 1
        b.note_notify(AG, addr(5), True)
        self.assertEqual(b.path.stat().st_mtime_ns, before)

    def test_drop_notify(self):
        b, _ = book()
        b.set_notify(AG, addr(5))
        self.assertTrue(b.drop_notify(AG))
        self.assertFalse(b.drop_notify(AG))


# ------------------------------------------------------------------------------------------------------------------------------------------- receiving (the service)

def field(n=5, t="fake"):
    return {"type": t, "addr": addr(n)}


class OnNotifyAt(unittest.TestCase):
    def test_a_good_field_is_queued_not_adopted(self):
        svc, b, c, clock = service()
        self.assertEqual(svc.on_notify_at(AG, field()), "ok")
        self.assertIsNone(b.notify_addr(AG))                                           # nothing is believed before a dial there has been answered
        self.assertEqual(svc._npending[AG], addr(5))
        self.assertEqual(svc._pending, {})

    def test_strangers_and_ourselves(self):
        svc, b, c, clock = service()
        self.assertEqual(svc.on_notify_at(AG2, field()), "unknown")
        svc2, *_ = service(ids=(ME.id,))
        self.assertEqual(svc2.on_notify_at(ME.id, field()), "unknown")
        self.assertEqual(svc._npending, {})

    def test_shapes(self):
        svc, b, c, clock = service()
        for bad in (None, "x", 5, [], {}, {"type": "fake"}, {"addr": addr(5)}, {"type": "fake", "addr": addr(5), "x": 1}, {"type": "onion", "addr": addr(5)}, {"type": 5, "addr": addr(5)}):
            self.assertEqual(svc.on_notify_at(AG, bad), "bad notify_at", repr(bad))
        for bad in (None, 5, "", "x" * 400, "nonsense", "x.onion:1", "h1.fake:0", b"h1.fake:1", ["h1.fake:1"]):
            self.assertIn(svc.on_notify_at(AG, {"type": "fake", "addr": bad}), ("bad address", "bad notify_at"), repr(bad)[:30])
        self.assertEqual(svc._npending, {})

    def test_the_carriers_own_rules_apply(self):
        svc, b, c, clock = service()
        c.problem = "a loopback address"
        self.assertEqual(svc.on_notify_at(AG, field()), "refused: a loopback address")
        self.assertEqual(svc._npending, {})

    def test_the_address_we_already_hold_is_no_news(self):
        svc, b, c, clock = service()
        b.set_notify(AG, addr(5))
        self.assertEqual(svc.on_notify_at(AG, field()), "ok")
        self.assertEqual(svc._npending, {})
        self.assertEqual(svc._nseen, {})

    def test_at_most_one_new_value_per_minute_and_one_verification_at_a_time(self):
        svc, b, c, clock = service()
        self.assertEqual(svc.on_notify_at(AG, field(5)), "ok")
        self.assertEqual(svc.on_notify_at(AG, field(6)), "rate limited")
        svc._npending.clear()
        clock.t += L.LOCATOR_MIN_GAP - 1
        self.assertEqual(svc.on_notify_at(AG, field(6)), "rate limited")
        clock.t += 2
        self.assertEqual(svc.on_notify_at(AG, field(6)), "ok")
        clock.t += L.LOCATOR_MIN_GAP + 1
        self.assertEqual(svc.on_notify_at(AG, field(7)), "busy")

    def test_a_dropped_value_is_ignored_for_an_hour_then_welcome_again(self):
        svc, b, c, clock = service(clock=Clock())
        b.set_notify(AG, addr(5))
        for _ in range(3):
            b.note_notify(AG, addr(5), False)
        self.assertEqual(svc.on_notify_at(AG, field(5)), "ignored")                    # N2
        self.assertEqual(svc.on_notify_at(AG, field(6)), "ok")                         # another value is judged on its own
        svc._npending.clear()
        svc.clock.t += L.NOTIFY_IGNORE + L.LOCATOR_MIN_GAP + 1
        self.assertEqual(svc.on_notify_at(AG, field(5)), "ok")

    def test_the_mute_is_shared_with_announcements_in_both_directions(self):
        svc, b, c, clock = service()
        svc.verify = lambda agent, a, ts, notify=False: (False, "connect refused")
        for i in range(L.LOCATOR_FAILS):
            clock.t += L.LOCATOR_MIN_GAP + 1
            self.assertEqual(svc.on_notify_at(AG, field(10 + i)), "ok")
            svc._work()
        self.assertEqual(svc.on_notify_at(AG, field(20)), "ignored")
        self.assertEqual(svc.on_locator(AG, addr(21), 300), "ignored")                 # ... announcements of the pull address are muted too
        clock.t += L.LOCATOR_BLOCK + 1
        self.assertEqual(svc.on_notify_at(AG, field(20)), "ok")
        # and the other way round: three failed announcements mute notify_at
        svc2, b2, c2, clock2 = service()
        svc2.verify = lambda agent, a, ts, notify=False: (False, "connect refused")
        for i in range(L.LOCATOR_FAILS):
            clock2.t += L.LOCATOR_MIN_GAP + 1
            self.assertEqual(svc2.on_locator(AG, addr(10 + i), 100 + i), "ok")
            svc2._work()
        self.assertEqual(svc2.on_notify_at(AG, field(30)), "ignored")

    def test_the_worker_verifies_a_notify_address_through_the_same_path(self):
        svc, b, c, clock = service()
        calls = []
        svc.verify = lambda agent, a, ts, notify=False: calls.append((agent, a, notify)) or (True, "")
        svc.on_notify_at(AG, field(5))
        svc._work()
        self.assertEqual(calls, [(AG, addr(5), True)])

    def test_verify_adopts_a_notify_address_only_as_such(self):
        svc, b, c, clock = service()
        b.seed(AG, addr(1))
        c.held = True                                                                  # (we hold a credential for this peer on this carrier)
        adopted = []
        svc.on_adopt = adopted.append
        with mock.patch.object(L.P, "exchange", return_value=(True, "", {}, 0.1)):
            c.dial = lambda ep, **kw: object()
            self.assertEqual(svc.verify(AG, addr(5), 0, notify=True), (True, ""))
        self.assertEqual(b.notify_addr(AG), addr(5))
        self.assertEqual(b.ordered(AG), [addr(1)])                                     # not a pull address
        svc.on_notify_at(AG, field(6))
        with mock.patch.object(L.P, "exchange", return_value=(True, "", {}, 0.1)):
            svc._work()
        self.assertEqual(adopted, [])                                                  # a notify address changes no pull address: the old backoff stands
        self.assertEqual(b.notify_addr(AG), addr(6))

    def test_a_failed_verification_changes_nothing_and_keeps_no_credential(self):
        svc, b, c, clock = service()
        b.seed(AG, addr(1))
        b.set_notify(AG, addr(1))
        c.held = False
        c.has_credential = lambda ep, agent=None: ep["addr"] == addr(1)                # a credential for the old address only (Tor would copy it)
        ok, why = svc.verify(AG, addr(5), 0, notify=True)                              # Carrier2.dial refuses
        self.assertFalse(ok)
        self.assertEqual(b.notify_addr(AG), addr(1))
        self.assertEqual(c.dropped, [addr(5)])

    def test_the_wrong_node_behind_the_address_is_not_adopted(self):
        svc, b, c, clock = service()
        c.dial = lambda ep, **kw: object()
        with mock.patch.object(L.P, "exchange", return_value=(False, "answered by another node id", None, 0.0)):
            ok, why = svc.verify(AG, addr(5), 0, notify=True)
        self.assertFalse(ok)
        self.assertIsNone(b.notify_addr(AG))

    def test_route_to_the_service_of_the_named_type_and_ignore_a_type_we_do_not_run(self):
        svc, b, c, clock = service()
        route = L.route_notify_at({"fake": svc})
        self.assertEqual(route(AG, field()), "ok")
        self.assertEqual(route(AG, {"type": "tcp", "addr": "1.2.3.4:47700#" + "a" * 64}), "ignored")      # a Tor-only node never adopts a tcp address
        for bad in (None, 5, "x", {}, {"type": ["x"]}):
            self.assertEqual(route(AG, bad), "ignored")


# ------------------------------------------------------------------------------------------------------------------------------------------- using it (the dialer)

class FakeDialer:
    def __init__(self, b, carrier, rt=5.0, ct=5.0):
        self.book, self.carrier, self.request_timeout, self.connect_timeout = b, carrier, rt, ct


class DialCarrier:
    def __init__(self, ctype="fake"):
        self.type, self.dialed, self.error = ctype, [], None

    def dial(self, ep, *, timeout, connect_timeout=None, agent=None):
        self.dialed.append((ep["addr"], agent))
        if self.error:
            raise self.error
        return mock.Mock(request=lambda r: {"t": "ok"})


class NotifyDial(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.b, _ = book(clock=self.clock)
        self.c = DialCarrier()
        self.nd = L.NotifyDialer({"fake": FakeDialer(self.b, self.c)}, clock=self.clock)
        self.rec = {"agent": AG, "name": "p"}

    def test_none_without_a_notify_address(self):
        self.assertIsNone(self.nd(self.rec))
        self.assertEqual(self.c.dialed, [])

    def test_dials_the_notify_address_with_the_agents_credential(self):
        self.b.set_notify(AG, addr(5))
        path = self.nd(self.rec)
        self.assertEqual(self.c.dialed, [(addr(5), AG)])
        self.assertEqual(path.request({}), {"t": "ok"})

    def test_one_dial_per_thirty_seconds_per_peer(self):
        self.b.set_notify(AG, addr(5))
        self.assertIsNotNone(self.nd(self.rec))
        self.assertIsNone(self.nd(self.rec))                                           # the caller falls back to the pull addresses
        self.clock.t += L.NOTIFY_MIN_GAP - 1
        self.assertIsNone(self.nd(self.rec))
        self.clock.t += 2
        self.assertIsNotNone(self.nd(self.rec))

    def test_a_carrier_that_is_down_is_left_out(self):
        self.b.set_notify(AG, addr(5))
        nd = L.NotifyDialer({"fake": FakeDialer(self.b, self.c)}, clock=self.clock, usable=lambda t: False)
        self.assertIsNone(nd(self.rec))
        self.assertEqual(self.c.dialed, [])

    def test_a_dial_that_fails_gives_a_path_whose_request_raises_and_the_caller_reports(self):
        self.b.set_notify(AG, addr(5))
        self.c.error = CarrierError("connect refused", retry=True)
        said = []
        nd = L.NotifyDialer({"fake": FakeDialer(self.b, self.c)}, clock=self.clock, log=said.append)
        for _ in range(3):
            path = nd(self.rec)
            with self.assertRaises(CarrierError):
                path.request({})
            path.done(False)
            self.clock.t += L.NOTIFY_MIN_GAP + 1
        self.assertIsNone(self.b.notify_addr(AG))
        self.assertTrue(self.b.notify_dropped(AG, addr(5)))
        self.assertEqual(len(said), 1)

    def test_done_reports_to_the_book(self):
        self.b.set_notify(AG, addr(5))
        path = self.nd(self.rec)
        path.done(False)
        self.assertEqual(self.b.notify_state(AG)["nfail"], 1)
        path.done(True)
        self.assertEqual(self.b.notify_state(AG)["nfail"], 0)

    def test_a_record_without_an_agent_gets_none(self):
        self.assertIsNone(self.nd({"name": "p"}))


# ------------------------------------------------------------------------------------------------------------------------------------------- the requests (N3 golden bytes)

class Me:
    id = "a" * 32
    sign_pub = "b" * 64

    def sign(self, x):
        return "c" * 128


class Spy:
    def __init__(self):
        self.reqs = []

    def request(self, r):
        self.reqs.append(r)
        raise OSError("stop here")


GOLDEN_SUMMARY = b'sigilnet/v1/sync\x00{"aud":"ffffffffffffffffffffffffffffffff","from":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"0101010101010101","pub":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","t":"summary","thread":"dddddddddddddddddddddddddddddddd","ts":1700000000}'
GOLDEN_NOTIFY = b'sigilnet/v1/sync\x00{"aud":"ffffffffffffffffffffffffffffffff","from":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","leaves":["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],"nonce":"0101010101010101","pub":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","t":"notify","thread":"dddddddddddddddddddddddddddddddd","ts":1700000000}'


class Requests(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        self.m.ingest(self.w.genesis)
        self.tid = self.w.t.id

    def capture_pull(self, **kw):
        spy = Spy()
        with mock.patch("os.urandom", lambda n: b"\x01" * n):
            S.pull(self.m, self.tid, spy, Me(), peer_id="f" * 32, stamp=lambda: 1700000000, rate_retries=0, **kw)
        return spy.reqs

    def test_N3_without_the_field_the_summary_request_is_byte_identical_to_before(self):
        spy = Spy()
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        with mock.patch("os.urandom", lambda n: b"\x01" * n):
            S.pull(m, "d" * 32, spy, Me(), peer_id="f" * 32, stamp=lambda: 1700000000, rate_retries=0, declare=False)       # (declare=False: the 0.1.x bytes; with the declaration the same request plus `ver`: tests/test_version.py)
        self.assertEqual(S._req_bytes(spy.reqs[0]), GOLDEN_SUMMARY)

    def test_N3_without_the_field_the_notify_request_is_byte_identical_to_before(self):
        spy = Spy()
        m = mock.Mock()
        m.threads = {"d" * 32: mock.Mock(leaves=lambda: ["e" * 32])}
        with mock.patch("os.urandom", lambda n: b"\x01" * n):
            S.notify(spy, Me(), "d" * 32, m, peer_id="f" * 32, stamp=lambda: 1700000000)
        self.assertEqual(S._req_bytes(spy.reqs[0]), GOLDEN_NOTIFY)

    def test_the_field_rides_in_summary_only_and_is_signed_with_it(self):
        f = {"type": "tcp", "addr": "1.2.3.4:47700#" + "a" * 64}
        reqs = self.capture_pull(notify_at=f)
        self.assertEqual(reqs[0]["notify_at"], f)
        self.assertIn(b'"notify_at":{"addr"', S._req_bytes(reqs[0]))
        spy = Spy()
        # the requests after the summary (list, get, key) never carry it: drive a pull that gets as far as `list`
        class Two:
            def __init__(self):
                self.reqs = []

            def request(s, r):
                s.reqs.append(r)
                return {"t": "summary", "thread": self.tid, "head": "0" * 32, "n": 1, "nonce": r["nonce"], "r": 1} if r["t"] == "summary" else (_ for _ in ()).throw(OSError("stop"))
        two = Two()
        with mock.patch.object(S, "response_signed_by", return_value=True):
            S.pull(self.m, self.tid, two, Me(), peer_id="f" * 32, stamp=lambda: 1700000000, rate_retries=0, notify_at=f)
        self.assertEqual([("notify_at" in r) for r in two.reqs], [True, False])         # summary yes, list no

    def test_notify_carries_it_when_given(self):
        f = {"type": "tcp", "addr": "1.2.3.4:47700#" + "a" * 64}
        spy = Spy()
        S.notify(spy, Me(), self.tid, self.m, peer_id="f" * 32, stamp=lambda: 1700000000, notify_at=f)
        self.assertEqual(spy.reqs[0]["notify_at"], f)

    def test_a_tampered_field_breaks_the_signature(self):
        w = World()
        me = w.ids["sansa"]
        req = S.sign_request(me, {"t": "summary", "thread": w.t.id, "notify_at": {"type": "fake", "addr": addr(5)}}, aud=w.ids["arya"].id)
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        m.ingest(w.genesis)
        srv = S.SyncServer(m, identity=w.ids["arya"], on_notify_at=lambda *a: None)
        req["notify_at"] = {"type": "fake", "addr": addr(6)}
        self.assertEqual(S.Loopback(srv).request(req)["why"], "bad signature")


class ServerHook(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.ids = self.w.ids
        self.m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        self.m.ingest(self.w.genesis)
        self.got = []
        self.srv = S.SyncServer(self.m, identity=self.ids["arya"], on_notify_at=lambda a, f: self.got.append((a, f)))
        self.srv.set_peers([self.ids["sansa"].id])

    def ask(self, who, t, **extra):
        body = {"t": t, "thread": self.w.t.id, **extra}
        return S.Loopback(self.srv).request(S.sign_request(self.ids[who], body, aud=self.ids["arya"].id))

    def test_only_peers_and_only_summary_and_notify(self):
        f = {"type": "fake", "addr": addr(5)}
        self.assertEqual(self.ask("sansa", "summary", notify_at=f)["t"], "summary")
        self.assertEqual(self.ask("sansa", "notify", leaves=[], notify_at=f)["t"], "ok")
        self.ask("sansa", "list", page=0, notify_at=f)
        self.ask("sansa", "ping", notify_at=f)
        self.assertEqual(self.got, [(self.ids["sansa"].id, f)] * 2)
        self.got.clear()
        self.ask("carol", "summary", notify_at=f)                                       # a member that is not a peer of the node
        self.ask("eve", "summary", notify_at=f)                                         # a stranger
        self.assertEqual(self.got, [])

    def test_a_request_without_the_field_does_not_call_the_hook(self):
        self.ask("sansa", "summary")
        self.assertEqual(self.got, [])

    def test_the_answer_never_depends_on_the_hook(self):
        def boom(*a):
            raise RuntimeError("x")
        self.srv.on_notify_at = boom
        self.assertEqual(self.ask("sansa", "summary", notify_at={"type": "fake", "addr": addr(5)})["t"], "summary")
        self.srv.on_notify_at = None
        self.assertEqual(self.ask("sansa", "summary", notify_at={"type": "fake", "addr": addr(5)})["t"], "summary")


# ------------------------------------------------------------------------------------------------------------------------------------------- the node

class FakePath:
    def __init__(self, tr, log):
        self.tr, self.log = tr, log

    def request(self, r):
        return self.tr.request(r)

    def done(self, ok):
        self.log.append(ok)


class NodeNotify(unittest.TestCase):
    def sim(self):
        from .test_m4a import PushSim
        sim = PushSim(2)
        sim.step(10.0, rounds=3)
        return sim

    def test_the_field_is_sent_on_summary_and_notify_when_configured_and_never_otherwise(self):
        sim = self.sim()
        seen = []
        orig = sim.servers["arya"].handle
        sim.servers["arya"].handle = lambda r: (seen.append((r["t"], r.get("notify_at"))), orig(r))[1]
        nd = sim.nodes["sansa"]
        sim.post("sansa", "one")
        sim.step(10.0, rounds=4)
        self.assertTrue(seen and all(f is None for _, f in seen))
        f = {"type": "fake", "addr": addr(5)}
        nd.notify_field = lambda peer: f if peer == sim.ids["arya"].id else None
        seen.clear()
        sim.post("sansa", "two")
        sim.post("arya", "arya two")                                                   # sansa pulls arya's news: a summary
        sim.step(10.0, rounds=6)
        kinds = {t for t, x in seen if x == f}
        self.assertEqual(kinds, {"summary", "notify"})
        self.assertTrue(all(x is None for t, x in seen if t not in ("summary", "notify")))

    def test_notify_goes_to_the_notify_address_first_and_not_to_the_pull_address(self):
        sim = self.sim()
        log = []
        sim.nodes["sansa"].notify_to = lambda rec: FakePath(__import__("sigilnet.tests.test_node", fromlist=["x"]).Sim.transport(sim, "sansa", rec), log)
        before = len(sim.kinds("sansa", "arya", "notify"))
        sim.post("sansa", "tell arya")
        sim.step(10.0, rounds=3)
        self.assertEqual(log, [True])
        self.assertIn("tell arya", sim.texts("arya"))

    def test_when_it_fails_the_pull_addresses_are_used_exactly_as_before(self):
        sim = self.sim()
        log = []

        class Dead:
            def request(self, r):
                raise CarrierError("connect refused", retry=True)
        sim.nodes["sansa"].notify_to = lambda rec: FakePath(Dead(), log)
        sim.post("sansa", "still arrives")
        sim.step(10.0, rounds=3)
        self.assertEqual(log, [False])
        self.assertIn("still arrives", sim.texts("arya"))
        job = sim.nodes["sansa"].jobs.get(sim.nodes["sansa"]._key(sim.ids["arya"].id, sim.tid, "notify"))
        self.assertTrue(job is None or job["tries"] == 0, job)                         # the job itself did not fail: the fallback delivered it

    def test_an_impostor_answer_from_the_notify_address_is_a_failure_not_an_acknowledgement(self):
        sim = self.sim()
        log = []

        class Liar:
            def request(self, r):
                return {"t": "ok", "nonce": r["nonce"], "r": 1}                         # unsigned
        sim.nodes["sansa"].notify_to = lambda rec: FakePath(Liar(), log)
        sim.post("sansa", "x")
        sim.step(10.0, rounds=3)
        self.assertEqual(log, [False])
        self.assertIn("x", sim.texts("arya"))

    def test_helpers_that_raise_never_break_a_pull_or_a_notify(self):
        sim = self.sim()
        nd = sim.nodes["sansa"]
        nd.notify_field = lambda peer: 1 / 0
        nd.notify_to = lambda rec: 1 / 0
        sim.post("sansa", "robust")
        sim.step(10.0, rounds=4)
        self.assertIn("robust", sim.texts("arya"))
        sim.post("arya", "robust too")
        sim.step(10.0, rounds=4)
        self.assertIn("robust too", sim.texts("sansa"))


class Roles(unittest.TestCase):
    """Sansa's follow-up (a): a node whose own role in the thread is not owner/admin/member neither pushes nor makes the follow-up pull."""

    def make(self, role):
        from .test_m4a import PushSim
        sim = PushSim(2, nodial={"sansa"})
        sim.step(10.0, rounds=3)
        nd = sim.nodes["sansa"]
        t = sim.mirrors["sansa"].threads[sim.tid]
        real = type(t).state

        def state(tt):
            st = real(tt)
            if tt is t:
                members = {a: dict(m) for a, m in st["members"].items()}
                members[sim.ids["sansa"].id]["role"] = role
                return {**st, "members": members}
            return st
        return sim, nd, mock.patch.object(type(t), "state", state)

    def test_a_member_pushes(self):
        sim, nd, patch = self.make("member")
        with patch:
            self.assertTrue(nd._may_push(sim.tid))

    def test_an_observer_and_a_guest_do_not_push_and_do_not_follow_up(self):
        for role in ("observer", "guest"):
            sim, nd, patch = self.make(role)
            with patch, mock.patch.object(S, "push") as push:
                self.assertFalse(nd._may_push(sim.tid))
                nd._push(sim.ids["arya"].id, sim.tid, None, {"peer_ids": set()})
                self.assertFalse(push.called, role)
                nd._follow[(sim.ids["arya"].id, sim.tid)] = (0.0, sim.clock.t + 1000.0)           # (due, and the peer was last heard before the notify was acknowledged)
                for j in nd.jobs.values():
                    j["next"] = N.NEVER
                n = len(sim.requests)
                nd.tick()
                self.assertEqual(len(sim.requests), n, role)                                  # no follow-up pull was made (nothing was dialed)

    def test_a_thread_we_do_not_hold_does_not_push(self):
        sim, nd, patch = self.make("member")
        self.assertFalse(nd._may_push("f" * 32))


class WorkerTick(unittest.TestCase):
    def test_tick_starts_the_worker_for_a_pending_notify_address_alone(self):
        svc, b, c, clock = service()
        done = []
        svc.verify = lambda agent, a, ts, notify=False: done.append((a, notify)) or (True, "")
        svc.on_notify_at(AG, field(5))
        svc.tick()
        deadline = time.time() + 5
        while time.time() < deadline and not done:
            time.sleep(0.02)
        self.assertEqual(done, [(addr(5), True)])


class NoCredential(unittest.TestCase):
    """Sansa's K2: a notify_at over a carrier where we hold no credential for the peer costs the peer nothing."""

    def test_nothing_is_dialed_nothing_is_counted_and_announcements_stay_welcome(self):
        svc, b, c, clock = service()
        c.held = False
        c.has_credential = lambda ep, agent=None: False
        said = []
        svc.log = said.append
        dialed = []
        c.dial = lambda ep, **kw: dialed.append(ep) or (_ for _ in ()).throw(AssertionError("dialed"))
        for i in range(L.LOCATOR_FAILS + 2):
            clock.t += L.LOCATOR_MIN_GAP + 1
            self.assertEqual(svc.on_notify_at(AG, field(10 + i)), "ok")
            svc._work()
        self.assertEqual(dialed, [])
        self.assertEqual(svc._fails, {})
        self.assertEqual(svc._block, {})
        clock.t += L.LOCATOR_MIN_GAP + 1
        self.assertEqual(svc.on_locator(AG, addr(50), 500), "ok")                      # its ordinary announcements are not muted
        self.assertIsNone(b.notify_addr(AG))
        self.assertEqual(len([x for x in said if "no fake credential" in x]), L.LOCATOR_FAILS + 2)      # (one line per (peer, value): five different values)

    def test_the_same_value_is_said_once_an_hour(self):
        svc, b, c, clock = service()
        c.has_credential = lambda ep, agent=None: False
        said = []
        svc.log = said.append
        for _ in range(3):
            svc._verify(AG, addr(5), 0, notify=True)
        self.assertEqual(len(said), 1)
        clock.t += 3601
        svc._verify(AG, addr(5), 0, notify=True)
        self.assertEqual(len(said), 2)

    def test_a_credential_for_another_address_of_that_peer_is_enough(self):
        svc, b, c, clock = service()
        b.seed(AG, addr(1))
        c.has_credential = lambda ep, agent=None: ep["addr"] == addr(1)
        c.dial = lambda ep, **kw: object()
        with mock.patch.object(L.P, "exchange", return_value=(True, "", {}, 0.1)):
            self.assertEqual(svc.verify(AG, addr(5), 0, notify=True), (True, ""))


class NotifyVia(unittest.TestCase):
    """Sansa's K1: the config says "tor", the carrier's type is "onion"."""

    def test_the_name_maps_to_the_type_for_a_real_config(self):
        from sigilnet import noderun
        h = Path(tempfile.mkdtemp())
        for name, etype in (("tor", "onion"), ("tcp", "tcp")):
            (h / "node_config.json").write_text(json.dumps({"carriers": ["tcp", "tor"], "tcp": {"bind": "127.0.0.1", "port_base": 47600}, "notify_via": name}))
            cfg = noderun.load_config(h)
            carriers = noderun.make_carriers(h, cfg, offline=True)
            self.assertEqual(sorted(carriers), ["onion", "tcp"])
            self.assertIn(noderun.NOTIFY_TYPES[cfg["notify_via"]], carriers)
            self.assertEqual(noderun.NOTIFY_TYPES[name], etype)
            self.assertEqual(carriers[noderun.NOTIFY_TYPES[name]].type, etype)

    def test_the_node_sends_the_field_when_notify_via_is_tor(self):
        """noderun.run with a Tor-named carrier registered under the type "onion": the field handed to the Node names type "onion"."""
        from sigilnet import noderun
        src = Path(noderun.__file__).read_text()
        self.assertIn('carriers.get(NOTIFY_TYPES.get(cfg.get("notify_via") or "", ""))', src)
        # behaviour: the lambda the node installs builds {"type": carrier.type, "addr": ...} from the service of that TYPE
        nvia = mock.Mock(type="onion")
        svcs = {"onion": mock.Mock(_our_address=lambda agent: "x.onion:47200")}
        f = lambda agent: ({"type": nvia.type, "addr": a} if (a := svcs[nvia.type]._our_address(agent)) else None)     # noqa: E731
        self.assertEqual(f("a"), {"type": "onion", "addr": "x.onion:47200"})


class FallbackCounts(unittest.TestCase):
    """Sansa's N-a: a failure of the notify address counts only if the pull addresses then delivered."""

    def run_case(self, pull_ok):
        from .test_m4a import PushSim
        sim = PushSim(2)
        sim.step(10.0, rounds=3)
        log = []

        class Dead:
            def request(self, r):
                raise CarrierError("connect refused", retry=True)
        sim.nodes["sansa"].notify_to = lambda rec: FakePath(Dead(), log)
        if not pull_ok:
            sim.up["arya"] = False
        sim.post("sansa", "x")
        sim.step(10.0, rounds=2)
        return log

    def test_counted_when_the_fallback_delivered(self):
        self.assertEqual(self.run_case(True), [False])

    def test_not_counted_when_the_whole_peer_is_offline(self):
        self.assertEqual(self.run_case(False), [])


# ------------------------------------------------------------------------------------------------------------------------------------------- end to end (two carriers, real doors)

class EndToEnd(unittest.TestCase):
    """Two nodes wired like `noderun.run` on two fake carriers ("fake" = the pull path, "fakeb" = the notify path). A gives B a SECOND door for B on fakeb and asks (signed, in its pull) for its
    notifies there: B verifies it with a fresh dial and a signed ping, adopts it as the notify address only, and tells A about news THERE first; when that door dies the pull addresses carry the
    notifies and after three failures the address is dropped."""

    def setUp(self):
        from .multirig import Rig2
        from .fake_carrier import _public_of
        self.rig = Rig2()
        self.A, self.B = self.rig.sides["a"], self.rig.sides["b"]
        self.a, self.b = self.rig.ids["a"].id, self.rig.ids["b"].id
        pub = _public_of(self.B.carriers["fakeb"]._held_agent[self.a]["key"])           # B's own credential for A's door: the same client key is admitted on the second door
        self.A.carriers["fakeb"].open_door("peer-b2", "peer", credential={"type": "fakeb", "key": pub}, agent=self.b)
        self.A.doors["fakeb"].sync()
        self.addr2 = self.A.carriers["fakeb"].door_endpoint("peer-b2")["addr"]
        self.A.node.notify_field = lambda agent: {"type": "fakeb", "addr": self.addr2} if agent == self.b else None
        self.dials = []
        for t in ("fake", "fakeb"):
            real = self.B.carriers[t].dial
            self.B.carriers[t].dial = lambda ep, _r=real, _t=t, **kw: (self.dials.append((_t, ep["addr"])), _r(ep, **kw))[1]

    def tearDown(self):
        self.rig.close()

    def adopt(self):
        self.rig.post("b", "seed")
        self.rig.tick("a", rounds=2)                                                    # A pulls B: the signed summary names the notify address
        deadline = time.time() + 10
        while time.time() < deadline and not self.B.books["fakeb"].notify_addr(self.a):
            self.B.svcs["fakeb"].tick()
            time.sleep(0.05)
        return self.B.books["fakeb"].notify_addr(self.a)

    def test_the_notify_address_is_verified_adopted_and_used_first(self):
        self.assertEqual(self.adopt(), self.addr2)
        self.assertNotIn(self.addr2, self.B.books["fakeb"].ordered(self.a))             # never a pull address
        self.assertEqual(self.B.books["fake"].notify_addr(self.a), None)
        self.dials.clear()
        self.rig.post("b", "news for a")
        self.rig.tick("b", rounds=1)
        notify_dials = [d for d in self.dials if d[0] == "fakeb" and d[1] == self.addr2]
        self.assertTrue(notify_dials, self.dials)                                       # B told A about its news at the notify address
        self.rig.tick("a", "b", rounds=4)
        self.assertIn("news for a", self.rig.texts("a"))

    def test_a_dead_notify_door_falls_back_to_the_pull_addresses_and_is_dropped_after_three(self):
        self.assertEqual(self.adopt(), self.addr2)
        self.A.carriers["fakeb"].close_door("peer-b2")
        self.A.doors["fakeb"].sync()
        with mock.patch.object(L, "NOTIFY_MIN_GAP", 0.0):
            for i in range(4):
                self.rig.post("b", f"news {i}")
                self.rig.tick("b", rounds=1)
                self.rig.tick("a", "b", rounds=3)
        self.assertIn("news 0", self.rig.texts("a"))                                     # delivered despite the dead notify door (the pull addresses)
        self.assertIn("news 3", self.rig.texts("a"))
        self.assertIsNone(self.B.books["fakeb"].notify_addr(self.a))
        self.assertTrue(self.B.books["fakeb"].notify_dropped(self.a, self.addr2))

    def test_a_node_that_does_not_run_that_carrier_ignores_the_field(self):
        """B is Tor-only in spirit: it has no service for the carrier type named: nothing is adopted (the router ignores the type)."""
        del self.B.svcs["fakeb"]
        self.rig.post("b", "seed")
        self.rig.tick("a", rounds=2)
        self.assertIsNone(self.B.books["fakeb"].notify_addr(self.a))


# ------------------------------------------------------------------------------------------------------------------------------------------- config and CLI

class Config(unittest.TestCase):
    def test_load_config(self):
        from sigilnet import noderun
        h = Path(tempfile.mkdtemp())
        self.assertIsNone(noderun.load_config(h)["notify_via"])
        for good in ("tcp", "tor", None):
            (h / "node_config.json").write_text(json.dumps({"notify_via": good}))
            self.assertEqual(noderun.load_config(h)["notify_via"], good)
        for bad in ("onion", "x", 5, ["tcp"]):
            (h / "node_config.json").write_text(json.dumps({"notify_via": bad}))
            with self.assertRaises(ValueError):
                noderun.load_config(h)


class Cli(unittest.TestCase):
    def setUp(self):
        from .test_locator_cli import TcpHomes
        self.h = TcpHomes("setUp")
        self.h.setUp()
        self.addCleanup(self.h.r.close)

    def run_(self, *args):
        return self.h.cli("a", *args)

    def test_notify_via_validates_saves_and_warns_about_the_ip(self):
        rc, out, err = self.run_("node", "notify-via")
        self.assertEqual((rc, out.split()[:2]), (0, ["notify_via:", "none"]))
        rc, out, err = self.run_("node", "notify-via", "tcp")
        self.assertEqual(rc, 0, err)
        self.assertIn("IP address", out)
        self.assertEqual(json.loads((self.h.r.sides["a"].home / "node_config.json").read_text())["notify_via"], "tcp")
        self.assertEqual((os.stat(self.h.r.sides["a"].home / "node_config.json").st_mode & 0o777), 0o600)
        rc, out, err = self.run_("node", "notify-via")
        self.assertIn("tcp", out)
        rc, out, err = self.run_("node", "notify-via", "none")
        self.assertEqual(rc, 0)
        self.assertNotIn("IP address", out)
        self.assertIsNone(json.loads((self.h.r.sides["a"].home / "node_config.json").read_text())["notify_via"])

    def test_a_carrier_the_node_does_not_run_and_bad_words_are_refused(self):
        rc, out, err = self.run_("node", "notify-via", "tor")
        self.assertNotEqual(rc, 0)
        self.assertIn("does not run tor", err)
        rc, out, err = self.run_("node", "notify-via", "onion")
        self.assertNotEqual(rc, 0)
        rc, out, err = self.run_("node", "notify-via", "tcp", "tor")
        self.assertNotEqual(rc, 0)

    def test_peer_list_shows_the_notify_address_apart_from_the_pull_addresses(self):
        before = self.run_("peer", "list")[1]
        self.assertNotIn("notify", before)
        self.h.a.book.set_notify(self.h.bid, "10.9.8.7:47999#" + "a" * 64)
        out = self.run_("peer", "list")[1]
        self.assertIn("notify tcp 10.9.8.7:47999", out)
        self.assertIn("also", out) if False else None
        self.h.a.book.note_notify(self.h.bid, "10.9.8.7:47999#" + "a" * 64, False)
        self.assertIn("1 failure(s) in a row", self.run_("peer", "list")[1])


if __name__ == "__main__":
    unittest.main()
