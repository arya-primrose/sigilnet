"""The locator service end to end on the rig (two agents, their nodes, servers, doors): announcing our address, verifying an announced one, the retry cycle, the server request,
PeerBook seeding, and an old home with no locator book."""
import json
import random
import tempfile
import unittest
from pathlib import Path

from sigilnet import locators as L
from sigilnet import node as N
from sigilnet import sync as S
from sigilnet.carrier import CarrierError
from sigilnet.keys import Identity
from sigilnet.tests import fake_carrier  # noqa: F401  (registers the "fake" endpoint type)
from sigilnet.tests.fake_carrier import FakeCarrier, FakeNet
from sigilnet.tests.locrig import Rig


class Clock:
    def __init__(self, t=10_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Spy:
    """Records what the SyncServer hands to on_locator, and passes it on."""

    def __init__(self, side):
        self.calls = []
        self.inner = side.svc.on_locator
        side.srv.on_locator = self

    def __call__(self, agent, addr, ts):
        out = self.inner(agent, addr, ts)
        self.calls.append((agent, addr, ts, out))
        return out


class Announce(unittest.TestCase):
    def setUp(self):
        self.r = Rig("fake")
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.aid, self.bid = self.r.ids["a"].id, self.r.ids["b"].id

    def tearDown(self):
        self.r.close()

    def test_we_tell_a_peer_the_address_of_the_door_we_offer_it_and_nothing_else(self):
        spy = Spy(self.a)
        self.r.service("b")
        self.assertEqual(len(spy.calls), 1)
        agent, addr, ts, out = spy.calls[0]
        self.assertEqual((agent, out), (self.bid, "ok"))
        self.assertEqual(addr, self.b.carrier.door_endpoint("peer-a")["addr"])      # B's door FOR a, no other address
        self.assertEqual(self.b.book.announced(self.aid), addr)

    def test_the_request_carries_exactly_one_address_and_is_signed_and_addressed_to_the_peer(self):
        seen = []
        orig = self.a.srv.handle
        self.a.srv.handle = lambda req: (seen.append(dict(req)), orig(req))[1]
        for name, d in list(self.a.doors.servers.items()):
            pass
        # rebuild A's doors so that they use the recording handler
        self.a.doors.stop()
        from sigilnet.doors import Doors
        self.a.doors = Doors(self.a.carrier, self.a.srv, lambda *x: None, {})
        self.a.doors.sync()
        self.r.service("b")
        reqs = [q for q in seen if q.get("t") == "locator"]
        self.assertEqual(len(reqs), 1)
        q = reqs[0]
        self.assertEqual(set(q), {"t", "addr", "from", "pub", "ts", "nonce", "aud", "sig"})
        self.assertEqual((q["from"], q["aud"]), (self.bid, self.aid))
        self.assertIsInstance(q["addr"], str)

    def test_an_address_already_announced_is_not_announced_again(self):
        spy = Spy(self.a)
        self.r.service("b")
        self.r.service("b")
        self.r.service("b")
        self.assertEqual(len(spy.calls), 1)

    def test_a_changed_address_is_announced_again(self):
        spy = Spy(self.a)
        self.r.service("b")
        new = self.r.move("b")
        self.r.service("b")
        self.assertEqual(len(spy.calls), 2)
        self.assertEqual(spy.calls[1][1], new)
        self.assertEqual(self.b.book.announced(self.aid), new)

    def test_a_failed_announcement_is_retried_with_a_growing_wait(self):
        clock = Clock()
        self.b.svc.clock = clock
        self.a.carrier.close_door("peer-b")                          # A's door for B is gone: B cannot reach A
        waits = []
        for _ in range(7):
            self.r.service("b")
            nxt, tries = self.b.svc._ann[self.aid]
            waits.append(round(nxt - clock.t))
            clock.t = nxt + 0.5
        self.assertEqual(waits, [15, 30, 60, 120, 300, 300, 300])
        self.assertIsNone(self.b.book.announced(self.aid))

    def test_nothing_is_attempted_before_the_wait_is_over(self):
        clock = Clock()
        self.b.svc.clock = clock
        self.a.carrier.close_door("peer-b")
        self.r.service("b")
        self.assertEqual(self.b.svc._due(), [])
        clock.t += 14
        self.assertEqual(self.b.svc._due(), [])
        clock.t += 2
        self.assertEqual(len(self.b.svc._due()), 1)

    def test_a_peer_with_an_older_build_that_does_not_know_the_request_is_a_failure_with_backoff(self):
        self.a.srv.on_locator = None
        old = self.a.srv.handle
        self.a.srv.handle = lambda req: self.a.srv._err(req, "unknown request type") if req.get("t") == "locator" else old(req)
        from sigilnet.doors import Doors
        self.a.doors.stop()
        self.a.doors = Doors(self.a.carrier, self.a.srv, lambda *x: None, {})
        self.a.doors.sync()
        self.r.service("b")
        self.assertIsNone(self.b.book.announced(self.aid))
        self.assertEqual(self.b.svc._ann[self.aid][1], 1)

    def test_an_answer_that_is_not_signed_by_the_peer_is_no_acknowledgement(self):
        from sigilnet.doors import Doors
        evil = Identity.generate("evil")
        self.a.srv.identity = evil                                    # the thing at that address answers with the wrong node id
        self.a.doors.stop()
        self.a.doors = Doors(self.a.carrier, self.a.srv, lambda *x: None, {})
        self.a.doors.sync()
        self.r.service("b")
        self.assertIsNone(self.b.book.announced(self.aid))

    def stub_ack(self, make):
        """Make B's dialer reach a transport that answers with whatever `make(req)` returns, and announce once."""
        self.b.svc.dialer = lambda rec, left=None: type("T", (), {"request": staticmethod(make)})()
        self.r.service("b")

    def test_a_properly_signed_ok_is_an_acknowledgement(self):
        self.stub_ack(lambda req: self.a.srv._reply(req, {"t": "ok"}))
        self.assertIsNotNone(self.b.book.announced(self.aid))

    def test_an_ok_that_is_not_signed_at_all_is_no_acknowledgement(self):
        self.stub_ack(lambda req: {"t": "ok", "nonce": req["nonce"], "r": 1})
        self.assertIsNone(self.b.book.announced(self.aid))

    def test_an_ok_signed_by_somebody_else_is_no_acknowledgement(self):
        evil = S.SyncServer(self.a.mirror, identity=Identity.generate("evil"))
        self.stub_ack(lambda req: evil._reply(req, {"t": "ok"}))
        self.assertIsNone(self.b.book.announced(self.aid))

    def test_an_ok_for_another_request_is_no_acknowledgement(self):
        self.stub_ack(lambda req: self.a.srv._reply(dict(req, nonce="0" * 16), {"t": "ok"}))
        self.assertIsNone(self.b.book.announced(self.aid))

    def test_a_request_that_is_echoed_back_is_no_acknowledgement(self):
        self.stub_ack(lambda req: dict(req))
        self.assertIsNone(self.b.book.announced(self.aid))

    def test_an_error_or_unknown_answer_is_no_acknowledgement(self):
        for t in ("error", "unknown", "pong"):
            self.stub_ack(lambda req, t=t: self.a.srv._reply(req, {"t": t}))
            self.assertIsNone(self.b.book.announced(self.aid), t)
            self.b.svc._ann.clear()

    def test_our_address_is_the_door_bound_to_that_peer_only(self):
        net = FakeNet()
        c = FakeCarrier(net, "x")
        c.start()
        p1, p2 = Identity.generate("p1").id, Identity.generate("p2").id
        _, pub = c.new_credential()
        c.open_door("peer-one", "peer", credential=pub, agent=p1)
        c.open_door("peer-two", "peer", credential=pub, agent=p2)
        c.open_door("peer-free", "peer", credential=pub)             # not bound to anybody: nobody is told about it
        c.open_door("pub", "read")
        tmp = Path(tempfile.mkdtemp())
        b = L.open_book(tmp, "fake")
        svc = L.LocatorService(Identity.generate("me"), N.PeerBook(tmp / "peers.json"), c, b, L.PeerDialer(c, b, request_timeout=1, connect_timeout=1))
        self.assertEqual(svc._our_address(p1), c.door_endpoint("peer-one")["addr"])
        self.assertEqual(svc._our_address(p2), c.door_endpoint("peer-two")["addr"])
        self.assertIsNone(svc._our_address(Identity.generate("p3").id))

    def test_a_peer_with_an_endpoint_of_another_carrier_type_is_not_told_anything(self):
        other = Identity.generate("onion-only").id
        self.b.peers.add(other, "o", {"type": "onion", "addr": "a" * 56 + ".onion:47200"}, [])
        self.assertEqual([a for a, _ in self.b.svc._due() if a == other], [])
        self.b.peers.add(self.aid, "a", {"type": "onion", "addr": "b" * 56 + ".onion:47200"}, [])       # (M1a: ADDS an onion endpoint to a peer that also has a fake one: it is still told)
        self.assertEqual([a for a, _ in self.b.svc._due() if a == self.aid], [self.aid])


class Verify(unittest.TestCase):
    def setUp(self):
        self.r = Rig("fake")
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.aid, self.bid = self.r.ids["a"].id, self.r.ids["b"].id

    def tearDown(self):
        self.r.close()

    def test_a_new_address_that_answers_as_the_peer_is_adopted_and_goes_first(self):
        new = self.r.move("b")
        self.r.tick()
        ok, why = self.a.svc.verify(self.bid, new, 77)
        self.assertEqual((ok, why), (True, None) if why is None else (True, why))
        self.assertEqual(self.a.book.ordered(self.bid)[0], new)
        self.assertEqual(self.a.book.adopt_ts(self.bid), 77)

    def test_an_address_where_nobody_answers_is_not_adopted(self):
        self.r.tick()
        before = self.a.book.ordered(self.bid)
        ok, why = self.a.svc.verify(self.bid, "nobody.fake:1", 77)
        self.assertFalse(ok)
        self.assertEqual(why, "connect refused")
        self.assertEqual(self.a.book.ordered(self.bid), before)

    def test_a_carrier_that_cannot_tell_what_it_holds_never_has_a_credential_dropped(self):
        """has_credential defaults to True: a rejected candidate must not cost a carrier that does not implement it the credential it already had for that address."""
        sec, _ = self.a.carrier.new_credential()
        self.a.carrier.use_credential({"type": "fake", "addr": "ghost.fake:1"}, sec)
        self.r.tick()
        ok, why = self.a.svc.verify(self.bid, "ghost.fake:1", 5)
        self.assertFalse(ok)
        self.assertIn("ghost.fake:1", self.a.carrier._held)

    def test_an_address_where_ANOTHER_node_answers_is_not_adopted(self):
        # a door that admits OUR key but is served by a different node id: the signed pong does not verify against the peer we meant
        net = self.r.net
        carol = Identity.generate("carol")
        cc = FakeCarrier(net, "c")
        cc.start()
        sec, pub = self.a.carrier.new_credential()
        cc.open_door("peer-a", "peer", credential=pub, agent=self.aid)
        self.a.carrier.use_credential(cc.door_endpoint("peer-a"), sec, agent=self.bid)      # (our key for 'b' also opens that door)
        from sigilnet.doors import Doors
        from sigilnet.mirror import Mirror
        from sigilnet.envelope import EnvCodec
        cm = Mirror(Path(tempfile.mkdtemp()) / "m", codec=EnvCodec(Path(tempfile.mkdtemp())), rate_limit=False)
        csrv = S.SyncServer(cm, identity=carol, pong=lambda who: {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1})
        d = Doors(cc, csrv, lambda *x: None, {})
        d.sync()
        try:
            self.r.tick()
            before = self.a.book.ordered(self.bid)
            ok, why = self.a.svc.verify(self.bid, cc.door_endpoint("peer-a")["addr"], 77)
            self.assertFalse(ok)
            self.assertEqual(why, "bad answer")
            self.assertEqual(self.a.book.ordered(self.bid), before)
        finally:
            d.stop()

    def test_an_unsigned_answer_is_not_the_peer(self):
        new = self.r.move("b")
        self.b.srv.identity = None                                   # answers without a signature
        from sigilnet.doors import Doors
        self.b.doors.stop()
        self.b.doors = Doors(self.b.carrier, self.b.srv, lambda *x: None, {})
        self.b.doors.sync()
        self.r.tick("a")
        ok, why = self.a.svc.verify(self.bid, new, 77)
        self.assertFalse(ok)
        self.assertEqual(why, "bad answer")

    def test_a_door_that_refuses_our_credential_is_not_adopted(self):
        new = self.r.move("b")
        self.a.carrier._held_agent.pop(self.bid)
        self.a.carrier._held.clear()
        self.r.tick()
        ok, why = self.a.svc.verify(self.bid, new, 77)
        self.assertFalse(ok)
        self.assertEqual(why, "refused: not authorized")

    def test_the_candidate_is_dialed_fresh_with_the_node_id_and_the_rebind_hook_runs_first(self):
        new = self.r.move("b")
        self.r.tick()
        order = []
        c = self.a.carrier
        od, orb = c.dial, c.rebind_credential
        c.dial = lambda ep, **kw: (order.append(("dial", ep["addr"], kw.get("agent"))), od(ep, **kw))[1]
        c.rebind_credential = lambda agent, held, ep: (order.append(("rebind", agent, ep["addr"])), orb(agent, held, ep))[1]
        self.a.svc.verify(self.bid, new, 77)
        self.assertEqual(order[0], ("rebind", self.bid, new))
        self.assertEqual(order[1], ("dial", new, self.bid))
        self.assertEqual(len(order), 2)

    def test_a_pending_announcement_is_verified_by_the_worker_and_logged_without_the_address(self):
        new = self.r.move("b")
        self.r.service("b")                                          # b announces
        self.assertEqual(list(self.a.svc._pending), [self.bid])
        self.r.service("a")                                          # a verifies
        self.assertEqual(self.a.book.ordered(self.bid)[0], new)
        self.assertEqual(self.a.svc._pending, {})
        line = [l for l in self.a.logs if "adopted" in l][0]
        self.assertNotIn(new, line)
        self.assertNotIn(".fake", line)

    def test_adoption_ends_the_backoff_the_dead_address_earned(self):
        self.r.post("a", "x")
        self.r.tick()
        self.r.service()
        new = self.r.move("b")
        self.r.post("b", "y")
        self.r.tick("a")                                             # a cannot reach b: backoff
        self.assertIn(self.bid, self.a.node.down)
        self.r.service("b")
        self.a.node.wake.clear()
        self.r.service("a")                                          # adopted
        self.assertEqual(self.a.book.ordered(self.bid)[0], new)
        self.assertNotIn(self.bid, self.a.node.down)
        self.assertTrue(all(j["next"] <= self.a.node.clock() for k, j in self.a.node.jobs.items() if k.startswith(self.bid + "/")))
        self.assertTrue(self.a.node.wake.is_set())
        self.r.tick("a")                                             # no waiting: the very next round pulls from the new address
        self.assertIn("y", self.r.texts("a"))

    def test_a_failing_callback_does_not_undo_the_adoption(self):
        new = self.r.move("b")
        self.r.tick()
        self.a.svc.on_adopt = lambda agent: 1 / 0
        self.a.svc.on_locator(self.bid, new, 99)
        self.a.svc._work()
        self.assertEqual(self.a.book.ordered(self.bid)[0], new)
        self.assertTrue(any("adopted" in l for l in self.a.logs))

    def test_a_success_forgets_the_earlier_failures_of_that_peer(self):
        self.r.tick()
        for i in range(L.LOCATOR_FAILS - 1):                          # two bad announcements ...
            self.a.svc._seen.clear()
            self.assertEqual(self.a.svc.on_locator(self.bid, f"nobody{i}.fake:1", 100 + i), "ok")
            self.a.svc._work()
        new = self.r.move("b")
        self.r.tick()
        self.a.svc._seen.clear()
        self.assertEqual(self.a.svc.on_locator(self.bid, new, 200), "ok")
        self.a.svc._work()                                           # ... then a good one: adopted, the slate is clean
        self.assertEqual(self.a.book.ordered(self.bid)[0], new)
        self.a.svc._seen.clear()
        self.assertEqual(self.a.svc.on_locator(self.bid, "nobody9.fake:1", 300), "ok")
        self.a.svc._work()                                           # one more bad one is failure number 1, not 3: no block
        self.a.svc._seen.clear()
        self.assertEqual(self.a.svc.on_locator(self.bid, "nobody10.fake:1", 301), "ok")

    def test_a_discarded_announcement_does_not_end_any_backoff(self):
        called = []
        self.a.svc.on_adopt = called.append
        self.r.tick()
        self.a.svc.on_locator(self.bid, "nobody.fake:1", 99)
        self.a.svc._work()
        self.assertEqual(called, [])

    def test_a_discarded_announcement_is_logged_with_the_reason_and_counted(self):
        self.r.tick()
        self.assertEqual(self.a.svc.on_locator(self.bid, "nobody.fake:1", 1000), "ok")
        self.a.svc._work()
        self.assertTrue(any("discarded (connect refused)" in l for l in self.a.logs))
        self.assertEqual(len(self.a.svc._fails[self.bid]), 1)
        self.assertNotIn("nobody", " ".join(self.a.logs))

    def test_close_stops_the_worker_from_doing_anything_more(self):
        self.a.svc.on_locator(self.bid, "nobody.fake:1", 1000)
        self.a.svc.close()
        self.a.svc.tick()
        self.assertFalse(self.a.svc._busy)
        self.a.svc._work()
        self.assertEqual(self.a.svc._fails, {})


class AddressChanged(unittest.TestCase):
    def test_only_the_named_peers_jobs_and_backoff_are_touched(self):
        r = Rig("fake")
        try:
            a = r.sides["a"]
            bid = r.ids["b"].id
            other = Identity.generate("o").id
            now = a.node.clock()
            a.node.jobs[f"{bid}/{r.tid}/pull"] = {"next": now + 500, "tries": 3, "err": "", "ok": None, "since": None, "blocked": False}
            a.node.jobs[f"{other}/{r.tid}/pull"] = {"next": now + 500, "tries": 3, "err": "", "ok": None, "since": None, "blocked": False}
            a.node.down[bid] = {"tries": 3, "until": now + 500, "err": "x", "blocked": False}
            a.node.down[other] = {"tries": 3, "until": now + 500, "err": "x", "blocked": False}
            a.node.address_changed(bid)
            self.assertNotIn(bid, a.node.down)
            self.assertIn(other, a.node.down)
            self.assertLessEqual(a.node.jobs[f"{bid}/{r.tid}/pull"]["next"], a.node.clock())
            self.assertGreater(a.node.jobs[f"{other}/{r.tid}/pull"]["next"], now + 400)
            a.node.address_changed("z" * 32)                         # an unknown peer: nothing happens
        finally:
            r.close()


class ServerRequest(unittest.TestCase):
    def setUp(self):
        self.r = Rig("fake")
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.aid, self.bid = self.r.ids["a"].id, self.r.ids["b"].id
        self.lb = S.Loopback(self.a.srv)

    def tearDown(self):
        self.r.close()

    def ask(self, ident, body, **kw):
        return self.lb.request(S.sign_request(ident, body, ts=kw.pop("ts", None), aud=kw.pop("aud", self.aid)))

    def test_a_member_peer_gets_ok(self):
        resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"})
        self.assertEqual(resp["t"], "ok")
        self.assertTrue(S.response_signed_by(resp, self.aid))

    def test_a_stranger_gets_the_usual_answer(self):
        resp = self.ask(Identity.generate("stranger"), {"t": "locator", "addr": "z.fake:9"})
        self.assertEqual(resp["t"], "unknown")

    def test_a_server_that_takes_no_announcements_answers_like_for_a_stranger(self):
        self.a.srv.on_locator = None
        self.assertEqual(self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"})["t"], "unknown")

    def test_the_shape_is_checked(self):
        for body in ({"t": "locator"}, {"t": "locator", "addr": 5}, {"t": "locator", "addr": "z.fake:9", "extra": 1}, {"t": "locator", "addr": ["z.fake:9"]}):
            resp = self.ask(self.r.ids["b"], body)
            self.assertEqual((resp["t"], resp["why"]), ("error", "malformed request"), body)

    def test_a_replayed_request_is_refused_by_the_normal_replay_guard(self):
        req = S.sign_request(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"}, aud=self.aid)
        self.assertEqual(self.lb.request(req)["t"], "ok")
        self.assertEqual(self.lb.request(dict(req))["why"], "replayed request")

    def test_a_far_future_timestamp_is_refused_before_it_can_freeze_adopt_ts(self):
        import time
        resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"}, ts=int(time.time()) + 100000)
        self.assertTrue(resp["why"].startswith("stale request (check clocks)"), resp["why"])      # (M0b: it also says the stamp was AHEAD of this clock)
        self.assertEqual(self.a.svc._pending, {})
        self.assertEqual(self.a.book.adopt_ts(self.bid), 0)
        resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"})              # and a normal one right after is fine
        self.assertEqual(resp["t"], "ok")

    def test_a_request_for_another_server_is_refused(self):
        resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"}, aud=self.bid)
        self.assertEqual(resp["why"], "wrong audience")

    def test_a_stale_request_is_refused_and_a_bad_signature_too(self):
        resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"}, ts=1)
        self.assertEqual(resp["why"], "stale request (check clocks)")
        req = S.sign_request(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"}, aud=self.aid)
        req["addr"] = "y.fake:9"
        self.assertEqual(self.lb.request(req)["why"], "bad signature")

    def test_a_handler_that_blows_up_is_an_error_not_a_crash(self):
        def boom(*x):
            raise RuntimeError("bug")
        self.a.srv.on_locator = boom
        resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"})
        self.assertEqual((resp["t"], resp["why"]), ("error", "internal: locator"))

    def test_rejections_name_a_reason_the_sender_can_read(self):
        import time
        self.a.book.adopt(self.bid, "k.fake:1", ts=int(time.time()) + 300)       # we already adopted something NEWER than now
        resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"})
        self.assertEqual((resp["t"], resp["why"]), ("error", "stale"))
        self.a.svc.carrier_problem = None
        resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "nonsense"})
        self.assertEqual((resp["t"], resp["why"]), ("error", "bad address"))

    def test_it_does_not_take_the_mirror_lock(self):
        held = self.a.mirror._lock()
        with held:
            resp = self.ask(self.r.ids["b"], {"t": "locator", "addr": "z.fake:9"})
        self.assertEqual(resp["t"], "ok")


class RetryCycle(unittest.TestCase):
    """Node._finish: a peer with several addresses is retried after `retry_wait` for the first LOCATOR_RETRIES failures, then by the ordinary backoff; one address: as before."""

    def setUp(self):
        self.r = Rig("fake")
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.bid = self.r.ids["b"].id
        self.clock = Clock()
        self.a.node.clock = self.clock
        self.a.node.retry_wait = 7.0
        self.b.carrier.close_door("peer-a")                          # B is unreachable at its known address
        self.r.post("a", "hello")

    def tearDown(self):
        self.r.close()

    def fail_once(self):
        node = self.a.node
        node.down.pop(self.bid, None)
        for j in node.jobs.values():
            j["next"] = 0
        node.tick()
        self.assertIn(self.bid, node.down, "the round must have failed")
        return node.down[self.bid]["until"] - self.clock.t

    def cycle(self, n):
        out = []
        for _ in range(n):
            node = self.a.node
            node.tick()
            d = node.down.get(self.bid)
            self.assertIsNotNone(d)
            out.append(d["until"] - self.clock.t)
            self.clock.t = d["until"] + 0.01
        return out

    def test_two_addresses_wait_a_fixed_time_for_the_first_three_retries_then_back_off(self):
        self.a.book.seed(self.bid, "dead.fake:1")
        self.assertEqual(self.a.book.count(self.bid), 2)
        waits = self.cycle(6)
        self.assertEqual(waits[:3], [7.0, 7.0, 7.0])
        self.assertEqual(L.LOCATOR_RETRIES, 3)
        # the 4th failed cycle: the ordinary backoff(4) = 15 * 2^3 = 120 s (jittered +-20%)
        self.assertTrue(96 <= waits[3] <= 144, waits)
        self.assertTrue(waits[4] > waits[3] * 1.5, waits)

    def test_one_address_keeps_the_ordinary_backoff_from_the_first_failure(self):
        self.assertEqual(self.a.book.count(self.bid), 1)
        waits = self.cycle(3)
        self.assertTrue(12 <= waits[0] <= 18, waits)                 # backoff(1) = 15 s +-20%
        self.assertTrue(24 <= waits[1] <= 36, waits)

    def refuse_our_credential(self):
        self.a.carrier._held_agent.clear()
        self.a.carrier._held.clear()
        self.b.carrier.open_door("peer-a", "peer", credential=self.a.carrier.new_credential()[1], agent=self.r.ids["a"].id)    # the door is back, but admits a key we do not hold

    def test_a_failure_that_waiting_cannot_fix_is_still_blocked_with_one_address(self):
        self.refuse_our_credential()
        node = self.a.node
        node.tick()
        d = node.down[self.bid]
        self.assertTrue(d["blocked"])
        self.assertTrue(N.BLOCKED_DELAY * 0.79 <= d["until"] - self.clock.t <= N.BLOCKED_DELAY)

    def test_a_failure_that_waiting_cannot_fix_is_still_blocked_when_EVERY_address_says_so(self):
        self.refuse_our_credential()
        extra = self.b.carrier
        extra.open_door("extra", "peer", credential=self.a.carrier.new_credential()[1], agent=self.r.ids["a"].id)
        self.a.book.seed(self.bid, extra.door_endpoint("extra")["addr"])
        self.assertEqual(self.a.book.count(self.bid), 2)
        node = self.a.node
        node.tick()
        d = node.down[self.bid]
        self.assertTrue(d["blocked"])
        self.assertTrue(d["until"] - self.clock.t >= N.BLOCKED_DELAY * 0.79)

    def test_one_dead_address_among_refusing_ones_is_still_worth_retrying(self):
        self.refuse_our_credential()
        self.a.book.seed(self.bid, "dead.fake:1")                    # this one could come back
        node = self.a.node
        node.tick()
        d = node.down[self.bid]
        self.assertFalse(d["blocked"])
        self.assertEqual(d["until"] - self.clock.t, 7.0)

    def test_a_success_ends_the_counter_and_a_later_failure_starts_a_new_cycle(self):
        self.a.book.seed(self.bid, "dead.fake:1")
        self.cycle(3)
        self.assertEqual(self.a.node.down[self.bid]["tries"], 3)
        new = self.b.carrier.open_door("peer-a2", "peer", credential=self.a.carrier.new_credential()[1], agent=self.r.ids["a"].id)
        # B comes back at an address A can reach: give A the key for it and adopt the address (what an announcement does)
        sec, pub = self.a.carrier.new_credential()
        self.b.carrier.open_door("peer-a3", "peer", credential=pub, agent=self.r.ids["a"].id)
        self.a.carrier.use_credential(self.b.carrier.door_endpoint("peer-a3"), sec, agent=self.bid)
        self.b.doors.sync()
        self.a.book.adopt(self.bid, self.b.carrier.door_endpoint("peer-a3")["addr"], ts=5)
        for j in self.a.node.jobs.values():
            j["next"] = 0
        self.a.node.down.clear()
        self.a.node.tick()
        self.assertNotIn(self.bid, self.a.node.down)
        self.b.carrier.close_door("peer-a3")                         # gone again
        self.b.doors.sync()
        for j in self.a.node.jobs.values():
            j["next"] = 0
        self.a.node.tick()
        self.assertEqual(self.a.node.down[self.bid]["tries"], 1)
        self.assertEqual(self.a.node.down[self.bid]["until"] - self.clock.t, 7.0)

    def test_a_damaged_book_does_not_break_the_schedule(self):
        def broken(self, a):
            raise RuntimeError("damaged book")
        self.a.node.locators = type("Broken", (), {"count": broken})()
        waits = self.cycle(2)
        self.assertTrue(12 <= waits[0] <= 18, waits)


class BackoffFollowsTheAddress(unittest.TestCase):
    """A backoff is earned by the address that failed: when the address dialed first CHANGES (a human's `peer move`/`peer add`, an adopted announcement) it is over."""

    def setUp(self):
        self.r = Rig("fake")
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.bid = self.r.ids["b"].id
        import time
        self.clock = Clock(time.time())                              # (a real-time base: the peer rejects requests stamped far in the past)
        self.a.node.clock = self.clock
        self.a.node.retry_wait = 7.0
        self.dials = []
        c = self.a.carrier
        od = c.dial
        c.dial = lambda ep, **kw: (self.dials.append(ep["addr"]), od(ep, **kw))[1]
        self.new = self.r.move("b")
        self.r.post("b", "after the move")
        self.a.node.tick()                                          # fails: b is not where a thinks
        self.assertIn(self.bid, self.a.node.down)
        self.dials.clear()

    def tearDown(self):
        self.r.close()

    def test_nothing_changed_the_backoff_holds(self):
        self.a.node.tick()
        self.a.node.tick()
        self.assertEqual(self.dials, [])
        self.assertIn(self.bid, self.a.node.down)

    def test_a_peer_add_by_hand_ends_the_backoff_at_once(self):
        self.a.peers.add(self.bid, "b", {"type": "fake", "addr": self.new}, [])
        self.a.node.tick()
        self.assertEqual(self.dials[0], self.new)
        self.assertNotIn(self.bid, self.a.node.down)
        self.assertIn("after the move", self.r.texts("a"))

    def test_an_adopted_address_ends_it_without_the_callback(self):
        self.a.book.adopt(self.bid, self.new, ts=5)                 # (what the CLI's `peer move` and the service both do to the book)
        self.a.node.tick()
        self.assertIn("after the move", self.r.texts("a"))

    def test_the_jobs_own_retry_times_are_reset_too(self):
        pull = lambda: [j for k, j in self.a.node.jobs.items() if k.startswith(self.bid + "/") and k.endswith("/pull")][0]
        self.assertGreater(pull()["next"], self.clock() + 5)         # the failed pull waits for its own retry time
        self.a.book.adopt(self.bid, self.new, ts=5)
        self.a.node.tick()
        self.assertIn("after the move", self.r.texts("a"))           # ... which the new address does not have to wait for
        self.assertNotIn(self.bid, self.a.node.down)

    def test_another_peers_backoff_is_left_alone(self):
        other = Identity.generate("o").id
        self.a.peers.add(other, "o", {"type": "fake", "addr": "zz.fake:1"}, [self.r.tid])
        self.a.node.down[other] = {"tries": 2, "until": self.clock() + 500, "err": "x", "blocked": False, "loc": "zz.fake:1"}
        self.a.node.tick()
        key = f"{other}/{self.r.tid}/pull"
        self.a.node.jobs[key]["next"] = self.clock() + 500
        self.a.book.adopt(self.bid, self.new, ts=5)
        self.a.node.tick()
        self.assertIn(other, self.a.node.down)                       # its first-dialed address did not change
        self.assertGreater(self.a.node.jobs[key]["next"], self.clock() + 400)

    def test_a_backoff_without_a_recorded_address_is_never_cleared_by_this_rule(self):
        self.a.node.down[self.bid].pop("loc", None)
        self.a.book.adopt(self.bid, self.new, ts=5)
        self.dials.clear()
        self.a.node.tick()
        self.assertEqual(self.dials, [])                             # (a state loaded from an older node.json keeps its backoff until it ends)

    def test_the_failure_reordering_the_book_does_not_clear_its_own_backoff(self):
        self.a.book.seed(self.bid, "dead.fake:1")
        self.clock.t += 1000
        self.a.node.down.clear()
        for j in self.a.node.jobs.values():
            j["next"] = 0
        self.a.node.tick()                                          # every address fails: the order may change, the recorded primary is the one AFTER the failure
        self.assertIn(self.bid, self.a.node.down)
        self.dials.clear()
        self.a.node.tick()
        self.assertEqual(self.dials, [])

    def test_a_damaged_book_means_no_primary_and_no_exception(self):
        self.a.node.locators = type("Broken", (), {"ordered": lambda self, a: 1 / 0, "count": lambda self, a: 1})()
        self.assertIsNone(self.a.node._primary(self.bid))
        self.a.node.tick()

    def test_a_state_file_with_junk_in_loc_is_loaded(self):
        self.a.node.down[self.bid]["loc"] = 12345
        self.a.node._save()
        from sigilnet.node import Node
        n2 = Node(self.a.mirror, self.a.me, self.a.peers, self.a.home / "node.json", self.a.dialer, locators=self.a.book)
        self.assertIn(self.bid, n2.down)
        self.assertNotIn("loc", n2.down[self.bid])


class PeerBookSeeding(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.pb = N.PeerBook(self.tmp / "peers.json")
        self.ag = Identity.generate("p").id

    def test_adding_a_peer_with_an_endpoint_seeds_the_book_in_front(self):
        self.pb.add(self.ag, "p", {"type": "fake", "addr": "h1.fake:2"}, [])
        b = L.open_book(self.tmp, "fake")
        self.assertEqual(b.ordered(self.ag), ["h1.fake:2"])
        b.seed(self.ag, "h2.fake:3")
        self.pb.add(self.ag, "p", {"type": "fake", "addr": "h3.fake:4"}, [])      # `peer add` / `peer move` again: the human's address is first
        self.assertEqual(b.ordered(self.ag)[0], "h3.fake:4")
        self.assertEqual(len(b.ordered(self.ag)), 3)

    def test_a_peer_without_an_endpoint_seeds_nothing(self):
        self.pb.add(self.ag, "p", None, [])
        self.assertFalse((self.tmp / "locators").exists())

    def test_records_carry_the_node_id(self):
        self.pb.add(self.ag, "p", {"type": "fake", "addr": "h1.fake:2"}, [])
        self.assertEqual(self.pb.all()[self.ag]["agent"], self.ag)

    def test_removing_a_peer_clears_it_from_every_book(self):
        self.pb.add(self.ag, "p", {"type": "fake", "addr": "h1.fake:2"}, [])
        L.open_book(self.tmp, "tcp").path.parent.mkdir(exist_ok=True)
        other = L.open_book(self.tmp, "tcp")
        other.path.write_text(json.dumps({"v": 1, "peers": {self.ag: {"locs": [{"addr": "10.0.0.5:47700#" + "a" * 64}]}}}))
        self.assertTrue(self.pb.remove(self.ag))
        self.assertEqual(L.open_book(self.tmp, "fake").ordered(self.ag), [])
        self.assertEqual(L.open_book(self.tmp, "tcp").ordered(self.ag), [])
        self.assertFalse(self.pb.remove(self.ag))

    def test_a_book_that_cannot_be_written_never_fails_the_add(self):
        (self.tmp / "locators").write_text("a file where the directory should be")
        self.pb.add(self.ag, "p", {"type": "fake", "addr": "h1.fake:2"}, [])
        self.assertIn(self.ag, self.pb.all())

    def test_a_peer_does_not_get_into_the_book_when_the_add_itself_fails(self):
        with self.assertRaises(ValueError):
            self.pb.add("not an agent", "p", {"type": "fake", "addr": "h1.fake:2"}, [])
        self.assertFalse((self.tmp / "locators").exists())


class OldHome(unittest.TestCase):
    """A home from before the locator book: peers.json has an endpoint, there is no locators/ directory."""

    def test_the_first_dial_seeds_the_book_and_works(self):
        r = Rig("fake")
        try:
            a, b = r.sides["a"], r.sides["b"]
            import shutil
            shutil.rmtree(a.home / "locators")
            self.assertEqual(a.book.ordered(r.ids["b"].id), [])
            r.post("b", "from b")
            r.tick("a")
            self.assertIn("from b", r.texts("a"))
            self.assertEqual(len(a.book.ordered(r.ids["b"].id)), 1)
        finally:
            r.close()


if __name__ == "__main__":
    unittest.main()
