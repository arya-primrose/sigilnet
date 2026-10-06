"""M4a: push on dial (DESIGN_multicarrier.md rev 9, Sansa's P1-P5). The server (who may push, what is ingested, the budgets before and inside the Mirror lock), the client
(`sync.push`), encrypted threads, and the node (push after a pull, caches, relay to third members). Offline: loopback transports, fake clocks, no sockets."""
import json
import tempfile
import threading
import time
import unittest
from unittest import mock

from sigilnet import canon
from sigilnet import node as N
from sigilnet import sync as S
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror

from .test_node import Sim
from .util import World


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


def req(me, tid, events, srv_id, **kw):
    return S.sign_request(me, {"t": "push", "thread": tid, "events": events, **kw}, aud=srv_id)


class Rig(unittest.TestCase):
    """arya = owner and server; sansa and carol members, hu observer; eve outside. `self.srv` answers for arya; sansa holds her own copy of the thread."""

    def setUp(self):
        self.clock = Clock()
        self.w = World()
        self.ids = self.w.ids
        self.tid = self.w.t.id
        self.ma = Mirror(tempfile.mkdtemp(), rate_limit=False, clock=self.clock)
        self.ma.ingest(self.w.genesis)
        self.ms = Mirror(tempfile.mkdtemp(), rate_limit=False, clock=self.clock)
        self.ms.ingest(self.w.genesis)
        self.pushed = []
        self.srv = S.SyncServer(self.ma, clock=self.clock, identity=self.ids["arya"], on_push=lambda *a: self.pushed.append(a))
        self.tr = S.Loopback(self.srv)

    def post(self, name, text, m=None):
        m = m or self.ms
        ev = Writer(self.ids[name], m.threads[self.tid]).post(text)
        r = m.ingest(ev, live=False)
        self.assertTrue(r.ok, (r.status, r.reason))
        return ev

    def chain(self, n, name="sansa", m=None):
        return [self.post(name, f"m{i}", m) for i in range(n)]

    def push(self, events, name="sansa", **kw):
        return self.tr.request(req(self.ids[name], self.tid, events, self.ids["arya"].id, **kw))

    def stored(self):
        return set(self.ma.threads[self.tid].stored)


class Server(Rig):
    def test_a_member_pushes_a_chain_in_order(self):
        evs = self.chain(3)
        resp = self.push(evs)
        self.assertEqual(resp["t"], "pushed", resp)
        self.assertEqual([x["s"] for x in resp["results"]], ["accepted"] * 3)
        self.assertEqual([x["id"] for x in resp["results"]], [event_id(e) for e in evs])
        self.assertTrue({event_id(e) for e in evs} <= self.stored())
        self.assertEqual(self.pushed, [(self.ids["sansa"].id, self.tid, [event_id(e) for e in evs])])      # the relay hook, once, with exactly the new ids

    def test_duplicates_cost_nothing(self):
        evs = self.chain(2)
        self.push(evs)
        b = self.srv.push_tokens[(self.ids["sansa"].id, self.tid)][0]
        resp = self.push(evs)
        self.assertEqual([x["s"] for x in resp["results"]], ["duplicate"] * 2)
        self.assertEqual(self.srv.push_tokens[(self.ids["sansa"].id, self.tid)][0], b)       # no token spent
        self.assertEqual(len(self.pushed), 1)                                               # nothing new: no relay

    def test_only_owner_admin_member_may_push(self):
        ev = self.post("sansa", "x")
        for who in ("hu", "eve", "dave"):                                 # observer, outsider, outsider
            resp = self.push([ev], name=who)
            self.assertEqual(resp["t"], "unknown", who)
        self.assertNotIn(event_id(ev), self.stored())
        self.assertEqual(self.push([ev])["t"], "pushed")
        carol_ev = self.post("carol", "carol's", m=self.ms)
        self.assertEqual(self.push([carol_ev], name="arya")["t"], "pushed")             # the owner may push too (relay of another author's event)

    def test_a_guest_member_may_not_push(self):
        r = self.ma.ingest(Writer(self.ids["arya"], self.ma.threads[self.tid]).add_member(self.ids["dave"], "guest"))
        self.assertTrue(r.ok, (r.status, r.reason))
        self.assertEqual(self.ma.threads[self.tid].state()["members"][self.ids["dave"].id]["role"], "guest")
        ev = Writer(self.ids["dave"], self.ma.threads[self.tid]).post("guest words")
        self.assertEqual(self.push([ev], name="dave")["t"], "unknown")
        self.assertNotIn(event_id(ev), self.stored())

    def test_pushed_history_is_not_author_rate_limited_like_a_pulled_one(self):
        """live=False parity with pull: the per-author hourly rule is not applied (the pusher's bucket is the limit)."""
        m = Mirror(tempfile.mkdtemp(), rate_limit=True, clock=self.clock)
        m.ingest(self.w.genesis)
        srv = S.SyncServer(m, clock=self.clock, identity=self.ids["arya"])
        limit = m.threads[self.tid].state()["rules"]["posts_per_author_per_hour"]
        evs = self.chain(limit + 10)
        got = []
        for i in range(0, len(evs), 40):
            resp = S.Loopback(srv).request(req(self.ids["sansa"], self.tid, evs[i:i + 40], self.ids["arya"].id))
            got += [x["s"] for x in resp["results"]]
        self.assertEqual(got, ["accepted"] * (limit + 10))

    def test_a_removed_member_gets_the_strangers_answer(self):
        rm = Writer(self.ids["arya"], self.ma.threads[self.tid]).admin("member_remove", {"agent": self.ids["carol"].id})
        self.assertTrue(self.ma.ingest(rm).ok)
        ev = self.post("carol", "after")
        self.assertEqual(self.push([ev], name="carol")["t"], "unknown")
        self.assertNotIn(event_id(ev), self.stored())

    def test_public_thread_is_not_open_to_pushes(self):
        w = World(visibility="public")
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        m.ingest(w.genesis)
        srv = S.SyncServer(m, identity=w.ids["arya"])
        ev = Writer(w.ids["eve"], m.threads[w.t.id]).post("hi")
        r = S.S if False else None
        resp = S.Loopback(srv).request(S.sign_request(w.ids["eve"], {"t": "push", "thread": w.t.id, "events": [ev]}, aud=w.ids["arya"].id))
        self.assertEqual(resp["t"], "unknown")                               # readable by anyone, writable through push by members only (membership first)
        self.assertEqual(S.Loopback(srv).request(S.sign_request(w.ids["eve"], {"t": "summary", "thread": w.t.id}, aud=w.ids["arya"].id))["t"], "summary")

    def test_a_thread_we_do_not_hold_is_the_usual_answer(self):
        resp = self.tr.request(req(self.ids["sansa"], "ab" * 16, [], self.ids["arya"].id))
        self.assertEqual(resp["t"], "unknown")

    @mock.patch.object(S, "PUSH_REQ_PER_MIN", 100)
    def test_shape_rules(self):
        ev = self.post("sansa", "x")
        for events in ("no", [], [1], [ev] * 65, None):
            self.assertEqual(self.push(events)["t"], "error", events if not isinstance(events, list) else len(events))
        self.assertEqual(self.push([ev], extra=1)["why"], "bad events")          # no unknown field
        resp = self.tr.request(req(self.ids["sansa"], self.tid, [ev], "f" * 32))
        self.assertEqual(resp["why"], "wrong audience")
        r = req(self.ids["sansa"], self.tid, [ev], self.ids["arya"].id)
        self.assertEqual(self.tr.request(r)["t"], "pushed")
        self.assertEqual(self.tr.request(r)["why"], "replayed request")

    def test_genesis_and_foreign_thread_events_are_rejected(self):
        other = World()
        foreign = Writer(other.ids["sansa"], other.t).post("elsewhere")
        ev = self.post("sansa", "mine")
        resp = self.push([self.w.genesis, foreign, ev])
        self.assertEqual([x["s"] for x in resp["results"]], ["rejected", "rejected", "accepted"])
        self.assertIn("genesis", resp["results"][0]["why"])
        self.assertIn("another thread", resp["results"][1]["why"])
        self.assertEqual(self.stored(), {self.tid, event_id(ev)})

    def test_junk_and_a_forged_event_are_rejected_and_change_nothing(self):
        ev = self.post("sansa", "real")
        forged = dict(ev, body=dict(ev["body"], text="not what was signed"))
        before = self.stored()
        resp = self.push([forged, {"kind": "post"}])
        self.assertEqual([x["s"] for x in resp["results"]], ["rejected", "rejected"], resp)
        self.assertEqual(self.stored(), before)
        self.assertEqual(self.pushed, [])

    def test_an_event_with_a_missing_parent_is_parked_then_resolved_by_its_parent(self):
        a, b = self.chain(2)
        resp = self.push([b])
        self.assertEqual(resp["results"][0]["s"], "parked")
        self.assertNotIn(event_id(b), self.ma.threads[self.tid].resolved_ids())
        resp = self.push([a])
        self.assertEqual(resp["results"][0]["s"], "accepted")
        self.assertTrue({event_id(a), event_id(b)} <= self.ma.threads[self.tid].resolved_ids())
        self.assertEqual(set(self.pushed[-1][2]), {event_id(a), event_id(b)})                 # the relay hook names the unparked child too

    def test_after_eight_rejects_the_rest_is_deferred(self):
        good = self.post("sansa", "g")
        bad = [{"kind": "post", "n": i} for i in range(S.PUSH_REJECTS)]
        resp = self.push(bad + [good, good])
        self.assertEqual([x["s"] for x in resp["results"]], ["rejected"] * S.PUSH_REJECTS + ["deferred", "deferred"])
        self.assertTrue(resp["retry"] > 0)
        self.assertNotIn(event_id(good), self.stored())

    def test_bucket_exhaustion_and_refill(self):
        with mock.patch.object(S, "PUSH_BURST", 3):
            evs = self.chain(5)
            resp = self.push(evs)
            self.assertEqual([x["s"] for x in resp["results"]], ["accepted"] * 3 + ["deferred"] * 2)
            self.assertGreaterEqual(resp["retry"], 1)
            self.clock.t += resp["retry"] + 1
            resp = self.push(evs[3:])
            self.assertEqual(resp["results"][0]["s"], "accepted")                    # one token came back (120 an hour)
            self.assertEqual(resp["results"][1]["s"], "deferred")
            self.assertEqual(len(self.stored()), 1 + 4)

    def test_every_non_duplicate_outcome_costs_one_token(self):
        with mock.patch.object(S, "PUSH_BURST", 10):
            a, b, c = self.chain(3)
            self.push([b])                                                           # parked: 1
            self.push([{"kind": "post", "n": 1}])                                    # rejected: 1
            self.push([a])                                                           # accepted (and unparks b): 1
            self.assertAlmostEqual(self.srv.push_tokens[(self.ids["sansa"].id, self.tid)][0], 7.0, delta=0.2)

    def test_the_time_budget_defers_the_rest(self):
        t = [0.0]
        self.srv.push_timer = lambda: t.__setitem__(0, t[0] + 2.0) or t[0]
        evs = self.chain(6)
        resp = self.push(evs)
        s = [x["s"] for x in resp["results"]]
        self.assertEqual(s[0], "accepted")
        self.assertIn("deferred", s)
        self.assertEqual(s, sorted(s, key=lambda x: x == "deferred"))                  # accepted ones first, then only deferred
        self.assertTrue(resp["retry"] > 0)

    def test_request_budget_per_sender_is_checked_before_the_mirror_lock(self):
        ev = self.post("sansa", "x")
        for _ in range(S.PUSH_REQ_PER_MIN):
            self.assertEqual(self.push([ev])["t"], "pushed")
        out = {}
        with self.ma._lock():                                                        # somebody holds the Mirror lock: an over-budget push must not wait for it
            th = threading.Thread(target=lambda: out.update(self.push([ev])))
            th.start()
            th.join(5)
            self.assertFalse(th.is_alive(), "an over-budget push waited for the Mirror lock")
        self.assertEqual((out["t"], out["why"]), ("error", "rate limited"))
        self.assertGreaterEqual(out["retry"], 1)
        self.clock.t += 61
        self.assertEqual(self.push([ev])["t"], "pushed")

    def test_total_push_budget_is_for_known_senders_only(self):
        with mock.patch.object(S, "PUSH_TOTAL_PER_MIN", 3):
            ev = self.post("sansa", "x")
            ok = [self.push([ev], name=n)["t"] for n in ("sansa", "carol", "arya")]
            self.assertEqual(ok.count("pushed") + ok.count("unknown"), 3, ok)
            self.assertEqual(self.push([ev], name="sansa")["why"], "rate limited")
            outsider = self.push([ev], name="eve")                                   # a stranger spends its own per-sender budget, not the peers' total
            self.assertEqual(outsider["t"], "unknown")

    def test_the_relay_hook_runs_after_the_lock_is_released(self):
        seen = []

        def hook(agent, tid, ids):
            with self.ma._lock():                                                    # would deadlock if the server still held it
                seen.append(ids)
        self.srv.on_push = hook
        self.assertEqual(self.push(self.chain(1))["t"], "pushed")
        self.assertEqual(len(seen), 1)

    def test_a_failing_hook_never_fails_the_answer(self):
        self.srv.on_push = lambda *a: 1 / 0
        self.assertEqual(self.push(self.chain(1))["results"][0]["s"], "accepted")

    def test_worst_case_lock_occupancy_is_bounded(self):
        """64 events through the real ingest of a real Mirror (fsync per event): the number the review asked for. Printed, and bounded by the 3 s budget plus one event."""
        evs = self.chain(64)
        t0 = time.monotonic()
        resp = self.push(evs)
        dt = time.monotonic() - t0
        print(f"\n[M4a] lock occupancy of a 64-event push: {dt * 1000:.0f} ms ({dt * 1000 / 64:.1f} ms per event)")
        self.assertEqual([x["s"] for x in resp["results"]].count("accepted") + [x["s"] for x in resp["results"]].count("deferred"), 64)
        self.assertLess(dt, S.PUSH_BUDGET_S + 2.0)


class Wake(unittest.TestCase):
    def test_a_pushed_post_wakes_the_reader_like_a_pulled_one(self):
        from sigilnet.inboxlog import InboxLog
        w = World()
        root = tempfile.mkdtemp()
        inbox = InboxLog(root)
        m = Mirror(root + "/m", rate_limit=False, me=w.ids["arya"].id, inbox=inbox)
        m.ingest(w.genesis)
        srv = S.SyncServer(m, identity=w.ids["arya"])
        ev = Writer(w.ids["sansa"], w.t).post("wake me")
        w.add(ev)
        size = inbox.size()
        resp = S.Loopback(srv).request(S.sign_request(w.ids["sansa"], {"t": "push", "thread": w.t.id, "events": [ev]}, aud=w.ids["arya"].id))
        self.assertEqual(resp["results"][0]["s"], "accepted")
        self.assertGreater(inbox.size(), size)


# ------------------------------------------------------------------------------------------------------------------------------------------- client

class Spy:
    """Wraps a transport and records the push requests."""

    def __init__(self, tr, fail=None):
        self.tr, self.reqs, self.fail = tr, [], fail

    def request(self, r):
        if r.get("t") == "push":
            self.reqs.append(r)
        if self.fail:
            raise self.fail
        return self.tr.request(r)


class Client(Rig):
    def run_push(self, ids=None, tr=None, **kw):
        t = self.ms.threads[self.tid]
        return S.push(self.ms, self.tid, tr or self.tr, self.ids["sansa"], t.resolved_ids() - {self.tid} if ids is None else ids, peer_id=self.ids["arya"].id, **kw)

    def test_pushes_exactly_the_difference_in_dependency_order_and_never_the_genesis(self):
        evs = self.chain(5)
        have = {event_id(e) for e in evs[:2]}
        self.push(evs[:2])                                                           # the peer already has two
        spy = Spy(self.tr)
        t = self.ms.threads[self.tid]
        r = S.push(self.ms, self.tid, spy, self.ids["sansa"], t.resolved_ids() - have, peer_id=self.ids["arya"].id)
        sent = [event_id(e) for q in spy.reqs for e in q["events"]]
        self.assertEqual(sent, [event_id(e) for e in evs[2:]])
        self.assertNotIn(self.tid, sent)
        self.assertEqual((r["sent"], r["accepted"], r["requests"], r["why"]), (3, 3, 1, ""))
        self.assertTrue(r["held"] == {} and not r["unsupported"] and not r["unknown"])

    def test_batches_by_count_by_size_and_four_requests_per_run(self):
        self.chain(70)
        spy = Spy(self.tr)
        r = self.run_push(tr=spy)
        self.assertEqual([len(q["events"]) for q in spy.reqs], [64, 6])
        self.assertEqual(r["accepted"], 70)
        # by bytes
        self.setUp()
        evs = self.chain(10)
        one = len(canon.dumps(evs[0]))
        with mock.patch.object(S, "PUSH_BYTES", int(one * 3.5)):
            spy = Spy(self.tr)
            self.run_push(tr=spy)
            self.assertEqual([len(q["events"]) for q in spy.reqs], [3, 3, 3, 1][:len(spy.reqs)])
            self.assertEqual(len(spy.reqs), 4)                                       # 4 requests per run: 9 of 10 went; the rest is next cycle
        spy = Spy(self.tr)
        r = self.run_push(tr=spy)
        self.assertEqual(sum(len(q["events"]) for q in spy.reqs), 10)                # (what the peer already holds is answered duplicate: the node never sends those)

    def test_four_requests_then_it_stops(self):
        self.chain(30)
        with mock.patch.object(S, "PUSH_MAX_EVENTS", 5):
            spy = Spy(self.tr)
            r = self.run_push(tr=spy)
        self.assertEqual((r["requests"], r["sent"]), (4, 20))

    def test_an_old_node_is_reported_not_raised(self):
        class Old(S.SyncServer):
            def _answer(s, rq, tid):
                return s._err(rq, "unknown request type") if rq.get("t") == "push" else super()._answer(rq, tid)
        tr = S.Loopback(Old(self.ma, identity=self.ids["arya"]))
        self.chain(2)
        r = self.run_push(tr=tr)
        self.assertTrue(r["unsupported"] and r["sent"] == 0, r)

    def test_unknown_answer_is_remembered_by_the_caller(self):
        self.chain(1)
        r = self.run_push(ids=set(self.ms.threads[self.tid].resolved_ids() - {self.tid}), tr=S.Loopback(S.SyncServer(self.ma, identity=self.ids["arya"])))
        self.assertEqual(r["accepted"], 1)
        rm = Writer(self.ids["arya"], self.ma.threads[self.tid]).admin("member_remove", {"agent": self.ids["sansa"].id})
        self.ma.ingest(rm)
        self.post("sansa", "later")
        r = self.run_push()
        self.assertTrue(r["unknown"], r)

    def test_an_event_too_big_for_a_request_is_left_to_the_pull(self):
        a = self.post("sansa", "y" * 3000)
        b = self.post("sansa", "small")
        spy = Spy(self.tr)
        with mock.patch.object(S, "PUSH_BYTES", 2000):
            r = self.run_push(tr=spy)
        self.assertEqual([event_id(e) for q in spy.reqs for e in q["events"]], [event_id(b)])
        self.assertEqual(r["sent"], 1)

    def test_a_dead_transport_is_a_field_of_the_result(self):
        self.chain(1)
        r = self.run_push(tr=Spy(self.tr, fail=OSError("down")))
        self.assertEqual((r["sent"], r["why"]), (0, "transport: OSError"))

    def test_a_bad_answer_stops_the_push(self):
        self.chain(2)

        class Liar:
            def request(s, rq):
                return {"t": "pushed", "results": [], "nonce": rq["nonce"], "r": 1}               # unsigned
        r = self.run_push(tr=Liar())
        self.assertEqual(r["sent"], 0)
        self.assertIn("does not answer", r["why"])

    def test_deferred_answer_sets_retry(self):
        with mock.patch.object(S, "PUSH_BURST", 2):
            self.chain(5)
            r = self.run_push()
        self.assertEqual((r["accepted"], r["deferred"]), (2, 3))
        self.assertGreaterEqual(r["retry"], 1)

    def test_held_ids_are_the_ones_answered_parked_rejected_unopened(self):
        a, b = self.chain(2)
        r = self.run_push(ids={event_id(b)})
        self.assertEqual(r["held"], {event_id(b): "parked"})


# ------------------------------------------------------------------------------------------------------------------------------------------- encrypted threads (P1)

class Enc(unittest.TestCase):
    def node(self):
        root = tempfile.mkdtemp()
        return Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False), root

    def setUp(self):
        self.a, self.b, self.c = Identity.generate("a"), Identity.generate("b"), Identity.generate("c")
        self.ma, self.ra = self.node()
        g = make_genesis(self.a, "secret", [(self.b, "member"), (self.c, "member")])
        self.ma.ingest(g)
        self.tid = event_id(g)
        self.ma.enable_encryption(self.tid, self.a)
        self.ma.ingest(Writer(self.a, self.ma.threads[self.tid]).post("owner's first words"))
        self.srv = S.SyncServer(self.ma, identity=self.a)
        self.tr = S.Loopback(self.srv)
        self.mb, self.rb = self.node()
        self.mb.ingest(g)
        r = S.pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id)
        S.fetch_keys(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, need=r["need_keys"], unopened=r["unopened"])
        self.assertTrue(self.mb.codec.ring(self.tid).get(self.tid)[1])

    def post_b(self, text):
        ev = Writer(self.b, self.mb.threads[self.tid]).post(text)
        self.assertTrue(self.mb.ingest(ev).ok)
        return ev

    def test_pushed_events_travel_and_are_stored_as_envelopes(self):
        self.post_b("very secret push")
        spy = Spy(self.tr)
        t = self.mb.threads[self.tid]
        r = S.push(self.mb, self.tid, spy, self.b, t.resolved_ids() - set(self.ma.threads[self.tid].stored), peer_id=self.a.id)
        self.assertEqual(r["accepted"], 1, r)
        wire = json.dumps(spy.reqs)
        self.assertNotIn("very secret", wire)                                         # the bytes that left: envelopes only
        self.assertIn('"ep"', wire)
        self.assertIn("very secret push", repr(self.ma.threads[self.tid].events))     # (the server read it: it holds the key)
        for f in (self.ra, ):
            for p in __import__("pathlib").Path(f).rglob("*"):
                if p.is_file() and p.suffix in (".jsonl", ".log") and "keys" not in p.parts:
                    self.assertNotIn(b"very secret", p.read_bytes(), str(p))           # events.jsonl / inbox.jsonl hold no plaintext

    def test_a_plaintext_event_into_an_encrypted_thread_is_a_downgrade(self):
        ev = self.post_b("plain")
        before = set(self.ma.threads[self.tid].stored)
        resp = self.tr.request(S.sign_request(self.b, {"t": "push", "thread": self.tid, "events": [ev]}, aud=self.a.id))
        self.assertEqual(resp["results"][0]["s"], "rejected")
        self.assertEqual(set(self.ma.threads[self.tid].stored), before)

    def test_an_envelope_in_a_plaintext_thread_is_rejected(self):
        w = World()
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        m.ingest(w.genesis)
        srv = S.SyncServer(m, identity=w.ids["arya"])
        env = {"v": 1, "th": w.t.id, "ep": "a" * 32, "n": "AAAA", "c": "AAAA"}
        resp = S.Loopback(srv).request(S.sign_request(w.ids["sansa"], {"t": "push", "thread": w.t.id, "events": [env]}, aud=w.ids["arya"].id))
        self.assertEqual(resp["results"][0]["s"], "rejected")

    def test_an_envelope_under_a_key_the_receiver_lacks_is_unopened_and_free(self):
        ev = self.post_b("under an epoch the server does not know")
        key = bytes(range(32))
        from sigilnet.envelope import seal_event
        env = seal_event(key, self.tid, "c" * 32, ev)
        before = set(self.ma.threads[self.tid].stored)
        resp = self.tr.request(S.sign_request(self.b, {"t": "push", "thread": self.tid, "events": [env]}, aud=self.a.id))
        self.assertEqual(resp["results"], [{"s": "unopened", "why": "c" * 32}])        # names the epoch, nothing else
        self.assertEqual(set(self.ma.threads[self.tid].stored), before)
        self.assertEqual(self.srv.push_tokens[(self.b.id, self.tid)][0], float(S.PUSH_BURST))      # no token spent
        self.assertEqual(self.ma.codec.ring(self.tid).get("c" * 32), None)             # nothing half-way stored

    def test_an_envelope_with_a_garbage_epoch_id_is_junk_not_free(self):
        env = {"v": 1, "th": self.tid, "ep": "zz", "n": "AAAA", "c": "AAAA"}
        resp = self.tr.request(S.sign_request(self.b, {"t": "push", "thread": self.tid, "events": [env]}, aud=self.a.id))
        self.assertEqual(resp["results"][0]["s"], "rejected")

    def test_events_we_hold_no_key_for_are_not_sent(self):
        ev = self.post_b("x")
        t = self.mb.threads[self.tid]
        with mock.patch.object(self.mb.codec, "key_for", side_effect=__import__("sigilnet.envelope", fromlist=["EnvelopeError"]).EnvelopeError("none")):
            spy = Spy(self.tr)
            r = S.push(self.mb, self.tid, spy, self.b, {event_id(ev)}, peer_id=self.a.id)
        self.assertEqual((r["sent"], len(spy.reqs)), (0, 0))


# ------------------------------------------------------------------------------------------------------------------------------------------- the node (P4, P5)

class PushSim(Sim):
    """Sim with the push hook wired and an `nodial` set: those nodes cannot be reached by anybody (an outbound-only node)."""

    def __init__(self, *a, nodial=(), **kw):
        self.nodial = set(nodial)
        super().__init__(*a, **kw)

    def build_node(self, x, pull_interval=300.0):
        nd = super().build_node(x, pull_interval)
        self.servers[x] = S.SyncServer(self.mirrors[x], clock=self.clock, on_notify=nd.on_notify, on_push=nd.on_push, identity=self.ids[x])
        self.servers[x].set_peers([i.id for n, i in self.ids.items() if n != x])
        nd.heard_from = self.servers[x].heard.get
        return nd

    def transport(self, me, rec):
        tr = super().transport(me, rec)
        callee = next(y for y in self.ids if N.endpoints_of(rec) and __import__("sigilnet.tests.test_node", fromlist=["ep"]).ep(list(self.ids).index(y)) == rec["endpoint"])
        sim = self

        class T:
            def request(self_, r):
                if callee in sim.nodial:
                    raise OSError("connection refused")
                return tr.request(r)
        return T()

    def kinds(self, caller=None, callee=None, kind=None):
        return [r for r in self.requests if (caller is None or r[0] == caller) and (callee is None or r[1] == callee) and (kind is None or r[2] == kind)]


class NodeFlow(unittest.TestCase):
    def test_an_outbound_only_node_converges_both_ways_through_its_own_pull_and_push(self):
        sim = PushSim(2, nodial={"sansa"})                                           # arya cannot dial sansa; sansa dials arya
        sim.step(1.0, rounds=3)                                                      # (the invited member fetches the thread first)
        sim.post("arya", "from arya")
        sim.post("sansa", "from sansa")
        sim.step(10.0, rounds=6)
        self.assertEqual(sorted(sim.texts("arya")), sorted(sim.texts("sansa")))
        self.assertIn("from sansa", sim.texts("arya"))
        self.assertIn("from arya", sim.texts("sansa"))
        self.assertTrue(sim.kinds("sansa", "arya", "push"))                         # sansa's own dial carried her events up

    def test_relay_a_outbound_only_to_b_to_c_in_one_loop(self):
        sim = PushSim(3, nodial={"sansa"})                                           # sansa (A) is outbound-only; arya = B is dialable; carol = C
        sim.step(1.0, rounds=3)
        sim.post("sansa", "from the outbound-only node")
        sim.step(10.0, rounds=8)
        self.assertIn("from the outbound-only node", sim.texts("arya"))
        self.assertIn("from the outbound-only node", sim.texts("carol"))
        n = sim.kinds("arya", "carol", "notify")
        self.assertTrue(n, "the relay hook made B tell C")

    def test_no_second_push_when_the_peer_has_everything(self):
        sim = PushSim(2)
        sim.post("arya", "one")
        sim.step(1.0, rounds=6)
        before = len(sim.kinds(kind="push"))
        sim.step(400.0, rounds=3)                                                    # anti-entropy rounds
        self.assertEqual(len(sim.kinds(kind="push")), before)

    def test_an_old_peer_is_cached_six_hours_and_the_pull_still_succeeds(self):
        sim = PushSim(2, nodial={"sansa"})
        sim.step(1.0, rounds=3)

        class Old(S.SyncServer):
            def _answer(s, rq, tid):
                return s._err(rq, "unknown request type") if rq.get("t") == "push" else super()._answer(rq, tid)
        old = Old(sim.mirrors["arya"], clock=sim.clock, on_notify=sim.nodes["arya"].on_notify, identity=sim.ids["arya"])
        old.set_peers([sim.ids["sansa"].id])
        sim.servers["arya"] = old
        sim.post("sansa", "to the old node")
        sim.step(10.0, rounds=5)
        pushes = sim.kinds("sansa", "arya", "push")
        self.assertEqual(len(pushes), 1)
        self.assertGreater(sim.nodes["sansa"].nopush[sim.ids["arya"].id], sim.clock() + 5 * 3600)
        job = sim.nodes["sansa"].jobs[sim.nodes["sansa"]._key(sim.ids["arya"].id, sim.tid, "pull")]
        self.assertEqual((job["tries"], job["err"]), (0, ""))                      # the pull is a success
        sim.post("sansa", "again")
        sim.step(400.0, rounds=3)
        self.assertEqual(len(sim.kinds("sansa", "arya", "push")), 1)               # not asked again inside 6 h
        sim.step(7 * 3600.0, rounds=1)
        sim.post("sansa", "much later")
        sim.step(400.0, rounds=3)
        self.assertGreater(len(sim.kinds("sansa", "arya", "push")), 1)

    def test_a_push_that_raises_never_fails_the_pull(self):
        sim = PushSim(2, nodial={"sansa"})
        sim.step(10.0, rounds=3)
        sim.post("sansa", "sansa has something to push")
        sim.post("arya", "x")
        with mock.patch.object(S, "push", side_effect=RuntimeError("boom")) as m:
            sim.step(10.0, rounds=6)
        self.assertTrue(m.called)                                                    # (the push really ran and raised)
        self.assertIn("x", sim.texts("sansa"))
        key = sim.nodes["sansa"]._key(sim.ids["arya"].id, sim.tid, "pull")
        self.assertEqual((sim.nodes["sansa"].jobs[key]["tries"], sim.nodes["sansa"].jobs[key]["err"]), (0, ""))

    def test_no_push_after_a_failed_pull(self):
        sim = PushSim(2, nodial={"sansa"})
        sim.step(10.0, rounds=3)
        sim.post("sansa", "pending")
        sim.post("arya", "sansa must fetch this, and cannot")
        real = sim.servers["arya"]._answer

        def failing(rq, tid):
            return sim.servers["arya"]._err(rq, "boom") if rq.get("t") == "get" else real(rq, tid)
        sim.servers["arya"]._answer = failing
        with mock.patch.object(S, "push") as m:
            sim.step(10.0, rounds=6)
        self.assertFalse(m.called)

    def test_unknown_and_retry_answers_are_cached_per_peer_and_thread(self):
        sim = PushSim(2)
        sim.step(1.0, rounds=3)
        nd, peer = sim.nodes["sansa"], sim.ids["arya"].id

        def out(**kw):
            base = dict(thread=sim.tid, sent=0, requests=1, accepted=0, duplicate=0, parked=0, rejected=0, unopened=0, deferred=0, retry=0, unsupported=False, unknown=False, held={}, why="")
            return S.PushResult(**{**base, **kw})
        calls = []
        with mock.patch.object(S, "push", side_effect=lambda *a, **k: calls.append(1) or out(unknown=True)), mock.patch.object(type(nd.m.threads[sim.tid]), "resolved_ids", return_value={"a" * 32}):
            nd._push(peer, sim.tid, None, {"peer_ids": set()})
            nd._push(peer, sim.tid, None, {"peer_ids": set()})
            self.assertEqual(len(calls), 1)                                          # "unknown" is remembered for the thread
            sim.clock.t += S.PUSH_UNKNOWN + 1
            nd._push(peer, sim.tid, None, {"peer_ids": set()})
            self.assertEqual(len(calls), 2)
        calls.clear()
        nd.push_off.clear()
        with mock.patch.object(S, "push", side_effect=lambda *a, **k: calls.append(1) or out(retry=300, deferred=1)), mock.patch.object(type(nd.m.threads[sim.tid]), "resolved_ids", return_value={"a" * 32}):
            nd._push(peer, sim.tid, None, {"peer_ids": set()})
            sim.clock.t += 100
            nd._push(peer, sim.tid, None, {"peer_ids": set()})
            self.assertEqual(len(calls), 1)                                          # the peer's `retry` is honoured
            sim.clock.t += 250
            nd._push(peer, sim.tid, None, {"peer_ids": set()})
            self.assertEqual(len(calls), 2)

    def test_relay_hook_tells_the_other_peers_and_not_the_source_nor_a_stranger(self):
        sim = PushSim(3)
        sim.step(10.0, rounds=3)
        nd = sim.nodes["arya"]
        sansa, carol = sim.ids["sansa"].id, sim.ids["carol"].id
        for j in nd.jobs.values():
            j["next"] = N.NEVER
        nd.on_push(sansa, sim.tid, ["a" * 32])
        due = {k.split("/")[0] for k, j in nd.jobs.items() if k.endswith("/notify") and j["next"] < N.NEVER}
        self.assertEqual(due, {carol})
        self.assertTrue(nd.wake.is_set())
        nd.wake.clear()
        for j in nd.jobs.values():
            j["next"] = N.NEVER
        nd.on_push("f" * 32, sim.tid, ["a" * 32])                                    # not in the book
        nd.on_push(sansa, sim.tid, [])                                               # nothing new
        self.assertFalse(nd.wake.is_set())
        self.assertTrue(all(j["next"] >= N.NEVER for j in nd.jobs.values()))

    def test_rejected_ids_are_not_pushed_again_until_a_membership_event_and_parked_ones_for_an_hour(self):
        sim = PushSim(2)
        sim.step(1.0, rounds=3)
        nd = sim.nodes["sansa"]
        peer = sim.ids["arya"].id
        t = sim.mirrors["sansa"].threads[sim.tid]
        with mock.patch.object(S, "push", return_value=S.PushResult(thread=sim.tid, sent=2, requests=1, accepted=0, duplicate=0, parked=1, rejected=1, unopened=0, deferred=0, retry=0,
                                                                  unsupported=False, unknown=False, held={"a" * 32: "rejected", "b" * 32: "parked"}, why="")):
            nd._push(peer, sim.tid, None, {"peer_ids": set()})
        h = nd.push_held[(peer, sim.tid)]
        self.assertEqual((h["rej"], set(h["park"])), ({"a" * 32}, {"b" * 32}))
        seen = []
        with mock.patch.object(S, "push", side_effect=lambda m, tid, tr, me, ids, **kw: seen.append(set(ids)) or S.PushResult(thread=tid, sent=0, requests=0, accepted=0, duplicate=0, parked=0, rejected=0, unopened=0, deferred=0, retry=0, unsupported=False, unknown=False, held={}, why="")):
            ids = {"a" * 32, "b" * 32, "c" * 32}
            with mock.patch.object(type(t), "resolved_ids", return_value=ids):
                nd._push(peer, sim.tid, None, {"peer_ids": set()})
                self.assertEqual(seen[-1], {"c" * 32})
                sim.clock.t += 3601
                nd._push(peer, sim.tid, None, {"peer_ids": set()})
                self.assertEqual(seen[-1], {"b" * 32, "c" * 32})                      # the parked one is due again after an hour, the rejected one is not
                h["head"] = "changed"
                nd._push(peer, sim.tid, None, {"peer_ids": set()})
                self.assertEqual(seen[-1], ids)                                      # a membership event (new admin head) clears the rejected ones


class Measure(Rig):
    def test_full_size_events_fit_one_tcp_request_and_the_lock_time_is_measured(self):
        """The biggest honest push: events of the maximum size, batched by bytes so every request fits tcp.MAX_REQ; and the worst case under the lock (real signature checks, fsync per event)."""
        from sigilnet import tcp
        big = "x" * 15000
        evs = [self.post("sansa", big + str(i)) for i in range(12)]
        spy = Spy(self.tr)
        t0 = time.monotonic()
        r = self.run_push(tr=spy)
        dt = time.monotonic() - t0
        self.assertEqual(r["accepted"], 12, r)
        self.assertTrue(spy.reqs and all(len(canon.dumps(q)) <= tcp.MAX_REQ for q in spy.reqs), [len(canon.dumps(q)) for q in spy.reqs])
        print(f"\n[M4a] {len(evs)} events of ~15 KB in {len(spy.reqs)} request(s): {dt * 1000:.0f} ms in all")

    def run_push(self, tr):
        t = self.ms.threads[self.tid]
        return S.push(self.ms, self.tid, tr, self.ids["sansa"], t.resolved_ids() - {self.tid}, peer_id=self.ids["arya"].id)

    def test_rejected_events_cost_at_most_eight_checks_per_request(self):
        evs = self.chain(64)
        forged = [dict(e, sig="0" * 128) for e in evs]
        t0 = time.monotonic()
        resp = self.push(forged)
        dt = time.monotonic() - t0
        s = [x["s"] for x in resp["results"]]
        self.assertEqual((s.count("rejected"), s.count("deferred")), (S.PUSH_REJECTS, 64 - S.PUSH_REJECTS))
        print(f"\n[M4a] 64 forged events: {dt * 1000:.0f} ms ({S.PUSH_REJECTS} checked, the rest deferred)")


class Follow(unittest.TestCase):
    def test_a_peer_that_pulls_back_costs_no_extra_pull(self):
        sim = PushSim(2)
        sim.step(10.0, rounds=3)
        sim.post("arya", "news")
        sim.step(10.0, rounds=2)                                                     # arya notifies, sansa pulls
        before = len(sim.kinds("arya", "sansa", "summary"))
        sim.step(10.0, rounds=5)                                                     # the follow-up window passes: sansa did come, arya does not pull her
        self.assertEqual(len(sim.kinds("arya", "sansa", "summary")), before)
        self.assertIn("news", sim.texts("sansa"))

    def test_a_peer_that_does_not_come_is_pulled_after_the_wait(self):
        sim = PushSim(2, nodial={"sansa"})
        sim.step(10.0, rounds=3)
        sim.post("sansa", "only by push")
        n = len(sim.kinds("sansa", "arya", "summary"))
        sim.step(5.0, rounds=2)
        self.assertEqual(len(sim.kinds("sansa", "arya", "summary")), n)               # not yet: the wait is FOLLOW_WAIT
        sim.step(10.0, rounds=4)
        self.assertGreater(len(sim.kinds("sansa", "arya", "summary")), n)
        self.assertIn("only by push", sim.texts("arya"))

    def test_without_the_server_hook_nothing_changes(self):
        sim = PushSim(2, nodial={"sansa"})
        sim.nodes["sansa"].heard_from = None
        sim.step(10.0, rounds=3)
        sim.post("sansa", "slow path")
        sim.step(10.0, rounds=5)
        self.assertNotIn("slow path", sim.texts("arya"))                              # the 300 s anti-entropy pull is all that is left

    def test_the_server_remembers_only_peers_it_heard_from(self):
        w = World()
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        m.ingest(w.genesis)
        srv = S.SyncServer(m, identity=w.ids["arya"])
        srv.set_peers([w.ids["sansa"].id])
        for who in ("sansa", "eve"):
            S.Loopback(srv).request(S.sign_request(w.ids[who], {"t": "summary", "thread": w.t.id}, aud=w.ids["arya"].id))
        S.Loopback(srv).request(S.sign_request(w.ids["sansa"], {"t": "ping"}, aud=w.ids["arya"].id)) if False else None
        self.assertEqual(set(srv.heard), {w.ids["sansa"].id})

    def test_on_push_for_a_stranger_does_nothing(self):
        sim = PushSim(2)
        sim.step(10.0, rounds=3)
        sigs = dict(sim.nodes["arya"].sigs)
        sim.nodes["arya"].on_push("f" * 32, sim.tid, ["a" * 32])
        self.assertEqual(sim.nodes["arya"].sigs, sigs)


class RealFraming(unittest.TestCase):
    """Two nodes wired like `noderun.run` (Doors, per-carrier books, a MultiDialer, the real framing and guards of tcp.py behind in-memory carriers); one of them is unreachable on
    every carrier (outbound only). The pair still converges in both directions: the unreachable side pulls and then pushes over its own connections."""

    def test_an_unreachable_node_converges_both_ways_over_framed_doors(self):
        from .multirig import Rig2
        rig = Rig2()
        try:
            for t in ("fake", "fakeb"):
                rig.blackhole("a", t)                                                    # B cannot dial A on either carrier
            with mock.patch.object(N, "FOLLOW_WAIT", 0.0):
                rig.post("a", "from the unreachable node")
                rig.post("b", "from the reachable node")
                for _ in range(8):
                    rig.tick("a", "b", rounds=1)
                    if rig.texts("a") == rig.texts("b") and len(rig.texts("a")) == 2:
                        break
            self.assertEqual(rig.texts("a"), ["from the reachable node", "from the unreachable node"])
            self.assertEqual(rig.texts("b"), rig.texts("a"))
            pushes = list(rig.sides["a"].node.pushes.values())
            self.assertTrue(pushes and "accepted 1" in pushes[0], pushes)                # it travelled by push (B could not pull it)
        finally:
            rig.close()

    def test_relay_to_a_third_member_in_one_loop_through_the_hook(self):
        sim = PushSim(3, nodial={"sansa"})
        sim.step(10.0, rounds=3)
        sim.post("sansa", "relay me")
        sim.step(10.0, rounds=3)
        self.assertIn("relay me", sim.texts("arya"))
        self.assertIn("relay me", sim.texts("carol"))


if __name__ == "__main__":
    unittest.main()
