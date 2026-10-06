"""Node against hostile peers, hints, parallel ticks, restart recovery, information leaks. No network."""
import json
import random
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sigilnet import node as N
from sigilnet import sync as S
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.torlink import TorError

from .h4 import ONION, Clock, Env, Reply, Signing, down_transport, ep


def ctrl(s):
    return [c for c in str(s) if ord(c) < 32 or ord(c) == 127 or 0x80 <= ord(c) < 0xA0 or c in "‮  "]


class HostileTextTest(unittest.TestCase):
    EVIL = "\x1b[2J\x1b]0;pwned\x07 ALL CLEAR\nFAKE LINE: peer p9 ok\r\x08\x08\x08"

    def test_peer_supplied_error_text_is_not_stored_or_logged_with_control_characters(self):
        logs = []
        env = Env(transport=Reply(lambda req: {"t": "error", "why": self.EVIL}))
        env.node.log = lambda *a: logs.append(" ".join(str(x) for x in a))
        env.node.tick()
        rows = env.node.status()
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(ctrl(r["error"]), [], "peer-controlled text reaches node.status() (and `node status`) with terminal escape sequences")
        self.assertEqual(ctrl("".join(logs)).count("\x1b"), 0, "peer-controlled text reaches the `node run` log with terminal escape sequences")
        self.assertFalse([c for c in ctrl(json.dumps(env.state())) if c != "\\"], "state file")

    def test_peer_supplied_non_string_why_is_neutralised(self):
        for why in (["a" * 1000] * 200, {"k": "v"}, 12345, True, None):
            with self.subTest(why=str(why)[:30]):
                env = Env(transport=Reply(lambda req, w=why: {"t": "error", "why": w}))
                env.node.tick()
                for j in env.node.jobs.values():
                    self.assertIsInstance(j["err"], str)
                    self.assertLessEqual(len(j["err"]), 200)
                self.assertLess(len(json.dumps(env.state())), 5000)

    def test_hostile_peer_cannot_inflate_tries_twice_per_failure(self):
        env = Env(transport=Reply(lambda req: {"t": "error", "why": {"x": 1}}))
        env.node.tick()
        pulls = [j for k, j in env.node.jobs.items() if k.endswith("/pull")]
        self.assertEqual([j["tries"] for j in pulls], [1])


class AckBindingTest(unittest.TestCase):
    def test_notify_ack_must_answer_this_request(self):
        env = Env()
        for resp in ({"t": "ok"}, {"t": "ok", "nonce": "0" * 16, "r": 1}, {"t": "ok", "r": 1}, {"t": "ok", "nonce": None, "r": 1}):
            with self.subTest(resp=resp):
                tr = Reply(lambda req, r=resp: dict(r), echo=False)
                self.assertFalse(S.notify(tr, env.me, env.tid, env.m, peer_id=env.peers[0].id),
                                 "notify() accepts an acknowledgement that does not carry the request's nonce (pull() and the README require it)")

    def test_notify_with_a_correct_answer(self):
        env = Env()
        tr = Reply(lambda req: {"t": "ok"})
        self.assertTrue(S.notify(Signing(tr, env.peers[0]), env.me, env.tid, env.m, peer_id=env.peers[0].id))
        self.assertFalse(S.notify(tr, env.me, env.tid, env.m, peer_id=env.peers[0].id))               # unsigned: nobody vouches for the answer
        self.assertFalse(S.notify(Signing(tr, env.peers[1 % len(env.peers)] if len(env.peers) > 1 else Identity.generate("imp")), env.me, env.tid, env.m,
                                  peer_id=env.peers[0].id))                                            # signed by somebody else

    def test_notify_ack_that_is_not_a_dict(self):
        env = Env()
        for resp in ([], "ok", None, 5):
            self.assertFalse(S.notify(Reply(lambda req, r=resp: r, echo=False), env.me, env.tid, env.m, peer_id=env.peers[0].id))


class StallTest(unittest.TestCase):
    def test_a_peer_that_says_rate_limited_forever_cannot_park_a_worker_for_a_minute(self):
        slept = []
        old = S.pull.__kwdefaults__["sleep"]
        S.pull.__kwdefaults__["sleep"] = slept.append
        self.addCleanup(lambda: S.pull.__kwdefaults__.__setitem__("sleep", old))
        env = Env(transport=Reply(lambda req: {"t": "error", "why": "rate limited"}))
        env.node.tick()
        self.assertLess(sum(slept), 10, f"one pull() against a hostile peer sleeps {sum(slept)} s inside the node's tick (RATE_RETRIES x 1.5 s); the serial loop stalls for every other peer")

    def test_parallel_tick_runs_slow_peers_concurrently_and_loses_no_update(self):
        env = Env(n_peers=6)

        def slow(req):
            time.sleep(0.3)
            return {"t": "unknown"}
        for p in env.peers:
            env.transports[p.id] = Reply(slow)
        t = time.time()
        for _ in range(3):
            env.node.tick(parallel=True)                                # (non-blocking since round 10: it submits and returns)
        end = time.time() + 6
        while time.time() < end and any(j["err"] != "peer does not have this thread (yet)" for j in env.node.jobs.values()):
            env.node.tick(parallel=True)                                # (the real loop ticks every 2 s; a job skipped by the per-peer single flight is retried)
            time.sleep(0.05)                                            # the slow peers run concurrently: all done in about one slow exchange, not 12
        dt = time.time() - t
        self.assertLess(dt, 4.0)
        env.node.tick(parallel=True)
        time.sleep(0.1)
        env.node._save()
        st = env.state()
        peers_in_state = {k.split("/")[0] for k in st["jobs"]}
        self.assertEqual(peers_in_state, {p.id for p in env.peers})
        # every peer's pull and notify job completed at least once
        for k, j in st["jobs"].items():
            self.assertEqual(j["tries"], 0, (k, j))
            self.assertEqual(j["err"], "peer does not have this thread (yet)", (k, j))

    def test_an_exception_in_one_worker_does_not_hide_or_abort_the_others(self):
        env = Env(n_peers=4)

        def boom(req):
            raise RuntimeError("bug in transport")
        env.transports[env.peers[0].id] = Reply(boom)
        for p in env.peers[1:]:
            env.transports[p.id] = Reply(lambda req: {"t": "unknown"})
        env.node.tick(parallel=True)
        for p in env.peers[1:]:
            self.assertTrue(all(j["tries"] == 0 for k, j in env.node.jobs.items() if k.startswith(p.id)))

    def test_transport_factory_that_raises_is_a_failed_job_not_a_crash(self):
        env = Env()
        env.node.transport_for = lambda rec: (_ for _ in ()).throw(ValueError("bad port"))
        env.node.tick()
        self.assertTrue(any(r["state"] == "failing" for r in env.node.status()))

    def test_one_thread_ids_jobs_for_one_peer_never_overlap(self):
        env = Env()
        active, peak = [0], [0]

        def slow(req):
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            active[0] -= 1
            return {"t": "unknown"}
        env.default = Reply(slow)
        env.node.tick(parallel=True)
        env.node.tick(parallel=True)
        self.assertEqual(peak[0], 1)


class RestartTest(unittest.TestCase):
    def test_blocked_state_survives_restart_and_is_not_forgotten_into_ok(self):
        env = Env(transport=down_transport(TorError("not authorized", retry=False)))
        env.node.tick()
        self.assertTrue(any(r["state"] == "BLOCKED" for r in env.node.status()))
        nd = env.build()
        self.assertTrue(any(r["state"] == "BLOCKED" for r in nd.status()), "BLOCKED forgotten on restart")
        n = len(env.default.calls)
        nd.tick()
        self.assertEqual(len(env.default.calls), n + 1, "a restarted node must make exactly one attempt per peer, not one per job")
        self.assertTrue(any(r["state"] == "BLOCKED" for r in nd.status()))

    def test_restart_does_not_reset_the_failure_count(self):
        env = Env(transport=down_transport(ConnectionError("x")))
        for _ in range(4):
            env.node.tick()
            env.clock.t += 1100
        t0 = env.node.down[env.peers[0].id]["tries"]
        nd = env.build()
        self.assertEqual(nd.down[env.peers[0].id]["tries"], t0)

    def test_notify_outbox_expires_after_24h_of_failures_but_pulls_continue(self):
        env = Env(transport=down_transport(ConnectionError("x")))
        end = env.clock.t + 26 * 3600
        while env.clock.t < end:
            env.node.tick()
            env.clock.t += 1000
        rows = env.node.status()
        self.assertFalse([r for r in rows if r["job"] == "notify"], rows)
        self.assertTrue([r for r in rows if r["job"] == "pull"])

    def test_persisted_since_makes_expiry_work_across_restarts(self):
        env = Env(transport=down_transport(ConnectionError("x")))
        env.node.tick()
        env.clock.t += 25 * 3600
        nd = env.build()
        for _ in range(3):
            nd.tick()
            env.clock.t += 1100
        self.assertFalse([r for r in nd.status() if r["job"] == "notify"])


class HintTest(unittest.TestCase):
    def test_a_hint_from_a_peer_that_is_not_a_member_of_a_public_thread_schedules_no_pull_from_it(self):
        env = Env()
        stranger = Identity.generate("stranger")
        env.book.add(stranger.id, "stranger", ep("c" * 56 + ".onion"))
        env.transports[stranger.id] = Reply(lambda req: {"t": "unknown"})
        env.node.tick()
        env.node.on_notify(stranger.id, env.tid, ["a" * 32])
        env.clock.t += 1
        env.node.tick()
        self.assertEqual(env.transports[stranger.id].calls, [], "we talked to a peer about a thread it is not a member of because it sent us a hint")

    def test_hint_for_unknown_thread_or_agent_creates_no_lasting_state(self):
        env = Env()
        env.default = Reply(lambda req: {"t": "unknown"})
        env.node.tick()
        before = set(env.node.jobs)
        for i in range(500):
            env.node.on_notify(env.peers[0].id, f"{i:032x}", ["b" * 32] * 50)
            env.node.on_notify(Identity.generate("x").id if i < 5 else "zz", f"{i:032x}", [])
        env.clock.t += 1
        env.node.tick()
        self.assertEqual(set(env.node.jobs), before)

    def test_hint_flood_with_hostile_leaves_types_does_not_raise(self):
        env = Env()
        env.default = Reply(lambda req: {"t": "unknown"})
        env.node.tick()
        for leaves in ([], [None], "abc", {"k": 1}, list(range(10000)), [True], ["g" * 32] * 4000):
            with self.subTest(leaves=str(leaves)[:30]):
                try:
                    env.node.on_notify(env.peers[0].id, env.tid, leaves)
                except Exception as e:                               # noqa: BLE001
                    self.fail(f"{type(e).__name__}: {e}")

    def test_hints_cannot_shorten_the_blocked_delay_more_than_once_a_minute(self):
        env = Env(transport=down_transport(TorError("not authorized", retry=False)))
        env.node.tick()
        n0 = len(env.default.calls)
        for i in range(200):
            env.clock.t += 1
            env.node.on_notify(env.peers[0].id, env.tid, ["c" * 32])
            env.node.tick()
        attempts = len(env.default.calls) - n0
        self.assertLessEqual(attempts, 200 // 60 + 2, f"{attempts} dials to a blocked peer within 200 s of hints")

    def test_hints_through_the_real_server_only_for_members_and_only_once_per_repull(self):
        env = Env()
        env.default = Reply(lambda req: {"t": "unknown"})
        env.node.tick()
        srv = S.SyncServer(env.m, identity=env.me, on_notify=env.node.on_notify)
        seen = []
        orig = env.node.on_notify
        srv.on_notify = lambda a, t, l: (seen.append((a, t, len(l))), orig(a, t, l))
        stranger = Identity.generate("s")
        r = srv.handle(S.sign_request(stranger, {"t": "notify", "thread": env.tid, "leaves": ["d" * 32]}, aud=env.me.id))
        self.assertEqual(r["t"], "unknown")
        self.assertEqual(seen, [])
        r = srv.handle(S.sign_request(env.peers[0], {"t": "notify", "thread": env.tid, "leaves": ["d" * 32] * 5000}, aud=env.me.id))
        self.assertEqual(r["t"], "ok")
        self.assertEqual(seen[0][2], S.LIST_PAGE)


class LeakTest(unittest.TestCase):
    """A non-member must not learn that a thread exists, through any request type."""

    def setUp(self):
        self.env = Env()
        self.srv = S.SyncServer(self.env.m, identity=self.env.me)
        self.stranger = Identity.generate("s")
        self.calls = []
        self.srv.on_notify = lambda a, t, l: self.calls.append((a, t))

    def ask(self, who, body, **kw):
        r = self.srv.handle(S.sign_request(who, body, aud=self.env.me.id, **kw))
        return {k: v for k, v in r.items() if k not in ("nonce", "rsig")}        # (the response signature covers the per-request nonce)

    def test_every_request_type_is_indistinguishable_for_missing_and_private_threads(self):
        bodies = [{"t": "summary"}, {"t": "list", "page": 0}, {"t": "list", "page": "x"}, {"t": "list", "page": -5}, {"t": "get", "ids": ["a" * 32]}, {"t": "get", "ids": "nope"},
                  {"t": "get", "ids": ["a" * 32] * 500}, {"t": "notify", "leaves": ["a" * 32]}, {"t": "notify", "leaves": 5}, {"t": "bogus"}, {}]
        for b in bodies:
            with self.subTest(body=b):
                real = self.ask(self.stranger, {**b, "thread": self.env.tid})
                fake = self.ask(self.stranger, {**b, "thread": "f" * 32})
                junk = self.ask(self.stranger, {**b, "thread": ["x"]})
                self.assertEqual(real, fake)
                self.assertEqual(real, junk)
        self.assertEqual(self.calls, [])

    def test_wrong_key_for_a_member_id_is_not_a_member(self):
        # same agent id claimed with another signing key fails authentication before any thread lookup
        imposter = Identity.generate("imp")
        req = S.sign_request(imposter, {"t": "summary", "thread": self.env.tid}, aud=self.env.me.id)
        req["from"] = self.env.peers[0].id
        r = self.srv.handle(req)
        self.assertNotEqual(r.get("t"), "summary")

    def test_removed_member_is_out_for_reads_and_for_hints(self):
        env = self.env
        env.m.ingest(Writer(env.me, env.m.threads[env.tid]).admin("member_remove", {"agent": env.peers[0].id}))
        r = self.ask(env.peers[0], {"t": "notify", "thread": env.tid, "leaves": ["a" * 32]})
        self.assertEqual(r["t"], "unknown")
        self.assertEqual(self.calls, [])
        env.node.default = None
        env.default = Reply(lambda req: {"t": "unknown"})
        env.node.tick()
        self.assertFalse([k for k in env.node.jobs if k.startswith(env.peers[0].id + "/" + env.tid)], "a removed member is still in the sync plan")


class EndToEndNamedOnlyTest(unittest.TestCase):
    def test_node_pull_never_creates_a_thread_nobody_named_even_from_a_member_peer(self):
        env = Env()
        other = Identity.generate("other")
        gx = make_genesis(other, "unnamed", [(env.me, "member"), (env.peers[0], "member")], k=1)
        gxid = event_id(gx)

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": env.tid, "head": gxid, "n": 2}
            if req["t"] == "list":
                return {"t": "list", "thread": req["thread"], "n": 2, "pages": 1, "ids": [gxid]}
            if req["t"] == "get":
                return {"t": "events", "events": [gx], "more": []}
            return {"t": "ok"}
        env.default = Reply(fn)
        env.node.tick()
        env.node.tick()
        self.assertNotIn(gxid, env.m.threads)
        self.assertNotIn(gxid, env.m.orphans)
        self.assertFalse(env.m._dir(gxid).exists())

    def test_named_thread_for_one_peer_cannot_be_created_by_another_peers_pull(self):
        env = Env(n_peers=2)
        other = Identity.generate("other")
        gx = make_genesis(other, "named for p0 only", [(env.me, "member"), (env.peers[1], "member")], k=1)
        gxid = event_id(gx)
        env.book.add(env.peers[0].id, "p0", ep("a" * 56 + ".onion"), threads=[gxid])

        def evil(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": req["thread"], "head": gxid, "n": 1}
            if req["t"] == "list":
                return {"t": "list", "thread": req["thread"], "n": 1, "pages": 1, "ids": [gxid]}
            if req["t"] == "get":
                return {"t": "events", "events": [gx], "more": []}
            return {"t": "ok"}
        env.transports[env.peers[1].id] = Reply(evil)
        env.transports[env.peers[0].id] = Reply(lambda req: {"t": "unknown"})
        for _ in range(3):
            env.node.tick()
        # p1 answered a pull of OUR thread with the genesis of a thread that is named only for p0: that must not be ingested through p1
        pulls_of_x_from_p1 = [c for c in env.transports[env.peers[1].id].calls if c.get("thread") == gxid]
        self.assertEqual(pulls_of_x_from_p1, [])
        self.assertNotIn(gxid, env.m.threads)


class CliRefreshTest(unittest.TestCase):
    def test_events_appended_by_another_process_are_noticed_and_announced(self):
        env = Env()

        def fn(req):
            return {"t": "ok"} if req["t"] == "notify" else {"t": "unknown"}
        env.default = Reply(fn)
        env.node.tick()
        env.clock.t += 1
        other = Mirror(env.home / "mirror", rate_limit=False)
        ev = Writer(env.me, other.threads[env.tid]).post("hello from the CLI")
        self.assertTrue(other.ingest(ev).ok)
        n = len(env.default.calls)
        env.node.tick()
        notifies = [c for c in env.default.calls[n:] if c["t"] == "notify"]
        self.assertTrue(notifies, "a post appended by the CLI was not announced")
        self.assertIn(event_id(ev), notifies[0]["leaves"])


class ConcurrentNodesTest(unittest.TestCase):
    def test_two_real_time_nodes_ticking_in_parallel_converge_without_deadlock(self):
        a, b = Identity.generate("a"), Identity.generate("b")
        ha, hb = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        ma, mb = Mirror(ha / "mirror", rate_limit=False), Mirror(hb / "mirror", rate_limit=False)
        g = make_genesis(a, "t", [(b, "member")], k=1)
        tid = event_id(g)
        ma.ingest(g)
        bookA, bookB = N.PeerBook(ha / "peers.json"), N.PeerBook(hb / "peers.json")
        bookA.add(b.id, "b", ep("b" * 56 + ".onion"))
        bookB.add(a.id, "a", ep("a" * 56 + ".onion"), threads=[tid])
        box = {}
        na = N.Node(ma, a, bookA, ha / "node.json", lambda rec: S.Loopback(box["sb"]), pull_interval=0.3)
        nb = N.Node(mb, b, bookB, hb / "node.json", lambda rec: S.Loopback(box["sa"]), pull_interval=0.3)
        box["sa"] = S.SyncServer(ma, identity=a, on_notify=na.on_notify)
        box["sb"] = S.SyncServer(mb, identity=b, on_notify=nb.on_notify)
        stop = threading.Event()
        errs = []

        def loop(nd):
            while not stop.is_set():
                try:
                    nd.tick(parallel=True)
                except Exception as e:                               # noqa: BLE001
                    errs.append(repr(e))
                time.sleep(0.02)
        ths = [threading.Thread(target=loop, args=(n,), daemon=True) for n in (na, nb)]
        [t.start() for t in ths]
        try:
            cli = Mirror(ha / "mirror", rate_limit=False)
            for i in range(15):
                cli.ingest(Writer(a, cli.threads[tid]).post(f"a{i}"))
                time.sleep(0.05)
            deadline = time.time() + 12
            while time.time() < deadline and len(mb.threads.get(tid).resolved_ids() if tid in mb.threads else ()) < 16:
                time.sleep(0.1)
        finally:
            stop.set()
            [t.join(5) for t in ths]
        self.assertFalse([t for t in ths if t.is_alive()], "a node loop deadlocked")
        self.assertEqual(errs, [])
        self.assertIn(tid, mb.threads)
        self.assertEqual(len(mb.threads[tid].resolved_ids()), 16)


if __name__ == "__main__":
    unittest.main()
