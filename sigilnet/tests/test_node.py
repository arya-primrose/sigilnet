"""Step 3, node behaviour on a simulated network: fake clock, fake onion transport with controllable outages. No real network, no tor."""
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
from sigilnet.carrier import CarrierError as TorError


def onion(i):
    return chr(ord("a") + i) * 56 + ".onion"


def ep(i, port=47200):
    return {"type": "onion", "addr": f"{onion(i)}:{port}"}


class Clock:
    def __init__(self):
        self.t = time.time()                                        # simulated time starts now and runs faster than real time

    def __call__(self):
        return self.t


class Sim:
    """n nodes (arya, sansa, carol, ...), each with its own mirror, peer book and Node; one thread owned by the first, everyone a member."""

    def __init__(self, n=2, links=None, pull_interval=300.0):
        self.clock = Clock()
        names = ["arya", "sansa", "carol", "dave", "erin"][:n]
        self.ids = {x: Identity.generate(x) for x in names}
        self.up = {x: True for x in names}
        self.blocked = set()                                      # (caller, callee) pairs that get "not authorized"
        self.gates = {}                                           # callee -> threading.Event: requests to it wait until the event is set (a hung tor exchange)
        self.requests = []                                        # (caller, callee, request type)
        self.homes = {x: Path(tempfile.mkdtemp()) for x in names}
        self.mirrors, self.nodes, self.servers = {}, {}, {}
        self.links = links if links is not None else {a: [b for b in names if b != a] for a in names}
        for i, x in enumerate(names):
            self.mirrors[x] = Mirror(self.homes[x] / "mirror", rate_limit=False, clock=self.clock)
            self.build_node(x, pull_interval)
        self.onions = {self.ids[x].id: onion(i) for i, x in enumerate(names)}
        for x in names:
            self.fill_book(x)
        others = [(self.ids[x], "member") for x in names[1:]]
        self.genesis = make_genesis(self.ids[names[0]], "sim thread", others, k=1)
        self.tid = event_id(self.genesis)
        self.mirrors[names[0]].ingest(self.genesis)
        for x in names[1:]:                                           # the invitation: a new member is told the thread id (and the owner's onion)
            self.fill_book(x, threads=[self.tid])

    def build_node(self, x, pull_interval=300.0):
        m = self.mirrors[x]
        nd = N.Node(m, self.ids[x], N.PeerBook(self.homes[x] / "peers.json"), self.homes[x] / "node.json", lambda rec, me=x: self.transport(me, rec),
                    clock=self.clock, rng=random.Random(1), pull_interval=pull_interval)
        self.nodes[x] = nd
        self.servers[x] = S.SyncServer(m, clock=self.clock, on_notify=nd.on_notify, identity=self.ids[x])
        return nd

    def fill_book(self, x, threads=()):
        for y in self.links[x]:
            self.nodes[x].peers.add(self.ids[y].id, y, ep(list(self.ids).index(y)), threads=threads)

    def restart(self, x):
        """Kill the node process and start a new one on the same files (the mirror is re-read from disk too)."""
        self.mirrors[x] = Mirror(self.homes[x] / "mirror", rate_limit=False, clock=self.clock)
        return self.build_node(x)

    def transport(self, me, rec):
        callee = next(y for y in self.ids if ep(list(self.ids).index(y)) == rec["endpoint"])
        sim = self

        class T:
            def request(self_, req):
                sim.requests.append((me, callee, req.get("t")))
                if callee in sim.gates:
                    sim.gates[callee].wait(15)
                if not sim.up[callee]:
                    raise TorError("tor could not reach the onion service: descriptor cannot be found", retry=True)
                if (me, callee) in sim.blocked:
                    raise TorError("onion service needs authentication", retry=False)
                return sim.servers[callee].handle(json.loads(json.dumps(req)))
        return T()

    def post(self, x, text):
        """The CLI appends an event to the mirror directory (another process than the node)."""
        m = Mirror(self.homes[x] / "mirror", rate_limit=False, clock=self.clock)
        r = m.ingest(Writer(self.ids[x], m.thread(self.tid)).post(text))
        assert r.ok, (r.status, r.reason)
        return r

    def step(self, secs=1.0, rounds=1, names=None):
        for _ in range(rounds):
            self.clock.t += secs
            for x in names or self.nodes:
                if self.up[x]:
                    self.nodes[x].tick()

    def texts(self, x):
        m = Mirror(self.homes[x] / "mirror", rate_limit=False, clock=self.clock)
        if self.tid not in m.threads:
            return None
        t = m.thread(self.tid)
        return sorted(e["body"].get("text", "") for i in t.resolved_ids() for e in [t.stored[i]] if e["kind"] == "post")


class Convergence(unittest.TestCase):
    def test_two_nodes_converge_both_ways_and_hints_beat_the_pull_interval(self):
        s = Sim(2)
        s.post("arya", "one")
        s.step(1, 3)
        self.assertEqual(s.texts("sansa"), ["one"])                   # sansa did not know the thread: she was invited (thread id in her peer book)
        s.post("sansa", "two")
        s.step(1, 3)                                                   # far less than the 300 s pull interval: the notify hint triggered arya's pull
        self.assertEqual(s.texts("arya"), ["one", "two"])
        self.assertEqual(s.texts("sansa"), ["one", "two"])

    def test_a_chain_of_three_propagates_through_the_middle_without_echoing_back(self):
        links = {"arya": ["sansa"], "sansa": ["arya", "carol"], "carol": ["sansa"]}
        s = Sim(3, links=links)
        s.nodes["carol"].peers.add(s.ids["arya"].id, "arya", None)    # (carol knows arya exists but cannot dial her)
        s.post("arya", "from arya")
        s.step(1, 6)
        self.assertEqual(s.texts("carol"), ["from arya"])
        s.requests.clear()
        s.step(1, 5)
        echoed = [r for r in s.requests if r[2] == "notify"]
        self.assertEqual(echoed, [])                                   # acknowledged hints are not repeated while nothing changes

    def test_idle_nodes_only_do_anti_entropy_pulls(self):
        s = Sim(2, pull_interval=300)
        s.post("arya", "x")
        s.step(1, 4)
        s.requests.clear()
        s.step(10, 20)                                                 # 200 s of nothing (the pull interval is 300 s +-20%)
        self.assertEqual(s.requests, [])
        s.step(10, 20)                                                 # past the pull interval: one pull round per node
        kinds = {r[2] for r in s.requests}
        self.assertTrue(kinds <= {"summary", "list"}, kinds)
        self.assertLessEqual(len(s.requests), 12)


class Outages(unittest.TestCase):
    def test_a_peer_that_is_down_for_an_hour_costs_few_attempts_and_catches_up_at_once(self):
        s = Sim(2)
        s.post("arya", "before")
        s.step(1, 4)
        self.assertEqual(s.texts("sansa"), ["before"])
        s.up["sansa"] = False
        s.post("arya", "during")
        s.requests.clear()
        s.step(30, 120, names=["arya"])                                # an hour, arya's node keeps ticking
        tries = len([r for r in s.requests if r[0] == "arya" and r[2] in ("summary", "notify")])
        self.assertLess(tries, 14, tries)                              # exponential backoff, ONE backoff for the peer (not one per job)
        self.assertGreater(tries, 3)                                   # but it does keep trying
        st = {r["job"]: r for r in s.nodes["arya"].status()}
        self.assertEqual(st["pull"]["state"], "failing")
        self.assertIn("descriptor", st["pull"]["error"])
        s.up["sansa"] = True
        s.nodes["sansa"] = s.restart("sansa")                          # sansa's node comes back (a restart starts every job at once)
        s.step(1, 3)
        self.assertEqual(s.texts("sansa"), ["before", "during"])
        self.assertEqual({r["state"] for r in s.nodes["arya"].status()}, {"ok"})

    def test_an_unacknowledged_hint_expires_after_a_day_but_anti_entropy_keeps_trying(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        s.up["sansa"] = False
        s.post("arya", "while she is away")
        s.step(600, 26 * 6, names=["arya"])                            # 26 hours
        jobs = {r["job"]: r for r in s.nodes["arya"].status()}
        self.assertNotIn("notify", jobs)                               # the hint was dropped (NOTIFY_TTL = 24 h) ...
        self.assertEqual(jobs["pull"]["state"], "failing")             # ... the periodic pull is still being attempted
        s.up["sansa"] = True
        s.step(1000, 2)
        self.assertEqual(s.texts("sansa"), ["while she is away", "x"])

    def test_the_owner_restarts_mid_run_and_loses_nothing(self):
        s = Sim(2)
        s.post("arya", "a1")
        s.step(1, 3)
        s.up["sansa"] = False
        s.step(40, 14, names=["arya"])                                 # 560 s: past the pull interval, so arya has tried (and failed)
        tries_before = {k: j["tries"] for k, j in s.nodes["arya"].jobs.items()}
        self.assertTrue(any(t > 0 for t in tries_before.values()))
        s.nodes["arya"] = s.restart("arya")                            # kill -9 and start again
        self.assertEqual({k: j["tries"] for k, j in s.nodes["arya"].jobs.items()}, tries_before)   # the history of failures survived
        s.post("arya", "written while the node was down")             # appended by the CLI to the same directory
        s.up["sansa"] = True
        s.step(1, 4)
        self.assertEqual(s.texts("sansa"), ["a1", "written while the node was down"])

    def test_a_corrupt_state_file_starts_clean(self):
        s = Sim(2)
        s.step(1, 2)
        (s.homes["arya"] / "node.json").write_text("{not json")
        nd = s.restart("arya")
        self.assertEqual(nd.jobs, {})
        s.step(1, 2)
        self.assertGreater(len(s.nodes["arya"].jobs), 0)

    def test_an_unauthorized_peer_is_blocked_and_not_hammered(self):
        s = Sim(2)
        s.post("arya", "x")
        s.blocked.add(("sansa", "arya"))
        s.requests.clear()
        s.step(30, 40, names=["sansa"])                                # 20 minutes
        mine = [r for r in s.requests if r[0] == "sansa"]
        self.assertLessEqual(len(mine), 6, len(mine))
        st = s.nodes["sansa"].status()
        self.assertTrue(st and all(r["state"] == "BLOCKED" for r in st if r["job"] == "pull"))
        s.blocked.clear()                                              # the owner authorizes her: within the blocked delay she connects
        s.step(60, 20, names=["sansa"])
        self.assertEqual(s.texts("sansa"), ["x"])


class NonBlocking(unittest.TestCase):
    def test_a_hung_exchange_with_one_peer_does_not_stall_the_loop_or_the_other_peers(self):
        # live test 2026-09-30: one tor exchange hung ~30 s; the whole tick (and so every other peer) waited for it
        s = Sim(3)
        s.post("arya", "x")
        s.step(1, 4)
        gate = s.gates["sansa"] = threading.Event()
        nd = s.nodes["arya"]
        s.post("carol", "from carol while sansa hangs")
        for j in nd.jobs.values():                                   # everything is due now
            j["next"] = 0
        t0 = time.time()
        nd.tick(parallel=True)
        self.assertLess(time.time() - t0, 1.0)                       # the tick returned although sansa's exchange is hung
        end = time.time() + 5
        while time.time() < end and "from carol while sansa hangs" not in (s.texts("arya") or []):
            s.clock.t += 1
            nd.tick(parallel=True)
            time.sleep(0.05)
        self.assertIn("from carol while sansa hangs", s.texts("arya"))   # carol was served meanwhile
        gate.set()
        nd.close()

    def test_a_job_that_is_still_running_is_never_queued_again(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 4)
        gate = s.gates["sansa"] = threading.Event()
        nd = s.nodes["arya"]
        for j in nd.jobs.values():
            j["next"] = 0
        s.requests.clear()
        for _ in range(6):
            nd.tick(parallel=True)
            time.sleep(0.05)
        self.assertLessEqual(len([r for r in s.requests if r[0] == "arya"]), 2)   # one request per distinct job, not one per tick
        gate.set()
        nd.close()


class Hostile(unittest.TestCase):
    def test_a_notify_flood_runs_at_most_one_pull_per_tick(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        s.requests.clear()
        a = s.ids["arya"].id
        for _ in range(1000):
            s.nodes["sansa"].on_notify(a, s.tid, ["f" * 32])
        s.nodes["sansa"].tick()
        pulls = len([r for r in s.requests if r[0] == "sansa" and r[2] == "summary"])
        self.assertLessEqual(pulls, 1)

    def test_a_hint_flood_from_an_unreachable_peer_cannot_force_a_stream_of_attempts(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        s.up["sansa"] = False
        s.step(30, 30, names=["arya"])                                 # arya knows sansa is down and backs off
        s.requests.clear()
        for i in range(200):                                           # sansa (hostile, or flapping) spams hints while staying unreachable
            s.nodes["arya"].on_notify(s.ids["sansa"].id, s.tid, ["f" * 32])
            s.step(1, 1, names=["arya"])
        attempts = len([r for r in s.requests if r[0] == "arya"])
        self.assertLessEqual(attempts, 12, attempts)                   # 200 s: at most a few rounds (one reset per minute), not 200

    def test_a_notify_from_an_unknown_agent_schedules_nothing(self):
        s = Sim(2)
        s.step(1, 2)
        before = json.dumps(s.nodes["sansa"].jobs, sort_keys=True)
        s.nodes["sansa"].on_notify(Identity.generate("eve").id, s.tid, ["f" * 32])
        self.assertEqual(json.dumps(s.nodes["sansa"].jobs, sort_keys=True), before)

    def test_a_notify_naming_only_events_we_hold_schedules_nothing(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 4)
        t = s.mirrors["sansa"].thread(s.tid)
        for j in s.nodes["sansa"].jobs.values():
            j["next"] = 10 ** 11
        s.nodes["sansa"].on_notify(s.ids["arya"].id, s.tid, t.leaves())
        self.assertTrue(all(j["next"] >= 10 ** 11 for j in s.nodes["sansa"].jobs.values()))

    def test_a_peer_that_answers_garbage_does_not_stop_the_other_peers(self):
        s = Sim(3)
        s.post("arya", "x")
        real = s.servers["carol"].handle
        s.servers["carol"].handle = lambda req: {"t": "summary", "thread": 5, "junk": object.__name__}     # not even a valid answer
        s.step(1, 6)
        self.assertEqual(s.texts("sansa"), ["x"])
        self.assertTrue(any(r["state"] != "ok" for r in s.nodes["sansa"].status() if r["peer"] == "carol"))
        s.servers["carol"].handle = real

    def test_the_follow_predicate_admits_exactly_the_named_threads(self):
        s = Sim(2)
        w = Sim(2)
        s.step(1, 1)                                                   # (sansa's book names the thread)
        f = s.mirrors["sansa"].follow
        self.assertTrue(f(s.genesis))
        self.assertFalse(f(w.genesis))

    def test_a_node_only_creates_threads_it_was_told_about(self):
        s = Sim(2)
        w = Sim(2)                                                     # a different world: another thread that arya "has"
        s.post("arya", "x")
        s.step(1, 3)
        stranger = make_genesis(w.ids["arya"], "unrelated", [(w.ids["sansa"], "member")])
        s.mirrors["arya"].ingest(stranger)
        s.step(1, 3)
        m = Mirror(s.homes["sansa"] / "mirror", rate_limit=False)
        self.assertNotIn(event_id(stranger), m.threads)               # arya's extra thread lists sansa as a member only by another identity: no plan entry


class StateFiles(unittest.TestCase):
    def test_only_well_formed_job_keys_are_loaded(self):
        s = Sim(2)
        a, b = s.ids["arya"].id, s.ids["sansa"].id
        good = {"next": 1, "tries": 2, "err": "x", "ok": None, "since": None, "blocked": False}
        bad_keys = [f"{b}/{'a' * 32}/other", f"{b}/short/pull", f"{b}/{'a' * 32}", f"not-an-agent/{'a' * 32}/pull", f"{b}/{'a' * 31}//pull", f"{b}/{'g' * 32}/pull"]
        (s.homes["arya"] / "node.json").write_text(json.dumps({"jobs": {**{k: good for k in bad_keys}, f"{b}/{'a' * 32}/pull": good}}))
        nd = s.restart("arya")
        self.assertEqual(list(nd.jobs), [f"{b}/{'a' * 32}/pull"])

    def test_the_temp_file_is_never_written_through_a_planted_symlink(self):
        victim = Path(tempfile.mkdtemp()) / "victim.txt"
        victim.write_text("precious")
        d = Path(tempfile.mkdtemp())
        import uuid
        orig, calls = uuid.uuid4, []
        uuid.uuid4 = lambda: calls.append(1) or (uuid.UUID("00000000-0000-0000-0000-000000000000") if len(calls) == 1 else orig())   # an attacker who predicted the name ...
        try:
            import os
            (d / f"state.json.{os.getpid()}.00000000.tmp").symlink_to(victim)        # ... plants a symlink there
            N._atomic(d / "state.json", {"a": 1})
        finally:
            uuid.uuid4 = orig
        self.assertEqual(victim.read_text(), "precious")
        self.assertEqual(json.loads((d / "state.json").read_text()), {"a": 1})


class PeerBookAndBackoff(unittest.TestCase):
    def test_peer_book_validates_and_ignores_bad_entries(self):
        p = N.PeerBook(Path(tempfile.mkdtemp()) / "peers.json")
        good = Identity.generate("g").id
        p.add(good, "good", ep(3), threads=["a" * 32])
        for agent, endpoint in (("x", ep(1)), (good, {"type": "onion", "addr": "example.com:1"}), (good, ep(1, 0)), (good, ep(1, 70000)), (good, {"type": "xyz", "addr": "foo"}),
                                (good, "a.onion"), (good, {"type": "onion"}), (good, {"type": "onion", "addr": onion(1)})):
            with self.assertRaises(ValueError, msg=str((agent, endpoint))):
                p.add(agent, "n", endpoint)
        raw = json.loads(p.path.read_text())
        raw["peers"]["not-an-agent"] = {"endpoint": ep(1)}
        h, i = Identity.generate("h").id, Identity.generate("i").id
        raw["peers"][h] = {"endpoint": {"type": "onion", "addr": "evil.com:1"}}
        raw["peers"][i] = {"endpoint": {"type": "xyz", "addr": "future-carrier"}}       # a type no carrier here supports: the ENDPOINT is left out of the view (M1a), never fatal
        p.path.write_text(json.dumps(raw))
        self.assertEqual(sorted(p.all()), sorted([good, h, i]), "a bad endpoint no longer hides the peer (M1a): only the endpoint is left out")
        self.assertEqual((p.all()[h]["endpoints"], p.all()[i]["endpoints"]), ([], []))
        self.assertEqual(p.all()[good]["endpoints"], [ep(3)])
        self.assertEqual(p.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(p.remove(good))
        self.assertFalse(p.remove(good))

    def test_backoff_grows_then_caps_with_jitter(self):
        rng = random.Random(5)
        d = [N.backoff(n, rng) for n in range(1, 12)]
        self.assertTrue(14 <= d[0] <= 16.5)
        self.assertTrue(all(x <= N.BACKOFF_MAX * 1.21 for x in d))
        self.assertGreater(d[5], d[1])
        self.assertTrue(len({round(N.backoff(6, rng), 3) for _ in range(20)}) > 10)           # jittered: not all equal

    def test_removing_a_peer_drops_its_jobs(self):
        s = Sim(2)
        s.step(1, 2)
        self.assertGreater(len(s.nodes["arya"].jobs), 0)
        s.nodes["arya"].peers.remove(s.ids["sansa"].id)
        s.step(1, 1)
        self.assertEqual(s.nodes["arya"].jobs, {})


if __name__ == "__main__":
    unittest.main()
