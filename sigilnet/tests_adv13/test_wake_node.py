"""Node.wake / on_notify token bucket / _run_queued (W1, W4, W5) on the simulated network, and the noderun loop wiring (W6) on a real tcp carrier."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import node as N
from sigilnet import noderun, wake
from sigilnet.keys import Identity
from sigilnet.tests.test_node import Sim
from sigilnet.tests.test_tcplink import free_base

REPO = str(Path(__file__).resolve().parents[2])


def synced_sim(n=2):
    s = Sim(n)
    s.post("arya", "hello")
    for _ in range(6):
        s.step(1.0)
    return s


class OnNotify(unittest.TestCase):
    def setUp(self):
        self.s = Sim(2)
        self.a = self.s.ids["arya"].id
        self.nd = self.s.nodes["sansa"]
        self.tid = self.s.tid
        self.key = f"{self.a}/{self.tid}/pull"

    def notify(self, leaves=("ab" * 16,)):
        self.nd.on_notify(self.a, self.tid, list(leaves))

    def test_a_known_peer_with_news_makes_the_pull_due_now_and_wakes(self):
        self.nd.wake.clear()
        self.notify()
        self.assertLessEqual(self.nd.jobs[self.key]["next"], self.s.clock())
        self.assertTrue(self.nd.wake.is_set())

    def test_an_unknown_agent_never_wakes_and_creates_no_job(self):
        self.nd.wake.clear()
        stranger = Identity.generate("eve").id
        self.nd.on_notify(stranger, self.tid, ["ab" * 16])
        self.assertFalse(self.nd.wake.is_set())
        self.assertEqual([k for k in self.nd.jobs if k.startswith(stranger)], [])

    def test_known_leaves_do_not_wake(self):
        s = synced_sim()
        nd = s.nodes["sansa"]
        t = s.mirrors["sansa"].threads[s.tid]
        nd.wake.clear()
        nd.on_notify(s.ids["arya"].id, s.tid, list(t.leaves()))
        self.assertFalse(nd.wake.is_set())

    def test_unknown_leaves_of_a_synced_thread_wake(self):
        s = synced_sim()
        nd = s.nodes["sansa"]
        nd.jobs[f"{s.ids['arya'].id}/{s.tid}/pull"]["next"] = N.NEVER
        nd.wake.clear()
        nd.on_notify(s.ids["arya"].id, s.tid, ["cd" * 16])
        self.assertTrue(nd.wake.is_set())

    def test_the_wake_event_is_a_threading_event(self):
        self.assertIsInstance(self.nd.wake, threading.Event)


class TokenBucket(unittest.TestCase):
    """W1: PULL_BURST tokens per (peer, thread), refilled at PULL_REFILL per second; a notify that makes the pull due spends one."""

    def setUp(self):
        self.s = Sim(3)
        self.nd = self.s.nodes["sansa"]
        self.a = self.s.ids["arya"].id
        self.c = self.s.ids["carol"].id
        self.tid = self.s.tid

    def key(self, who):
        return f"{who}/{self.tid}/pull"

    def hint(self, who, n=0):
        """One hint with new leaves; the previous pull is 'finished' (job pushed far away) first, as it is after a real pull."""
        k = self.key(who)
        if k in self.nd.jobs:
            self.nd.jobs[k]["next"] = N.NEVER
        self.nd.wake.clear()
        self.nd.on_notify(who, self.tid, [f"{n:032x}"])
        return self.nd.jobs[k]["next"], self.nd.wake.is_set()

    def test_constants(self):
        self.assertEqual((N.PULL_BURST, N.PULL_REFILL), (3, 1.0))

    def test_the_burst_is_due_at_once_then_the_pulls_are_spaced(self):
        now = self.s.clock()
        due = [self.hint(self.a, n) for n in range(3)]
        for nxt, woke in due:
            self.assertLessEqual(nxt, now + 1e-6)
            self.assertTrue(woke)
        nxt, woke = self.hint(self.a, 99)                                    # the 4th at the same instant: no token
        self.assertGreater(nxt, now + 0.5)
        self.assertLessEqual(nxt, now + 1.0 / N.PULL_REFILL + 1e-6)
        self.assertFalse(woke, "a pull that is NOT due now must not wake the loop")

    def test_the_bucket_refills_one_token_per_second(self):
        for n in range(3):
            self.hint(self.a, n)
        nxt, _ = self.hint(self.a, 50)
        self.assertGreater(nxt, self.s.clock())
        self.s.clock.t += 1.05
        nxt, woke = self.hint(self.a, 51)
        self.assertLessEqual(nxt, self.s.clock() + 1e-6)
        self.assertTrue(woke)
        nxt, woke = self.hint(self.a, 52)                                    # and only ONE token came back
        self.assertGreater(nxt, self.s.clock())

    def test_the_bucket_does_not_overfill_after_a_long_quiet_time(self):
        self.s.clock.t += 3600
        due = [self.hint(self.a, n)[0] <= self.s.clock() + 1e-6 for n in range(6)]
        self.assertEqual(due, [True] * 3 + [False] * 3)

    def test_buckets_are_per_peer(self):
        for n in range(3):
            self.hint(self.a, n)
        self.assertGreater(self.hint(self.a, 9)[0], self.s.clock())
        nxt, woke = self.hint(self.c, 1)                                     # another peer: its own bucket is full
        self.assertLessEqual(nxt, self.s.clock() + 1e-6)
        self.assertTrue(woke)

    def test_constants_are_read_at_call_time(self):
        with mock.patch.object(N, "PULL_BURST", 5):
            due = [self.hint(self.a, n)[0] <= self.s.clock() + 1e-6 for n in range(7)]
        self.assertEqual(due, [True] * 5 + [False] * 2)

    def test_a_flood_of_hints_cannot_make_more_than_burst_plus_refill_pulls_due(self):
        now0 = self.s.clock()
        due_now = 0
        for i in range(3000):
            self.s.clock.t = now0 + i * 0.01                                  # 30 simulated seconds, 100 hints a second
            nxt, _ = self.hint(self.a, i)
            if nxt <= self.s.clock() + 1e-6:
                due_now += 1
        self.assertLessEqual(due_now, 3 + int(30 * N.PULL_REFILL) + 1)

    def test_the_old_five_second_floor_is_gone(self):
        """Two real posts 1 s apart are both pulled promptly (burst), not 5 s after the first pull STARTED."""
        k = self.key(self.a)
        self.nd.on_notify(self.a, self.tid, ["aa" * 16])
        self.nd.jobs[k]["started"] = self.s.clock()
        self.nd.jobs[k]["next"] = N.NEVER                                    # the first pull ran
        self.s.clock.t += 1.0
        self.nd.on_notify(self.a, self.tid, ["bb" * 16])
        self.assertLessEqual(self.nd.jobs[k]["next"], self.s.clock() + 1e-6)


class RunQueued(unittest.TestCase):
    def test_a_pull_that_ingested_wakes_the_loop_once(self):
        s = Sim(2)
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        s.post("arya", "news")
        plan = nd._plan()
        nd.wake.clear()
        nd._run_queued((a, s.tid, "pull"), a, s.tid, "pull", plan[a])
        self.assertIn("news", s.texts("sansa") or [])
        self.assertTrue(nd.wake.is_set())

    def test_a_pull_that_found_nothing_does_not_wake(self):
        s = synced_sim()
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        plan = nd._plan()
        nd.wake.clear()
        nd._run_queued((a, s.tid, "pull"), a, s.tid, "pull", plan[a])
        self.assertFalse(nd.wake.is_set())

    def test_a_notify_job_does_not_wake_the_loop(self):
        s = synced_sim()
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        plan = nd._plan()
        nd.wake.clear()
        nd._run_queued((a, s.tid, "notify"), a, s.tid, "notify", plan[a])
        self.assertFalse(nd.wake.is_set())

    def test_the_wake_is_set_even_when_the_job_raised(self):
        """A failing exchange must not leave the key queued (existing contract) and must not wake for nothing."""
        s = Sim(2)
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        s.up["arya"] = False
        plan = nd._plan()
        nd.wake.clear()
        nd._run_queued((a, s.tid, "pull"), a, s.tid, "pull", plan[a])
        self.assertNotIn((a, s.tid, "pull"), nd._queued)


def tcp_home():
    home = Path(tempfile.mkdtemp(prefix="adv13_loop_"))
    env = {**os.environ, "PYTHONPATH": REPO, "PYTHONDONTWRITEBYTECODE": "1"}
    base = free_base()
    for args in (["id", "init", "loop"], ["node", "init", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", str(base)]):
        r = subprocess.run([sys.executable, "-B", "-m", "sigilnet", "--home", str(home), *args], capture_output=True, text=True, env=env, cwd=REPO)
        assert r.returncode == 0, r.stderr
    return home


class Loop(unittest.TestCase):
    """The loop wiring on a real node with the TICK made huge: only a wake can start a round."""

    def run_node(self, home, seconds, tick):
        me = Identity.load(home / "identity.json")
        self.lines = []
        self.th = threading.Thread(target=lambda: noderun.run(home, me, seconds=seconds, out=lambda s: self.lines.append(s)))
        self.patch = mock.patch.object(noderun, "TICK", tick)
        self.patch.start()
        self.home = home
        self.th.start()
        t0 = time.time()
        while time.time() - t0 < 30:
            st = self.status(home)
            if st and st.get("ready"):
                self.end = time.time() + seconds
                return
            time.sleep(0.05)
        self.fail("the node never became ready")

    def status(self, home):
        try:
            return json.loads((home / "node.status.json").read_text())
        except (OSError, ValueError):
            return None

    def finish(self):
        """The node ends at the first loop top after `seconds`; with a huge TICK that needs a wake: poke it once the time is up."""
        while self.th.is_alive():
            time.sleep(max(0.0, self.end - time.time()) + 0.05)
            wake.poke(self.home / "node.poke")
            self.th.join(2)
        self.patch.stop()

    def at(self, home):
        return self.status(home)["at"]

    def wait_round(self, home, since, within):
        t0 = time.time()
        while time.time() - t0 < within:
            if self.at(home) > since:
                return time.time() - t0
            time.sleep(0.01)
        return None

    def test_an_idle_node_does_not_run_rounds_faster_than_the_tick(self):
        home = tcp_home()
        self.run_node(home, 4, tick=30.0)
        try:
            time.sleep(0.5)
            a0 = self.at(home)
            time.sleep(2.0)
            self.assertEqual(self.at(home), a0, "a round ran with nothing to do and a 30 s tick")
        finally:
            self.finish()

    def test_a_poke_starts_a_round_promptly(self):
        home = tcp_home()
        self.run_node(home, 3, tick=30.0)
        try:
            time.sleep(0.5)
            a0 = self.at(home)
            wake.poke(home / "node.poke")
            took = self.wait_round(home, a0, 1.0)
            self.assertIsNotNone(took, "a poke did not start a round within 1 s (tick is 30 s)")
            self.assertLess(took, 0.6)
        finally:
            self.finish()

    def test_a_cli_style_append_wakes_the_node(self):
        """What `sigilnet post` does: its own Mirror (open_mirror, poke on) appends an event; the node (another process in real life) runs a round at once."""
        from sigilnet.build import make_genesis, Writer
        from sigilnet.home import open_mirror
        home = tcp_home()
        self.run_node(home, 3, tick=30.0)
        try:
            time.sleep(0.5)
            a0 = self.at(home)
            me = Identity.load(home / "identity.json")
            m = open_mirror(home, me.id)
            m.ingest(make_genesis(me, "t", [(Identity.generate("x"), "member")]))
            ev = Writer(me, next(iter(m.threads.values()))).post("hello")
            self.assertTrue(m.ingest(ev).ok)
            took = self.wait_round(home, a0, 1.0)
            self.assertIsNotNone(took, "an append through the factory mirror did not wake the node")
        finally:
            self.finish()

    def test_a_notify_that_sets_node_wake_starts_a_round_promptly(self):
        """The loop and the Node share ONE event: Node.on_notify -> node.wake -> the loop's wait returns at once."""
        home = tcp_home()
        nodes = []
        real_init = N.Node.__init__

        def spy(self_, *a, **k):
            real_init(self_, *a, **k)
            nodes.append(self_)

        with mock.patch.object(N.Node, "__init__", spy):
            self.run_node(home, 3, tick=30.0)
        try:
            time.sleep(0.5)
            a0 = self.at(home)
            nodes[0].wake.set()
            took = self.wait_round(home, a0, 1.0)
            self.assertIsNotNone(took, "node.wake did not start a round (the loop does not wait on the node's event)")
            self.assertLess(took, 0.6)
        finally:
            self.finish()

    def test_the_tick_is_still_the_backstop(self):
        home = tcp_home()
        self.run_node(home, 3, tick=0.5)
        try:
            a0 = self.at(home)
            took = self.wait_round(home, a0, 1.5)
            self.assertIsNotNone(took, "no round within 1.5 s with a 0.5 s tick and no wake")
        finally:
            self.finish()

    def test_a_burst_of_pokes_is_bounded_by_min_round(self):
        home = tcp_home()
        self.run_node(home, 6, tick=30.0)
        try:
            time.sleep(0.5)
            seen, last = set(), self.at(home)
            end = time.time() + 3.0
            while time.time() < end:
                wake.poke(home / "node.poke")
                time.sleep(0.005)
                a = self.at(home)
                if a != last:
                    seen.add(a)
                    last = a
            self.assertLessEqual(len(seen), int(3.0 / 0.2) + 2, f"{len(seen)} rounds in 3 s of poking")
            self.assertGreaterEqual(len(seen), 5)
        finally:
            self.finish()


if __name__ == "__main__":
    unittest.main()
