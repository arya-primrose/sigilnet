"""DESIGN_node_wake.md rev 1: the node loop wakes at once (Waker, poke, token bucket, Mirror poke). Fake clock and sleep: no real waiting."""
import os
import tempfile
import threading
import unittest
from pathlib import Path

from sigilnet import node as N
from sigilnet import wake as W
from sigilnet.build import Writer
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.tests.test_node import Sim


class FakeTime:
    def __init__(self):
        self.t = 100.0
        self.slept = []
        self.hook = None                                      # called with the time after each sleep (to simulate things that happen meanwhile)

    def clock(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s
        if self.hook:
            self.hook(self.t)


def waker(tmp, **kw):
    ft = FakeTime()
    return ft, W.Waker(Path(tmp) / "node.poke", clock=ft.clock, sleep=ft.sleep, **kw)


class PokeWriter(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = Path(self.d) / "node.poke"

    def test_each_poke_appends_one_byte_with_mode_600(self):
        W.poke(self.p)
        W.poke(self.p)
        self.assertEqual(self.p.read_bytes(), b"xx")
        self.assertEqual(self.p.stat().st_mode & 0o777, 0o600)

    def test_the_file_is_truncated_once_it_passes_the_cap(self):
        for _ in range(W.POKE_CAP + 10):
            W.poke(self.p)
        self.assertLessEqual(self.p.stat().st_size, W.POKE_CAP)
        self.assertGreaterEqual(self.p.stat().st_size, 1)

    def test_a_poke_never_raises(self):
        W.poke(Path(self.d) / "nodir" / "node.poke")            # parent missing
        os.symlink(self.d + "/target", self.d + "/link")
        W.poke(Path(self.d) / "link")                           # O_NOFOLLOW: a symlink is refused, quietly
        self.assertFalse(Path(self.d + "/target").exists())
        W.poke(self.d)                                          # a directory

    def test_a_non_path_argument_never_raises_either(self):
        for bad in (None, 5, b"x\0y", "a\0b", object()):
            W.poke(bad)

    def test_a_poke_through_a_readonly_file_is_swallowed(self):
        self.p.write_bytes(b"")
        os.chmod(self.p, 0o400)
        if os.geteuid() != 0:
            W.poke(self.p)


class WakerTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_nothing_happens_then_it_times_out_after_exactly_the_timeout(self):
        ft, w = waker(self.d)
        w.round_started()
        t0 = ft.t
        self.assertEqual(w.wait(2.0), "timeout")
        self.assertAlmostEqual(ft.t - t0, 2.0, places=6)
        self.assertTrue(all(s <= W.POLL + 1e-9 for s in ft.slept))

    def test_default_timeout_is_tick_and_poll_slices_are_poll(self):
        ft, w = waker(self.d)
        w.round_started()
        t0 = ft.t
        w.wait()
        self.assertAlmostEqual(ft.t - t0, W.TICK, places=6)
        self.assertEqual(ft.slept[0], W.POLL)

    def test_the_event_wakes_within_one_poll_after_min_round(self):
        ft, w = waker(self.d)
        w.round_started()
        ft.t += 1.0                                            # the round took a second
        w.event.set()
        t0 = ft.t
        self.assertEqual(w.wait(2.0), "wake")
        self.assertEqual(ft.t, t0)

    def test_an_event_set_late_in_the_wait_returns_at_the_next_slice(self):
        ft, w = waker(self.d)
        w.round_started()
        ft.hook = lambda t: w.event.set() if t >= 100.5 else None
        ft.t += 0.0
        t0 = ft.t
        self.assertEqual(w.wait(2.0), "wake")
        self.assertLessEqual(ft.t - t0, 0.5 + W.POLL + 1e-9)
        self.assertGreaterEqual(ft.t - t0, 0.5)

    def test_a_changed_poke_file_wakes_it(self):
        ft, w = waker(self.d)
        w.round_started()
        ft.t += 1.0
        W.poke(Path(self.d) / "node.poke")
        self.assertEqual(w.wait(2.0), "poke")

    def test_a_poke_that_happened_before_round_started_does_not_wake_again(self):
        W.poke(Path(self.d) / "node.poke")
        ft, w = waker(self.d)
        W.poke(Path(self.d) / "node.poke")
        w.round_started()
        self.assertEqual(w.wait(1.0), "timeout")

    def test_the_stamp_includes_size_and_inode(self):
        p = Path(self.d) / "node.poke"
        p.write_bytes(b"x")
        ft, w = waker(self.d)
        w.round_started()
        st = os.stat(p)
        p.write_bytes(b"xy")                                   # same file, new size
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))       # (mtime put back: only size differs)
        self.assertEqual(w.wait(1.0), "poke")
        w.round_started()
        hold = Path(self.d) / "hold"
        hold.write_bytes(b"")                                  # (keeps the old inode number from being reused at once)
        os.rename(p, Path(self.d) / "old")
        p.write_bytes(b"xy")                                   # new inode
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertEqual(w.wait(1.0), "poke")

    def test_a_same_size_rewrite_with_a_new_mtime_is_a_poke(self):
        p = Path(self.d) / "node.poke"
        p.write_bytes(b"x")
        os.utime(p, ns=(1_000_000_000, 1_000_000_000))
        ft, w = waker(self.d)
        w.round_started()
        os.utime(p, ns=(2_000_000_000, 2_000_000_000))         # (a truncate-and-refill lands on the same size: the mtime tells)
        self.assertEqual(w.wait(1.0), "poke")

    def test_a_missing_or_vanishing_file_is_no_change(self):
        p = Path(self.d) / "node.poke"
        p.write_bytes(b"x")
        ft, w = waker(self.d)
        w.round_started()
        os.unlink(p)
        self.assertEqual(w.wait(0.5), "timeout")

    def test_a_missing_file_that_appears_is_a_poke(self):
        ft, w = waker(self.d)
        w.round_started()
        W.poke(Path(self.d) / "node.poke")
        self.assertEqual(w.wait(0.5), "poke")

    def test_min_round_is_a_floor_for_early_wakes(self):
        ft, w = waker(self.d)
        w.round_started()
        t0 = ft.t
        w.event.set()
        self.assertEqual(w.wait(2.0), "wake")
        self.assertGreaterEqual(ft.t - t0, W.MIN_ROUND - 1e-9)
        self.assertLessEqual(ft.t - t0, W.MIN_ROUND + W.POLL + 1e-9)

    def test_the_timeout_beats_min_round(self):
        ft, w = waker(self.d, min_round=5.0)
        w.round_started()
        t0 = ft.t
        w.event.set()
        w.wait(1.0)
        self.assertLessEqual(ft.t - t0, 1.0 + 1e-9)

    def test_a_thousand_pokes_cost_a_bounded_number_of_rounds(self):
        ft, w = waker(self.d)
        rounds = 0
        t0 = ft.t
        while ft.t - t0 < 10.0:                                # ten seconds with a poke arriving before every wait
            w.round_started()
            rounds += 1
            W.poke(Path(self.d) / "node.poke")
            w.wait(2.0)
        self.assertLessEqual(rounds, 10.0 / W.MIN_ROUND + 1)
        self.assertGreaterEqual(rounds, 10.0 / (W.MIN_ROUND + W.POLL) - 1)

    def test_round_started_clears_the_event_and_a_set_during_the_round_survives_to_the_wait(self):
        ft, w = waker(self.d)
        w.event.set()
        w.round_started()
        self.assertFalse(w.event.is_set())
        w.event.set()                                          # a notify arriving during the round
        ft.t += 1.0
        t0 = ft.t
        self.assertEqual(w.wait(2.0), "wake")
        self.assertEqual(ft.t, t0)

    def test_module_constants_are_read_at_call_time(self):
        old = W.POLL, W.TICK
        W.POLL, W.TICK = 0.5, 3.0
        try:
            ft, w = waker(self.d)
            w.round_started()
            t0 = ft.t
            w.wait()
            self.assertAlmostEqual(ft.t - t0, 3.0)
            self.assertEqual(ft.slept[0], 0.5)
        finally:
            W.POLL, W.TICK = old

    def test_real_clock_and_a_thread_setting_the_event(self):
        w = W.Waker(Path(self.d) / "node.poke")
        w.round_started()
        threading.Timer(0.3, w.event.set).start()
        import time
        t0 = time.monotonic()
        self.assertEqual(w.wait(2.0), "wake")
        self.assertLess(time.monotonic() - t0, 0.6)


class MirrorPoke(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.me = Identity.generate("a")
        self.pk = self.d / "node.poke"

    def mirror(self, poke):
        return Mirror(self.d / "m", rate_limit=False, poke=poke)

    def genesis(self, m):
        from sigilnet.build import make_genesis
        g = make_genesis(self.me, "t", [], k=1)
        return m, g

    def test_an_append_pokes_after_the_events_are_on_disk(self):
        m, g = self.genesis(self.mirror(self.pk))
        self.assertFalse(self.pk.exists())
        self.assertTrue(m.ingest(g).ok)
        self.assertEqual(self.pk.read_bytes(), b"x")
        t = m.thread(next(iter(m.threads)))
        m.ingest(Writer(self.me, t).post("hi"))
        self.assertEqual(self.pk.read_bytes(), b"xx")

    def test_a_mirror_without_poke_writes_nothing(self):
        m, g = self.genesis(self.mirror(None))
        m.ingest(g)
        self.assertFalse(self.pk.exists())
        self.assertEqual(os.listdir(self.d), ["m"])

    def test_a_duplicate_ingest_does_not_poke(self):
        m, g = self.genesis(self.mirror(self.pk))
        m.ingest(g)
        m.ingest(g)
        self.assertEqual(self.pk.read_bytes(), b"x")

    def test_a_failing_poke_never_fails_the_append(self):
        m, g = self.genesis(self.mirror(self.d / "no" / "such" / "dir" / "node.poke"))
        r = m.ingest(g)
        self.assertTrue(r.ok)
        m2 = self.mirror(None)
        self.assertEqual(len(m2.threads), 1)                     # persisted

    def test_open_mirror_pokes_by_default_and_not_for_the_node(self):
        from sigilnet.home import open_mirror
        h = self.d / "home"
        h.mkdir(mode=0o700)
        (h / "keys").mkdir(mode=0o700)
        self.assertEqual(open_mirror(h, self.me.id).poke, h / "node.poke")
        self.assertIsNone(open_mirror(h, self.me.id, poke=False).poke)

    def test_a_string_poke_path_becomes_a_path(self):
        self.assertEqual(Mirror(self.d / "m3", poke=str(self.pk)).poke, self.pk)

    def test_poke_is_keyword_only_and_never_derived_from_the_root(self):
        with self.assertRaises(TypeError):
            Mirror(self.d / "m", None, None)                      # (positional beyond root is refused)
        self.assertIsNone(Mirror(self.d / "m2").poke)

    def test_the_one_factory_grep_also_covers_poke(self):
        import re
        pkg = Path(__file__).resolve().parents[1]
        sites = [f"{f.name}:{n}" for f in sorted(pkg.glob("*.py")) for n, line in enumerate(f.read_text().splitlines(), 1)
                 if re.search(r"\bpoke\s*=", line) and "def " not in line and f.name not in ("wake.py",)]
        self.assertTrue(all(s.split(":")[0] in ("home.py", "mirror.py", "noderun.py") for s in sites), sites)


class NodeWake(unittest.TestCase):
    def test_a_notify_that_makes_the_pull_due_wakes_the_loop(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        nd = s.nodes["sansa"]
        nd.wake.clear()
        for j in nd.jobs.values():
            j["next"] = 10 ** 11
        nd.on_notify(s.ids["arya"].id, s.tid, ["f" * 32])
        self.assertTrue(nd.wake.is_set())
        pull = next(j for k, j in nd.jobs.items() if k.endswith("/pull"))
        self.assertLessEqual(pull["next"], s.clock())

    def test_an_unknown_agent_does_not_wake(self):
        s = Sim(2)
        s.step(1, 2)
        s.nodes["sansa"].wake.clear()
        s.nodes["sansa"].on_notify(Identity.generate("eve").id, s.tid, ["f" * 32])
        self.assertFalse(s.nodes["sansa"].wake.is_set())

    def test_leaves_we_already_hold_do_not_wake(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 4)
        nd = s.nodes["sansa"]
        nd.wake.clear()
        nd.on_notify(s.ids["arya"].id, s.tid, s.mirrors["sansa"].thread(s.tid).leaves())
        self.assertFalse(nd.wake.is_set())

    def test_the_bucket_gives_burst_then_refill(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        woke = []
        for _ in range(N.PULL_BURST + 2):
            nd.wake.clear()
            for j in nd.jobs.values():
                j["next"] = 10 ** 11
            nd.on_notify(a, s.tid, ["f" * 32])
            woke.append(nd.wake.is_set())
        self.assertEqual(woke, [True] * N.PULL_BURST + [False] * 2)
        pull = next(j for k, j in nd.jobs.items() if k.endswith("/pull"))
        self.assertGreater(pull["next"], s.clock())                   # no token: due when the next one is available
        self.assertLessEqual(pull["next"], s.clock() + 1.0 / N.PULL_REFILL + 1e-6)
        s.clock.t += 1.0 / N.PULL_REFILL
        nd.wake.clear()
        for j in nd.jobs.values():
            j["next"] = 10 ** 11
        nd.on_notify(a, s.tid, ["f" * 32])
        self.assertTrue(nd.wake.is_set())                              # a token came back

    def test_buckets_are_per_peer_and_thread(self):
        s = Sim(3)
        s.post("arya", "x")
        s.step(1, 4)
        nd = s.nodes["sansa"]
        for _ in range(N.PULL_BURST + 1):
            nd.on_notify(s.ids["arya"].id, s.tid, ["f" * 32])
        nd.wake.clear()
        for j in nd.jobs.values():
            j["next"] = 10 ** 11
        nd.on_notify(s.ids["carol"].id, s.tid, ["f" * 32])             # another peer: its own bucket
        self.assertTrue(nd.wake.is_set())

    def test_the_constants_are_the_designed_ones(self):
        self.assertEqual((N.PULL_BURST, N.PULL_REFILL), (3, 1.0))
        self.assertEqual((W.TICK, W.POLL, W.MIN_ROUND, W.POKE_CAP), (2.0, 0.05, 0.2, 4096))

    def test_a_long_quiet_time_never_banks_more_than_the_burst(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        nd.on_notify(a, s.tid, ["f" * 32])                             # (creates the bucket: it holds BURST-1 now)
        s.clock.t += 10_000.0
        woke = []
        for _ in range(N.PULL_BURST + 3):
            nd.wake.clear()
            for j in nd.jobs.values():
                j["next"] = 10 ** 11
            nd.on_notify(a, s.tid, ["f" * 32])
            woke.append(nd.wake.is_set())
        self.assertEqual(woke, [True] * N.PULL_BURST + [False] * 3)

    def test_a_hint_that_ends_an_unreachable_backoff_wakes_the_loop(self):
        s = Sim(2)
        s.post("arya", "x")
        s.step(1, 3)
        nd = s.nodes["sansa"]
        a = s.ids["arya"].id
        nd.down[a] = {"tries": 3, "until": s.clock() + 500, "err": "x", "blocked": False}
        for j in nd.jobs.values():
            j["next"] = s.clock() + 500
        t = nd.m.threads[s.tid]
        nd.wake.clear()
        nd.on_notify(a, s.tid, t.leaves())                             # nothing new to pull, but the peer is proven reachable: its jobs are due now
        self.assertTrue(nd.wake.is_set())
        self.assertNotIn(a, nd.down)

    def test_pruning_the_bucket_table_keeps_the_buckets_that_are_in_use(self):
        s = Sim(2)
        nd = s.nodes["sansa"]
        now = s.clock()
        nd._token("p", "busy", now)                                    # spent one: not full
        for i in range(N.MAX_JOBS + 5):
            nd._tokens[("q", f"t{i}")] = (float(N.PULL_BURST), now)    # full buckets: they hold no information
        nd._token("p", "other", now)                                   # table over the cap: prune
        self.assertIn(("p", "busy"), nd._tokens)
        self.assertLess(len(nd._tokens), 10)

    def test_the_bucket_table_is_bounded(self):
        s = Sim(2)
        nd = s.nodes["sansa"]
        for i in range(N.MAX_JOBS + 50):
            nd._token("p", f"t{i}", s.clock() - 1000.0 + 0)           # (all full by now)
        s.clock.t += 1000
        nd._token("p", "last", s.clock())
        self.assertLessEqual(len(nd._tokens), N.MAX_JOBS + 1)

    def test_a_finished_pull_wakes_once(self):
        s = Sim(2)
        s.post("arya", "x")
        s.nodes["sansa"].wake.clear()
        s.step(1, 3)
        self.assertTrue(s.nodes["sansa"].wake.is_set())
        self.assertEqual(s.texts("sansa"), ["x"])

    def test_node_wake_is_an_event_the_waker_can_adopt(self):
        s = Sim(2)
        w = W.Waker(s.homes["sansa"] / "node.poke")
        w.event = s.nodes["sansa"].wake
        w.round_started()
        s.nodes["sansa"].wake.set()
        self.assertEqual(w.wait(2.0), "wake")


class TwoNodeLoops(unittest.TestCase):
    """Two Nodes driven by real Waker loops (the shape of noderun.run) with the backstop at 30 s: a post must still reach the other side in about a second."""

    def run_loops(self, post_n=1):
        import time
        s = Sim(2)
        s.post("arya", "first")
        s.step(1, 3)                                                  # sansa now knows the thread
        stop = threading.Event()
        rounds = {"arya": 0, "sansa": 0}

        def loop(x):
            nd = s.nodes[x]
            w = W.Waker(s.homes[x] / "node.poke")
            w.event = nd.wake
            while not stop.is_set():
                w.round_started()
                nd.tick()
                rounds[x] += 1
                w.wait(30.0)
        ths = [threading.Thread(target=loop, args=(x,), daemon=True) for x in ("arya", "sansa")]
        for t in ths:
            t.start()
        time.sleep(0.3)
        base = dict(rounds)
        t0 = time.monotonic()
        for i in range(post_n):
            m = Mirror(s.homes["arya"] / "mirror", rate_limit=False, clock=s.clock, poke=s.homes["arya"] / "node.poke")
            m.ingest(Writer(s.ids["arya"], m.thread(s.tid)).post(f"live {i}"))
        want = ["first"] + [f"live {i}" for i in range(post_n)]
        got = None
        while time.monotonic() - t0 < 5.0:
            got = s.texts("sansa")
            if got == sorted(want):
                break
            time.sleep(0.02)
        dt = time.monotonic() - t0
        idle0 = dict(rounds)
        stop.set()
        for x in s.nodes:
            s.nodes[x].wake.set()
        for t in ths:
            t.join(5)
        return got, sorted(want), dt, base, idle0, s

    def test_a_post_reaches_the_other_node_in_about_a_second_with_a_30_s_backstop(self):
        got, want, dt, base, after, s = self.run_loops()
        self.assertEqual(got, want)
        self.assertLess(dt, 1.0, dt)

    def test_a_burst_of_posts_all_arrive_quickly(self):
        got, want, dt, base, after, s = self.run_loops(post_n=6)
        self.assertEqual(got, want)
        self.assertLess(dt, 3.0, dt)

    def test_an_idle_node_does_not_spin(self):
        import time
        got, want, dt, base, after, s = self.run_loops()
        self.assertLess(after["arya"] - base["arya"], 6)              # a post costs a few rounds, not hundreds


class LoopIntegration(unittest.TestCase):
    def test_noderun_uses_the_waker_and_not_a_sleep(self):
        src = (Path(__file__).resolve().parents[1] / "noderun.py").read_text()
        self.assertIn("waker.wait(TICK)", src)
        self.assertIn("waker.round_started()", src)
        self.assertIn("open_mirror(home, me.id, poke=False)", src)
        self.assertIn("waker.event = node.wake", src)
        self.assertNotIn("time.sleep(TICK)", src)
        from sigilnet import noderun
        self.assertEqual(noderun.TICK, W.TICK)


if __name__ == "__main__":
    unittest.main()
