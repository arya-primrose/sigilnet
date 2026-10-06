"""tools/soak.py: the pure parts (schedule, token bucket, message formats and parsing, duplicate/gap detection, stop rules, latency stats), the driver against a SCRIPTED CLI (what it
does with hostile or odd peer messages: it never puts peer text on a command line), subprocess timeouts, the marker scan, and one real compressed end-to-end run of the selftest."""
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
_spec = importlib.util.spec_from_file_location("soak", ROOT / "tools" / "soak.py")
soak = importlib.util.module_from_spec(_spec)
sys.modules["soak"] = soak
_spec.loader.exec_module(soak)

from sigilnet import blob as B  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class Schedule(unittest.TestCase):
    def test_deterministic_sorted_bounded_and_sized(self):
        a, b = soak.schedule("1", "arya", 6), soak.schedule("1", "arya", 6)
        self.assertEqual(a, b)
        self.assertNotEqual(a, soak.schedule("2", "arya", 6))
        self.assertEqual(a, sorted(a, key=lambda e: (e[0], e[1])))
        self.assertTrue(all(0 <= t < 6 * 3600 for t, _, _ in a))
        kinds = {}
        for _, k, _ in a:
            kinds[k] = kinds.get(k, 0) + 1
        self.assertTrue(50 <= kinds["post"] <= 100, kinds)
        self.assertTrue(10 <= kinds["ask"] <= 15 and 5 <= kinds["blob"] <= 7 and kinds["sample"] == 35 and kinds["marker"] == 5, kinds)
        self.assertTrue(all(soak.BLOB_MIN <= x <= soak.BLOB_MAX for _, k, x in a if k == "blob"))

    def test_posts_keep_a_hard_floor_between_them(self):
        ts = [t for t, k, _ in soak.schedule("7", "sansa", 6) if k == "post"]
        self.assertGreaterEqual(min(b - a for a, b in zip(ts, ts[1:])), 30.0 - 1e-9)

    def test_faults_per_side_as_agreed_with_sansa(self):
        self.assertEqual([(t, x) for t, k, x in soak.schedule("1", "sansa", 6) if k == "fault"], [(7200.0, "term"), (18000.0, "kill9")])
        self.assertEqual([(t, x) for t, k, x in soak.schedule("1", "arya", 6) if k == "fault"], [(10800.0, "torkill"), (14400.0, "term")])
        self.assertEqual([k for _, k, _ in soak.schedule("1", "arya", 1) if k == "fault"], [], "a short run injects no fault that would not fit")

    def test_compressed_time_scales_everything_and_keeps_the_event_mix(self):
        full, small = soak.schedule("1", "sansa", 6), soak.schedule("1", "sansa", 6, soak.Cfg(1 / 30))
        self.assertEqual({k for _, k, _ in full}, {k for _, k, _ in small})
        self.assertLessEqual(max(t for t, _, _ in small), 6 * 3600 / 30)
        self.assertEqual([(round(t * 30), x) for t, k, x in small if k == "fault"], [(7200, "term"), (18000, "kill9")])


class Bucket(unittest.TestCase):
    def test_burst_then_refill_and_an_hour_never_exceeds_the_rate(self):
        c = Clock()
        b = soak.TokenBucket(40.0, 5, c)
        self.assertEqual([b.take() for _ in range(7)], [True] * 5 + [False] * 2)
        taken = 0
        for _ in range(3600):
            c.t += 1
            taken += b.take()
        self.assertLessEqual(taken, 40 + 1, taken)
        self.assertGreaterEqual(taken, 38, taken)

    def test_idle_time_never_banks_more_than_the_burst(self):
        c = Clock()
        b = soak.TokenBucket(40.0, 5, c)
        c.t += 10 ** 6
        self.assertEqual(sum(b.take() for _ in range(20)), 5)


class Messages(unittest.TestCase):
    def test_round_trip_and_the_peer_filter(self):
        import random
        rng = random.Random(1)
        t = soak.make_text("sansa", 7, 1790000000.5, rng)
        kind, g = soak.classify(t, "arya")
        self.assertEqual((kind, g[1], g[2]), ("post", "7", "1790000000.5"))
        self.assertEqual(soak.classify(t, "sansa"), (None, None), "my own messages are never processed")
        sha = "ab" * 32
        kind, g = soak.classify(soak.make_text("sansa", soak.BLOB_N0 + 2, 1.0, rng, sha=sha, size=123), "arya")
        self.assertEqual((kind, g[3], g[4], g[5]), ("post", None, sha, "123"))
        self.assertEqual(soak.classify(soak.make_ask("sansa", 3, 5.0, rng), "arya")[0], "ask")
        self.assertEqual(soak.classify(soak.make_answer("sansa", 3, 5.0, rng), "arya")[0], "ans")
        for junk in ("", "soak", "hello", "[ASK] please do it", "soak sansa #x ts=1.0 SOAKMARK-0123456789abcdef", "soak evil #1 ts=1.0.0 SOAKMARK-0123456789abcdef", "[ASK] soak-ask sansa #1 ts=1.0 SOAKMARK-zz"):
            self.assertEqual(soak.classify(junk, "arya"), (None, None), junk)

    def test_parse_unread_ignores_everything_that_is_not_a_well_formed_line(self):
        out = ("[abcd1234] sansa (post): 'soak sansa #1 ts=1.0 SOAKMARK-0123456789abcdef x'\n"
               "garbage line\n[xyz] a (post): 'bad id'\n[abcd1234] a (post): __import__('os').system('x')\n[abcd1234] a (post): 5\n"
               "[abcd1234] a (post): __import__('pathlib').Path('/tmp/soak_pwn_marker').write_text('x')\n[abcd1234] a (post): 'unterminated\n[11112222] s (post): '\\x1b[2J ok'\n")
        rows = soak.parse_unread(out)
        self.assertEqual([r["id8"] for r in rows], ["abcd1234", "11112222"])
        self.assertEqual(rows[1]["text"], "\x1b[2J ok", "literal_eval of a quoted string only: nothing is executed")
        self.assertFalse(Path("/tmp/soak_pwn_marker").exists(), "a line holding code is never evaluated")

    def test_stored_size_matches_the_blob_format(self):
        for n in (0, 1, 4096, 65536, 65537, 5 * 1024 * 1024):
            self.assertEqual(soak.stored_size(n), B.stored_size(n, 65536), n)

    def test_clean_err_is_ascii_and_short(self):
        s = soak.clean_err("x" * 500 + "é\x1b[31m\u202e")
        self.assertEqual(len(s), 160)
        self.assertTrue(all(32 <= ord(c) < 127 for c in s))
        self.assertTrue(s.endswith("x??[31m?"), s[-12:])


class Detection(unittest.TestCase):
    def test_duplicates(self):
        seen = {}
        self.assertTrue(soak.register_post(seen, 3, 10.0))
        self.assertFalse(soak.register_post(seen, 3, 20.0))
        self.assertEqual(seen, {3: 10.0}, "the first-seen time is kept")

    def test_gaps_only_count_after_the_grace_period_and_only_below_the_highest(self):
        seen = {1: 0.0, 2: 10.0, 4: 100.0}
        self.assertEqual(soak.find_gaps(seen, 100 + 1800, 1800), [], "inside the grace period")
        self.assertEqual(soak.find_gaps(seen, 100 + 1801, 1800), [3])
        self.assertEqual(soak.find_gaps({}, 10 ** 9, 1800), [])
        self.assertEqual(soak.find_gaps({1: 0.0, 2: 1.0}, 10 ** 9, 1800), [], "no hole")
        self.assertEqual(soak.find_gaps({5: 0.0}, 10 ** 9, 1800), [1, 2, 3, 4])

    def test_percentiles_and_stats(self):
        self.assertIsNone(soak.percentile([], 50))
        xs = list(range(1, 101))
        self.assertEqual((soak.percentile(xs, 50), soak.percentile(xs, 95), soak.percentile(xs, 99), soak.percentile(xs, 100)), (50, 95, 99, 100))
        self.assertEqual(soak.percentile([7], 99), 7)
        st = soak.latency_stats([1.0, 3.0, 2.0])
        self.assertEqual((st["n"], st["p50"], st["max"]), (3, 2.0, 3.0))
        self.assertEqual(soak.latency_stats([]), {"n": 0, "p50": None, "p95": None, "p99": None, "max": None})


class StopRules(unittest.TestCase):
    def test_each_condition_and_the_quiet_case(self):
        ok = [200_000] * 20
        self.assertIsNone(soak.check_stop(ok, 10 ** 6, [], [], []))
        self.assertIn("marker", soak.check_stop(ok, 0, ["/x"], [], []))
        self.assertIn("twice", soak.check_stop(ok, 0, [], [4], []))
        self.assertIn("gap", soak.check_stop(ok, 0, [], [], [3]))
        self.assertIn("blob", soak.check_stop(ok, 0, [], [], [], 1))
        self.assertIn("home", soak.check_stop(ok, soak.HOME_LIMIT + 1, [], [], []))
        self.assertIsNone(soak.check_stop(ok, soak.HOME_LIMIT, [], [], []))
        self.assertIn("RSS", soak.check_stop([100, soak.RSS_LIMIT_KB + 1], 0, [], [], []))
        self.assertIsNone(soak.check_stop([None, 0, soak.RSS_LIMIT_KB], 0, [], [], []), "the limit itself and missing samples are fine")

    def test_rss_growth_over_the_first_hours_median(self):
        base = [200_000] * 6
        self.assertIsNone(soak.check_stop(base + [200_000 + soak.RSS_GROWTH_KB] * 7, 0, [], [], []))
        self.assertIn("grew", soak.check_stop(base + [200_000 + soak.RSS_GROWTH_KB + 1] * 7, 0, [], [], []))
        self.assertIsNone(soak.check_stop(base + [200_000 + soak.RSS_GROWTH_KB + 1] * 3, 0, [], [], []), "too few samples to call it growth")


class FakeCli:
    """Scripted CLI: `unread` returns what the test put in .unread; `outputs` maps a command (or 'envelope status') to (rc, stdout); `raises` maps a command to an exception; every call is recorded."""

    def __init__(self, home):
        self.home, self.tree, self.hangs, self.calls, self.unread, self.outputs, self.raises = Path(home), Path("."), 0, [], "", {}, {}

    def run(self, *args, timeout=0):
        self.calls.append(args)
        key = " ".join(args[:2]) if args[0] == "envelope" else args[0]
        if key in self.raises:
            raise self.raises[key]
        if key in self.outputs:
            out = self.outputs[key]
            return (out[0], out[1], "") if not callable(out) else out(args)
        if args[0] == "unread":
            return 0, self.unread, ""
        if args[0] == "brief":
            return 0, json.dumps({"events": 3, "awaiting": 0, "missing": [], "conflicts": 0, "voided": 0}), ""
        if args[0] == "blob":
            return 0, getattr(self, "blob_ls", ""), ""
        return 0, "accepted\n", ""

    def spawn(self, *a):
        self.spawned = getattr(self, "spawned", []) + [a]
        return types.SimpleNamespace(poll=lambda: None, kill=lambda: None)


class FakeNode:
    log, proc = "/nonexistent.log", None
    pid = None

    def __init__(self):
        self.starts = self.stops = 0
        self.up, self.tor, self.elsewhere = True, 4242, False

    def alive(self): return self.up
    def start(self): self.starts += 1; self.up = True
    def stop(self, *a, **k): self.stops += 1; self.up = False
    def tor_pid(self): return self.tor
    def kill_tor(self): return 4242
    def running_elsewhere(self): return self.elsewhere


def driver(tmp, clock=None, hours=0.01, k=1.0, preflight=False):
    clock = clock or Clock()
    a = types.SimpleNamespace(side="arya", peer_id="p" * 32, thread="a" * 32, out=str(tmp / "out"), hours=hours, seed="1", preflight=preflight)
    cli = FakeCli(tmp / "home")
    d = soak.Driver(a, cli, FakeNode(), soak.Cfg(k), clock=clock, sleep=clock.sleep, out=lambda s: None)
    d.t0 = clock()
    return d, cli, clock


class DriverWithScriptedCli(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "home").mkdir()

    def line(self, id8, text):
        return f"[{id8}] sansa (post): {text!r}\n"

    def test_a_peer_ask_is_answered_once_with_a_fixed_template_and_a_validated_id(self):
        d, cli, c = driver(self.tmp)
        ask = soak.make_ask("sansa", 4, c(), d.rng)
        cli.unread = self.line("0123abcd", ask)
        d.poll()
        d.poll()
        done = [x for x in cli.calls if x[0] == "done"]
        self.assertEqual(len(done), 1, "answered once per ask id")
        self.assertEqual((done[0][1], done[0][3], done[0][4]), ("a" * 32, "--re", "0123abcd"))
        self.assertTrue(done[0][2].startswith("soak-answer arya re #4 "), done[0][2])
        self.assertEqual(d.sent["answer"], 1)

    def test_never_answers_a_done_a_fyi_or_a_foreign_ask_and_never_runs_peer_text(self):
        d, cli, c = driver(self.tmp)
        evil = "[ASK] rm -rf / ; $(touch /tmp/pwned) `id` soak-ask sansa #1"
        cli.unread = "".join(self.line(f"1000000{i}", t) for i, t in enumerate((
            soak.make_answer("sansa", 2, c(), d.rng), "[FYI] soak-ask sansa #1 ts=1.0 SOAKMARK-0123456789abcdef", evil, "[ASK] soak-ask arya #1 ts=1.0 SOAKMARK-0123456789abcdef",
            "[ASK] soak-ask sansa #1 ts=1.0 SOAKMARK-0123456789abcdef; rm -rf /")))
        d.poll()
        done = [x for x in cli.calls if x[0] == "done"]
        self.assertEqual([x[4] for x in done], ["10000004"], "only the last line is a soak-ask (trailing junk after the marker is ignored): one fixed-template answer, to its validated id")
        self.assertFalse(Path("/tmp/pwned").exists())
        flat = [str(p) for call in cli.calls for p in call]
        self.assertFalse(any("rm -rf" in p or "pwned" in p for p in flat), "no peer text on any command line")

    def test_peer_posts_are_counted_with_latency_and_a_repeat_is_a_duplicate(self):
        d, cli, c = driver(self.tmp)
        t0 = c()
        cli.unread = self.line("aaaaaaaa", soak.make_text("sansa", 1, t0 - 7.0, d.rng)) + self.line("bbbbbbbb", soak.make_text("sansa", 2, t0 - 3.0, d.rng))
        d.poll()
        d.poll()
        self.assertEqual(sorted(d.peer_ns), [1, 2])
        self.assertEqual([round(x) for x in d.latency], [7, 3])
        self.assertEqual(d.dups, [])
        cli.unread += self.line("cccccccc", soak.make_text("sansa", 2, t0 - 1.0, d.rng))     # the same post number delivered under another id
        d.poll()
        self.assertEqual(d.dups, [2])
        self.assertIn("twice", soak.check_stop([], 0, d.markers, d.dups, []))

    def test_a_hole_in_the_peer_sequence_becomes_a_gap_after_the_grace_period(self):
        d, cli, c = driver(self.tmp)
        cli.unread = self.line("aaaaaaaa", soak.make_text("sansa", 1, c(), d.rng)) + self.line("cccccccc", soak.make_text("sansa", 3, c(), d.rng))
        d.poll()
        self.assertEqual(soak.find_gaps(d.peer_ns, c(), d.cfg.gap_seconds), [])
        c.t += d.cfg.gap_seconds + 1
        self.assertEqual(soak.find_gaps(d.peer_ns, c(), d.cfg.gap_seconds), [2])

    def test_blob_posts_do_not_look_like_gaps_in_the_post_sequence(self):
        d, cli, c = driver(self.tmp)
        cli.unread = self.line("aaaaaaaa", soak.make_text("sansa", 1, c(), d.rng)) + self.line("bbbbbbbb", soak.make_text("sansa", soak.BLOB_N0 + 1, c(), d.rng, sha="cd" * 32, size=1000))
        d.poll()
        c.t += 10 ** 6
        self.assertEqual(soak.find_gaps(d.peer_ns, c(), d.cfg.gap_seconds), [])
        self.assertEqual(sorted(d.peer_blobs), [soak.BLOB_N0 + 1])
        self.assertIn(("blob", "ls", "a" * 32), cli.calls, "a blob post triggers a listing (no cid is ever taken from peer text)")

    def test_the_blob_fetched_is_the_one_whose_stored_size_matches_and_is_not_yet_fetched(self):
        d, cli, c = driver(self.tmp)
        size = 100_000
        right, other, held = "sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64
        cli.blob_ls = (f"aaaaaaaa  {other}  {soak.stored_size(size + 5)} bytes  not fetched\n"
                       f"aaaaaaaa  {held}  {soak.stored_size(size)} bytes  HELD  authored\n"
                       f"aaaaaaaa  {right}  {soak.stored_size(size)} bytes  not fetched\n")
        d.start_blob_fetch(size, "ef" * 32)
        self.assertEqual(len(cli.spawned), 1)
        self.assertEqual(cli.spawned[0][:3], ("blob", "get", "a" * 32))
        self.assertEqual(cli.spawned[0][3], right)
        d.blob_jobs.clear()
        cli.blob_ls = f"aaaaaaaa  {other}  {soak.stored_size(size + 5)} bytes  not fetched\n"
        d.start_blob_fetch(size, "ef" * 32)
        self.assertEqual(len(cli.spawned), 1, "no row of the right size: nothing is fetched")

    def test_the_bucket_defers_posts_and_notes_it(self):
        d, cli, c = driver(self.tmp)
        for _ in range(12):
            d.do_post()
        self.assertEqual(d.sent["post"], 5, "burst of 5, then deferred")
        self.assertEqual(d.deferred, 7)
        self.assertEqual(len([x for x in cli.calls if x[0] == "post"]), 5)

    def test_no_event_text_in_the_results_files(self):
        d, cli, c = driver(self.tmp)
        secret = "TOPSECRETBODY"
        cli.unread = self.line("aaaaaaaa", f"soak sansa #1 ts={c():.1f} SOAKMARK-0123456789abcdef {secret}")
        d.poll()
        d.do_sample()
        d.finish(None)
        blob = "".join(p.read_text() for p in (self.tmp / "out").iterdir() if p.is_file())
        self.assertNotIn(secret, blob)
        for p in (self.tmp / "out").iterdir():
            self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600", p)
        self.assertEqual(oct((self.tmp / "out").stat().st_mode & 0o777), "0o700")


GOOD_PREFLIGHT = {"list": (0, "aaaaaaaa  'soak'  owner=x  events=3  unread=0\n"),
                  "envelope status": (0, "'soak': ENCRYPTED; epochs on the current chain:\n  aaaaaaaa  epoch 0 (genesis)  key: verified\n  bbbbbbbb  removal  key: verified\n  lines skipped on load: 0\n"),
                  "wait": (3, "")}


class Robustness(unittest.TestCase):
    """r33b (Sansa's review): the run survives a failing step, always stops the node and writes the summary, ends on SIGTERM through finish(), has a stop command and a preflight."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "home").mkdir()

    def summary(self):
        return json.loads((self.tmp / "out" / "summary.json").read_text())

    def test_the_summary_collects_every_finding_in_one_list(self):
        d, cli, c = driver(self.tmp)
        d.finish(None)
        self.assertEqual(self.summary()["findings"], [], "a clean run has none")
        d.dups, d.markers, d.blob_bad, d.errors_total, d.cli.hangs = [3], ["/x"], 2, 4, 1
        d.post_failed = [{"n": 1, "rc": 1}]
        d.peer_ns = {1: 0.0, 4: 0.0}
        d.fault_notes = [{"kind": "torkill", "at": 10800.0, "verdict": "FINDING: node alive with NO tor (silently dead doors)"}, {"kind": "term", "at": 1.0, "verdict": "restarted by the driver; verify clean"}]
        d.cli.outputs["verify"] = (1, "bad")
        d.finish("some reason")
        f = self.summary()["findings"]
        for needle in ("stopped early: some reason", "verify rc 1", "duplicate deliveries: [3]", "gaps in the peer's posts: [2, 3]", "2 blob(s)", "1 file(s) with the plaintext marker",
                       "1 post(s) refused", "4 driver step error(s)", "1 CLI call(s) hit their timeout", "fault torkill at 10800.0 s: FINDING"):
            self.assertTrue(any(needle in x for x in f), (needle, f))
        self.assertFalse(any("fault term" in x for x in f), "a good verdict is not a finding")

    def test_a_failing_step_is_counted_and_the_run_carries_on(self):
        d, cli, c = driver(self.tmp, hours=0.2, k=0.01)
        cli.raises["post"] = RuntimeError("disk on fire")
        rc = d.run()
        s = self.summary()
        self.assertEqual(d.node.stops, 1)
        self.assertGreater(s["driver_errors"], 0)
        self.assertEqual(s["reason"], "completed", "a few errors are not a reason to stop")
        self.assertEqual(rc, 0)

    def test_twenty_failures_of_the_same_step_in_a_row_stop_the_run_normally(self):
        d, cli, c = driver(self.tmp, hours=1.0, k=0.01)
        cli.raises["unread"] = RuntimeError("boom")
        d.cfg = soak.Cfg(0.01)
        d.run()
        s = self.summary()
        self.assertIn("raised 20 times in a row", s["reason"])
        self.assertTrue(s["stopped_early"])
        self.assertEqual(d.node.stops, 1)

    def test_an_error_between_good_calls_of_the_same_step_does_not_accumulate(self):
        d, cli, c = driver(self.tmp, hours=1.0, k=0.01)
        n = {"i": 0}

        def flaky(args):
            n["i"] += 1
            if n["i"] % 3 == 0:
                raise RuntimeError("sometimes")
            return 0, "", ""
        cli.outputs["unread"] = flaky
        d.run()
        self.assertEqual(self.summary()["reason"], "completed")

    def test_the_failure_count_of_a_step_resets_on_success_and_stops_at_exactly_twenty(self):
        for pattern, expect in (([1] * 19 + [0] + [1] * 19 + [0] * 60, "completed"), ([1] * 20 + [0] * 80, "raised 20 times in a row"), ([1] * 19 + [0] * 80, "completed")):
            self.setUp()
            d, cli, c = driver(self.tmp, hours=2.0, k=0.01)
            seq = iter(pattern + [0] * 500)

            def step(args, seq=seq):
                if next(seq):
                    raise RuntimeError("fail")
                return 0, "", ""
            cli.outputs["unread"] = step
            d.run()
            self.assertIn(expect, self.summary()["reason"], (pattern[:3], self.summary()["reason"]))

    def test_a_stop_condition_found_by_the_checks_ends_the_run_with_that_reason(self):
        import random
        d, cli, c = driver(self.tmp, hours=1.0, k=0.01)
        rng = random.Random(1)
        mk = lambda i, n: f"[{i:08x}] sansa (post): {soak.make_text('sansa', n, c(), rng)!r}\n"
        cli.unread = mk(1, 5) + mk(2, 5)                   # the same post number under two ids
        d.run()
        s = self.summary()
        self.assertIn("twice", s["reason"])
        self.assertEqual((s["stopped_early"], d.node.stops), (True, 1))

    def test_an_exception_outside_every_guard_still_stops_the_node_and_writes_the_summary(self):
        d, cli, c = driver(self.tmp)
        d._loop = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
        rc = d.run()
        s = self.summary()
        self.assertEqual((rc, s["reason"], d.node.stops), (1, "driver crashed: KeyboardInterrupt", 1))

    def test_a_hanging_verify_or_export_at_the_end_cannot_skip_the_node_stop(self):
        d, cli, c = driver(self.tmp)
        cli.raises["verify"] = RuntimeError("x")
        cli.raises["export"] = RuntimeError("y")
        rc = d.finish(None)
        self.assertEqual((d.node.stops, rc), (1, 1))
        self.assertTrue((self.tmp / "out" / "summary.json").exists())

    def test_sigterm_ends_the_run_through_finish(self):
        import signal
        d, cli, c = driver(self.tmp, hours=1.0, k=0.01)
        old = soak.install_signal_handlers(d)
        n = {"i": 0}
        real_sleep = c.sleep

        def sleep(sec):
            n["i"] += 1
            if n["i"] == 3:
                signal.raise_signal(signal.SIGTERM)
            real_sleep(sec)
        d.sleep = sleep
        try:
            d.run()
        finally:
            for sg, h in old.items():
                signal.signal(sg, h)
        s = self.summary()
        self.assertEqual((s["reason"], d.node.stops), ("signal SIGTERM", 1))
        self.assertTrue(s["stopped_early"])

    def test_stop_command_signals_only_a_real_soak_driver(self):
        import subprocess
        out = self.tmp / "out"
        out.mkdir()
        fake = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "/x/tools/soak.py"])
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            (out / "driver.pid").write_text(str(other.pid))
            self.assertEqual(soak.stop_running(out), 1)
            self.assertIsNone(other.poll(), "a process that is not a soak driver is left alone")
            (out / "driver.pid").write_text(str(fake.pid))
            self.assertEqual(soak.stop_running(out), 0)
            self.assertIsNotNone(__import__("time").sleep(0.5) or fake.poll())
            (out / "driver.pid").write_text("not a pid")
            self.assertEqual(soak.stop_running(out), 1)
            self.assertEqual(soak.stop_running(self.tmp / "nowhere"), 1)
        finally:
            for p in (fake, other):
                p.kill()
                p.wait()

    def test_a_real_sigterm_to_a_driver_process_ends_with_a_summary_and_a_stopped_node(self):
        """The signal path as an operator uses it (`--stop`): a separate process, real clock, SIGTERM from outside."""
        import subprocess
        import time as _t
        out = self.tmp / "out"
        marker = self.tmp / "node_stopped"
        harness = f"""
import sys, types
from pathlib import Path
sys.path.insert(0, {str(ROOT / "tools")!r})
import soak
class Cli:
    home, tree, hangs = Path({str(self.tmp / "home")!r}), Path("."), 0
    def run(self, *a, timeout=0): return 0, "", ""
    def spawn(self, *a): raise SystemExit("no spawn")
class Node:
    log, starts, proc, pid = "/nonexistent", 0, None, None
    def start(self): self.starts += 1
    def stop(self, *a, **k): Path({str(marker)!r}).write_text("stopped")
    def alive(self): return True
    def tor_pid(self): return None
    def kill_tor(self): return None
    def running_elsewhere(self): return False
a = types.SimpleNamespace(side="arya", peer_id="p"*32, thread="a"*32, out={str(out)!r}, hours=1.0, seed="1", preflight=False)
d = soak.Driver(a, Cli(), Node(), soak.Cfg(0.01))
soak.install_signal_handlers(d)
sys.exit(d.run())
"""
        proc = subprocess.Popen([sys.executable, "-c", harness, "/x/soak.py"])
        try:
            for _ in range(100):
                if (out / "driver.pid").exists():
                    break
                _t.sleep(0.1)
            _t.sleep(2)
            os.kill(proc.pid, __import__("signal").SIGTERM)
            rc = proc.wait(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
        s = json.loads((out / "summary.json").read_text())
        self.assertEqual(s["reason"], "signal SIGTERM")
        self.assertEqual(marker.read_text(), "stopped")
        self.assertEqual(rc, 1)

    def test_the_driver_writes_its_pid_file(self):
        d, cli, c = driver(self.tmp)
        d._loop()
        self.assertEqual((self.tmp / "out" / "driver.pid").read_text(), str(os.getpid()))


class FailedPosts(unittest.TestCase):
    """r33b F2: a failed post must not leave a hole the PEER would report as an event gap."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "home").mkdir()

    def numbers(self, cli):
        import re
        return [int(re.match(r"soak arya #(\d+) ", x[2]).group(1)) for x in cli.calls if x[0] == "post"]

    def test_a_refused_post_gives_its_number_back(self):
        d, cli, c = driver(self.tmp)
        cli.outputs["post"] = (1, "")
        for _ in range(3):
            d.do_post()
            c.t += 600
        cli.outputs["post"] = (0, "accepted")
        d.do_post()
        self.assertEqual(self.numbers(cli), [1, 1, 1, 1], "the same number is reused until a post is accepted")
        self.assertEqual(d.sent["post"], 1)
        self.assertEqual([x["rc"] for x in d.post_failed], [1, 1, 1])
        self.assertEqual(d.pending_skips, [])

    def test_a_timed_out_post_is_kept_and_announced_as_skip_in_the_next_one(self):
        d, cli, c = driver(self.tmp)
        cli.outputs["post"] = (124, "")
        d.do_post()
        cli.outputs["post"] = (0, "accepted")
        c.t += 600
        d.do_post()
        self.assertEqual(self.numbers(cli), [1, 2])
        self.assertIn("skip=1 ", cli.calls[1][2])
        self.assertEqual(d.post_unknown, [1])
        self.assertEqual(d.pending_skips, [], "announced in an accepted post")
        c.t += 600
        d.do_post()
        self.assertNotIn("skip=", cli.calls[2][2])

    def test_failed_posts_are_listed_in_the_summary(self):
        d, cli, c = driver(self.tmp)
        cli.outputs["post"] = (1, "")
        d.do_post()
        d.finish(None)
        self.assertEqual(json.loads((self.tmp / "out" / "summary.json").read_text())["post_failed"], [{"n": 1, "rc": 1}])

    def test_skips_stay_pending_until_an_accepted_post_carries_them(self):
        d, cli, c = driver(self.tmp)
        cli.outputs["post"] = (124, "")
        d.do_post(); c.t += 600
        cli.outputs["post"] = (1, "")
        d.do_post(); c.t += 600
        self.assertEqual(d.pending_skips, [1])
        cli.outputs["post"] = (0, "")
        d.do_post()
        self.assertIn("skip=1 ", cli.calls[-1][2])

    def test_the_peer_does_not_count_announced_skips_as_gaps(self):
        import random
        d, cli, c = driver(self.tmp)
        rng = random.Random(3)
        mk = lambda n, **kw: f"[{n:08x}] sansa (post): {soak.make_text('sansa', n, c(), rng, **kw)!r}\n"
        cli.unread = mk(1) + mk(3, skips=[2])
        d.poll()
        c.t += d.cfg.gap_seconds + 1
        self.assertEqual(d.peer_skipped, {2})
        self.assertEqual(soak.find_gaps(d.peer_ns, c(), d.cfg.gap_seconds, d.peer_skipped), [])
        self.assertEqual(soak.find_gaps(d.peer_ns, c(), d.cfg.gap_seconds), [2], "without the announcement it would be a gap")
        self.assertIsNone(d._check())

    def test_skip_lists_are_capped_and_strictly_numeric(self):
        import random
        t = soak.make_text("arya", 99, 1.0, random.Random(1), skips=list(range(1, 40)))
        g = soak.classify(t, "sansa")[1]
        self.assertEqual(len(g[3].split(",")), 20)
        for bad in ("skip=1,2,x ", "skip=1;rm ", "skip= "):
            kind, g = soak.classify(f"soak arya #5 ts=1.0 {bad}SOAKMARK-0123456789abcdef", "sansa")
            self.assertTrue(kind is None or g[3] is None, bad)


class Preflight(unittest.TestCase):
    """r33b F3."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "home").mkdir()

    def make(self, **over):
        d, cli, c = driver(self.tmp, preflight=True)
        cli.outputs.update(GOOD_PREFLIGHT)
        cli.outputs.update(over)
        return d, cli

    def test_a_good_home_passes_and_the_first_wait_is_done_before_the_loop(self):
        d, cli = self.make()
        self.assertEqual(d.preflight(), [])
        self.assertIn(("wait", "--max", "1"), cli.calls)

    def test_each_problem_is_reported(self):
        for over, text in (({"list": (0, "")}, "not in `list`"), ({"list": (1, "")}, "not in `list`"),
                           ({"envelope status": (0, "'x': ENCRYPTED;\n  aaaaaaaa  epoch 0  key: MISSING\n")}, "VERIFIED key"),
                           ({"envelope status": (0, "x\n  aaaaaaaa  e  key: verified\n  bbbbbbbb  removal  key: UNVERIFIED\n")}, "VERIFIED key"),
                           ({"envelope status": (0, "no key lines at all\n")}, "VERIFIED key"), ({"envelope status": (1, "")}, "VERIFIED key"),
                           ({"wait": (1, "")}, "`wait` failed")):
            d, cli = self.make(**over)
            self.assertTrue(any(text in p for p in d.preflight()), (over, d.preflight()))
        d, cli = self.make()
        d.node.elsewhere = True
        self.assertTrue(any("already running" in p for p in d.preflight()))

    def test_a_failed_preflight_never_starts_the_node_and_still_writes_a_summary(self):
        d, cli = self.make(**{"envelope status": (0, "  aaaaaaaa  e  key: MISSING\n")})
        rc = d.run()
        s = json.loads((self.tmp / "out" / "summary.json").read_text())
        self.assertEqual((rc, d.node.starts), (1, 0))
        self.assertTrue(s["reason"].startswith("preflight failed"), s["reason"])

    def test_no_preflight_when_not_asked(self):
        d, cli, c = driver(self.tmp, preflight=False)
        d._loop()
        self.assertNotIn("envelope", [x[0] for x in cli.calls])


class FaultVerdicts(unittest.TestCase):
    """r33b (i): the follow-ups and a verdict end up in the summary, not only in events.log."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "home").mkdir()

    def follow(self, alive, tor):
        d, cli, c = driver(self.tmp)
        d.do_fault("torkill")
        d.node.up, d.node.tor = alive, tor
        for sec in (120, 300, 600):
            c.t += sec
            d.supervise()
            if not alive:
                d.node.up = False
        return d.fault_notes[0]

    def test_torkill_verdicts(self):
        r = self.follow(True, 777)
        self.assertEqual(r["verdict"], "node restarted its tor")
        self.assertFalse(r["node_exited"])
        self.assertEqual([f["after_s"] for f in r["followups"]], [120, 300, 600])
        self.assertIn("FINDING", self.follow(True, None)["verdict"])
        r = self.follow(False, None)
        self.assertEqual(r["verdict"], "node exited; the driver restarted it")
        self.assertTrue(r["node_exited"])

    def test_node_that_exits_and_is_restarted_by_the_driver_is_not_reported_as_restarting_its_tor(self):
        """S2: by the follow-up time the driver's restart made the node alive with a tor again; only node_deaths tells the truth."""
        d, cli, c = driver(self.tmp)
        d.do_fault("torkill")
        d.node.up = False                      # the node exits because its tor died
        for sec in (120, 300, 600):
            c.t += sec
            d.supervise()                      # the driver restarts it (FakeNode.start brings it up with a tor)
        r = d.fault_notes[0]
        self.assertTrue(d.node.alive() and d.node.tor_pid())
        self.assertEqual(r["verdict"], "node exited; the driver restarted it")
        self.assertEqual(d.node_deaths, 1)

    def test_a_second_torkill_starts_a_fresh_followup_list(self):
        d, cli, c = driver(self.tmp)
        for _ in range(2):
            d.do_fault("torkill")
            for sec in (120, 300, 600):
                c.t += sec
                d.supervise()
        self.assertEqual([len(f["followups"]) for f in d.fault_notes], [3, 3])

    def test_term_and_kill9_record_the_verify_after_the_restart(self):
        for kind in ("term", "kill9"):
            d, cli, c = driver(self.tmp)
            d.do_fault(kind)
            c.t += d.cfg.fault_down + 1
            d.supervise()
            self.assertEqual(d.fault_notes[0]["verdict"], "restarted by the driver; verify clean", kind)
            d2, cli2, c2 = driver(self.tmp)
            cli2.outputs["verify"] = (1, "problems")
            d2.do_fault(kind)
            c2.t += d2.cfg.fault_down + 1
            d2.supervise()
            self.assertIn("FINDING", d2.fault_notes[0]["verdict"])


class Processes(unittest.TestCase):
    def test_a_hung_cli_call_is_killed_counted_and_the_driver_carries_on(self):
        class Slow(soak.Cli):
            def argv(self, *args):
                return [sys.executable, "-c", "import time; time.sleep(30)"]
        cli = Slow(ROOT, Path("/tmp"))
        t0 = __import__("time").time()
        self.assertEqual(cli.run("anything", timeout=0.5), (124, "", "timeout"))
        self.assertLess(__import__("time").time() - t0, 5)
        self.assertEqual(cli.hangs, 1)

    def test_marker_scan_finds_real_files_and_never_follows_a_symlink(self):
        tmp = Path(tempfile.mkdtemp())
        outside = tmp / "outside"
        outside.mkdir()
        (outside / "leak.txt").write_bytes(b"x" + soak.MARK.encode() + b"1")
        home = tmp / "home"
        (home / "sub").mkdir(parents=True)
        (home / "sub" / "clean.bin").write_bytes(os.urandom(1000))
        os.symlink(outside, home / "link")
        self.assertEqual(soak.marker_scan([home]), [], "a symlinked directory is not followed")
        (home / "sub" / "bad.bin").write_bytes(b"\x00\x01" + soak.MARK.encode() + b"\xff")
        self.assertEqual([Path(p).name for p in soak.marker_scan([home])], ["bad.bin"], "binary files are searched")

    def test_proc_stats_and_dir_bytes_on_this_process(self):
        st = soak.proc_stats(os.getpid())
        self.assertTrue(st["rss_kb"] > 0 and st["threads"] >= 1 and st["fds"] >= 3, st)
        self.assertEqual(soak.proc_stats(2 ** 22 + 12345), {})
        tmp = Path(tempfile.mkdtemp())
        (tmp / "a").write_bytes(b"x" * 100)
        (tmp / "d").mkdir()
        (tmp / "d" / "b").write_bytes(b"y" * 50)
        self.assertEqual(soak.dir_bytes(tmp), 150)


class SelftestEndToEnd(unittest.TestCase):
    def test_a_real_compressed_run_passes_every_end_of_run_check(self):
        """Two real drivers, the real CLI, real encrypted thread, in-process nodes (no Tor): posts, asks, blobs, term/kill9 restarts, marker scan, compare."""
        import soak_selftest
        self.assertEqual(soak_selftest.run(2.0), 0)


if __name__ == "__main__":
    unittest.main()
