"""Watcher (section 7, 14): one stdout line per NEW inbox line; the cursor belongs to the consumer and is saved AFTER the line is printed."""
import json
import os
import signal
import stat
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

from sigilnet import inboxlog
from sigilnet.inboxlog import InboxLog
from sigilnet.watch import Watcher

from .h import Clock, Env, entries, raw_gen

REPO = str(Path(__file__).resolve().parents[2])


def mk(env, consumer="watch", clk=None, **kw):
    clk = clk or Clock()
    out = []
    w = Watcher(env.home, consumer, out=out.append, clock=clk, sleep=clk.sleep, **kw)
    return w, out, clk


def cursor(env, consumer="watch"):
    return json.loads((env.home / "cursors" / f"{consumer}.json").read_text())


def seed(env, consumer="watch"):
    """A consumer that already announced everything up to the current head (the cursor file as the spec describes it)."""
    d = env.home / "cursors"
    d.mkdir(mode=0o700, exist_ok=True)
    (d / f"{consumer}.json").write_text(json.dumps({"gen": InboxLog(env.home).gen, "seq": InboxLog(env.home).head()}))
    (d / f"{consumer}.json").chmod(0o600)


def inbox_line(seq, tid, guest=False):
    return f"INBOX {seq} {tid[:8]}" + (" (guest request): run 'sigilnet requests list " + tid[:8] + "'" if guest else f": run sigilnet unread {tid[:8]}")


class Start(unittest.TestCase):
    def test_a_fresh_consumer_starts_at_the_head_and_reports_the_unread_count(self):
        env = Env("public")
        for k in range(3):
            env.post("sansa", f"old {k}")
        w, out, clk = mk(env)
        self.assertEqual(w.run(seconds=0.5), 0)
        self.assertEqual(out, ["WATCH started: 3 unannounced"])                           # three unread events, none of them announced as INBOX lines
        env.post("sansa", "new")
        w.step()
        self.assertEqual(out[1:], [inbox_line(4, env.tid)])

    def test_an_existing_cursor_announces_the_backlog_in_order_after_the_start_line(self):
        env = Env("public")
        seed(env)
        for k in range(3):
            env.post("sansa", f"p{k}")
        w, out, clk = mk(env)
        w.run(seconds=0.6)
        self.assertEqual(out[0], "WATCH started: 3 unannounced")
        self.assertEqual(out[1:4], [inbox_line(n, env.tid) for n in (1, 2, 3)])
        self.assertEqual(len(out), 4)
        self.assertEqual(cursor(env)["seq"], 3)

    def test_a_cursor_at_the_head_says_zero_and_stays_quiet(self):
        env = Env("public")
        env.post("sansa", "x")
        seed(env)
        w, out, _ = mk(env)
        w.run(seconds=1.0)
        self.assertEqual(out, ["WATCH started: 0 unannounced"])

    def test_the_run_loop_sleeps_by_poll_and_returns_zero_at_the_deadline(self):
        env = Env("public")
        sleeps = []
        clk = Clock()
        out = []
        w = Watcher(env.home, "p", out=out.append, clock=clk, sleep=lambda d: (sleeps.append(d), clk.sleep(d)), poll=0.5)
        self.assertEqual(w.run(seconds=2.0), 0)
        self.assertTrue(sleeps and set(sleeps) == {0.5})
        self.assertLessEqual(len(sleeps), 5)
        self.assertEqual(out[0], "WATCH started: 0 unannounced")


class Lines(unittest.TestCase):
    def test_one_line_per_new_inbox_line_with_the_exact_text(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        env.post("sansa", "a")
        env.post("carol", "b")
        got = w.step()
        self.assertEqual(got, [inbox_line(1, env.tid), inbox_line(2, env.tid)])
        self.assertEqual(out[1:], got)
        self.assertEqual(w.step(), [])                                                    # nothing new: nothing printed

    def test_a_guest_line(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        env.m.note_guest(env.tid)
        self.assertEqual(w.step(), [inbox_line(1, env.tid, guest=True)])

    def test_the_watcher_never_writes_the_inbox_file(self):
        env = Env("public")
        env.post("sansa", "a")
        before = (env.home / "inbox.jsonl").read_bytes()
        ino = (env.home / "inbox.jsonl").stat().st_ino
        w, out, clk = mk(env, "x")
        w.run(seconds=1.0)
        w.step()
        self.assertEqual((env.home / "inbox.jsonl").read_bytes(), before)
        self.assertEqual((env.home / "inbox.jsonl").stat().st_ino, ino)

    def test_works_with_no_node_anywhere(self):
        """The file is the truth: a CLI-style second handle posts, the watcher (a third) hears it. No node, no daemon, no socket."""
        env = Env("public")
        cli = env.open()
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        env.post("sansa", "from the cli", m=cli)
        self.assertEqual(w.step(), [inbox_line(1, env.tid)])


class Cursor(unittest.TestCase):
    def test_cursor_file_shape_and_modes(self):
        env = Env("public")
        w, out, clk = mk(env, "alpha")
        w.run(seconds=0.3)
        env.post("sansa", "a")
        w.step()
        p = env.home / "cursors" / "alpha.json"
        self.assertEqual(json.loads(p.read_text()), {"gen": raw_gen(env.home), "seq": 1})
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(p.parent.stat().st_mode), 0o700)
        self.assertEqual([x.name for x in p.parent.iterdir()], ["alpha.json"])           # no temp file left behind

    def test_the_cursor_is_saved_after_the_line_is_printed(self):
        env = Env("public")
        seed(env)
        env.post("sansa", "a")
        seen = []
        clk = Clock()

        def out(line):
            p = env.home / "cursors" / "watch.json"
            seen.append((line, json.loads(p.read_text())["seq"] if p.exists() else None))

        w = Watcher(env.home, "watch", out=out, clock=clk, sleep=clk.sleep)
        w.step()
        self.assertEqual(len(seen), 1)
        self.assertIn(seen[0][1], (None, 0), "the cursor already said 'seen' while the line was being printed")
        self.assertEqual(cursor(env)["seq"], 1)

    def test_a_failure_while_printing_re_announces_never_loses(self):
        env = Env("public")
        seed(env)
        env.post("sansa", "a")
        clk = Clock()

        def broken(line):
            raise BrokenPipeError("the Monitor tool went away")

        w = Watcher(env.home, "watch", out=broken, clock=clk, sleep=clk.sleep)
        with self.assertRaises(BrokenPipeError):
            w.step()
        w2, out2, _ = mk(env)
        self.assertEqual(w2.step(), [inbox_line(1, env.tid)])
        self.assertEqual(mk(env)[0].step(), [])                                           # and only once more

    def test_kill_minus_9_after_printing_re_announces_never_loses(self):
        env = Env("public")
        seed(env)
        env.post("sansa", "a")
        env.post("sansa", "b")
        script = textwrap.dedent(f"""
            import os, sys
            sys.path.insert(0, {REPO!r})
            from pathlib import Path
            from sigilnet.watch import Watcher
            def out(l):
                print(l, flush=True)
                if l.startswith("INBOX"):
                    os.kill(os.getpid(), 9)            # killed right after the first INBOX line reached the pipe, before anything else
            Watcher(Path({str(env.home)!r}), "watch", out=out).run(seconds=5)
        """)
        r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, -signal.SIGKILL)
        self.assertIn(inbox_line(1, env.tid), r.stdout)
        w2, out2, _ = mk(env)
        got = w2.step()
        self.assertEqual(got[-1], inbox_line(2, env.tid))                                   # nothing lost
        self.assertLessEqual(len(got), 2)                                                    # the first one may come again (at-least-once), never a third
        self.assertEqual(mk(env)[0].step(), [])

    @unittest.skipIf(os.environ.get("ADV12_SKIP_OPEN_FINDINGS") == "1", "open finding P2-5: after a failed print the SAME watcher object does not retry")
    def test_a_failed_print_is_retried_by_the_same_watcher_object(self):
        env = Env("public")
        seed(env)
        env.post("sansa", "a")
        calls = []

        def flaky(line):
            calls.append(line)
            if len(calls) == 1:
                raise BrokenPipeError("the Monitor tool went away")

        clk = Clock()
        w = Watcher(env.home, "watch", out=flaky, clock=clk, sleep=clk.sleep)
        with self.assertRaises(BrokenPipeError):
            w.step()
        self.assertEqual(w.step(), [inbox_line(1, env.tid)])                              # the cursor was not saved: the line is announced again, even with the file unchanged
        self.assertEqual(w.step(), [])

    def test_two_consumers_are_independent(self):
        env = Env("public")
        wa, outa, _ = mk(env, "a")
        wb, outb, _ = mk(env, "b")
        wa.run(seconds=0.3)
        wb.run(seconds=0.3)
        env.post("sansa", "x")
        self.assertEqual(wa.step(), [inbox_line(1, env.tid)])
        self.assertEqual(wa.step(), [])
        self.assertEqual(wb.step(), [inbox_line(1, env.tid)])                              # b has not heard it yet
        self.assertEqual({p.name for p in (env.home / "cursors").iterdir()}, {"a.json", "b.json"})

    def test_a_damaged_cursor_means_from_zero(self):
        for junk in (b"\x00 garbage", b"{", b"[]", b'{"gen": 5}', b'{"seq": "x", "gen": "y"}', b""):
            env = Env("public")
            env.post("sansa", "a")
            env.post("sansa", "b")
            (env.home / "cursors").mkdir(mode=0o700)
            (env.home / "cursors" / "watch.json").write_bytes(junk)
            w, out, _ = mk(env)
            got = w.step()
            self.assertEqual(got, [inbox_line(1, env.tid), inbox_line(2, env.tid)], junk)
            self.assertEqual(cursor(env)["seq"], 2)

    @unittest.skipIf(os.environ.get("ADV12_SKIP_OPEN_FINDINGS") == "1", "open finding P2-1: a cursor file that is not valid UTF-8 is a traceback")
    def test_a_cursor_that_is_not_utf8_means_from_zero_not_a_traceback(self):
        env = Env("public")
        env.post("sansa", "a")
        (env.home / "cursors").mkdir(mode=0o700)
        (env.home / "cursors" / "watch.json").write_bytes(b"\x00\xff\xfe garbage")
        w, out, _ = mk(env)
        self.assertEqual(w.step(), [inbox_line(1, env.tid)])

    def test_a_cursor_of_another_generation_means_from_zero(self):
        env = Env("public")
        for k in range(3):
            env.post("sansa", f"p{k}")
        (env.home / "cursors").mkdir(mode=0o700)
        (env.home / "cursors" / "watch.json").write_text(json.dumps({"gen": "f" * 16, "seq": 3}))
        w, out, _ = mk(env)
        self.assertEqual(w.step(), [inbox_line(n, env.tid) for n in (1, 2, 3)])
        self.assertEqual(cursor(env), {"gen": raw_gen(env.home), "seq": 3})

    def test_a_rebuild_while_watching_re_announces_what_is_still_unread(self):
        env = Env("public")
        w, out, _ = mk(env)
        w.run(seconds=0.3)
        for k in range(3):
            env.post("sansa", f"p{k}")
        self.assertEqual(len(w.step()), 3)
        old = raw_gen(env.home)
        env.m.rebuild_inbox()                                                              # seqs restart at 1 in a NEW generation
        self.assertNotEqual(raw_gen(env.home), old)
        got = w.step()
        self.assertEqual(len(got), len(env.unread()))
        self.assertEqual(cursor(env)["gen"], raw_gen(env.home))
        self.assertEqual(w.step(), [])

    def test_a_cursor_ahead_of_the_head_is_quiet_not_a_crash(self):
        env = Env("public")
        env.post("sansa", "a")
        (env.home / "cursors").mkdir(mode=0o700)
        (env.home / "cursors" / "watch.json").write_text(json.dumps({"gen": raw_gen(env.home), "seq": 99}))
        w, out, _ = mk(env)
        self.assertEqual(w.step(), [])


class Burst(unittest.TestCase):
    def _fill(self, env, n, clk, guest=False):
        log = InboxLog(env.home, clock=clk)
        for _ in range(n):
            clk.t += 0.05
            log.append(env.tid, guest=guest)

    def test_more_than_burst_n_lines_in_burst_s_collapse_into_one(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        self._fill(env, 25, Clock(clk.t))
        got = w.step()
        self.assertEqual(got, ["INBOX x25 (burst): run sigilnet list"])
        self.assertEqual(cursor(env)["seq"], 25)
        self.assertEqual(w.step(), [])

    def test_exactly_burst_n_lines_are_not_a_burst(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        self._fill(env, 20, Clock(clk.t))
        self.assertEqual(w.step(), [inbox_line(n, env.tid) for n in range(1, 21)])

    def test_one_more_than_burst_n_is_a_burst(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        self._fill(env, 21, Clock(clk.t))
        self.assertEqual(w.step(), ["INBOX x21 (burst): run sigilnet list"])

    def test_burst_parameters_are_honoured(self):
        env = Env("public")
        w, out, clk = mk(env, burst_n=3)
        w.run(seconds=0.3)
        self._fill(env, 4, Clock(clk.t))
        self.assertEqual(w.step(), ["INBOX x4 (burst): run sigilnet list"])

    def test_a_slow_trickle_is_never_a_burst(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        for k in range(30):
            env.post("sansa", f"p{k}")
            clk.t += 1.0
            self.assertEqual(len(w.step()), 1, k)
        self.assertEqual(len([l for l in out if "burst" in l]), 0)

    def test_after_a_burst_the_next_single_line_is_announced_normally(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        self._fill(env, 30, Clock(clk.t))
        w.step()
        clk.t += 60
        env.post("sansa", "later")
        self.assertEqual(w.step(), [inbox_line(31, env.tid)])


class Reminder(unittest.TestCase):
    def test_reminder_every_remind_seconds_while_announced_events_are_unread(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        env.post("sansa", "a")
        env.post("carol", "b")
        w.step()
        rem = "REMINDER: 2 unread in 1 thread(s): run sigilnet list"
        clk.t += 299
        self.assertNotIn(rem, w.step())
        clk.t += 2
        self.assertIn(rem, w.step())
        clk.t += 50
        self.assertNotIn(rem, w.step())
        clk.t += 260
        self.assertIn(rem, w.step())

    def test_no_reminder_once_everything_is_read(self):
        env = Env("public")
        w, out, clk = mk(env)
        w.run(seconds=0.3)
        env.post("sansa", "a")
        w.step()
        env.m.mark_read(env.tid)
        clk.t += 400
        self.assertEqual([l for l in w.step() if l.startswith("REMINDER")], [])
        clk.t += 400
        self.assertEqual([l for l in w.step() if l.startswith("REMINDER")], [])

    def test_the_remind_parameter_is_honoured(self):
        env = Env("public")
        w, out, clk = mk(env, remind=10.0)
        w.run(seconds=0.3)
        env.post("sansa", "a")
        w.step()
        clk.t += 11
        self.assertTrue(any(l.startswith("REMINDER: 1 unread in 1 thread(s)") for l in w.step()))


if __name__ == "__main__":
    unittest.main()
