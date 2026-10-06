"""P2: `sigilnet watch` (watch.py): one line per inbox line, cursors, burst, reminder."""
import contextlib
import io
import os
import random
import tempfile
import unittest
from pathlib import Path

from sigilnet import cli, cursors
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.home import open_mirror
from sigilnet.inboxlog import GUEST_GAP, InboxLog
from sigilnet.keys import Identity
from sigilnet.watch import Watcher


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write(str(e.code) if not isinstance(e.code, int) else "")
    return rc, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.home = Path(os.path.realpath(tempfile.mkdtemp())) / "home"
        base = cli._free_range(random.randint(20000, 55000), 128, ["127.0.0.1"])
        rc, out, err = run_cli("--home", str(self.home), "init", "arya", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", str(base))
        self.assertEqual(rc, 0, err)
        self.me = Identity.load(self.home / "identity.json")
        self.other = Identity.generate("sansa")
        g = make_genesis(self.me, "t", [(self.other, "member")], visibility="private")
        self.tid = event_id(g)
        self.m = open_mirror(self.home, self.me.id)
        self.m.ingest(g)
        self.clock = Clock()
        self.out = []
        self.sleeps = []

    def post(self, who=None, n=1, text="hi"):
        for _ in range(n):
            ev = Writer(who or self.other, self.m.threads[self.tid]).post(text)
            self.assertTrue(self.m.ingest(ev).ok)

    def watcher(self, consumer="watch", **kw):
        kw.setdefault("clock", self.clock)
        kw.setdefault("sleep", lambda s: (self.sleeps.append(s), setattr(self.clock, "t", self.clock.t + s)))
        return Watcher(self.home, consumer, out=self.out.append, **kw)

    @property
    def t8(self):
        return self.tid[:8]


class Lines(Base):
    def test_a_fresh_consumer_starts_at_the_head_counts_the_unread_and_saves_the_cursor(self):
        self.post(n=2)
        w = self.watcher()
        w.run(seconds=0)
        self.assertEqual(self.out, ["WATCH started: 2 unannounced"])
        self.assertEqual(cursors.load(self.home, "watch")["seq"], 2)                     # a restart does not forget it (and does not announce old lines)
        self.out.clear()
        w2 = self.watcher()
        w2.run(seconds=0)
        self.assertEqual(self.out, ["WATCH started: 0 unannounced"])

    def test_each_new_line_is_one_output_line_and_own_posts_make_none(self):
        w = self.watcher()
        w.run(seconds=0)
        self.out.clear()
        self.post()
        self.post(self.me)
        self.assertEqual(w.step(), [f"INBOX 1 {self.t8}: run sigilnet unread {self.t8}"])
        self.assertEqual(self.out, [f"INBOX 1 {self.t8}: run sigilnet unread {self.t8}"])
        self.assertEqual(w.step(), [])

    def test_the_cursor_is_written_after_the_print(self):
        w = self.watcher()
        w.run(seconds=0)
        self.post()
        order = []
        w.out = lambda l: order.append(("print", cursors.load(self.home, "watch")["seq"]))
        w.step()
        self.assertEqual(order, [("print", 0)])                                          # at print time the cursor had not moved yet
        self.assertEqual(cursors.load(self.home, "watch")["seq"], 1)

    def test_a_kill_between_print_and_save_reannounces_and_never_loses(self):
        w = self.watcher()
        w.run(seconds=0)
        self.post()
        real = cursors.save
        cursors.save = lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt())
        try:
            with self.assertRaises(KeyboardInterrupt):
                w.step()
        finally:
            cursors.save = real
        self.out.clear()
        w2 = self.watcher()
        w2.run(seconds=0)
        self.assertEqual(self.out[0], "WATCH started: 1 unannounced")
        w2.step()
        self.assertEqual(self.out[-1], f"INBOX 1 {self.t8}: run sigilnet unread {self.t8}")

    def test_restart_with_a_cursor_announces_the_backlog(self):
        w = self.watcher()
        w.run(seconds=0)
        self.post(n=3)
        self.out.clear()
        w2 = self.watcher()
        w2.run(seconds=0.3)
        self.assertEqual(self.out[0], "WATCH started: 3 unannounced")
        self.assertEqual([l.split()[1] for l in self.out[1:4]], ["1", "2", "3"])

    def test_two_consumers_are_independent(self):
        a, b = self.watcher("a"), self.watcher("b")
        a.run(seconds=0)
        b.run(seconds=0)
        self.post()
        self.assertEqual(len(a.step()), 1)
        self.assertEqual(len(b.step()), 1)
        self.assertEqual(a.step(), [])
        self.post()
        self.assertEqual(len(a.step()), 1)
        self.assertEqual(cursors.load(self.home, "b")["seq"], 1)

    def test_a_damaged_cursor_starts_from_zero(self):
        self.post(n=2)
        d = self.home / "cursors"
        d.mkdir(mode=0o700)
        (d / "watch.json").write_text("{{{")
        w = self.watcher()
        w.run(seconds=0)
        self.assertEqual(self.out[0], "WATCH started: 2 unannounced")
        w.step()
        self.assertEqual(len([l for l in self.out if l.startswith("INBOX")]), 2)

    def test_a_new_generation_announces_everything_again(self):
        w = self.watcher()
        w.run(seconds=0)
        self.post(n=2)
        w.step()
        self.m.rebuild_inbox()
        self.out.clear()
        lines = w.step()
        self.assertEqual(len(lines), 2)                                                   # the rebuilt file's lines, from 0
        self.assertEqual(cursors.load(self.home, "watch")["gen"], InboxLog(self.home).gen)

    def test_the_command_a_line_tells_you_to_run_really_runs(self):
        w = self.watcher()
        w.run(seconds=0)
        self.post()
        line = w.step()[0]
        cmd = line.split("run ", 1)[1].split()                                           # ['sigilnet', 'unread', '<t8>']
        self.assertEqual(cmd[:2], ["sigilnet", "unread"])
        rc, out, err = run_cli("--home", str(self.home), *cmd[1:])
        self.assertEqual(rc, 0, err)
        self.assertIn("(post)", out)
        rc, out, err = run_cli("--home", str(self.home), "list")                           # what burst and REMINDER lines tell you to run
        self.assertEqual(rc, 0, err)
        self.assertIn("unread=1", out)

    def test_a_guest_line_text(self):
        w = self.watcher()
        w.run(seconds=0)
        self.m.note_guest(self.tid)
        self.assertEqual(w.step(), [f"INBOX 1 {self.t8} (guest request): run 'sigilnet requests list {self.t8}'"])

    def test_the_watcher_never_writes_the_inbox(self):
        self.post()
        before = (self.home / "inbox.jsonl").read_bytes()
        w = self.watcher()
        w.run(seconds=1)
        self.assertEqual((self.home / "inbox.jsonl").read_bytes(), before)

    def test_nothing_in_the_output_names_an_author_a_kind_or_text(self):
        self.post(text="top secret text")
        w = self.watcher()
        w.run(seconds=0)
        w2 = self.watcher("x")
        cursors.save(self.home, "x", InboxLog(self.home).gen, 0)
        w2.step()
        text = "\n".join(self.out)
        for needle in ("secret", self.other.id[:8], "sansa", "post"):
            self.assertNotIn(needle, text.replace("run sigilnet unread", ""))

    def test_poll_is_the_sleep_between_steps(self):
        w = self.watcher(poll=0.25)
        w.run(seconds=1.0)
        self.assertEqual(set(self.sleeps), {0.25})
        self.assertEqual(len(self.sleeps), 4)

    def test_a_bad_consumer_name_is_refused(self):
        with self.assertRaises(ValueError):
            Watcher(self.home, "../x")


class Skip(Base):
    def test_an_unchanged_file_is_not_read_again(self):
        w = self.watcher()
        w.run(seconds=0)
        self.post()
        w.step()
        calls = []
        real = w.log.read_from
        w.log.read_from = lambda *a, **k: (calls.append(1), real(*a, **k))[1]
        for _ in range(5):
            w.step()
        self.assertEqual(calls, [])
        self.post()
        self.assertEqual(len(w.step()), 1)                                              # a change is seen at once
        self.assertEqual(len(calls), 1)

    def test_a_failed_print_is_retried_by_the_same_watcher_object(self):
        w = self.watcher()
        w.run(seconds=0)
        self.post()
        real = w.out

        def boom(l):
            raise BrokenPipeError("the monitor went away")
        w.out = boom
        with self.assertRaises(BrokenPipeError):
            w.step()
        self.assertEqual(cursors.load(self.home, "watch")["seq"], 0)                    # not saved
        w.out = real
        self.assertEqual(w.step(), [f"INBOX 1 {self.t8}: run sigilnet unread {self.t8}"])        # announced now, by the same object

    def test_the_reminder_still_fires_on_an_unchanged_file(self):
        w = self.watcher(remind=300.0)
        w.run(seconds=0)
        self.post()
        w.step()
        self.clock.t += 301
        self.assertEqual(len(w.step()), 1)


class Burst(Base):
    def lines_at(self, ts):
        log = InboxLog(self.home, clock=self.clock)
        for t in ts:
            self.clock.t = t
            log.append(self.tid)

    def test_more_than_burst_n_lines_inside_burst_s_collapse_into_one_line(self):
        w = self.watcher()
        w.run(seconds=0)
        self.lines_at([1_800_000_000.0 + i * 0.05 for i in range(21)])
        self.assertEqual(w.step(), ["INBOX x21 (burst): run sigilnet list"])
        self.assertEqual(cursors.load(self.home, "watch")["seq"], 21)

    def test_exactly_burst_n_lines_are_individual(self):
        w = self.watcher()
        w.run(seconds=0)
        self.lines_at([1_800_000_000.0 + i * 0.05 for i in range(20)])
        self.assertEqual(len(w.step()), 20)

    def test_one_line_a_second_is_never_a_burst(self):
        w = self.watcher()
        w.run(seconds=0)
        self.lines_at([1_800_000_000.0 + i for i in range(30)])
        lines = w.step()
        self.assertEqual(len(lines), 30)
        self.assertFalse(any("burst" in l for l in lines))

    def test_a_backlog_spread_over_more_than_burst_s_is_individual(self):
        w = self.watcher()
        w.run(seconds=0)
        self.lines_at([1_800_000_000.0 + i * 1.0 for i in range(25)])               # 25 lines over 24 s: no 10 s window holds more than 11
        self.assertEqual(len(w.step()), 25)

    def test_the_constants_are_parameters(self):
        w = self.watcher(burst_n=2, burst_s=1.0)
        w.run(seconds=0)
        self.lines_at([1_800_000_000.0 + i * 0.1 for i in range(3)])
        self.assertEqual(w.step(), ["INBOX x3 (burst): run sigilnet list"])


class Reminder(Base):
    def test_reminder_after_remind_seconds_while_announced_events_are_unread(self):
        w = self.watcher(remind=300.0)
        w.run(seconds=0)
        self.post(n=2)
        w.step()
        self.out.clear()
        self.clock.t += 299
        self.assertEqual(w.step(), [])
        self.clock.t += 2
        self.assertEqual(w.step(), ["REMINDER: 2 unread in 1 thread(s): run sigilnet list"])
        self.assertEqual(w.step(), [])                                                    # and again only after another 300 s

    def test_no_reminder_once_everything_is_read(self):
        w = self.watcher(remind=300.0)
        w.run(seconds=0)
        self.post()
        w.step()
        self.m.mark_read(self.tid)
        self.clock.t += 400
        self.assertEqual(w.step(), [])

    def test_no_reminder_for_events_that_were_never_announced(self):
        self.post()
        w = self.watcher(remind=10.0)
        w.run(seconds=0)                                                                  # fresh consumer: the unread count is in the start line only
        self.out.clear()
        self.clock.t += 100
        self.assertEqual(w.step(), [])


class Cli(Base):
    def test_watch_command_prints_lines_and_exits_at_the_deadline(self):
        self.post()
        rc, out, err = run_cli("--home", str(self.home), "watch", "--seconds", "0.5", "--consumer", "c1")
        self.assertEqual(rc, 0, err)
        self.assertTrue(out.startswith("WATCH started: 1 unannounced"))

    def test_a_home_without_identity_says_so_not_a_traceback(self):
        bare = Path(tempfile.mkdtemp())
        rc, out, err = run_cli("--home", str(bare), "watch", "--seconds", "0.1")
        self.assertNotEqual(rc, 0)
        self.assertIn("no identity yet", err)

    def test_a_binary_cursor_is_started_from_zero_by_the_command(self):
        self.post()
        d = self.home / "cursors"
        d.mkdir(mode=0o700)
        (d / "watch.json").write_bytes(b"\x00\xff\xfe garbage")
        rc, out, err = run_cli("--home", str(self.home), "watch", "--seconds", "0.5")
        self.assertEqual(rc, 0, err)
        self.assertIn("INBOX 1", out)

    def test_a_bad_consumer_is_an_error_line(self):
        rc, out, err = run_cli("--home", str(self.home), "watch", "--seconds", "0.1", "--consumer", "../x")
        self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
