"""`sigilnet live`: the human's read-only live view (liveview.py). Peer text is data: nothing a post says may reach the terminal as a control sequence."""
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sigilnet import liveview
from sigilnet.liveview import Renderer, clean, wrap

ROOT = Path(__file__).resolve().parents[2]
ENV = {**os.environ, "TZ": "UTC", "PYTHONPATH": str(ROOT)}
ESC = "\x1b"


def run(home, *args, inp=None):
    p = subprocess.run([sys.executable, "-B", "-m", "sigilnet", "--home", str(home), *args], capture_output=True, text=True, input=inp, cwd=str(ROOT), timeout=120, env=ENV)
    return p.returncode, p.stdout, p.stderr


class Text(unittest.TestCase):
    def test_clean_strips_controls_bidi_and_keeps_newlines(self):
        s = clean(f"a{ESC}[31mred{ESC}[0m\x07b‮c​d e\tf\r\ng\rh\x00i j")
        self.assertNotIn(ESC, s)
        for bad in ("\x07", "‮", "​", " ", "\x00", " ", "\r", "\t"):
            self.assertNotIn(bad, s)
        self.assertEqual(s.count("\n"), 2)
        self.assertIn("    f", s)
        self.assertEqual(clean(None), "")
        self.assertEqual(clean(5), "")

    def test_wrap_keeps_indent_and_blank_lines_and_breaks_long_words(self):
        out = wrap("    code line that is long enough to wrap around the edge\n\nnext", 24)
        self.assertTrue(all(len(l) <= 24 for l in out), out)
        self.assertTrue(out[0].startswith("    code"), out)
        self.assertTrue(all(l.startswith("    ") for l in out[:-2] if l), out)
        self.assertIn("", out)
        self.assertEqual(out[-1], "next")
        self.assertTrue(all(len(l) <= 40 for l in wrap("x" * 500, 40)))
        self.assertEqual(wrap("", 40), [])
        self.assertEqual(wrap("a\n\n\n", 40), ["a"])

    def test_admin_lines(self):
        class T:
            def state(self):
                return {"members": {"a" * 32: {"name": "ann"}}}
            states = {}
        t = T()
        L = liveview._admin_line
        self.assertEqual(L(t, {"kind": "member_add", "body": {"name": "bo\x1bb", "role": "member"}}), "bo b joined as member")
        self.assertEqual(L(t, {"kind": "member_add", "body": {"agent": "a" * 32, "name": "ann", "role": "member"}}), "ann joined as member")
        t.states = {"x": {"members": {"b" * 32: {"name": "ann"}}}}                      # a twin of ann: the join line carries the id prefix
        self.assertEqual(L(t, {"kind": "member_add", "body": {"agent": "b" * 32, "name": "ann", "role": "member"}}), "ann (bbbbbb) joined as member")
        t.states = {}
        self.assertEqual(L(t, {"kind": "member_remove", "body": {"agent": "a" * 32}}), "ann was removed")
        self.assertEqual(L(t, {"kind": "member_remove", "body": {"agent": 5}}), "? was removed")
        self.assertIn("CLOSED", L(t, {"kind": "close", "body": {}}))
        self.assertEqual(L(t, {"kind": "x-foo", "body": {}}), "(x-foo)")

    def test_two_members_with_one_name_never_look_alike(self):
        class T:
            id = "t" * 32
            states = {}
            void_ids = set()
            events = {}

            def state(self):
                return {"members": {"a" * 32: {"name": "alice", "role": "owner"}, "b" * 32: {"name": "alice\u202e", "role": "member"}, "c" * 32: {"name": "carol", "role": "member"}, "d" * 32: {"role": "member"}}, "title": "x", "closed": False}
        t = T()
        self.assertEqual(liveview.name_of(t, "a" * 32), "alice (aaaaaa)")
        self.assertEqual(liveview.name_of(t, "b" * 32), "alice (bbbbbb)")        # (the look-alike is found after cleaning)
        self.assertEqual(liveview.name_of(t, "c" * 32), "carol")
        self.assertEqual(liveview.name_of(t, "d" * 32), "dddddd")
        self.assertEqual(liveview.name_of(t, "e" * 32), "eeeeee")                # not a member
        t.states = {"x": {"members": {"f" * 32: {"name": "carol"}}}}             # a member of another branch counts too
        self.assertEqual(liveview.name_of(t, "c" * 32), "carol (cccccc)")
        banner = Renderer(width=80).banner(None, t)[1]
        self.assertIn("alice (aaaaaa) (owner)", banner)

    def test_a_voided_parent_is_not_quoted(self):
        class T:
            states = {}
            void_ids = {"b" * 32}
            events = {"b" * 32: {"kind": "post", "author": "m" * 32, "body": {"text": "SECRET text beyond a cut"}}, "c" * 32: {"kind": "post", "author": "m" * 32, "body": {"text": "visible"}}}

            def state(self):
                return {"members": {"m" * 32: {"name": "mallory"}}}
        r = Renderer(width=80)
        note = r._reply_note(T(), "b" * 32, 70)
        self.assertNotIn("SECRET", note)
        self.assertIn("voided", note)
        self.assertIn("visible", r._reply_note(T(), "c" * 32, 70))
        self.assertEqual(r._reply_note(T(), "d" * 32, 70), f"in reply to [{'d' * 8}]")

    def test_follow_mode_on_an_empty_mirror_says_it_is_waiting(self):
        c = tempfile.mkdtemp()
        run(c, "id", "init", "carol")
        rc, out, err = run(c, "live", "--seconds", "1", "--poll", "0.2")
        self.assertEqual(rc, 0, err)
        self.assertIn("(no threads yet: waiting)", out)
        self.assertIn("(no matching thread yet: waiting)", run(c, "live", "--seconds", "1", "--poll", "0.2", "abcd")[1])
        rc, out, err = run(c, "live", "--once")
        self.assertEqual((rc, out.strip()), (1, "no threads in this mirror"))

    def test_wide_characters_are_wrapped_by_terminal_columns(self):
        cjk = "\u4f60\u597d" * 40                                                  # 80 characters, 160 columns
        for width in (40, 41, 60):
            out = wrap(cjk, width)
            self.assertTrue(all(liveview.cells(l) <= width for l in out), (width, out))
            self.assertEqual("".join(out), cjk)                                    # (nothing lost, nothing added)
        mixed = wrap("hello " + "\U0001f600" * 30 + " world \u65e5\u672c\u8a9e" * 10, 50)
        self.assertTrue(all(liveview.cells(l) <= 50 for l in mixed), mixed)
        self.assertEqual(liveview.cells("e\u0301"), 1)                              # a combining mark takes no column
        self.assertEqual(liveview.cells("\uff21"), 2)                               # fullwidth A
        self.assertEqual(liveview.cut("\u4f60\u597d\u4e16", 5), "\u4f60\u597d")
        self.assertEqual(liveview.cut("abc", 10), "abc")
        self.assertEqual(wrap("  " + "\u4f60" * 30, 20)[1][:2], "  ")            # indentation kept on continuation rows
        self.assertTrue(all(liveview.cells(l) <= 6 for l in wrap("\u4f60" * 9, 6)))

    def test_ascii_wrapping_is_unchanged(self):
        text = "word " * 40
        out = wrap(text, 30)
        self.assertTrue(all(len(l) <= 30 for l in out), out)
        self.assertEqual(" ".join(out).split(), text.split())
        self.assertEqual(wrap("a   b", 40), ["a   b"])                            # inner runs of spaces stay

    def test_rendered_block_fits_the_width_with_wide_names_and_text(self):
        class T:
            id = "t" * 32
            states = {}
            void_ids = set()
            events = {}

            def state(self):
                return {"members": {"a" * 32: {"name": "\u5c0f\u660e" * 8, "role": "member"}}, "title": "x", "closed": False}
        t = T()
        t.events = {"e" * 32: {"kind": "post", "author": "a" * 32, "ts": 0, "body": {"text": "\u4f60\u597d\u4e16\u754c" * 30, "reply_to": "f" * 32}, "parents": [], "seq": 1}}
        lines = Renderer(width=60).event(None, t, "e" * 32)
        self.assertTrue(all(liveview.cells(l) <= 60 for l in lines), [(liveview.cells(l), l) for l in lines])

    def test_renderer_width_is_clamped(self):
        self.assertEqual(Renderer(width=5).width, liveview.MIN_WIDTH)
        self.assertEqual(Renderer(width=5000).width, liveview.MAX_WIDTH)
        self.assertEqual(Renderer(width=100).width, 100)

    def test_colour_is_ours_not_the_peers(self):
        r = Renderer(width=80, color=True)
        self.assertEqual(r._tagged("[DONE] x"), f"{ESC}[1;32m[DONE]{ESC}[0m x")
        self.assertEqual(r._tagged("plain"), "plain")
        self.assertEqual(Renderer(width=80, color=False)._tagged("[DONE] x"), "[DONE] x")
        self.assertEqual(liveview.author_colour("abc"), liveview.author_colour("abc"))


class Cli(unittest.TestCase):
    def setUp(self):
        self.a, self.b = tempfile.mkdtemp(), tempfile.mkdtemp()
        run(self.a, "id", "init", "alice")
        run(self.b, "id", "init", "bob")
        pub = Path(self.a) / "bob.pub"
        pub.write_text(run(self.b, "id", "show", "--json")[1])
        rc, out, err = run(self.a, "new", "plan the trip", "--plaintext", "--member", f"member={pub}")
        self.tid = out.split("thread ")[1].split()[0]
        self.sync()

    def sync(self):
        run(self.b, "ingest", "-", inp=run(self.a, "export", self.tid)[1])

    def live(self, *args, home=None):
        rc, out, err = run(home or self.b, "live", "--once", "--no-color", "--width", "80", *args)
        self.assertEqual(rc, 0, err)
        return out

    def test_same_name_members_are_told_apart_in_the_view(self):
        c = tempfile.mkdtemp()
        run(c, "id", "init", "alice")                                          # a second 'alice' (the impostor) is a member of the first one's thread
        pub = Path(self.a) / "alice2.pub"
        pub.write_text(run(c, "id", "show", "--json")[1])
        rc, out, err = run(self.a, "new", "twins", "--plaintext", "--member", f"member={pub}")
        tid = out.split("thread ")[1].split()[0]
        run(self.a, "post", tid, "I am the owner")
        sync = run(self.a, "export", tid)[1]
        run(c, "ingest", "-", inp=sync)
        run(c, "post", tid, "no, I am")
        run(self.a, "ingest", "-", inp=run(c, "export", tid)[1])
        out = run(self.a, "live", tid[:8], "--once", "--no-color", "--width", "80")[1]
        self.assertRegex(out, r"alice \([0-9a-z]{6}\) \(owner\), alice \([0-9a-z]{6}\) \(member\)")
        heads = [l for l in out.splitlines() if re.match(r"\d\d:\d\d:\d\d  alice \(", l)]
        self.assertEqual(len(heads), 2, out)
        self.assertEqual(len({re.search(r"alice \(([0-9a-z]{6})\)", l).group(1) for l in heads}), 2)

    def test_shows_title_members_names_and_hides_nothing_hostile(self):
        run(self.a, "post", self.tid, f"hello{ESC}[2J{ESC}]0;pwned\x07 ‮evil", "--to", "bob")
        self.sync()
        out = self.live()
        self.assertIn("plan the trip", out)
        self.assertIn("alice (owner)", out)
        self.assertIn("bob (member)", out)
        self.assertIn("alice -> bob", out)
        self.assertIn("hello", out)
        self.assertNotIn(ESC, out)
        self.assertNotIn("\x07", out)
        self.assertNotIn("‮", out)

    def test_admin_events_are_quiet_lines_and_the_reply_names_its_parent(self):
        out = self.live()
        self.assertIn("thread created: 'plan the trip'", out)
        run(self.a, "post", self.tid, "[ASK] can you see this?", "--to", "bob")
        self.sync()
        first = [l for l in self.live().splitlines() if "[ASK] can you see this?" in l]
        self.assertEqual(len(first), 1)
        import re
        parent = re.search(r"\[([0-9a-f]{8})\] alice[^\n]*can you see this", run(self.b, "unread", self.tid)[1]).group(1)
        rc, _, err = run(self.b, "done", self.tid, "yes", "--re", parent)
        self.assertEqual(rc, 0, err)
        out = self.live()
        self.assertIn(f"in reply to alice [{parent[:8]}]: [ASK] can you see this?", out)
        self.assertIn("bob -> alice", out)

    def test_long_posts_are_cut_with_a_marker_unless_full(self):
        text = "\n".join(f"line {n:03d}" for n in range(100)) + "\nTHE-END"
        run(self.a, "post", self.tid, text)
        self.sync()
        out = self.live()
        self.assertIn("line 029", out)
        self.assertNotIn("line 030", out)
        self.assertNotIn("THE-END", out)
        self.assertIn("(+71 more lines", out)
        full = run(self.b, "live", "--once", "--no-color", "--full", "--width", "80")[1]
        self.assertIn("THE-END", full)
        self.assertNotIn("more lines", full)

    def test_mentions_show_names_and_last_limits_the_backlog(self):
        run(self.a, "post", self.tid, "one")
        run(self.a, "post", self.tid, "two")
        run(self.a, "post", self.tid, "three")
        self.sync()
        out = self.live("--last", "1")
        self.assertIn("three", out)
        self.assertNotIn("two", out)
        self.assertIn("earlier events not shown", out)
        self.assertNotIn("earlier events not shown", self.live("--last", "100"))
        self.assertNotIn("three", self.live("--last", "0"))

    def test_closed_threads_only_when_asked_for(self):
        rc, out, err = run(self.a, "rotate", self.tid, "--close")
        self.assertEqual(rc, 0, err)
        self.sync()
        self.assertIn("[CLOSED]", self.live(self.tid[:8]))
        rc, out, err = run(self.b, "live", "--once", "--no-color")
        self.assertEqual(rc, 1)
        self.assertIn("no threads", out)
        self.assertNotIn("plan the trip", out)

    def test_a_closed_pipe_ends_it_quietly(self):
        for n in range(60):
            run(self.a, "post", self.tid, f"post number {n}")
        self.sync()
        p = subprocess.Popen([sys.executable, "-B", "-m", "sigilnet", "--home", self.b, "live", "--no-color", "--last", "70", "--seconds", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=str(ROOT), env=ENV)
        p.stdout.readline()
        p.stdout.close()                                                            # the reader goes away (like `| head -1`)
        _, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 0, err)
        self.assertEqual(err, b"", err)

    def test_unknown_thread_is_an_error_in_once_mode(self):
        rc, out, err = run(self.b, "live", "--once", "--no-color", "ffffffff")
        self.assertEqual(rc, 1)
        self.assertIn("no thread matches", out)

    def test_read_only(self):
        run(self.a, "post", self.tid, "hello")
        self.sync()
        ev = Path(self.b) / "mirror" / "threads" / self.tid / "events.jsonl"
        before = (ev.read_bytes(), run(self.b, "unread", self.tid)[1])
        self.live()
        run(self.b, "live", "--seconds", "1", "--poll", "0.2", "--no-color")
        self.assertEqual((ev.read_bytes(), run(self.b, "unread", self.tid)[1]), before)
        self.assertIn("hello", before[1])                                # (still unread: the viewer marks nothing read)

    def test_follows_new_posts_and_a_new_thread_as_they_arrive(self):
        p = subprocess.Popen([sys.executable, "-u", "-B", "-m", "sigilnet", "--home", self.b, "live", "--no-color", "--seconds", "12", "--poll", "0.2", "--width", "80"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(ROOT), env=ENV)
        try:
            time.sleep(2.0)
            run(self.a, "post", self.tid, "arrived while watching")
            self.sync()
            rc, out, err = run(self.a, "new", "second thread", "--plaintext", "--member", f"member={Path(self.a) / 'bob.pub'}")
            tid2 = out.split("thread ")[1].split()[0]
            run(self.b, "ingest", "-", inp=run(self.a, "export", tid2)[1])
            stdout, stderr = p.communicate(timeout=30)
        finally:
            if p.poll() is None:
                p.kill()
        self.assertEqual(p.returncode, 0, stderr)
        self.assertIn("arrived while watching", stdout)
        self.assertIn("second thread", stdout)
        self.assertLess(stdout.index("plan the trip"), stdout.index("arrived while watching"))
        self.assertEqual(stdout.count("arrived while watching"), 1)


if __name__ == "__main__":
    unittest.main()
