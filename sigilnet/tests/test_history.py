"""P2: history.log, the plain-text record."""
import os
import re
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import history
from sigilnet.history import History


class Clock:
    t = 1_700_000_000.0

    def __call__(self):
        return self.t


class Hist(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.h = History(self.home, clock=Clock())
        self._tz = os.environ.get("TZ")
        os.environ["TZ"] = "America/Denver"
        time.tzset()
        self.addCleanup(self.restore_tz)

    def restore_tz(self):
        if self._tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self._tz
        time.tzset()

    def lines(self):
        return Path(self.home, "history.log").read_text().splitlines()

    def test_line_format_with_the_zone(self):
        self.h.log("node", "carrier tcp up")
        self.assertEqual(self.lines(), ["2023-11-14 15:13:20 MST  node  carrier tcp up"])

    def test_the_zone_abbreviation_follows_the_process_tz(self):
        os.environ["TZ"] = "UTC"
        time.tzset()
        self.h.log("node", "x")
        self.assertTrue(self.lines()[0].startswith("2023-11-14 22:13:20 UTC  node"))

    def test_control_and_format_characters_become_spaces_and_it_is_one_line(self):
        self.h.log("no\nde", "a\x1b[31mred\r\nline\u202ebidi\x00z")
        ls = self.lines()
        self.assertEqual(len(ls), 1)
        self.assertNotRegex(ls[0], r"[\x00-\x08\x0b-\x1f\x7f\u202e]")
        self.assertIn("a [31mred line bidi z", ls[0])

    def test_a_line_is_capped_prefix_included(self):
        self.h.log("node", "x" * 5000)
        ls = self.lines()
        self.assertEqual(len(ls[0]), history.MAX_LINE)
        self.assertEqual(len(ls), 1)

    def test_mode_is_0600(self):
        self.h.log("node", "x")
        self.assertEqual(stat.S_IMODE(os.stat(self.h.path).st_mode), 0o600)

    def test_one_write_per_record_in_append_mode(self):
        writes, opens = [], []
        real_write, real_open = os.write, os.open
        with mock.patch("sigilnet.history.os.write", lambda fd, b: (writes.append(b), real_write(fd, b))[1]), \
             mock.patch("sigilnet.history.os.open", lambda p, f, *a: (opens.append(f), real_open(p, f, *a))[1]):
            self.h.log("node", "x")
        self.assertEqual(len(writes), 1)
        self.assertTrue(opens[0] & os.O_APPEND)
        self.assertFalse(opens[0] & os.O_TRUNC)

    def test_an_outside_rename_is_followed_at_the_next_record(self):
        self.h.log("node", "one")
        os.rename(self.h.path, Path(self.home) / "history.log.1")
        self.h.log("node", "two")
        self.assertEqual(len(self.lines()), 1)
        self.assertIn("two", self.lines()[0])
        self.assertIn("one", Path(self.home, "history.log.1").read_text())

    def test_rotation_keeps_one_old_file(self):
        old = history.MAX_BYTES
        history.MAX_BYTES = 300
        try:
            for i in range(40):
                self.h.log("node", f"record {i} " + "x" * 30)
        finally:
            history.MAX_BYTES = old
        names = sorted(n for n in os.listdir(self.home))
        self.assertEqual(names, ["history.lock", "history.log", "history.log.1"])
        self.assertLess(os.path.getsize(self.h.path), 600)
        self.assertIn("record 39", self.lines()[-1])

    def test_rotation_restats_inside_the_lock(self):
        old = history.MAX_BYTES
        history.MAX_BYTES = 100
        try:
            self.h.log("node", "x" * 200)
            real = os.stat
            calls = []

            def stat_then_shrink(p, *a, **k):
                r = real(p, *a, **k)
                if str(p) == str(self.h.path):
                    calls.append(r.st_size)
                return r
            os.truncate(self.h.path, 10)                                              # another rotator already did the work
            with mock.patch("sigilnet.history.os.stat", stat_then_shrink):
                self.h._rotate()
        finally:
            history.MAX_BYTES = old
        self.assertFalse((Path(self.home) / "history.log.1").exists())                 # re-checked inside the lock: nothing to rotate

    def test_the_lock_file_is_made_on_rotation_only(self):
        self.h.log("node", "x")
        self.assertFalse((Path(self.home) / "history.lock").exists())

    def test_concurrent_writers_never_tear_a_line(self):
        def w(k):
            for i in range(100):
                self.h.log(f"w{k}", f"line {i} " + "y" * 50)
        ts = [threading.Thread(target=w, args=(k,)) for k in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        ls = self.lines()
        self.assertEqual(len(ls), 400)
        self.assertTrue(all(re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \w+  w\d  line \d+ y{50}$", l) for l in ls))

    def test_an_unwritable_home_never_raises(self):
        History(Path(self.home) / "nope" / "deeper").log("node", "x")

    def test_tail(self):
        for i in range(30):
            self.h.log("node", f"n{i}")
        self.assertEqual(len(self.h.tail(5)), 5)
        self.assertIn("n29", self.h.tail(1)[0])
        self.assertEqual(History(tempfile.mkdtemp()).tail(), [])

    def test_the_node_and_the_cli_write_through_it(self):
        from sigilnet import noderun, cli
        import io, contextlib
        h = tempfile.mkdtemp()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main(["--home", h, "id", "init", "arya"])
            cli.main(["--home", h, "new", "t"])
            tid = out.getvalue().split("thread ")[1].split()[0][:8]
            cli.main(["--home", h, "post", tid, "hello"])
            cli.main(["--home", h, "read", tid])
        text = Path(h, "history.log").read_text()
        self.assertIn(f"cli  post in thread {tid}", text)
        self.assertIn(f"cli  read thread {tid}", text)
        self.assertNotIn("hello", text)                                                # never message text


if __name__ == "__main__":
    unittest.main()
