"""History (section 6, 13 point 3, 14): one atomic line per record, open per record, rotation under a lock with the size re-checked inside it."""
import multiprocessing as mp
import os
import re
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import history
from sigilnet.history import History

from .h import Clock

LINE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [A-Za-z0-9+-]{2,8}  (.*?)  (.*)$")
OLD_TZ = os.environ.get("TZ")


def home():
    return Path(tempfile.mkdtemp(prefix="adv12_hist_"))


def set_tz(name):
    os.environ["TZ"] = name
    time.tzset()


def restore_tz():
    if OLD_TZ is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = OLD_TZ
    time.tzset()


class Format(unittest.TestCase):
    def tearDown(self):
        restore_tz()

    def test_exact_line_in_mountain_time(self):
        set_tz("America/Denver")
        h = home()
        History(h, clock=Clock(1_700_000_000.0)).log("node", "door up")                  # 2023-11-14 22:13:20 UTC
        self.assertEqual((h / "history.log").read_text(), "2023-11-14 15:13:20 MST  node  door up\n")
        set_tz("America/Denver")
        History(h, clock=Clock(1_690_000_000.0)).log("cli", "x")                           # a summer date: MDT
        self.assertTrue((h / "history.log").read_text().splitlines()[-1].startswith("2023-07-21 22:26:40 MDT  cli  x"))

    def test_zone_follows_the_environment(self):
        set_tz("UTC")
        h = home()
        History(h, clock=Clock(1_700_000_000.0)).log("node", "t")
        self.assertEqual((h / "history.log").read_text(), "2023-11-14 22:13:20 UTC  node  t\n")

    def test_file_mode_and_creation(self):
        h = home()
        self.assertFalse((h / "history.log").exists())
        History(h).log("node", "a")
        self.assertEqual(stat.S_IMODE((h / "history.log").stat().st_mode), 0o600)

    def test_each_record_is_one_line_appended(self):
        h = home()
        log = History(h)
        for i in range(5):
            log.log("node", f"line {i}")
        ls = (h / "history.log").read_text().splitlines()
        self.assertEqual(len(ls), 5)
        self.assertEqual([LINE.match(l).group(2) for l in ls], [f"line {i}" for i in range(5)])
        self.assertEqual(log.tail(2), ls[-2:])
        self.assertEqual(log.tail(99), ls)

    def test_tail_of_a_missing_file_is_empty(self):
        self.assertEqual(History(home()).tail(), [])


class Hygiene(unittest.TestCase):
    def test_control_and_format_characters_become_spaces_and_it_stays_one_line(self):
        h = home()
        log = History(h)
        log.log("no\nde\x1b[31m", "a\nb\r\nc\x00d\x07e\u202ef\u200bg\u2028h\u2029i\x85j")
        data = (h / "history.log").read_bytes()
        self.assertEqual(data.count(b"\n"), 1)
        txt = data.decode()
        for bad in ("\x1b", "\x00", "\x07", "\r", "\u202e", "\u200b", "\u2028", "\u2029", "\x85"):
            self.assertNotIn(bad, txt)
        m = LINE.match(txt.rstrip("\n"))
        self.assertTrue(m, txt)
        for part in ("a", "b", "c", "d", "e", "f", "g", "h", "i", "j"):
            self.assertIn(part, m.group(2))

    def test_the_line_is_capped(self):
        h = home()
        History(h).log("node", "x" * 5000)
        ls = (h / "history.log").read_text().splitlines()
        self.assertEqual(len(ls), 1)
        self.assertLessEqual(len(ls[0]), history.MAX_LINE)
        self.assertGreater(len(ls[0]), history.MAX_LINE - 60)                              # capped, not truncated to nothing

    def test_a_cap_in_characters_does_not_split_a_multibyte_character(self):
        h = home()
        History(h).log("node", "é" * 3000)
        (h / "history.log").read_bytes().decode("utf-8")                                    # must not raise

    def test_non_string_arguments_do_not_crash_the_node(self):
        h = home()
        History(h).log("node", 12345)
        History(h).log("node", None)
        self.assertEqual(len((h / "history.log").read_text().splitlines()), 2)


def _writer(home, tag, n, width):
    log = History(home)
    for i in range(n):
        log.log(tag, f"{tag}-{i:04d}-" + "z" * width)


class Concurrency(unittest.TestCase):
    def test_four_processes_no_line_is_torn_or_interleaved(self):
        h = home()
        ctx = mp.get_context("fork")
        ps = [ctx.Process(target=_writer, args=(h, f"p{k}", 150, 400)) for k in range(4)]
        [p.start() for p in ps]
        [p.join(60) for p in ps]
        ls = (h / "history.log").read_text().splitlines()
        self.assertEqual(len(ls), 600)
        seen = {}
        for l in ls:
            m = LINE.match(l)
            self.assertTrue(m, l[:80])
            who, text = m.groups()
            mm = re.fullmatch(rf"{who}-(\d{{4}})-z{{400}}", text)
            self.assertTrue(mm, text[:60])
            seen.setdefault(who, []).append(int(mm.group(1)))
        for who, nums in seen.items():
            self.assertEqual(nums, list(range(150)), who)                                   # each writer's own lines are whole and in order


class Rotation(unittest.TestCase):
    def test_a_rename_by_someone_else_is_followed_at_the_next_record(self):
        """Section 13 point 3: open per record. A long-lived fd would keep writing into history.log.1 for ever."""
        h = home()
        log = History(h)
        log.log("node", "before")
        os.rename(h / "history.log", h / "history.log.1")
        log.log("node", "after")
        self.assertIn("after", (h / "history.log").read_text())
        self.assertNotIn("before", (h / "history.log").read_text())
        self.assertNotIn("after", (h / "history.log.1").read_text())

    def test_rotation_past_max_bytes_keeps_one_old_file(self):
        with mock.patch.object(history, "MAX_BYTES", 3000):
            h = home()
            log = History(h)
            for i in range(200):
                log.log("node", f"record {i:04d} " + "y" * 60)
            names = sorted(p.name for p in h.iterdir() if p.name.startswith("history.log"))
            self.assertEqual(names, ["history.log", "history.log.1"])                       # never a .2
            cur = (h / "history.log").read_text().splitlines()
            old = (h / "history.log.1").read_text().splitlines()
            self.assertLess((h / "history.log").stat().st_size, 3000 + 200)
            self.assertTrue(cur[-1].endswith("record 0199 " + "y" * 60))                    # the newest is in the live file
            allnums = [int(re.search(r"record (\d{4})", l).group(1)) for l in old + cur]
            self.assertEqual(allnums, sorted(allnums))                                       # old file holds earlier records than the live one
            for l in old + cur:
                self.assertTrue(LINE.match(l), l)                                            # no torn line in either
            self.assertEqual(stat.S_IMODE((h / "history.log.1").stat().st_mode), 0o600)

    def test_a_second_rotator_does_not_rotate_the_fresh_file_over_the_old_one(self):
        """The size is re-checked INSIDE history.lock. Eight processes hammer a tiny limit: every rotation must move a file that really was past the limit, so the
        old file ends up at least MAX_BYTES big (a double rotation would leave it nearly empty)."""
        with mock.patch.object(history, "MAX_BYTES", 6000):
            h = home()
            ctx = mp.get_context("fork")
            ps = [ctx.Process(target=_writer, args=(h, f"w{k}", 120, 120)) for k in range(8)]
            [p.start() for p in ps]
            [p.join(120) for p in ps]
            self.assertTrue((h / "history.log.1").exists())
            self.assertGreaterEqual((h / "history.log.1").stat().st_size, 6000)
            self.assertFalse((h / "history.log.2").exists())
            for name in ("history.log", "history.log.1"):
                for l in (h / name).read_text().splitlines():
                    self.assertTrue(LINE.match(l), (name, l[:80]))

    def test_the_lock_file_is_history_lock(self):
        with mock.patch.object(history, "MAX_BYTES", 500):
            h = home()
            log = History(h)
            for i in range(30):
                log.log("node", "q" * 80)
            self.assertTrue((h / "history.lock").exists())


if __name__ == "__main__":
    unittest.main()
