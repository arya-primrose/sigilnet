"""P0 of DESIGN_node_daemon.md: inbox/ -> guest/ migration and the `inbox` -> `requests` rename."""
import contextlib
import fcntl
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sigilnet import cli, noderun
from sigilnet.inbox import Inbox
from sigilnet.keys import Identity
from sigilnet.migrate import MigrationError, check_layout, migrate_home
from sigilnet.mirror import Mirror

SECRET = bytes(range(32))


def old_home():
    h = Path(tempfile.mkdtemp())
    (h / "inbox").mkdir(mode=0o700)
    (h / "inbox" / "secret").write_bytes(SECRET)
    (h / "inbox" / "wake.json").write_text('{"threads": {"abc": 2}}')
    (h / "inbox" / "t1.bits.json").write_text("{}")
    return h


def run_cli(home, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(["--home", str(home), *args])
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write(str(e.code) if not isinstance(e.code, int) else "")
    return rc, out.getvalue(), err.getvalue()


class Migrate(unittest.TestCase):
    def test_moves_everything_and_keeps_the_secret(self):
        h = old_home()
        self.assertTrue(migrate_home(h))
        self.assertFalse((h / "inbox").exists())
        self.assertEqual((h / "guest" / "secret").read_bytes(), SECRET)
        self.assertFalse((h / "guest" / "wake.json").exists())                                   # P2: the counters are gone (a line in inbox.jsonl does their job)
        self.assertTrue((h / "guest" / "t1.bits.json").exists())

    def test_second_call_is_a_noop(self):
        h = old_home()
        self.assertTrue(migrate_home(h))
        self.assertFalse(migrate_home(h))
        self.assertEqual((h / "guest" / "secret").read_bytes(), SECRET)

    def test_neither_directory_creates_nothing(self):
        h = Path(tempfile.mkdtemp())
        self.assertFalse(migrate_home(h))
        self.assertFalse((h / "guest").exists())
        self.assertFalse((h / "inbox").exists())
        self.assertFalse((h / ".migrate.lock").exists())

    def test_only_guest_is_untouched(self):
        h = Path(tempfile.mkdtemp())
        (h / "guest").mkdir()
        (h / "guest" / "secret").write_bytes(SECRET)
        self.assertFalse(migrate_home(h))
        self.assertEqual((h / "guest" / "secret").read_bytes(), SECRET)

    def test_both_present_is_an_error_naming_both_and_merges_nothing(self):
        h = old_home()
        (h / "guest").mkdir()
        (h / "guest" / "secret").write_bytes(b"x" * 32)
        with self.assertRaises(MigrationError) as c:
            migrate_home(h)
        self.assertIn(str(h / "inbox"), str(c.exception))
        self.assertIn(str(h / "guest"), str(c.exception))
        self.assertEqual((h / "inbox" / "secret").read_bytes(), SECRET)
        self.assertEqual((h / "guest" / "secret").read_bytes(), b"x" * 32)

    def test_a_symlink_inbox_is_refused_and_its_target_untouched(self):
        h = Path(tempfile.mkdtemp())
        target = Path(tempfile.mkdtemp())
        (target / "secret").write_bytes(SECRET)
        os.symlink(target, h / "inbox")
        with self.assertRaises(MigrationError):
            migrate_home(h)
        self.assertTrue(os.path.islink(h / "inbox"))
        self.assertFalse((h / "guest").exists())

    def test_a_plain_file_named_inbox_is_refused(self):
        h = Path(tempfile.mkdtemp())
        (h / "inbox").write_text("x")
        with self.assertRaises(MigrationError):
            migrate_home(h)
        self.assertEqual((h / "inbox").read_text(), "x")

    def test_refused_while_a_node_holds_the_lock(self):
        h = old_home()
        fd = os.open(h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaises(MigrationError) as c:
            migrate_home(h)
        self.assertIn("stop it first", str(c.exception))
        self.assertTrue((h / "inbox" / "secret").exists())
        self.assertFalse((h / "guest").exists())

    def test_a_probe_holding_the_node_lock_for_a_moment_does_not_block_the_migration(self):
        import threading
        import time
        h = old_home()
        fd = os.open(h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        t = threading.Thread(target=lambda: (time.sleep(0.3), os.close(fd)))
        t.start()
        self.addCleanup(t.join)
        self.assertTrue(migrate_home(h))

    def test_the_node_lock_is_free_again_after_a_migration(self):
        h = old_home()
        migrate_home(h)
        fd = os.open(h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)                 # must not raise: the probe released its lock

    def test_losing_the_race_is_a_success_not_an_error(self):
        from unittest import mock
        h = old_home()
        real = os.path.lexists
        seen = []

        def lexists(p):
            if str(p) == str(h / "inbox"):
                seen.append(1)
                if len(seen) > 1:
                    return False                                   # another process moved it while we waited for the lock
            return real(p)
        with mock.patch("sigilnet.migrate.os.path.lexists", lexists):
            self.assertFalse(migrate_home(h))
        self.assertEqual(len(seen), 2)

    def test_a_rename_that_finds_nothing_is_a_success(self):
        from unittest import mock
        h = old_home()
        with mock.patch("sigilnet.migrate.os.rename", side_effect=FileNotFoundError):
            self.assertFalse(migrate_home(h))

    def test_other_rename_failures_are_a_migration_error_not_a_traceback(self):
        import errno
        from unittest import mock
        for code in (errno.EACCES, errno.EROFS, errno.ENOTEMPTY):
            h = old_home()
            with mock.patch("sigilnet.migrate.os.rename", side_effect=OSError(code, os.strerror(code))):
                with self.assertRaises(MigrationError) as c:
                    migrate_home(h)
            self.assertIn("cannot rename", str(c.exception))
            self.assertTrue((h / "inbox" / "secret").exists())
            self.assertFalse((h / "guest").exists())

    def test_a_cli_command_on_an_unmovable_old_home_exits_with_an_error_line(self):
        import errno
        from unittest import mock
        h = old_home()
        with mock.patch("sigilnet.migrate.os.rename", side_effect=OSError(errno.EROFS, "Read-only file system")):
            rc, out, err = run_cli(h, "list")
        self.assertNotEqual(rc, 0)
        self.assertIn("cannot rename", err)

    def test_four_processes_at_once_all_succeed_and_one_directory_results(self):
        h = old_home()
        code = "import sys; from sigilnet.migrate import migrate_home; sys.exit(0 if migrate_home(sys.argv[1]) in (True, False) else 9)"
        procs = [subprocess.Popen([sys.executable, "-c", code, str(h)], cwd=str(Path(__file__).resolve().parents[2])) for _ in range(4)]
        self.assertEqual([p.wait(timeout=60) for p in procs], [0, 0, 0, 0])
        self.assertFalse((h / "inbox").exists())
        self.assertEqual((h / "guest" / "secret").read_bytes(), SECRET)


class LoudNeverFresh(unittest.TestCase):
    def test_check_layout_flags_the_old_layout_only(self):
        h = old_home()
        with self.assertRaises(MigrationError):
            check_layout(h)
        migrate_home(h)
        check_layout(h)
        check_layout(tempfile.mkdtemp())

    def test_inbox_refuses_to_open_an_old_home_and_creates_no_secret(self):
        h = old_home()
        m = Mirror(str(h / "mirror"))
        with self.assertRaises(MigrationError):
            Inbox(m, h)
        self.assertFalse((h / "guest").exists())
        self.assertEqual((h / "inbox" / "secret").read_bytes(), SECRET)

    def test_inbox_uses_guest(self):
        h = Path(tempfile.mkdtemp())
        ib = Inbox(Mirror(str(h / "mirror")), h)
        self.assertEqual(ib.dir, h / "guest")
        self.assertFalse((h / "inbox").exists())


class WakeFilesGone(unittest.TestCase):
    def test_leftover_wake_files_in_a_migrated_home_are_removed_too(self):
        h = Path(tempfile.mkdtemp())
        (h / "guest").mkdir()
        for n in ("wake.json", "wake_seen.json", "secret"):
            (h / "guest" / n).write_text("x")
        migrate_home(h)
        self.assertEqual(sorted(os.listdir(h / "guest")), ["secret"])

    def test_a_symlinked_guest_dir_is_left_alone(self):
        h = Path(tempfile.mkdtemp())
        target = Path(tempfile.mkdtemp())
        (target / "wake.json").write_text("x")
        os.symlink(target, h / "guest")
        migrate_home(h)
        self.assertTrue((target / "wake.json").exists())


class CommandsMigrate(unittest.TestCase):
    def test_any_command_migrates_and_the_door_secret_survives(self):
        h = old_home()
        run_cli(h, "id", "init", "arya")
        self.assertFalse((h / "inbox").exists())
        m = Mirror(str(h / "mirror"))
        self.assertEqual(Inbox(m, h).secret, SECRET)

    def test_a_command_stops_with_an_error_when_both_exist(self):
        h = old_home()
        (h / "guest").mkdir()
        rc, out, err = run_cli(h, "list")
        self.assertNotEqual(rc, 0)
        self.assertIn("both", err)

    def test_node_run_refuses_to_migrate_under_a_running_node(self):
        h = old_home()
        fd = os.open(h / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lines = []
        me = Identity.generate("arya")
        rc = noderun.run(h, me, seconds=1, offline=True, out=lines.append)
        self.assertEqual(rc, 1)
        self.assertTrue(any("old-code node" in x for x in lines), lines)          # the MIGRATION refusal, not the instance lock's own message
        self.assertTrue((h / "inbox" / "secret").exists())


class Rename(unittest.TestCase):
    def setUp(self):
        self.h = tempfile.mkdtemp()
        run_cli(self.h, "id", "init", "arya")

    def test_requests_and_the_old_name_both_work_and_only_the_old_one_notes_it(self):
        rc, out, err = run_cli(self.h, "new", "t", "--public")
        tid = out.split("thread ")[1].split()[0][:8]
        rc, out, err = run_cli(self.h, "requests", "list", tid)
        self.assertEqual(rc, 0, err)
        self.assertIn("0 waiting", out)
        self.assertIn("requests show THREAD ID", out)
        self.assertNotIn("renamed", err)
        rc2, out2, err2 = run_cli(self.h, "inbox", "list", tid)
        self.assertEqual(rc2, 0)
        self.assertEqual(out2, out)
        self.assertIn("renamed to `requests`", err2)

    def test_requests_needs_a_thread(self):
        rc, out, err = run_cli(self.h, "requests", "list")
        self.assertNotEqual(rc, 0)
        self.assertIn("requests list: give a thread", err)

    def test_wait_still_times_out_quietly(self):
        rc, out, err = run_cli(self.h, "requests", "wait", "--timeout", "0.1")
        self.assertEqual(rc, 0, err)
        self.assertIn("no new guest requests", out)


if __name__ == "__main__":
    unittest.main()
