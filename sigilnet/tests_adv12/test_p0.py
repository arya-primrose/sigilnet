"""P0 (renames + migration) from the OUTSIDE: real processes, the CLI, read-only homes. Findings still open are skipped with ADV12_SKIP_OPEN_FINDINGS=1."""
import fcntl
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import migrate
from sigilnet.migrate import MigrationError, check_layout, migrate_home

REPO = str(Path(__file__).resolve().parents[2])
SKIP = os.environ.get("ADV12_SKIP_OPEN_FINDINGS") == "1"


def old_home(secret=b"s" * 32):
    h = Path(tempfile.mkdtemp(prefix="adv12_p0_"))
    (h / "inbox").mkdir(mode=0o700)
    (h / "inbox" / "secret").write_bytes(secret)
    (h / "inbox" / "wake.json").write_text('{"threads": {"t": 2}}')
    (h / "inbox" / "t.bits.json").write_text("{}")
    return h


def cli(home, *args, env=None):
    r = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(home), *args], capture_output=True, text=True, timeout=60, cwd=REPO,
                       env={**os.environ, "PYTHONPATH": REPO, **(env or {})})
    return r.returncode, r.stdout, r.stderr


class Outside(unittest.TestCase):
    def test_eight_real_processes_one_rename_the_secret_bytes_unchanged_nothing_lost(self):
        secret = os.urandom(32)
        h = old_home(secret)
        script = textwrap.dedent(f"""
            import sys; sys.path.insert(0, {REPO!r})
            from sigilnet.migrate import migrate_home
            sys.exit(0 if migrate_home({str(h)!r}) in (True, False) else 1)
        """)
        ps = [subprocess.Popen([sys.executable, "-c", script], stderr=subprocess.PIPE) for _ in range(8)]
        codes = [p.wait(60) for p in ps]
        self.assertEqual(codes, [0] * 8)
        self.assertFalse((h / "inbox").exists())
        self.assertEqual((h / "guest" / "secret").read_bytes(), secret)
        self.assertEqual(sorted(p.name for p in (h / "guest").iterdir()), ["secret", "t.bits.json"])          # P2: the old wake files are dropped by the migration
        self.assertEqual(stat.S_IMODE((h / ".migrate.lock").stat().st_mode), 0o600)

    def test_a_node_in_another_process_blocks_the_migration_and_nothing_moves(self):
        h = old_home()
        holder = subprocess.Popen([sys.executable, "-c", textwrap.dedent(f"""
            import fcntl, os, sys, time
            fd = os.open({str(h / 'node.lock')!r}, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print("held", flush=True)
            time.sleep(60)
        """)], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            with self.assertRaises(MigrationError):
                migrate_home(h)
            self.assertTrue((h / "inbox" / "secret").exists())
            self.assertFalse((h / "guest").exists())
            rc, out, err = cli(h, "list")
            self.assertNotEqual(rc, 0)
            self.assertIn("node is running", err)
            self.assertNotIn("Traceback", err)
        finally:
            holder.kill()
            holder.wait(10)
            holder.stdout.close()
        self.assertTrue(migrate_home(h))                                               # the node is gone: now it goes

    def test_after_a_rollback_the_two_directories_are_reported_and_nothing_is_merged(self):
        h = old_home(b"A" * 32)
        migrate_home(h)
        (h / "inbox").mkdir()                                                          # old code ran again and made its own empty inbox/ with a new secret
        (h / "inbox" / "secret").write_bytes(b"B" * 32)
        rc, out, err = cli(h, "list")
        self.assertNotEqual(rc, 0)
        self.assertIn("inbox", err)
        self.assertIn("guest", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual((h / "guest" / "secret").read_bytes(), b"A" * 32)
        self.assertEqual((h / "inbox" / "secret").read_bytes(), b"B" * 32)

    def test_check_layout_never_creates_anything(self):
        h = Path(tempfile.mkdtemp(prefix="adv12_p0_"))
        check_layout(h)
        self.assertEqual(list(h.iterdir()), [])
        (h / "inbox").mkdir()
        with self.assertRaises(MigrationError):
            check_layout(h)
        self.assertEqual([p.name for p in h.iterdir()], ["inbox"])

    def test_the_cli_migrates_on_its_first_command_and_the_stdout_is_the_same_after(self):
        h = old_home()
        rc, out, err = cli(h, "id", "init", "arya")
        self.assertEqual(rc, 0, err)
        self.assertTrue((h / "guest" / "secret").exists())
        self.assertFalse((h / "inbox").exists())
        rc, out, err = cli(h, "requests", "wait", "--timeout", "0.1")
        self.assertEqual(rc, 0, err)
        self.assertIn("no new guest requests", out)                                                  # P2: the old wake.json counters are gone, not carried over
        self.assertEqual(err, "")


class OpenFindings(unittest.TestCase):
    @unittest.skipIf(SKIP, "open finding F1 (P0): a failing rename is a traceback")
    def test_a_rename_that_fails_is_a_migration_error_not_a_traceback(self):
        for exc in (PermissionError(13, "Permission denied"), OSError(30, "Read-only file system"), OSError(39, "Directory not empty")):
            h = old_home()
            with mock.patch.object(migrate.os, "rename", side_effect=exc):
                with self.assertRaises(MigrationError):
                    migrate_home(h)
            self.assertTrue((h / "inbox" / "secret").exists())

    @unittest.skipIf(SKIP, "open finding F1 (P0): a failing rename is a traceback")
    def test_the_cli_reports_a_failing_migration_as_an_error_line(self):
        h = old_home()
        sitecustomize = Path(tempfile.mkdtemp(prefix="adv12_sc_"))
        (sitecustomize / "sitecustomize.py").write_text("import os\n_r = os.rename\ndef rename(a, b, *k, **kw):\n    if str(a).endswith('/inbox'):\n        raise OSError(30, 'Read-only file system')\n    return _r(a, b, *k, **kw)\nos.rename = rename\n")
        rc, out, err = cli(h, "list", env={"PYTHONPATH": f"{sitecustomize}:{REPO}"})
        self.assertNotEqual(rc, 0)
        self.assertNotIn("Traceback", err)
        self.assertIn("error:", err)


if __name__ == "__main__":
    unittest.main()
