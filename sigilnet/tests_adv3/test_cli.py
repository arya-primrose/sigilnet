"""`key` and `sync` commands: paths, permissions, error messages, secrets."""
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[2])


def cli(home, *args, timeout=60):
    return subprocess.run([sys.executable, "-m", "sigilnet", "--home", home, *args], capture_output=True, text=True, cwd=ROOT,
                          env={**os.environ, "PYTHONPATH": ROOT}, timeout=timeout)


class Key(unittest.TestCase):
    def test_key_new_into_a_home_that_does_not_exist_yet_fails_cleanly(self):
        d = tempfile.mkdtemp()
        r = cli(f"{d}/fresh/home", "key", "new")
        self.assertNotIn("Traceback", r.stderr, r.stderr)          # BUG (low) if a raw traceback: default path is <home>/sync.key and home is not created

    def test_key_new_into_a_missing_directory_fails_cleanly(self):
        # BUG (low): uncaught exception, raw traceback instead of a one-line message
        d = tempfile.mkdtemp()
        r = cli(d, "key", "new", "--file", f"{d}/nope/k")
        self.assertNotIn("Traceback", r.stderr, r.stderr)

    def test_key_file_is_0600_and_never_overwritten_or_followed_through_a_symlink(self):
        d = tempfile.mkdtemp()
        victim = Path(d, "victim")
        victim.write_text("precious")
        os.symlink(victim, f"{d}/k")
        r = cli(d, "key", "new", "--file", f"{d}/k")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(victim.read_text(), "precious")
        r = cli(d, "key", "new", "--file", f"{d}/k2")
        self.assertEqual(stat.S_IMODE(os.stat(f"{d}/k2").st_mode), 0o600)
        again = cli(d, "key", "new", "--file", f"{d}/k2")
        self.assertNotEqual(again.returncode, 0)

    def test_key_new_does_not_print_the_key(self):
        d = tempfile.mkdtemp()
        r = cli(d, "key", "new", "--file", f"{d}/k")
        secret = Path(f"{d}/k").read_text().strip()
        self.assertNotIn(secret, r.stdout + r.stderr)

    def test_a_group_readable_key_file_is_accepted_silently(self):
        # BUG (low): `sync` reads whatever key file it is given, even world-readable ones, and says nothing
        d = tempfile.mkdtemp()
        cli(d, "id", "init", "me")
        cli(d, "key", "new", "--file", f"{d}/k")
        os.chmod(f"{d}/k", 0o644)
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        r = cli(d, "sync", "pull", f"127.0.0.1:{port}", "--key-file", f"{d}/k")
        self.assertIn("readable by others", (r.stdout + r.stderr).lower(), "no warning about a world-readable transport secret")


class Sync(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        cli(self.d, "id", "init", "me")

    def test_garbage_key_file_gives_a_message_without_the_contents_or_a_traceback(self):
        Path(f"{self.d}/k").write_text("SECRETSECRETSECRETSECRET")
        r = cli(self.d, "sync", "pull", "127.0.0.1:1", "--key-file", f"{self.d}/k")
        self.assertNotIn("SECRETSECRET", r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stderr, r.stderr)             # BUG (low) if a traceback

    def test_empty_key_file(self):
        # BUG (low): uncaught exception, raw traceback instead of a one-line message
        Path(f"{self.d}/k").write_text("")
        r = cli(self.d, "sync", "pull", "127.0.0.1:1", "--key-file", f"{self.d}/k")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr, r.stderr)

    def test_bad_peer_strings(self):
        # BUG (low): uncaught exception, raw traceback instead of a one-line message
        cli(self.d, "key", "new", "--file", f"{self.d}/k")
        for peer in ("127.0.0.1:abc", "127.0.0.1:", ":80", "127.0.0.1", "127.0.0.1:99999", "[::1]:1"):
            r = cli(self.d, "sync", "pull", peer, "--key-file", f"{self.d}/k")
            self.assertNotEqual(r.returncode, 0, peer)
            self.assertNotIn("Traceback", r.stderr, (peer, r.stderr))

    def test_serve_refuses_all_interfaces_without_an_explicit_override(self):
        # BUG (same as tcp bind test): --host 0.0.0.0 is accepted although the help text promises private addresses only
        cli(self.d, "key", "new", "--file", f"{self.d}/k")
        p = subprocess.Popen([sys.executable, "-m", "sigilnet", "--home", self.d, "sync", "serve", "--host", "0.0.0.0", "--port", "0", "--key-file", f"{self.d}/k",
                              "--seconds", "3"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT})
        try:
            out, err = p.communicate(timeout=20)
        finally:
            p.kill()
        self.assertNotIn("serving", out, "server started on 0.0.0.0")

    def test_serve_on_a_public_address_gives_a_clean_refusal(self):
        # BUG (low): uncaught exception, raw traceback instead of a one-line message
        cli(self.d, "key", "new", "--file", f"{self.d}/k")
        r = cli(self.d, "sync", "serve", "--host", "8.8.8.8", "--port", "0", "--key-file", f"{self.d}/k", "--seconds", "1")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr, r.stderr)

    def test_unreachable_peer_reports_failure_per_thread_and_exit_code(self):
        cli(self.d, "key", "new", "--file", f"{self.d}/k")
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        r = cli(self.d, "sync", "pull", f"127.0.0.1:{port}", "--key-file", f"{self.d}/k", "--thread", "0" * 32)
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAILED", r.stdout)

    def test_thread_prefix_that_matches_nothing_is_not_silently_treated_as_a_full_id_for_a_different_thread(self):
        cli(self.d, "key", "new", "--file", f"{self.d}/k")
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        r = cli(self.d, "sync", "pull", f"127.0.0.1:{port}", "--key-file", f"{self.d}/k", "--thread", "zz")
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
