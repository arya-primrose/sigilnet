"""TorNode / torrc / key files / pid handling. A real tor runs only with DisableNetwork 1 (offline=True); no hidden service is published."""
import base64
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

from sigilnet import torlink as T
from sigilnet.torlink import TorNode, _free_port, make_client_key

from .h4 import ONION, ONION2

PUB = make_client_key()[1]
KNOWN_KEYS = {"DataDirectory", "SocksPort", "ControlPort", "Log", "PidFile", "SafeLogging", "AvoidDiskWrites", "ClientOnionAuthDir", "DisableNetwork", "HiddenServiceDir",
              "HiddenServiceVersion", "HiddenServicePort", "HiddenServiceMaxStreams", "HiddenServiceMaxStreamsCloseCircuit", "HiddenServiceEnableIntroDoSDefense", "HiddenServicePoWDefensesEnabled",
              "UseBridges", "Bridge", "ClientTransportPlugin"}
HAVE_TOR = shutil.which("tor") is not None


def tmp():
    d = Path(tempfile.mkdtemp())
    return d


def lines_ok(cfg):
    for ln in cfg.splitlines():
        key = ln.split(" ", 1)[0]
        assert key in KNOWN_KEYS, f"unexpected torrc line: {ln!r}"
        if key == "SocksPort":
            assert ln.startswith("SocksPort 127.0.0.1:"), ln
        if key == "ControlPort":
            assert ln == "ControlPort 0", ln


class ConfigTest(unittest.TestCase):
    def test_default_config_shape(self):
        for lp in (None, 47200):
            cfg = TorNode(tmp() / "r", local_port=lp, offline=True).config()
            lines_ok(cfg)
            self.assertIn("ControlPort 0", cfg)
            self.assertNotIn("0.0.0.0", cfg)
            self.assertEqual(("HiddenServiceDir" in cfg), bool(lp))
            self.assertNotIn("ExitPolicy", cfg)
            self.assertNotIn("ORPort", cfg)
            self.assertNotIn("DirPort", cfg)
            self.assertNotIn("ExtORPort", cfg)
            self.assertNotIn("TransPort", cfg)
            self.assertNotIn("DNSPort", cfg)
            self.assertNotIn("CookieAuthentication", cfg)

    def test_root_directory_with_a_newline_cannot_add_torrc_lines(self):
        root = tmp() / "x\nSocksPort 0.0.0.0:9999\n#"
        try:
            tn = TorNode(root, local_port=1234, offline=True)
        except (ValueError, OSError):
            return
        cfg = tn.config()
        try:
            lines_ok(cfg)
        except AssertionError as e:
            self.fail("a --home path containing a newline injects torrc lines: " + str(e))

    def test_root_directory_with_a_carriage_return_or_backslash(self):
        for name in ("a\rControlPort 9051", "a\\"):
            with self.subTest(name=name):
                try:
                    tn = TorNode(tmp() / name, local_port=1234, offline=True)
                except (ValueError, OSError):
                    continue
                try:
                    lines_ok(tn.config())
                except AssertionError as e:
                    self.fail(str(e))
                self.assertNotIn("\\\n", tn.config(), "a trailing backslash continues the line in torrc syntax")

    def test_ports_are_coerced_to_integers(self):
        for kw in ({"local_port": "1234\nControlPort 9051"}, {"virtual_port": "1 127.0.0.1:1\nControlPort 9051"}, {"socks_port": "9050\nControlPort 9051"}):
            with self.subTest(kw=kw):
                try:
                    tn = TorNode(tmp() / "r", **{"local_port": 1234, **kw}, offline=True)
                except (ValueError, TypeError, OSError):
                    continue
                try:
                    lines_ok(tn.config())
                except AssertionError as e:
                    self.fail(str(e))

    def test_bridge_lines(self):
        ok = ["Bridge 192.0.2.1:443 AAAA", "  Bridge obfs4 192.0.2.1:443 AAAA cert=x iat-mode=0  ", "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy", "UseBridges 1",
              "Bridge 192.0.2.1:443 \\"]
        bad = ["", "Bridge", "bridge 1.2.3.4:1", "ControlPort 9051", "Bridge x\nControlPort 9051", "Bridge x\rControlPort 9051", "\nBridge x", "SocksPort 0.0.0.0:9050",
               "Bridge\tx", "ExitPolicy accept *:*", "UseBridges\t0", "X Bridge x", "DataDirectory /", "Bridge x ControlPort 9051"]
        for b in bad:
            with self.subTest(bad=b):
                try:
                    tn = TorNode(tmp() / "r", bridge_lines=[b], offline=True)
                except ValueError:
                    continue
                self.assertEqual(tn.config().count("\n"), TorNode(tmp() / "r2", offline=True).config().count("\n") + 2, repr(b))
        for b in ok:
            with self.subTest(ok=b):
                lines_ok(TorNode(tmp() / "r", bridge_lines=[b], offline=True).config())
        cfg = TorNode(tmp() / "r", bridge_lines=["UseBridges 0", "Bridge x"], offline=True).config()
        self.assertEqual(cfg.count("UseBridges"), 1)
        self.assertIn("UseBridges 1", cfg)

    def test_trailing_backslash_bridge_line_cannot_swallow_the_next_bridge_or_option(self):
        cfg = TorNode(tmp() / "r", bridge_lines=["Bridge a \\", "Bridge b"], offline=True).config()
        for ln in cfg.splitlines():
            self.assertFalse(ln.endswith("\\"), "a bridge line ending in a backslash is a torrc line continuation and merges the next line into it")

    @unittest.expectedFailure
    def test_client_transport_plugin_exec_is_operator_supplied_code_execution(self):
        """ACCEPTED BY DESIGN (README: a pluggable transport binary is installed by the operator; bridge lines are a pass-through): `ClientTransportPlugin x exec CMD`
        makes tor run CMD. Anyone who can write node_config.json / run `node init --bridge` already owns the account, so this is documented here, not a bug."""
        with self.assertRaises(ValueError):
            TorNode(tmp() / "r", bridge_lines=["ClientTransportPlugin x exec /bin/sh -c id"], offline=True)


class FileApiTest(unittest.TestCase):
    def setUp(self):
        self.base = tmp()
        self.tn = TorNode(self.base / "root", local_port=1234, offline=True)

    def test_authorize_and_revoke_reject_every_odd_name_without_touching_the_disk(self):
        names = ["../x", "a/b", "", "A", "a" * 33, "a\n", "é", "x.auth", "a b", "..", ".", "a\x00b", "a\\b", "١", "-", "__", "a" * 32 + "\n", "/etc/passwd"]
        outside = self.base / "root" / "hs"
        before = sorted(p.name for p in self.base.rglob("*"))
        for n in names:
            with self.subTest(name=n):
                if re.fullmatch(r"[a-z0-9_-]{1,32}", n) and "\n" not in n:
                    continue
                with self.assertRaises(ValueError):
                    self.tn.authorize(n, PUB)
                with self.assertRaises(ValueError):
                    self.tn.revoke(n)
        self.assertEqual(before, sorted(p.name for p in self.base.rglob("*")))

    def test_authorize_content_is_exactly_one_descriptor_line(self):
        for pub in (PUB, "  " + PUB + "\n", PUB + "\n"):
            p = self.tn.authorize("bob", pub)
            self.assertEqual(p.read_text(), f"descriptor:x25519:{PUB}\n")
        bad = [PUB + "\ndescriptor:x25519:" + PUB, PUB.lower(), PUB[:-1], PUB + "A", "", None, "1" * 52, PUB[:10] + "\x00" + PUB[11:], PUB[:-1] + "١", PUB[:26] + "\n" + PUB[26:]]
        for pub in bad:
            with self.subTest(pub=repr(pub)[:40]):
                with self.assertRaises(ValueError):
                    self.tn.authorize("eve", pub)
        self.assertEqual(self.tn.authorized(), ["bob"])

    def test_authorize_key_file_is_0600_and_the_dirs_are_0700(self):
        old = os.umask(0)
        try:
            p = self.tn.authorize("bob", PUB)
            q = self.tn.add_client_auth(ONION, make_client_key()[0])
        finally:
            os.umask(old)
        for f in (p, q):
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
        for d in (self.tn.root, self.tn.data, self.tn.hs, self.tn.auth_in, self.tn.hs / "authorized_clients"):
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700, d)

    def test_private_client_key_is_never_world_readable_even_for_an_instant(self):
        modes = []
        real = os.open

        def spy(path, flags, mode=0o777, *a, **k):
            if str(path).endswith(".auth_private"):
                modes.append(mode)                                   # the mode the file is CREATED with (before any umask effect)
            return real(path, flags, mode, *a, **k)
        old = os.umask(0o022)
        os.open = spy
        try:
            self.tn.add_client_auth(ONION, make_client_key()[0])
        finally:
            os.open = real
            os.umask(old)
        self.assertTrue(modes)
        self.assertEqual([m for m in modes if m & 0o077], [], f"the private key file was created with mode {[oct(m) for m in modes]} (must be 0600 from the first byte)")
        f = next(self.tn.auth_in.glob("*.auth_private"))
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)

    def test_client_private_key_is_valid_and_never_leaves_its_file(self):
        priv, pub = make_client_key()
        raw = base64.b32decode(priv + "=" * (-len(priv) % 8))
        self.assertEqual(len(raw), 32)
        k = x25519.X25519PrivateKey.from_private_bytes(raw)
        from cryptography.hazmat.primitives import serialization as s
        self.assertEqual(base64.b32encode(k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).decode().rstrip("="), pub)
        p = self.tn.add_client_auth(ONION.upper(), priv + "\n")
        self.assertEqual(p.name, "a" * 56 + ".auth_private")
        self.assertEqual(p.read_text(), f"{'a' * 56}:descriptor:x25519:{priv}\n")
        self.assertNotIn(priv, self.tn.config())
        self.assertNotIn(priv, " ".join(map(str, self.base.rglob("*"))))
        for bad in ("", None, priv[:-1], priv + "\nx", priv.lower(), PUB + PUB):
            with self.assertRaises(ValueError):
                self.tn.add_client_auth(ONION2, bad)
        self.assertEqual(sorted(x.name for x in self.tn.auth_in.iterdir()), ["a" * 56 + ".auth_private"])

    def test_add_client_auth_rejects_odd_onions(self):
        for o in ("../../x", ONION + "/../../etc", ONION[:-6], "", None, ONION + ".onion"):
            with self.subTest(o=o):
                with self.assertRaises(ValueError):
                    self.tn.add_client_auth(o, make_client_key()[0])

    def test_a_client_only_node_refuses_authorize_and_has_no_hs_dir(self):
        tn = TorNode(self.base / "c", local_port=None, offline=True)
        self.assertFalse(tn.hs.exists())
        with self.assertRaises(ValueError):
            tn.authorize("bob", PUB)

    def test_authorized_lists_only_well_formed_names_and_hostname_is_validated(self):
        self.tn.authorize("bob", PUB)
        d = self.tn.hs / "authorized_clients"
        (d / "weird name.auth").write_text("x")
        (d / "notauth.txt").write_text("x")
        self.assertIn("bob", self.tn.authorized())
        for junk in ("evil.onion\nControlPort 9051", "a" * 56 + ".onion.evil", "", "\x00" * 10, ONION.upper(), "a" * 57 + ".onion"):
            (self.tn.hs / "hostname").write_text(junk)
            self.assertIsNone(self.tn.hostname(), junk)
        (self.tn.hs / "hostname").write_text(ONION + "\n")
        self.assertEqual(self.tn.hostname(), ONION)

    def test_revoke_is_idempotent_and_does_not_follow_a_name_to_another_dir(self):
        self.tn.authorize("bob", PUB)
        self.assertTrue(self.tn.revoke("bob"))
        self.assertFalse(self.tn.revoke("bob"))


class PidTest(unittest.TestCase):
    def setUp(self):
        self.base = tmp()
        self.tn = TorNode(self.base / "root", local_port=1234, offline=True)
        self.procs = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for p in self.procs:
            try:
                p.kill()
                p.wait(3)
            except Exception:                                        # noqa: BLE001
                pass

    def spawn(self, argv, code="import time; time.sleep(60)"):
        p = subprocess.Popen(argv, executable=sys.executable, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        time.sleep(0.3)
        return p

    def point(self, pid):
        self.tn.pidfile.write_text(f"{pid}\n")

    def test_pid_file_pointing_at_an_unrelated_process_is_never_signalled(self):
        victims = [self.spawn(["sleep", "-c", "import time; time.sleep(60)"]),
                   self.spawn(["tor", "-c", "import time; time.sleep(60)", str(self.base / "other" / "torrc")]),                # named tor, somebody else's torrc
                   self.spawn(["python3", "-c", "import time; time.sleep(60)", str(self.tn.torrc)]),                            # our torrc in argv but not tor
                   self.spawn(["tor", "-c", "import time; time.sleep(60)", "--x=" + str(self.tn.torrc)]),                      # substring only
                   self.spawn(["/tmp/tor-fake/notor", "-c", "import time; time.sleep(60)", str(self.tn.torrc)])]
        for v in victims:
            with self.subTest(argv=open(f"/proc/{v.pid}/cmdline", "rb").read()[:60]):
                self.point(v.pid)
                self.assertFalse(self.tn.reload())
                time.sleep(0.2)
                self.assertIsNone(v.poll(), "reload() signalled a process that is not our tor")

    HUP_CODE = "import signal, sys, time; signal.signal(signal.SIGHUP, lambda *a: sys.exit(7)); time.sleep(60)"      # a dummy tor that CATCHES SIGHUP (M1c: reload() only signals a process that has installed its handler)

    def wait_handler(self, pid, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end and not TorNode._handles_sighup(pid):
            time.sleep(0.05)

    def test_our_tor_lookalike_is_signalled_positive_control(self):
        v = self.spawn(["tor", "-c", self.HUP_CODE, str(self.tn.torrc)])
        self.point(v.pid)
        self.wait_handler(v.pid)
        self.assertTrue(self.tn.reload())
        v.wait(3)
        self.assertEqual(v.returncode, 7, "the SIGHUP was delivered to the handler (exit 7), not the default action")

    def test_a_process_without_a_sighup_handler_is_not_signalled(self):
        v = self.spawn(["tor", "-c", "import time; time.sleep(60)", str(self.tn.torrc)])
        self.point(v.pid)
        self.assertFalse(self.tn.reload())
        time.sleep(0.3)
        self.assertIsNone(v.poll(), "the default action of SIGHUP would have killed it")

    def test_garbage_and_hostile_pid_files(self):
        me = os.getpid()
        for raw in ("", "\n", "abc", "-1", "0", "1", "99999999999999999999999", "1e3", str(me), "../self", f"{me}\n{me}", " 12 x", "\x00", "4294967296", f"{me}.0"):
            with self.subTest(raw=raw):
                self.tn.pidfile.write_text(raw)
                self.assertFalse(self.tn.reload())
        self.tn.pidfile.unlink()
        self.assertFalse(self.tn.reload())

    def test_dead_pid_and_reused_pid_number(self):
        p = subprocess.Popen(["true"])
        p.wait()
        self.point(p.pid)
        self.assertFalse(self.tn.reload())

    def test_pid_file_being_a_directory_or_a_fifo_does_not_hang_or_crash(self):
        self.tn.pidfile.mkdir()
        self.assertFalse(self.tn.reload())
        self.tn.pidfile.rmdir()
        os.mkfifo(self.tn.pidfile)
        res = []
        th = threading.Thread(target=lambda: res.append(self.tn.reload()), daemon=True)
        th.start()
        th.join(3)
        hung = th.is_alive()
        if hung:                                                    # release the blocked open() so the thread can end
            fd = os.open(self.tn.pidfile, os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
            th.join(3)
        self.assertFalse(hung, "reload() blocked forever on a pid file that is a fifo (open() of a fifo with no writer)")
        self.assertEqual(res, [False])

    def test_wrapper_named_tor_bin_still_reloads(self):
        # tor_bin may be a path like /usr/local/bin/tor (name == tor) -- a custom name cannot be reloaded from the CLI; documenting behaviour
        v = self.spawn(["/opt/whatever/tor", "-c", self.HUP_CODE, str(self.tn.torrc)])
        self.point(v.pid)
        self.wait_handler(v.pid)
        self.assertTrue(self.tn.reload())
        v.wait(3)
        self.assertEqual(v.returncode, 7)


@unittest.skipUnless(HAVE_TOR, "tor not installed")
class RealTorOfflineTest(unittest.TestCase):
    def start(self, sub="root", **kw):
        tn = TorNode(tmp() / sub, local_port=_free_port(), offline=True, **kw)
        self.addCleanup(tn.stop)
        tn.start(timeout=15)
        return tn

    @staticmethod
    def listeners(pid):
        inodes = set()
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            try:
                t = os.readlink(fd)
            except OSError:
                continue
            m = re.fullmatch(r"socket:\[(\d+)\]", t)
            if m:
                inodes.add(m.group(1))
        out = []
        for proto in ("tcp", "tcp6", "udp", "udp6", "raw", "raw6"):
            try:
                rows = Path(f"/proc/net/{proto}").read_text().splitlines()[1:]
            except OSError:
                continue
            for r in rows:
                f = r.split()
                if f[9] in inodes and (not proto.startswith("tcp") or f[3] == "0A"):
                    out.append((proto, f[1]))
        return out

    def test_nothing_listens_on_a_public_address(self):
        """NB: with DisableNetwork 1 tor opens NO listeners at all (not even the SocksPort), so this only proves the offline process is clean; the
        SocksPort address itself can only be checked from the torrc text (ConfigTest)."""
        tn = self.start()
        time.sleep(0.5)
        for proto, addr in self.listeners(tn.proc.pid):
            self.assertTrue(addr.startswith("0100007F:") or addr.startswith("00000000000000000000000001000000:"), f"tor listens on a non-loopback address: {proto} {addr}")

    def test_files_are_private_and_pid_file_matches(self):
        tn = self.start()
        self.assertEqual(stat.S_IMODE(tn.torrc.stat().st_mode), 0o600)
        for d in (tn.root, tn.data, tn.hs):
            self.assertEqual(stat.S_IMODE(d.stat().st_mode) & 0o077, 0, d)
        self.assertEqual(int(tn.pidfile.read_text()), tn.proc.pid)
        self.assertTrue(tn.hostname())

    def test_reload_from_another_object_signals_our_tor_and_tor_survives(self):
        tn = self.start()
        cli = TorNode(tn.root, local_port=tn.local_port, offline=True, socks_port=tn.socks_port)
        self.assertEqual(cli._running_pid(), tn.proc.pid)
        cli.authorize("bob", PUB)
        time.sleep(0.5)
        self.assertIsNone(tn.proc.poll())
        self.assertTrue(cli.revoke("bob"))
        time.sleep(0.3)
        self.assertIsNone(tn.proc.poll())
        self.assertIn("reload signal", tn._log_text())
        self.assertFalse(cli.reload() is False)

    def test_odd_but_valid_paths_start_tor(self):
        for sub in ("with space", "ünï", "a'b", 'a"b', "a;b", "a$b", "a%b", "a#b"):
            with self.subTest(sub=sub):
                tn = TorNode(tmp() / sub, local_port=_free_port(), offline=True)
                try:
                    try:
                        tn.start(timeout=10)
                    except T.TorError as e:
                        self.fail(f"tor did not start with --home containing {sub!r}: {e}")
                    self.assertTrue(tn.hostname())
                finally:
                    tn.stop()


if __name__ == "__main__":
    unittest.main()
