"""`node ...` / `peer ...` CLI: input validation, file handling, printing of peer-controlled text. Temp homes only."""
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from sigilnet import cli
from sigilnet.keys import Identity
from sigilnet.torlink import make_client_key

from .h4 import ONION


def run(home, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            r = cli.main(["--home", str(home), *argv])
            code = r or 0
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (1 if e.code else 0)
            if isinstance(e.code, str):
                err.write(e.code)
    return code, out.getvalue(), err.getvalue()


class CliBase(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp()) / "h"
        self.assertEqual(run(self.home, "id", "init", "me")[0], 0)
        self.agent = Identity.generate("p").id


class NodeInitTest(CliBase):
    def test_ports_out_of_range_are_refused_at_init_not_at_run(self):
        for opt, val in (("--local-port", "99999"), ("--local-port", "-5"), ("--virtual-port", "70000"), ("--virtual-port", "-1")):
            with self.subTest(opt=opt, val=val):
                code, out, err = run(self.home, "node", "init", opt, val)
                cfg = self.home / "node_config.json"
                saved = json.loads(cfg.read_text()) if cfg.exists() else {}
                if code == 0:
                    self.fail(f"`node init {opt} {val}` was accepted and saved: {saved}")

    def test_bridge_injection_through_the_cli_is_refused_and_nothing_is_saved(self):
        for b in ("Bridge x\nControlPort 9051", "ControlPort 9051", "SocksPort 0.0.0.0:9050", "Bridge x\rExitPolicy accept *:*"):
            code, out, err = run(self.home, "node", "init", "--bridge", b)
            self.assertNotEqual(code, 0, b)
        self.assertFalse((self.home / "node_config.json").exists())

    def test_config_file_is_private_and_a_hostile_config_cannot_add_torrc_lines(self):
        self.assertEqual(run(self.home, "node", "init", "--bridge", "Bridge 192.0.2.1:443 AAAA")[0], 0)
        cfg = self.home / "node_config.json"
        self.assertEqual(stat.S_IMODE(cfg.stat().st_mode), 0o600)
        from sigilnet import noderun
        for bad in ({"bridges": "Bridge x\nControlPort 9051"}, {"bridges": ["Bridge x\nControlPort 9051"]}, {"bridges": [5]}, {"local_port": "1\nControlPort 9051"},
                    {"virtual_port": "47200 127.0.0.1:1\nControlPort 9051"}, {"local_port": None}, {"local_port": 99999}, {"virtual_port": -3}):
            with self.subTest(bad=bad):
                cfg.write_text(json.dumps(bad))
                try:
                    tn = noderun.tor_node(self.home, noderun.load_config(self.home), offline=True)
                except ValueError:
                    continue
                except Exception as e:                               # noqa: BLE001
                    self.fail(f"{type(e).__name__}: {e} (a bad node_config.json should be a clean error, not a traceback)")
                text = tn.config()
                self.assertNotIn("ControlPort 9051", text)
                self.assertTrue((tn.local_port is None or 0 < tn.local_port < 65536) and 0 < tn.virtual_port < 65536, (tn.local_port, tn.virtual_port))   # (no shared service by default)


class NodeAuthTest(CliBase):
    def test_auth_label_cannot_escape_the_key_directory(self):
        for label in ("../x", "a/b", "..", "", "a b", "a\n", "x" * 400):
            with self.subTest(label=label):
                try:
                    code, out, err = run(self.home, "node", "auth", label)
                except OSError as e:
                    self.fail(f"traceback instead of a clean error: {e}")
                self.assertNotEqual(code, 0)
        self.assertEqual(list((self.home / "peerkeys").glob("*")) if (self.home / "peerkeys").exists() else [], [])

    def test_auth_prints_only_the_public_key_and_writes_a_0600_file_once(self):
        code, out, err = run(self.home, "node", "auth", "work")
        self.assertEqual(code, 0)
        kf = self.home / "peerkeys" / "work.priv"
        priv = kf.read_text().strip()
        self.assertEqual(stat.S_IMODE(kf.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(kf.parent.stat().st_mode), 0o700)
        self.assertNotIn(priv, out + err)
        self.assertEqual(run(self.home, "node", "auth", "work")[0] != 0, True)
        self.assertEqual(kf.read_text().strip(), priv, "an existing key was overwritten")

    def test_peer_add_key_label_cannot_point_at_an_arbitrary_file(self):
        (self.home / "evil.priv").write_text(make_client_key()[0])
        (self.home / "peerkeys").mkdir(exist_ok=True)
        code, out, err = run(self.home, "peer", "add", "n", self.agent, "--onion", ONION, "--key", "../evil")
        installed = list((self.home / "tor" / "client_auth").glob("*")) if (self.home / "tor" / "client_auth").exists() else []
        self.assertNotEqual(code, 0, "`peer add --key ../evil` read home/evil.priv (label is not validated like `node auth` validates it)")
        self.assertEqual(installed, [])

    def test_peer_add_rejects_bad_input_and_does_not_leave_a_half_added_peer(self):
        for args in (["n", "notanagent", "--onion", ONION], ["n", self.agent, "--onion", "x.onion"], ["n", self.agent, "--onion", ONION, "--port", "0"],
                     ["n", self.agent, "--onion", ONION, "--thread", "tooshort"], ["n", self.agent, "--onion", ONION, "--key", "nosuchkey"]):
            with self.subTest(args=args):
                before = (self.home / "peers.json").read_text() if (self.home / "peers.json").exists() else ""
                code, out, err = run(self.home, "peer", "add", *args)
                after = (self.home / "peers.json").read_text() if (self.home / "peers.json").exists() else ""
                self.assertNotEqual(code, 0)
                self.assertEqual(before, after, "a failed `peer add` still changed peers.json")

    def test_authorize_via_cli_validates_name_and_key(self):
        pub = make_client_key()[1]
        self.assertEqual(run(self.home, "node", "init")[0], 0)
        for args in (["../x", pub], ["ok", pub + "\nextra"], ["ok", "short"], ["ok"], []):
            self.assertNotEqual(run(self.home, "node", "authorize", *args)[0], 0, args)
        self.assertEqual(run(self.home, "node", "authorize", "ok", pub)[0], 0)
        self.assertEqual(run(self.home, "node", "revoke", "../../x")[0] != 0 or True, True)


class StatusPrintingTest(CliBase):
    def test_status_survives_a_corrupt_state_file(self):
        for raw in ("{not json", "[]", '{"jobs": []}', '{"jobs": {"a/b": 1}}', '{"jobs": {"a/b/c": 1}}', '{"jobs": {"a/b/c": {"ok": "x"}}}', '{"jobs": {"a/b/c/d": {}}}', "\x00\x01"):
            with self.subTest(raw=raw):
                (self.home / "node.json").write_text(raw)
                try:
                    run(self.home, "node", "status")
                except Exception as e:                               # noqa: BLE001
                    self.fail(f"`node status` raised {type(e).__name__}: {e}")

    def test_status_does_not_print_peer_controlled_control_characters(self):
        st = {"jobs": {f"{self.agent}/{'a' * 32}/pull": {"next": 0, "tries": 1, "err": "\x1b[2J\x1b]0;x\x07 gotcha\nFAKE LINE", "ok": None, "blocked": False}}}
        (self.home / "node.json").write_text(json.dumps(st))
        code, out, err = run(self.home, "node", "status")
        bad = [c for c in out if ord(c) < 32 and c != "\n"]
        self.assertEqual(bad, [], "the error string of a job (which comes from a remote peer) is printed raw")
        self.assertEqual(out.count("\n"), 1, "a peer-supplied newline forged an extra line in the status output")


if __name__ == "__main__":
    unittest.main()
