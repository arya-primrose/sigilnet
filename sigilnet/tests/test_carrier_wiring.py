"""Round B2: the protocol layer talks to carrier.Carrier only. (1) the whole protocol runs over the FAKE carrier in an interpreter where torlink/noderun cannot be
imported; (2) public doors are refused on a carrier that does not hide the host's address; (3) capsules and peers.json carry typed endpoints and refuse what no
carrier here supports; (4) sync audience stays the agent id, never an endpoint; (5) no secret is printed by the CLI."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sigilnet import capsule as C
from sigilnet import sync as S
from sigilnet.build import make_genesis
from sigilnet.carrier import CarrierError
from sigilnet.doors import Doors
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.sync import SyncServer
from sigilnet.tests.fake_carrier import FakeCarrier, FakeNet

ROOT = Path(__file__).resolve().parents[2]

BLOCKER = '''
import sys
class Block:
    def find_spec(self, name, path=None, target=None):
        if name in ("sigilnet.torlink", "sigilnet.noderun"):
            raise ImportError("BLOCKED: " + name)
sys.meta_path.insert(0, Block())
from sigilnet.tests import fake_e2e
print(fake_e2e.run())
assert "sigilnet.torlink" not in sys.modules and "sigilnet.noderun" not in sys.modules
'''


class NoHiddenTorDependency(unittest.TestCase):
    def test_whole_protocol_over_the_fake_carrier_with_torlink_blocked(self):
        r = subprocess.run([sys.executable, "-c", BLOCKER], capture_output=True, text=True, cwd=str(ROOT), timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("E2E OK", r.stdout)

    def test_the_blocker_really_blocks(self):
        r = subprocess.run([sys.executable, "-c", BLOCKER.split("from sigilnet.tests")[0] + "import sigilnet.torlink"], capture_output=True, text=True, cwd=str(ROOT), timeout=240)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BLOCKED: sigilnet.torlink", r.stderr)

    @staticmethod
    def torlink_imports(src: str) -> list:
        """Every way a module can name torlink: `from .torlink import x`, `from . import torlink`, `from sigilnet import torlink`, `import sigilnet.torlink`,
        importlib.import_module("...torlink"), __import__("...torlink"), importlib.util.find_spec(...)."""
        import ast
        hits = []
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[-1] == "torlink" or any(a.name == "torlink" for a in node.names):
                    hits.append(node.lineno)
            elif isinstance(node, ast.Import):
                if any("torlink" in a.name for a in node.names):
                    hits.append(node.lineno)
            elif isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name in ("import_module", "__import__", "find_spec", "import_from_string") and any(isinstance(a, ast.Constant) and isinstance(a.value, str) and "torlink" in a.value for a in node.args):
                    hits.append(node.lineno)
        return hits

    def test_protocol_modules_do_not_import_torlink(self):
        offenders = []
        for p in (ROOT / "sigilnet").glob("*.py"):
            if p.name in ("torlink.py", "noderun.py"):                # noderun is the composition root; cli.py reaches Tor only through it (lazy `from . import noderun`)
                continue
            if self.torlink_imports(p.read_text()):
                offenders.append(p.name)
        self.assertEqual(offenders, [], "only torlink.py and the composition root noderun.py may name the Tor carrier")

    def test_the_scan_sees_every_spelling(self):
        for src in ("from .torlink import TorError", "from . import torlink", "from . import torlink as t", "from sigilnet import torlink", "import sigilnet.torlink",
                    "import sigilnet.torlink as t", "import importlib\nimportlib.import_module('sigilnet.torlink')", "__import__('sigilnet.torlink')",
                    "import importlib.util\nimportlib.util.find_spec('sigilnet.torlink')", "def f():\n    from .torlink import X"):
            self.assertTrue(self.torlink_imports(src), src)
        for src in ("from .carrier import Carrier", "from . import carrier", "x = 'torlink is a word'", "import os"):
            self.assertFalse(self.torlink_imports(src), src)

    def test_cli_reaches_tor_only_through_noderun(self):
        src = (ROOT / "sigilnet" / "cli.py").read_text()
        self.assertFalse(self.torlink_imports(src))
        self.assertIn("from . import noderun", src)


class PublicDoorsNeedIpHiding(unittest.TestCase):
    def setUp(self):
        self.net = FakeNet()
        self.c = FakeCarrier(self.net, "owner")
        self.c.start()
        self.owner = Identity.generate("o")
        g = make_genesis(self.owner, "t", [])
        self.m = Mirror(tempfile.mkdtemp() + "/m", rate_limit=False)
        self.m.ingest(g)
        self.srv = SyncServer(self.m, identity=self.owner)
        self.c.open_door("pub-read", "read")
        self.c.open_door("pub-inbox", "inbox")
        _, pub = self.c.new_credential()
        self.c.open_door("peer-x", "peer", credential=pub)

    def test_refused_without_the_capability_unless_told(self):
        said = []
        d = Doors(self.c, self.srv, said.append, {})
        self.addCleanup(d.stop)
        d.sync()
        self.assertEqual(sorted(d.servers), ["peer-x"], "only the non-public door is served")
        self.assertTrue(any("does not hide" in x for x in said), said)
        d.stop()                                                     # (the same loopback ports: the first listeners must be gone)
        d2 = Doors(self.c, self.srv, lambda *a: None, {}, allow_public_without_ip_hiding=True)
        self.addCleanup(d2.stop)
        d2.sync()
        self.assertEqual(sorted(d2.servers), ["peer-x", "pub-inbox", "pub-read"])

    def test_a_carrier_that_hides_the_ip_serves_them(self):
        class Hiding(FakeCarrier):
            capabilities = frozenset({"hides_ip"})
        c = Hiding(self.net, "hider")
        c.start()
        c.open_door("pub-read", "read")
        d = Doors(c, self.srv, lambda *a: None, {})
        self.addCleanup(d.stop)
        d.sync()
        self.assertEqual(sorted(d.servers), ["pub-read"])


class TypedEndpointsEverywhere(unittest.TestCase):
    def test_a_capsule_for_another_carrier_type_is_refused_at_accept(self):
        import sigilnet.tests.test_capsule as T

        class Case(T.Base):
            def runTest(self):
                pass
        t = Case()
        t.setUp()
        block, cid, fp = t.create()
        c = C.decode_capsule(block, now=t.clock())
        with self.assertRaises(C.CapsuleError) as cm:
            C.accept(t.jh, FakeCarrier(FakeNet(), "other"), t.joiner, block, C.fingerprint(t.owner.id), clock=t.clock)
        self.assertIn("needs a carrier of one of ['onion']", str(cm.exception))
        self.assertEqual(c["joins"][0]["endpoint"]["type"], "onion")

    def test_a_join_request_naming_a_foreign_endpoint_type_is_refused(self):
        import sigilnet.tests.test_capsule as T

        class Case(T.Base):
            def runTest(self):
                pass
        t = Case()
        t.setUp()
        block, cid, fp = t.create()
        tok = C.decode_capsule(block, now=t.clock())["token"]
        x = Identity.generate("x")
        r = t.server.handle(T.sreq(x, tok, offers=[{"endpoint": {"type": "fake", "addr": "x.fake:1"}, "credential": {"type": "fake", "key": "0" * 64}}]))
        self.assertEqual(r, {"t": "refused"})
        self.assertEqual(len(C.pending(t.oh, t.clock)), 0, "a refused request does not burn the token")

    def test_add_normalizes_an_upper_case_onion_and_the_reader_skips_a_hand_edited_one(self):
        from sigilnet.node import PeerBook
        d = Path(tempfile.mkdtemp())
        a, b = Identity.generate("a").id, Identity.generate("b").id
        book = PeerBook(d / "peers.json")
        book.add(a, "upper", {"type": "onion", "addr": ("A" * 56 + ".ONION:47200")})
        self.assertEqual(book.all()[a]["endpoint"]["addr"], "a" * 56 + ".onion:47200", "add() stores the normalized (lower-case) form")
        raw = json.loads((d / "peers.json").read_text())
        raw["peers"][b] = {"name": "hand", "endpoint": {"type": "onion", "addr": "B" * 56 + ".ONION:47200"}, "threads": []}      # a hand-edited, not normalized record
        (d / "peers.json").write_text(json.dumps(raw))
        self.assertEqual(book.all()[b]["endpoints"], [], "the reader requires the exact normalized form; a hand-edited upper-case endpoint is left out (M1a: the peer itself stays)")

    def test_old_format_records_are_skipped_not_fatal(self):
        from sigilnet.node import PeerBook
        d = Path(tempfile.mkdtemp())
        a, b = Identity.generate("a").id, Identity.generate("b").id
        (d / "peers.json").write_text(json.dumps({"peers": {a: {"name": "old", "onion": "a" * 56 + ".onion", "port": 47200, "threads": []},
                                                            b: {"name": "new", "endpoint": {"type": "onion", "addr": "b" * 56 + ".onion:47200"}, "threads": []}}}))
        got = PeerBook(d / "peers.json").all()
        self.assertIsNone(got[a]["endpoint"], "the old {onion, port} shape carries no endpoint: the node never dials it (it may still dial us)")
        self.assertEqual(got[b]["endpoint"]["addr"], "b" * 56 + ".onion:47200")

    def test_sync_audience_is_the_agent_id_whatever_the_carrier(self):
        a, b, c = Identity.generate("a"), Identity.generate("b"), Identity.generate("c")
        m = Mirror(tempfile.mkdtemp() + "/m", rate_limit=False)
        g = make_genesis(a, "t", [(b, "member")])
        m.ingest(g)
        tid = event_id(g)
        srv = S.Loopback(SyncServer(m, identity=a))
        ok = srv.request(S.sign_request(b, {"t": "summary", "thread": tid}, aud=a.id))
        self.assertNotEqual(ok.get("t"), "unknown")
        srv_c = S.Loopback(SyncServer(Mirror(tempfile.mkdtemp() + "/m", rate_limit=False), identity=c))
        replay = srv_c.request(S.sign_request(b, {"t": "summary", "thread": tid}, aud=a.id))        # a captured request replayed at ANOTHER server
        self.assertIn(replay.get("t"), ("unknown", "refused", "error"))


class CliDoesNotFoldLookalikes(unittest.TestCase):
    def test_peer_add_and_guest_refuse_a_kelvin_sign_onion(self):
        home = tempfile.mkdtemp()
        env = {**os.environ, "SIGILNET_HOME": home}
        run = lambda *a: subprocess.run([sys.executable, "-m", "sigilnet", *a], capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=240)
        self.assertEqual(run("id", "init", "me").returncode, 0)
        evil = "\u212a" + "a" * 55 + ".onion"                       # str.lower() would fold this onto an ASCII 'k'
        agent = Identity.generate("p").id
        r = run("peer", "add", "p", agent, "--onion", evil)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual(run("peer", "list").stdout.count(agent), 0, "nothing was added")
        ok = run("peer", "add", "p", agent, "--onion", "a" * 56 + ".onion")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        r = run("guest", "pull", "a" * 32, "--read", evil)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)


class NoSecretOnTheTerminal(unittest.TestCase):
    def test_node_auth_prints_only_the_public_key(self):
        home = tempfile.mkdtemp()
        env = {**os.environ, "SIGILNET_HOME": home}
        run = lambda *a: subprocess.run([sys.executable, "-m", "sigilnet", *a], capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=240)
        self.assertEqual(run("id", "init", "me").returncode, 0)
        r = run("node", "auth", "lbl")
        self.assertEqual(r.returncode, 0, r.stderr)
        secret = json.loads(Path(home, "peerkeys", "lbl.priv").read_text())
        self.assertEqual(set(secret), {"type", "key"})
        self.assertNotIn(secret["key"], r.stdout + r.stderr)
        self.assertEqual(oct(Path(home, "peerkeys", "lbl.priv").stat().st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
