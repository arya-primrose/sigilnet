"""Round A of the sigilnet rename: the break with the old project name is REAL (old contexts are rejected), every signature/KDF/AEAD context carries the new name,
and no old name is left in the package."""
import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sigilnet import envelope as V
from sigilnet import event as E
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.tests.test_capsule import Base as CapsuleBase

PKG = Path(__file__).resolve().parents[1]
OLD = {"event": b"arya_net/v1/event\0", "env": b"arya_net/v1/env\0"}


def source_files():
    for p in sorted(PKG.rglob("*.py")):
        if "tests" in p.relative_to(PKG).parts[0]:
            continue
        yield p


class Contexts(unittest.TestCase):
    def test_every_context_constant_is_new_and_distinct(self):
        found = {}
        for p in source_files():
            for node in ast.walk(ast.parse(p.read_text())):
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id.lstrip("_").endswith("CTX") for t in node.targets):
                    v = ast.literal_eval(node.value)
                    found[f"{p.name}:{node.targets[0].id}"] = v
        self.assertGreaterEqual(len(found), 10, found)
        for k, v in found.items():
            self.assertTrue(v.startswith(b"sigilnet/v1/") and v.endswith(b"\0"), (k, v))
        self.assertEqual(len(set(found.values())), len(found), "two contexts are equal: a signature for one purpose could verify for another")

    def test_every_literal_handed_to_a_crypto_call_carries_the_new_name(self):
        """A bytes literal that is a DIRECT argument (or a concatenated part of one) of hmac.new/encrypt/decrypt/HKDF/Scrypt/sha256 is a context, AAD, info or
        salt label: it must carry the new name. (Names/constants like *_CTX are covered by the test above.)"""
        calls = {"new", "encrypt", "decrypt", "HKDF", "Scrypt", "sha256", "sha512", "blake2b"}

        def leaves(n):
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                yield from leaves(n.left)
                yield from leaves(n.right)
            elif isinstance(n, ast.Constant):
                yield n

        bad, seen = [], 0
        for p in source_files():
            for node in ast.walk(ast.parse(p.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name not in calls:
                    continue
                for arg in list(node.args) + [k.value for k in node.keywords]:
                    for c in leaves(arg):
                        if isinstance(c.value, bytes) and len(c.value) > 3:
                            seen += 1
                            if not c.value.startswith(b"sigilnet"):
                                bad.append((p.name, node.lineno, c.value))
        self.assertGreaterEqual(seen, 2, "the scan found nothing to check: it is broken")
        self.assertEqual(bad, [])

    def test_no_old_name_in_the_package(self):
        pat = re.compile(r"arya[_ -]?net", re.I)
        hits = [(str(p.relative_to(PKG)), i) for p in PKG.rglob("*") if p.is_file() and p.suffix in (".py", ".md") and "__pycache__" not in p.parts
                for i, line in enumerate(p.read_text().splitlines(), 1) if pat.search(line) and p.name != "test_rename.py" and not (p.name == "cli.py" and ("legacy" in line or "old arya_net home" in line))]
        self.assertEqual(hits, [])


class IdsAreDomainSeparated(unittest.TestCase):
    def test_agent_id_and_event_id_are_not_the_bare_hashes(self):
        import base64
        import hashlib
        from sigilnet import keys as K
        a = Identity.generate("a")
        bare = base64.b32encode(hashlib.sha256(a.sign_key_bytes() if hasattr(a, "sign_key_bytes") else bytes.fromhex(a.sign_pub)).digest()[:20]).decode().lower()
        self.assertNotEqual(a.id, bare)
        g = make_genesis(a, "t", [])
        self.assertNotEqual(event_id(g), hashlib.sha256(E.signed_bytes(g)).hexdigest()[:32])
        self.assertEqual(event_id(g), hashlib.sha256(E.EVENT_ID_CTX + E.signed_bytes(g)).hexdigest()[:32])
        self.assertEqual(K.agent_id(bytes.fromhex(a.sign_pub)), a.id)


class OldContextsAreRejected(unittest.TestCase):
    """A thing built exactly as the old project built it must NOT verify: that is the proof that the break is real."""

    def setUp(self):
        self.a = Identity.generate("a")
        self.g = make_genesis(self.a, "t", [])
        self.m = Mirror(tempfile.mkdtemp() + "/m", rate_limit=False)
        self.assertTrue(self.m.ingest(self.g).ok)
        self.tid = event_id(self.g)

    def test_event_signed_with_the_old_context_is_refused(self):
        old, E.EVENT_CTX = E.EVENT_CTX, OLD["event"]
        try:
            ev = Writer(self.a, self.m.threads[self.tid]).post("old world")
        finally:
            E.EVENT_CTX = old
        res = self.m.ingest(ev)
        self.assertFalse(res.ok, res)
        self.assertNotIn(event_id(ev), self.m.threads[self.tid].stored)

    def test_genesis_signed_with_the_old_context_is_refused(self):
        old, E.EVENT_CTX = E.EVENT_CTX, OLD["event"]
        try:
            g = make_genesis(self.a, "old thread", [])
        finally:
            E.EVENT_CTX = old
        self.assertFalse(Mirror(tempfile.mkdtemp() + "/m", rate_limit=False).ingest(g).ok)

    def test_envelope_sealed_with_the_old_context_does_not_open(self):
        key, tid = os.urandom(32), "ab" * 16
        old, V.ENV_CTX = V.ENV_CTX, OLD["env"]
        try:
            env = V.seal_event(key, tid, tid, {"x": 1})
        finally:
            V.ENV_CTX = old
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(key, env, tid)

    def test_sync_request_signed_with_the_old_context_is_refused(self):
        from sigilnet import sync as S
        srv = S.SyncServer(self.m, identity=self.a)
        b = Identity.generate("b")
        old, S.CTX = S.CTX, b"arya_net/v1/sync\0"
        try:
            req = S.sign_request(b, {"t": "summary", "thread": self.tid}, aud=self.a.id)
        finally:
            S.CTX = old
        self.assertNotEqual(S.Loopback(srv).request(req).get("t"), "summary")


class OldCapsulePrefix(CapsuleBase):
    def test_real_capsule_with_only_the_prefix_swapped_is_refused(self):
        from sigilnet import capsule as C
        block, cid, fp = self.create()
        self.assertEqual(C.PREFIX, "SIGILNET-CAPSULE-1")
        self.assertEqual(C.decode_capsule(block, now=self.clock())["thread"], self.tid)       # the unmodified block is accepted ...
        old = "ARYA-CAPSULE-1 " + block.split(" ", 1)[1]
        self.assertEqual(len(old.split()), 3)                                                 # ... and the swapped one has the right shape, valid body and checksum
        with self.assertRaises(C.CapsuleError) as cm:
            C.decode_capsule(old, now=self.clock())
        self.assertEqual(str(cm.exception), "not a capsule")


class Naming(unittest.TestCase):
    def run_cli(self, home_env, *args, home=None, cwd=None):
        env = {k: v for k, v in os.environ.items() if k not in ("SIGILNET_HOME", "ARYA_NET_HOME", "HOME")}
        env.update(home_env)
        env["PYTHONPATH"] = str(PKG.parent)                         # the working directory may be anywhere (home lookup walks up from it)
        return subprocess.run([sys.executable, "-m", "sigilnet", *args], capture_output=True, text=True, env=env, cwd=cwd or str(PKG.parent))

    def test_cli_runs_as_sigilnet_and_reads_the_new_env_var_only(self):
        new, old, fake_home = (tempfile.mkdtemp() for _ in range(3))
        r = self.run_cli({"SIGILNET_HOME": new, "HOME": fake_home}, "id", "init", "x")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(Path(new, "identity.json").exists())
        work = tempfile.mkdtemp()
        r = self.run_cli({"ARYA_NET_HOME": old, "HOME": fake_home}, "id", "init", "y", cwd=work)
        self.assertFalse(Path(old, "identity.json").exists(), "the old env var must not be honoured")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no .sigilnet found", r.stderr)                 # and there is no ~/.sigilnet default any more (DESIGN_node_daemon.md P1)
        self.assertFalse(Path(fake_home, ".sigilnet").exists())

    def test_old_arya_net_home_is_never_used_or_touched(self):
        fake_home, work = tempfile.mkdtemp(), tempfile.mkdtemp()
        Path(fake_home, ".arya_net").mkdir()
        Path(fake_home, ".arya_net", "identity.json").write_text("{}")
        r = self.run_cli({"HOME": fake_home}, "list", cwd=work)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no .sigilnet found", r.stderr)
        self.assertEqual(sorted(os.listdir(Path(fake_home, ".arya_net"))), ["identity.json"])
        self.assertFalse(Path(fake_home, ".sigilnet").exists())


if __name__ == "__main__":
    unittest.main()
