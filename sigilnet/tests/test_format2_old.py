"""A format-2 thread against the OLD software (the parent tree, or the genuine v0.1.1 named by SIGIL_OLD_TREE): the old client is refused WITH THE TEXT by this release's server (its job
error), the old node shows it in `peer list`'s source (the job table) and its log, and an old Mirror refuses a format-2 genesis it should never have been given."""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from sigilnet import sync as S
from sigilnet import version as V
from sigilnet.build import Writer

from .test_format2_rotate import World2
from .test_version_gate import TheDeployedTreeAsClient as _Base
from .test_version import fake_pong


class OldAgainstFormat2(_Base):
    def setUp(self):
        self.w = World2(2)
        self.arya, self.sansa = self.w.ids["arya"], self.w.ids["sansa"]
        self.m = self.w.m
        w = Writer(self.sansa, self.m.threads[self.w.tid])
        self.assertTrue(self.m.ingest(w.ext("t", {"a": 1})).ok)
        self.tid = self.w.tid
        self.dir = Path(tempfile.mkdtemp())
        self.sansa.save(self.dir / "sansa.json")

    def test_the_old_client_is_refused_with_the_format_text(self):
        r = self.old_pull(self.server())
        self.assertFalse(r["ok"])
        self.assertTrue(r["why"].startswith("thread uses format 2, the peer reads format 1"), r["why"])
        self.assertEqual(r["held"], 0)

    def test_the_old_node_shows_the_text_as_its_job_error_and_in_its_log(self):
        r = self.old_node_status(self.server())
        text = V.refusal(V.decl(), None, 2)
        errs = [str(j.get("error", "")) for j in r["status"] if isinstance(j, dict)]
        self.assertTrue(any(text in e for e in errs), (errs, r["status"]))
        self.assertTrue(any(text in line for line in r["log"]), r["log"])

    def test_an_old_mirror_refuses_a_format_2_genesis_and_never_holds_the_thread(self):
        code = textwrap.dedent("""
            import json, sys, tempfile
            from sigilnet import canon
            from sigilnet.mirror import Mirror
            g = canon.loads(sys.stdin.buffer.read())
            m = Mirror(tempfile.mkdtemp(), rate_limit=False)
            r = m.ingest(g)
            print(json.dumps({"status": r.status, "reason": r.reason, "threads": len(m.threads)}))
        """)
        from sigilnet import canon
        p = subprocess.run([sys.executable, "-c", code], input=canon.dumps(self.w.g), capture_output=True, env=dict(os.environ, PYTHONPATH=str(self.tree)), cwd=str(self.dir), timeout=60)
        out = json.loads(p.stdout.decode())
        self.assertEqual((out["status"], out["threads"]), ("rejected", 0), out)
        self.assertEqual(out["reason"], "unsupported version")


for _n in [n for n in dir(_Base) if n.startswith("test_")]:
    if _n not in OldAgainstFormat2.__dict__:
        setattr(OldAgainstFormat2, _n, None)           # only the format-2 tests above run here: the inherited ones belong to test_version_gate


del _Base


if __name__ == "__main__":
    unittest.main()
