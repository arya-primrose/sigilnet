"""W1 of live test 2: `show` and `unread` cap a long post (BODY_CAP characters + a marker) unless --full; the marker counts what was left out."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sigilnet.mirror import BODY_CAP, cap_text

ROOT = Path(__file__).resolve().parents[2]


def run(home, *args, inp=None):
    p = subprocess.run([sys.executable, "-B", "-m", "sigilnet", "--home", str(home), *args], capture_output=True, text=True, input=inp, cwd=str(ROOT), timeout=120)
    return p.returncode, p.stdout, p.stderr


class CapText(unittest.TestCase):
    def test_boundary_marker_and_none(self):
        self.assertEqual(cap_text("x" * 600, 600), "x" * 600)
        out = cap_text("x" * 601, 600)
        self.assertTrue(out.startswith("x" * 600 + " ... (+1 more characters"), out)
        self.assertIn("--full", out)
        self.assertEqual(cap_text("x" * 10 ** 5, None), "x" * 10 ** 5)
        self.assertIn("+99400 more", cap_text("y" * 10 ** 5, 600))
        self.assertEqual(cap_text("", 600), "")
        self.assertEqual(BODY_CAP, 600)


class Cli(unittest.TestCase):
    def setUp(self):
        self.a, self.b = tempfile.mkdtemp(), tempfile.mkdtemp()
        run(self.a, "id", "init", "alice")
        run(self.b, "id", "init", "bob")
        pub = Path(self.a) / "bob.pub"
        pub.write_text(run(self.b, "id", "show", "--json")[1])
        rc, out, err = run(self.a, "new", "t", "--plaintext", "--member", f"member={pub}")
        self.tid = out.split("thread ")[1].split()[0]
        lines = run(self.a, "export", self.tid)[1]
        run(self.b, "ingest", "-", inp=lines)
        self.big = "B" * 3000 + "END"

    def bob_posts(self, text):
        self.assertEqual(run(self.b, "post", self.tid, text)[0], 0)
        run(self.a, "ingest", "-", inp=run(self.b, "export", self.tid)[1])

    def test_unread_caps_by_default_and_prints_everything_with_full(self):
        self.bob_posts(self.big)
        out = run(self.a, "unread", self.tid)[1]
        self.assertLess(len(out), 900, len(out))
        self.assertIn("(+2403 more characters", out)
        self.assertNotIn("END", out)
        full = run(self.a, "unread", self.tid, "--full")[1]
        self.assertIn("END", full)
        self.assertGreater(len(full), 3000)

    def test_show_caps_by_default_and_prints_everything_with_full(self):
        self.bob_posts(self.big)
        out = run(self.a, "show", self.tid)[1]
        self.assertNotIn("END", out)
        self.assertIn("more lines; --full", out)
        self.assertLess(len(out), 4500)
        self.assertIn("END", run(self.a, "show", self.tid, "--full")[1])
        lines = run(self.a, "show", self.tid, "--lines")[1]                    # the older form keeps its character cap
        self.assertIn("more characters; use --full", lines)
        self.assertLess(len(lines), 1600)

    def test_short_posts_and_other_commands_are_unchanged(self):
        self.bob_posts("short and sweet")
        self.assertIn("'short and sweet'", run(self.a, "unread", self.tid)[1])
        self.assertIn("short and sweet", run(self.a, "show", self.tid)[1])
        self.assertNotIn("more characters", run(self.a, "show", self.tid, "--lines")[1])
        self.assertNotIn("more lines", run(self.a, "show", self.tid)[1])
        self.bob_posts("C" * 5000)
        brief = json.loads(run(self.a, "brief", self.tid)[1])
        self.assertTrue(all(len(u["preview"]) <= 200 for u in brief["unread"]))

    def test_the_printed_line_is_bounded_even_for_text_that_escapes_to_many_characters(self):
        """Sansa's nit: 600 x U+10FFFF repr()s to 6000 characters; the cap now counts the escaped form."""
        self.bob_posts("\U0010ffff" * 1000 + "tail")
        out = run(self.a, "unread", self.tid)[1]
        self.assertLess(len(out), 900, len(out))
        self.assertNotIn("tail", out)
        self.assertTrue(out.rstrip().endswith("--full)'"), out[-60:])
        self.assertIn("tail", run(self.a, "unread", self.tid, "--full")[1])

    def test_the_cap_is_applied_before_quoting_so_the_marker_stays_inside(self):
        self.bob_posts("\x1b[2J" + "D" * 1000)
        out = run(self.a, "unread", self.tid)[1]
        self.assertNotIn("\x1b", out)
        self.assertTrue(out.rstrip().endswith("--full)'"), out[-80:])


if __name__ == "__main__":
    unittest.main()
