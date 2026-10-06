"""One factory (section 13 point 5): a forgotten construction site is a node that never wakes anyone, so the guard is a test over the SOURCE."""
import re
import unittest
from pathlib import Path

from sigilnet.inboxlog import InboxLog
from sigilnet.keys import Identity

from .h import entries

PKG = Path(__file__).resolve().parents[1]
CALL = re.compile(r"(?<![A-Za-z_.])Mirror\(")


def code_lines(path: Path):
    """(lineno, text) of the lines that are code: comments and docstring-ish prose are not parsed; a '#' cuts the line, and lines inside triple quotes are skipped."""
    inside = False
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        quotes = raw.count('"""') + raw.count("'''")
        if inside:
            if quotes % 2:
                inside = False
            continue
        if quotes % 2:
            inside = True
            continue
        yield n, raw.split("#", 1)[0]


class OneFactory(unittest.TestCase):
    def test_no_module_builds_a_Mirror_except_the_factory_and_the_class_itself(self):
        offenders = []
        for p in sorted(PKG.glob("*.py")):
            if p.name in ("mirror.py", "home.py"):
                continue
            for n, text in code_lines(p):
                if CALL.search(text):
                    offenders.append(f"{p.name}:{n}: {text.strip()[:90]}")
        self.assertEqual(offenders, [], "a Mirror built outside home.open_mirror writes no inbox lines (a node that never wakes anyone)")

    def test_home_py_has_exactly_one_Mirror_call(self):
        calls = [n for n, t in code_lines(PKG / "home.py") if CALL.search(t)]
        self.assertEqual(len(calls), 1, calls)

    def test_the_factory_wires_me_and_the_inbox_log(self):
        import tempfile
        from sigilnet import home as H
        from sigilnet.tests.util import World
        d = Path(tempfile.mkdtemp(prefix="adv12_site_"))
        w = World()
        w.ids["sansa"].save(d / "identity.json")
        m = H.open_mirror(d, w.ids["sansa"].id)
        self.assertFalse(m.inbox_off)
        self.assertTrue(m.ingest(w.genesis).ok)
        mine = w.w("sansa").post("mine")
        w.add(mine)
        m.ingest(mine)
        self.assertEqual(entries(d), [])                                                  # my own event: no line
        theirs = w.w("carol").post("theirs")
        w.add(theirs)
        m.ingest(theirs)
        self.assertEqual(len(entries(d)), 1)
        self.assertEqual(entries(d)[0]["thread"], next(iter(m.threads)))


if __name__ == "__main__":
    unittest.main()
