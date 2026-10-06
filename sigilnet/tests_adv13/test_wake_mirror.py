"""Mirror(poke=) and home.open_mirror(poke=) (DESIGN_node_wake W2, W3, W5)."""
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import home as H
from sigilnet import wake
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.mirror import Mirror
from sigilnet.tests.util import World

PKG = Path(__file__).resolve().parents[1]


def setup(poke=True, cap=None):
    d = Path(tempfile.mkdtemp(prefix="adv13_m_"))
    w = World()
    w.ids["hu"].save(d / "identity.json")
    m = H.open_mirror(d, w.ids["hu"].id, poke=poke)
    assert m.ingest(w.genesis).ok
    return d, w, m


def psize(d):
    try:
        return (d / "node.poke").stat().st_size
    except FileNotFoundError:
        return 0


def post(w, m, name="sansa", text="x"):
    ev = w.w(name).post(text)
    w.add(ev)
    return m.ingest(ev)


class OpenMirror(unittest.TestCase):
    def test_poke_true_is_the_default_and_uses_home_node_poke(self):
        d = Path(tempfile.mkdtemp(prefix="adv13_m_"))
        w = World()
        m = H.open_mirror(d, w.ids["hu"].id)
        m.ingest(w.genesis)
        post(w, m)
        self.assertTrue((d / "node.poke").exists())
        self.assertEqual(stat.S_IMODE((d / "node.poke").stat().st_mode), 0o600)

    def test_poke_false_never_creates_the_file(self):
        d, w, m = setup(poke=False)
        post(w, m)
        post(w, m)
        self.assertFalse((d / "node.poke").exists())

    def test_the_mirror_still_has_me_and_the_inbox_when_poking(self):
        d, w, m = setup()
        self.assertFalse(m.inbox_off)
        post(w, m)
        self.assertTrue((d / "inbox.jsonl").exists())


class Poking(unittest.TestCase):
    def test_every_append_of_events_pokes(self):
        d, w, m = setup()
        s0 = psize(d)
        for k in range(5):
            before = psize(d)
            self.assertEqual(post(w, m, text=f"p{k}").status, "accepted")
            self.assertGreater(psize(d), before)
        self.assertGreater(psize(d), s0)

    def test_a_duplicate_or_rejected_event_does_not_poke(self):
        d, w, m = setup()
        ev = w.w("sansa").post("once")
        w.add(ev)
        m.ingest(ev)
        n = psize(d)
        self.assertEqual(m.ingest(ev).status, "duplicate")
        self.assertEqual(psize(d), n)

    def test_the_poke_comes_after_the_events_append(self):
        """W2: the line is on disk before the poke; the loop's refresh then finds it."""
        d, w, m = setup()
        order = []
        real = Mirror._append

        def spy(self_, path, evs, t=None):
            r = real(self_, path, evs, t)
            if str(path).endswith("events.jsonl"):
                order.append(("appended", psize(d)))
            return r

        before = psize(d)
        with mock.patch.object(Mirror, "_append", spy):
            post(w, m)
        self.assertEqual(order, [("appended", before)], "the poke was already touched when events.jsonl was appended")
        self.assertGreater(psize(d), before)

    def test_a_failing_poke_never_fails_the_append(self):
        d = Path(tempfile.mkdtemp(prefix="adv13_m_"))
        w = World()
        m = Mirror(d / "mirror", me=w.ids["hu"].id, inbox=__import__("sigilnet.inboxlog", fromlist=["InboxLog"]).InboxLog(d), poke=d / "no" / "such" / "dir" / "node.poke")
        self.assertTrue(m.ingest(w.genesis).ok)
        self.assertEqual(post(w, m).status, "accepted")
        m2 = Mirror(d / "mirror")
        self.assertEqual(len(m2.threads[event_id(w.genesis)].order), 2)

    def test_a_poke_that_is_a_directory_never_fails_the_append(self):
        d = Path(tempfile.mkdtemp(prefix="adv13_m_"))
        (d / "node.poke").mkdir()
        w = World()
        from sigilnet.inboxlog import InboxLog
        m = Mirror(d / "mirror", me=w.ids["hu"].id, inbox=InboxLog(d), poke=d / "node.poke")
        m.ingest(w.genesis)
        self.assertEqual(post(w, m).status, "accepted")

    def test_a_symlinked_poke_is_not_followed(self):
        d = Path(tempfile.mkdtemp(prefix="adv13_m_"))
        target = d / "precious"
        target.write_text("keep")
        os.symlink(target, d / "node.poke")
        w = World()
        m = H.open_mirror(d, w.ids["hu"].id)
        m.ingest(w.genesis)
        post(w, m)
        self.assertEqual(target.read_text(), "keep")

    def test_the_file_stays_below_the_cap_over_many_appends(self):
        with mock.patch.object(wake, "POKE_CAP", 64):
            d, w, m = setup()
            for k in range(200):
                post(w, m, text=f"p{k}")
                self.assertLessEqual(psize(d), 64)

    def test_a_mirror_without_poke_writes_no_file_anywhere_near(self):
        d = Path(tempfile.mkdtemp(prefix="adv13_m_"))
        w = World()
        m = Mirror(d / "mirror")
        m.ingest(w.genesis)
        post(w, m)
        self.assertEqual([p.name for p in d.iterdir()], ["mirror"])

    def test_the_poke_goes_exactly_to_the_path_given(self):
        d = Path(tempfile.mkdtemp(prefix="adv13_m_"))
        w = World()
        from sigilnet.inboxlog import InboxLog
        m = Mirror(d / "mirror", me=w.ids["hu"].id, inbox=InboxLog(d), poke=d / "custom.poke")
        m.ingest(w.genesis)
        post(w, m)
        self.assertTrue((d / "custom.poke").exists())
        self.assertFalse((d / "node.poke").exists(), "the mirror derived a poke path of its own")

    def test_poke_is_keyword_only(self):
        with self.assertRaises(TypeError):
            Mirror(Path(tempfile.mkdtemp()) / "m", None, 256, __import__("time").time, True, None, None, None, Path("/tmp/x"))

    def test_the_poke_file_is_never_derived_from_the_mirror_root(self):
        """W2: a Mirror built without poke= touches nothing next to its root (250 test Mirrors live in tempdirs)."""
        base = Path(tempfile.mkdtemp(prefix="adv13_m_"))
        (base / "deep").mkdir()
        w = World()
        m = Mirror(base / "deep" / "mirror")
        m.ingest(w.genesis)
        post(w, m)
        self.assertEqual(sorted(p.name for p in base.iterdir()), ["deep"])
        self.assertEqual(sorted(p.name for p in (base / "deep").iterdir()), ["mirror"])


class Sites(unittest.TestCase):
    def test_only_home_py_passes_poke_to_a_Mirror(self):
        """The one-factory guard covers poke=: no other module builds a Mirror at all (test_sites in adv12), and only home.py names poke= for it."""
        hits = []
        for p in sorted(PKG.glob("*.py")):
            if p.name in ("mirror.py", "home.py", "wake.py"):
                continue
            for n, line in enumerate(p.read_text().splitlines(), 1):
                code = line.split("#", 1)[0]
                if re.search(r"\bMirror\([^)]*poke\s*=", code):
                    hits.append(f"{p.name}:{n}")
        self.assertEqual(hits, [])

    def test_the_node_run_asks_for_a_mirror_that_does_not_poke(self):
        """W5: the node's own mirror must not poke (a 10k-event first sync would be a poke per event)."""
        src = (PKG / "noderun.py").read_text()
        self.assertRegex(src, r"open_mirror\([^)]*poke\s*=\s*False")


if __name__ == "__main__":
    unittest.main()
