"""Thread format 2, stage 3 of DESIGN_versioning.md: serving (gating by the thread's REAL format, no patching), rotation as the upgrade path (`rotate` keeps the format, `--format 2` is an
explicit decision that needs every member known to read it), the follow expiry text, and the CLI switches."""
import contextlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import autorotate as AR
from sigilnet import cli
from sigilnet import event as E
from sigilnet import sync as S
from sigilnet import version as V
from sigilnet.build import Writer, make_genesis
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.peerver import PeerVer
from sigilnet.rotate import RotateError, lagging_members, rotate_thread

from .test_version import fake_pong


def decl(formats, sw="0.3.0", wire="1.0", majors=(1, 0)):
    return {"wire": wire, "majors": list(majors), "formats": list(formats), "sw": sw}


class World2:
    """arya owns a thread of `fmt` with sansa and carol (members) and hu (observer) in a throwaway mirror."""

    def __init__(self, fmt=1):
        self.ids = {n: Identity.generate(n) for n in ("arya", "sansa", "carol", "hu", "eve")}
        i = self.ids
        self.g = make_genesis(i["arya"], "rot test", [(i["sansa"], "member"), (i["carol"], "member"), (i["hu"], "observer")], fmt=fmt)
        self.tid = E.event_id(self.g)
        self.m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        assert self.m.ingest(self.g).ok
        assert self.m.ingest(Writer(i["sansa"], self.m.threads[self.tid]).post("hello")).ok
        self.pv = PeerVer(Path(tempfile.mkdtemp()) / "pv.json")

    def declare(self, *names, formats=(2, 1), legacy=False):
        for n in names:
            self.pv.note(self.ids[n].id, None if legacy else V.parse_decl(decl(formats)), legacy=legacy)


class Rotation(unittest.TestCase):
    def test_rotate_keeps_the_format_by_default(self):
        for fmt in (1, 2):
            w = World2(fmt)
            r = rotate_thread(w.m, w.ids["arya"], w.tid)
            self.assertEqual((r["format"], w.m.threads[r["new"]].format), (fmt, fmt))
            first = w.m.threads[r["new"]].stored
            self.assertTrue(all(e["v"] == fmt for e in first.values()))
            self.assertTrue(all(e["v"] == fmt for e in w.m.threads[w.tid].stored.values()))      # the pointer post in the OLD thread keeps its format too

    def test_a_format_upgrade_needs_every_member_known_to_read_it(self):
        w = World2(1)
        with self.assertRaises(RotateError) as c:
            rotate_thread(w.m, w.ids["arya"], w.tid, fmt=2, peerver=w.pv)
        msg = str(c.exception)
        for n in ("sansa", "carol", "hu"):
            self.assertIn(n, msg)
        self.assertIn("never declared", msg)
        self.assertNotIn(w.ids["arya"].id[:8], msg.replace("arya", ""))
        self.assertEqual(len(w.m.threads), 1, "nothing was created")
        w.declare("sansa", "carol")
        with self.assertRaises(RotateError) as c:
            rotate_thread(w.m, w.ids["arya"], w.tid, fmt=2, peerver=w.pv)
        self.assertIn("hu", str(c.exception))                                            # the observer counts: the human's seat must read the format
        self.assertNotIn("sansa", str(c.exception))
        w.declare("hu")
        r = rotate_thread(w.m, w.ids["arya"], w.tid, fmt=2, peerver=w.pv)
        nt = w.m.threads[r["new"]]
        self.assertEqual((r["format"], nt.format), (2, 2))
        self.assertTrue(all(e["v"] == 2 for e in nt.stored.values()))
        self.assertEqual(w.m.threads[w.tid].format, 1)                                    # the old thread stays format 1, readable and unchanged
        self.assertTrue(all(e["v"] == 1 for e in w.m.threads[w.tid].stored.values()))
        self.assertEqual(sorted(nt.state()["members"]), sorted(w.m.threads[w.tid].state()["members"]))

    def test_a_member_that_declares_only_format_1_or_is_0_1_x_blocks_the_upgrade(self):
        w = World2(1)
        w.declare("sansa", formats=(1,))
        w.declare("carol", legacy=True)
        w.declare("hu")
        with self.assertRaises(RotateError) as c:
            rotate_thread(w.m, w.ids["arya"], w.tid, fmt=2, peerver=w.pv)
        msg = str(c.exception)
        self.assertIn("sansa (sigilnet 0.3.0 reads formats 1 only)", msg)
        self.assertIn("carol (runs sigilnet 0.1.x", msg)
        self.assertNotIn("hu (", msg)

    def test_no_peer_cache_at_all_refuses(self):
        w = World2(1)
        with self.assertRaises(RotateError):
            rotate_thread(w.m, w.ids["arya"], w.tid, fmt=2, peerver=None)

    def test_force_format_rotates_anyway_but_never_with_close(self):
        w = World2(1)
        with self.assertRaises(RotateError) as c:
            rotate_thread(w.m, w.ids["arya"], w.tid, fmt=2, peerver=w.pv, close=True, force_format=True)
        self.assertIn("--close is never allowed", str(c.exception))
        self.assertFalse(w.m.threads[w.tid].state()["closed"])
        r = rotate_thread(w.m, w.ids["arya"], w.tid, fmt=2, peerver=w.pv, force_format=True)
        self.assertEqual(w.m.threads[r["new"]].format, 2)
        self.assertFalse(r["closed"])

    def test_close_with_a_format_upgrade_is_fine_when_everybody_declared(self):
        w = World2(1)
        w.declare("sansa", "carol", "hu")
        r = rotate_thread(w.m, w.ids["arya"], w.tid, fmt=2, peerver=w.pv, close=True)
        self.assertTrue(r["closed"])

    def test_a_thread_never_goes_back_and_unknown_formats_are_refused(self):
        w = World2(2)
        for fmt, text in ((1, "never goes back"), (3, "does not read or write thread format 3"), (0, "does not read or write thread format 0"), (99, "does not read or write thread format 99")):
            with self.assertRaises(RotateError) as c:
                rotate_thread(w.m, w.ids["arya"], w.tid, fmt=fmt, peerver=w.pv, force_format=True)
            self.assertIn(text, str(c.exception))
        self.assertEqual(len(w.m.threads), 1)

    def test_same_format_needs_no_declarations(self):
        w = World2(1)
        r = rotate_thread(w.m, w.ids["arya"], w.tid, fmt=1, peerver=w.pv)
        self.assertEqual(r["format"], 1)

    def test_guests_are_not_checked_because_they_are_not_carried_over(self):
        w = World2(1)
        st = w.m.threads[w.tid].state()
        st = {**st, "members": {**st["members"], w.ids["eve"].id: {"role": "guest", "name": "eve", "sign": "", "kex": ""}}}
        w.declare("sansa", "carol", "hu")
        self.assertEqual(lagging_members(st, w.ids["arya"].id, 2, w.pv), [])

    def test_the_auto_rotation_keeps_the_format(self):
        """AutoRotator._owner calls rotate_thread without a format: a wall rotation must never silently cut members off."""
        w = World2(1)
        with mock.patch("sigilnet.autorotate.near_wall", lambda n: True):
            ar = AR.AutoRotator(w.m, w.ids["arya"], mock.Mock(), Path(tempfile.mkdtemp()) / "rot.json", auto_rotate=True)
            ar._owner(time.time())
        news = [t for t in w.m.threads.values() if t.id != w.tid]
        self.assertEqual([t.format for t in news], [1])


class Expiry(unittest.TestCase):
    def run_expiry(self, err):
        w = World2(1)
        logs = []
        peers = mock.Mock()
        peers.auto_entries.return_value = [("a" * 32, "b" * 32, {"at": 1.0, "owner": w.ids["arya"].id, "old": w.tid})]
        ar = AR.AutoRotator(w.m, w.ids["sansa"], peers, Path(tempfile.mkdtemp()) / "rot.json", log=logs.append, follow_rotation=True)
        if err is not None:
            ar.last_error = lambda peer, tid: err
        ar._verify(1.0 + AR.FOLLOW_EXPIRY + 5)
        peers.settle_auto.assert_called_once_with("b" * 32, False)
        return logs

    def test_the_expiry_names_the_format_when_the_owner_said_so(self):
        text = V.refusal(V.decl(), None, 2)
        logs = self.run_expiry(text)
        self.assertTrue(any("refused: the new thread needs a newer thread format" in x for x in logs), logs)

    def test_the_expiry_without_a_reason_keeps_the_old_line(self):
        for err in (None, "", "connection refused", "peer declares no wire version (0.1.x); this node ..."):
            logs = self.run_expiry(err)
            self.assertTrue(any("the thread never arrived" in x for x in logs), (err, logs))


class Serving(unittest.TestCase):
    """A REAL format-2 thread served by a SyncServer: no patching of thread_format."""

    def setUp(self):
        self.w = World2(2)
        self.srv_ids = self.w.ids
        self.arya, self.sansa, self.eve = self.w.ids["arya"], self.w.ids["sansa"], self.w.ids["eve"]

    def ask(self, body, who=None, ver=None):
        q = S.sign_request(who or self.sansa, {**body, **({"ver": ver} if ver else {})}, aud=self.arya.id)
        srv = S.SyncServer(self.w.m, identity=self.arya, pong=fake_pong)
        srv.set_peers([self.sansa.id])
        return srv.handle(json.loads(json.dumps(q)))

    def bodies(self):
        return [{"t": "summary", "thread": self.w.tid}, {"t": "list", "thread": self.w.tid, "page": 0}, {"t": "get", "thread": self.w.tid, "ids": [self.w.tid]}]

    def test_a_peer_that_declares_nothing_or_format_1_is_told_why_and_gets_no_events(self):
        for ver in (None, decl([1], sw="0.2.0")):
            for b in self.bodies():
                r = self.ask(b, ver=ver)
                self.assertEqual(r["t"], "error", (b, ver))
                self.assertTrue(r["why"].startswith("thread uses format 2, the peer reads format 1"), r["why"])
                self.assertNotIn("events", r)

    def test_a_peer_that_declares_format_2_is_served(self):
        for b in self.bodies():
            self.assertNotEqual(self.ask(b, ver=decl([2, 1]))["t"], "error", b)

    def test_a_non_member_still_learns_nothing(self):
        self.assertEqual(self.ask(self.bodies()[0], who=self.eve)["t"], "unknown")

    def test_this_node_serves_a_format_1_thread_to_everybody_as_before(self):
        w1 = World2(1)
        q = S.sign_request(w1.ids["sansa"], {"t": "summary", "thread": w1.tid}, aud=w1.ids["arya"].id)
        srv = S.SyncServer(w1.m, identity=w1.ids["arya"], pong=fake_pong)
        srv.set_peers([w1.ids["sansa"].id])
        self.assertEqual(srv.handle(json.loads(json.dumps(q)))["t"], "summary")


class NodeLine(unittest.TestCase):
    def test_a_pull_that_met_unreadable_events_leaves_one_line_for_the_operator(self):
        from .test_node import Sim
        s = Sim(2)
        lines = []
        s.nodes["sansa"].log = lambda *a: lines.append(" ".join(str(x) for x in a))
        orig = S.pull

        count = [2]

        def fake(*a, **k):
            r = orig(*a, **k)
            count[0] += 1
            r["refused"] = {"unsupported version": count[0] if count[0] < 100 else 3}      # (a hostile peer varies the count: the text must not be part of the dedup key)
            return r

        def n_lines(ls):
            return len([l for l in ls if "events refused" in l])
        s.post("arya", "one")
        with mock.patch.object(S, "pull", fake):
            s.step(1, 3)
            s.step(301, 3)                                                                  # (several pulls: the pull interval is 300 s)
        self.assertTrue(any("events refused: unsupported version" in l for l in lines), lines)
        self.assertEqual(n_lines(lines), 1)
        s.clock.t += 3700
        s.post("arya", "two")
        with mock.patch.object(S, "pull", fake):
            s.step(301, 3)
        self.assertEqual(n_lines(lines), 2, lines)                                    # and again an hour later


    def test_the_table_of_noted_lines_stays_bounded(self):
        from .test_node import Sim
        n = Sim(2).nodes["sansa"]
        for i in range(600):
            self.assertTrue(n._note_once(("p", f"t{i}")))
        self.assertLessEqual(len(n._noted_at), 256)


class Pull(unittest.TestCase):
    def test_a_node_that_cannot_read_a_format_counts_the_refusals_by_reason(self):
        r = {}
        S._why_refused(r, "unsupported version")
        S._why_refused(r, "unsupported version")
        S._why_refused(r, "format mismatch (this thread is format 1, the event is format 2)")
        S._why_refused(r, "bad signature")
        self.assertEqual(S.refused_note(S.PullResult(**r)), "3 events refused: format mismatch (1), unsupported version (2)")
        self.assertEqual(S.refused_note({}), "")


class Cli(unittest.TestCase):
    def run_cli(self, home, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = cli.main(["--home", str(home), *args])
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else 1
                err.write("" if isinstance(e.code, int) or e.code is None else str(e.code))
        return rc, out.getvalue(), err.getvalue()

    def setUp(self):
        self.home = Path(tempfile.mkdtemp()) / "h"
        rc, out, err = self.run_cli(self.home, "init", "arya", "--carrier", "tcp", "--bind", "127.0.0.1")
        self.assertEqual(rc, 0, err)

    def test_new_format_and_list(self):
        rc, out, err = self.run_cli(self.home, "new", "fmt two", "--format", "2", "--plaintext")
        self.assertEqual(rc, 0, err)
        rc, out, err = self.run_cli(self.home, "list")
        self.assertIn("format 2", out)
        rc, out, err = self.run_cli(self.home, "new", "fmt one", "--plaintext")
        self.assertEqual(rc, 0, err)
        rc, out, err = self.run_cli(self.home, "list")
        self.assertEqual([l for l in out.splitlines() if "fmt one" in l and "format" in l.split("events=")[0] + l.split("events=")[1]], [])

    def test_new_refuses_unknown_formats_and_public_format_2(self):
        for args in (["--format", "3"], ["--format", "0"], ["--format", "2", "--public"]):
            rc, out, err = self.run_cli(self.home, "new", "bad", *args)
            self.assertNotEqual(rc, 0, args)
            self.assertIn("format", err)

    def test_rotate_to_format_2_refuses_without_declarations_and_the_message_says_how(self):
        self.run_cli(self.home, "new", "r", "--plaintext")
        # a thread with only the owner has no one to wait for: it rotates; with a member it is refused (library tests cover the lists)
        rc, out, err = self.run_cli(self.home, "list")
        tid = out.split()[0]
        rc, out, err = self.run_cli(self.home, "rotate", tid, "--format", "2")
        self.assertEqual(rc, 0, err)
        self.assertIn("thread format 2", out)

    def test_rotate_cli_refuses_a_member_that_never_declared_and_force_format_overrides(self):
        other = Identity.generate("bob")
        pub = self.home.parent / "bob.pub"
        pub.write_text(json.dumps({"name": "bob", "agent": other.id, "sign": other.sign_pub, "kex": other.kex_pub}))
        rc, out, err = self.run_cli(self.home, "new", "with a member", "--plaintext", "--member", f"member={pub}")
        self.assertEqual(rc, 0, err)
        tid = out.split("thread ")[1].split()[0]
        rc, out, err = self.run_cli(self.home, "rotate", tid, "--format", "2")
        self.assertNotEqual(rc, 0)
        self.assertIn("bob", err)
        self.assertIn("never declared", err)
        self.assertIn("--force-format", err)
        rc, out, err = self.run_cli(self.home, "rotate", tid, "--format", "2", "--close")
        self.assertNotEqual(rc, 0)
        self.assertIn("--close is never allowed", err)
        rc, out, err = self.run_cli(self.home, "rotate", tid, "--format", "2", "--force-format")
        self.assertEqual(rc, 0, err)
        self.assertIn("thread format 2", out)
        rc, out, err = self.run_cli(self.home, "capsule", "--carrier", "tcp", "create", out.split("new thread is ")[1].split()[0])
        self.assertIn("this thread is format 2", out)

    def test_version_lists_the_formats(self):
        rc, out, err = self.run_cli(self.home, "--version")
        self.assertIn("thread formats 2, 1", out)


if __name__ == "__main__":
    unittest.main()
