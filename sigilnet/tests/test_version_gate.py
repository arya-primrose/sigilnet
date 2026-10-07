"""Stage 2 of DESIGN_versioning.md rev 3: a node that cannot serve a peer says WHY in plain text (the `why` of an error answer), decided on the declaration of the request being
answered (undeclared = 0.1.x), never on a cache. Today's constants serve everybody; the tests patch the constants to a future release (wire 3.0, majors 3 and 2) and to a thread of
format 2."""
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import ping as P
from sigilnet import sync as S
from sigilnet import version as V
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.peerver import PeerVer

from .test_node import Sim
from .test_sync import mirror_with
from .test_version import AG, AG2, GOOD, Cli as _unused, fake_pong, parent_tree
from .util import World

FUTURE = {"wire": "3.0", "majors": [3, 2], "formats": [1], "sw": "3.0.0"}


def future():
    """Patch this node to a release that speaks wire 3.0 and 2 (its previous major) and no longer 0."""
    return mock.patch.multiple(V, SW="3.0.0", WIRE=(3, 0), MAJORS=(3, 2))


def decl(wire, majors, formats=(1,), sw="1.0.0"):
    return {"wire": wire, "majors": list(majors), "formats": list(formats), "sw": sw}


class RefusalText(unittest.TestCase):
    def test_compatible_peers_get_none(self):
        self.assertIsNone(V.refusal(V.decl(), None))
        self.assertIsNone(V.refusal(V.decl(), V.decl()))
        self.assertIsNone(V.refusal(FUTURE, decl("2.4", [2, 1])))
        self.assertIsNone(V.refusal(FUTURE, decl("3.1", [3, 2])))

    def test_a_legacy_peer_and_a_declared_old_peer_of_a_future_node(self):
        t = V.refusal(FUTURE, None)
        self.assertTrue(t.startswith("peer declares no wire version (0.1.x)"), t)
        self.assertIn("this node (sigilnet 3.0.0) speaks wire 3 or 2", t)
        self.assertIn("must upgrade", t)
        t = V.refusal(FUTURE, decl("1.5", [1, 0], sw="1.5.2"))
        self.assertTrue(t.startswith("peer speaks wire 1.5 (sigilnet 1.5.2)"), t)

    def test_a_format_the_peer_cannot_read(self):
        t = V.refusal(V.decl(), None, 2)
        self.assertTrue(t.startswith("thread uses format 2, the peer reads format 1"), t)
        self.assertIsNone(V.refusal(V.decl(), decl("1.0", [1, 0], [2, 1]), 2))
        t = V.refusal(V.decl(), decl("1.0", [1, 0], [1]), 2)
        self.assertIn("reads format 1", t)
        self.assertIsNone(V.refusal(V.decl(), None, 1))

    def test_the_text_is_short_printable_ascii_and_has_no_url(self):
        worst = [(FUTURE, decl("999.999", [999], sw="x" * 40)), (FUTURE, None), ({**FUTURE, "sw": "y" * 40, "majors": list(range(999, 991, -1))}, None)]
        for local, peer in worst:
            t = V.refusal(local, peer)
            self.assertLessEqual(len(t), V.MAX_WHY, t)
            self.assertTrue(t.isascii() and t.isprintable(), t)
            for bad in ("http", "://", "www.", ".com"):
                self.assertNotIn(bad, t.lower())
        self.assertLessEqual(len(V.refusal(V.decl(), decl("1.0", [1, 0], list(range(1, 9))), 99) or ""), V.MAX_WHY)
        self.assertLess(V.MAX_WHY, 200)                                  # (a 0.1.x asker keeps 200 characters of a why)

    def test_thread_format_is_the_threads_format_which_is_the_genesis_v(self):
        from sigilnet.build import make_genesis
        from sigilnet.thread import Thread
        ids = World().ids
        for fmt in (1, 2):
            self.assertEqual(V.thread_format(Thread(make_genesis(ids["arya"], "t", [(ids["sansa"], "member")], fmt=fmt))), fmt)
        for bad in (True, "2", 0, -1, None, 7.5):
            class T:
                format = bad
            self.assertEqual(V.thread_format(T()), 1, bad)
        self.assertEqual(V.thread_format(object()), 1)


class Server(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.post("sansa", "hello")
        self.arya, self.sansa, self.eve = self.w.ids["arya"], self.w.ids["sansa"], self.w.ids["eve"]
        self.m = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        self.tid = self.w.t.id
        self.refused = []
        self.srv = S.SyncServer(self.m, identity=self.arya, pong=fake_pong, on_refuse=lambda who, text, d=None: self.refused.append((who, text)))
        self.srv.set_peers([self.sansa.id])

    def ask(self, body, who=None, ver=None):
        q = S.sign_request(who or self.sansa, {**body, **({"ver": ver} if ver else {})}, aud=self.arya.id)
        srv = S.SyncServer(self.m, identity=self.arya, pong=fake_pong, on_refuse=lambda w_, text, d=None: self.refused.append((w_, text)))     # (a fresh server: no ping rate gap)
        srv.set_peers([self.sansa.id])
        return srv.handle(json.loads(json.dumps(q)))

    BODIES = lambda self: [{"t": "summary", "thread": self.tid}, {"t": "list", "thread": self.tid, "page": 0}, {"t": "get", "thread": self.tid, "ids": [self.tid]}]

    def test_today_nobody_is_refused(self):
        for body in self.BODIES():
            for ver in (None, V.decl(), decl("1.7", [1, 0], sw="1.7.0")):
                self.assertNotEqual(self.ask(body, ver=ver)["t"], "error", (body, ver))
        self.assertEqual(self.refused, [])

    def test_a_future_node_refuses_a_legacy_known_peer_with_the_text(self):
        with future():
            for body in self.BODIES():
                r = self.ask(body)
                self.assertEqual(r["t"], "error")
                self.assertEqual(r["why"], V.refusal(V.decl(), None))
                self.assertTrue(r["why"].startswith("peer declares no wire version (0.1.x)"), r["why"])
                self.assertEqual(r["by"], self.arya.sign_pub)                 # (signed: an old client accepts the answer and shows the why)
        self.assertEqual(len(self.refused), 3)
        self.assertTrue(all(w == self.sansa.id for w, _ in self.refused))

    def test_a_declared_old_major_is_refused_and_the_previous_major_is_served(self):
        with future():
            self.assertEqual(self.ask({"t": "summary", "thread": self.tid}, ver=decl("1.0", [1, 0]))["t"], "error")
            self.assertEqual(self.ask({"t": "summary", "thread": self.tid}, ver=decl("2.9", [2, 1]))["t"], "summary")
            self.assertEqual(self.ask({"t": "summary", "thread": self.tid}, ver=decl("3.0", [3, 2]))["t"], "summary")

    def test_the_decision_uses_the_request_never_a_cache(self):
        """A server with a cache that says 'declared 3.0' still refuses a request that declares nothing: the cache is display only."""
        with future():
            pv = PeerVer(Path(tempfile.mkdtemp()) / "pv.json")
            pv.note(self.sansa.id, V.parse_decl(decl("3.0", [3, 2], sw="3.0.0")))
            self.assertEqual(self.ask({"t": "summary", "thread": self.tid})["t"], "error")

    def test_a_stranger_gets_unknown_not_the_text_and_pings_are_still_answered(self):
        with future():
            r = self.ask({"t": "summary", "thread": self.tid}, who=self.eve)
            self.assertEqual(r["t"], "unknown")
            self.assertEqual(self.refused, [])
            self.assertEqual(self.ask({"t": "ping"})["t"], "pong")             # (health stays answerable; the sync request carries the explanation)
            self.assertEqual(self.ask({"t": "notify", "thread": self.tid, "leaves": []})["t"], "ok")   # (notify and the rest are not gated)

    def test_a_format_2_thread_is_refused_to_a_peer_that_cannot_read_it_with_the_text(self):
        with mock.patch.object(V, "thread_format", lambda t: 2):
            for body in self.BODIES():
                r = self.ask(body)
                self.assertEqual(r["t"], "error", body)
                self.assertTrue(r["why"].startswith("thread uses format 2, the peer reads format 1"), r["why"])
            for body in self.BODIES():
                self.assertNotEqual(self.ask(body, ver=decl("1.0", [1, 0], [2, 1]))["t"], "error", body)
            # a non-member never learns the format: the same `unknown` as for a thread that is not here
            self.assertEqual(self.ask({"t": "summary", "thread": self.tid}, who=self.eve)["t"], "unknown")

    def test_the_callback_failing_never_changes_the_answer(self):
        srv = S.SyncServer(self.m, identity=self.arya, on_refuse=lambda *a: 1 / 0)
        srv.set_peers([self.sansa.id])
        with future():
            q = S.sign_request(self.sansa, {"t": "summary", "thread": self.tid}, aud=self.arya.id)
            r = srv.handle(q)
            self.assertEqual(r["t"], "error")
            self.assertTrue(r["why"].startswith("peer declares no wire version (0.1.x)"), r["why"])          # (the refusal text, not an 'internal' error)
        with mock.patch.object(V, "thread_format", lambda t: 2):
            r = srv.handle(S.sign_request(self.sansa, {"t": "summary", "thread": self.tid}, aud=self.arya.id))
            self.assertTrue(r["why"].startswith("thread uses format 2"), r["why"])

    def test_the_protocol_refusal_comes_before_anything_about_the_thread(self):
        """A known peer that cannot talk to us at all is told so even when it asks for a thread we do not hold (not 'unknown'), and the decision is the request's own declaration."""
        with future():
            r = self.ask({"t": "summary", "thread": "0" * 32})
            self.assertEqual(r["t"], "error")
            self.assertTrue(r["why"].startswith("peer declares no wire version"), r["why"])
            r = self.ask({"t": "summary", "thread": "0" * 32}, ver=decl("1.0", [1, 0]))
            self.assertTrue(r["why"].startswith("peer speaks wire 1.0"), r["why"])
            self.assertEqual(self.ask({"t": "summary", "thread": "0" * 32}, ver=decl("3.0", [3, 2]))["t"], "unknown")

    def test_the_public_read_door_does_not_gate(self):
        from sigilnet.publicread import PublicRead
        w = World(visibility="public")
        w.post("sansa", "hi")
        m = mirror_with(w.genesis, [w.t.events[i] for i in w.t.order[1:]])
        door = PublicRead(S.SyncServer(m, identity=w.ids["arya"]))
        with future(), mock.patch.object(V, "thread_format", lambda t: 2):
            r = door.handle({"t": "summary", "thread": w.t.id, "nonce": os.urandom(8).hex()})
        self.assertEqual(r["t"], "summary")


class Cache(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "peerver.json"
        self.now = [5000.0]
        self.pv = PeerVer(self.path, clock=lambda: self.now[0])

    def test_refuse_records_the_text_and_makes_an_unknown_peer_legacy(self):
        self.pv.refuse(AG, "peer declares no wire version (0.1.x); this node needs wire 3")
        e = PeerVer(self.path).get(AG)
        self.assertTrue(e["legacy"])
        self.assertEqual(e["refused"], {"at": 5000, "why": "peer declares no wire version (0.1.x); this node needs wire 3"})

    def test_a_refusal_is_recorded_at_most_once_per_ten_minutes_whatever_the_text(self):
        self.pv.refuse(AG, "a")
        m0 = os.stat(self.path).st_mtime_ns
        for i in range(50):
            self.now[0] += 5
            self.pv.refuse(AG, f"different text {i}")                    # (the text carries the peer's own declared wire and sw: a peer varying them)
        self.assertEqual(os.stat(self.path).st_mtime_ns, m0)
        self.assertEqual(self.pv.get(AG)["refused"]["why"], "a")
        self.now[0] += 601
        self.pv.refuse(AG, "later")
        self.assertEqual(PeerVer(self.path).get(AG)["refused"]["why"], "later")

    def test_the_same_text_is_not_rewritten_within_a_day(self):
        self.pv.refuse(AG, "a")
        self.now[0] += 3600
        m0 = os.stat(self.path).st_mtime_ns
        self.pv.refuse(AG, "a")
        self.assertEqual(os.stat(self.path).st_mtime_ns, m0)
        self.now[0] += 86401
        self.pv.refuse(AG, "a")
        self.assertEqual(PeerVer(self.path).get(AG)["refused"]["at"], int(self.now[0]))

    def test_the_declaration_of_the_refused_request_is_recorded_so_the_peer_is_not_shown_as_0_1_x(self):
        d = V.parse_decl({"wire": "7.0", "majors": [7], "formats": [1], "sw": "7.0.1"})
        self.pv.refuse(AG, "peer speaks wire 7.0 (sigilnet 7.0.1); ...", d)
        e = PeerVer(self.path).get(AG)
        self.assertFalse(e["legacy"])
        self.assertEqual((e["wire"], e["sw"]), ("7.0", "7.0.1"))
        self.assertIn("refused", e)
        self.pv.refuse(AG2, "undeclared")                                  # no declaration: legacy, as before
        self.assertTrue(self.pv.get(AG2)["legacy"])

    def test_refused_count_counts_the_recent_ones(self):
        self.pv.refuse(AG, "a")
        self.pv.refuse(AG2, "b")
        self.assertEqual(self.pv.refused_count(self.now[0]), 2)
        self.assertEqual(self.pv.refused_count(self.now[0] + 8 * 86400), 0)
        self.pv.note("c" * 32, V.parse_decl(GOOD))
        self.assertEqual(self.pv.refused_count(self.now[0]), 2)

    def test_a_new_declaration_keeps_what_we_told_the_peer(self):
        self.pv.note(AG, V.parse_decl(GOOD))
        self.now[0] += 61
        self.pv.refuse(AG, "why")
        self.now[0] += 61
        self.pv.note(AG, V.parse_decl({**GOOD, "sw": "2.9.9"}))
        e = self.pv.get(AG)
        self.assertEqual((e["sw"], e["refused"]["why"]), ("2.9.9", "why"))

    def test_garbage_is_never_recorded_or_loaded(self):
        self.pv.refuse("short", "x")
        self.pv.refuse(AG, 5)
        self.pv.refuse(AG, "bad\x1b[2Jtext\n")
        self.assertEqual(self.pv.get(AG)["refused"]["why"], "bad?[2Jtext?")
        self.pv.refuse(AG2, "z" * 500)
        self.assertEqual(len(self.pv.get(AG2)["refused"]["why"]), 200)
        for bad in [{"at": "x", "why": "w"}, {"at": 1, "why": ""}, {"at": 1, "why": "w" * 201}, {"at": 1, "why": "a\x00b"}, {"at": True, "why": "w"}, 5, None, {"why": "w"}]:
            self.path.write_text(json.dumps({"peers": {AG: {"legacy": True, "seen": 1, "refused": bad}}}))
            self.assertNotIn("refused", PeerVer(self.path).get(AG), bad)

    def test_the_table_stays_bounded(self):
        for i in range(300):
            self.pv.refuse(f"{i:032x}", "w")
        self.assertLessEqual(len(self.pv.d), 256)


class NodeLog(unittest.TestCase):
    def test_a_refusal_is_logged_once_an_hour_per_peer_whatever_the_text_and_cached(self):
        s = Sim(2)
        lines = []
        n = s.nodes["arya"]
        n.log = lambda *a: lines.append(a)
        n.pv = PeerVer(s.homes["arya"] / "peerver.json", clock=s.clock)
        peer = s.ids["sansa"].id
        n.note_refusal(peer, "text one")
        n.note_refusal(peer, "text one")
        n.note_refusal(peer, "text two")
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0][2], "refused")
        s.clock.t += 3601
        n.note_refusal(peer, "text three")
        self.assertEqual(len(lines), 2)
        self.assertEqual(n.pv.get(peer)["refused"]["why"], "text three")

    def test_a_peer_varying_its_declared_sw_cannot_flood_the_log_or_the_file(self):
        """Through the REAL server wired to the node: a known peer declares an unsupported major (refused TODAY) and a new sw on every request."""
        s = Sim(2)
        lines = []
        n = s.nodes["arya"]
        n.log = lambda *a: lines.append(a)
        n.pv = PeerVer(s.homes["arya"] / "peerver.json")
        s.servers["arya"].on_refuse = n.note_refusal
        sansa = s.ids["sansa"]
        saves = []
        real_save = PeerVer._save
        answers = []
        with mock.patch.object(PeerVer, "_save", lambda self_: (saves.append(1), real_save(self_))[1]):
            for i in range(300):
                q = S.sign_request(sansa, {"t": "summary", "thread": s.tid, "ver": decl("7.0", [7], sw=f"1.0.{i}")}, ts=int(s.clock()), aud=s.ids["arya"].id)
                answers.append(s.servers["arya"].handle(json.loads(json.dumps(q))))
        refused = [a for a in answers if a.get("t") == "error" and str(a.get("why", "")).startswith("peer speaks wire 7.0")]
        self.assertGreater(len(refused), 20)                                  # (the per-peer rate limit answers the rest; many were really refused)
        self.assertEqual(len(lines), 1)
        self.assertEqual(len(saves), 1)
        e = n.pv.get(sansa.id)
        self.assertFalse(e["legacy"])                                        # (the declaration the request carried is recorded: not shown as 0.1.x)
        self.assertEqual(e["wire"], "7.0")

    def test_a_node_without_a_cache_still_logs(self):
        s = Sim(2)
        lines = []
        s.nodes["arya"].log = lambda *a: lines.append(a)
        s.nodes["arya"].note_refusal(s.ids["sansa"].id, "t")
        self.assertEqual(len(lines), 1)

    def test_the_table_of_logged_refusals_stays_bounded(self):
        s = Sim(2)
        n = s.nodes["arya"]
        n.log = lambda *a: None
        for i in range(600):
            n.note_refusal(f"{i:032x}", "t")
        self.assertLessEqual(len(n._refused_at), 256)

    def test_the_server_is_wired_to_the_node_in_noderun(self):
        src = (Path(__file__).resolve().parents[1] / "noderun.py").read_text()                   # (a wiring check: the real nodes cannot be run at a future version)
        self.assertIn("on_refuse=node.note_refusal", src)

    def test_the_table_of_logged_refusals_with_a_declaration_argument(self):
        s = Sim(2)
        s.nodes["arya"].log = lambda *a: None
        s.nodes["arya"].pv = PeerVer(s.homes["arya"] / "peerver.json")
        s.nodes["arya"].note_refusal(s.ids["sansa"].id, "t", V.parse_decl(decl("7.0", [7], sw="7.0.0")))
        self.assertEqual(s.nodes["arya"].pv.get(s.ids["sansa"].id)["wire"], "7.0")


class PeerList(unittest.TestCase):
    def test_peer_list_shows_that_we_refuse_a_peer_and_why(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2]))
        home = Path(tempfile.mkdtemp()) / "h"
        r = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(home), "init", "me", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", "47970"], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        h = home / ".sigilnet" if (home / ".sigilnet").is_dir() else home
        (h / "peers.json").write_text(json.dumps({"peers": {AG: {"name": "old", "endpoint": {"type": "tcp", "addr": "127.0.0.1:47971#" + "ab" * 32}, "threads": []}}}))
        pv = PeerVer(h / "peerver.json")
        pv.refuse(AG, "peer declares no wire version (0.1.x); this node (sigilnet 3.0.0) speaks wire 3 or 2: the peer must upgrade sigilnet")
        raw = json.loads((h / "peerver.json").read_text())
        pv2 = {**raw}
        pv2["peers"][AG2] = {"legacy": True, "seen": int(time.time()) - 9 * 86400, "refused": {"at": int(time.time()) - 8 * 86400, "why": "a very old refusal"}}
        (h / "peerver.json").write_text(json.dumps(pv2))
        pj = json.loads((h / "peers.json").read_text())
        pj["peers"][AG2] = {"name": "older", "endpoint": {"type": "tcp", "addr": "127.0.0.1:47972#" + "cd" * 32}, "threads": []}
        (h / "peers.json").write_text(json.dumps(pj))
        r = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(h), "peer", "list"], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("we refuse it (", r.stdout)
        self.assertIn("peer declares no wire version (0.1.x)", r.stdout)
        self.assertEqual(r.stdout.count("we refuse it ("), 1)                  # (a refusal older than a week is not shown)
        self.assertNotIn("a very old refusal", r.stdout)


class StatusLine(unittest.TestCase):
    def test_status_says_how_many_peers_are_refused_and_stays_quiet_otherwise(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2]))
        home = Path(tempfile.mkdtemp()) / "h"
        r = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(home), "init", "me", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", "47960"], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        h = home / ".sigilnet" if (home / ".sigilnet").is_dir() else home
        quiet = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(h), "status"], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(quiet.returncode, 0, quiet.stderr)
        self.assertNotIn("refused", quiet.stdout)
        pv = PeerVer(h / "peerver.json")
        pv.refuse(AG, "peer declares no wire version (0.1.x); ...")
        pv.refuse(AG2, "thread uses format 2, ...")
        loud = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(h), "status"], capture_output=True, text=True, env=env, timeout=120)
        self.assertIn("2 peer(s) refused (protocol or thread format not served): see `peer list`", loud.stdout)


class TheDeployedTreeAsClient(unittest.TestCase):
    """The 0.1.x CLIENT (the parent tree, or the tree named by SIGIL_OLD_TREE) pulls from a patched future server: its pull FAILS and its `why` is the refusal text, which is what its job
    error, `peer list` and history.log show to its operator. The old process asks over a pipe; this process answers with the real server."""

    @classmethod
    def setUpClass(cls):
        env = os.environ.get("SIGIL_OLD_TREE")
        cls.owned = env is None
        cls.tree = Path(env) if env else parent_tree()
        if cls.tree is None:
            raise unittest.SkipTest("the parent tree is not available (git archive)")

    @classmethod
    def tearDownClass(cls):
        if cls.owned and getattr(cls, "tree", None):
            import shutil
            shutil.rmtree(cls.tree, True)

    def setUp(self):
        self.w = World()
        self.w.post("sansa", "hello")
        self.arya, self.sansa = self.w.ids["arya"], self.w.ids["sansa"]
        self.m = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        self.tid = self.w.t.id
        self.dir = Path(tempfile.mkdtemp())
        self.sansa.save(self.dir / "sansa.json")

    def old_pull(self, srv):
        code = textwrap.dedent("""
            import json, sys, tempfile
            from sigilnet import sync as S
            from sigilnet.keys import Identity
            from sigilnet.mirror import Mirror
            job = json.loads(sys.argv[1])
            me = Identity.load(job["me"])
            class T:
                def request(self, req):
                    sys.stdout.write("REQ " + json.dumps(req) + "\\n"); sys.stdout.flush()
                    return json.loads(sys.stdin.readline())
            m = Mirror(tempfile.mkdtemp(), rate_limit=False)
            r = S.pull(m, job["tid"], T(), me, peer_id=job["peer"])
            sys.stdout.write("RES " + json.dumps({"ok": r["ok"], "why": r["why"], "held": len(m.threads[job["tid"]].resolved_ids()) if job["tid"] in m.threads else 0}) + "\\n")
        """)
        job = json.dumps({"me": str(self.dir / "sansa.json"), "tid": self.tid, "peer": self.arya.id})
        p = subprocess.Popen([sys.executable, "-c", code, job], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env=dict(os.environ, PYTHONPATH=str(self.tree)), cwd=str(self.dir))
        try:
            while True:
                line = p.stdout.readline()
                if not line:
                    raise AssertionError("old client ended: " + p.stderr.read())
                kind, _, rest = line.partition(" ")
                if kind == "REQ":
                    p.stdin.write(json.dumps(srv.handle(json.loads(rest))) + "\n")
                    p.stdin.flush()
                elif kind == "RES":
                    return json.loads(rest)
        finally:
            p.kill()
            p.wait(5)
            for f in (p.stdin, p.stdout, p.stderr):
                f.close()

    def server(self):
        srv = S.SyncServer(self.m, identity=self.arya, pong=fake_pong)
        srv.set_peers([self.sansa.id])
        return srv

    def old_node_status(self, srv):
        """The old tree's NODE (peer book, jobs, backoff) ticks once against the server over the pipe; its job table is what `peer list`/status/history.log show."""
        code = textwrap.dedent("""
            import json, sys, tempfile, time
            from pathlib import Path
            from sigilnet import node as N
            from sigilnet.keys import Identity
            from sigilnet.mirror import Mirror
            job = json.loads(sys.argv[1])
            me = Identity.load(job["me"])
            class T:
                def request(self, req):
                    sys.stdout.write("REQ " + json.dumps(req) + "\\n"); sys.stdout.flush()
                    return json.loads(sys.stdin.readline())
            tmp = Path(tempfile.mkdtemp())
            m = Mirror(tmp / "mirror", rate_limit=False)
            book = N.PeerBook(tmp / "peers.json")
            book.add(job["peer"], "arya", {"type": "onion", "addr": "a" * 56 + ".onion:47200"}, threads=[job["tid"]])
            lines = []
            nd = N.Node(m, me, book, tmp / "node.json", lambda rec: T(), clock=time.time, pull_interval=300, log=lambda *a: lines.append(" ".join(str(x) for x in a)))
            for _ in range(8):
                nd.tick()
                if any(j.get("error") or j.get("last_ok") for j in nd.status()):
                    break
                time.sleep(0.5)
            sys.stdout.write("RES " + json.dumps({"status": nd.status(), "log": lines}) + "\\n")
        """)
        job = json.dumps({"me": str(self.dir / "sansa.json"), "tid": self.tid, "peer": self.arya.id})
        p = subprocess.Popen([sys.executable, "-c", code, job], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env=dict(os.environ, PYTHONPATH=str(self.tree)), cwd=str(self.dir))
        try:
            while True:
                line = p.stdout.readline()
                if not line:
                    raise AssertionError("old node ended: " + p.stderr.read())
                kind, _, rest = line.partition(" ")
                if kind == "REQ":
                    p.stdin.write(json.dumps(srv.handle(json.loads(rest))) + "\n")
                    p.stdin.flush()
                elif kind == "RES":
                    return json.loads(rest)
        finally:
            p.kill()
            p.wait(5)
            for f in (p.stdin, p.stdout, p.stderr):
                f.close()

    def test_the_old_node_shows_the_refusal_as_its_job_error_and_in_its_log(self):
        with future():
            r = self.old_node_status(self.server())
        text = V.refusal({"wire": "3.0", "majors": [3, 2], "formats": [1], "sw": "3.0.0"}, None)
        jobs = [j for j in r["status"] if isinstance(j, dict)]
        errs = [str(j.get("error", "")) for j in jobs]
        self.assertTrue(any(text in e for e in errs), (errs, r["status"]))
        self.assertTrue(any(text in line for line in r["log"]), r["log"])

    def test_today_the_old_node_pulls_without_an_error(self):
        r = self.old_node_status(self.server())
        self.assertFalse(any(j.get("error") for j in r["status"] if isinstance(j, dict)), r["status"])

    def test_today_the_old_client_pulls_fine(self):
        r = self.old_pull(self.server())
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["held"], 2)

    def test_a_future_server_refuses_it_and_the_text_reaches_its_why(self):
        with future():
            r = self.old_pull(self.server())
        self.assertFalse(r["ok"])
        self.assertEqual(r["why"], V.refusal({"wire": "3.0", "majors": [3, 2], "formats": [1], "sw": "3.0.0"}, None))
        self.assertTrue(r["why"].startswith("peer declares no wire version (0.1.x)"), r["why"])
        self.assertEqual(r["held"], 0)

    def test_a_format_2_thread_gives_the_old_client_the_format_text(self):
        with mock.patch.object(V, "thread_format", lambda t: 2):
            r = self.old_pull(self.server())
        self.assertFalse(r["ok"])
        self.assertTrue(r["why"].startswith("thread uses format 2, the peer reads format 1"), r["why"])


if __name__ == "__main__":
    unittest.main()
