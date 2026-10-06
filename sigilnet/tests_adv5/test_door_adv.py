import contextlib
import io
import json
import re
import tempfile
import threading
import unittest

from sigilnet import cli, noderun
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.inbox import Inbox
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.publicread import PublicRead
from sigilnet.sync import SyncServer, sign_request
from sigilnet.tcp import TcpServer
from sigilnet.torlink import TorNode
from sigilnet.tests.test_cli_public import run
from sigilnet.tests.test_inbox import Base


def strip_nonce(d):
    d = dict(d)
    for k in ("nonce", "rsig"):
        d.pop(k, None)
    return d


class ReadDoor(Base):
    def setUp(self):
        super().setUp()
        self.me = self.owner
        self.srv = SyncServer(self.m, identity=self.owner, clock=self.clock)
        self.pr = PublicRead(self.srv, clock=self.clock)
        g = make_genesis(self.owner, "secret", [], visibility="private", ts=int(self.clock()))
        self.m.ingest(g)
        self.ptid = event_id(g)
        self.pev = Writer(self.owner, self.m.threads[self.ptid]).post("PRIVATE TEXT")
        self.m.ingest(self.pev)

    def q(self, **kw):
        return self.pr.handle({"nonce": "n" * 16, **kw})

    def test_private_equals_missing_for_every_type(self):
        for body in ({"t": "summary"}, {"t": "list"}, {"t": "list", "page": -5}, {"t": "list", "page": "x"}, {"t": "get", "ids": ["z"]},
                     {"t": "get", "ids": [event_id(self.pev)]}, {"t": "get"}, {"t": "get", "ids": list(range(10 ** 4))}):
            a = strip_nonce(self.q(thread=self.ptid, **body))
            b = strip_nonce(self.q(thread="c" * 32, **body))
            self.assertEqual(a, b, body)
            self.assertEqual(a["t"], "unknown")

    def test_private_text_and_awaiting_never_served(self):
        r, ev = self.req()
        self.inbox.handle(r)
        eid = event_id(ev)
        self.assertIn(eid, self.t.awaiting)
        lst = self.q(thread=self.tid, t="list")
        self.assertNotIn(eid, lst["ids"])
        got = self.q(thread=self.tid, t="get", ids=[eid, event_id(self.pev)])
        self.assertEqual(got["events"], [])
        self.assertNotIn("PRIVATE TEXT", json.dumps(self.q(thread=self.tid, t="get", ids=list(self.t.stored))))
        self.assertEqual(self.q(thread=self.tid, t="summary")["n"], len(self.t.resolved_ids()))

    def test_cross_thread_get_does_not_leak(self):
        got = self.q(thread=self.tid, t="get", ids=[event_id(self.pev)])
        self.assertEqual(got.get("events"), [])

    def test_only_read_types(self):
        for t in ("notify", "submit", "challenge", "x", None, 5, [], {}):
            out = self.q(thread=self.tid, t=t)
            self.assertEqual(out["t"], "error", t)

    def test_extra_fields_refused_and_no_raise(self):
        for bad in ({"t": "summary", "thread": self.tid, "evil": 1}, {"t": "summary", "thread": self.tid, "nonce": 5},
                    {"t": "summary", "thread": self.tid, "nonce": "short"}, []):
            self.assertEqual(self.pr.handle(bad)["t"], "error")

    def test_budget_bounds_and_window(self):
        pr = PublicRead(self.srv, clock=self.clock, req_per_min=5)
        outs = [pr.handle({"t": "summary", "thread": self.tid, "nonce": "n" * 16})["t"] for _ in range(8)]
        self.assertEqual(outs.count("summary"), 5)
        self.clock.t += 61
        self.assertEqual(pr.handle({"t": "summary", "thread": self.tid, "nonce": "n" * 16})["t"], "summary")

    def test_bytes_budget(self):
        pr = PublicRead(self.srv, clock=self.clock, bytes_per_min=50)
        pr.handle({"t": "list", "thread": self.tid, "nonce": "n" * 16})
        self.assertEqual(pr.handle({"t": "list", "thread": self.tid, "nonce": "n" * 16})["why"], "rate limited")


class Doors(unittest.TestCase):
    def node(self, services):
        home = tempfile.mkdtemp()
        tn = TorNode(home + "/tor", offline=True)
        tn.svc_file.write_text(json.dumps(services))
        return tn

    def test_services_json_injection_dropped(self):
        ok = {"port": 47210, "agent": None, "kind": "read"}
        evil = {"read\nHiddenServiceDir /": ok, "a": {**ok, "kind": "read\nHiddenServicePort 1 1.1.1.1:1"}, "b": {**ok, "port": "47211"},
                "c": {**ok, "port": True}, "d": {**ok, "agent": "x"}, "e": {**ok, "kind": ["read"]}, "f": {**ok, "kind": None}, "g": [], "h": {"port": 99999},
                "good": ok, "../x": ok, "A": ok, "": ok}
        tn = self.node(evil)
        self.assertEqual(set(tn._load_services()), {"good"})
        tn.services = tn._load_services()
        cfg = tn.config()
        self.assertEqual(cfg.count("HiddenServiceDir"), 1)
        self.assertNotIn("1.1.1.1", cfg)

    def test_add_public_service_names_and_kinds(self):
        tn = self.node({})
        for name in ("a\n", "A", "", "x" * 33, "../x", "a b", None, "a\x00"):
            with self.assertRaises(ValueError):
                tn.add_public_service(name, "read")
        for kind in ("peer", "join", "read\n", None, "", ["read"]):
            with self.assertRaises((ValueError, TypeError)):
                tn.add_public_service("ok", kind)

    def test_public_door_never_gets_client_auth(self):
        tn = self.node({})
        tn.add_public_service("pub", "inbox")
        with self.assertRaises(ValueError):
            tn.add_service("pub", "A" * 52, None, "peer")
        with self.assertRaises(ValueError):
            tn.add_service("pub", "A" * 52, None, "join")
        self.assertFalse((tn.svc_dir / "pub" / "authorized_clients").exists())
        with self.assertRaises(ValueError):
            tn.add_public_service("pub", "read")

    def test_kind_handler_routing(self):
        seen = []
        srv = SyncServer(Mirror(tempfile.mkdtemp()))
        h = {"read": lambda r: seen.append("read") or {"t": "x"}}
        for kind in ("inbox", "join", "weird", None, "peer"):
            out = noderun.door_handler(kind, None, srv, h)
            if kind == "peer":
                continue
            self.assertEqual(out({"t": "summary", "thread": "a" * 32})["t"], "unknown", kind)
        self.assertEqual(noderun.door_handler("read", None, srv, h)({})["t"], "x")

    def test_unbound_peer_door_with_agent_none_is_not_a_public_door_by_kind(self):
        # kind "peer" + agent None is the only way to a sync server; a public kind must never reach it even if handlers are empty
        srv = SyncServer(Mirror(tempfile.mkdtemp()))
        for kind in ("read", "inbox", "join"):
            r = noderun.door_handler(kind, None, srv, {})({"t": "summary", "thread": "a" * 32, "nonce": "n" * 16})
            self.assertEqual(r["t"], "unknown")


ESC = "\x1b[2J\x1b]0;pwned\x07"


class HostileInboxOutput(unittest.TestCase):
    """The guest's terminal must not be driven by the (hostile) inbox owner's answers."""

    def setUp(self):
        self.o, self.g = tempfile.mkdtemp(), tempfile.mkdtemp()
        run(self.o, "id", "init", "arya")
        run(self.g, "id", "init", "stranger")
        rc, out, _ = run(self.o, "new", "open topic", "--public")
        self.tid = out.split("thread ")[1].split()[0]
        run(self.o, "post", self.tid[:8], "who can help?")
        m = Mirror(self.o + "/mirror")
        self.root = [i for i, e in m.threads[self.tid].stored.items() if e["kind"] == "post"][0]
        me = Identity.load(self.o + "/identity.json")
        self.read = TcpServer("127.0.0.1", 0, None, PublicRead(SyncServer(m, identity=me)).handle).start()
        self.addCleanup(self.read.stop)
        self.assertEqual(run(self.g, "guest", "pull", self.tid, "--loopback", str(self.read.port))[0], 0)

    def submit(self, handler):
        ib = TcpServer("127.0.0.1", 0, None, handler).start()
        self.addCleanup(ib.stop)
        return run(self.g, "guest", "submit", self.tid, "--loopback", str(ib.port), "--reply-to", self.root[:8], "--text", "hi")

    def test_escape_in_answer_type(self):
        def h(req):
            if req.get("t") == "challenge":
                return {"t": "challenge", "thread": req["thread"], "salt": "ab" * 16, "bits": 0}
            return {"t": ESC, "why": "x"}
        rc, out, err = self.submit(h)
        self.assertNotIn("\x1b", out + err)

    def test_escape_in_challenge_why(self):
        rc, out, err = self.submit(lambda req: {"t": "refused", "why": ESC})
        self.assertNotIn("\x1b", out + err)

    def test_escape_in_pull_failure(self):
        bad = TcpServer("127.0.0.1", 0, None, lambda req: {"t": "error", "why": ESC, "nonce": req.get("nonce"), "r": 1}).start()
        self.addCleanup(bad.stop)
        rc, out, err = run(self.g, "guest", "pull", self.tid, "--loopback", str(bad.port))
        self.assertNotIn("\x1b", out + err)


if __name__ == "__main__":
    unittest.main()
