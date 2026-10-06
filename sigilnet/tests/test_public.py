import os
import tempfile
import unittest

from sigilnet import canon
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.noderun import Doors, door_handler
from sigilnet.publicread import PublicRead
from sigilnet.sync import SyncServer, pull, sign_request, Loopback
from sigilnet.torlink import TorNode
from sigilnet.tcp import TcpTransport


def setup(vis):
    m = Mirror(tempfile.mkdtemp() + "/m", rate_limit=False)
    owner = Identity.generate("arya")
    g = make_genesis(owner, "t", [], visibility=vis)
    m.ingest(g)
    tid = event_id(g)
    root = Writer(owner, m.threads[tid]).post("hello")
    m.ingest(root)
    return m, owner, tid, event_id(root)


def rq(body):
    return {**body, "nonce": os.urandom(8).hex()}


class Read(unittest.TestCase):
    def setUp(self):
        self.m, self.owner, self.tid, self.rid = setup("public")
        self.srv = SyncServer(self.m, identity=self.owner)
        self.pr = PublicRead(self.srv)

    def test_unsigned_read_works(self):
        r = self.pr.handle(rq({"t": "summary", "thread": self.tid}))
        self.assertEqual((r["t"], r["n"]), ("summary", 2))
        r = self.pr.handle(rq({"t": "list", "thread": self.tid}))
        self.assertIn(self.rid, r["ids"])
        r = self.pr.handle(rq({"t": "get", "thread": self.tid, "ids": [self.rid]}))
        self.assertEqual(len(r["events"]), 1)
        self.assertEqual(r["r"], 1)

    def test_full_pull_by_a_stranger(self):
        stranger = Identity.generate("eve")
        m2 = Mirror(tempfile.mkdtemp() + "/m2", rate_limit=False)
        m2.ingest(self.m.threads[self.tid].stored[self.tid])       # the genesis (the address gave us the thread id)
        res = pull(m2, self.tid, Loopback(self.srv) if False else type("T", (), {"request": lambda s, q: self.pr.handle(q)})(), stranger, peer_id=self.owner.id)
        self.assertTrue(res["ok"], res)
        self.assertEqual(len(m2.threads[self.tid].resolved_ids()), 2)

    def test_notify_and_everything_else_refused(self):
        for t in ("notify", "post", "submit", "challenge", ""):
            r = self.pr.handle(rq({"t": t, "thread": self.tid, "leaves": []}) if t == "notify" else rq({"t": t, "thread": self.tid}))
            self.assertEqual(r["t"], "error", t)

    def test_extra_fields_refused(self):
        self.assertEqual(self.pr.handle(rq({"t": "summary", "thread": self.tid, "x": 1}))["t"], "error")
        for junk in (None, [], "x", {"t": "summary"}, {"t": "summary", "thread": self.tid}, {"t": "summary", "thread": self.tid, "nonce": "short"}):
            self.assertEqual(self.pr.handle(junk)["t"], "error")

    def test_private_equals_missing(self):
        m, owner, tid, rid = setup("private")
        pr = PublicRead(SyncServer(m, identity=owner))
        a = pr.handle({"t": "summary", "thread": tid, "nonce": "0" * 16})
        b = pr.handle({"t": "summary", "thread": "f" * 32, "nonce": "0" * 16})
        strip = lambda x: {k: v for k, v in x.items() if k not in ("rsig",)}
        self.assertEqual(strip(a), strip(b))
        self.assertEqual(a["t"], "unknown")
        for q in ({"t": "list", "thread": tid}, {"t": "get", "thread": tid, "ids": [rid]}):
            self.assertEqual(pr.handle({**q, "nonce": "1" * 16})["t"], "unknown")

    def test_budget(self):
        pr = PublicRead(self.srv, req_per_min=3)
        out = [pr.handle(rq({"t": "summary", "thread": self.tid}))["t"] for _ in range(5)]
        self.assertEqual(out, ["summary"] * 3 + ["error"] * 2)
        pr = PublicRead(self.srv, bytes_per_min=50)
        self.assertEqual(pr.handle(rq({"t": "list", "thread": self.tid}))["t"], "list")
        self.assertEqual(pr.handle(rq({"t": "list", "thread": self.tid}))["why"], "rate limited")

    def test_bad_page_and_ids(self):
        self.assertEqual(self.pr.handle(rq({"t": "list", "thread": self.tid, "page": -1}))["t"], "error")
        self.assertEqual(self.pr.handle(rq({"t": "get", "thread": self.tid, "ids": ["zz"]}))["t"], "error")
        self.assertEqual(self.pr.handle(rq({"t": "get", "thread": self.tid, "ids": [self.rid] * 500}))["t"], "error")

    def test_signed_fields_ignored_not_trusted(self):
        req = sign_request(Identity.generate("x"), {"t": "summary", "thread": self.tid})
        req["sig"] = "0" * 128                                      # a bad signature does not matter: the answer is public data anyway
        self.assertEqual(self.pr.handle(req)["t"], "summary")


class Kinds(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.tor = TorNode(self.d + "/tor", offline=True)

    def test_public_door_has_no_client_auth_and_fingerprints(self):
        port = self.tor.add_public_service("public-read", "read")
        self.assertEqual(self.tor.add_public_service("public-read", "read"), port)   # idempotent
        self.tor.add_public_service("public-inbox", "inbox")
        self.tor.reconfigure()
        cfg = self.tor.config()
        self.assertIn("HiddenServiceDir", cfg)
        self.assertEqual(cfg.count("HiddenServicePort"), 2)
        self.assertFalse((self.tor.svc_dir / "public-read" / "authorized_clients").exists())
        self.assertEqual(self.tor.services["public-read"]["kind"], "read")
        self.assertNotEqual(self.tor.services["public-read"]["port"], self.tor.services["public-inbox"]["port"])
        self.assertEqual(oct((self.tor.svc_dir / "public-read").stat().st_mode & 0o777), "0o700")

    def test_kind_cannot_change(self):
        self.tor.add_public_service("a", "read")
        with self.assertRaises(ValueError):
            self.tor.add_public_service("a", "inbox")
        with self.assertRaises(ValueError):
            self.tor.add_service("a", "A" * 52)
        self.tor.add_service("p", "A" * 52, kind="peer")
        with self.assertRaises(ValueError):
            self.tor.add_public_service("p", "read")
        for bad in ("shared", "peer", "", None):
            with self.assertRaises(ValueError):
                self.tor.add_public_service("z", bad)
        with self.assertRaises(ValueError):
            self.tor.add_service("q", "A" * 52, agent="a" * 32, kind="join")      # a join door is never bound to an agent

    def test_services_json_bad_kind_dropped(self):
        self.tor.add_public_service("ok", "read")
        import json
        raw = json.loads(self.tor.svc_file.read_text())
        raw["evil"] = {"port": 47999, "agent": None, "kind": "admin"}
        raw["pubagent"] = {"port": 47998, "agent": "a" * 32, "kind": "read"}
        self.tor.svc_file.write_text(json.dumps(raw))
        self.assertEqual(set(self.tor._load_services()), {"ok"})

    def test_public_kinds_never_reach_the_sync_server(self):
        m, owner, tid, rid = setup("private")
        srv = SyncServer(m, identity=owner)
        h = door_handler("inbox", None, srv, {})                    # kind with no handler: the stranger's answer, never sync
        self.assertEqual(h({"t": "summary", "thread": tid})["t"], "unknown")
        h = door_handler("join", None, srv, {"join": lambda r: {"t": "joined"}})
        self.assertEqual(h({})["t"], "joined")
        h = door_handler("peer", "a" * 32, srv, {})
        self.assertEqual(h({"from": "b" * 32})["t"], "unknown")

    def test_doors_follow_kinds_over_tcp(self):
        m, owner, tid, rid = setup("public")
        srv = SyncServer(m, identity=owner)
        self.tor.service_base = __import__("random").randrange(20000, 31000)       # (a fixed base collided with other suites running in parallel; below the ephemeral range 32768-60999 so no outgoing socket of another test can hold it)
        self.tor.add_public_service("public-read", "read")
        self.tor.add_public_service("public-inbox", "inbox")
        doors = Doors(self.tor, srv, lambda *a: None, {"read": PublicRead(srv).handle, "inbox": lambda r: {"t": "inbox-here"}})
        try:
            doors.sync()
            ports = {n: s["port"] for n, s in self.tor.services.items()}
            r = TcpTransport("127.0.0.1", ports["public-read"], None).request(rq({"t": "summary", "thread": tid}))
            self.assertEqual(r["t"], "summary")
            r = TcpTransport("127.0.0.1", ports["public-inbox"], None).request({"t": "x"})
            self.assertEqual(r["t"], "inbox-here")
            r = TcpTransport("127.0.0.1", ports["public-inbox"], None).request(rq({"t": "summary", "thread": tid}))
            self.assertEqual(r["t"], "inbox-here")                   # the inbox door does not serve reads
        finally:
            doors.stop()


if __name__ == "__main__":
    unittest.main()
