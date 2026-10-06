import json
import tempfile
import time
import unittest
from pathlib import Path

from sigilnet import capsule as C
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.node import PeerBook
from sigilnet.torlink import TorNode

A32 = "a" * 56 + ".onion"
EP = {"type": "onion", "addr": A32 + ":47200"}
CRED = {"type": "onion", "key": "A" * 52}


def sreq(who, tok, **over):
    """A join_request signed by `who` (the joiner signs its own request since round 18); `over` replaces fields BEFORE signing."""
    from sigilnet import canon
    body = {"t": "join_request", "token": tok, "sign": who.sign_pub, "kex": who.kex_pub, "name": "x", "offers": [{"endpoint": EP, "credential": CRED}], **over}
    body["sig"] = who.sign(C.JOINREQ_CTX + canon.dumps(body))
    return body


def onion_for(i):
    import base64
    return base64.b32encode(bytes([i % 256]) * 35).decode().lower()[:56] + ".onion"


class Clock:
    def __init__(self): self.t = time.time()
    def __call__(self): return self.t


class Fake:
    """Fills in the hostname file tor would create."""
    def __init__(self, tor): self.tor, self.n = tor, 0

    def __call__(self, *a):                                         # (carrier, name) since M2; the name alone still works for a single carrier
        name = a[-1]
        d = self.tor.svc_dir / name
        if not (d / "hostname").exists():
            self.n += 1
            (d / "hostname").write_text(onion_for(len(name) + self.n + hash(name) % 50 + 60 * len(list(self.tor.svc_dir.iterdir()))) + "\n")
        return self.tor.door_endpoint(name)


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.oh, self.jh = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.owner, self.joiner = Identity.generate("arya"), Identity.generate("carol")
        self.otor, self.jtor = TorNode(self.oh + "/tor", offline=True), TorNode(self.jh + "/tor", offline=True)
        self.ofake, self.jfake = Fake(self.otor), Fake(self.jtor)
        self.om = Mirror(self.oh + "/m", clock=self.clock, rate_limit=False)
        g = make_genesis(self.owner, "secret project", [], ts=int(self.clock()))
        self.om.ingest(g)
        self.tid = event_id(g)
        self.obook, self.jbook = PeerBook(Path(self.oh) / "peers.json"), PeerBook(Path(self.jh) / "peers.json")
        self.server = C.JoinServer(self.oh, self.otor, self.owner, self.om, self.clock)

        class T:
            def request(s, q): return self.server.handle(q)
        self.transport_for = lambda ep: T()

    def create(self, **kw):
        return C.create(self.oh, self.otor, self.owner, self.om, self.tid, clock=self.clock, wait_address=self.ofake, **kw)

    def accept(self, block, fp=None, **kw):
        return C.accept(self.jh, self.jtor, self.joiner, block, fp or C.fingerprint(self.owner.id), clock=self.clock, wait_address=self.jfake, **kw)

    def poll(self):
        return C.poll(self.jh, self.jtor, self.joiner, self.jbook, self.transport_for, clock=self.clock)


class Flow(Base):
    def test_full_join(self):
        block, cid, fp = self.create()
        self.assertEqual(fp, C.fingerprint(self.owner.id))
        self.assertTrue(block.startswith("SIGILNET-CAPSULE-1 "))
        self.assertEqual(self.otor.services[f"join-{cid}"]["kind"], "join")
        r = self.accept(block)
        self.assertEqual(r["fingerprint"], C.fingerprint(self.joiner.id))
        self.assertEqual(self.poll(), {r["cid"]: "requested"})
        self.assertEqual(self.poll(), {})                                   # waiting for the human
        pend = C.pending(self.oh, self.clock)
        self.assertEqual(len(pend), 1)
        with self.assertRaises(C.CapsuleError):
            C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, "aaaa bbbb cccc dddd", clock=self.clock)
        self.assertNotIn(self.joiner.id, self.om.threads[self.tid].state()["members"])       # nothing changed on a wrong fingerprint
        out = C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, C.fingerprint(self.joiner.id).upper(), clock=self.clock)
        self.assertEqual(self.om.threads[self.tid].state()["members"][self.joiner.id]["role"], "member")
        self.assertIn(self.joiner.id, self.obook.all())
        self.assertEqual(self.otor.services[out["door"]]["agent"], self.joiner.id)
        self.ofake(out["door"])
        self.assertEqual(self.poll(), {r["cid"]: "joined"})
        self.assertIn(self.owner.id, self.jbook.all())
        self.assertEqual(self.jbook.all()[self.owner.id]["threads"], [self.tid])
        # the join door is torn down after the grace time, and the bootstrap key is gone from the joiner
        self.assertIn(f"join-{cid}", self.otor.services)
        self.clock.t += C.GRACE + 1
        self.assertEqual(C.sweep(self.oh, self.otor, clock=self.clock), [cid])
        self.assertNotIn(f"join-{cid}", self.otor._load_services())
        self.assertFalse((self.otor.svc_dir / f"join-{cid}").exists())
        self.assertEqual(list(self.jtor.auth_in.glob("*.auth_private")), list(self.jtor.auth_in.glob("*.auth_private")))
        rec = json.loads((Path(self.jh) / "joins.json").read_text())[r["cid"]]
        self.assertEqual(rec["state"], "joined")

    def test_collected_shortens_grace(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.poll()
        out = C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, C.fingerprint(self.joiner.id), clock=self.clock)
        self.ofake(out["door"])
        self.poll()
        self.clock.t += 130
        self.assertEqual(C.sweep(self.oh, self.otor, clock=self.clock), [cid])

    def test_expiry_tears_down_even_unused(self):
        block, cid, _ = self.create(ttl=120)
        self.clock.t += 121
        self.assertEqual(C.sweep(self.oh, self.otor, clock=self.clock), [cid])
        self.assertNotIn(f"join-{cid}", self.otor._load_services())
        self.assertFalse((Path(self.oh) / "peerkeys" / f"cap-{cid}-onion.priv").exists())
        with self.assertRaises(C.CapsuleError):
            self.accept(block)

    def test_reject_tears_down(self):
        block, cid, _ = self.create()
        self.accept(block)
        self.poll()
        self.assertTrue(C.reject(self.oh, self.otor, cid, clock=self.clock))
        self.assertNotIn(f"join-{cid}", self.otor._load_services())
        self.assertFalse(C.reject(self.oh, self.otor, cid, clock=self.clock))
        self.assertEqual(self.server.handle({"t": "join_status", "token": json.loads(__import__("base64").urlsafe_b64decode(block.split()[1] + "==").decode())["token"]})["t"], "refused")

    def test_startup_sweep_after_crash(self):
        block, cid, _ = self.create(ttl=60)
        self.clock.t += 61
        fresh_tor = TorNode(self.oh + "/tor", offline=True)                # a new process after a kill -9: no memory, only the files
        C.sweep(self.oh, fresh_tor, clock=self.clock)
        self.assertNotIn(f"join-{cid}", fresh_tor._load_services())
        self.assertNotIn(f"join-{cid}", TorNode(self.oh + "/tor", offline=True).config())

    def test_second_request_burns_token(self):
        block, cid, _ = self.create()
        tok = C.decode_capsule(block, now=self.clock())["token"]
        stranger = Identity.generate("x")
        req = lambda who: sreq(who, tok)
        self.assertEqual(self.server.handle(req(stranger))["t"], "pending")
        self.assertEqual(self.server.handle(req(self.joiner))["t"], "refused")       # one pending request per token
        self.assertEqual(len(C.pending(self.oh, self.clock)), 1)

    def test_wrong_token_and_junk_refused(self):
        self.create()
        for q in ({"t": "join_request", "token": "0" * 32}, {"t": "join_status", "token": "0" * 32}, {"t": "list", "thread": self.tid}, None, [], {"token": 5}, {"t": "join_status"}):
            self.assertEqual(self.server.handle(q), {"t": "refused"}, q)

    def test_join_door_does_not_answer_sync_or_reads(self):
        from sigilnet.noderun import door_handler
        from sigilnet.sync import SyncServer
        h = door_handler("join", None, SyncServer(self.om, identity=self.owner), {"join": self.server.handle})
        self.assertEqual(h({"t": "summary", "thread": self.tid, "nonce": "0" * 16}), {"t": "refused"})

    def test_existing_member_cannot_use_a_capsule(self):
        block, cid, _ = self.create()
        tok = C.decode_capsule(block, now=self.clock())["token"]
        out = self.server.handle(sreq(self.owner, tok, name="me", port=1))
        self.assertEqual(out, {"t": "refused"})

    def test_wrong_fingerprint_refuses_to_join(self):
        block, cid, _ = self.create()
        with self.assertRaises(C.CapsuleError):
            self.accept(block, "abcd efgh ijkl mnop")
        self.assertEqual(self.jtor._load_services(), {})                   # nothing was built

    def test_capsule_reuse_and_own_capsule(self):
        block, cid, _ = self.create()
        self.accept(block)
        with self.assertRaises(C.CapsuleError):
            self.accept(block)
        with self.assertRaises(C.CapsuleError):
            C.accept(self.oh, self.otor, self.owner, block, C.fingerprint(self.owner.id), clock=self.clock, wait_address=self.ofake)

    def test_only_owner_private_limit(self):
        with self.assertRaises(C.CapsuleError):
            C.create(self.oh, self.otor, self.joiner, self.om, self.tid, clock=self.clock, wait_address=self.ofake)
        pm = Mirror(tempfile.mkdtemp())
        pg = make_genesis(self.owner, "pub", [], visibility="public")
        pm.ingest(pg)
        with self.assertRaises(C.CapsuleError):
            C.create(self.oh, self.otor, self.owner, pm, event_id(pg), clock=self.clock, wait_address=self.ofake)
        for ttl in (10, 10 ** 6):
            with self.assertRaises(C.CapsuleError):
                self.create(ttl=ttl)
        for _ in range(C.MAX_OPEN):
            self.create()
        with self.assertRaises(C.CapsuleError):
            self.create()

    def test_passphrase(self):
        block, cid, _ = self.create(passphrase="correct horse")
        self.assertNotIn("boot\":\"", __import__("base64").urlsafe_b64decode(block.split()[1] + "==").decode())
        with self.assertRaises(C.CapsuleError):
            self.accept(block, passphrase="wrong")
        self.assertEqual(self.jtor._load_services(), {})
        self.accept(block, passphrase="correct horse")

    def test_no_failed_create_leaves_a_door(self):
        def nowhere(*a): return None
        with self.assertRaises(C.CapsuleError):
            C.create(self.oh, self.otor, self.owner, self.om, self.tid, clock=self.clock, wait_address=nowhere)
        self.assertEqual([k for k in self.otor._load_services() if k.startswith("join-")], [])


class Hostile(Base):
    def test_capsule_validation(self):
        block, cid, _ = self.create()
        good = C.decode_capsule(block, now=self.clock())
        def mk(**kw):
            c = {**good, **kw}
            return C.encode_capsule(c)
        bad = [mk(v=1), mk(v=3), mk(thread="zz"), mk(token="00"), mk(exp=int(self.clock()) - 5), mk(title="x\x1b[31m"), mk(title="a" * 200),
               mk(owner={**good["owner"], "id": "a" * 32}), mk(owner={**good["owner"], "name": "\x07"}),
               mk(joins=[{**good["joins"][0], "endpoint": {"type": "onion", "addr": "evil.example.com:1"}}]), mk(joins=[{**good["joins"][0], "endpoint": {"type": "onion", "addr": good["joins"][0]["endpoint"]["addr"].split(":")[0] + ":0"}}]),
               mk(joins=[{**good["joins"][0], "endpoint": {"type": "xyz", "addr": "foo"}}]), mk(joins=[{"onion": A32, "port": 47200}]), mk(joins=[]), mk(joins="x"), mk(join=good["joins"][0]["endpoint"]),
               mk(joins=[{**good["joins"][0], "boot": "short"}]), mk(joins=[{**good["joins"][0], "boot": {"type": "zzz", "key": "x"}}]), mk(joins=[{**good["joins"][0], "boot": {"type": "onion", "key": "x"}}]),
               mk(joins=[{**good["joins"][0], "dial": "x"}]), mk(joins=[{**good["joins"][0], "dial": {"type": "zzz", "key": "x"}}]),
               mk(joins=[good["joins"][0], good["joins"][0]]), mk(joins=[good["joins"][0]] * 5),
               mk(observers=[{"id": "x", "name": "y"}]), mk(rules={"a": "b"}), mk(bridges=["ClientTransportPlugin obfs4 exec /bin/sh"]),
               mk(bridges=["Bridge obfs4 1.2.3.4:5 \\"]), mk(bridges=["Bridge x\nClientTransportPlugin y exec z"]), mk(bridges=["UseBridges 1"]),
               "SIGILNET-CAPSULE-1 " + "A" * 10, "nonsense", "SIGILNET-CAPSULE-1 x", "", None, 5, "SIGILNET-CAPSULE-1 " + "A" * 9000 + " 00000000"]
        for b in bad:
            with self.assertRaises(C.CapsuleError, msg=str(b)[:60]):
                C.decode_capsule(b, now=self.clock())
        extra = dict(good, evil=1)
        with self.assertRaises(C.CapsuleError):
            C.decode_capsule(C.encode_capsule(extra), now=self.clock())

    def test_checksum_detects_damage_but_is_not_authenticity(self):
        block, cid, _ = self.create()
        p = block.split()
        with self.assertRaises(C.CapsuleError):
            C.decode_capsule(f"{p[0]} {p[1][:-2]}AA {p[2]}", now=self.clock())
        # a forged capsule with a VALID checksum and a different owner decodes fine: only the fingerprint comparison stops it
        good = C.decode_capsule(block, now=self.clock())
        fake = Identity.generate("mallory")
        forged = C.encode_capsule({**good, "owner": {"id": fake.id, "sign": fake.sign_pub, "kex": fake.kex_pub, "name": "arya"}})
        C.decode_capsule(forged, now=self.clock())
        with self.assertRaises(C.CapsuleError):
            self.accept(forged)                                              # the fingerprint the human was told is the real owner's

    def test_forged_join_answer_rejected(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.poll()
        C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, C.fingerprint(self.joiner.id), clock=self.clock)
        rec = json.loads((Path(self.jh) / "joins.json").read_text())[r["cid"]]
        mallory = Identity.generate("m")
        body = {"t": "joined", "token": rec["token"], "endpoints": [EP], "thread": rec["thread"], "owner": rec["owner"]["id"], "by": mallory.sign_pub}
        body["rsig"] = mallory.sign(C.JOIN_CTX + __import__("sigilnet.canon", fromlist=["x"]).dumps(body))
        self.assertFalse(C._verify_joined(body, rec))                        # signed by the wrong key
        body2 = {k: v for k, v in body.items() if k != "rsig"}
        self.assertFalse(C._verify_joined(body2, rec))
        self.assertFalse(C._verify_joined({}, rec))

    def test_bad_join_requests(self):
        block, cid, _ = self.create()
        tok = C.decode_capsule(block, now=self.clock())["token"]
        x = Identity.generate("x")
        base = sreq(x, tok)
        for k, v in (("sign", "00" * 32), ("kex", "zz"), ("kex", 5), ("name", "\x1b"), ("name", ""), ("name", "a" * 100), ("offers", [{"endpoint": {"type": "onion", "addr": "x.com:1"}, "credential": CRED}]), ("offers", [{"endpoint": {"type": "onion", "addr": A32 + ":0"}, "credential": CRED}]),
                     ("offers", "str"), ("offers", []), ("offers", [{"endpoint": {"type": "xyz", "addr": "foo"}, "credential": CRED}]), ("offers", [{"endpoint": {"type": "onion", "addr": A32}, "credential": CRED}]),
                     ("offers", [{"endpoint": EP, "credential": "nope"}]), ("offers", [{"endpoint": EP, "credential": {"type": "zzz", "key": "x"}}]), ("offers", [{"endpoint": EP, "credential": {"type": "onion", "key": "short"}}]),
                     ("offers", [{"endpoint": EP, "credential": CRED}, {"endpoint": EP, "credential": CRED}]), ("offers", [{"endpoint": EP}]), ("offers", [{"endpoint": EP, "credential": CRED, "x": 1}])):
            self.assertEqual(self.server.handle(sreq(x, tok, **{k: v})), {"t": "refused"}, (k, v))
        self.assertEqual(self.server.handle({**base, "sig": "0" * 128}), {"t": "refused"})                 # unsigned / wrongly signed
        self.assertEqual(self.server.handle({k: v for k, v in base.items() if k != "sig"}), {"t": "refused"})
        other = Identity.generate("mallory")
        self.assertEqual(self.server.handle({**base, "kex": other.kex_pub}), {"t": "refused"})            # the kex key is covered by the signature (Sansa must-fix 2)
        self.assertEqual(self.server.handle({**base, "extra": 1}), {"t": "refused"})
        self.assertEqual(len(C.pending(self.oh, self.clock)), 0)             # none of those burned the token
        self.assertEqual(self.server.handle(base)["t"], "pending")


if __name__ == "__main__":
    unittest.main()


class DoorNames(Base):
    def test_door_takeover_by_prefix_collision_refused(self):
        """Sansa round 15 F2: add_service re-binds an existing door to any agent; a joiner whose id shares the first characters with another peer's must not take it over."""
        block, cid, _ = self.create()
        self.accept(block)
        self.poll()
        rec = C.Store(self.oh).all()[cid]
        victim = "a" * 27 + "bbbbb"
        attacker = rec["req"]["agent"]
        door = f"peer-{attacker[:27]}"
        self.otor.add_service(door, "A" * 52, agent=victim)                  # a door of that name already belongs to someone else
        with self.assertRaises(C.CapsuleError):
            C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, C.fingerprint(attacker), clock=self.clock)
        self.assertEqual(self.otor.services[door]["agent"], victim)
        self.assertNotIn(attacker, self.om.threads[self.tid].state()["members"])
        self.assertEqual(C.Store(self.oh).all()[cid]["state"], "pending")      # and the human can still decide

    def test_joiner_side_same(self):
        block, cid, _ = self.create()
        c = C.decode_capsule(block, now=self.clock())
        self.jtor.add_service(f"owner-{c['owner']['id'][:26]}", "A" * 52, agent="c" * 32)
        with self.assertRaises(C.CapsuleError):
            self.accept(block)
