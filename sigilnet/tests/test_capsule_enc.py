import json
import tempfile
import unittest
from pathlib import Path

from sigilnet import capsule as C
from sigilnet import envelope as V
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.node import PeerBook
from sigilnet.sync import Loopback, SyncServer, fetch_keys, pull
from sigilnet.tests.test_capsule import Base, Fake, sreq
from sigilnet.torlink import TorNode


class EncJoin(Base):
    def setUp(self):
        self.clock = __import__("sigilnet.tests.test_capsule", fromlist=["Clock"]).Clock()
        self.oh, self.jh = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.owner, self.joiner = Identity.generate("arya"), Identity.generate("carol")
        self.otor, self.jtor = TorNode(self.oh + "/tor", offline=True), TorNode(self.jh + "/tor", offline=True)
        self.ofake, self.jfake = Fake(self.otor), Fake(self.jtor)
        self.ocodec, self.jcodec = EnvCodec(self.oh + "/keys"), EnvCodec(self.jh + "/keys")
        self.om = Mirror(self.oh + "/m", clock=self.clock, rate_limit=False, codec=self.ocodec)
        self.jm = Mirror(self.jh + "/m", clock=self.clock, rate_limit=False, codec=self.jcodec)
        g = make_genesis(self.owner, "secret project", [(Identity.generate("x"), "member"), (Identity.generate("y"), "member")], ts=int(self.clock()))
        self.om.ingest(g)
        self.tid = event_id(g)
        self.om.enable_encryption(self.tid, self.owner)
        self.om.ingest(Writer(self.owner, self.om.threads[self.tid]).post("the plan is X"))
        self.obook, self.jbook = PeerBook(Path(self.oh) / "peers.json"), PeerBook(Path(self.jh) / "peers.json")
        self.server = C.JoinServer(self.oh, self.otor, self.owner, self.om, self.clock)

        class T:
            def request(s, q): return self.server.handle(q)
        self.transport_for = lambda ep: T()

    def poll(self):
        return C.poll(self.jh, self.jtor, self.joiner, self.jbook, self.transport_for, clock=self.clock, codec=self.jcodec)

    def join(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.poll()
        out = C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, C.fingerprint(self.joiner.id), clock=self.clock)
        self.ofake(out["door"])
        return block, cid, r

    def test_capsule_says_encrypted_and_keys_arrive_in_the_signed_answer(self):
        block, cid, r = self.join()
        self.assertTrue(C.decode_capsule(block, now=self.clock())["enc"])
        self.assertIn("ENCRYPTED", "\n".join(C.describe(C.decode_capsule(block, now=self.clock()))))
        self.assertEqual(self.poll(), {r["cid"]: "joined"})
        self.assertTrue(self.jcodec.is_encrypted(self.tid))
        self.assertEqual(self.jcodec.ring(self.tid).ids(), [self.tid])
        self.assertEqual(self.jcodec.ring(self.tid).get(self.tid)[1], True)           # trusted: it came in the owner's signed answer, with the owner's confirmation
        # the joiner can now read the thread: pull (genesis, then envelopes opened with the delivered key)
        tr = Loopback(SyncServer(self.om, identity=self.owner))
        self.jm.ingest(self.om.threads[self.tid].stored[self.tid])
        res = pull(self.jm, self.tid, tr, self.joiner, peer_id=self.owner.id)
        self.assertTrue(res["ok"] and not res["need_keys"], res)
        texts = sorted(e["body"].get("text") for e in self.jm.threads[self.tid].events.values() if e["kind"] == "post")
        self.assertEqual(texts, ["the plan is X"])
        self.assertNotIn(b"the plan is X", (Path(self.jh) / "m" / "threads" / self.tid / "events.jsonl").read_bytes())

    def test_enc_capsule_but_no_keys_refused(self):
        block, cid, r = self.join()
        orig = self.server._sealed_keys
        self.server._sealed_keys = lambda rec: []                                      # a hostile or broken owner answers without keys
        self.assertEqual(self.poll(), {r["cid"]: "failed"})
        self.assertIn("no keys", json.loads((Path(self.jh) / "joins.json").read_text())[r["cid"]]["why"])
        self.assertNotIn(self.owner.id, self.jbook.all())

    def test_keys_win_over_enc_false(self):
        block, cid, r = self.join()
        rec = C.Joins(self.jh).all()[r["cid"]]
        C.Joins(self.jh).edit(lambda d: d[r["cid"]].update(enc=False))
        self.assertEqual(self.poll(), {r["cid"]: "joined"})
        self.assertTrue(self.jcodec.is_encrypted(self.tid))

    def test_garbage_key_in_the_answer_refused(self):
        block, cid, r = self.join()
        other = Identity.generate("z")
        self.server._sealed_keys = lambda rec: [{"id": self.tid, "sealed": V.seal_key(other.kex_pub, other.id, self.tid, self.tid, b"k" * 32)}]     # sealed to someone else
        self.assertEqual(self.poll(), {r["cid"]: "failed"})
        self.assertFalse(self.jcodec.is_encrypted(self.tid))

    def test_answer_waits_when_owner_cannot_provide_keys(self):
        block, cid, r = self.join()
        import os
        os.unlink(self.ocodec.ring(self.tid).path)
        out = self.server.handle({"t": "join_status", "token": C.decode_capsule(block, now=self.clock())["token"]})
        self.assertEqual(out, {"t": "wait"})                                          # never answers an encrypted thread without its keys

    def test_unsigned_kex_swap_cannot_redirect_keys(self):
        """Sansa must-fix 2: a capsule holder pairing a victim's id with its own kex key is refused."""
        block, cid, _ = self.create()
        tok = C.decode_capsule(block, now=self.clock())["token"]
        victim, mallory = Identity.generate("victim"), Identity.generate("mallory")
        forged = sreq(victim, tok)
        forged["kex"] = mallory.kex_pub
        self.assertEqual(self.server.handle(forged), {"t": "refused"})
        self.assertEqual(C.pending(self.oh, self.clock), {})

    def test_plaintext_thread_join_unchanged(self):
        om = Mirror(self.oh + "/m2", clock=self.clock, rate_limit=False, codec=self.ocodec)
        g = make_genesis(self.owner, "plain one", [(Identity.generate("x"), "member"), (Identity.generate("y"), "member")])
        om.ingest(g)
        pt = event_id(g)
        self.assertFalse(C.decode_capsule(C.create(self.oh, self.otor, self.owner, om, pt, clock=self.clock, wait_address=self.ofake)[0], now=self.clock())["enc"])


if __name__ == "__main__":
    unittest.main()
