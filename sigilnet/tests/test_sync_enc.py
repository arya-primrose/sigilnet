import tempfile
import unittest

from sigilnet import envelope as V
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.sync import Loopback, SyncServer, fetch_keys, pull


class Net(unittest.TestCase):
    def node(self, who):
        root = tempfile.mkdtemp()
        codec = EnvCodec(root + "/keys")
        return Mirror(root + "/m", codec=codec, rate_limit=False), codec

    def setUp(self):
        self.a, self.b, self.c, self.d = (Identity.generate(n) for n in "abcd")
        self.ma, self.ca = self.node(self.a)
        g = make_genesis(self.a, "secret", [(self.b, "member"), (self.c, "member"), (self.d, "member")])
        self.ma.ingest(g)
        self.tid = event_id(g)
        self.ma.enable_encryption(self.tid, self.a)
        self.ma.ingest(Writer(self.a, self.ma.threads[self.tid]).post("top secret words"))
        self.srv = SyncServer(self.ma, identity=self.a)
        self.tr = Loopback(self.srv)
        self.mb, self.cb = self.node(self.b)
        self.mb.ingest(g)                                        # the genesis is public knowledge (plaintext by design)

    def pull_b(self, **kw):
        return pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, **kw)

    def texts(self, m):
        return sorted(e["body"].get("text") for e in m.threads[self.tid].events.values() if e["kind"] == "post")

    def test_wire_is_envelopes_not_plaintext(self):
        from sigilnet.sync import sign_request
        ids = list(self.ma.threads[self.tid].stored)
        resp = self.tr.request(sign_request(self.b, {"t": "get", "thread": self.tid, "ids": ids}, aud=self.a.id))
        body = repr(resp)
        self.assertNotIn("top secret", body)
        kinds = [("ev" if "kind" in x else "env") for x in resp["events"]]
        self.assertEqual(sorted(kinds), ["env", "ev"])            # exactly the genesis is raw

    def test_pull_without_key_reports_need_keys_not_junk(self):
        r = self.pull_b()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["rejected"], 0)
        self.assertEqual(r["need_keys"], {self.tid})
        self.assertEqual(self.texts(self.mb), [])

    def test_key_fetch_then_pull(self):
        r = self.pull_b()
        got = fetch_keys(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, need=r["need_keys"], unopened=r["unopened"])
        self.assertTrue(got["ok"], got)
        self.assertEqual(got["installed"], 1)
        self.assertEqual(self.cb.ring(self.tid).get(self.tid)[1], True)      # verified: it opened a held envelope
        r2 = self.pull_b()
        self.assertTrue(r2["ok"] and not r2["need_keys"], r2)
        self.assertEqual(self.texts(self.mb), ["top secret words"])
        import os
        self.assertTrue(self.cb.is_encrypted(self.tid))                      # the marker came with the first key

    def test_removed_member_gets_no_new_key_and_cannot_read_new_events(self):
        r = self.pull_b()
        fetch_keys(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, need=r["need_keys"], unopened=r["unopened"])
        self.pull_b()
        t = self.ma.threads[self.tid]
        rm = Writer(self.a, t).admin("member_remove", {"agent": self.b.id})
        self.assertTrue(self.ma.ingest(rm).ok)
        e1 = event_id(rm)
        self.ca.ring(self.tid).create(e1, self.a)                                       # the owner makes the new epoch's key
        self.ma.ingest(Writer(self.a, t).post("after the removal"))
        r = self.pull_b()                                                       # B is a stranger now: "unknown"
        self.assertFalse(r["ok"])
        # and B asking for keys gets nothing
        got = fetch_keys(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, need={e1})
        self.assertFalse(got["ok"])
        self.assertEqual(self.texts(self.mb), ["top secret words"])
        # C, still a member, gets both epochs
        mc, cc = self.node(self.c)
        mc.ingest(self.ma.threads[self.tid].stored[self.tid])
        rc = pull(mc, self.tid, self.tr, self.c, peer_id=self.a.id)
        got = fetch_keys(mc, self.tid, self.tr, self.c, peer_id=self.a.id, need=rc["need_keys"], unopened=rc["unopened"])
        self.assertEqual(got["installed"], 1)                                   # epoch 0 first: only reading the removal (sealed under epoch 0) reveals epoch 1
        rc = pull(mc, self.tid, self.tr, self.c, peer_id=self.a.id)
        self.assertEqual(len(rc["need_keys"]), 1)
        got = fetch_keys(mc, self.tid, self.tr, self.c, peer_id=self.a.id, need=rc["need_keys"], unopened=rc["unopened"])
        self.assertEqual(got["installed"], 1)
        rc = pull(mc, self.tid, self.tr, self.c, peer_id=self.a.id)
        self.assertTrue(rc["ok"] and not rc["need_keys"], rc)
        self.assertEqual(self.texts(mc), ["after the removal", "top secret words"])

    def test_plaintext_downgrade_is_junk(self):
        r = self.pull_b()
        fetch_keys(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, need=r["need_keys"], unopened=r["unopened"])
        real = list(self.ma.threads[self.tid].stored.values())
        forged = Writer(self.a, self.ma.threads[self.tid]).post("plain injected")
        class Evil:
            def request(s, req):
                out = self.tr.request(req)
                if out.get("t") == "events":
                    out["events"] = [e for e in real if e["kind"] != "genesis"] + [forged]
                    out.pop("rsig", None)
                return out
        res = pull(self.mb, self.tid, Evil(), self.b, peer_id=None)
        self.assertGreater(res["rejected"], 0)
        self.assertNotIn(event_id(forged), self.mb.threads[self.tid].events)

    def test_garbage_key_answers_not_installed(self):
        r = self.pull_b()
        class Liar:
            def __init__(s, mutate): s.mutate = mutate
            def request(s, req):
                out = self.tr.request(req)
                if out.get("t") == "keys":
                    s.mutate(out)
                    from sigilnet.sync import RESP_CTX
                    from sigilnet import canon
                    out["by"] = self.a.sign_pub
                    out["rsig"] = self.a.sign(RESP_CTX + canon.dumps({k: v for k, v in out.items() if k != "rsig"}))   # (a real member lying with valid signature)
                return out
        def garble(o):
            o["keys"][0]["sealed"] = V.seal_key(self.b.kex_pub, self.b.id, self.tid, self.tid, b"j" * 32)       # well-formed, wrong key
        got = fetch_keys(self.mb, self.tid, Liar(garble), self.b, peer_id=self.a.id, need=r["need_keys"], unopened=r["unopened"])
        self.assertEqual((got["installed"], got["rejected"]), (0, 1))
        self.assertIsNone(self.cb.ring(self.tid).get(self.tid))
        def wrong_id(o):
            o["keys"][0]["id"] = "f" * 32
        got = fetch_keys(self.mb, self.tid, Liar(wrong_id), self.b, peer_id=self.a.id, need=r["need_keys"], unopened=r["unopened"])
        self.assertEqual(got["installed"], 0)

    def test_answer_from_a_non_member_or_unsigned_refused(self):
        r = self.pull_b()
        eve = Identity.generate("eve")
        self.assertFalse(fetch_keys(self.mb, self.tid, self.tr, self.b, peer_id=eve.id, need=r["need_keys"], unopened=r["unopened"])["ok"])       # not signed by eve
        class NoSig:
            def request(s, req):
                out = self.tr.request(req)
                out.pop("rsig", None)
                return out
        self.assertFalse(fetch_keys(self.mb, self.tid, NoSig(), self.b, peer_id=self.a.id, need=r["need_keys"])["ok"])

    def test_stranger_and_guest_cannot_ask_for_keys(self):
        from sigilnet.sync import sign_request
        for who in (Identity.generate("stranger"), ):
            resp = self.tr.request(sign_request(who, {"t": "key", "thread": self.tid, "ids": []}, aud=self.a.id))
            self.assertEqual(resp["t"], "unknown")
        # a member asking with someone else's key id list is fine, but a wrong `pub` for a member id is refused at authentication
        resp = self.tr.request(sign_request(self.b, {"t": "key", "thread": self.tid, "ids": ["z" * 32]}, aud=self.a.id))
        self.assertEqual(resp["t"], "unknown")

    def test_plain_threads_unchanged(self):
        m, _ = self.node(self.a)
        g = make_genesis(self.a, "plain", [(self.b, "member")])
        m.ingest(g)
        tid = event_id(g)
        m.ingest(Writer(self.a, m.threads[tid]).post("not encrypted"))
        from sigilnet.sync import sign_request
        resp = Loopback(SyncServer(m, identity=self.a)).request(sign_request(self.b, {"t": "get", "thread": tid, "ids": list(m.threads[tid].stored)}, aud=self.a.id))
        self.assertIn("not encrypted", repr(resp))
        resp = Loopback(SyncServer(m, identity=self.a)).request(sign_request(self.b, {"t": "key", "thread": tid, "ids": []}, aud=self.a.id))
        self.assertEqual(resp["t"], "unknown")


if __name__ == "__main__":
    unittest.main()


class Withholding(Net):
    def test_withheld_events_are_not_explained_away_by_duplicate_envelopes(self):
        """Mutation-run finding: the same unopened envelope served again must not count twice, or a server that withholds events looks complete."""
        real_request = self.tr.request
        seen = {"n": 0}
        class Greedy:
            def request(s, req):
                out = real_request(req)
                if out.get("t") == "events" and out["events"]:
                    env = [e for e in out["events"] if "kind" not in e]
                    if env:
                        out["events"] = out["events"] + env * 3                      # the same ciphertext three times
                        out.pop("rsig", None)
                return out
        res = pull(self.mb, self.tid, Greedy(), self.b, peer_id=None)
        self.assertEqual(len(res["unopened"]), 1)
