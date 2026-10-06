import json
import os
import tempfile
import unittest
from pathlib import Path

from sigilnet import envelope as V
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.sync import Loopback, SyncServer, fetch_keys, pull, sign_request, response_signed_by


def node():
    root = tempfile.mkdtemp()
    codec = EnvCodec(root + "/keys")
    return root, codec, Mirror(root + "/m", codec=codec, rate_limit=False)


def evfile(root, tid):
    return Path(root) / "m" / "threads" / tid / "events.jsonl"


class World(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c, self.d = (Identity.generate(n) for n in "abcd")
        self.ra, self.ca, self.ma = node()
        self.g = make_genesis(self.a, "title", [(self.b, "member"), (self.c, "member"), (self.d, "member")])
        self.ma.ingest(self.g)
        self.tid = event_id(self.g)

    def w(self, who, m=None):
        return Writer(who, (m or self.ma).threads[self.tid])

    def srv(self):
        return Loopback(SyncServer(self.ma, identity=self.a))


class Bugs(World):
    def test_crash_between_marker_and_rewrite_loses_no_events(self):
        """enable_encryption crash after key+marker, before rewrite: a fresh process must not lose the plaintext posts (and re-running enable must not make it permanent)."""
        self.ma.ingest(self.w(self.a).post("p1"))
        self.ma.ingest(self.w(self.a).post("p2"))
        self.ca.ring(self.tid).create(self.tid)
        self.ca.mark(self.tid, migrating=True)                   # crash here (the protocol: keys, marker "migrating", rewrite, marker final)
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        texts = lambda m: sorted(e["body"]["text"] for e in m.threads[self.tid].events.values() if e["kind"] == "post")
        try:
            m2.enable_encryption(self.tid)
        except ValueError:
            pass
        m3 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(texts(m3), ["p1", "p2"])

    def test_marker_deleted_never_downgrades_to_plaintext(self):
        self.ma.enable_encryption(self.tid)
        self.ma.ingest(self.w(self.a).post("secret one"))
        os.unlink(self.ca._marker(self.tid))
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        if self.tid in m2.threads:
            m2.ingest(Writer(self.a, m2.threads[self.tid]).post("secret two"))
        self.assertNotIn(b"secret two", evfile(self.ra, self.tid).read_bytes())
        # and never served as plaintext
        resp = Loopback(SyncServer(m2, identity=self.a)).request(
            sign_request(self.b, {"t": "get", "thread": self.tid, "ids": list(m2.threads[self.tid].stored) if self.tid in m2.threads else []}, aud=self.a.id))
        self.assertNotIn("secret", repr(resp))

    def test_forged_sample_cannot_poison_epoch_key(self):
        """A member serving a forged envelope + a matching garbage key must not get that key VERIFIED (a verified key is never replaced: permanent DoS)."""
        self.ma.enable_encryption(self.tid)
        real = self.ca.ring(self.tid).get(self.tid)[0]
        rb, cb, mb = node()
        mb.ingest(self.g)
        junk = os.urandom(32)
        forged = V.seal_event(junk, self.tid, self.tid, {"hello": 1})
        # responder = malicious member c, who answers `key` honestly-signed with the garbage key sealed to b
        evil = Identity.generate("c2")
        mal = Mirror(tempfile.mkdtemp() + "/m", codec=EnvCodec(tempfile.mkdtemp() + "/k"), rate_limit=False)
        mal.ingest(self.g)
        mal.enable_encryption(self.tid)
        # make 'c' the responder: give c's mirror the garbage key as verified
        rc, cc, mc = node()
        mc.ingest(self.g)
        cc.ring(self.tid).install(self.tid, junk, verified=True)
        cc.mark(self.tid)
        tr = Loopback(SyncServer(mc, identity=self.c))
        got = fetch_keys(mb, self.tid, tr, self.b, peer_id=self.c.id, need={self.tid}, unopened=[forged])
        ring = cb.ring(self.tid).get(self.tid)
        self.assertFalse(ring is not None and ring[1] and ring[0] == junk, "garbage key became VERIFIED from a self-made sample")

    def test_skipped_counter_does_not_grow_per_persist(self):
        self.ma.enable_encryption(self.tid)
        rm = self.w(self.a).admin("member_remove", {"agent": self.d.id})
        rb, cb, mb = node()
        mb.ingest(self.g)
        k0 = self.ca.ring(self.tid).get(self.tid)[0]
        cb.ring(self.tid).install(self.tid, k0, verified=True)
        cb.mark(self.tid)
        mb.reload(self.tid)
        self.ma.ingest(rm)
        self.ca.ring(self.tid).create(event_id(rm))
        p = self.w(self.a).post("late epoch post")          # admin_ref = removal
        mb.ingest(p)                                         # parked: its admin_ref is unknown to b
        mb.ingest(rm)                                        # resolves p; b has no epoch-1 key: p cannot be written
        for i in range(5):
            mb.ingest(self.w(self.a).post(f"x{i}") if False else Writer(self.b, mb.threads[self.tid]).post(f"old{i}"))
        # one stuck event => at most 1 (or small constant), not one per persist
        self.assertLessEqual(mb.skipped.get(self.tid, 0), 1, mb.skipped)


class Props(World):
    def setUp(self):
        super().setUp()
        self.ma.enable_encryption(self.tid)
        self.ma.ingest(self.w(self.a).post("the secret text"))

    def test_key_op_refused_for_stranger_removed_and_other_thread(self):
        stranger = Identity.generate("s")
        srv = Loopback(SyncServer(self.ma, identity=self.a))
        r = srv.request(sign_request(stranger, {"t": "key", "thread": self.tid, "ids": [self.tid]}, aud=self.a.id))
        self.assertEqual(r["t"], "unknown")
        rm = self.w(self.a).admin("member_remove", {"agent": self.d.id})
        self.ma.ingest(rm)
        self.ca.ring(self.tid).create(event_id(rm))
        r = srv.request(sign_request(self.d, {"t": "key", "thread": self.tid, "ids": []}, aud=self.a.id))
        self.assertEqual(r["t"], "unknown")
        r = srv.request(sign_request(self.b, {"t": "key", "thread": self.tid, "ids": []}, aud=self.a.id))
        self.assertEqual(r["t"], "keys")
        self.assertEqual(len(r["keys"]), 2)
        # b's sealed keys do not open for d, and ids filter works
        r1 = srv.request(sign_request(self.b, {"t": "key", "thread": self.tid, "ids": [self.tid]}, aud=self.a.id))
        self.assertEqual([k["id"] for k in r1["keys"]], [self.tid])
        with self.assertRaises(V.EnvelopeError):
            V.open_key(self.d, self.tid, self.tid, r1["keys"][0]["sealed"])
        # wrong pub (b's id, other pub)
        req = sign_request(self.b, {"t": "key", "thread": self.tid, "ids": []}, aud=self.a.id)
        self.assertEqual(srv.request(sign_request(self.b, {"t": "key", "thread": "00" * 32, "ids": []}, aud=self.a.id))["t"], "unknown")

    def test_removed_member_gets_no_post_removal_events(self):
        rm = self.w(self.a).admin("member_remove", {"agent": self.d.id})
        self.ma.ingest(rm)
        self.ca.ring(self.tid).create(event_id(rm))
        self.ma.ingest(self.w(self.a).post("after removal"))
        srv = Loopback(SyncServer(self.ma, identity=self.a))
        r = srv.request(sign_request(self.d, {"t": "get", "thread": self.tid, "ids": list(self.ma.threads[self.tid].stored)}, aud=self.a.id))
        self.assertEqual(r["t"], "unknown")

    def test_wire_and_disk_have_no_plaintext(self):
        raw = evfile(self.ra, self.tid).read_bytes()
        self.assertNotIn(b"the secret text", raw)
        srv = Loopback(SyncServer(self.ma, identity=self.a))
        for t in ("list", "summary"):
            r = srv.request(sign_request(self.b, {"t": t, "thread": self.tid, "page": 0}, aud=self.a.id))
            self.assertNotIn("secret text", repr(r))
        for f in Path(self.ra, "m", "threads", self.tid).iterdir():
            self.assertNotIn(b"the secret text", f.read_bytes())

    def test_downgrade_plaintext_rejected_and_counted(self):
        rb, cb, mb = node()
        mb.ingest(self.g)
        cb.ring(self.tid).install(self.tid, self.ca.ring(self.tid).get(self.tid)[0], verified=True)
        cb.mark(self.tid)
        mb.reload(self.tid)
        real = SyncServer(self.ma, identity=self.a)
        plain = [e for i, e in self.ma.threads[self.tid].stored.items() if i != self.tid]

        class T:
            def request(s, req):
                resp = canon_rt(real.handle(req))
                if req["t"] == "get":
                    resp["events"] = plain
                return resp
        from sigilnet import canon
        canon_rt = lambda x: canon.loads(canon.dumps(x))
        r = pull(mb, self.tid, T(), self.b)
        self.assertEqual(len(mb.threads[self.tid].stored), 1)
        self.assertGreaterEqual(r["rejected"], 1)
        self.assertNotIn(b"the secret text", evfile(rb, self.tid).read_bytes())

    def test_envelope_replay_to_other_thread_fails(self):
        ev = [e for i, e in self.ma.threads[self.tid].stored.items() if i != self.tid][0]
        k = self.ca.ring(self.tid).get(self.tid)[0]
        env = V.seal_event(k, self.tid, self.tid, ev)
        self.assertEqual(V.open_envelope(k, env, self.tid), ev)
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(k, {**env, "th": "ab" * 32}, "ab" * 32)
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(k, {**env, "ep": "ab" * 32}, self.tid)
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(k, {**env, "c": env["c"][:-8]}, self.tid)

    def test_symlinked_keyring_locks(self):
        p = self.ca.ring(self.tid).path
        data = p.read_bytes()
        alt = Path(self.ra) / "alt.json"
        alt.write_bytes(data)
        p.unlink()
        p.symlink_to(alt)
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertNotIn(self.tid, m2.threads)
        self.assertIn(self.tid, m2.locked)

    def test_torn_encrypted_tail_recovered(self):
        p = evfile(self.ra, self.tid)
        with open(p, "ab") as f:
            f.write(b'{"c":"abc')
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(len(m2.threads[self.tid].stored), 2)
        self.assertTrue(p.read_bytes().endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
