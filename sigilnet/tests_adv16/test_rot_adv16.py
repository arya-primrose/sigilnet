"""Sansa's independent checks of r44_rotate."""
import json
import multiprocessing
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import rotate as R
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.home import open_mirror
from sigilnet.keys import Identity
from sigilnet.node import PeerBook


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ids = {n: Identity.generate(n) for n in ("arya", "sansa", "hu", "dave")}
        self.m = open_mirror(self.tmp / "arya", self.ids["arya"].id, poke=False)

    def thread(self, members=(("sansa", "member"), ("hu", "observer")), encrypt=True, **kw):
        g = make_genesis(self.ids["arya"], "coordination", [(self.ids[n], r) for n, r in members], **kw)
        self.assertTrue(self.m.ingest(g).ok)
        tid = event_id(g)
        if encrypt:
            self.m.enable_encryption(tid, self.ids["arya"])
        return tid


class Edge(Base):
    def test_at_the_wall_the_rotation_half_fails_and_says_so(self):
        """What happens if the owner waits until the thread is full: the pointer cannot be posted. Must be a clean RotateError with partial, never a crash or silent success."""
        with mock.patch("sigilnet.thread.MAX_STORED", 12):
            tid = self.thread(encrypt=False)
            t = self.m.threads[tid]
            n = 0
            while len(t.stored) < 12:
                r = self.m.ingest(Writer(self.ids["arya"], t).post(f"p{n}"), live=False)
                self.assertTrue(r.ok, r.reason)
                n += 1
            with self.assertRaises(R.RotateError) as c:
                R.rotate_thread(self.m, self.ids["arya"], tid)
        self.assertIsNotNone(c.exception.partial)
        self.assertIn("EXISTS", str(c.exception))
        # the owner can still rotate "by re-run": makes a second thread (documented), and the old thread has no pointer
        self.assertIsNone(R.already_rotated(self.m.threads[tid], self.ids["arya"].id))

    def test_member_pointer_does_not_block_but_owner_typed_one_does(self):
        tid = self.thread(encrypt=False)
        t = self.m.threads[tid]
        self.assertTrue(self.m.ingest(Writer(self.ids["sansa"], t).post("[ROTATED-TO] " + "0" * 32 + " fake")).ok)
        self.assertIsNone(R.already_rotated(t, self.ids["arya"].id))
        res = R.rotate_thread(self.m, self.ids["arya"], tid)
        self.assertTrue(res["new"])
        # a rotation of the NEW thread is independent of the old one
        res2 = R.rotate_thread(self.m, self.ids["arya"], res["new"])
        self.assertEqual(res2["title"], "coordination (3)")
        self.assertNotEqual(res2["new"], res["new"])

    def test_new_thread_is_encrypted_on_disk_and_has_its_own_key(self):
        tid = self.thread()
        res = R.rotate_thread(self.m, self.ids["arya"], tid)
        old_ring = self.m.codec.ring(tid)
        new_ring = self.m.codec.ring(res["new"])
        self.assertTrue(new_ring.exists())
        self.assertNotEqual(old_ring, new_ring)
        blob = b""
        for root, _, files in os.walk(self.tmp / "arya"):
            for f in files:
                if res["new"][:32] in os.path.join(root, f) or tid in os.path.join(root, f):
                    blob += (Path(root) / f).read_bytes()
        self.assertNotIn(b"ROTATED-FROM", blob)
        self.assertNotIn(b"ROTATED-TO", blob)

    def test_guests_and_removed_members_stay_out_observer_stays_observer(self):
        tid = self.thread(members=(("sansa", "member"), ("hu", "observer"), ("dave", "member")), encrypt=False)
        t = self.m.threads[tid]
        self.assertTrue(self.m.ingest(Writer(self.ids["arya"], t).admin("member_remove", {"agent": self.ids["dave"].id})).ok)
        res = R.rotate_thread(self.m, self.ids["arya"], tid)
        st = self.m.threads[res["new"]].state()
        self.assertEqual({a: r["role"] for a, r in st["members"].items()},
                         {self.ids["arya"].id: "owner", self.ids["sansa"].id: "member", self.ids["hu"].id: "observer"})
        self.assertNotIn(self.ids["dave"].id, [a for _, a in res["invite"]])

    def test_the_old_thread_stays_intact(self):
        tid = self.thread()
        t = self.m.threads[tid]
        before = dict(t.stored)
        R.rotate_thread(self.m, self.ids["arya"], tid)
        for i, e in before.items():
            self.assertEqual(self.m.threads[tid].stored[i], e)
        self.assertEqual(len(self.m.threads[tid].stored), len(before) + 1)      # exactly the pointer


def _inviter(path, agent, tids, q):
    try:
        for t in tids:
            PeerBook(path).invite(agent, [t])
        q.put(None)
    except Exception as e:      # pragma: no cover
        q.put(repr(e))


def _adder(path, k, q):
    try:
        for i in range(10):
            PeerBook(path).add(Identity.generate("p").id, "p", None, [])
        q.put(None)
    except Exception as e:
        q.put(repr(e))


class Invite(unittest.TestCase):
    def test_concurrent_invites_and_adds_lose_nothing(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "peers.json"
        ids = {n: Identity.generate(n) for n in ("a", "b")}
        PeerBook(path).add(ids["a"].id, "a", None, ["1" * 32])
        q = multiprocessing.Queue()
        want = [f"{i:032x}" for i in range(2, 22)]
        ps = [multiprocessing.Process(target=_inviter, args=(path, ids["a"].id, want[k::4], q)) for k in range(4)]
        ps += [multiprocessing.Process(target=_adder, args=(path, k, q)) for k in range(2)]
        for p in ps:
            p.start()
        res = [q.get(timeout=60) for _ in ps]
        for p in ps:
            p.join()
        self.assertEqual(res, [None] * len(ps), res)
        rec = PeerBook(path).all()[ids["a"].id]
        self.assertEqual(sorted(rec["threads"]), sorted(["1" * 32] + want))
        self.assertIsNone(rec["endpoint"])
        self.assertEqual(rec["name"], "a")
        raw = json.loads(path.read_text())
        self.assertEqual(len(raw["peers"]), 1 + 20)                                         # no concurrent add was lost

    def test_invite_garbage_inputs(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "peers.json"
        a = Identity.generate("a").id
        b = PeerBook(path)
        b.add(a, "a", None, [])
        for bad in (["x"], ["G" * 32], [1], ["a" * 31], ["a" * 33], [None]):
            with self.assertRaises(ValueError):
                b.invite(a, bad)
        with self.assertRaises(ValueError):
            b.invite(Identity.generate("z").id, ["a" * 32])
        self.assertTrue(b.invite(a, ["a" * 32]))
        self.assertFalse(b.invite(a, ["a" * 32]))
        self.assertEqual(b.all()[a]["threads"], ["a" * 32])
        mode = oct(os.stat(path).st_mode & 0o777)
        self.assertEqual(mode, "0o600")


if __name__ == "__main__":
    unittest.main()
