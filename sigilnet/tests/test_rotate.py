"""Manual rotation (rotate.py, `sigilnet rotate`, `peer invite`, the ROTATE SOON note): DESIGN_retention.md option A, built after the human's "Build manual" (2026-10-03)."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import cli, rotate as R
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.home import open_mirror
from sigilnet.keys import Identity
from sigilnet.node import PeerBook
from sigilnet.thread import MAX_STORED, default_guest_policy, default_rules


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write("" if isinstance(e.code, int) or e.code is None else str(e.code))
    return rc, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ids = {n: Identity.generate(n) for n in ("arya", "sansa", "hu", "dave")}

    def mirror(self, who="arya", name=None):
        return open_mirror(self.tmp / (name or who), self.ids[who].id, poke=False)

    def thread(self, m, *, owner="arya", members=(("sansa", "member"), ("hu", "observer")), encrypt=True, **kw):
        g = make_genesis(self.ids[owner], "coordination", [(self.ids[n], r) for n, r in members], **kw)
        self.assertTrue(m.ingest(g).ok)
        tid = event_id(g)
        if encrypt and kw.get("visibility", "private") == "private":
            m.enable_encryption(tid, self.ids[owner])
        return tid


class Titles(unittest.TestCase):
    def test_next_title(self):
        self.assertEqual(R.next_title("arya+sansa coordination"), "arya+sansa coordination (2)")
        self.assertEqual(R.next_title("x (2)"), "x (3)")
        self.assertEqual(R.next_title("x (9)"), "x (10)")
        self.assertEqual(R.next_title("x (a)"), "x (a) (2)")
        self.assertEqual(R.next_title("x (2) y"), "x (2) y (2)")
        long = R.next_title("t" * 200)
        self.assertEqual(len(long), 200)
        self.assertTrue(long.endswith(" (2)"))

    def test_the_wall_warning_starts_at_80_percent(self):
        self.assertFalse(R.near_wall(0))
        self.assertFalse(R.near_wall(int(0.8 * MAX_STORED) - 1))
        self.assertTrue(R.near_wall(int(0.8 * MAX_STORED)))
        self.assertTrue(R.near_wall(MAX_STORED))


class Rotate(Base):
    def test_the_new_thread_has_the_same_people_rules_and_encryption(self):
        m = self.mirror()
        rules = {**default_rules(), "max_members": 7}
        tid = self.thread(m, members=(("sansa", "member"), ("hu", "observer"), ("dave", "admin")), rules=rules, guest_policy={**default_guest_policy(), "pow_bits": 8})
        for i in range(3):
            self.assertTrue(m.ingest(Writer(self.ids["arya"], m.threads[tid]).post(f"p{i}")).ok)
        old = m.threads[tid]
        n_old, head_old = len(old.stored), old.head
        res = R.rotate_thread(m, self.ids["arya"], tid)
        self.assertEqual((res["old"], res["events"], res["title"], res["closed"]), (tid, n_old, "coordination (2)", False))
        nt = m.threads[res["new"]]
        st, ost = nt.state(), old.state()
        self.assertEqual({a: r["role"] for a, r in st["members"].items()}, {a: r["role"] for a, r in ost["members"].items()})
        self.assertEqual({a: (r["sign"], r["kex"], r["name"]) for a, r in st["members"].items()}, {a: (r["sign"], r["kex"], r["name"]) for a, r in ost["members"].items()})
        self.assertEqual((st["owner"], st["visibility"], st["rules"], st["guest_policy"], st["admin_threshold"]), (ost["owner"], "private", ost["rules"], ost["guest_policy"], ost["admin_threshold"]))
        self.assertTrue(m.codec.is_encrypted(res["new"]))                                    # the old one was encrypted: so is the new one
        texts = [nt.events[i]["body"].get("text") for i in nt.order if nt.events[i]["kind"] == "post"]
        self.assertEqual(texts, [f"[ROTATED-FROM] {tid} {head_old} {n_old}"])
        ptr = [old.events[i]["body"]["text"] for i in old.order if old.events[i]["kind"] == "post"][-1]
        self.assertTrue(ptr.startswith(f"[ROTATED-TO] {res['new']} "))
        self.assertIn(f"sigilnet peer invite {self.ids['arya'].id} --thread {res['new']}", ptr)               # the instruction for the other nodes travels with the pointer
        self.assertFalse(ost["closed"])
        self.assertEqual(sorted(a for _, a in res["invite"]), sorted([self.ids["sansa"].id, self.ids["hu"].id, self.ids["dave"].id]))
        again = self.mirror()                                                                # reload from disk: everything was persisted
        self.assertIn(res["new"], again.threads)
        self.assertEqual(len(again.threads[res["new"]].order), len(nt.order))

    def test_a_plaintext_thread_stays_plaintext_and_the_chain_counts_up(self):
        m = self.mirror()
        tid = self.thread(m, encrypt=False)
        r1 = R.rotate_thread(m, self.ids["arya"], tid)
        self.assertFalse(m.codec.is_encrypted(r1["new"]))
        r2 = R.rotate_thread(m, self.ids["arya"], r1["new"], title="custom")
        self.assertEqual(r2["title"], "custom")
        r3 = R.rotate_thread(m, self.ids["arya"], r2["new"])
        self.assertEqual(r3["title"], "custom (2)")

    def test_a_second_rotation_of_the_same_thread_is_refused(self):
        m = self.mirror()
        tid = self.thread(m)
        R.rotate_thread(m, self.ids["arya"], tid)
        n = len(m.threads)
        with self.assertRaisesRegex(R.RotateError, "already rotated"):
            R.rotate_thread(m, self.ids["arya"], tid)
        self.assertEqual(len(m.threads), n)                                                  # and it created nothing

    def test_close_closes_the_old_thread_after_the_pointer(self):
        m = self.mirror()
        tid = self.thread(m)
        res = R.rotate_thread(m, self.ids["arya"], tid, close=True)
        old = m.threads[tid]
        self.assertTrue(res["closed"] and old.state()["closed"])
        kinds = [old.events[i]["kind"] for i in old.order][-2:]
        self.assertEqual(kinds, ["post", "close"])                                           # the pointer was posted BEFORE the thread closed
        self.assertFalse(m.ingest(Writer(self.ids["arya"], old).post("late")).ok)
        with self.assertRaisesRegex(R.RotateError, "closed"):
            R.rotate_thread(m, self.ids["arya"], tid)

    def test_refusals(self):
        m = self.mirror()
        tid = self.thread(m, members=(("sansa", "admin"), ("hu", "observer")), k=1)
        with self.assertRaises(R.RotateError):
            R.rotate_thread(m, self.ids["arya"], "0" * 32)                                   # no such thread
        # not the owner: sansa's own mirror holds arya's thread as an admin
        ms = self.mirror("sansa")
        for ev in (m.threads[tid].events[i] for i in m.threads[tid].order):
            ms.ingest(ev)
        before = len(ms.threads)
        with self.assertRaisesRegex(R.RotateError, "only the owner"):
            R.rotate_thread(ms, self.ids["sansa"], tid)
        self.assertEqual(len(ms.threads), before)
        # a public thread
        pub = make_genesis(self.ids["arya"], "open", [(self.ids["sansa"], "member")], visibility="public")
        self.assertTrue(m.ingest(pub).ok)
        with self.assertRaisesRegex(R.RotateError, "private"):
            R.rotate_thread(m, self.ids["arya"], event_id(pub))
        # --close with a threshold above 1
        m2 = self.mirror("arya", "arya2")
        t2 = self.thread(m2, members=(("sansa", "admin"), ("dave", "admin")), k=2)
        with self.assertRaisesRegex(R.RotateError, "co-signatures"):
            R.rotate_thread(m2, self.ids["arya"], t2, close=True)
        self.assertEqual(len(m2.threads), 1)                                                 # refused BEFORE anything was created
        self.assertTrue(R.rotate_thread(m2, self.ids["arya"], t2)["new"] in m2.threads)      # without --close it works, threshold and admins copied
        new = [t for t in m2.threads.values() if t.id != t2][0]
        self.assertEqual(new.state()["admin_threshold"], 2)

    def test_successors_are_carried_over(self):
        m = self.mirror()
        tid = self.thread(m, members=(("sansa", "member"), ("dave", "admin")), k=2, successors=[self.ids["sansa"].id])     # a successor must be a plain member
        res = R.rotate_thread(m, self.ids["arya"], tid)
        self.assertEqual(m.threads[res["new"]].state()["successors"], [self.ids["sansa"].id])

    def test_a_removed_member_is_not_in_the_new_thread(self):
        m = self.mirror()
        tid = self.thread(m, members=(("sansa", "member"), ("hu", "observer"), ("dave", "member")))
        ev = Writer(self.ids["arya"], m.threads[tid]).admin("member_remove", {"agent": self.ids["dave"].id})
        m.codec.ring(tid).create(event_id(ev), self.ids["arya"])
        self.assertTrue(m.ingest(ev).ok)
        res = R.rotate_thread(m, self.ids["arya"], tid)
        self.assertNotIn(self.ids["dave"].id, m.threads[res["new"]].state()["members"])
        self.assertNotIn(self.ids["dave"].id, [a for _, a in res["invite"]])

    def test_a_failure_half_way_says_the_new_thread_exists(self):
        m = self.mirror()
        tid = self.thread(m)
        real = m.ingest
        calls = []

        def flaky(ev, *a, **k):
            calls.append(ev["kind"] if isinstance(ev, dict) else "?")
            if len(calls) == 3:                                                              # genesis, first post, then the pointer in the old thread fails
                from sigilnet.thread import Result
                return Result("rejected", "disk on fire")
            return real(ev, *a, **k)
        with mock.patch.object(m, "ingest", flaky):
            with self.assertRaises(R.RotateError) as c:
                R.rotate_thread(m, self.ids["arya"], tid)
        self.assertIn("EXISTS", str(c.exception))
        self.assertIn("disk on fire", str(c.exception))
        self.assertEqual(len(m.threads), 2)
        self.assertEqual(c.exception.partial["new"], [t for t in m.threads if t != tid][0])


class Cli(Base):
    def setUp(self):
        super().setUp()
        self.home = self.tmp / "h"
        rc, out, err = run_cli("--home", str(self.home), "id", "init", "arya")
        self.assertEqual(rc, 0, err)
        pub = run_cli("--home", str(self.home), "id", "show", "--json")[1]
        self.me = json.loads(pub)["agent"]
        (self.tmp / "sansa.pub").write_text(json.dumps({"name": "sansa", "agent": self.ids["sansa"].id, "sign": self.ids["sansa"].sign_pub, "kex": self.ids["sansa"].kex_pub}))
        rc, out, err = run_cli("--home", str(self.home), "new", "coordination", "--member", f"member={self.tmp / 'sansa.pub'}")
        self.assertEqual(rc, 0, err)
        self.tid = out.split("thread ")[1].split()[0].strip(":")

    def cli(self, *a):
        return run_cli("--home", str(self.home), *a)

    def test_rotate_prints_the_invitation_and_list_shows_both_threads(self):
        rc, out, err = self.cli("rotate", self.tid[:8])
        self.assertEqual(rc, 0, err)
        new = [l for l in out.splitlines() if l.startswith("rotated:")][0].split()[5]
        self.assertEqual(len(new), 32)
        self.assertIn(f"sigilnet peer invite {self.me} --thread {new}", out)
        self.assertIn("sansa", out)
        rc, out, err = self.cli("list")
        self.assertIn("coordination (2)", out)
        self.assertEqual(len(out.strip().splitlines()), 2)
        rc, out, err = self.cli("rotate", self.tid)
        self.assertEqual(rc, 1)
        self.assertIn("already rotated", err)

    def test_list_says_rotate_soon_only_near_the_wall(self):
        self.assertNotIn("ROTATE SOON", self.cli("list")[1])
        with mock.patch.object(R, "WARN_AT", 0.0):
            self.assertIn("ROTATE SOON", self.cli("list")[1])

    def test_peer_invite(self):
        book = PeerBook(self.home / ".sigilnet" / "peers.json") if (self.home / ".sigilnet").is_dir() else PeerBook(self.home / "peers.json")
        sid = self.ids["sansa"].id
        ep = {"type": "onion", "addr": "a" * 56 + ".onion:47200"}
        book.add(sid, "sansa", ep, ["1" * 32])
        t = "2" * 32
        rc, out, err = self.cli("peer", "invite", "sansa", "--thread", t)
        self.assertEqual(rc, 0, err)
        rec = book.all()[sid]
        self.assertEqual((rec["endpoint"], rec["name"], rec["threads"]), (ep, "sansa", sorted(["1" * 32, t])))   # the endpoint, the name and the old invitation are untouched
        rc, out, err = self.cli("peer", "invite", sid[:10], "--thread", t)                                # by id prefix; again: nothing to add
        self.assertEqual(rc, 0, err)
        self.assertIn("already invited", out)
        for args in (("peer", "invite", "nobody", "--thread", t), ("peer", "invite", "sansa"), ("peer", "invite", "sansa", "--thread", "xyz")):
            rc, out, err = self.cli(*args)
            self.assertNotEqual(rc, 0, args)
        self.assertEqual(book.all()[sid]["threads"], sorted(["1" * 32, t]))

    def test_peerbook_invite_limits_and_unknown_peer(self):
        book = PeerBook(self.tmp / "p.json")
        sid = self.ids["sansa"].id
        with self.assertRaisesRegex(ValueError, "no such peer"):
            book.invite(sid, ["1" * 32])
        book.add(sid, "sansa", None, [])
        self.assertTrue(book.invite(sid, ["%032x" % i for i in range(64)]))
        with self.assertRaisesRegex(ValueError, "too many"):
            book.invite(sid, ["f" * 32])
        self.assertFalse(book.invite(sid, []))
        self.assertEqual(len(book.all()[sid]["threads"]), 64)


if __name__ == "__main__":
    unittest.main()
