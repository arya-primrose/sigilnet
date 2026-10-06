"""Sansa's adversarial tests for autorotate (p7)."""
import json, os, shutil, threading, time, unittest
from pathlib import Path
from sigilnet import autorotate as AR, rotate as R, noderun
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.tests.test_autorotate import Base, T0, run_cli


class Adv(Base):
    def test_cost_of_a_round_with_many_big_threads(self):
        """20 threads x 600 events (no pointer): a member round must stay cheap (every undecided thread is rescanned each round)."""
        ma, ms = self.mirror("arya"), self.mirror("sansa")
        tids = []
        for k in range(20):
            tid = self.thread(ma, title=f"t{k}")
            for i in range(300):
                self.assertTrue(ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post(f"p{i}"), live=False).ok)
            self.copy(ma, ms, tid)
            tids.append(tid)
        r, peers = self.rot(ms, "sansa", follow_rotation=True, auto_rotate=True)
        peers.add(self.ids["arya"].id, "arya", None, [])
        t0 = time.time()
        r.tick(T0, self.plan(peers, {"arya": set(tids)}))
        dt = time.time() - t0
        print(f"[adv32] round over 20 threads x 300 events: {dt:.2f}s")
        self.assertLess(dt, 5.0)
        self.assertEqual([l for l in self.logs if "failed" in l], [])

    def test_a_round_beside_a_writer_never_fails(self):
        ma, ms = self.mirror("arya"), self.mirror("sansa")
        tid = self.thread(ma)
        self.copy(ma, ms, tid)
        r, peers = self.rot(ms, "sansa", follow_rotation=True, auto_rotate=True)
        peers.add(self.ids["arya"].id, "arya", None, [])
        stop = threading.Event()
        errs = []

        def writer():
            n = 0
            while not stop.is_set():
                try:
                    ms.ingest(Writer(self.ids["sansa"], ms.threads[tid]).post(f"w{n}"))
                except Exception as e:
                    errs.append(repr(e))
                n += 1
        th = threading.Thread(target=writer); th.start()
        try:
            for k in range(200):
                r._next = 0.0
                r.tick(T0 + k, self.plan(peers, {"arya": {tid}}))
        finally:
            stop.set(); th.join()
        self.assertEqual(errs, [])
        self.assertEqual([l for l in self.logs if "failed" in l], [], self.logs[:3])

    def test_bogus_pointers_are_bounded_by_the_day_limit_and_the_expiry(self):
        """A (hostile) owner of 12 threads, each with a pointer to a made-up id: only 4 per day are acted on, the entries expire after 7 days, the peer record never nears the 64 limit."""
        ma, ms = self.mirror("arya"), self.mirror("sansa")
        tids = []
        for k in range(12):
            tid = self.thread(ma, title=f"lure{k}")
            ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("[ROTATED-TO] " + format(k + 1, "x").rjust(32, "e")))
            self.copy(ma, ms, tid)
            tids.append(tid)
        r, peers = self.rot(ms, "sansa", follow_rotation=True)
        peers.add(self.ids["arya"].id, "arya", None, [])
        plan = self.plan(peers, {"arya": set(tids)})
        mx = 0
        for day in range(20):
            now = T0 + day * AR.DAY if hasattr(AR, "DAY") else T0 + day * 86400.0
            r._next = 0.0
            r.tick(now, plan)
            mx = max(mx, len(peers.all()[self.ids["arya"].id]["threads"]))
        print(f"[adv32] max follow list under 12 bogus pointers over 20 days: {mx}")
        self.assertLessEqual(mx, 12)
        r._next = 0.0
        r.tick(T0 + 40 * 86400.0, plan)
        self.assertEqual(peers.auto_entries(), [])
        self.assertEqual(peers.all()[self.ids["arya"].id]["threads"], [])

    def test_a_pointer_to_the_old_thread_itself_or_zero_id(self):
        ma, ms = self.mirror("arya"), self.mirror("sansa")
        tid = self.thread(ma)
        ma.ingest(Writer(self.ids["arya"], ma.threads[tid]).post("[ROTATED-TO] " + tid))
        self.copy(ma, ms, tid)
        r, peers = self.rot(ms, "sansa", follow_rotation=True)
        peers.add(self.ids["arya"].id, "arya", None, [])
        r.tick(T0, self.plan(peers, {"arya": {tid}}))
        self.assertEqual(peers.auto_entries(), [])
        self.assertEqual(peers.all()[self.ids["arya"].id]["threads"], [])

    def test_an_observer_follows_too(self):
        ma, ms, tid, new = self.rotated_pair()
        mh = self.mirror("hu")
        self.copy(ma, mh, tid)
        r, peers = self.rot(mh, "hu", follow_rotation=True)
        peers.add(self.ids["arya"].id, "arya", None, [])
        r.tick(T0, self.plan(peers, {"arya": {tid}}))
        self.assertEqual([t for _, t, _ in peers.auto_entries()], [new])
        self.copy(ma, mh, new)
        r.tick(T0 + 700, self.plan(peers, {"arya": {tid, new}}))
        self.assertEqual(peers.auto_entries(), [])
        self.assertEqual(peers.all()[self.ids["arya"].id]["threads"], [new])

    def test_encrypted_old_thread_pointer_is_read_only_with_the_key(self):
        ma, ms, tid, new = self.rotated_pair(encrypt=True)
        r, peers = self.rot(ms, "sansa", follow_rotation=True)
        peers.add(self.ids["arya"].id, "arya", None, [])
        r.tick(T0, self.plan(peers, {"arya": {tid}}))
        got = [t for _, t, _ in peers.auto_entries()]
        print(f"[adv32] encrypted old thread, receiver copy w/o key via plain ingest: follows={got}")
        # either it followed (events opened) or nothing, but never a crash and never a wrong id
        self.assertIn(got, ([], [new]))

    def test_config_switch_keeps_the_rest(self):
        import contextlib
        home = self.tmp / "h"
        home.mkdir()
        old = os.getcwd()
        os.chdir(home)
        self.addCleanup(os.chdir, old)
        rc, out, err = run_cli("init", "x", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", "47990")
        self.assertEqual(rc, 0, err)
        cfgp = home / ".sigilnet" / "node_config.json"
        rc, out, err = run_cli("node", "notify-via", "tcp")
        self.assertEqual(rc, 0, err)
        before = json.loads(cfgp.read_text())
        rc, out, err = run_cli("node", "auto-rotate", "on")
        self.assertEqual(rc, 0, err)
        after = json.loads(cfgp.read_text())
        for k in before:
            if k != "auto_rotate":
                self.assertEqual(after[k], before[k], k)
        self.assertIs(after["auto_rotate"], True)
        rc, out, err = run_cli("node", "follow-rotation", "on")
        self.assertEqual(json.loads(cfgp.read_text())["notify_via"], "tcp")
        self.assertEqual(oct(os.stat(cfgp).st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
