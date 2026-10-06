"""Sansa's attacks on r46b_m0 (per-sender replay tables, two budget tiers)."""
import contextlib, io, json, os, shutil, tempfile, time, unittest
from collections import OrderedDict
from pathlib import Path

from sigilnet import cli, sync as S
from sigilnet.home import open_mirror
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
    return rc, out.getvalue(), err.getvalue()


def blob_req(ident, ts):
    return S.sign_request(ident, {"t": "blob", "thread": "0" * 32, "cid": "sha256:" + "0" * 64}, ts=ts)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.now = [1_000_000.0]
        self.me = Identity.generate("srv")
        self.m = Mirror(self.tmp / "m")
        self.srv = S.SyncServer(self.m, identity=self.me, clock=lambda: self.now[0])
        self.good = Identity.generate("peer")
        self.srv.set_peers([self.good.id])

    def req(self, ident, t="summary", ts=None, **kw):
        return S.sign_request(ident, {"t": t, "thread": "0" * 32, **kw}, ts=int(self.now[0]) if ts is None else ts)

    def why(self, r):
        return r.get("why") if r.get("t") == "error" else None


class RealMembers(Base):
    """15 members chosen by a thread admin (real thread, real mirror): they are KNOWN but not peers."""

    def setUp(self):
        super().setUp()
        home = self.tmp / "h"
        self.assertEqual(run_cli("--home", str(home), "id", "init", "arya")[0], 0)
        self.ids, args = [], []
        for i in range(15):
            ident = Identity.generate("mem" + str(i))
            self.ids.append(ident)
            p = self.tmp / f"m{i}.json"
            p.write_text(json.dumps({"name": ident.name, "agent": ident.id, "sign": ident.sign_pub, "kex": ident.kex_pub}))
            args += ["--member", f"member={p}"]
        rc, out, err = run_cli("--home", str(home), "new", "t", *args)
        me = json.loads(run_cli("--home", str(home), "id", "show", "--json")[1])["agent"]
        self.msrv = S.SyncServer(open_mirror(home, me, poke=False), identity=self.me, clock=lambda: self.now[0])
        self.msrv.set_peers([self.good.id])
        self.assertTrue(all(self.msrv._known(i.id) for i in self.ids))

    def test_member_flood_of_future_blob_requests_does_not_lock_out_a_peer_or_other_members(self):
        for a in self.ids[:14]:
            for _ in range(S.BLOB_NONCES_PER_MIN):
                self.msrv.handle(blob_req(a, int(self.now[0]) + S.FUTURE_SKEW))
        self.now[0] += 1
        self.msrv.handle(blob_req(self.ids[0], int(self.now[0]) + S.FUTURE_SKEW))
        r = self.msrv.handle(self.req(self.good, ts=int(self.now[0])))
        self.assertIsNone(self.why(r), r)
        r = self.msrv.handle(self.req(self.ids[14], ts=int(self.now[0])))
        self.assertNotIn(self.why(r), ("stale request (check clocks)", "rate limited"), r)

    def test_member_pull_flood_cannot_spend_the_peers_budget(self):
        for a in self.ids:
            for _ in range(S.RATE_PER_MIN):
                self.msrv.handle(self.req(a))
        self.assertLessEqual(len(self.msrv.m_total), S.MEMBER_RATE_PER_MIN)
        self.assertEqual(len(self.msrv.total), 0)
        self.assertIsNone(self.why(self.msrv.handle(self.req(self.good))))

    def test_members_only_tier_is_small_for_honest_outbound_only_members(self):
        # 15 honest members pulling at once (each a modest 60 requests): the shared member tier refuses some
        refused = 0
        for a in self.ids:
            for _ in range(60):
                if self.why(self.msrv.handle(self.req(a))) == "rate limited":
                    refused += 1
        print("M-tier: refused", refused, "of", 15 * 60, "requests from 15 honest members in one minute")


class Tables(Base):
    def test_a_known_sender_flooding_only_locks_itself_out(self):
        evil = Identity.generate("evil")
        self.srv.set_peers([self.good.id, evil.id])
        S.RATE_PER_MIN = S.GLOBAL_RATE_PER_MIN = S.BLOB_NONCES_PER_MIN = 10 ** 9
        self.addCleanup(setattr, S, "RATE_PER_MIN", 240); self.addCleanup(setattr, S, "GLOBAL_RATE_PER_MIN", 1500); self.addCleanup(setattr, S, "BLOB_NONCES_PER_MIN", 600)
        for _ in range(S.NONCES + 20):
            self.srv.handle(blob_req(evil, int(self.now[0]) + S.FUTURE_SKEW))
        self.now[0] += 1
        self.srv.handle(blob_req(evil, int(self.now[0]) + S.FUTURE_SKEW))
        self.assertEqual(self.why(self.srv.handle(self.req(evil, ts=int(self.now[0])))), "stale request (check clocks)")
        self.assertIsNone(self.why(self.srv.handle(self.req(self.good, ts=int(self.now[0])))))

    def test_replay_still_refused_per_sender_and_across_senders_is_independent(self):
        a, b = Identity.generate("a"), Identity.generate("b")
        self.srv.set_peers([a.id, b.id])
        r = self.req(a)
        self.assertIsNone(self.why(self.srv.handle(r)))
        self.assertEqual(self.why(self.srv.handle(r)), "replayed request")

    def test_heavy_honest_sender_and_a_clock_behind_under_load(self):
        # a peer at the blob budget (600/min): its own table turns over in ~100 s, so its floor trails the clock by that much
        a = Identity.generate("heavy")
        self.srv.set_peers([a.id])
        for i in range(S.NONCES + 5):
            self.srv.handle(blob_req(a, int(self.now[0])))
            self.now[0] += 0.1
        lag = self.now[0] - self.srv.floors[a.id]
        print("T3 floor trails the clock by", round(lag, 1), "s at 10 req/s")
        r = self.srv.handle(self.req(a, ts=int(self.now[0]) - 150))
        print("T3 a request stamped 150 s ago (a clock 150 s behind):", self.why(r))

    def test_drop_idle_cost_at_the_table_cap(self):
        now = int(self.now[0])
        for i in range(S.MAX_TABLES):
            self.srv.seen[f"a{i:030d}"] = OrderedDict((f"{j:016x}", now) for j in range(S.NONCES))
        t0 = time.time()
        self.srv._remember(("z" * 32, "0" * 16), now, self.now[0])
        dt = time.time() - t0
        print("T4 one new sender at the table cap with every table busy: %.2f s under SyncServer.mu" % dt)
        self.assertLess(dt, 0.5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
