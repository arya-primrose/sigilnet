"""Sansa's independent attacks on r46_m0 (SyncServer classes KNOWN / STRANGER)."""
import contextlib, io, json, os, shutil, tempfile, unittest
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


class Collusion(Base):
    """K1: 'known' includes a member of ANY thread we hold; a thread's admin chooses its members (up to max_members, 16 by default, 256 at most)."""

    def test_many_known_agents_poison_the_floor_with_future_blob_requests(self):
        agents = [Identity.generate(f"m{i}") for i in range(16)]
        self.srv.set_peers([a.id for a in agents] + [self.good.id])          # same effect as 16 thread members (see the real-thread test below)
        for a in agents:
            for _ in range(S.BLOB_NONCES_PER_MIN):
                self.srv.handle(blob_req(a, int(self.now[0]) + S.FUTURE_SKEW))
        print("K1 floor", self.srv.floor, "clock", self.now[0], "seen", len(self.srv.seen))
        extra = Identity.generate("extra"); self.srv.set_peers([a.id for a in agents] + [self.good.id, extra.id])
        self.now[0] += 1
        self.srv.handle(blob_req(extra, int(self.now[0]) + S.FUTURE_SKEW))      # one more eviction a second later
        print("K1 floor after one more", self.srv.floor, "clock", self.now[0])
        r = self.srv.handle(self.req(self.good, ts=int(self.now[0])))
        print("K1 honest peer:", self.why(r))
        self.assertIsNone(self.why(r), "16 known agents locked the honest peer out (floor poisoned)")

    @unittest.expectedFailure   # residual accepted with M0b: 16 PEERS (book entries) can spend the shared 1500/min peer tier; members use their own tier
    def test_many_known_agents_burn_the_global_budget(self):
        agents = [Identity.generate(f"g{i}") for i in range(16)]
        self.srv.set_peers([a.id for a in agents] + [self.good.id])
        for a in agents:
            for _ in range(S.RATE_PER_MIN):
                self.srv.handle(self.req(a))
        r = self.srv.handle(self.req(self.good))
        print("K2 honest peer after 16 x 240 requests:", self.why(r), "total", len(self.srv.total))
        self.assertIsNone(self.why(r))


N = 15


class RealThread(Base):
    def test_thread_members_added_by_an_admin_are_known(self):
        home = self.tmp / "h"
        self.assertEqual(run_cli("--home", str(home), "id", "init", "arya")[0], 0)
        args = []
        ids = []
        for i in range(N):
            ident = Identity.generate("mem" + str(i))
            ids.append(ident)
            p = self.tmp / f"m{i}.json"
            p.write_text(json.dumps({"name": ident.name, "agent": ident.id, "sign": ident.sign_pub, "kex": ident.kex_pub}))
            args += ["--member", f"member={p}"]
        rc, out, err = run_cli("--home", str(home), "new", "t", *args)
        self.assertEqual(rc, 0, (out, err))
        m = open_mirror(home, json.loads(run_cli("--home", str(home), "id", "show", "--json")[1])["agent"], poke=False)
        srv = S.SyncServer(m, identity=self.me, clock=lambda: self.now[0])
        known = sum(srv._known(i.id) for i in ids)
        print("R1 members known:", known, "of", len(ids))
        self.assertEqual(known, N)
        for a in ids:
            for _ in range(S.BLOB_NONCES_PER_MIN):
                srv.handle(blob_req(a, int(self.now[0]) + S.FUTURE_SKEW))
        self.now[0] += 1
        r = srv.handle(S.sign_request(self.good, {"t": "summary", "thread": "0" * 32}, ts=int(self.now[0])))
        print("R1 floor", srv.floor, "honest (a non-member peer, now a stranger here) ->", self.why(r))
        srv.set_peers([self.good.id])
        self.now[0] += 1
        r = srv.handle(S.sign_request(self.good, {"t": "summary", "thread": "0" * 32}, ts=int(self.now[0])))
        print("R1 honest known peer:", self.why(r))


class Strangers(Base):
    def test_a_stranger_request_can_be_replayed_after_its_nonce_left_the_fifo(self):
        k = Identity.generate("k")
        r = self.req(k)
        self.srv.handle(r)
        for i in range(S.STRANGER_NONCES + 5):
            self.srv.handle(self.req(Identity.generate(f"f{i}")))
            self.now[0] += 0.0
        again = self.srv.handle(r)
        print("S1 replay after fifo eviction:", again.get("t"), self.why(again))

    def test_stranger_budget_starves_a_member_added_since_the_refresh(self):
        for i in range(S.STRANGER_RATE_PER_MIN):
            self.srv.handle(self.req(Identity.generate(f"s{i}")))
        newcomer = Identity.generate("newcomer")
        r = self.srv.handle(self.req(newcomer))
        print("S2 newcomer during flood:", self.why(r))

    def test_stranger_reachable_types_answer_unknown(self):
        k = Identity.generate("k2")
        for t in ("summary", "list", "get", "key", "notify", "ping", "locator", "push", "blob"):
            r = self.srv.handle(self.req(k, t=t, ids=["0" * 32], page=0, leaves=[], addr="10.0.0.1:1"))
            self.assertIn(r.get("t"), ("unknown", "error"), (t, r))
            if r.get("t") == "error":
                print("S3", t, r.get("why"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
