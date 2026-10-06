"""M0 (DESIGN_multicarrier.md, Sansa's review F1/Q4): the sync server charges by CLASS (known sender or stranger) before it remembers a nonce; a request stamped far ahead is refused;
blob requests have a per-agent nonce budget; a peer with two doors dials each with its own key. Sansa's two attacks (tests_adv17-style, her test_floor.py) are reproduced here as assertions."""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sigilnet import sync as S
from sigilnet.build import Writer
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.tests.test_tcplink import Rig, carrier


def blob_req(ident, ts, now):
    return S.sign_request(ident, {"t": "blob", "thread": "0" * 32, "cid": "sha256:" + "0" * 64}, ts=ts)


class Floor(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.now = [1_000_000.0]
        self.me = Identity.generate("srv")
        self.m = Mirror(self.tmp / "m")
        self.srv = S.SyncServer(self.m, identity=self.me, clock=lambda: self.now[0])
        self.good = Identity.generate("peer")
        self.srv.set_peers([self.good.id])                           # a known sender (a peer of the node)

    def req(self, ident, t="summary", ts=None, **kw):
        return S.sign_request(ident, {"t": t, "thread": "0" * 32, **kw}, ts=int(self.now[0]) if ts is None else ts)

    def why(self, r):
        return r.get("why") if r.get("t") == "error" else None

    def test_strangers_cannot_burn_the_budget_of_known_senders(self):
        for i in range(S.GLOBAL_RATE_PER_MIN + 5):
            self.srv.handle(self.req(Identity.generate(f"z{i}")))
        self.assertEqual(len(self.srv.total), 0, "a stranger was charged to the budget of known senders")
        self.assertIsNone(self.why(self.srv.handle(self.req(self.good))))

    def test_strangers_have_their_own_small_budget(self):
        res = [self.why(self.srv.handle(self.req(Identity.generate(f"s{i}")))) for i in range(S.STRANGER_RATE_PER_MIN + 30)]
        self.assertEqual(res.count("rate limited"), 30)
        self.assertEqual(len(self.srv.total), 0)

    def test_strangers_cannot_raise_the_floor_with_future_blob_requests(self):
        n = S.NONCES + 50
        for i in range(n):
            self.srv.handle(blob_req(Identity.generate(f"x{i}"), int(self.now[0]) + S.FUTURE_SKEW, self.now[0]))
        self.assertEqual(self.srv.floor, 0)
        self.assertEqual(len(self.srv.seen), 0)
        self.now[0] += 1
        self.assertIsNone(self.why(self.srv.handle(self.req(self.good))))
        self.assertLessEqual(len(self.srv.s_seen), S.STRANGER_NONCES)

    def test_a_stranger_nonce_is_still_a_replay(self):
        k = Identity.generate("k")
        r = self.req(k)
        self.assertNotEqual(self.why(self.srv.handle(r)), "replayed request")
        self.assertEqual(self.why(self.srv.handle(r)), "replayed request")

    def test_a_request_stamped_far_ahead_is_refused_a_little_ahead_is_not(self):
        k = self.good
        for delta, ok in ((0, True), (S.FUTURE_SKEW, True), (S.FUTURE_SKEW + 1, False), (S.SKEW, False), (-S.SKEW, True), (-S.SKEW - 1, False)):
            r = self.srv.handle(self.req(k, ts=int(self.now[0]) + delta))
            self.assertEqual(not str(self.why(r)).startswith("stale request (check clocks)"), ok, delta)

    def test_a_known_sender_cannot_turn_the_nonce_cache_over_alone_with_blob_requests(self):
        k = self.good
        res = [self.why(self.srv.handle(blob_req(k, int(self.now[0]) + S.FUTURE_SKEW, self.now[0]))) for _ in range(S.BLOB_NONCES_PER_MIN + 40)]
        self.assertEqual(res.count("rate limited"), 40)
        self.assertEqual(len(self.srv.seen[self.good.id]), S.BLOB_NONCES_PER_MIN)
        self.assertEqual(self.srv.floor, 0)
        self.now[0] += 61                                            # a minute later the same sender may go on (nothing is blocked for good)
        self.assertNotEqual(self.why(self.srv.handle(blob_req(k, int(self.now[0]), self.now[0]))), "rate limited")

    def test_blob_budget_of_one_known_sender_does_not_touch_another(self):
        other = Identity.generate("other")
        self.srv.set_peers([self.good.id, other.id])
        for _ in range(S.BLOB_NONCES_PER_MIN + 5):
            self.srv.handle(blob_req(self.good, int(self.now[0]), self.now[0]))
        self.assertNotEqual(self.why(self.srv.handle(blob_req(other, int(self.now[0]), self.now[0]))), "rate limited")
        self.assertIsNone(self.why(self.srv.handle(self.req(other))))

    def test_pull_requests_of_a_known_sender_keep_the_old_per_key_limit(self):
        res = [self.why(self.srv.handle(self.req(self.good))) for _ in range(S.RATE_PER_MIN + 5)]
        self.assertEqual(res.count("rate limited"), 5)

    def test_a_member_of_a_thread_is_known_without_being_in_peers_json(self):
        # build a thread with `member` in it: its first request is then charged to the known budget
        from sigilnet import cli
        import contextlib, io, json
        home = self.tmp / "h"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main(["--home", str(home), "id", "init", "arya"])
            me = json.loads(self._run(home, "id", "show", "--json"))["agent"]
        member = Identity.generate("mem")
        p = self.tmp / "mem.pub"
        p.write_text(json.dumps({"name": member.name, "agent": member.id, "sign": member.sign_pub, "kex": member.kex_pub}))
        tidout = self._run(home, "new", "t", "--member", f"member={p}")
        from sigilnet.home import open_mirror
        m = open_mirror(home, me, poke=False)
        srv = S.SyncServer(m, identity=Identity.generate("srv2"), clock=lambda: self.now[0])
        self.assertTrue(srv._known(member.id))
        self.assertFalse(srv._known(Identity.generate("nobody").id))
        before = len(srv.m_total)
        srv.handle(S.sign_request(member, {"t": "summary", "thread": "0" * 32}, ts=int(self.now[0])))
        self.assertEqual(len(srv.m_total), before + 1)            # a member that is not a peer: the smaller member budget, not the peers' one
        self.assertEqual(len(srv.total), 0)

    # ---- M0b (Sansa's R1): many KNOWN senders that a thread admin chose
    def _members(self, n, prefix="m"):
        ids = [Identity.generate(f"{prefix}{i}") for i in range(n)]
        have = {i.id for i in ids}
        self.srv._known = lambda a: a in have                        # (stand-in for "a member of some thread we hold": the probe itself is tested above)
        return ids

    def test_many_known_members_cannot_poison_the_floor_with_future_blob_requests(self):
        ms = self._members(16)
        for a in ms:
            for _ in range(S.BLOB_NONCES_PER_MIN):
                self.srv.handle(blob_req(a, int(self.now[0]) + S.FUTURE_SKEW, self.now[0]))
        self.now[0] += 1
        self.srv.handle(blob_req(ms[0], int(self.now[0]) + S.FUTURE_SKEW, self.now[0]))
        self.assertIsNone(self.why(self.srv.handle(self.req(self.good, ts=int(self.now[0])))), "an honest peer was locked out")
        self.assertEqual(self.srv.floors.get(self.good.id, 0), 0)

    def test_a_flooding_member_can_only_lock_ITSELF_out(self):
        """Budgets lifted so one sender CAN overflow its own table inside the 60 s a stamp may be ahead (with the real budgets it cannot: 840 requests/min against 1024 slots)."""
        for name in ("BLOB_NONCES_PER_MIN", "RATE_PER_MIN", "MEMBER_RATE_PER_MIN"):
            self.addCleanup(setattr, S, name, getattr(S, name))
            setattr(S, name, 10 ** 9)
        a, b = self._members(2, "f")
        for _ in range(S.NONCES + 200):
            self.srv.handle(blob_req(a, int(self.now[0]) + S.FUTURE_SKEW, self.now[0]))
        self.assertLessEqual(S.NONCES, 2048, "a per-sender table must stay small (it is held for every known sender)")
        self.assertLessEqual(len(self.srv.seen[a.id]), S.NONCES)
        self.assertEqual(self.srv.floors.get(a.id), int(self.now[0]), "the flooder's own floor should have risen to now")
        self.assertEqual(self.why(self.srv.handle(self.req(a, ts=int(self.now[0])))), "stale request (check clocks)")      # it locked ITSELF out
        self.assertIsNone(self.why(self.srv.handle(self.req(b, ts=int(self.now[0])))), "another member was locked out")
        self.assertIsNone(self.why(self.srv.handle(self.req(self.good, ts=int(self.now[0])))), "a peer was locked out")
        self.assertEqual(self.srv.floors.get(b.id, 0), 0)
        self.assertEqual(self.srv.floors.get(self.good.id, 0), 0)

    def test_members_chosen_by_a_thread_admin_cannot_spend_the_peers_budget(self):
        ms = self._members(16, "g")
        for a in ms:
            for _ in range(S.RATE_PER_MIN):
                self.srv.handle(self.req(a))
        self.assertLessEqual(len(self.srv.m_total), S.MEMBER_RATE_PER_MIN)
        self.assertEqual(len(self.srv.total), 0)
        self.assertIsNone(self.why(self.srv.handle(self.req(self.good))), "an operator-chosen peer was refused")
        self.assertEqual(len(self.srv.total), 1)

    def test_a_peer_keeps_the_full_global_budget_even_when_members_are_rate_limited(self):
        ms = self._members(4, "h")
        res = [self.why(self.srv.handle(self.req(ms[i % 4]))) for i in range(S.MEMBER_RATE_PER_MIN + 20)]
        self.assertIn("rate limited", res)
        peers = [Identity.generate(f"p{i}") for i in range(7)]
        self.srv.set_peers([p.id for p in peers])
        got = [self.why(self.srv.handle(self.req(p))) for p in peers for _ in range(100)]
        self.assertEqual(got.count("rate limited"), 0)

    def test_the_replay_tables_are_bounded_and_idle_ones_are_dropped(self):
        old = S.MAX_TABLES
        S.MAX_TABLES = 8
        self.addCleanup(setattr, S, "MAX_TABLES", old)
        ms = self._members(20, "t")
        for a in ms:
            self.srv.handle(blob_req(a, int(self.now[0]), self.now[0]))
        self.assertLessEqual(len(self.srv.seen), 8)
        self.now[0] += S.SKEW + 5                                    # everything is outside the window now
        late = self._members(9, "u")
        for a in late:
            self.srv.handle(blob_req(a, int(self.now[0]), self.now[0]))
        self.assertLessEqual(len(self.srv.seen), 9)

    def test_a_stranger_nonce_table_covers_the_whole_window_at_the_stranger_rate(self):
        self.assertGreaterEqual(S.STRANGER_NONCES, S.STRANGER_RATE_PER_MIN * (S.SKEW // 60))

    def test_a_request_stamped_ahead_says_so(self):
        r = self.srv.handle(self.req(self.good, ts=int(self.now[0]) + S.FUTURE_SKEW + 1))
        self.assertIn("ahead", self.why(r))
        r = self.srv.handle(self.req(Identity.generate("o"), ts=int(self.now[0]) - S.SKEW - 1))
        self.assertEqual(self.why(r), "stale request (check clocks)")

    def _run(self, home, *args):
        import contextlib, io
        from sigilnet import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["--home", str(home), *args])
        return out.getvalue()


class TwoDoorsOnePeer(Rig):
    def test_a_peer_with_two_doors_dials_each_with_its_own_key(self):
        server = self.new()
        client = carrier()
        self.carriers.append(client)
        agent = "b" * 32
        s1, p1 = client.new_credential()
        s2, p2 = client.new_credential()
        port1 = server.open_door("d1", "peer", credential=p1, agent="c" * 32)
        port2 = server.open_door("d2", "peer", credential=p2, agent="c" * 32)
        from sigilnet.tcp import TcpServer
        for port in (port1, port2):
            self.servers.append(TcpServer("127.0.0.1", port, None, lambda req: {"t": "pong", "echo": req.get("n")}).start())
        server.start()
        server.reconfigure()
        e1, e2 = server.door_endpoint("d1"), server.door_endpoint("d2")
        client.use_credential(e1, s1, agent=agent)                     # stored under the address AND under agent:<id>
        client.use_credential(e2, s2, agent=agent)                     # overwrites agent:<id> with the OTHER door's key
        self.assertEqual(client.dial(e1, timeout=5, agent=agent).request({"t": "ping", "n": 1}), {"t": "pong", "echo": 1})
        self.assertEqual(client.dial(e2, timeout=5, agent=agent).request({"t": "ping", "n": 2}), {"t": "pong", "echo": 2})

    def test_the_agent_key_is_still_used_when_the_address_has_no_entry(self):
        server = self.new()
        client = carrier()
        self.carriers.append(client)
        agent = "b" * 32
        s1, p1 = client.new_credential()
        port1 = server.open_door("d1", "peer", credential=p1, agent="c" * 32)
        from sigilnet.tcp import TcpServer
        self.servers.append(TcpServer("127.0.0.1", port1, None, lambda req: {"t": "pong", "echo": req.get("n")}).start())
        server.start()
        server.reconfigure()
        e1 = server.door_endpoint("d1")
        client.use_credential({"type": "tcp", "addr": "10.0.0.9:47700#" + "0" * 64}, s1, agent=agent)       # an OLD address of the peer
        self.assertEqual(client.dial(e1, timeout=5, agent=agent).request({"t": "ping", "n": 3}), {"t": "pong", "echo": 3})


if __name__ == "__main__":
    unittest.main()
