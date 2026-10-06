"""Can a fresh (or behind) mirror always catch up? Parents are discovered one hop per round; parked events are bounded and memory-only."""
import tempfile
import unittest

from sigilnet import sync as S
from sigilnet.mirror import Mirror

from .h3 import all_events, big_world, mirror_with, vis


class LongChains(unittest.TestCase):
    def chain(self, n, authors=("carol",)):
        w = big_world()
        for k in range(n):
            w.add(w.w(authors[k % len(authors)]).post(str(k)))          # default parents = tips: a linear conversation
        return w, mirror_with(w.genesis, all_events(w))

    def sync_fresh(self, w, a, tries=3):
        d = tempfile.mkdtemp()
        results = []
        for _ in range(tries):
            b = Mirror(d, rate_limit=False)                              # re-opened each time, like separate CLI runs
            results.append(S.pull(b, w.t.id, S.Loopback(S.SyncServer(a)), w.ids["sansa"]))
        return b, results

    def test_single_author_chain_of_150_syncs_to_a_fresh_mirror(self):
        # BUG: the client learns one parent per round and parks every child (per-author pool 64, memory only), so a chain > ~64 never resolves,
        # and pull still reports ok=True.
        w, a = self.chain(150)
        b, res = self.sync_fresh(w, a)
        self.assertEqual(vis(a, w.t.id), vis(b, w.t.id), [dict(r) for r in res])

    def test_two_author_chain_of_300(self):
        # BUG: same cause; the total parked pool (1000) is not the limit, the per-author pool of 64 is
        w, a = self.chain(300, ("carol", "sansa"))
        b, res = self.sync_fresh(w, a)
        self.assertEqual(vis(a, w.t.id), vis(b, w.t.id))

    def test_incomplete_pull_must_not_claim_success(self):
        # BUG: even when the walk gives up, ok is True and why is empty
        w, a = self.chain(120)
        b, res = self.sync_fresh(w, a, tries=1)
        complete = vis(a, w.t.id) == vis(b, w.t.id)
        self.assertTrue(complete or not res[0]["ok"], "pull reported ok=True with a thread that is still incomplete")

    def test_returning_member_that_is_100_events_behind(self):
        # BUG: same cause as the fresh-mirror chain case
        w = big_world()
        for k in range(10):
            w.add(w.w("carol").post(str(k)))
        old = mirror_with(w.genesis, all_events(w))
        for k in range(100):
            w.add(w.w("carol").post("n" + str(k)))
        a = mirror_with(w.genesis, all_events(w))
        for _ in range(3):
            S.pull(old, w.t.id, S.Loopback(S.SyncServer(a)), w.ids["sansa"])
        self.assertEqual(vis(a, w.t.id), vis(old, w.t.id))

    def test_chain_within_the_pool_still_works(self):
        w, a = self.chain(50)
        b, res = self.sync_fresh(w, a, tries=1)
        self.assertEqual(vis(a, w.t.id), vis(b, w.t.id))

    def test_wide_history_of_500_syncs_and_uses_few_requests(self):
        w = big_world()
        for k in range(500):
            w.add(w.w(("carol", "sansa", "arya")[k % 3]).post(str(k), parents=[w.t.id]))
        a = mirror_with(w.genesis, all_events(w))
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        from .h3 import Fn
        tr = Fn(S.Loopback(S.SyncServer(a)).request)
        r = S.pull(b, w.t.id, tr, w.ids["sansa"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(vis(a, w.t.id), vis(b, w.t.id))
        self.assertLess(len(tr.calls), 60)


class ServerRateVsWalk(unittest.TestCase):
    def test_an_honest_full_sync_of_a_deep_thread_stays_inside_the_servers_own_rate_limit(self):
        # BUG: one request per DAG level, and the server allows 240/min per requester: an honest peer is rate-limited by design
        w = big_world()
        for k in range(60):
            w.add(w.w("carol").post(str(k)))
        a = mirror_with(w.genesis, all_events(w))
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        from .h3 import Fn
        srv = S.SyncServer(a)
        tr = Fn(S.Loopback(srv).request)
        S.pull(b, w.t.id, tr, w.ids["sansa"])
        self.assertLess(len(tr.calls), 30, f"{len(tr.calls)} requests to fetch 60 events (limit {S.RATE_PER_MIN}/min)")


if __name__ == "__main__":
    unittest.main()
