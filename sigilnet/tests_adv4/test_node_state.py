"""PeerBook / node.json robustness, backoff arithmetic, clocks. No network."""
import json
import random
import threading
import time
import unittest
from pathlib import Path

from sigilnet import node as N
from sigilnet import sync as S
from sigilnet.keys import Identity
from sigilnet.carrier import CarrierError as TorError

from .h4 import ONION, ONION2, Clock, Env, Reply, down_transport, ep


def good_peer(i=0):
    return Identity.generate(f"g{i}").id


class BackoffTest(unittest.TestCase):
    def test_backoff_arithmetic_is_total_for_any_failure_count(self):
        rng = random.Random(1)
        for tries in (0, 1, 2, 10, 60, 1024, 1025, 1100, 5000, 10 ** 6, -5):
            with self.subTest(tries=tries):
                v = N.backoff(tries, rng)
                self.assertGreater(v, 0)
                self.assertLessEqual(v, N.BACKOFF_MAX * (1 + N.JITTER))

    def test_a_peer_that_is_down_for_three_weeks_does_not_crash_the_node(self):
        """Natural sequence: every attempt fails, the clock moves to the next allowed attempt. After ~1025 failures 15*2**(n-1) no longer fits a float."""
        env = Env(transport=down_transport(TorError("tor could not reach: host unreachable", retry=True)))
        for i in range(2300):
            try:
                env.node.tick()
            except Exception as e:                                   # noqa: BLE001
                self.fail(f"tick raised {type(e).__name__}: {e} after {i} failed rounds ({i * 900 / 86400:.1f} days of outage)")
            env.clock.t += 1100

    def test_a_restart_with_a_huge_failure_count_in_the_state_file_does_not_crash(self):
        env = Env(transport=down_transport(ConnectionError("x")))
        env.node.tick()
        st = env.state()
        for k in st["jobs"]:
            st["jobs"][k]["tries"] = 5000
        for k in st["down"]:
            st["down"][k]["tries"] = 5000
        (env.home / "node.json").write_text(json.dumps(st))
        nd = env.build()
        env.clock.t += 2000
        try:
            nd.tick()
        except Exception as e:                                       # noqa: BLE001
            self.fail(f"{type(e).__name__}: {e}")

    def test_jitter_never_pushes_a_wait_past_the_documented_maximum(self):
        class Top:
            def random(self):
                return 0.999999
        self.assertLessEqual(N.backoff(50, Top()), N.BACKOFF_MAX, "the README/docstring say a peer is retried at least every BACKOFF_MAX (15 min); jitter adds up to +20% on top")


class ClockTest(unittest.TestCase):
    def requests(self, env):
        return len(env.default.calls) + sum(len(t.calls) for t in env.transports.values())

    def test_a_clock_that_steps_backwards_does_not_freeze_the_schedule(self):
        ok = Reply(lambda req: {"t": "unknown"})
        env = Env(transport=ok)
        env.node.tick()
        n0 = self.requests(env)
        env.clock.t -= 86400                                         # NTP / a wrong RTC corrected: one day back
        env.clock.t += 3600                                          # an hour later
        env.node.tick()
        self.assertGreater(self.requests(env), n0, "after the clock stepped back a day, no job ran for an hour (next = old_now + interval is now a day in the future)")

    def test_a_clock_that_steps_backwards_does_not_freeze_an_unreachable_peers_backoff(self):
        env = Env(transport=down_transport(ConnectionError("x")))
        for _ in range(3):
            env.node.tick()
            env.clock.t += 1100
        n0 = len(env.default.calls)
        env.clock.t -= 7 * 86400
        env.clock.t += 2000
        env.node.tick()
        self.assertGreater(len(env.default.calls), n0, "the unreachable backoff (`until`) is an absolute time: a backwards step freezes the peer for days")

    def test_the_clock_running_ahead_does_not_break_anything(self):
        env = Env(transport=Reply(lambda req: {"t": "unknown"}))
        env.node.tick()
        env.clock.t += 10 ** 9
        env.node.tick()
        self.assertTrue(all(isinstance(r["in"], (int, type(None))) for r in env.node.status()))


class NodeStateFileTest(unittest.TestCase):
    def node_with_state(self, raw):
        env = Env(transport=Reply(lambda req: {"t": "unknown"}))
        (env.home / "node.json").write_bytes(raw if isinstance(raw, bytes) else json.dumps(raw).encode())
        return env

    def test_adversarial_state_files_never_stop_the_node_from_starting(self):
        peer = good_peer()
        bad = [b"", b"{", b"\x00" * 50, b"[]", b"null", b"\xff\xfe", b'{"jobs": 5}', b'{"jobs": []}', b'{"jobs": null, "down": null}', b'{"down": []}',
               json.dumps({"jobs": {f"{peer}/{'a'*32}/pull": 5}}).encode(),
               json.dumps({"jobs": {f"{peer}/{'a'*32}/pull": {"tries": "many"}}}).encode(),
               json.dumps({"jobs": {f"{peer}/{'a'*32}/pull": {"tries": None}}}).encode(),
               json.dumps({"jobs": {f"{peer}/{'a'*32}/pull": {"tries": [1]}}}).encode(),
               b'{"jobs": {"a/b/c": {"tries": NaN}}}', b'{"jobs": {"a/b/c": {"tries": Infinity}}}', b'{"jobs": {"a/b/c": {"tries": 1e999}}}',
               b'{"jobs": {"a/b/c": {"tries": -Infinity}}}', b'{"down": {"x": {"tries": NaN}}}', b'{"down": {"x": {"tries": "7"}}}', b'{"down": {"x": {"tries": {}}}}',
               b'{"down": {"x": 7}}', b'{"jobs": {"a/b/c": {"err": {"deep": [1]}, "ok": "yesterday", "since": "x", "blocked": "no"}}}']
        for raw in bad:
            with self.subTest(raw=raw[:60]):
                env = self.node_with_state(raw)
                try:
                    nd = env.build()
                    nd.tick()
                except Exception as e:                               # noqa: BLE001
                    self.fail(f"{type(e).__name__}: {e}")

    def test_truncated_state_file_after_a_crash_loses_history_not_the_node(self):
        env = Env(transport=down_transport(ConnectionError("x")))
        env.node.tick()
        raw = (env.home / "node.json").read_bytes()
        for cut in (1, len(raw) // 2, len(raw) - 1):
            (env.home / "node.json").write_bytes(raw[:cut])
            nd = env.build()
            nd.tick()                                                # must not raise
        json.loads((env.home / "node.json").read_text())             # and the state was rewritten whole

    def test_stale_tmp_file_and_symlinked_tmp_do_not_hurt(self):
        env = Env(transport=Reply(lambda req: {"t": "unknown"}))
        victim = env.home / "victim.txt"
        victim.write_text("precious")
        (env.home / "node.json.tmp").symlink_to(victim)
        env.node.tick()
        self.assertEqual(victim.read_text(), "precious", "the state writer followed a pre-planted symlink at node.json.tmp")

    def test_state_file_is_private(self):
        env = Env(transport=Reply(lambda req: {"t": "unknown"}))
        env.node.tick()
        self.assertEqual((env.home / "node.json").stat().st_mode & 0o777, 0o600)


class PeerBookTest(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.book = self.env.book
        self.path = self.env.home / "peers.json"

    def write(self, peers):
        self.path.write_text(json.dumps({"peers": peers}) if not isinstance(peers, (bytes, str)) else peers)

    def test_one_bad_record_does_not_hide_the_good_ones_or_crash_the_reader(self):
        good = good_peer(1)
        rec = lambda **kw: {"name": "x", "endpoint": ep(ONION), "threads": [], **kw}
        bads = [rec(endpoint=ep(ONION, "abc")), rec(endpoint="str"), rec(endpoint=[1]), rec(endpoint={}), rec(threads=None), rec(threads=5), rec(threads=[[1]], endpoint=ep(ONION, 1)),
                rec(name=["a"]), rec(endpoint=5), rec(endpoint=[ONION]), rec(threads=[{"a": 1}] * 3), "str", 5, None, [], rec(endpoint=ep(ONION, 10 ** 30)),
                rec(endpoint={"type": "xyz", "addr": "future"}), rec(endpoint={"type": "onion", "addr": ONION}), rec(endpoint={**ep(ONION), "extra": 1})]
        for i, b in enumerate(bads):
            with self.subTest(i=i, bad=str(b)[:50]):
                self.write({good_peer(9): b, good: rec(endpoint=ep(ONION2))})
                try:
                    got = self.book.all()
                except Exception as e:                               # noqa: BLE001
                    self.fail(f"PeerBook.all() raised {type(e).__name__}: {e} (the whole node loop dies on every tick until the file is hand-fixed)")
                self.assertIn(good, got)

    def test_nan_and_infinity_ports(self):
        good = good_peer(1)
        for port in ("NaN", "Infinity", "-Infinity", "1e999"):
            with self.subTest(port=port):
                self.write('{"peers": {"%s": {"endpoint": {"type": "onion", "addr": "%s:%s"}}}}' % (good, ONION, port))
                try:
                    self.book.all()
                except Exception as e:                               # noqa: BLE001
                    self.fail(f"{type(e).__name__}: {e}")

    def test_ports_out_of_range_are_not_handed_to_the_dialer(self):
        good = good_peer(1)
        for port in (0, -1, 65536, 10 ** 12):
            self.write({good: {"endpoint": ep(ONION, port), "threads": []}})
            with self.subTest(port=port):
                got = self.book.all().get(good)
                self.assertTrue(all(0 < int(e["addr"].rsplit(":", 1)[1]) < 65536 for e in (got or {}).get("endpoints", [])), "an out-of-range port is never handed out (M1a: the peer stays, its endpoint is left out)")
                self.assertEqual((got or {}).get("endpoints", []), [])

    def test_more_than_max_peers_in_the_file_are_not_all_served(self):
        self.write({good_peer(i): {"endpoint": ep(ONION)} for i in range(N.MAX_PEERS + 40)})
        self.assertLessEqual(len(self.book.all()), N.MAX_PEERS)

    def test_thread_ids_that_would_break_the_job_key_are_refused_or_harmless(self):
        peer = self.env.peers[0].id
        evil = "a" * 31 + "/"
        try:
            self.book.add(peer, "p0", ep(ONION), threads=[evil])
        except ValueError:
            return                                                   # refused at the door: fine
        self.env.default = Reply(lambda req: {"t": "unknown"})
        try:
            self.env.node.tick()
            self.env.node.tick()
        except Exception as e:                                       # noqa: BLE001
            self.fail(f"a thread id containing '/' in peers.json made tick() raise {type(e).__name__}: {e} (job keys are 'peer/thread/kind' split on '/')")

    def test_thread_ids_in_a_hand_edited_file_with_slashes_do_not_break_tick(self):
        peer = self.env.peers[0].id
        self.write({peer: {"endpoint": ep(ONION), "threads": ["a/b/" + "c" * 28, "x" * 32]}})
        self.env.default = Reply(lambda req: {"t": "unknown"})
        try:
            self.env.node.tick()
        except Exception as e:                                       # noqa: BLE001
            self.fail(f"{type(e).__name__}: {e}")

    def test_add_rejects_thread_ids_that_the_reader_would_silently_drop(self):
        peer = self.env.peers[0].id
        with self.assertRaises(ValueError):
            self.book.add(peer, "p0", ep(ONION), threads=["too-short"])

    def test_add_validates_inputs(self):
        for agent, endpoint in (("nope", ep(ONION)), (good_peer(), ep("x.onion")), (good_peer(), ep(ONION, 0)), (good_peer(), ep(ONION, 70000)),
                                (good_peer() + "\n", ep(ONION)), (good_peer(), {"type": "xyz", "addr": "f"}), (good_peer(), "x")):
            with self.subTest(agent=agent, endpoint=endpoint):
                with self.assertRaises(ValueError):
                    self.book.add(agent, "n", endpoint)

    def test_adding_a_peer_does_not_drop_fields_or_records_it_did_not_understand(self):
        a, b = good_peer(1), good_peer(2)
        self.write({a: {"endpoint": ep(ONION), "threads": [], "name": "a", "note": "keep me"}, b: {"endpoint": {"type": "onion", "addr": ONION2.upper() + ":1"}}})
        self.book.add(good_peer(3), "c", ep(ONION))
        raw = json.loads(self.path.read_text())["peers"]
        self.assertEqual(raw.get(a, {}).get("note"), "keep me", "a field the book does not know was destroyed by an unrelated `peer add`")
        self.assertIn(b, raw, "a record that failed validation was silently deleted by an unrelated `peer add`")

    def test_concurrent_peer_adds_lose_nothing_and_do_not_crash(self):
        ids = [good_peer(i) for i in range(40)]
        errs = []

        def add(chunk):
            for aid in chunk:
                try:
                    self.book.add(aid, "x", ep(ONION))
                except Exception as e:                               # noqa: BLE001
                    errs.append(repr(e))
        ts = [threading.Thread(target=add, args=(ids[i::2],)) for i in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        have = self.book.all()
        self.assertEqual([i for i in ids if i not in have], [], "concurrent `peer add` (read-modify-write with no lock) lost entries")

    def test_peer_book_file_is_private(self):
        self.book.add(good_peer(), "n", ep(ONION))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_removing_a_peer_twice_and_unknown(self):
        a = good_peer()
        self.book.add(a, "n", ep(ONION))
        self.assertTrue(self.book.remove(a))
        self.assertFalse(self.book.remove(a))
        self.assertFalse(self.book.remove("../../etc"))


if __name__ == "__main__":
    unittest.main()
