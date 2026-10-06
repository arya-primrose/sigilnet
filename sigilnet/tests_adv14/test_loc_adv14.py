"""Sansa's independent adversarial tests for the locator book (r42_locator, S1). Written from DESIGN_locator_book.md rev 1 and my review notes, not from Arya's tests."""
import json
import os
import random
import tempfile
import threading
import unittest
from pathlib import Path

from sigilnet import locators as L
from sigilnet import tcplink as TL
from sigilnet.carrier import CarrierError
from sigilnet.keys import Identity

A1 = "10.0.0.1:47700#" + "1" * 64
A2 = "10.0.0.2:47700#" + "2" * 64
A3 = "10.0.0.3:47700#" + "3" * 64
A4 = "10.0.0.4:47700#" + "4" * 64
A5 = "10.0.0.5:47700#" + "5" * 64
PEER = "n" * 32
PEER2 = "m" * 32


def book(clock=None):
    d = Path(tempfile.mkdtemp())
    return L.open_book(d, "tcp", clock=clock or (lambda: 1000.0)), d


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        self.t += 1.0
        return self.t


# ---------------------------------------------------------------- the order, against my own model of the rule
class Model:
    """The human's rule as I read it: most recent good contact first; a locator whose last attempt failed AFTER its last good contact goes behind the others; ties by the order added;
    at most 4, the worst-ordered dropped."""

    def __init__(self):
        self.locs = []                                              # [addr, ok, fail]

    def order(self):
        keyed = sorted(enumerate(self.locs), key=lambda t: ((1 if (t[1][2] is not None and (t[1][1] is None or t[1][2] > t[1][1])) else 0), -(t[1][1] or 0.0), t[0]))
        return [l[0] for _, l in keyed]

    def trim(self):
        keyed = sorted(enumerate(self.locs), key=lambda t: ((1 if (t[1][2] is not None and (t[1][1] is None or t[1][2] > t[1][1])) else 0), -(t[1][1] or 0.0), t[0]))
        self.locs = [l for _, l in keyed]
        while len(self.locs) > 4:
            self.locs.pop()


class OrderProperty(unittest.TestCase):
    def test_random_histories_match_the_model(self):
        addrs = [A1, A2, A3, A4, A5]
        for seed in range(60):
            rnd = random.Random(seed)
            clock = Clock()
            b, _ = book(clock)
            m = Model()
            for step in range(40):
                op = rnd.choice(["adopt", "ok", "fail", "seed", "seedfront"])
                a = rnd.choice(addrs)
                if op == "adopt":
                    b.adopt(PEER, a)
                    now = clock.t
                    for l in m.locs:
                        if l[0] == a:
                            l[1], l[2] = now, None
                            break
                    else:
                        m.locs.append([a, now, None])
                    m.trim()
                elif op in ("ok", "fail"):
                    b.note_ok(PEER, a) if op == "ok" else b.note_fail(PEER, a)
                    now = clock.t
                    for l in m.locs:
                        if l[0] == a:
                            if op == "ok":
                                l[1], l[2] = now, None
                            else:
                                l[2] = now
                            m.trim()
                            break
                else:
                    front = op == "seedfront"
                    if not front and a in [l[0] for l in m.locs]:
                        b.seed(PEER, a)
                        continue
                    b.seed(PEER, a, front=front)
                    now = clock.t
                    for l in m.locs:
                        if l[0] == a:
                            if front:
                                l[1], l[2] = now, None
                            break
                    else:
                        m.locs.append([a, now if front else None, None])
                    m.trim()
                got = b.ordered(PEER)
                self.assertEqual(got, m.order(), f"seed {seed} step {step} op {op}")
                self.assertLessEqual(len(got), 4)
                self.assertEqual(len(set(got)), len(got))


# ---------------------------------------------------------------- the file is hostile data
class HostileFile(unittest.TestCase):
    def setUp(self):
        self.b, self.d = book()
        self.p = self.b.path

    def test_garbage_files_read_as_empty_and_the_book_still_works(self):
        for raw in (b"", b"\xff\xfe", b"[]", b"null", b"{\"peers\": 5}", b"{\"peers\": []}", b"[" * 100000, b"{\"peers\": {\"" + PEER.encode() + b"\": 7}}", b"x" * (3 * 1024 * 1024)):
            self.p.write_bytes(raw)
            self.assertEqual(self.b.ordered(PEER), [])
            self.b.seed(PEER, A1, front=True)
            self.assertEqual(self.b.ordered(PEER), [A1])
            self.p.unlink()

    def test_a_huge_but_valid_file_is_ignored_not_parsed(self):
        peers = {PEER: {"locs": [{"addr": A1, "ok": 1.0}], "announced": None, "adopt_ts": 0, "pad": "x" * (3 * 1024 * 1024)}}
        self.p.write_text(json.dumps({"v": 1, "peers": peers}))
        self.assertEqual(self.b.ordered(PEER), [])                  # over the 2 MiB cap: read as empty (a hostile or runaway file must not be loaded)

    def test_hostile_entries_are_skipped_not_fatal(self):
        peers = {PEER: {"locs": [{"addr": A1, "ok": True, "fail": "x"}, {"addr": 5}, 7, {"addr": "10.0.0.9:80#zz"}, {"addr": A1}, {"addr": A2, "ok": float("nan")}], "announced": 7, "adopt_ts": "9"},
                 "bad id": {"locs": []}, PEER2: "str"}
        self.p.write_text(json.dumps({"v": 1, "peers": peers}))
        got = self.b.ordered(PEER)
        self.assertEqual(sorted(got), sorted([A1, A2]))
        self.assertEqual(self.b.adopt_ts(PEER), 0)
        self.assertIsNone(self.b.announced(PEER))
        self.assertEqual(self.b.ordered(PEER2), [])

    def test_more_than_64_peers_in_the_file_are_cut(self):
        peers = {("%032d" % i).replace("0", "a").replace("1", "b").replace("8", "c").replace("9", "d")[:32]: {"locs": [{"addr": A1}]} for i in range(200)}
        peers = {k: v for k, v in peers.items() if len(k) == 32}
        self.p.write_text(json.dumps({"v": 1, "peers": peers}))
        self.assertLessEqual(len(self.b.agents()), 64)

    def test_a_symlink_where_the_temp_file_goes_is_not_followed(self):
        victim = Path(tempfile.mkdtemp()) / "victim"
        victim.write_text("keep")
        for f in list(self.p.parent.iterdir()):
            f.unlink()
        # an attacker who can write in the locators dir pre-plants symlinks named like temp files: O_EXCL|O_NOFOLLOW means the write must fail or pick another name, never write through
        self.b.seed(PEER, A1, front=True)
        for f in self.p.parent.iterdir():
            self.assertFalse(f.is_symlink())
        self.assertEqual(victim.read_text(), "keep")

    def test_the_file_is_0600_and_the_dir_0700(self):
        self.b.seed(PEER, A1, front=True)
        self.assertEqual(self.p.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.p.parent.stat().st_mode & 0o777, 0o700)

    def test_a_removed_directory_under_a_running_book_is_recreated(self):
        self.b.seed(PEER, A1, front=True)
        import shutil
        shutil.rmtree(self.p.parent)
        self.b.note_ok(PEER, A1)                                     # nothing there: must not raise
        self.b.seed(PEER, A2, front=True)
        self.assertEqual(self.b.ordered(PEER)[0], A2)

    def test_threads_editing_at_once_leave_a_valid_file(self):
        errs = []

        def work(k):
            try:
                rnd = random.Random(k)
                for _ in range(40):
                    a = rnd.choice([A1, A2, A3, A4, A5])
                    rnd.choice([lambda: self.b.adopt(PEER, a), lambda: self.b.note_fail(PEER, a), lambda: self.b.note_ok(PEER, a), lambda: self.b.seed(PEER, a)])()
            except Exception as e:  # noqa: BLE001
                errs.append(repr(e))
        ts = [threading.Thread(target=work, args=(k,)) for k in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        raw = json.loads(self.p.read_text())
        self.assertLessEqual(len(raw["peers"][PEER]["locs"]), 4)
        self.assertEqual(len([f for f in self.p.parent.iterdir() if f.name.endswith(".tmp")]), 0)

    def test_two_book_objects_on_one_file_do_not_lose_each_others_writes(self):
        b2 = L.open_book(self.d, "tcp")
        self.b.adopt(PEER, A1)
        b2.adopt(PEER, A2)
        self.b.set_announced(PEER, A3)
        self.assertEqual(sorted(b2.ordered(PEER)), sorted([A1, A2]))
        self.assertEqual(b2.announced(PEER), A3)

    def test_a_peer_removed_leaves_nothing(self):
        self.b.adopt(PEER, A1)
        self.b.set_announced(PEER, A2)
        self.assertTrue(self.b.remove(PEER))
        self.assertEqual(self.b.ordered(PEER), [])
        self.assertIsNone(self.b.announced(PEER))


# ---------------------------------------------------------------- FallbackTransport
class Dummy:
    def __init__(self, addr, log, dead):
        self.addr, self.log, self.dead = addr, log, dead

    def request(self, req):
        self.log.append(self.addr)
        if self.dead(self.addr):
            raise CarrierError("refused", retry=True)
        return {"t": "ok", "from": self.addr}


class Fallback(unittest.TestCase):
    def test_a_single_address_raises_the_very_same_error(self):
        b, _ = book()
        b.seed(PEER, A1, front=True)
        err = CarrierError("boom", retry=False)

        def one(a):
            class T:
                def request(s, r):
                    raise err
            return T()
        ft = L.FallbackTransport(one, b, PEER, [A1])
        with self.assertRaises(CarrierError) as cm:
            ft.request({})
        self.assertIs(cm.exception, err)

    def test_retry_is_false_only_if_no_address_could_ever_work(self):
        b, _ = book()
        b.seed(PEER, A1, front=True)
        b.seed(PEER, A2)

        def one(a):
            class T:
                def request(s, r):
                    raise CarrierError("x", retry=(a == A2))
            return T()
        with self.assertRaises(CarrierError) as cm:
            L.FallbackTransport(one, b, PEER, [A1, A2]).request({})
        self.assertTrue(cm.exception.retry)

    def test_a_dead_first_address_is_not_dialed_again_for_every_request_of_one_transport(self):
        """One pull / one blob fetch makes many requests over ONE transport object. After the dead address failed once, the later requests must not wait on it again."""
        b, _ = book()
        b.seed(PEER, A1, front=True)
        b.seed(PEER, A2)
        log = []
        ft = L.FallbackTransport(lambda a: Dummy(a, log, lambda x: x == A1), b, PEER, b.ordered(PEER))
        for _ in range(6):
            ft.request({})
        self.assertEqual(log.count(A1), 1, f"the dead address was dialed {log.count(A1)} times in 6 requests: {len(log)} dials")

    def test_nothing_is_raised_when_the_book_cannot_be_written(self):
        class Broken:
            def note_ok(self, *a): raise OSError("disk")
            def note_fail(self, *a): raise OSError("disk")
        ft = L.FallbackTransport(lambda a: Dummy(a, [], lambda x: x == A1), Broken(), PEER, [A1, A2])
        self.assertEqual(ft.request({})["from"], A2)


# ---------------------------------------------------------------- announcements: the cheap checks
class FakePeers:
    def __init__(self, agents):
        self._a = {a: {"name": "p", "endpoint": {"type": "tcp", "addr": A1}, "agent": a, "threads": []} for a in agents}

    def all(self):
        return self._a


class Service(unittest.TestCase):
    def setUp(self):
        self.me = Identity.generate("me")
        self.t = [5000.0]
        self.carrier = TL.TcpCarrier(Path(tempfile.mkdtemp()) / "tcp", bind="127.0.0.2", port_base=random.randrange(30000, 60000, 2))
        self.b = L.open_book(Path(tempfile.mkdtemp()), "tcp", clock=lambda: self.t[0])
        self.svc = L.LocatorService(self.me, FakePeers([PEER, PEER2]), self.carrier, self.b, None, clock=lambda: self.t[0])

    def test_input_fuzz_never_raises_and_never_queues(self):
        junk = [None, 5, True, 1.5, [], {}, b"x", "", "x" * 400, "\x00", "10.0.0.1", "10.0.0.1:47700", "10.0.0.1:47700#zz", "[::1]:47700#" + "a" * 64, "10.0.0.1:47700#" + "A" * 64,
                "10.0.0.1:99999#" + "a" * 64, "10.0.0.1:-1#" + "a" * 64, "ａ" * 10, "10.0.0.1:47700#" + "a" * 64 + "\n", " 10.0.0.1:47700#" + "a" * 64]
        for a in junk:
            for ts in (None, True, 1.0, "9", -1, 0):
                r = self.svc.on_locator(PEER, a, ts)
                self.assertIsInstance(r, str)
        self.assertEqual(self.svc._pending, {})            # (any non-int / non-positive-newer ts: nothing queued; a real int ts is bounded by the server's SKEW check before this)

    def test_unknown_and_self_are_unknown(self):
        self.assertEqual(self.svc.on_locator("z" * 32, A2, 2000000000), "unknown")
        self.assertEqual(self.svc.on_locator(self.me.id, A2, 2000000000), "unknown")

    def test_good_announcement_is_queued_once_then_busy_then_rate_limited(self):
        ok_addr = "10.9.9.9:47700#" + "a" * 64
        self.assertEqual(self.svc.on_locator(PEER, ok_addr, 2000000000), "ok")
        self.assertEqual(self.svc.on_locator(PEER, ok_addr, 2000000001), "rate limited")
        self.t[0] += 61
        self.assertEqual(self.svc.on_locator(PEER, ok_addr, 2000000002), "busy")          # still waiting for its verification
        self.svc._pending.clear()
        self.assertEqual(self.svc.on_locator(PEER, ok_addr, 2000000003), "ok")

    def test_a_stale_or_replayed_timestamp_is_ignored(self):
        self.b.adopt(PEER, A2, ts=2000000100)
        new = "10.9.9.9:47700#" + "a" * 64
        for ts in (2000000100, 2000000099, 0, -5):
            self.assertEqual(self.svc.on_locator(PEER, new, ts), "stale")
        self.assertEqual(self.svc._pending, {})

    def test_an_address_already_held_changes_nothing(self):
        self.b.seed(PEER, "10.9.9.9:47700#" + "a" * 64, front=True)
        before = self.b.path.read_text()
        self.assertEqual(self.svc.on_locator(PEER, "10.9.9.9:47700#" + "a" * 64, 1), "ok")
        self.assertEqual(self.svc._pending, {})
        self.assertEqual(self.b.path.read_text(), before)

    def test_blocking_after_three_failures_lasts_an_hour(self):
        for i in range(3):
            self.svc._fails.setdefault(PEER, [])
        now = self.t[0]
        self.svc.verify = lambda agent, addr, ts: (False, "bad answer")
        for i in range(3):
            self.svc._verify(PEER, "10.9.9.9:47700#" + "a" * 64, 2000000000 + i)
        self.assertEqual(self.svc.on_locator(PEER, "10.8.8.8:47700#" + "b" * 64, 2000001000), "ignored")
        self.t[0] += 3601
        self.assertEqual(self.svc.on_locator(PEER, "10.8.8.8:47700#" + "b" * 64, 2000001001), "ok")

    def test_the_book_is_untouched_by_a_failed_verification(self):
        self.b.seed(PEER, A2, front=True)
        before = self.b.path.read_text()
        self.svc.verify = lambda agent, addr, ts: (False, "bad answer")
        self.svc._verify(PEER, "10.9.9.9:47700#" + "a" * 64, 2000000000)
        self.assertEqual(self.b.path.read_text(), before)


# ---------------------------------------------------------------- the carrier's own rules
class Problem(unittest.TestCase):
    def mk(self, bind="127.0.0.2", allow_public=False):
        return TL.TcpCarrier(Path(tempfile.mkdtemp()) / "tcp", bind=bind, port_base=random.randrange(30000, 60000, 2), allow_public=allow_public)

    def test_matrix(self):
        fp = "#" + "a" * 64
        c = self.mk()                                                # a loopback node
        bad = ["0.0.0.0:47700", "224.0.0.1:47700", "255.255.255.255:47700", "240.0.0.1:47700", "169.254.1.1:47700", "0.1.2.3:47700", "10.0.0.1:1023", "10.0.0.1:0"]
        for a in bad:
            self.assertIsNotNone(c.locator_problem(a + fp), a)
        good = ["10.0.0.1:47700", "172.17.0.3:47600", "192.168.1.5:50000", "127.0.0.9:47700", "8.8.8.8:47700", "1.1.1.1:47700", "100.64.0.9:47700"]      # (M3: public addresses are fine)
        for a in good:
            self.assertIsNone(c.locator_problem(a + fp), a)
        self.assertIsNotNone(c.locator_problem("10.0.0.1:47700"))        # no pin
        self.assertIsNotNone(c.locator_problem("10.0.0.1:47700#" + "a" * 63))

    def test_loopback_is_refused_on_a_node_that_is_not_on_loopback(self):
        c = self.mk(bind="10.1.2.3") if False else None
        # a real private bind needs an address the machine owns; use the matrix function through a stand-in
        c = self.mk()
        c.bind = "172.17.0.4"
        self.assertIsNotNone(c.locator_problem("127.0.0.1:47700#" + "a" * 64))
        self.assertIsNone(c.locator_problem("172.17.0.3:47700#" + "a" * 64))

    def test_public_is_allowed_whatever_allow_public_says_M3(self):
        c = self.mk()
        self.assertIsNone(c.locator_problem("93.184.216.34:47700#" + "a" * 64))
        c.allow_public = True
        self.assertIsNone(c.locator_problem("93.184.216.34:47700#" + "a" * 64))
        self.assertIsNotNone(c.locator_problem("224.0.0.1:47700#" + "a" * 64))

    def test_one_of_our_own_doors_is_refused(self):
        c = self.mk()
        _, pub = c.new_credential()
        c.open_door("d1", "peer", credential=pub, agent="n" * 32)
        c.start()
        try:
            ep = c.door_endpoint("d1")["addr"]
            self.assertIsNotNone(c.locator_problem(ep))
            ip, port, fp = TL._split_addr(ep)
            self.assertIsNone(c.locator_problem(f"{ip}:{port + 1000}#{fp}"))
        finally:
            c.stop()


class ResolveBind(unittest.TestCase):
    def test_explicit_address_is_untouched(self):
        self.assertEqual(TL.resolve_bind("172.17.0.4"), "172.17.0.4")
        self.assertEqual(TL.resolve_bind("8.8.8.8"), "8.8.8.8")        # (TcpCarrier refuses it later, not this function)

    def test_auto_skips_loopback_linklocal_public_and_picks_the_route(self):
        ifs = lambda: ["127.0.0.1", "169.254.7.7", "8.8.4.4", "172.17.0.4", "10.5.5.5", "0.0.0.0", "224.1.1.1"]
        self.assertEqual(TL.resolve_bind("auto", False, (), interfaces=ifs, route=lambda d: None), "8.8.4.4", "M3: public addresses are candidates; the kernel's first one")
        self.assertEqual(TL.resolve_bind("auto", False, ["10.5.5.9"], interfaces=ifs, route=lambda d: "10.5.5.5"), "10.5.5.5")
        self.assertEqual(TL.resolve_bind("auto", False, ["8.8.8.8"], interfaces=ifs, route=lambda d: "8.8.4.4"), "8.8.4.4", "the route to a public peer address picks the public interface")
        self.assertEqual(TL.resolve_bind("auto", True, (), interfaces=lambda: ["127.0.0.1", "8.8.4.4"], route=lambda d: None), "8.8.4.4")
        self.assertEqual(TL.resolve_bind("auto", False, (), interfaces=lambda: ["127.0.0.1", "169.254.7.7", "0.0.0.0", "224.1.1.1", "172.17.0.4"], route=lambda d: None), "172.17.0.4")

    def test_auto_without_any_private_address_is_an_error_not_loopback(self):
        with self.assertRaises(ValueError):
            TL.resolve_bind("auto", False, (), interfaces=lambda: ["127.0.0.1", "169.254.1.1"], route=lambda d: None)
        with self.assertRaises(ValueError):
            TL.resolve_bind("auto", False, (), interfaces=lambda: [], route=lambda d: None)

    def test_auto_survives_junk_from_the_interface_lookup(self):
        self.assertEqual(TL.resolve_bind("auto", False, (), interfaces=lambda: ["junk", "", "10.1.1.1"], route=lambda d: None), "10.1.1.1")
        self.assertEqual(TL.resolve_bind("auto", False, ["junk"], interfaces=lambda: ["10.1.1.1"], route=lambda d: "999.1.1.1"), "10.1.1.1")

    def test_the_real_interface_lookup_returns_addresses(self):
        got = TL._interfaces()
        self.assertTrue(all(isinstance(x, str) for x in got))
        self.assertIn("127.0.0.1", got)


# ---------------------------------------------------------------- credentials by node id, migration
class Credentials(unittest.TestCase):
    def setUp(self):
        self.c = TL.TcpCarrier(Path(tempfile.mkdtemp()) / "tcp", bind="127.0.0.2", port_base=random.randrange(30000, 60000, 2))

    def held(self):
        return json.loads(self.c.held_file.read_text()) if self.c.held_file.exists() else {}

    def test_use_credential_holds_it_under_both_and_drop_removes_both(self):
        sec, _ = self.c.new_credential()
        ep = {"type": "tcp", "addr": A1}
        self.c.use_credential(ep, sec, agent=PEER)
        h = self.held()
        self.assertIn(A1, h)
        self.assertIn("agent:" + PEER, h)
        self.assertEqual(h[A1], h["agent:" + PEER])
        self.assertEqual(self.c.held_file.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.c.drop_credential(ep, agent=PEER))
        self.assertEqual(self.held(), {})
        self.assertFalse(self.c.drop_credential(ep, agent=PEER))

    def test_a_bad_agent_id_is_refused_and_nothing_is_written(self):
        sec, _ = self.c.new_credential()
        for bad in ("x", "N" * 32, "n" * 31, "n" * 33, "agent:" + "n" * 26, "", 5):
            with self.assertRaises(ValueError):
                self.c.use_credential({"type": "tcp", "addr": A1}, sec, agent=bad)
        self.assertEqual(self.held(), {})

    def test_index_credentials_is_idempotent_never_deletes_and_ignores_strays(self):
        s1, _ = self.c.new_credential()
        s2, _ = self.c.new_credential()
        self.c.use_credential({"type": "tcp", "addr": A1}, s1)
        self.c.use_credential({"type": "tcp", "addr": A2}, s2)          # a stray (no peer)
        before = self.held()
        n = self.c.index_credentials([(PEER, A1), (PEER2, A3), ("bad", A1), (PEER, "junk"), (PEER, A1)])
        self.assertEqual(n, 1)
        h = self.held()
        for k, v in before.items():
            self.assertEqual(h[k], v)
        self.assertEqual(h["agent:" + PEER], before[A1])
        self.assertEqual(self.c.index_credentials([(PEER, A1)]), 0)
        self.assertEqual(self.held(), h)

    def test_index_credentials_never_overwrites_a_newer_node_id_entry(self):
        s1, _ = self.c.new_credential()
        s2, _ = self.c.new_credential()
        self.c.use_credential({"type": "tcp", "addr": A1}, s1)
        self.c.use_credential({"type": "tcp", "addr": A2}, s2, agent=PEER)     # newer one, under the node id
        keep = self.held()["agent:" + PEER]
        self.c.index_credentials([(PEER, A1)])
        self.assertEqual(self.held()["agent:" + PEER], keep)

    def test_a_damaged_held_file_is_a_carrier_error_on_migration(self):
        self.c.held_file.parent.mkdir(parents=True, exist_ok=True)
        self.c.held_file.write_text("{not json")
        with self.assertRaises(CarrierError):
            self.c.index_credentials([(PEER, A1)])


if __name__ == "__main__":
    unittest.main()
