"""The locator book (DESIGN_locator_book.md rev 1, S1): the per-carrier book, the fallback dialer, the announcement checks, verification, the retry cycle."""
import json
import os
import random
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from sigilnet import locators as L
from sigilnet.carrier import CarrierError
from sigilnet.keys import Identity
from sigilnet.node import Node, PeerBook
from sigilnet.tests import fake_carrier  # noqa: F401  (registers the "fake" endpoint type)

AG = Identity.generate("peer").id
AG2 = Identity.generate("peer2").id
ME = Identity.generate("me")


def addr(n: int) -> str:
    return f"h{n}.fake:{n + 1}"


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def book(tmp=None, clock=None):
    tmp = Path(tmp or tempfile.mkdtemp())
    return L.LocatorBook(tmp / "locators" / "fake.json", "fake", clock=clock or Clock()), tmp


class BookOrder(unittest.TestCase):
    def test_seeded_addresses_keep_the_order_they_were_added(self):
        b, _ = book()
        b.seed(AG, addr(1))
        b.seed(AG, addr(2))
        b.seed(AG, addr(3))
        self.assertEqual(b.ordered(AG), [addr(1), addr(2), addr(3)])

    def test_the_last_good_one_goes_first(self):
        c = Clock()
        b, _ = book(clock=c)
        for i in (1, 2, 3):
            b.seed(AG, addr(i))
        c.t += 5
        b.note_ok(AG, addr(3))
        self.assertEqual(b.ordered(AG)[0], addr(3))
        c.t += 5
        b.note_ok(AG, addr(2))
        self.assertEqual(b.ordered(AG)[:2], [addr(2), addr(3)])

    def test_a_failure_after_the_last_good_contact_sorts_the_locator_behind_the_others(self):
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        b.seed(AG, addr(2))
        c.t += 1
        b.note_ok(AG, addr(1))
        c.t += 1
        b.note_fail(AG, addr(1))                                    # the primary failed AFTER its last good contact
        self.assertEqual(b.ordered(AG), [addr(2), addr(1)])
        c.t += 1
        b.note_ok(AG, addr(1))                                      # and works again: first again
        self.assertEqual(b.ordered(AG)[0], addr(1))

    def test_a_failing_one_with_older_good_contact_still_sorts_behind_a_never_failed_one(self):
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        b.seed(AG, addr(2))
        c.t += 1
        b.note_ok(AG, addr(2))
        c.t += 1
        b.note_ok(AG, addr(1))                                      # 1 is the newest good one ...
        c.t += 1
        b.note_fail(AG, addr(1))                                    # ... then fails: 2 (older good contact, never failed since) goes first
        self.assertEqual(b.ordered(AG), [addr(2), addr(1)])

    def test_seed_does_not_reorder_what_is_there_but_front_does(self):
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        b.seed(AG, addr(2))
        c.t += 1
        b.note_ok(AG, addr(2))
        self.assertFalse(b.seed(AG, addr(1)))                       # already known: nothing changes
        self.assertEqual(b.ordered(AG)[0], addr(2))
        c.t += 1
        self.assertTrue(b.seed(AG, addr(1), front=True))            # a human said so
        self.assertEqual(b.ordered(AG)[0], addr(1))

    def test_adopt_puts_the_verified_address_first_and_remembers_the_newest_timestamp(self):
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        c.t += 1
        b.adopt(AG, addr(2), ts=500)
        self.assertEqual(b.ordered(AG), [addr(2), addr(1)])
        self.assertEqual(b.adopt_ts(AG), 500)
        b.adopt(AG, addr(3), ts=400)                                # an older timestamp never lowers it
        self.assertEqual(b.adopt_ts(AG), 500)

    def test_at_most_four_addresses_the_worst_one_is_dropped(self):
        c = Clock()
        b, _ = book(clock=c)
        for i in range(1, 6):
            c.t += 1
            b.adopt(AG, addr(i))
        got = b.ordered(AG)
        self.assertEqual(len(got), L.MAX_LOCATORS)
        self.assertEqual(got, [addr(5), addr(4), addr(3), addr(2)])      # the oldest good one is gone
        self.assertEqual(L.MAX_LOCATORS, 4)

    def test_a_failing_address_is_the_one_dropped_when_the_list_is_full(self):
        c = Clock()
        b, _ = book(clock=c)
        for i in range(1, 5):
            c.t += 1
            b.adopt(AG, addr(i))
        c.t += 1
        b.note_fail(AG, addr(4))                                    # the newest of the four fails ...
        c.t += 1
        b.adopt(AG, addr(5))                                        # ... so it is the one a fifth pushes out
        self.assertNotIn(addr(4), b.ordered(AG))
        self.assertEqual(b.ordered(AG)[0], addr(5))

    def test_count_detail_agents_remove_drop(self):
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        b.seed(AG, addr(2))
        b.seed(AG2, addr(3))
        self.assertEqual((b.count(AG), b.count(AG2), b.count("x" * 32)), (2, 1, 0))
        self.assertEqual(sorted(b.agents()), sorted([AG, AG2]))
        c.t += 7
        b.note_ok(AG, addr(2))
        c.t += 3
        det = b.detail(AG)
        self.assertEqual(det[0], (addr(2), 3.0, False))
        self.assertEqual(det[1][1:], (None, False))
        self.assertTrue(b.drop(AG, addr(1)))
        self.assertFalse(b.drop(AG, addr(1)))
        self.assertTrue(b.remove(AG))
        self.assertFalse(b.remove(AG))
        self.assertEqual(b.ordered(AG), [])

    def test_announced_is_remembered(self):
        b, _ = book()
        self.assertIsNone(b.announced(AG))
        b.set_announced(AG, addr(1))
        self.assertEqual(b.announced(AG), addr(1))
        b.set_announced(AG, "not an address")                       # ignored
        self.assertEqual(b.announced(AG), addr(1))


class BookFile(unittest.TestCase):
    def test_modes_are_private(self):
        b, tmp = book()
        b.seed(AG, addr(1))
        self.assertEqual(stat.S_IMODE(os.stat(b.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(b.path.parent).st_mode), 0o700)

    def test_the_file_is_plain_json_and_survives_a_new_object(self):
        b, tmp = book()
        b.adopt(AG, addr(1), ts=9)
        raw = json.loads(b.path.read_text())
        self.assertEqual(raw["v"], 1)
        self.assertEqual(raw["peers"][AG]["adopt_ts"], 9)
        b2 = L.LocatorBook(b.path, "fake")
        self.assertEqual(b2.ordered(AG), [addr(1)])

    def test_the_directory_may_vanish_under_a_running_node(self):
        import shutil
        b, tmp = book()
        b.seed(AG, addr(1))
        shutil.rmtree(tmp / "locators")
        b.seed(AG, addr(2))
        self.assertEqual(b.ordered(AG), [addr(2)])
        self.assertEqual(stat.S_IMODE(os.stat(b.path.parent).st_mode), 0o700)

    def test_a_damaged_file_reads_as_empty_and_is_rewritten_by_the_next_change(self):
        b, _ = book()
        b.seed(AG, addr(1))
        b.path.write_text("{not json")
        self.assertEqual(b.ordered(AG), [])
        b.seed(AG, addr(2))
        self.assertEqual(b.ordered(AG), [addr(2)])
        json.loads(b.path.read_text())

    def test_hostile_content_is_skipped_not_fatal(self):
        b, _ = book()
        raw = {"v": 1, "peers": {
            AG: {"locs": [{"addr": addr(1), "ok": "x", "fail": True}, {"addr": "../../etc/passwd"}, {"addr": 5}, "junk", {"addr": addr(1)}, {"addr": addr(2), "ok": float("nan")}],
                 "announced": 7, "adopt_ts": "no"},
            "not-an-agent": {"locs": [{"addr": addr(3)}]},
            AG2: "nope"}}
        b.path.write_text(json.dumps(raw))
        self.assertEqual(b.ordered(AG), [addr(1), addr(2)])
        self.assertEqual(b.adopt_ts(AG), 0)
        self.assertIsNone(b.announced(AG))
        self.assertEqual(b.agents(), [AG])

    def test_a_huge_file_is_ignored(self):
        b, _ = book()
        b.path.write_text(" " * (2 * 1024 * 1024 + 10))
        self.assertEqual(b.agents(), [])

    def test_too_many_peers_are_capped(self):
        b, _ = book()
        peers = {Identity.generate(str(i)).id: {"locs": [{"addr": addr(1)}]} for i in range(L.MAX_PEERS + 10)}
        b.path.write_text(json.dumps({"v": 1, "peers": peers}))
        self.assertEqual(len(b.agents()), L.MAX_PEERS)

    def test_a_bad_address_is_refused_not_stored(self):
        b, _ = book()
        for bad in ("", "nonsense", "x.onion:1", 5, None):
            with self.assertRaises(ValueError):
                b.seed(AG, bad)
        with self.assertRaises(ValueError):
            b.seed("not an agent id", addr(1))
        self.assertEqual(b.agents(), [])

    def test_a_good_contact_is_written_at_most_once_a_minute(self):
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        writes = []
        orig = b._write
        b._write = lambda peers: (writes.append(1), orig(peers))[1]
        b.note_ok(AG, addr(1))
        self.assertEqual(len(writes), 1)
        for _ in range(20):
            c.t += 1
            b.note_ok(AG, addr(1))
        self.assertEqual(len(writes), 1)                            # nothing new to say for a minute
        c.t += L.OK_WRITE_EVERY
        b.note_ok(AG, addr(1))
        self.assertEqual(len(writes), 2)
        b.note_fail(AG, addr(1))                                    # a failure always writes, and the next success writes again at once
        self.assertEqual(len(writes), 3)
        b.note_ok(AG, addr(1))
        self.assertEqual(len(writes), 4)

    def test_the_write_throttle_never_hides_a_change_of_which_address_is_first(self):
        """ok A1, ok A2, ok A1 within the throttle window: the third must be written (A1 is first again), not skipped as 'recent' (Sansa F2)."""
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        b.seed(AG, addr(2))
        c.t += 1
        b.note_ok(AG, addr(1))
        c.t += 1
        b.note_ok(AG, addr(2))
        self.assertEqual(b.ordered(AG)[0], addr(2))
        c.t += 1
        b.note_ok(AG, addr(1))
        self.assertEqual(b.ordered(AG)[0], addr(1))
        c.t += 1
        b.note_ok(AG, addr(2))
        self.assertEqual(b.ordered(AG), [addr(2), addr(1)])

    def test_every_kind_of_write_for_a_peer_ends_the_throttle_of_its_other_addresses(self):
        for op in ("fail", "adopt", "seed_front", "drop", "ok_other"):
            c = Clock()
            b, _ = book(clock=c)
            b.seed(AG, addr(1))
            b.seed(AG, addr(2))
            c.t += 1
            b.note_ok(AG, addr(1))                                  # addr(1) is first and marked as written
            c.t += 1
            if op == "fail":
                b.note_fail(AG, addr(1))
            elif op == "adopt":
                b.adopt(AG, addr(3))
            elif op == "seed_front":
                b.seed(AG, addr(2), front=True)
            elif op == "drop":
                b.drop(AG, addr(2))
            else:
                b.note_ok(AG, addr(2))
            before = b.ordered(AG)
            c.t += 1
            b.note_ok(AG, addr(1))                                  # within 60 s of the first note: only written if the mark was cleared
            self.assertEqual(b.ordered(AG)[0], addr(1), op)
            self.assertNotEqual(before[0], addr(1), op) if op != "drop" else None

    def test_the_throttle_still_spares_repeated_notes_of_the_same_first_address(self):
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        b.note_ok(AG, addr(1))
        writes = []
        orig = b._write
        b._write = lambda peers: (writes.append(1), orig(peers))[1]
        for _ in range(30):
            c.t += 1
            b.note_ok(AG, addr(1))
        self.assertEqual(writes, [])

    def test_notes_about_an_unknown_peer_or_address_change_nothing(self):
        b, _ = book()
        b.seed(AG, addr(1))
        b.note_ok(AG2, addr(1))
        b.note_fail(AG, addr(9))
        b.note_ok(AG, addr(9))
        self.assertEqual(b.agents(), [AG])
        self.assertEqual(b.ordered(AG), [addr(1)])

    def test_concurrent_writers_leave_a_valid_file(self):
        b, _ = book(clock=lambda: 1.0)
        for i in range(1, 5):
            b.seed(AG, addr(i))
        errs = []

        def hammer(k):
            try:
                other = L.LocatorBook(b.path, "fake")                # a second object = a second process
                for j in range(30):
                    (b if k % 2 else other).note_fail(AG, addr(1 + (j + k) % 4))
                    (b if k % 2 else other).adopt(AG2, addr(1 + (j + k) % 4))
            except Exception as e:                                  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=hammer, args=(k,)) for k in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        json.loads(b.path.read_text())
        self.assertEqual(sorted(b.ordered(AG)), sorted(addr(i) for i in range(1, 5)))

    def test_no_update_is_lost_between_two_objects_writing_at_once(self):
        """Two LocatorBook objects on one file stand for two processes (the node and the CLI): the file lock must make every read-modify-write whole."""
        b, _ = book(clock=lambda: 1.0)
        other = L.LocatorBook(b.path, "fake", clock=lambda: 1.0)
        ids = [Identity.generate(f"w{i}").id for i in range(40)]
        errs = []

        def work(bk, mine):
            try:
                for a in mine:
                    bk.adopt(a, addr(1))
                    bk.set_announced(a, addr(2))
            except Exception as e:                                  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=work, args=(b, ids[0::2])), threading.Thread(target=work, args=(other, ids[1::2]))]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        self.assertEqual(sorted(b.agents()), sorted(ids))
        self.assertTrue(all(b.announced(a) == addr(2) and b.ordered(a) == [addr(1)] for a in ids))

    def test_open_book_names_the_file_by_the_carrier_type(self):
        tmp = Path(tempfile.mkdtemp())
        self.assertEqual(L.open_book(tmp, "tcp").path, tmp / "locators" / "tcp.json")
        self.assertEqual(L.open_book(tmp, "onion").path, tmp / "locators" / "onion.json")


# ------------------------------------------------------------------ the fallback dialer
class Stub:
    def __init__(self, fn):
        self.fn = fn

    def request(self, req):
        return self.fn(req)


def fallback(script: dict, addrs):
    b, _ = book()
    for a in addrs:
        b.seed(AG, a)
    calls = []

    def dial_one(a):
        def go(req):
            calls.append(a)
            r = script[a]
            if isinstance(r, BaseException):
                raise r
            return r
        return Stub(go)
    return L.FallbackTransport(dial_one, b, AG, b.ordered(AG)), b, calls


class Fallback(unittest.TestCase):
    def test_the_first_address_that_answers_is_used_and_the_rest_are_not_touched(self):
        t, b, calls = fallback({addr(1): {"t": "ok"}, addr(2): {"t": "never"}}, [addr(1), addr(2)])
        self.assertEqual(t.request({"x": 1}), {"t": "ok"})
        self.assertEqual(calls, [addr(1)])

    def test_a_failure_falls_back_at_once_and_the_working_address_moves_to_the_top(self):
        t, b, calls = fallback({addr(1): CarrierError("connect refused", retry=True), addr(2): {"t": "ok"}}, [addr(1), addr(2)])
        self.assertEqual(t.request({}), {"t": "ok"})
        self.assertEqual(calls, [addr(1), addr(2)])
        self.assertEqual(b.ordered(AG)[0], addr(2))
        self.assertTrue(b.detail(AG)[1][2])                         # the dead one is marked "failed since"

    def test_a_success_clears_the_failed_mark_of_the_address_that_answered(self):
        c = Clock()
        b, _ = book(clock=c)
        b.seed(AG, addr(1))
        b.seed(AG, addr(2))
        for a in (addr(1), addr(2)):                                # both worked once, then both failed
            c.t += 1
            b.note_ok(AG, a)
        for a in (addr(1), addr(2)):
            c.t += 1
            b.note_fail(AG, a)
        self.assertEqual([x[2] for x in b.detail(AG)], [True, True])
        dial = {addr(1): CarrierError("down", retry=True), addr(2): {"t": "ok"}}
        t = L.FallbackTransport(lambda a: Stub(lambda req: (_ for _ in ()).throw(dial[a]) if isinstance(dial[a], BaseException) else dial[a]), b, AG, b.ordered(AG))
        c.t += 1
        self.assertEqual(t.request({}), {"t": "ok"})
        det = b.detail(AG)
        self.assertEqual((det[0][0], det[0][2]), (addr(2), False))  # 2 answered: first, and no longer "failed since"

    def test_os_errors_fall_back_too(self):
        t, b, calls = fallback({addr(1): TimeoutError("slow"), addr(2): {"t": "ok"}}, [addr(1), addr(2)])
        self.assertEqual(t.request({}), {"t": "ok"})

    def test_an_answer_that_is_an_error_is_an_answer_and_does_not_fall_back(self):
        t, b, calls = fallback({addr(1): {"t": "error", "why": "rate limited"}, addr(2): {"t": "ok"}}, [addr(1), addr(2)])
        self.assertEqual(t.request({})["t"], "error")
        self.assertEqual(calls, [addr(1)])

    def test_when_every_address_fails_the_first_error_is_raised_and_the_others_counted(self):
        t, b, calls = fallback({addr(1): CarrierError("connect refused", retry=True), addr(2): CarrierError("not admitted", retry=False)}, [addr(1), addr(2)])
        with self.assertRaises(CarrierError) as cm:
            t.request({})
        self.assertIn("connect refused", str(cm.exception))
        self.assertIn("1 other address", str(cm.exception))
        self.assertTrue(cm.exception.retry)                         # one of them might recover by waiting
        self.assertEqual(calls, [addr(1), addr(2)])

    def test_when_nothing_can_be_retried_neither_can_the_whole(self):
        t, b, calls = fallback({addr(1): CarrierError("a", retry=False), addr(2): CarrierError("b", retry=False)}, [addr(1), addr(2)])
        with self.assertRaises(CarrierError) as cm:
            t.request({})
        self.assertFalse(cm.exception.retry)

    def test_one_address_behaves_exactly_like_a_plain_transport(self):
        err = CarrierError("connect refused", retry=True)
        t, b, calls = fallback({addr(1): err}, [addr(1)])
        with self.assertRaises(CarrierError) as cm:
            t.request({})
        self.assertIs(cm.exception, err)                            # the very same error, no wrapper text

    def test_what_the_first_request_learned_is_used_by_the_next_one_of_the_same_transport(self):
        """One pull or blob fetch = many requests over ONE transport: the dead first address must not be dialed again for every one of them."""
        b, _ = book()
        for a in (addr(1), addr(2), addr(3)):
            b.seed(AG, a)
        calls = []

        def dial_one(a):
            def go(req):
                calls.append(a)
                if a == addr(1):
                    raise CarrierError("connect refused", retry=True)
                return {"t": "ok"}
            return Stub(go)
        t = L.FallbackTransport(dial_one, b, AG, b.ordered(AG))
        for _ in range(6):
            t.request({})
        self.assertEqual(calls.count(addr(1)), 1)
        self.assertEqual(len(calls), 7)                             # 1 failed + 6 answered, none wasted
        self.assertEqual(t.addrs, [addr(2), addr(3), addr(1)])

    def test_an_address_that_fails_moves_to_the_back_of_the_transport_so_the_one_that_answers_is_first(self):
        b, _ = book()
        for a in (addr(1), addr(2), addr(3)):
            b.seed(AG, a)
        state = {"down": {addr(1), addr(2)}}

        def dial_one(a):
            def go(req):
                if a in state["down"]:
                    raise CarrierError("x", retry=True)
                return {"t": "ok"}
            return Stub(go)
        t = L.FallbackTransport(dial_one, b, AG, b.ordered(AG))
        t.request({})
        self.assertEqual(t.addrs, [addr(3), addr(1), addr(2)])
        state["down"] = {addr(3)}                                   # the first one died, an earlier failure came back: 3 fails, then 1 answers
        t.request({})
        self.assertEqual(t.addrs, [addr(1), addr(2), addr(3)])

    def test_when_every_address_fails_the_transport_still_has_all_of_them(self):
        b, _ = book()
        for a in (addr(1), addr(2)):
            b.seed(AG, a)
        t = L.FallbackTransport(lambda a: Stub(lambda r: (_ for _ in ()).throw(CarrierError("x", retry=True))), b, AG, b.ordered(AG))
        with self.assertRaises(CarrierError):
            t.request({})
        self.assertEqual(sorted(t.addrs), sorted([addr(1), addr(2)]))

    def test_a_book_that_cannot_be_written_never_fails_a_request(self):
        t, b, calls = fallback({addr(1): CarrierError("connect refused", retry=True), addr(2): {"t": "ok"}}, [addr(1), addr(2)])
        b.note_ok = lambda *a: 1 / 0
        b.note_fail = lambda *a: (_ for _ in ()).throw(OSError("read-only file system"))
        self.assertEqual(t.request({}), {"t": "ok"})

    def test_no_address_is_an_error_that_waiting_cannot_fix(self):
        b, _ = book()
        t = L.FallbackTransport(lambda a: None, b, AG, [])
        with self.assertRaises(CarrierError) as cm:
            t.request({})
        self.assertFalse(cm.exception.retry)


class FakeCarrierStub:
    type = "fake"

    def __init__(self):
        self.dialed = []

    def dial(self, endpoint, *, timeout, connect_timeout=None, agent=None):
        self.dialed.append((endpoint, timeout, connect_timeout, agent))
        return Stub(lambda req: {"t": "ok"})


class Dialer(unittest.TestCase):
    def setUp(self):
        self.b, self.tmp = book()
        self.c = FakeCarrierStub()
        self.d = L.PeerDialer(self.c, self.b, request_timeout=20.0, connect_timeout=45.0)

    def test_a_peer_the_book_does_not_know_gets_its_record_endpoint_once(self):
        rec = {"agent": AG, "endpoint": {"type": "fake", "addr": addr(1)}, "name": "p", "threads": []}
        self.d(rec).request({})
        self.assertEqual(self.b.ordered(AG), [addr(1)])
        self.assertEqual(self.c.dialed[0][0], {"type": "fake", "addr": addr(1)})
        self.assertEqual(self.c.dialed[0][3], AG)                  # the node id goes to the carrier

    def test_the_book_wins_over_the_record_once_it_has_entries(self):
        self.b.adopt(AG, addr(2))
        rec = {"agent": AG, "endpoint": {"type": "fake", "addr": addr(1)}, "name": "p", "threads": []}
        self.d(rec).request({})
        self.assertEqual(self.c.dialed[0][0]["addr"], addr(2))
        self.assertEqual(self.b.ordered(AG), [addr(2)])             # the stale record address is NOT re-added on every dial

    def test_left_shortens_both_timeouts(self):
        rec = {"agent": AG, "endpoint": {"type": "fake", "addr": addr(1)}, "name": "p", "threads": []}
        self.d(rec, 3.0).request({})
        self.assertEqual(self.c.dialed[0][1:3], (3.0, 3.0))
        self.d(rec).request({})
        self.assertEqual(self.c.dialed[1][1:3], (20.0, 45.0))
        self.d(rec, 100.0).request({})
        self.assertEqual(self.c.dialed[2][1:3], (20.0, 45.0))      # never longer than the node's own budgets

    def test_a_record_without_any_address_is_an_error_that_waiting_cannot_fix(self):
        with self.assertRaises(CarrierError) as cm:
            self.d({"agent": AG, "endpoint": None, "name": "p", "threads": []})
        self.assertFalse(cm.exception.retry)

    def test_an_endpoint_of_another_carrier_type_is_left_to_the_carrier_to_refuse(self):
        rec = {"agent": AG, "endpoint": {"type": "other", "addr": "z"}, "name": "p", "threads": []}
        self.d(rec)
        self.assertEqual(self.c.dialed[0][0], {"type": "other", "addr": "z"})
        self.assertEqual(self.b.agents(), [])

    def test_a_record_without_a_node_id_dials_its_endpoint_plainly(self):
        rec = {"endpoint": {"type": "fake", "addr": addr(1)}, "name": "p", "threads": []}
        self.d(rec).request({})
        self.assertEqual(self.c.dialed[0][3], None)


# ------------------------------------------------------------------ receiving an announcement
class PB:
    """A peer book stand-in."""

    def __init__(self, ids):
        self.ids = set(ids)

    def all(self):
        return {a: {"name": "p", "endpoint": {"type": "fake", "addr": addr(1)}, "agent": a, "threads": []} for a in self.ids}


class Carrier2:
    type = "fake"

    def __init__(self):
        self.problem = None
        self.rebinds = []
        self.dropped = []
        self.held = False
        self.dial_error = CarrierError("connect refused", retry=True)

    def has_credential(self, ep, agent=None):
        return self.held

    def drop_credential(self, ep, agent=None):
        self.dropped.append(ep["addr"])
        return True

    def dial(self, ep, **kw):
        raise self.dial_error

    def locator_problem(self, a):
        return self.problem

    def rebind_credential(self, agent, held, new):
        self.rebinds.append((agent, held, new))
        return True

    def doors(self):
        return {}


def service(ids=(AG,), clock=None):
    b, tmp = book(clock=clock)
    c = Carrier2()
    clock = clock or Clock()
    svc = L.LocatorService(ME, PB(ids), c, b, L.PeerDialer(c, b, request_timeout=5, connect_timeout=5), clock=clock)
    return svc, b, c, clock


class OnLocator(unittest.TestCase):
    def test_a_good_announcement_is_queued_not_adopted(self):
        svc, b, c, clock = service()
        b.seed(AG, addr(1))
        self.assertEqual(svc.on_locator(AG, addr(2), 100), "ok")
        self.assertEqual(b.ordered(AG), [addr(1)])                  # nothing is believed before a dial there has been answered
        self.assertEqual(svc._pending[AG], (addr(2), 100))

    def test_a_stranger_is_unknown(self):
        svc, b, c, clock = service()
        self.assertEqual(svc.on_locator(AG2, addr(2), 100), "unknown")
        self.assertEqual(svc._pending, {})

    def test_ourselves_are_unknown(self):
        svc, b, c, clock = service(ids=(ME.id,))
        self.assertEqual(svc.on_locator(ME.id, addr(2), 100), "unknown")

    def test_a_bad_address_is_refused(self):
        svc, b, c, clock = service()
        for bad in (None, 5, "", "x" * 400, "nonsense", "x.onion:1", "h1.fake:0", "a.fake:1\n.fake:2", b"h1.fake:1", ["h1.fake:1"]):
            self.assertEqual(svc.on_locator(AG, bad, 100), "bad address", repr(bad)[:30])
        self.assertEqual(svc._pending, {})

    def test_the_address_is_normalized_like_everywhere_else(self):
        svc, b, c, clock = service()
        self.assertEqual(svc.on_locator(AG, " H1.FAKE:2 ", 100), "ok")
        self.assertEqual(svc._pending[AG][0], "h1.fake:2")

    def test_the_carriers_own_rules_are_applied(self):
        svc, b, c, clock = service()
        c.problem = "a loopback address"
        self.assertEqual(svc.on_locator(AG, addr(2), 100), "refused: a loopback address")
        self.assertEqual(svc._pending, {})

    def test_an_address_we_already_hold_changes_nothing_and_is_not_rate_limited(self):
        svc, b, c, clock = service()
        b.seed(AG, addr(1))
        for _ in range(5):
            self.assertEqual(svc.on_locator(AG, addr(1), 100), "ok")
        self.assertEqual(svc._pending, {})

    def test_a_stale_timestamp_is_ignored(self):
        svc, b, c, clock = service()
        b.adopt(AG, addr(1), ts=500)
        self.assertEqual(svc.on_locator(AG, addr(2), 500), "stale")
        self.assertEqual(svc.on_locator(AG, addr(2), 499), "stale")
        self.assertEqual(svc.on_locator(AG, addr(2), 501), "ok")

    def test_a_non_integer_timestamp_is_stale(self):
        svc, b, c, clock = service()
        for bad in (1.5, True, "501", None):
            self.assertEqual(svc.on_locator(AG, addr(2), bad), "stale", repr(bad))
        self.assertEqual(svc._pending, {})

    def test_one_announcement_per_peer_per_minute(self):
        svc, b, c, clock = service()
        self.assertEqual(svc.on_locator(AG, addr(2), 100), "ok")
        svc._pending.clear()
        self.assertEqual(svc.on_locator(AG, addr(3), 101), "rate limited")
        clock.t += L.LOCATOR_MIN_GAP - 1
        self.assertEqual(svc.on_locator(AG, addr(3), 101), "rate limited")
        clock.t += 1.5
        self.assertEqual(svc.on_locator(AG, addr(3), 102), "ok")

    def test_one_verification_at_a_time_per_peer(self):
        svc, b, c, clock = service()
        self.assertEqual(svc.on_locator(AG, addr(2), 100), "ok")
        clock.t += 1000
        self.assertEqual(svc.on_locator(AG, addr(3), 101), "busy")
        self.assertEqual(svc._pending[AG][0], addr(2))

    def test_three_failed_verifications_in_an_hour_block_the_peer_for_an_hour(self):
        svc, b, c, clock = service()
        svc.verify = lambda agent, a, ts: (False, "connect refused")
        for i in range(L.LOCATOR_FAILS):
            clock.t += L.LOCATOR_MIN_GAP + 1
            self.assertEqual(svc.on_locator(AG, addr(10 + i), 100 + i), "ok")
            svc._work()
        self.assertEqual(svc.on_locator(AG, addr(20), 200), "ignored")
        clock.t += L.LOCATOR_BLOCK - 5
        self.assertEqual(svc.on_locator(AG, addr(20), 200), "ignored")
        clock.t += 10
        self.assertEqual(svc.on_locator(AG, addr(20), 200), "ok")

    def test_failures_spread_over_more_than_an_hour_do_not_block(self):
        svc, b, c, clock = service()
        svc.verify = lambda agent, a, ts: (False, "connect refused")
        for i in range(L.LOCATOR_FAILS + 2):
            clock.t += L.LOCATOR_FAIL_WINDOW / 2 + 1
            self.assertEqual(svc.on_locator(AG, addr(10 + i), 100 + i), "ok", i)
            svc._work()

    def test_a_rejected_candidate_leaves_no_credential_behind_unless_it_was_held_before(self):
        svc, b, c, clock = service()
        ok, why = svc.verify(AG, addr(7), 100)
        self.assertEqual((ok, why), (False, "connect refused"))
        self.assertEqual(c.rebinds[0][2], {"type": "fake", "addr": addr(7)})        # the key was copied for it (Tor) ...
        self.assertEqual(c.dropped, [addr(7)])                                       # ... and is dropped again
        c.held = True                                                                # it was held before (or TCP: nothing was copied)
        c.dropped.clear()
        svc.verify(AG, addr(8), 101)
        self.assertEqual(c.dropped, [])

    def test_a_failing_drop_changes_nothing_about_the_result(self):
        svc, b, c, clock = service()
        c.drop_credential = lambda ep, agent=None: 1 / 0
        self.assertEqual(svc.verify(AG, addr(7), 100), (False, "connect refused"))

    def test_a_flood_of_strangers_leaves_no_trace(self):
        svc, b, c, clock = service()
        for i in range(1500):
            self.assertEqual(svc.on_locator(Identity.generate(str(i)).id, addr(2), 100 + i), "unknown")
        self.assertEqual((svc._pending, svc._seen, svc._fails, svc._block, svc._ann), ({}, {}, {}, {}, {}))
        self.assertEqual(b.agents(), [])

if __name__ == "__main__":
    unittest.main()
