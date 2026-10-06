"""M1b (DESIGN_multicarrier.md rev 4): a node runs SEVERAL carriers at once. The locator book remembers the last INBOUND contact per carrier (`in_at`); the MultiDialer orders the carriers
of a peer by the last good contact in either direction and fails over at once, with a per-(peer, carrier) skip timer; the node's backoff is about the SET of addresses; the sync
server tells the book which carrier an authenticated request arrived on; noderun starts, serves, watches and stops every configured carrier."""
import json
import shutil
import time
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import locators as L
from sigilnet import noderun
from sigilnet import sync as S
from sigilnet.carrier import CarrierError
from sigilnet.doors import service_handler
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.tests.multirig import Rig2
from sigilnet.tests.test_locator_cli import TcpHomes
from sigilnet.tests.test_tcplink import free_base

FP = "ab" * 32


def taddr(i):
    return f"127.0.0.{10 + i}:47{700 + i}#{FP}"


def oaddr(i):
    return chr(ord("a") + i) * 56 + ".onion:47200"


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


# ---------------------------------------------------------------------------------------------------------------- the book
class InAt(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.clk = Clock()
        self.book = L.LocatorBook(self.d / "locators" / "tcp.json", "tcp", clock=self.clk)
        self.a = Identity.generate("a").id

    def test_a_note_sets_in_at_and_the_contact_is_the_later_of_in_at_and_the_last_good_dial(self):
        self.book.seed(self.a, taddr(1))
        self.assertEqual(self.book.contact(self.a), (None, False))
        self.clk.t = 1100.0
        self.book.note_ok(self.a, taddr(1))
        self.assertEqual(self.book.contact(self.a)[0], 1100.0)
        self.clk.t = 1200.0
        self.book.note_inbound(self.a)
        self.assertEqual(self.book.contact(self.a)[0], 1200.0)
        self.assertEqual(self.book._read()[self.a]["in_at"], 1200.0)

    def test_it_is_written_at_most_once_a_minute_per_peer(self):
        self.book.note_inbound(self.a)
        self.clk.t += 10
        self.book.note_inbound(self.a)
        self.assertEqual(self.book._read()[self.a]["in_at"], 1000.0, "a second note inside OK_WRITE_EVERY is not written")
        self.clk.t += L.OK_WRITE_EVERY
        self.book.note_inbound(self.a)
        self.assertEqual(self.book._read()[self.a]["in_at"], 1000.0 + 10 + L.OK_WRITE_EVERY)

    def test_a_peer_the_book_does_not_hold_gets_a_record_with_a_contact_and_no_address(self):
        self.book.note_inbound(self.a)
        self.assertEqual((self.book.count(self.a), self.book.ordered(self.a)), (0, []))
        self.assertEqual(self.book.contact(self.a), (1000.0, False))

    def test_a_carrier_whose_every_address_failed_is_failing_unless_the_peer_reached_us_since(self):
        self.book.seed(self.a, taddr(1))
        self.book.seed(self.a, taddr(2))
        self.clk.t = 1100.0
        self.book.note_fail(self.a, taddr(1))
        self.assertFalse(self.book.contact(self.a)[1], "one address that did not fail yet")
        self.book.note_fail(self.a, taddr(2))
        self.assertTrue(self.book.contact(self.a)[1])
        self.clk.t = 1200.0
        self.book.note_inbound(self.a)
        self.assertFalse(self.book.contact(self.a)[1], "it reached us over this carrier after our last failed dial")

    def test_the_last_failure_is_the_latest_of_all_the_addresses_not_the_first_listed(self):
        self.book.seed(self.a, taddr(1))
        self.book.seed(self.a, taddr(2))
        self.assertIsNone(self.book.last_fail(self.a))
        self.clk.t = 1100.0
        self.book.note_fail(self.a, taddr(1))
        self.clk.t = 1300.0
        self.book.note_fail(self.a, taddr(2))
        self.assertEqual(self.book.last_fail(self.a), 1300.0)
        self.clk.t = 1500.0
        self.book.note_fail(self.a, taddr(1))                              # (the list order is B, A now: the first listed has the older failure)
        self.assertEqual(self.book.last_fail(self.a), 1500.0)
        self.assertIsNone(self.book.last_fail(Identity.generate("z").id))

    def test_a_damaged_in_at_reads_as_none(self):
        self.book.seed(self.a, taddr(1))
        raw = json.loads(self.book.path.read_text())
        raw["peers"][self.a]["in_at"] = "yesterday"
        self.book.path.write_text(json.dumps(raw))
        self.assertIsNone(self.book._read()[self.a]["in_at"])


# ---------------------------------------------------------------------------------------------------------------- the ordering
class StubTransport:
    def __init__(self, d, agent=None):
        self.d, self.agent = d, agent

    def request(self, req):
        self.d.requests.append(req)
        if self.d.clock is not None:
            self.d.clock.t += self.d.cost
        addrs = self.d.book.ordered(self.agent) if (self.d.note and self.agent) else []
        if self.d.fail is not None:
            for a in addrs[:1]:
                self.d.book.note_fail(self.agent, a)                       # (what FallbackTransport does with the book)
            raise self.d.fail
        for a in addrs[:1]:
            self.d.book.note_ok(self.agent, a)
        return {"t": "ok", "from": self.d.name}


class StubDialer:
    """What a PeerDialer is to the MultiDialer: a book, `addresses(rec)`, `__call__(rec, left)` -> a transport."""

    def __init__(self, name, book, clock=None):
        self.name, self.book, self.clock, self.cost, self.note = name, book, clock, 0.0, False
        self.fail, self.requests, self.lefts = None, [], []

    def addresses(self, rec):
        return self.book.ordered(rec["agent"])

    def __call__(self, rec, left=None):
        self.lefts.append(left)
        return StubTransport(self, rec.get("agent"))


class Ordering(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.clk = Clock()
        self.agent = Identity.generate("p").id
        self.tb = L.open_book(self.d, "tcp", clock=self.clk)
        self.ob = L.open_book(self.d, "onion", clock=self.clk)
        self.tb.seed(self.agent, taddr(1))
        self.ob.seed(self.agent, oaddr(1))
        self.t, self.o = StubDialer("tcp", self.tb, self.clk), StubDialer("onion", self.ob, self.clk)
        self.logs = []
        self.md = L.MultiDialer({"tcp": self.t, "onion": self.o}, clock=self.clk, log=lambda *a: self.logs.append(" ".join(map(str, a))))
        self.rec = {"agent": self.agent, "endpoints": [{"type": "tcp", "addr": taddr(1)}, {"type": "onion", "addr": oaddr(1)}]}

    def order(self, rec=None, probe=False):
        """The dial order. By default WITHOUT the re-probe (a stale preferred carrier is put first once per CARRIER_RETRY by `_order`: the probe is marked spent here so these tests see the plain order)."""
        rec = rec or self.rec
        if not probe:
            for t in self.md.dialers:
                self.md._probed[(rec.get("agent"), t)] = self.clk.t
        return self.md._order(rec)

    def test_with_no_contact_the_peers_primary_endpoint_comes_first_then_the_nodes_carrier_order(self):
        self.assertEqual(self.order(), ["tcp", "onion"])
        flipped = {**self.rec, "endpoints": list(reversed(self.rec["endpoints"]))}
        self.assertEqual(self.order(flipped), ["onion", "tcp"])
        self.assertEqual(self.order({"agent": self.agent}), ["tcp", "onion"], "no endpoint in the record: the carrier order of the node")

    def test_among_fresh_carriers_the_nodes_order_wins_and_recency_decides_only_when_stale(self):
        """The human wants tcp used when it works: a carrier is FRESH when its last good contact (our dial or the peer reaching us) is at most L.FRESH old; among fresh carriers the node's own carrier
        order decides (tcp before tor); a fresh one beats a stale one; between stale ones the more recent wins."""
        self.clk.t = 1100.0
        self.tb.note_ok(self.agent, taddr(1))
        self.assertEqual(self.order(), ["tcp", "onion"])
        self.clk.t = 1200.0
        self.ob.note_ok(self.agent, oaddr(1))
        self.assertEqual(self.order(), ["tcp", "onion"], "both fresh: the node's order (tcp), although tor was the more recent")
        self.clk.t = 1300.0
        self.ob.note_inbound(self.agent)
        self.assertEqual(self.order(), ["tcp", "onion"], "the peer reaching us over tor does not move us off a fresh tcp")
        self.clk.t = 1100.0 + L.FRESH + 50                                   # tcp (1100) is stale now, tor (1300) is still fresh
        self.assertEqual(self.order(), ["onion", "tcp"], "a fresh carrier beats a stale one")
        self.clk.t = 1300.0 + L.FRESH + 50                                   # both stale
        self.assertEqual(self.order(), ["onion", "tcp"], "stale: the more recent contact first")
        self.clk.t += 10
        self.tb.note_ok(self.agent, taddr(1))                                # tcp worked again: fresh, and first
        self.assertEqual(self.order(), ["tcp", "onion"])

    def test_the_freshness_edge_is_inclusive_and_a_carrier_with_no_contact_is_never_fresh(self):
        self.tb.note_ok(self.agent, taddr(1))                                # (clock 1000)
        self.clk.t = 1000.0 + L.FRESH
        self.ob.note_ok(self.agent, oaddr(1))
        self.assertEqual(self.order(), ["tcp", "onion"], "exactly FRESH old is still fresh")
        self.clk.t = 1000.0 + L.FRESH + 1
        self.assertEqual(self.order(), ["onion", "tcp"], "one second more: stale, tor is fresh")
        none = {"agent": Identity.generate("n").id}
        self.tb.seed(none["agent"], taddr(2))
        self.ob.seed(none["agent"], oaddr(2))
        self.assertEqual(self.order(none), ["tcp", "onion"], "no contact at all: the node's order")

    def test_a_carrier_whose_addresses_all_failed_goes_last_until_it_works_or_the_peer_reaches_us_on_it(self):
        self.clk.t = 1100.0
        self.tb.note_ok(self.agent, taddr(1))
        self.clk.t = 1200.0
        self.tb.note_fail(self.agent, taddr(1))
        self.assertEqual(self.order(), ["onion", "tcp"])
        self.clk.t = 1300.0
        self.tb.note_inbound(self.agent)
        self.assertEqual(self.order(), ["tcp", "onion"])

    def test_a_carrier_without_an_address_for_the_peer_is_left_out(self):
        self.ob.remove(self.agent)
        self.assertEqual(self.order({"agent": self.agent, "endpoints": [{"type": "tcp", "addr": taddr(1)}]}), ["tcp"])

    def test_a_carrier_that_just_failed_for_this_peer_is_tried_last_for_CARRIER_SKIP_seconds_and_only_for_that_peer(self):
        other = Identity.generate("q").id
        self.tb.seed(other, taddr(2))
        self.ob.seed(other, oaddr(2))
        self.md._failed(self.agent, "tcp", CarrierError("down", retry=True))
        self.assertEqual(self.order(), ["onion", "tcp"])
        self.assertEqual(self.md._order({"agent": other}), ["tcp", "onion"])
        self.clk.t += L.CARRIER_SKIP - 1
        self.assertEqual(self.order(), ["onion", "tcp"])
        self.clk.t += 2
        self.assertEqual(self.order(), ["tcp", "onion"])
        self.md._failed(self.agent, "tcp", CarrierError("down", retry=True))
        self.md._worked(self.agent, "tcp")
        self.assertEqual(self.order(), ["tcp", "onion"], "a success ends the skip")

    def test_a_single_carrier_nodes_ping_result_has_no_via_key(self):
        import sigilnet.ping as P
        with mock.patch.object(P, "exchange", return_value=(True, "", {"unread": 0, "watching": True, "up": True}, 3.0)):
            pass                                                           # (the file shape itself is pinned by tests/test_ping.py: set(r) == {id, ok, why, pong, rtt_ms})
        self.assertEqual(P.PingResult(True, None, {}, 1.0, "n", "i").via, None)

    def test_the_skip_table_is_bounded(self):
        for i in range(L.MAX_SKIPS + 50):
            self.md._failed(f"peer{i}", "tcp", CarrierError("x"))
        self.assertLessEqual(len(self.md._skip), L.MAX_SKIPS)
        self.assertIn(("peer%d" % (L.MAX_SKIPS + 49), "tcp"), self.md._skip, "the newest failure is kept")

    def test_the_combined_view_the_node_asks(self):
        self.tb.seed(self.agent, taddr(2))
        self.assertEqual(self.md.count(self.agent), 3)
        self.assertEqual(sorted(self.md.ordered(self.agent)), sorted([taddr(1), taddr(2), oaddr(1)]))


class Reprobe(Ordering):
    """Sansa F1: a failed carrier must be tried again, or one blip keeps the preferred carrier unused for ever."""

    def setUp(self):
        super().setUp()
        self.t.note = self.o.note = True

    def pull(self):
        """One pull of the peer, as the node does it every 300 s."""
        self.md(self.rec).request({"t": "x"})

    def test_a_day_with_tcp_down_and_tor_up_probes_tcp_about_once_per_CARRIER_RETRY_and_not_every_pull(self):
        self.t.fail = CarrierError("tcp is down", retry=True)
        for _ in range(86400 // 300):
            self.pull()
            self.clk.t += 300.0
        n = len(self.t.requests)
        expected = 86400 // int(L.CARRIER_RETRY)
        self.assertTrue(expected - 3 <= n <= expected + 3, f"{n} tcp requests in a day (one per {L.CARRIER_RETRY:g} s = about {expected})")
        self.assertGreater(len(self.o.requests), 200)

    def test_a_stale_carrier_that_never_failed_is_probed_too_or_it_could_never_become_fresh(self):
        """Sansa P2: tcp last good an hour ago, tor fresh, nothing failed: tcp must still get its turn."""
        self.tb.note_ok(self.agent, taddr(1))                                # clock 1000
        self.clk.t = 1000.0 + 3600
        self.ob.note_ok(self.agent, oaddr(1))
        self.assertEqual(self.md._order(self.rec), ["tcp", "onion"], "stale preferred carrier: probed first, once")
        self.assertEqual(self.md._order(self.rec), ["onion", "tcp"], "the probe is spent for CARRIER_RETRY")
        self.clk.t += L.CARRIER_RETRY
        self.ob.note_ok(self.agent, oaddr(1))
        self.assertEqual(self.md._order(self.rec)[0], "tcp", "asked again after CARRIER_RETRY")

    def test_a_day_with_tcp_idle_and_tor_fresh_probes_tcp_about_once_per_period_until_it_works_then_all_pulls_are_tcp(self):
        self.tb.note_ok(self.agent, taddr(1))
        self.clk.t = 1000.0 + 3600
        self.ob.note_ok(self.agent, oaddr(1))
        self.t.note = self.o.note = True
        self.t.fail = CarrierError("tcp is dead", retry=True)
        for _ in range(86400 // 300):
            self.pull()
            self.clk.t += 300.0
        n = len(self.t.requests)
        expected = 86400 // int(L.CARRIER_RETRY)
        self.assertTrue(expected - 3 <= n <= expected + 3, f"{n} tcp probes in a day (about {expected})")
        self.t.fail = None
        self.clk.t += L.CARRIER_RETRY + 1
        self.t.requests.clear()
        self.o.requests.clear()
        for _ in range(6):
            self.pull()
            self.clk.t += 300.0
        self.assertEqual((len(self.t.requests), len(self.o.requests)), (6, 0), "tcp works again: fresh and first for every pull")

    def test_a_less_preferred_stale_carrier_is_not_probed_ahead_and_a_preferred_one_with_no_contact_is(self):
        self.ob.note_ok(self.agent, oaddr(1))
        self.clk.t = 1000.0 + 3600
        self.tb.note_ok(self.agent, taddr(1))                                # tcp fresh, tor stale and LESS preferred
        self.assertEqual(self.md._order(self.rec), ["tcp", "onion"])
        self.assertEqual(self.md._probed, {})
        other = Identity.generate("q").id
        self.tb.seed(other, taddr(2), front=False)                           # tcp known, never contacted; tor fresh
        self.ob.seed(other, oaddr(2))
        self.ob.note_ok(other, oaddr(2))
        self.assertEqual(self.md._order({"agent": other})[0], "tcp", "a preferred carrier without any contact gets its probe")

    def test_a_probe_that_works_puts_the_preferred_carrier_first_for_good(self):
        self.t.fail = CarrierError("blip", retry=True)
        self.pull()                                                        # tcp fails once, tor answers
        self.t.fail = None
        self.clk.t += L.CARRIER_RETRY + 1
        self.t.requests.clear()
        self.o.requests.clear()
        self.pull()                                                        # the probe: the preferred carrier first, and it works
        self.assertEqual((len(self.t.requests), len(self.o.requests)), (1, 0))
        self.t.requests.clear()
        for _ in range(5):
            self.clk.t += 300.0
            self.pull()
        self.assertEqual((len(self.t.requests), len(self.o.requests)), (5, 0), "back on tcp: every pull goes there")

    def test_the_probe_is_once_per_period_per_peer_and_carrier(self):
        self.t.fail = CarrierError("down", retry=True)
        self.pull()
        self.clk.t += L.CARRIER_RETRY + 1
        self.assertEqual(self.md._order(self.rec)[0], "tcp")
        self.assertEqual(self.md._order(self.rec)[0], "onion", "asked again at once: the probe is spent")
        other = Identity.generate("q").id
        self.tb.seed(other, taddr(2))
        self.ob.seed(other, oaddr(2))
        self.tb.note_fail(other, taddr(2))
        self.assertEqual(self.md._order({"agent": other})[0], "onion")
        self.assertEqual(self.md._order({"agent": other})[0], "onion", "per peer: another peer has its own probe")

    def test_a_carrier_the_node_prefers_less_is_not_probed_while_the_preferred_one_is_first(self):
        self.tb.note_ok(self.agent, taddr(1))
        self.clk.t += L.CARRIER_RETRY + 1
        self.assertEqual(self.md._order(self.rec), ["tcp", "onion"], "tcp is first and preferred: nothing to probe")
        self.clk.t += 3 * L.CARRIER_RETRY
        self.assertEqual(self.md._order(self.rec), ["tcp", "onion"])
        self.assertEqual(self.md._probed, {})

    def test_a_failed_carrier_the_node_prefers_less_is_never_put_before_the_preferred_one(self):
        self.tb.note_ok(self.agent, taddr(1))
        self.clk.t += 10
        self.ob.note_fail(self.agent, oaddr(1))
        self.clk.t += 5 * L.CARRIER_RETRY
        self.assertEqual(self.md._order(self.rec), ["tcp", "onion"], "tor is behind and less preferred: no probe puts it first")
        self.assertEqual(self.md._probed, {})

    def test_a_dead_preferred_carrier_costs_one_connect_per_probe_and_the_failover_is_at_once(self):
        self.t.fail = CarrierError("down", retry=True)
        self.t.cost = 10.0
        self.pull()
        self.clk.t += L.CARRIER_RETRY + 1
        before = self.clk.t
        self.t.requests.clear()
        self.pull()
        self.assertEqual(len(self.t.requests), 1)
        self.assertEqual(self.clk.t - before, 10.0, "one connect timeout, then tor answered")


class Failover(Ordering):
    def test_the_first_carrier_that_answers_wins_and_a_failed_one_goes_to_the_back_for_the_next_request(self):
        self.t.fail = CarrierError("tcp is down", retry=True)
        tr = self.md(self.rec)
        self.assertIsInstance(tr, L.MultiTransport)
        self.assertEqual(tr.request({"t": "x"})["from"], "onion")
        self.assertEqual(tr.via, "onion")
        self.assertEqual(tr.order, ["onion", "tcp"])
        self.t.requests.clear()
        self.assertEqual(tr.request({"t": "y"})["from"], "onion")
        self.assertEqual(self.t.requests, [], "the failed carrier is not asked again by this transport before the one that answered")

    def test_a_success_ends_the_skip_and_a_failure_starts_it(self):
        self.t.fail = CarrierError("down", retry=True)
        self.md(self.rec).request({"t": "x"})
        self.assertGreater(self.md._skip[(self.agent, "tcp")], self.clk.t)
        self.assertNotIn((self.agent, "onion"), self.md._skip)
        self.t.fail = None
        self.clk.t += L.CARRIER_SKIP + 1
        self.md(self.rec).request({"t": "x"})
        self.assertNotIn((self.agent, "tcp"), self.md._skip)

    def test_when_every_carrier_failed_the_error_says_so_and_retry_is_true_if_any_error_can_be_retried(self):
        self.t.fail = CarrierError("tcp down", retry=False)
        self.o.fail = CarrierError("onion down", retry=True)
        with self.assertRaises(CarrierError) as cm:
            self.md(self.rec).request({"t": "x"})
        self.assertIn("1 other carrier(s) failed too", str(cm.exception))
        self.assertTrue(cm.exception.retry)
        self.o.fail = CarrierError("onion down", retry=False)
        with self.assertRaises(CarrierError) as cm:
            self.md(self.rec).request({"t": "x"})
        self.assertFalse(cm.exception.retry)

    def test_an_os_error_counts_as_a_failure_of_that_carrier(self):
        self.t.fail = TimeoutError("timed out")
        self.assertEqual(self.md(self.rec).request({"t": "x"})["from"], "onion")
        self.o.fail = ConnectionResetError("reset")
        self.clk.t += L.CARRIER_SKIP + 1
        with self.assertRaises(CarrierError):
            self.md(self.rec).request({"t": "x"})

    def test_the_cli_deadline_is_split_over_the_carriers(self):
        self.t.fail, self.t.cost = CarrierError("slow", retry=True), 3.0
        self.md(self.rec, left=10.0).request({"t": "x"})
        self.assertEqual(self.t.lefts, [10.0])
        self.assertEqual(self.o.lefts, [7.0], "the second carrier gets what is left of the deadline")
        self.t.cost = 100.0
        self.clk.t += L.CARRIER_SKIP + 1
        self.o.lefts.clear()
        self.md(self.rec, left=10.0).request({"t": "x"})
        self.assertEqual(self.o.lefts, [0.1], "never zero")

    def test_a_node_with_one_carrier_gets_that_carriers_own_transport(self):
        solo = L.MultiDialer({"tcp": self.t})
        self.assertIsInstance(solo(self.rec), StubTransport)

    def test_a_peer_only_one_carrier_has_an_address_for_gets_that_carriers_transport(self):
        self.ob.remove(self.agent)
        self.assertIsInstance(self.md({"agent": self.agent, "endpoints": [{"type": "tcp", "addr": taddr(1)}]}), StubTransport)

    def test_a_peer_no_carrier_knows_an_address_for_gets_the_first_carriers_own_error(self):
        self.tb.remove(self.agent)
        self.ob.remove(self.agent)
        self.md({"agent": self.agent, "endpoints": []})
        self.assertEqual(self.t.lefts, [None], "the first carrier is asked (its dialer raises the real error: no address, or the refusal of an endpoint of another type)")

    def test_a_failure_that_waiting_cannot_fix_is_logged_once_per_peer_carrier_and_text(self):
        self.t.fail = CarrierError("door key does not match the endpoint", retry=False)
        for _ in range(3):
            self.clk.t += L.CARRIER_SKIP + 1
            self.md(self.rec).request({"t": "x"})                           # (the onion carrier answers: the success must not hide the tcp problem)
        pins = [l for l in self.logs if "door key does not match" in l]
        self.assertEqual(len(pins), 1, self.logs)
        self.assertIn("carrier tcp", pins[0])
        self.t.fail = CarrierError("not authorized", retry=False)
        self.clk.t += L.CARRIER_SKIP + 1
        self.md(self.rec).request({"t": "x"})
        self.assertEqual(len([l for l in self.logs if "not authorized" in l]), 1)
        self.t.fail = CarrierError("flaky", retry=True)
        self.clk.t += L.CARRIER_SKIP + 1
        self.md(self.rec).request({"t": "x"})
        self.assertFalse([l for l in self.logs if "flaky" in l], "a failure that waiting can fix is not logged")

    def test_a_carrier_that_cannot_even_build_its_transport_is_a_failure_of_that_carrier(self):
        def boom(rec, left=None):
            raise CarrierError("no such door", retry=True)
        self.t.__class__ = type("Boom", (StubDialer,), {"__call__": lambda s, rec, left=None: boom(rec, left)})
        self.assertEqual(self.md(self.rec).request({"t": "x"})["from"], "onion")


# ---------------------------------------------------------------------------------------------------------------- the server
class Inbound(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.me = Identity.generate("srv")
        self.peer = Identity.generate("peer")
        self.stranger = Identity.generate("stranger")
        self.seen = []
        self.srv = S.SyncServer(Mirror(self.tmp / "m"), identity=self.me, on_inbound=lambda a, v: self.seen.append((a, v)))
        self.srv.set_peers([self.peer.id])

    def req(self, ident, **kw):
        import time
        return S.sign_request(ident, {"t": "summary", "thread": "0" * 32, **kw}, ts=int(time.time()))

    def test_an_authenticated_request_of_a_peer_over_a_door_is_told_with_its_carrier(self):
        h = service_handler(self.srv, self.peer.id, "tcp")
        h(self.req(self.peer))
        self.assertEqual(self.seen, [(self.peer.id, "tcp")])

    def test_a_blob_request_counts_too(self):
        h = service_handler(self.srv, None, "onion")
        h(S.sign_request(self.peer, {"t": "blob", "thread": "0" * 32, "cid": "sha256:" + "0" * 64}, ts=int(__import__("time").time())))
        self.assertEqual(self.seen, [(self.peer.id, "onion")])

    def test_nothing_is_told_for_a_bad_signature_a_stranger_a_wrong_door_or_a_call_that_is_not_through_a_door(self):
        h = service_handler(self.srv, None, "tcp")
        bad = self.req(self.peer)
        bad["sig"] = "00" * 64
        h(bad)
        h(self.req(self.stranger))
        service_handler(self.srv, self.peer.id, "tcp")(self.req(self.stranger))     # a door bound to the peer: another agent's request is refused at the door
        self.srv.handle(self.req(self.peer))                                         # no door: no carrier
        self.assertEqual(self.seen, [])

    def test_a_member_that_is_not_a_peer_is_not_told(self):
        self.srv.set_peers([])
        service_handler(self.srv, None, "tcp")(self.req(self.peer))
        self.assertEqual(self.seen, [])

    def test_a_failure_of_the_callback_never_fails_the_request(self):
        srv = S.SyncServer(Mirror(self.tmp / "m2"), identity=self.me, on_inbound=mock.Mock(side_effect=RuntimeError("boom")))
        srv.set_peers([self.peer.id])
        r = service_handler(srv, None, "tcp")(self.req(self.peer))
        self.assertNotEqual(r.get("why"), "internal: RuntimeError")

    def test_the_carrier_of_a_request_is_per_thread_and_ends_with_the_call(self):
        self.assertIsNone(self.srv.via())
        with self.srv.arrived_on("tcp"):
            self.assertEqual(self.srv.via(), "tcp")
            with self.srv.arrived_on("onion"):
                self.assertEqual(self.srv.via(), "onion")
            self.assertEqual(self.srv.via(), "tcp")
        self.assertIsNone(self.srv.via())

    def test_a_handler_with_no_carrier_or_a_server_double_without_arrived_on_still_works(self):
        srv = mock.Mock(spec=["handle", "refuse"])
        srv.handle.return_value = {"t": "ok"}
        self.assertEqual(service_handler(srv, None, "tcp")({"from": "x"}), {"t": "ok"})
        self.assertEqual(service_handler(self.srv, None)(self.req(self.peer)).get("t"), self.srv.handle(self.req(self.peer)).get("t"))
        self.assertEqual(self.seen, [])


# ---------------------------------------------------------------------------------------------------------------- two carriers, two nodes
class TwoCarrierNodes(unittest.TestCase):
    def setUp(self):
        self.r = Rig2()
        self.addCleanup(self.r.close)
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.aid, self.bid = self.r.ids["a"].id, self.r.ids["b"].id

    def test_a_peer_with_an_address_on_each_carrier_is_planned_once_and_pulled(self):
        self.assertEqual(len(self.b.dialer.ordered(self.aid)), 2)
        self.assertIn(self.aid, self.b.node._plan())
        self.r.post("a", "hello")
        self.r.tick("b")
        self.assertIn("hello", self.r.texts("b"))
        self.assertNotIn(self.aid, self.b.node.down)

    def test_when_one_carrier_is_unreachable_the_other_carries_the_pull_and_the_peer_is_not_down(self):
        self.r.blackhole("a", "fake")
        self.r.post("a", "over fakeb")
        self.r.tick("b")
        self.assertIn("over fakeb", self.r.texts("b"))
        self.assertNotIn(self.aid, self.b.node.down, "Node.down means EVERY carrier failed")
        self.assertIn((self.aid, "fake"), self.b.dialer._skip, "the carrier that failed is tried last for a while")
        self.assertIsNotNone(self.b.books["fakeb"].contact(self.aid)[0], "a good dial is remembered on the carrier that worked")

    def test_when_every_carrier_is_unreachable_the_peer_is_down_and_a_returning_carrier_ends_it(self):
        self.r.blackhole("a", "fake")
        self.r.blackhole("a", "fakeb")
        self.r.post("a", "later")
        self.r.tick("b", rounds=1)
        self.assertIn(self.aid, self.b.node.down)
        self.assertIn("other carrier(s) failed too", self.b.node.down[self.aid]["err"])
        self.r.blackhole("a", "fakeb", False)
        self.b.node.address_changed(self.aid)
        self.b.dialer._skip.clear()
        self.r.tick("b")
        self.assertIn("later", self.r.texts("b"))
        self.assertNotIn(self.aid, self.b.node.down)

    def test_a_request_that_arrives_over_one_carrier_makes_that_carrier_the_one_we_answer_on(self):
        """The human: "the only requirement is that you respond to them on the last-known-good carrier"."""
        rec = self.a.peers.all()[self.bid]
        self.assertEqual([e["type"] for e in rec["endpoints"]], ["fake", "fakeb"], "setup: fake is the primary")
        self.assertEqual(self.a.dialer._order(rec), ["fake", "fakeb"])
        self.r.blackhole("a", "fake")                                          # B can only reach A over fakeb
        self.r.post("a", "x")
        self.r.tick("b", rounds=1)                                              # B pulls from A over fakeb: A sees an authenticated request on fakeb
        self.assertIsNotNone(self.a.books["fakeb"]._read()[self.bid]["in_at"])
        self.assertIsNone(self.a.books["fake"]._read()[self.bid]["in_at"], "nothing arrived over fake")
        self.assertEqual(self.a.dialer._order(rec), ["fake", "fakeb"], "fake was good a moment ago too: still fresh, the node's order (fake) wins")

        def age(peers):                                                         # the fake book's last good contact is old now
            for rec_ in peers.values():
                for l in rec_["locs"]:
                    l["ok"] = (l["ok"] or 0) - (L.FRESH + 100)
            return True
        self.a.books["fake"]._edit(age)
        for t in self.a.dialer.dialers:
            self.a.dialer._probed[(self.bid, t)] = time.time()              # (the re-probe of a stale preferred carrier is not what this test is about)
        self.assertEqual(self.a.dialer._order(rec), ["fakeb", "fake"], "fake is stale, B just reached us over fakeb: A answers B over the carrier B just used")

    def test_an_announcement_goes_over_its_own_carrier_and_is_remembered_in_its_own_book(self):
        A = self.a
        due = {t: [x for x, _ in A.svcs[t]._due()] for t in A.svcs}
        self.assertEqual(due, {"fake": [self.bid], "fakeb": [self.bid]})
        A.svcs["fakeb"]._work()
        self.assertEqual(A.books["fakeb"].announced(self.bid), A.carriers["fakeb"].door_endpoint("peer-b")["addr"])
        self.assertIsNone(A.books["fake"].announced(self.bid), "the other carrier's service has not told B yet")
        B_logs = [l for l in self.b.logs if "locator" in l]
        self.assertFalse([l for l in B_logs if "discarded" in l])

    def test_a_flipping_order_does_not_end_a_backoff_but_a_new_address_does(self):
        n = self.b.node
        n.down[self.aid] = {"tries": 3, "until": n.clock() + 500, "err": "x", "blocked": False, "loc": n._addrs(self.aid)}
        with n.mu:
            n._drop_stale_backoffs(n.clock())
        self.assertIn(self.aid, n.down)
        self.b.books["fake"].seed(self.aid, "second.fake:1")
        n.down[self.aid]["loc"] = n._addrs(self.aid)
        first = self.b.dialer.ordered(self.aid)[0]
        before = n._addrs(self.aid)
        self.b.books["fake"].note_fail(self.aid, first)                                           # the dial ORDER changes: that address goes behind its sibling
        self.assertNotEqual(self.b.dialer.ordered(self.aid)[0], first)
        self.assertEqual(n._addrs(self.aid), before, "the same SET")
        with n.mu:
            n._drop_stale_backoffs(n.clock())
        self.assertIn(self.aid, n.down, "the same SET of addresses in another order")
        self.b.books["fake"].seed(self.aid, "new-one.fake:1", front=False)
        with n.mu:
            n._drop_stale_backoffs(n.clock())
        self.assertNotIn(self.aid, n.down, "a different set of addresses: the backoff was earned by the old ones")

    def test_a_ping_names_the_carrier_that_answered(self):
        from sigilnet import ping as P
        self.r.tick("a", "b")
        svc = P.PingService(self.b.node, self.b.home, self.b.dialer)
        svc.dir.mkdir(parents=True, exist_ok=True)
        (svc.dir / "abc.req").write_text("{}")
        rec = self.b.peers.all()[self.aid]
        svc._run("abc", {"peer": self.aid, "deadline": self.b.node.clock() + 10}, rec)
        res = json.loads((svc.dir / "abc.res").read_text())
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["via"], "fake", "the answering carrier is in the result")
        self.assertIn("via", res)
        self.r.blackhole("a", "fake")
        self.b.dialer._skip.clear()
        (svc.dir / "abd.req").write_text("{}")
        svc._run("abd", {"peer": self.aid, "deadline": self.b.node.clock() + 10}, rec)
        self.assertEqual(json.loads((svc.dir / "abd.res").read_text())["via"], "fakeb")
        line = P.format_result(P.PingResult(True, None, {"unread": 0, "watching": True}, 5.0, "a", self.aid, "fakeb"), 1.0)
        self.assertTrue(line.endswith("rtt 5 ms, via fakeb"), line)
        self.assertTrue(P.format_result(P.PingResult(True, None, {"unread": 0, "watching": True}, 5.0, "a", self.aid), 1.0).endswith("rtt 5 ms"))

    def test_status_survives_two_carriers(self):
        self.assertEqual(self.b.node.status(), [])
        self.r.tick("a", "b")
        self.assertIsInstance(self.b.node.status(), list)


# ---------------------------------------------------------------------------------------------------------------- config and the node
class Config(unittest.TestCase):
    def setUp(self):
        self.h = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.h, True)

    def write(self, **kw):
        (self.h / "node_config.json").write_text(json.dumps(kw))

    def test_defaults_and_the_old_single_carrier_key(self):
        self.assertEqual(noderun.load_config(self.h)["carriers"], ["tor"])
        self.write(carrier="tcp", tcp={"bind": "127.0.0.1", "port_base": 47600})
        cfg = noderun.load_config(self.h)
        self.assertEqual((cfg["carrier"], cfg["carriers"]), ("tcp", ["tcp"]))

    def test_a_set_of_carriers_the_first_is_the_primary(self):
        self.write(carriers=["tcp", "tor"], tcp={"bind": "127.0.0.1", "port_base": 47600})
        cfg = noderun.load_config(self.h)
        self.assertEqual((cfg["carrier"], cfg["carriers"]), ("tcp", ["tcp", "tor"]))
        self.write(carriers=["tor", "tcp"], tcp={"bind": "127.0.0.1", "port_base": 47600})
        self.assertEqual(noderun.load_config(self.h)["carrier"], "tor")

    def test_carriers_wins_over_carrier_when_both_are_there(self):
        self.write(carrier="tor", carriers=["tcp"], tcp={"bind": "127.0.0.1", "port_base": 47600})
        self.assertEqual(noderun.load_config(self.h)["carriers"], ["tcp"])

    def test_node_init_writes_a_consistent_carrier_and_set(self):
        """`node init --carrier tcp` once saved carrier=tcp next to the default carriers=[tor], and carriers won: the node came up on Tor."""
        from sigilnet import cli
        import contextlib, io
        h = self.h
        h.chmod(0o700)
        Identity.generate("me").save(h / "identity.json")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["--home", str(h), "node", "init", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", str(free_base())])
        self.assertEqual(rc, 0, out.getvalue() + err.getvalue())
        saved = json.loads((h / "node_config.json").read_text())
        self.assertEqual((saved["carrier"], saved["carriers"]), ("tcp", ["tcp"]))
        cfg = noderun.load_config(h)
        self.assertEqual((cfg["carrier"], cfg["carriers"]), ("tcp", ["tcp"]))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["--home", str(h), "node", "init", "--carrier", "tor"])
        self.assertEqual(json.loads((h / "node_config.json").read_text())["carriers"], ["tor"])

    def test_bad_sets_are_refused(self):
        for bad in ([], ["tcp", "tcp"], ["tor", "tcp", "tor"], ["udp"], "tcp", None, [1], ["tcp", "tor", "x"], [["tcp"]], [{"a": 1}], [None], [True], {"tcp": 1}):
            self.write(carriers=bad, tcp={"bind": "127.0.0.1", "port_base": 47600})
            with self.assertRaises(ValueError, msg=repr(bad)):
                noderun.load_config(self.h)

    def test_tcp_in_the_set_needs_its_section(self):
        self.write(carriers=["tor", "tcp"])
        with self.assertRaises(ValueError):
            noderun.load_config(self.h)

    def test_make_carriers_builds_each_in_order_with_its_endpoint_type_and_carrier_for_picks_one(self):
        self.write(carriers=["tcp", "tor"], tcp={"bind": "127.0.0.1", "port_base": free_base()})
        cfg = noderun.load_config(self.h)
        cs = noderun.make_carriers(self.h, cfg, offline=True)
        self.assertEqual(list(cs), ["tcp", "onion"])
        self.assertEqual(noderun.make_carrier(self.h, cfg, offline=True).type, "tcp")
        self.assertEqual(noderun.carrier_for(self.h, cfg, "onion", offline=True).type, "onion")
        self.write(carriers=["tcp"], tcp={"bind": "127.0.0.1", "port_base": free_base()})
        with self.assertRaises(ValueError) as cm:
            noderun.carrier_for(self.h, noderun.load_config(self.h), "onion", offline=True)
        self.assertIn("does not run the onion carrier", str(cm.exception))

    def test_connect_timeouts_are_per_carrier(self):
        self.assertLess(noderun.CONNECT_TIMEOUTS["tcp"], noderun.CONNECT_TIMEOUTS["onion"])
        self.assertEqual(noderun.CONNECT_TIMEOUTS["onion"], noderun.CONNECT_TIMEOUT)


class CliWithTwoCarriers(TcpHomes):
    """The home of side `a` is configured to run tcp AND tor: `peer move` picks the carrier of the endpoint's type."""

    def setUp(self):
        super().setUp()
        h = self.r.sides["a"].home
        cfg = json.loads((h / "node_config.json").read_text())
        (h / "node_config.json").write_text(json.dumps({**cfg, "carriers": ["tcp", "tor"], "service_port_base": free_base()}))

    def test_an_onion_endpoint_can_be_set_without_verifying_and_becomes_primary_beside_the_tcp_one(self):
        onion = oaddr(4)
        rc, out, err = self.cli("a", "peer", "move", "b", "--endpoint", "onion:" + onion, "--no-verify")
        self.assertEqual(rc, 0, out + err)
        eps = json.loads((self.a.home / "peers.json").read_text())["peers"][self.bid]["endpoints"]
        self.assertEqual([e["type"] for e in eps], ["onion", "tcp"])
        rc, out, err = self.cli("a", "peer", "list")
        self.assertIn("onion " + onion, out)
        self.assertIn("also tcp ", out)

    def test_an_onion_endpoint_cannot_be_verified_from_the_cli_even_when_the_node_runs_tor(self):
        rc, out, err = self.cli("a", "peer", "move", "b", "--endpoint", "onion:" + oaddr(4))
        self.assertNotEqual(rc, 0)
        self.assertIn("cannot verify a Tor address", err)

    def test_a_tcp_endpoint_is_still_verified_on_the_tcp_carrier(self):
        old = self.a.book.ordered(self.bid)[0]
        port = old.partition("#")[0].split(":")[1]
        new = self.r.move("b", "127.0.0.4")
        self.r.tick()
        rc, out, err = self.cli("a", "peer", "move", "b", "--ip", "127.0.0.4")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("verified: b answered", out)


class DoorCommandsPickTheCarrier(TcpHomes):
    """`node auth/authorize/address/revoke --carrier tor|tcp` act on THAT carrier of a tcp+tor home; without it on the primary (tcp), as before."""

    def setUp(self):
        super().setUp()
        h = self.r.sides["a"].home
        cfg = json.loads((h / "node_config.json").read_text())
        (h / "node_config.json").write_text(json.dumps({**cfg, "carriers": ["tcp", "tor"], "service_port_base": free_base()}))
        self.h = h

    def pub_of(self, label, *extra):
        rc, out, err = self.cli("a", "node", "auth", label, *extra)
        self.assertEqual(rc, 0, out + err)
        return out.strip().splitlines()[-1].strip(), json.loads((self.h / "peerkeys" / f"{label}.priv").read_text())

    def test_auth_makes_a_key_of_the_chosen_carriers_type(self):
        _, tcp_secret = self.pub_of("ktcp")
        self.assertEqual(tcp_secret["type"], "tcp", "default = the primary carrier")
        _, tor_secret = self.pub_of("ktor", "--carrier", "tor")
        self.assertEqual(tor_secret["type"], "onion")

    def test_authorize_opens_the_door_on_the_chosen_carrier_only(self):
        pub, _ = self.pub_of("ktor", "--carrier", "tor")
        peer = Identity.generate("p").id
        rc, out, err = self.cli("a", "node", "authorize", "p-tor", pub, "--agent", peer, "--carrier", "tor")
        self.assertEqual(rc, 0, out + err)
        tor = noderun.carrier_for(self.h, noderun.load_config(self.h), "onion", offline=True)
        self.assertIn("p-tor", tor.doors())
        tcp = noderun.carrier_for(self.h, noderun.load_config(self.h), "tcp", offline=True)
        self.assertNotIn("p-tor", tcp.doors())
        rc, out, err = self.cli("a", "node", "address", "--carrier", "tor")
        self.assertIn("p-tor", out)
        rc, out, err = self.cli("a", "node", "address")
        self.assertNotIn("p-tor", out, "without --carrier: the primary's doors only")
        rc, out, err = self.cli("a", "node", "revoke", "p-tor", "--carrier", "tcp")
        self.assertIn("no such name", out)
        self.assertIn("p-tor", noderun.carrier_for(self.h, noderun.load_config(self.h), "onion", offline=True).doors())
        rc, out, err = self.cli("a", "node", "revoke", "p-tor", "--carrier", "tor")
        self.assertIn("revoked", out)
        self.assertNotIn("p-tor", noderun.carrier_for(self.h, noderun.load_config(self.h), "onion", offline=True).doors())

    def test_a_carrier_the_node_does_not_run_is_an_error(self):
        (self.h / "node_config.json").write_text(json.dumps({"carrier": "tcp", "tcp": {"bind": "127.0.0.1", "port_base": free_base()}}))
        rc, out, err = self.cli("a", "node", "address", "--carrier", "tor")
        self.assertNotEqual(rc, 0)
        self.assertIn("does not run the onion carrier", err)

    def test_the_default_is_unchanged_for_a_home_with_one_carrier(self):
        rc, out, err = self.cli("a", "node", "address")
        self.assertEqual(rc, 0, err)
        self.assertIn("peer-", out)


class RunTwoCarriers(unittest.TestCase):
    """noderun.run with tcp + tor (tor offline: no network): both start (tcp first), the doors are counted over both, the status names both, both stop."""

    def test_both_carriers_start_serve_and_stop(self):
        h = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, h, True)
        h.chmod(0o700)
        (h / "node_config.json").write_text(json.dumps({"carriers": ["tcp", "tor"], "tcp": {"bind": "127.0.0.1", "port_base": free_base()}, "service_port_base": free_base()}))
        me = Identity.generate("me")
        me.save(h / "identity.json")
        lines = []
        rc = noderun.run(h, me, seconds=3, offline=True, out=lines.append)
        self.assertEqual(rc, 0, lines)
        ups = [l.strip() for l in lines if l.strip().startswith("carrier ") and l.strip().endswith(": up")]
        self.assertEqual(ups, ["carrier tcp: up", "carrier onion: up"], lines)
        self.assertTrue(any("serving sync on loopback" in l and "tcp+onion" in l for l in lines), lines)
        self.assertFalse((h / "node.pid").exists())


if __name__ == "__main__":
    unittest.main()
