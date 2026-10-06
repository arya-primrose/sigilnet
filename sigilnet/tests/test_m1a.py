"""M1a (DESIGN_multicarrier.md rev 4): a peer record holds ONE endpoint PER CARRIER TYPE (`endpoints`, the primary first); every reader goes through `carrier.endpoints_of` /
`endpoint_of`. The runtime still has one carrier; these tests are the readers Sansa listed (a-i) with two carriers' addresses for one peer, and a peer with none."""
import json
import re
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import cli
from sigilnet import locators as L
from sigilnet import node as N
from sigilnet.carrier import CarrierError, endpoint_of, endpoints_of
from sigilnet.keys import Identity
from sigilnet.tests import fake_carrier  # noqa: F401  (registers the "fake" endpoint type)
from sigilnet.tests.locrig import Rig
from sigilnet.tests.test_locator_cli import TcpHomes, run_cli

SRC = Path(__file__).resolve().parents[1]


def onion(i):
    return chr(ord("a") + i) * 56 + ".onion"


def oep(i, port=47200):
    return {"type": "onion", "addr": f"{onion(i)}:{port}"}


def tep(i):
    return {"type": "tcp", "addr": f"127.0.0.{10 + i}:47{700 + i}#" + f"{i:02x}" * 32}


class Book(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.p = N.PeerBook(self.d / "peers.json")
        self.a = Identity.generate("a").id

    def raw(self):
        return json.loads(self.p.path.read_text())["peers"]

    def test_a_second_add_with_the_other_carriers_endpoint_adds_it_and_makes_it_primary(self):
        self.p.add(self.a, "bee", tep(1), ["1" * 32])
        self.p.add(self.a, "bee", oep(1), ["1" * 32])
        self.assertEqual(self.p.all()[self.a]["endpoints"], [oep(1), tep(1)])
        self.assertEqual(self.p.all()[self.a]["endpoint"], oep(1), "`endpoint` is the primary, for display")
        self.assertEqual(endpoint_of(self.p.all()[self.a], "tcp"), tep(1))
        self.assertEqual(self.raw()[self.a]["endpoints"], [oep(1), tep(1)])
        self.assertNotIn("endpoint", self.raw()[self.a], "the file holds `endpoints` only")

    def test_the_first_address_of_an_additional_carrier_is_not_a_good_contact_but_every_other_add_is(self):
        """Sansa H1: `peer add --endpoint onion:...` for a peer that has a working tcp address must not make the fresh onion win the dial order."""
        tcp_book, onion_book = L.open_book(self.d, "tcp"), L.open_book(self.d, "onion")
        self.p.add(self.a, "bee", tep(1), [])
        self.assertIsNotNone(tcp_book.contact(self.a)[0], "a brand new peer: its first address is a good contact, as before")
        self.p.add(self.a, "bee", oep(1), [])
        self.assertEqual(onion_book.contact(self.a), (None, False), "a first address of another carrier proves nothing")
        self.assertEqual(onion_book.ordered(self.a), [oep(1)["addr"]], "but it is known")
        self.assertIsNotNone(tcp_book.contact(self.a)[0])
        self.p.add(self.a, "bee", oep(2), [])
        self.assertIsNotNone(onion_book.contact(self.a)[0], "replacing an address of a carrier the peer already has is an explicit move: first and good")
        self.assertEqual(onion_book.ordered(self.a)[0], oep(2)["addr"])
        self.p.add(self.a, "bee", tep(2), [])
        self.assertEqual(tcp_book.ordered(self.a)[0], tep(2)["addr"])

    def test_a_carrier_the_record_already_lists_or_the_book_already_holds_is_not_a_new_carrier(self):
        tcp_book, onion_book = L.open_book(self.d, "tcp"), L.open_book(self.d, "onion")
        self.p.add(self.a, "bee", tep(1), [])
        raw = json.loads(self.p.path.read_text())
        raw["peers"][self.a]["endpoints"].append(oep(1))                       # the record lists an onion endpoint, the onion book has nothing (a hand edit, a lost book)
        self.p.path.write_text(json.dumps(raw))
        self.assertEqual(onion_book.count(self.a), 0)
        self.p.add(self.a, "bee", oep(2), [])
        self.assertIsNotNone(onion_book.contact(self.a)[0], "the carrier was already listed: this is a move, first and good")
        b = Identity.generate("b").id
        self.p.add(b, "bee2", tep(3), [])
        onion_book.seed(b, oep(3)["addr"])                                    # an address the book holds (an adopted announcement) although the record has no onion endpoint
        onion_book.adopt(b, oep(3)["addr"], ts=1)
        self.p.add(b, "bee2", oep(4), [])
        self.assertEqual(onion_book.ordered(b)[0], oep(4)["addr"], "the book already had an address of this carrier: not the first one: first and good")

    def test_the_order_of_the_carriers_stays_tcp_first_after_an_onion_address_is_added(self):
        from sigilnet.tests.test_m1b import Clock, StubDialer
        clk = Clock(5000.0)
        tcp_book, onion_book = L.open_book(self.d, "tcp", clock=clk), L.open_book(self.d, "onion", clock=clk)
        self.p.add(self.a, "bee", tep(1), [])
        clk.t = 5100.0
        tcp_book.note_ok(self.a, tep(1)["addr"])
        self.p.add(self.a, "bee", oep(1), [])
        md = L.MultiDialer({"tcp": StubDialer("tcp", tcp_book, clk), "onion": StubDialer("onion", onion_book, clk)}, clock=clk)
        rec = self.p.all()[self.a]
        self.assertEqual([e["type"] for e in rec["endpoints"]], ["onion", "tcp"], "the record lists the new endpoint first")
        self.assertEqual(md._order(rec), ["tcp", "onion"], "the dial order follows the last good contact: tcp")

    def test_an_endpoint_of_a_type_the_peer_already_has_replaces_that_one_only(self):
        self.p.add(self.a, "bee", tep(1), [])
        self.p.add(self.a, "bee", oep(1), [])
        self.p.add(self.a, "bee", tep(2), [])
        self.assertEqual(self.p.all()[self.a]["endpoints"], [tep(2), oep(1)])

    def test_no_endpoint_in_an_add_leaves_the_endpoints_alone_and_a_new_peer_has_none(self):
        self.p.add(self.a, "bee", tep(1), [])
        self.p.add(self.a, "renamed", None, ["2" * 32])
        rec = self.p.all()[self.a]
        self.assertEqual((rec["name"], rec["endpoints"], rec["threads"]), ("renamed", [tep(1)], ["2" * 32]))
        b = Identity.generate("b").id
        self.p.add(b, "dialsus", None, [])
        self.assertEqual((self.p.all()[b]["endpoints"], self.p.all()[b]["endpoint"]), ([], None))

    def test_one_endpoint_per_type_and_a_bounded_number_of_types(self):
        raw = {"peers": {self.a: {"name": "x", "endpoints": [tep(1), tep(2), oep(1)] + [{"type": f"t{i}", "addr": "z"} for i in range(20)], "threads": []}}}
        self.p.path.write_text(json.dumps(raw))
        self.assertEqual(N.PeerBook._raw_endpoints(raw["peers"][self.a]).__len__(), N.MAX_ENDPOINTS)
        self.assertEqual([e["type"] for e in N.PeerBook._raw_endpoints(raw["peers"][self.a])][:2], ["tcp", "onion"], "the first endpoint of a type wins")

    def test_a_type_this_process_does_not_know_is_left_out_of_the_view_but_never_lost_from_the_file(self):
        """Sansa (a): a node that only carries tcp keeps a peer that also has an address of a type it cannot load, and an edit of the record does not delete that address."""
        raw = {"peers": {self.a: {"name": "x", "endpoints": [tep(1), {"type": "xyz", "addr": "future-carrier"}], "threads": []}}}
        self.p.path.write_text(json.dumps(raw))
        self.assertEqual(self.p.all()[self.a]["endpoints"], [tep(1)])
        self.p.invite(self.a, ["3" * 32])
        self.p.add(self.a, "x", oep(2), [])
        self.assertEqual(self.raw()[self.a]["endpoints"], [oep(2), tep(1), {"type": "xyz", "addr": "future-carrier"}])
        self.assertEqual(self.p.all()[self.a]["endpoints"], [oep(2), tep(1)])

    def test_a_peer_whose_only_endpoint_is_of_an_unknown_type_is_kept_with_no_endpoint(self):
        self.p.path.write_text(json.dumps({"peers": {self.a: {"name": "x", "endpoints": [{"type": "xyz", "addr": "f"}], "threads": []}}}))
        self.assertEqual(self.p.all()[self.a]["endpoints"], [])
        self.assertEqual(endpoints_of(self.p.all()[self.a]), [])

    def test_the_old_single_endpoint_file_loads_the_same_twice_and_is_rewritten_as_endpoints(self):
        """Sansa (h): migration, not rollback safety. A peers.json of the pre-M1a shape reads as a list of one; reading changes nothing; the next edit of THAT record rewrites it."""
        b = Identity.generate("b").id
        old = {"peers": {self.a: {"name": "sansa", "endpoint": tep(1), "threads": ["1" * 32]}, b: {"name": "obs", "endpoint": None, "threads": []}}}
        self.p.path.write_text(json.dumps(old))
        first = self.p.all()
        self.assertEqual(first[self.a]["endpoints"], [tep(1)])
        self.assertEqual(first[b]["endpoints"], [])
        self.assertEqual(self.p.all(), first)
        self.assertEqual(json.loads(self.p.path.read_text()), old, "reading never rewrites the file")
        self.p.invite(b, ["4" * 32])                                    # edits the OTHER record: the legacy one is kept as it was
        self.assertEqual(self.raw()[self.a], old["peers"][self.a])
        self.p.add(self.a, "sansa", oep(1), ["1" * 32])
        self.assertEqual(self.raw()[self.a]["endpoints"], [oep(1), tep(1)])
        self.assertNotIn("endpoint", self.raw()[self.a])

    def test_remove_drops_the_peer_from_every_carriers_locator_book(self):
        self.p.add(self.a, "bee", tep(1), [])
        self.p.add(self.a, "bee", oep(1), [])
        for t in ("tcp", "onion"):
            self.assertEqual(L.open_book(self.d, t).count(self.a), 1, t)
        self.assertTrue(self.p.remove(self.a))
        for t in ("tcp", "onion"):
            self.assertEqual(L.open_book(self.d, t).count(self.a), 0, t)

    def test_the_helpers_read_a_record_with_one_old_style_endpoint_key_too(self):
        self.assertEqual(endpoints_of({"endpoint": tep(1)}), [tep(1)])
        self.assertEqual(endpoints_of({"endpoint": None}), [])
        self.assertEqual(endpoints_of({"endpoints": [tep(1), "junk", oep(1)]}), [tep(1), oep(1)])
        self.assertEqual(endpoints_of(None), [])
        self.assertIsNone(endpoint_of({"endpoints": [tep(1)]}, "onion"))


class Readers(unittest.TestCase):
    """Node._plan, LocatorService._due and PeerDialer with a peer that holds two carriers' endpoints, one, or none."""

    def setUp(self):
        self.r = Rig("fake")
        self.addCleanup(self.r.close)
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.aid, self.bid = self.r.ids["a"].id, self.r.ids["b"].id

    def test_plan_includes_a_peer_with_an_address_of_this_carrier_and_one_with_both(self):
        self.assertIn(self.bid, self.a.node._plan())
        self.a.peers.add(self.bid, "b", oep(1), [])                          # ADDS an onion endpoint beside the fake one
        self.assertEqual(len(endpoints_of(self.a.peers.all()[self.bid])), 2)
        self.assertIn(self.bid, self.a.node._plan())

    def test_plan_skips_a_peer_with_no_address_at_all_and_plans_one_the_book_holds_an_address_for(self):
        other = Identity.generate("o").id
        self.a.peers.add(other, "dialsus", None, [])
        self.assertNotIn(other, self.a.node._plan(), "no endpoint and no book address: it dials us")
        self.a.book.seed(other, self.a.book.ordered(self.bid)[0])
        self.assertIn(other, self.a.node._plan(), "the locator book holds an address for it")

    def test_a_peer_that_dials_us_is_still_served(self):
        other = Identity.generate("o").id
        self.a.peers.add(other, "dialsus", None, [])
        self.assertIn(other, self.a.peers.all())                              # (noderun hands peers.all() to the sync server)

    def test_dialer_seeds_from_the_endpoint_of_ITS_carrier_type_and_not_the_primary(self):
        d = L.PeerDialer(self.a.carrier, L.open_book(self.a.home / "elsewhere", "fake"), request_timeout=5.0, connect_timeout=3.0)
        fake_ep = self.a.peers.all()[self.bid]["endpoints"][0]
        rec = {"agent": self.bid, "endpoints": [oep(1), fake_ep]}              # the onion one is the primary; this node runs the fake carrier
        self.assertEqual(d.addresses(rec), [fake_ep["addr"]])
        self.assertEqual(d.book.ordered(self.bid), [fake_ep["addr"]], "seeded once")

    def test_dialer_with_endpoints_of_other_types_only_lets_the_carrier_refuse_it(self):
        d = L.PeerDialer(self.a.carrier, L.open_book(self.a.home / "elsewhere2", "fake"), request_timeout=5.0, connect_timeout=3.0)
        with mock.patch.object(self.a.carrier, "dial", side_effect=CarrierError("not mine", retry=False)) as dial:
            with self.assertRaises(CarrierError):
                d({"agent": self.bid, "endpoints": [oep(1)]})
        self.assertEqual(dial.call_args[0][0], oep(1))
        with self.assertRaises(CarrierError) as cm:
            d({"agent": self.bid, "endpoints": []})
        self.assertIn("no address", str(cm.exception))

    def test_due_announces_to_a_peer_that_has_this_carriers_endpoint_among_others_and_not_to_an_onion_only_one(self):
        onion_only = Identity.generate("oo").id
        self.b.peers.add(onion_only, "oo", oep(2), [])
        self.b.peers.add(self.aid, "a", oep(3), [])                           # beside the fake endpoint it already has
        due = [a for a, _ in self.b.svc._due()]
        self.assertNotIn(onion_only, due)
        self.assertIn(self.aid, due)

    def test_due_also_announces_to_a_peer_with_no_endpoint_when_the_book_holds_an_address_of_this_type(self):
        other = Identity.generate("o").id
        self.b.peers.add(other, "o", None, [])
        self.assertNotIn(other, [a for a, _ in self.b.svc._due()])
        self.b.book.seed(other, self.b.book.ordered(self.aid)[0])
        with mock.patch.object(self.b.svc, "_our_address", return_value="b.fake:9"):
            self.assertIn(other, [a for a, _ in self.b.svc._due()])

    def test_two_books_of_two_carrier_types_are_edited_at_once_without_losing_either(self):
        """Sansa (i): one file and one lock per carrier type; two carriers' services writing at the same time lose nothing."""
        d = Path(tempfile.mkdtemp())
        books = [L.open_book(d, "tcp"), L.open_book(d, "onion")]
        agents = [Identity.generate(f"p{i}").id for i in range(6)]
        errs = []

        def work(book, mk):
            try:
                for ag in agents:
                    book.seed(ag, mk(agents.index(ag)))
                    book.note_ok(ag, mk(agents.index(ag)))
            except Exception as e:                                         # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=work, args=(books[0], lambda i: tep(i)["addr"])), threading.Thread(target=work, args=(books[1], lambda i: oep(i)["addr"]))]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        for b in books:
            self.assertEqual(sorted(b.agents()), sorted(agents))
        self.assertIsNot(books[0]._clean, books[1]._clean)


class TwoCarrierCli(TcpHomes):
    """`peer list/move/rm/add` for a peer that holds a tcp AND an onion endpoint (the home runs the tcp carrier)."""

    def setUp(self):
        super().setUp()
        self.a.peers.add(self.bid, "b", oep(5), [self.r.tid] if hasattr(self.r, "tid") else [])      # ADDS the onion endpoint (it becomes the primary)

    def test_list_shows_every_address_with_its_carrier(self):
        rc, out, err = self.cli("a", "peer", "list")
        self.assertEqual(rc, 0, err)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 2, out)
        self.assertIn("onion " + oep(5)["addr"], lines[0])
        self.assertIn("also tcp " + self.a.book.ordered(self.bid)[0], lines[1])

    def test_move_ip_picks_the_tcp_address_of_a_two_carrier_peer_and_keeps_the_onion_endpoint(self):
        old = self.a.book.ordered(self.bid)[0]
        ip_port, _, fp = old.partition("#")
        port = ip_port.split(":")[1]
        new = self.r.move("b", "127.0.0.4")
        self.r.tick()
        rc, out, err = self.cli("a", "peer", "move", "b", "--ip", "127.0.0.4")
        self.assertEqual(rc, 0, err + out)
        eps = {e["type"]: e["addr"] for e in self.peers()[self.bid]["endpoints"]}
        self.assertEqual(eps["tcp"], new)
        self.assertEqual(eps["onion"], oep(5)["addr"])

    def test_a_peer_with_no_endpoint_but_a_book_address_is_listed_and_its_credential_dropped_by_rm(self):
        """Sansa R1: `_plan` and `_due` use the locator book for a peer with no endpoint; `peer list` and `peer rm` must agree with them."""
        other = Identity.generate("o").id
        self.a.peers.add(other, "bookonly", None, [])
        addr = "127.0.0.9:47800#" + "ab" * 32
        self.a.book.seed(other, addr)
        rc, out, err = self.cli("a", "peer", "list")
        self.assertEqual(rc, 0, err)
        line = [l for l in out.splitlines() if other in l][0]
        self.assertIn("tcp " + addr, line)
        self.assertNotIn("dials us", line)
        dropped = []
        carrier = mock.Mock(type="tcp")
        carrier.drop_credential.side_effect = lambda ep, agent=None: dropped.append((ep["addr"], agent))
        with mock.patch("sigilnet.noderun.carrier_for", side_effect=lambda h, c, t, offline=False: carrier if t == "tcp" else (_ for _ in ()).throw(ValueError("not run"))):
            rc, out, err = self.cli("a", "peer", "rm", other)
        self.assertEqual(dropped, [(addr, other)])

    def test_an_unreadable_locators_directory_does_not_stop_list_or_rm_of_a_peer_with_no_endpoint(self):
        """Sansa R3: the fallback must not fail on a locators/ directory it cannot list."""
        import os
        other = Identity.generate("o3").id
        self.a.peers.add(other, "noend", None, [])
        d = self.a.home / "locators"
        os.chmod(d, 0)
        self.addCleanup(os.chmod, d, 0o700)
        if os.access(d, os.R_OK):
            self.skipTest("this user can read a mode-0 directory (root): the case cannot be made")
        rc, out, err = self.cli("a", "peer", "list")
        self.assertEqual(rc, 0, err)
        self.assertIn("(no endpoint: it dials us)", out)
        rc, out, err = self.cli("a", "peer", "rm", other)
        self.assertEqual(rc, 0, err)
        self.assertNotIn(other, self.a.peers.all())

    def test_a_stale_endpoint_key_in_a_record_that_has_endpoints_is_ignored(self):
        other = Identity.generate("o2").id
        raw = json.loads((self.a.home / "peers.json").read_text())
        raw["peers"][other] = {"name": "stale", "endpoints": [], "endpoint": tep(3), "threads": []}
        (self.a.home / "peers.json").write_text(json.dumps(raw))
        self.assertEqual(self.a.peers.all()[other]["endpoints"], [])
        self.assertIsNone(self.a.peers.all()[other]["endpoint"])

    def test_move_ip_for_a_peer_with_no_tcp_address_is_refused(self):
        other = Identity.generate("o").id
        self.a.peers.add(other, "oo", oep(6), [])
        rc, out, err = self.cli("a", "peer", "move", "oo", "--ip", "127.0.0.4")
        self.assertNotEqual(rc, 0)
        self.assertIn("--ip is for a tcp peer", err)

    def test_rm_drops_the_credentials_of_the_carrier_this_node_runs_and_the_peer_with_both_endpoints(self):
        dropped = []
        carrier = mock.Mock(type="tcp")
        carrier.drop_credential.side_effect = lambda ep, agent=None: dropped.append((ep["type"], ep["addr"], agent))
        with mock.patch("sigilnet.noderun.carrier_for", side_effect=lambda h, c, t, offline=False: carrier if t == "tcp" else (_ for _ in ()).throw(ValueError("not run"))):
            rc, out, err = self.cli("a", "peer", "rm", self.bid)
        self.assertEqual(rc, 0, err)
        self.assertIn("removed", out)
        self.assertTrue(dropped and all(t == "tcp" for t, _, _ in dropped), dropped)       # (the onion address is not a credential this carrier holds)
        self.assertNotIn(self.bid, self.a.peers.all())
        self.assertEqual(self.a.book.count(self.bid), 0)

    def test_peer_add_of_the_other_carriers_endpoint_to_an_existing_peer_keeps_the_first(self):
        rc, out, err = self.cli("a", "peer", "add", "bee", self.bid, "--endpoint", "onion:" + oep(7)["addr"])
        self.assertEqual(rc, 0, err + out)
        eps = self.peers()[self.bid]["endpoints"]
        self.assertEqual([e["type"] for e in eps], ["onion", "tcp"])
        self.assertEqual(eps[0]["addr"], oep(7)["addr"])


class NodeRunReaders(unittest.TestCase):
    def test_tcp_peer_ips_and_the_credential_index_read_every_endpoint_not_only_the_primary(self):
        from sigilnet import noderun
        d = Path(tempfile.mkdtemp())
        book = N.PeerBook(d / "peers.json")
        a, b = Identity.generate("a").id, Identity.generate("b").id
        book.add(a, "two", tep(1), [])
        book.add(a, "two", oep(1), [])                                      # the onion one is the primary now
        book.add(b, "tcp-only", tep(2), [])
        book.add(Identity.generate("c").id, "dialsus", None, [])
        self.assertEqual(sorted(noderun._tcp_peer_ips(d)), sorted([tep(1)["addr"].split(":")[0], tep(2)["addr"].split(":")[0]]))
        self.assertEqual(sorted(noderun._credential_pairs(book, "tcp")), sorted([(a, tep(1)["addr"]), (b, tep(2)["addr"])]))
        self.assertEqual(noderun._credential_pairs(book, "onion"), [(a, oep(1)["addr"])])


class Guard(unittest.TestCase):
    """M1a is only worth anything if no reader goes around the helpers: a peer record's endpoint is read through `endpoints_of` / `endpoint_of` (or `PeerBook`, which owns the file)."""

    PATTERN = re.compile(r"""\b(rec|r|p|peer|row)\.get\(\s*["']endpoint["']\s*\)|\b(rec|r|p|peer|row)\[\s*["']endpoint["']\s*\]""")

    def test_no_module_reads_the_single_endpoint_of_a_peer_record_directly(self):
        bad = []
        for name in ("locators.py", "cli.py", "noderun.py", "ping.py", "blobworker.py", "daemon.py", "doors.py"):          # (capsule.py's `r`/`rec` are JOIN records with their one endpoint: M2)
            for i, line in enumerate((SRC / name).read_text().splitlines(), 1):
                m = self.PATTERN.search(line)
                if m and not line.lstrip().startswith("#"):
                    bad.append(f"{name}:{i}: {line.strip()[:100]}")
        self.assertEqual(bad, [], "read a peer's endpoints through carrier.endpoints_of / endpoint_of")


if __name__ == "__main__":
    unittest.main()
