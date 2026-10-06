"""The locator book at the carrier level: credentials by node id (TCP and Tor), the migration helper, the rules for an announced address, `bind: auto`, and the whole address-change
story over REAL TcpCarriers on loopback aliases."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import carrier as C
from sigilnet import tcplink as TL
from sigilnet.carrier import Carrier, CarrierError, Secret
from sigilnet.keys import Identity
from sigilnet.tests.locrig import Rig
from sigilnet.tests.test_tcplink import free_base

AG = Identity.generate("p").id
AG2 = Identity.generate("q").id
FP = "ab" * 32
FP2 = "cd" * 32


def tcp(**kw):
    tmp = Path(tempfile.mkdtemp())
    kw.setdefault("bind", "127.0.0.1")
    return TL.TcpCarrier(tmp / "tcp", port_base=free_base(), **kw)


def ep(ip="10.0.0.5", port=47700, fp=FP):
    return {"type": "tcp", "addr": f"{ip}:{port}#{fp}"}


class CredentialsByNodeId(unittest.TestCase):
    def setUp(self):
        self.c = tcp()
        self.secret, self.pub = self.c.new_credential()

    def held(self):
        return json.loads(self.c.held_file.read_text())

    def test_without_an_agent_nothing_changes(self):
        self.c.use_credential(ep(), self.secret)
        self.assertEqual(list(self.held()), [ep()["addr"]])

    def test_with_an_agent_the_key_is_held_under_the_address_and_under_the_node_id(self):
        self.c.use_credential(ep(), self.secret, agent=AG)
        h = self.held()
        self.assertEqual(set(h), {ep()["addr"], "agent:" + AG})
        self.assertEqual(h["agent:" + AG], h[ep()["addr"]])

    def test_a_bad_agent_id_is_refused_and_nothing_is_written(self):
        for bad in ("", "nope", AG + "x", 5, b"x"):
            with self.assertRaises(ValueError):
                self.c.use_credential(ep(), self.secret, agent=bad)
        self.assertFalse(self.c.held_file.exists())

    def test_the_file_is_private(self):
        self.c.use_credential(ep(), self.secret, agent=AG)
        self.assertEqual(stat.S_IMODE(os.stat(self.c.held_file).st_mode), 0o600)

    def test_drop_by_address_keeps_the_node_id_entry_and_drop_with_agent_removes_both(self):
        self.c.use_credential(ep(), self.secret, agent=AG)
        self.assertTrue(self.c.drop_credential(ep()))
        self.assertEqual(list(self.held()), ["agent:" + AG])
        self.c.use_credential(ep(), self.secret, agent=AG)
        self.assertTrue(self.c.drop_credential(ep(), agent=AG))
        self.assertEqual(self.held(), {})
        self.assertFalse(self.c.drop_credential(ep(), agent=AG))

    def test_dropping_only_the_node_id_entry_counts(self):
        self.c.use_credential(ep(), self.secret, agent=AG)
        self.c.drop_credential(ep())
        self.assertTrue(self.c.drop_credential(ep("10.0.0.6"), agent=AG))
        self.assertEqual(self.held(), {})

    def test_two_peers_two_keys(self):
        s2, _ = self.c.new_credential()
        self.c.use_credential(ep(), self.secret, agent=AG)
        self.c.use_credential(ep("10.0.0.6"), s2, agent=AG2)
        h = self.held()
        self.assertNotEqual(h["agent:" + AG], h["agent:" + AG2])


class IndexCredentials(unittest.TestCase):
    def setUp(self):
        self.c = tcp()
        self.s1, _ = self.c.new_credential()
        self.s2, _ = self.c.new_credential()

    def held(self):
        return json.loads(self.c.held_file.read_text())

    def test_an_address_entry_gets_a_node_id_entry_and_nothing_is_deleted(self):
        self.c.use_credential(ep(), self.s1)
        self.c.use_credential(ep("10.0.0.9", fp=FP2), self.s2)                  # belongs to no peer
        self.assertEqual(self.c.index_credentials([(AG, ep()["addr"])]), 1)
        h = self.held()
        self.assertEqual(set(h), {ep()["addr"], ep("10.0.0.9", fp=FP2)["addr"], "agent:" + AG})
        self.assertEqual(h["agent:" + AG], h[ep()["addr"]])

    def test_it_is_idempotent(self):
        self.c.use_credential(ep(), self.s1)
        self.assertEqual(self.c.index_credentials([(AG, ep()["addr"])]), 1)
        before = self.c.held_file.read_bytes()
        self.assertEqual(self.c.index_credentials([(AG, ep()["addr"])]), 0)
        self.assertEqual(self.c.held_file.read_bytes(), before)

    def test_an_existing_node_id_entry_is_never_overwritten(self):
        self.c.use_credential(ep(), self.s1, agent=AG)
        self.c.use_credential(ep("10.0.0.7"), self.s2)
        self.assertEqual(self.c.index_credentials([(AG, ep("10.0.0.7")["addr"])]), 0)
        self.assertEqual(self.held()["agent:" + AG]["key"], self.held()[ep()["addr"]]["key"])

    def test_junk_pairs_are_skipped(self):
        self.c.use_credential(ep(), self.s1)
        self.assertEqual(self.c.index_credentials([("bad", ep()["addr"]), (AG, "nonsense"), (AG, None), (None, None), (AG2, ep("1.2.3.4")["addr"])]), 0)
        self.assertEqual(list(self.held()), [ep()["addr"]])

    def test_nothing_held_is_fine(self):
        self.assertEqual(self.c.index_credentials([(AG, ep()["addr"])]), 0)
        self.assertFalse(self.c.held_file.exists())

    def test_a_crash_while_writing_leaves_the_old_file(self):
        self.c.use_credential(ep(), self.s1)
        before = self.c.held_file.read_bytes()
        with mock.patch.object(TL, "_write_private", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.c.index_credentials([(AG, ep()["addr"])])
        self.assertEqual(self.c.held_file.read_bytes(), before)
        self.assertEqual(self.c.index_credentials([(AG, ep()["addr"])]), 1)      # and the retry works

    def test_a_damaged_file_is_reported_not_overwritten(self):
        self.c.held_file.write_text("{broken")
        with self.assertRaises(CarrierError):
            self.c.index_credentials([(AG, ep()["addr"])])
        self.assertEqual(self.c.held_file.read_text(), "{broken")


class AnnouncedAddressRules(unittest.TestCase):
    """Sansa's Q4 list: private only (unless allow_public), no loopback unless we are on loopback, no link-local / multicast / unspecified, not our own door, no port below 1024."""

    def check(self, c, ip, port=47700, fp=FP):
        return c.locator_problem(f"{ip}:{port}#{fp}")

    def test_a_private_address_is_fine(self):
        c = tcp(bind="127.0.0.1")
        for ip in ("10.1.2.3", "172.17.0.4", "192.168.1.9"):
            self.assertIsNone(self.check(c, ip), ip)

    def test_public_addresses_are_allowed_M3(self):
        for ip in ("8.8.8.8", "203.0.113.9", "100.64.1.1", "198.51.100.7"):                 # (public, documentation, carrier-grade NAT: all fine)
            self.assertIsNone(self.check(tcp(), ip), ip)
        self.assertIsNone(self.check(tcp(allow_public=True, advertise="127.0.0.1"), "8.8.8.8"), "allow_public is accepted and ignored")

    def test_the_unsafe_ranges_and_every_spelling_that_is_not_a_plain_dotted_quad_are_refused(self):
        """Sansa A3: what a PEER may make our node dial. Refused: this-network, link-local (metadata), multicast, reserved/broadcast, loopback unless we are on loopback, our own door, port 0 and
        below 1024; literal dotted-quad IPv4 only: no hostname, no octal/hex/short/IPv6 spelling."""
        c = tcp(bind="172.17.0.3", advertise="172.17.0.3")
        for ip in ("0.0.0.0", "0.5.5.5", "169.254.169.254", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "127.0.0.1"):
            self.assertIsNotNone(self.check(c, ip), ip)
        for addr in ("010.0.0.1:47700#" + FP, "127.1:47700#" + FP, "0x7f.0.0.1:47700#" + FP, "2130706433:47700#" + FP, "::ffff:127.0.0.1:47700#" + FP, "[::1]:47700#" + FP, "localhost:47700#" + FP,
                     "example.com:47700#" + FP, "8.8.8.8:0#" + FP, "8.8.8.8:47700", "8.8.8.8:47700#" + FP[:-1], "8.8.8.8.8:47700#" + FP, "8.8.8:47700#" + FP, "256.1.1.1:47700#" + FP, "1.2.3.4:70000#" + FP):
            self.assertIsNotNone(c.locator_problem(addr), addr)
        self.assertIsNotNone(self.check(c, "8.8.8.8", port=80))
        self.assertIsNone(self.check(c, "8.8.8.8", port=1024))

    def test_loopback_only_for_a_node_that_is_on_loopback(self):
        self.assertIsNone(self.check(tcp(bind="127.0.0.1"), "127.0.0.3"))
        c = tcp(bind="127.0.0.1")
        c.bind = "172.17.0.3"                                        # (what a node bound to a LAN address looks like)
        self.assertEqual(self.check(c, "127.0.0.3"), "a loopback address (this node is not on loopback)")

    def test_link_local_multicast_unspecified_are_refused(self):
        c = tcp()
        self.assertEqual(self.check(c, "169.254.1.1"), "a link-local address")
        self.assertEqual(self.check(c, "224.0.0.1"), "an unspecified or multicast address")
        self.assertEqual(self.check(c, "0.0.0.0"), "an unspecified or multicast address")
        for ip in ("255.255.255.255", "240.0.0.1", "0.1.2.3"):
            self.assertEqual(self.check(c, ip), "a reserved address", ip)

    def test_ports_below_1024_are_refused(self):
        c = tcp()
        self.assertEqual(self.check(c, "10.0.0.5", port=22), "a port below 1024")
        self.assertEqual(self.check(c, "10.0.0.5", port=1023), "a port below 1024")
        self.assertIsNone(self.check(c, "10.0.0.5", port=1024))

    def test_one_of_our_own_doors_is_refused_but_the_same_ip_on_another_port_is_fine(self):
        c = tcp()
        c.start()
        try:
            _, pub = c.new_credential()
            c.open_door("peer-x", "peer", credential=pub, agent=AG)
            port = c.door_endpoint("peer-x")["addr"].split("#")[0].split(":")[1]
            self.assertEqual(c.locator_problem(f"127.0.0.1:{port}#{FP}"), "that is one of our own doors")
            self.assertIsNone(c.locator_problem(f"127.0.0.1:{int(port) + 100}#{FP}"))
        finally:
            c.stop()

    def test_garbage_is_a_reason_not_an_exception(self):
        c = tcp()
        for bad in ("", "x", "1.2.3.4:5", "1.2.3.4:5#zz", "1.2.3.4:99999#" + FP, "01.2.3.4:5000#" + FP):
            self.assertIsInstance(c.locator_problem(bad), str, bad)


def fake_ifs(ips):
    return lambda: list(ips)


class ResolveBind(unittest.TestCase):
    def test_an_explicit_address_is_returned_untouched(self):
        self.assertEqual(TL.resolve_bind("10.9.9.9", interfaces=fake_ifs([])), "10.9.9.9")
        self.assertEqual(TL.resolve_bind("127.0.0.2", interfaces=fake_ifs(["10.0.0.1"])), "127.0.0.2")

    def test_auto_picks_the_first_private_non_loopback_address(self):
        self.assertEqual(TL.resolve_bind("auto", interfaces=fake_ifs(["127.0.0.1", "172.17.0.3"])), "172.17.0.3")
        self.assertEqual(TL.resolve_bind("auto", interfaces=fake_ifs(["127.0.0.1", "10.0.0.2", "192.168.0.5"])), "10.0.0.2")

    def test_auto_prefers_the_address_the_route_to_a_peer_uses(self):
        ifs = fake_ifs(["10.0.0.2", "192.168.0.5"])
        route = lambda dest: {"192.168.0.77": "192.168.0.5", "10.0.0.77": "10.0.0.2"}.get(dest)
        self.assertEqual(TL.resolve_bind("auto", hints=["192.168.0.77"], interfaces=ifs, route=route), "192.168.0.5")
        self.assertEqual(TL.resolve_bind("auto", hints=["8.8.8.8", "10.0.0.77"], interfaces=ifs, route=route), "10.0.0.2")
        self.assertEqual(TL.resolve_bind("auto", hints=["8.8.8.8"], interfaces=ifs, route=route), "10.0.0.2")      # no route known: the first

    def test_a_route_that_leads_to_an_address_we_would_not_use_is_ignored(self):
        ifs = fake_ifs(["10.0.0.2"])
        self.assertEqual(TL.resolve_bind("auto", hints=["1.1.1.1"], interfaces=ifs, route=lambda d: "203.0.113.9"), "10.0.0.2")

    def test_loopback_link_local_unspecified_multicast_and_reserved_are_never_chosen(self):
        for ifs in (["127.0.0.1"], ["169.254.3.3"], ["0.0.0.0"], ["224.0.0.5"], ["240.0.0.9"], [], ["127.0.0.1", "169.254.1.1", "0.0.0.0"]):
            with self.assertRaises(ValueError) as cm:
                TL.resolve_bind("auto", interfaces=fake_ifs(ifs))
            self.assertIn("auto", str(cm.exception))

    def test_public_addresses_are_candidates_and_allow_public_is_ignored_M3(self):
        self.assertEqual(TL.resolve_bind("auto", interfaces=fake_ifs(["127.0.0.1", "8.8.4.4"])), "8.8.4.4")
        self.assertEqual(TL.resolve_bind("auto", allow_public=True, interfaces=fake_ifs(["127.0.0.1", "8.8.4.4"])), "8.8.4.4")
        self.assertEqual(TL.resolve_bind("auto", allow_public=False, interfaces=fake_ifs(["8.8.4.4", "10.0.0.2"])), "8.8.4.4", "the kernel's first address, as with private ones")
        self.assertEqual(TL.resolve_bind("auto", interfaces=fake_ifs(["8.8.4.4", "10.0.0.2"]), hints=["10.0.0.9"], route=lambda h: "10.0.0.2"), "10.0.0.2", "the route to a peer still decides")

    def test_junk_in_the_interface_list_is_skipped(self):
        self.assertEqual(TL.resolve_bind("auto", interfaces=fake_ifs(["not an ip", "", "10.0.0.2", "10.0.0.2"])), "10.0.0.2")

    def test_the_carrier_itself_still_refuses_the_word_auto(self):
        with self.assertRaises(ValueError):
            tcp(bind="auto")

    def test_the_real_interface_list_is_a_list_of_dotted_quads(self):
        ips = TL._interfaces()
        self.assertIsInstance(ips, list)
        for ip in ips:
            self.assertRegex(ip, r"^\d+\.\d+\.\d+\.\d+$")
        if os.path.exists("/proc/net/dev"):
            self.assertIn("127.0.0.1", ips)

    def test_route_ip_gives_the_address_of_the_interface_toward_a_destination(self):
        self.assertEqual(TL._route_ip("127.0.0.1"), "127.0.0.1")
        self.assertIsNone(TL._route_ip("not an address"))


class RetryWaits(unittest.TestCase):
    def test_each_carrier_says_how_long_to_wait_between_cycles(self):
        from sigilnet.torlink import TorNode
        self.assertEqual(TL.TcpCarrier.retry_wait, 10.0)
        self.assertEqual(TorNode.retry_wait, 45.0)
        self.assertEqual(Carrier.retry_wait, 30.0)
        self.assertTrue(TorNode.retry_wait > TL.TcpCarrier.retry_wait)           # a rendezvous circuit is slow: waiting less would only stack attempts


ONION1 = "a" * 56 + ".onion"
ONION2 = "b" * 56 + ".onion"
KEY = "A" * 52


class TorRebind(unittest.TestCase):
    def setUp(self):
        from sigilnet.torlink import TorNode
        self.t = TorNode(Path(tempfile.mkdtemp()) / "tor", local_port=None, virtual_port=47200, bridge_lines=[], offline=True, service_port_base=47210)

    def ep(self, onion):
        return {"type": "onion", "addr": f"{onion}:47200"}

    def test_the_key_we_hold_for_the_old_onion_is_installed_for_the_new_one(self):
        self.t.add_client_auth(ONION1, KEY)
        self.assertTrue(self.t.rebind_credential(AG, [self.ep(ONION1)], self.ep(ONION2)))
        self.assertEqual(self.t._held_key(ONION2), KEY)
        self.assertEqual(self.t._held_key(ONION1), KEY)                          # the old one stays (nothing is deleted)

    def test_a_key_already_held_for_the_new_onion_is_not_replaced(self):
        self.t.add_client_auth(ONION1, KEY)
        self.t.add_client_auth(ONION2, "B" * 52)
        self.assertTrue(self.t.rebind_credential(AG, [self.ep(ONION1)], self.ep(ONION2)))
        self.assertEqual(self.t._held_key(ONION2), "B" * 52)

    def test_no_key_to_copy_is_reported(self):
        self.assertFalse(self.t.rebind_credential(AG, [self.ep(ONION1)], self.ep(ONION2)))
        self.assertIsNone(self.t._held_key(ONION2))

    def test_the_first_held_key_of_the_list_is_the_one_used_and_junk_entries_are_skipped(self):
        self.t.add_client_auth(ONION1, KEY)
        self.assertTrue(self.t.rebind_credential(AG, [{"type": "onion", "addr": "junk"}, self.ep(ONION1)], self.ep(ONION2)))
        self.assertEqual(self.t._held_key(ONION2), KEY)

    def test_the_agent_keyword_is_accepted_everywhere(self):
        secret, pub = self.t.new_credential()
        self.t.use_credential(self.ep(ONION1), secret, agent=AG)
        self.t.dial(self.ep(ONION1), timeout=1.0, connect_timeout=1.0, agent=AG)
        self.assertTrue(self.t.drop_credential(self.ep(ONION1), agent=AG))

    def test_has_credential_is_about_the_onion_not_the_node_id(self):
        self.assertFalse(self.t.has_credential(self.ep(ONION1), AG))
        self.t.add_client_auth(ONION1, KEY)
        self.assertTrue(self.t.has_credential(self.ep(ONION1), AG))
        self.assertFalse(self.t.has_credential(self.ep(ONION2), AG))
        self.assertFalse(self.t.has_credential({"type": "onion", "addr": "junk"}))

    def test_a_rejected_candidate_onion_leaves_no_copied_key_but_a_held_one_stays(self):
        from sigilnet import locators as L
        from sigilnet.node import PeerBook
        tmp = Path(tempfile.mkdtemp())
        book = L.open_book(tmp, "onion")
        pb = PeerBook(tmp / "peers.json")
        pb.add(AG, "p", self.ep(ONION1), [])
        self.t.add_client_auth(ONION1, KEY)
        me = Identity.generate("me")
        svc = L.LocatorService(me, pb, self.t, book, L.PeerDialer(self.t, book, request_timeout=1.0, connect_timeout=1.0))
        ok, why = svc.verify(AG, self.ep(ONION2)["addr"], 5)
        self.assertFalse(ok)                                         # (offline: nothing answers)
        self.assertIsNone(self.t._held_key(ONION2))                  # the key copied for the candidate was dropped again
        self.assertEqual(self.t._held_key(ONION1), KEY)              # the one for the known onion is untouched
        self.t.add_client_auth(ONION2, "B" * 52)                      # but a key that was ALREADY held for the candidate stays
        ok, why = svc.verify(AG, self.ep(ONION2)["addr"], 6)
        self.assertFalse(ok)
        self.assertEqual(self.t._held_key(ONION2), "B" * 52)

    def test_a_damaged_key_file_is_not_a_key(self):
        self.t.add_client_auth(ONION1, KEY)
        (self.t.auth_in / f"{ONION1[:-6]}.auth_private").write_text("junk\n")
        self.assertIsNone(self.t._held_key(ONION1))
        self.assertFalse(self.t.rebind_credential(AG, [self.ep(ONION1)], self.ep(ONION2)))


class RealTcpAddressChange(unittest.TestCase):
    """The scenario of finding PF-1, automated: two nodes on real TcpCarriers, one of them gets a NEW IP."""

    def setUp(self):
        self.r = Rig("tcp")
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.aid, self.bid = self.r.ids["a"].id, self.r.ids["b"].id

    def tearDown(self):
        self.r.close()

    def test_a_new_ip_is_learned_without_a_human_and_the_posts_catch_up(self):
        self.r.post("a", "one")
        self.r.tick()
        self.assertEqual(self.r.texts("b"), ["one"])
        self.r.service()                                             # first announcements: same addresses, nothing new
        old = self.a.book.ordered(self.bid)
        self.assertEqual(len(old), 1)
        new = self.r.move("b", "127.0.0.4")
        self.assertNotEqual(new, old[0])
        self.assertTrue(new.startswith("127.0.0.4:"))
        self.r.post("b", "two")
        self.r.tick("a")
        self.assertEqual(self.r.texts("a"), ["one"])                 # a cannot reach b any more
        self.r.service("b")                                          # b announces its new address to a (a's address did not change)
        self.r.service("a")                                          # a dials it, b answers a signed ping as itself: adopted
        self.assertEqual(self.a.book.ordered(self.bid)[0], new)
        self.assertEqual(self.a.book.ordered(self.bid)[1], old[0])   # the old one stays as a fallback
        self.r.tick("a")                                             # (no manual reset: the adoption itself ended the backoff)
        self.assertEqual(self.r.texts("a"), ["one", "two"])

    def test_the_credential_found_the_new_address_by_node_id(self):
        new = self.r.move("b", "127.0.0.4")
        held = json.loads(self.a.carrier.held_file.read_text())
        self.assertNotIn(new, held)                                  # nothing is held for the NEW address ...
        self.assertIn("agent:" + self.bid, held)                     # ... only by node id
        self.r.tick()
        ok, why = self.a.svc.verify(self.bid, new, 5)
        self.assertTrue(ok, why)

    def test_a_home_with_only_the_old_address_entry_still_dials(self):
        """Before the migration (or when a held.json was written by older code) only the by-address entry exists: it must keep working."""
        held = json.loads(self.a.carrier.held_file.read_text())
        for k in [k for k in held if k.startswith("agent:")]:
            del held[k]
        self.a.carrier.held_file.write_text(json.dumps(held))
        self.r.post("b", "old style")
        self.r.tick("a")
        self.assertIn("old style", self.r.texts("a"))

    def test_a_home_with_only_the_node_id_entry_dials_a_new_address(self):
        new = self.r.move("b", "127.0.0.4")
        held = json.loads(self.a.carrier.held_file.read_text())
        for k in [k for k in held if not k.startswith("agent:")]:
            del held[k]
        self.a.carrier.held_file.write_text(json.dumps(held))
        self.r.tick()
        ok, why = self.a.svc.verify(self.bid, new, 5)
        self.assertTrue(ok, why)

    def test_when_the_two_entries_differ_the_address_one_dials(self):
        """M0 (DESIGN_multicarrier.md Q4): THIS door's own entry (by address) first, the node-id entry only when the address has none. A peer with two doors holds one key per door, and
        the node-id entry holds only the LAST one stored."""
        new = self.r.move("b", "127.0.0.4")
        self.r.tick()
        held = json.loads(self.a.carrier.held_file.read_text())
        good = held["agent:" + self.bid]
        bad = {"type": "tcp", "key": "0" * 64}
        held[new] = bad                                              # an address entry for the NEW address with a wrong key
        self.a.carrier.held_file.write_text(json.dumps(held))
        ok, why = self.a.svc.verify(self.bid, new, 5)
        self.assertFalse(ok)                                         # the address entry (wrong) was used and refused
        held["agent:" + self.bid] = bad
        held[new] = good                                             # now the other way round
        self.a.carrier.held_file.write_text(json.dumps(held))
        ok, why = self.a.svc.verify(self.bid, new, 6)
        self.assertTrue(ok, why)                                     # the address entry (right) won over a wrong node-id entry
        del held[new]                                                # the address has no entry at all: the node-id entry (right again) is the fallback
        held["agent:" + self.bid] = good
        self.a.carrier.held_file.write_text(json.dumps(held))
        ok, why = self.a.svc.verify(self.bid, new, 7)
        self.assertTrue(ok, why)

    def test_has_credential_looks_under_the_node_id_and_the_address(self):
        c = self.a.carrier
        ep = {"type": "tcp", "addr": "10.5.5.5:47700#" + "ab" * 32}
        self.assertFalse(c.has_credential(ep, AG))
        secret, _ = c.new_credential()
        c.use_credential(ep, secret)
        self.assertTrue(c.has_credential(ep))
        self.assertTrue(c.has_credential(ep, AG))                    # by address
        c.use_credential({"type": "tcp", "addr": "10.6.6.6:47700#" + "ab" * 32}, secret, agent=AG)
        self.assertTrue(c.has_credential({"type": "tcp", "addr": "10.7.7.7:47700#" + "ab" * 32}, AG))      # by node id, whatever the address
        self.assertFalse(c.has_credential({"type": "tcp", "addr": "10.7.7.7:47700#" + "ab" * 32}))
        self.assertFalse(c.has_credential({"type": "tcp", "addr": "nonsense"}, None))
        c.held_file.write_text("{broken")
        self.assertFalse(c.has_credential(ep, AG))                   # a damaged file is "no", not an exception

    def test_a_wrong_door_fingerprint_is_not_adopted(self):
        new = self.r.move("b", "127.0.0.4")
        ip_port, _, fp = new.partition("#")
        self.r.tick()
        before = self.a.book.ordered(self.bid)
        ok, why = self.a.svc.verify(self.bid, f"{ip_port}#{'0' * 64}", 5)
        self.assertFalse(ok)
        self.assertEqual(self.a.book.ordered(self.bid), before)

    def test_a_loopback_announcement_from_a_node_that_is_not_on_loopback_is_refused(self):
        self.a.carrier.bind = "172.17.0.99"
        self.assertTrue(self.a.svc.on_locator(self.bid, "127.0.0.9:47700#" + FP, 5).startswith("refused: a loopback"))

    def test_both_sides_moving_at_once_is_repaired_by_hand_with_the_new_addresses(self):
        self.r.post("a", "one")
        self.r.tick()
        new_b = self.r.move("b", "127.0.0.4")
        new_a = self.r.move("a", "127.0.0.5")
        # nobody can announce to anybody: the human relays the two new addresses (`peer move` = PeerBook.add, which puts the address first)
        self.a.peers.add(self.bid, "b", {"type": "tcp", "addr": new_b}, [])
        self.b.peers.add(self.aid, "a", {"type": "tcp", "addr": new_a}, [])
        self.r.post("b", "two")
        for s in (self.a, self.b):
            s.node.down.clear()
            for j in s.node.jobs.values():
                j["next"] = 0
        self.r.tick()
        self.assertEqual(self.r.texts("a"), ["one", "two"])

    def test_the_door_keys_and_credentials_survive_a_restart_on_another_ip(self):
        before = json.loads((self.b.carrier.dir / "doors.json").read_text())
        self.r.move("b", "127.0.0.4")
        after = json.loads((self.b.carrier.dir / "doors.json").read_text())
        self.assertEqual({k: v["fp"] for k, v in before["doors"].items()}, {k: v["fp"] for k, v in after["doors"].items()})
        self.assertEqual({k: v["listen_port"] for k, v in before["doors"].items()}, {k: v["listen_port"] for k, v in after["doors"].items()})


if __name__ == "__main__":
    unittest.main()
