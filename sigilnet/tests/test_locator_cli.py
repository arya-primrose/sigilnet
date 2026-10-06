"""The locator book in the CLI: `peer list`, `peer move`, `peer rm`, `peer add --key`, `init --bind auto`, and the capsule paths that seed the book."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import cli
from sigilnet import locators as L
from sigilnet import tcplink as TL
from sigilnet.keys import Identity
from sigilnet.tests.locrig import Rig
from sigilnet.tests.test_capsule import Base as CapsuleBase


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write("" if isinstance(e.code, int) or e.code is None else str(e.code))
    return rc, out.getvalue(), err.getvalue()


class TcpHomes(unittest.TestCase):
    """The rig's two sides, each with an identity.json and a node_config.json so the CLI can open them like real homes."""

    def setUp(self):
        self.r = Rig("tcp")
        self.addCleanup(self.r.close)
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.aid, self.bid = self.r.ids["a"].id, self.r.ids["b"].id
        for n, s in self.r.sides.items():
            os.chmod(s.home, 0o700)
            self.r.ids[n].save(s.home / "identity.json")
            (s.home / "node_config.json").write_text(json.dumps({"carrier": "tcp", "tcp": {"bind": self.r.ips[n], "port_base": self.r.bases[n]}}))

    def cli(self, side, *args):
        return run_cli("--home", str(self.r.sides[side].home), *args)

    def peers(self, side="a"):
        return json.loads((self.r.sides[side].home / "peers.json").read_text())["peers"]


class PeerList(TcpHomes):
    def test_one_address_is_one_line_as_before(self):
        rc, out, err = self.cli("a", "peer", "list")
        self.assertEqual(rc, 0, err)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn(self.bid, lines[0])
        self.assertIn("tcp " + self.a.book.ordered(self.bid)[0], lines[0])
        self.assertNotIn("also", out)

    def test_the_other_addresses_follow_in_dial_order_with_what_we_know_about_them(self):
        old = self.a.book.ordered(self.bid)[0]
        new = "127.0.0.9:47800#" + "ab" * 32
        self.a.book.adopt(self.bid, new, ts=1)
        self.a.book.note_fail(self.bid, old)
        rc, out, err = self.cli("a", "peer", "list")
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 2, out)
        self.assertIn("tcp " + new, lines[0])                        # the first one dialed
        self.assertIn("also tcp " + old, lines[1])
        self.assertIn("(failed since)", lines[1])

    def test_a_peer_with_no_endpoint_says_so(self):
        other = Identity.generate("o").id
        self.a.peers.add(other, "dialsus", None, [])
        rc, out, err = self.cli("a", "peer", "list")
        self.assertIn("(no endpoint: it dials us)", out)


class PeerMove(TcpHomes):
    def test_ip_keeps_the_port_and_fingerprint_and_is_verified_by_a_signed_ping(self):
        old = self.a.book.ordered(self.bid)[0]
        ip_port, _, fp = old.partition("#")
        port = ip_port.split(":")[1]
        new = self.r.move("b", "127.0.0.4")
        self.assertEqual(new, f"127.0.0.4:{port}#{fp}")
        self.r.tick()                                                # (the node loop refreshes the pong snapshot a ping is answered from)
        rc, out, err = self.cli("a", "peer", "move", "b", "--ip", "127.0.0.4")
        self.assertEqual(rc, 0, err + out)
        self.assertIn("address moved (verified: b answered)", out)
        self.assertEqual(self.peers()[self.bid]["endpoints"][0]["addr"], new)
        self.assertEqual(L.open_book(self.a.home, "tcp").ordered(self.bid)[0], new)

    def test_a_dead_address_changes_nothing_unless_told_not_to_verify(self):
        before = json.dumps(self.peers(), sort_keys=True)
        rc, out, err = self.cli("a", "peer", "move", "b", "--ip", "127.0.0.77")
        self.assertEqual(rc, 1)
        self.assertIn("no answer from b at the new address (connect refused)", err)
        self.assertIn("nothing was changed", err)
        self.assertEqual(json.dumps(self.peers(), sort_keys=True), before)
        self.assertNotIn("127.0.0.77", " ".join(self.a.book.ordered(self.bid)))
        rc, out, err = self.cli("a", "peer", "move", self.bid, "--ip", "127.0.0.77", "--no-verify")
        self.assertEqual(rc, 0, err)
        self.assertIn("address moved (not verified)", out)
        self.assertTrue(self.peers()[self.bid]["endpoints"][0]["addr"].startswith("127.0.0.77:"))
        self.assertTrue(self.a.book.ordered(self.bid)[0].startswith("127.0.0.77:"))

    def test_the_name_the_agent_id_and_a_unique_prefix_all_find_the_peer(self):
        for who in ("b", self.bid, self.bid[:8]):
            rc, out, err = self.cli("a", "peer", "move", who, "--ip", "127.0.0.78", "--no-verify")
            self.assertEqual(rc, 0, (who, err))

    def test_the_full_endpoint_form_works_and_is_verified_too(self):
        new = self.r.move("b", "127.0.0.4")
        self.r.tick()
        rc, out, err = self.cli("a", "peer", "move", "b", "--endpoint", "tcp:" + new)
        self.assertEqual(rc, 0, err)
        self.assertIn("verified", out)

    def test_a_wrong_fingerprint_is_not_accepted_by_the_verification(self):
        new = self.r.move("b", "127.0.0.4")
        self.r.tick()
        ip_port = new.split("#")[0]
        rc, out, err = self.cli("a", "peer", "move", "b", "--endpoint", f"tcp:{ip_port}#{'0' * 64}")
        self.assertEqual(rc, 1)
        self.assertIn("nothing was changed", err)

    def test_the_threads_and_the_name_of_the_peer_survive(self):
        self.a.peers.add(self.bid, "bee", self.a.peers.all()[self.bid]["endpoint"], [self.r.tid])
        self.cli("a", "peer", "move", "bee", "--ip", "127.0.0.79", "--no-verify")
        rec = self.peers()[self.bid]
        self.assertEqual((rec["name"], rec["threads"]), ("bee", [self.r.tid]))

    def test_usage_errors(self):
        for args in ((), ("b",), ("b", "--ip", "1.2.3.4", "--endpoint", "tcp:1.2.3.4:5000#" + "ab" * 32), ("--ip", "1.2.3.4"), ("nobody", "--ip", "127.0.0.9"),
                     ("b", "--ip", "not an ip"), ("b", "--ip", "300.1.1.1"), ("b", "--endpoint", "nonsense"), ("b", "--endpoint", "onion:x.onion:1")):
            rc, out, err = self.cli("a", "peer", "move", *args, "--no-verify")
            self.assertNotEqual(rc, 0, args)
        self.assertEqual(self.peers()[self.bid]["endpoints"][0]["addr"], self.a.book.ordered(self.bid)[0])

    def test_a_peer_of_another_carrier_cannot_be_moved_with_ip(self):
        other = Identity.generate("o").id
        self.a.peers.add(other, "tor1", {"type": "onion", "addr": "a" * 56 + ".onion:47200"}, [])
        rc, out, err = self.cli("a", "peer", "move", "tor1", "--ip", "1.2.3.4", "--no-verify")
        self.assertNotEqual(rc, 0)
        self.assertIn("--ip is for a tcp peer", err)

    def test_an_endpoint_of_the_other_carrier_cannot_be_verified_from_this_node(self):
        rc, out, err = self.cli("a", "peer", "move", "b", "--endpoint", "onion:" + "a" * 56 + ".onion:47200")
        self.assertNotEqual(rc, 0)
        self.assertIn("does not run the onion carrier", err)


class PeerMoveOnTor(unittest.TestCase):
    def test_a_tor_node_cannot_verify_from_the_cli_and_changes_nothing_without_no_verify(self):
        d = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, d, True)
        home = d / "h"
        rc, out, err = run_cli("--home", str(home), "init", "arya")
        self.assertEqual(rc, 0, err)
        other = Identity.generate("o").id
        onion1, onion2 = "a" * 56 + ".onion:47200", "b" * 56 + ".onion:47200"
        rc, out, err = run_cli("--home", str(home), "peer", "add", "tor1", other, "--endpoint", "onion:" + onion1)
        self.assertEqual(rc, 0, err)
        rc, out, err = run_cli("--home", str(home), "peer", "move", "tor1", "--endpoint", "onion:" + onion2)
        self.assertNotEqual(rc, 0)
        self.assertIn("cannot verify a Tor address", err)
        self.assertEqual(json.loads((home / "peers.json").read_text())["peers"][other]["endpoints"][0]["addr"], onion1)
        rc, out, err = run_cli("--home", str(home), "peer", "move", "tor1", "--endpoint", "onion:" + onion2, "--no-verify")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads((home / "peers.json").read_text())["peers"][other]["endpoints"][0]["addr"], onion2)


class PeerRm(TcpHomes):
    def test_removing_a_peer_forgets_its_credentials_and_addresses(self):
        self.a.book.adopt(self.bid, "127.0.0.9:47800#" + "ab" * 32, ts=1)
        held = json.loads(self.a.carrier.held_file.read_text())
        self.assertIn("agent:" + self.bid, held)
        rc, out, err = self.cli("a", "peer", "rm", self.bid)
        self.assertEqual((rc, out.splitlines()[0]), (0, "removed"), err)
        self.assertIn("closed the tcp door peer-b we gave this peer", out)       # M3c: the door we gave it goes too
        held = json.loads(self.a.carrier.held_file.read_text())
        self.assertEqual(held, {})                                   # the node-id entry AND the address entry
        self.assertEqual(L.open_book(self.a.home, "tcp").ordered(self.bid), [])
        self.assertNotIn(self.bid, self.peers())

    def test_removing_an_unknown_peer_says_so(self):
        rc, out, err = self.cli("a", "peer", "rm", "x" * 32)
        self.assertEqual(out.strip(), "no such peer")

    def test_other_peers_credentials_stay(self):
        other = Identity.generate("o").id
        sec, _ = self.a.carrier.new_credential()
        ep = {"type": "tcp", "addr": "10.1.1.1:47900#" + "cd" * 32}
        self.a.carrier.use_credential(ep, sec, agent=other)
        self.a.peers.add(other, "o", ep, [])
        self.cli("a", "peer", "rm", self.bid)
        held = json.loads(self.a.carrier.held_file.read_text())
        self.assertEqual(set(held), {ep["addr"], "agent:" + other})


class PeerAdd(TcpHomes):
    def test_add_with_a_key_holds_the_credential_under_the_node_id(self):
        rc, out, err = self.cli("a", "node", "auth", "lbl")
        self.assertEqual(rc, 0, err)
        other = Identity.generate("o").id
        ep = "tcp:10.2.2.2:47900#" + "ef" * 32
        rc, out, err = self.cli("a", "peer", "add", "oo", other, "--endpoint", ep, "--key", "lbl")
        self.assertEqual(rc, 0, err)
        held = json.loads(self.a.carrier.held_file.read_text())
        self.assertIn("agent:" + other, held)
        self.assertEqual(L.open_book(self.a.home, "tcp").ordered(other), ["10.2.2.2:47900#" + "ef" * 32])

    def test_add_without_a_key_still_seeds_the_book(self):
        other = Identity.generate("o").id
        self.cli("a", "peer", "add", "oo", other, "--endpoint", "tcp:10.2.2.3:47900#" + "ef" * 32)
        self.assertEqual(L.open_book(self.a.home, "tcp").ordered(other), ["10.2.2.3:47900#" + "ef" * 32])


class InitAuto(unittest.TestCase):
    def setUp(self):
        self.d = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_init_with_bind_auto_stores_the_word_and_says_what_it_means_now(self):
        with mock.patch("sigilnet.tcplink._interfaces", return_value=["127.0.0.1", "10.7.7.7"]), mock.patch("sigilnet.tcplink._route_ip", return_value=None):
            with mock.patch("sigilnet.cli._free_range", return_value=47990) as fr:
                rc, out, err = run_cli("--home", str(self.d / "h"), "init", "arya", "--carrier", "tcp", "--bind", "auto")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads((self.d / "h" / "node_config.json").read_text())["tcp"]["bind"], "auto")
        self.assertIn("carrier tcp on auto (now 10.7.7.7)", out)
        self.assertEqual(fr.call_args[0][2], ["127.0.0.1", "10.7.7.7"])            # the free-port probe used the real address

    def test_init_with_bind_auto_on_a_machine_without_a_private_address_fails_cleanly(self):
        with mock.patch("sigilnet.tcplink._interfaces", return_value=["127.0.0.1"]):
            rc, out, err = run_cli("--home", str(self.d / "h"), "init", "arya", "--carrier", "tcp", "--bind", "auto")
        self.assertNotEqual(rc, 0)
        self.assertIn("auto", err)
        self.assertFalse((self.d / "h" / "identity.json").exists())

    def test_the_config_loads_and_the_carrier_resolves_auto_every_time(self):
        from sigilnet import noderun
        home = self.d / "h2"
        home.mkdir(mode=0o700)
        cfg = {"carrier": "tcp", "tcp": {"bind": "auto", "port_base": 47990}}
        noderun.save_config(home, cfg)
        loaded = noderun.load_config(home)
        self.assertEqual(loaded["tcp"]["bind"], "auto")
        for ip in ("10.7.7.7", "10.8.8.8"):                        # the machine got a new address between two starts
            with mock.patch("sigilnet.tcplink._interfaces", return_value=["127.0.0.1", ip]):
                c = noderun.make_carrier(home, loaded)
            self.assertEqual((c.bind, c.advertise), (ip, ip))

    def test_an_explicit_advertise_still_wins_over_the_resolved_bind(self):
        from sigilnet import noderun
        home = self.d / "h3"
        home.mkdir(mode=0o700)
        cfg = {"carrier": "tcp", "tcp": {"bind": "auto", "port_base": 47990, "advertise": "10.9.9.9"}}
        with mock.patch("sigilnet.tcplink._interfaces", return_value=["10.7.7.7"]):
            c = noderun.make_carrier(home, cfg)
        self.assertEqual((c.bind, c.advertise), ("10.7.7.7", "10.9.9.9"))

    def test_auto_picks_a_public_address_with_or_without_allow_public_M3(self):
        from sigilnet import noderun
        home = self.d / "h5"
        home.mkdir(mode=0o700)
        with mock.patch("sigilnet.tcplink._interfaces", return_value=["127.0.0.1", "8.8.4.4"]):
            for tcp_cfg in ({"bind": "auto", "port_base": 47990, "allow_public": True}, {"bind": "auto", "port_base": 47990}):
                c = noderun.make_carrier(home, {"carrier": "tcp", "tcp": tcp_cfg})
                self.assertEqual(c.bind, "8.8.4.4")
        with mock.patch("sigilnet.tcplink._interfaces", return_value=["127.0.0.1", "169.254.2.2"]):
            with self.assertRaises(ValueError):
                noderun.make_carrier(home, {"carrier": "tcp", "tcp": {"bind": "auto", "port_base": 47990}})

    def test_auto_uses_the_route_to_a_known_peers_address(self):
        from sigilnet import noderun
        from sigilnet.node import PeerBook
        home = self.d / "h4"
        home.mkdir(mode=0o700)
        PeerBook(home / "peers.json").add(Identity.generate("p").id, "p", {"type": "tcp", "addr": "192.168.5.5:47700#" + "ab" * 32}, [])
        cfg = {"carrier": "tcp", "tcp": {"bind": "auto", "port_base": 47990}}
        with mock.patch("sigilnet.tcplink._interfaces", return_value=["10.0.0.2", "192.168.5.9"]):
            with mock.patch("sigilnet.tcplink._route_ip", side_effect=lambda d: "192.168.5.9" if d == "192.168.5.5" else None):
                c = noderun.make_carrier(home, cfg)
        self.assertEqual(c.bind, "192.168.5.9")


class CapsuleSeedsTheBook(CapsuleBase):
    """After a capsule join both sides know the other's address through the locator book (and hold the credential by node id)."""

    def test_a_join_seeds_both_books(self):
        block, cid, fp = self.create()
        r = self.accept(block)
        self.poll()
        from sigilnet import capsule as C
        out = C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, C.fingerprint(self.joiner.id), clock=self.clock)
        self.ofake(out["door"])
        self.assertEqual(self.poll(), {r["cid"]: "joined"})
        ob = L.open_book(self.oh, "onion")
        jb = L.open_book(self.jh, "onion")
        self.assertEqual(len(ob.ordered(self.joiner.id)), 1)
        self.assertEqual(len(jb.ordered(self.owner.id)), 1)
        self.assertEqual(jb.ordered(self.owner.id)[0], self.jbook.all()[self.owner.id]["endpoint"]["addr"])
        self.assertEqual(ob.ordered(self.joiner.id)[0], self.obook.all()[self.joiner.id]["endpoint"]["addr"])

    def test_the_capsule_paths_pass_the_node_id_to_the_carrier(self):
        calls = []
        orig_o, orig_j = self.otor.use_credential, self.jtor.use_credential
        self.otor.use_credential = lambda ep, secret, agent=None: (calls.append(("owner", agent)), orig_o(ep, secret, agent=agent))[1]
        self.jtor.use_credential = lambda ep, secret, agent=None: (calls.append(("joiner", agent)), orig_j(ep, secret, agent=agent))[1]
        block, cid, fp = self.create()
        r = self.accept(block)
        self.poll()
        from sigilnet import capsule as C
        out = C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, C.fingerprint(self.joiner.id), clock=self.clock)
        self.ofake(out["door"])
        self.poll()
        self.assertIn(("owner", self.joiner.id), calls)
        self.assertIn(("joiner", self.owner.id), calls)


if __name__ == "__main__":
    unittest.main()
