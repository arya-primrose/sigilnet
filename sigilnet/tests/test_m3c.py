"""M3c (DESIGN_multicarrier.md A5, hole 5): `peer rm` also closes the doors we gave that peer on every carrier this node runs; `node doors` lists every door with its peer; nothing is revoked
automatically and a door bound to no agent is never touched."""
import json
from unittest import mock

from sigilnet import noderun
from sigilnet.keys import Identity
from sigilnet.tests.test_locator_cli import TcpHomes
from sigilnet.tests.test_tcplink import free_base


class Base(TcpHomes):
    """Side `a` runs tcp AND tor (offline: the doors are files). It has a tcp door for b already (the rig's), and now: an onion door for b, doors for another agent, a door bound to no agent, a read door."""

    def setUp(self):
        super().setUp()
        self.h = self.a.home
        cfg = json.loads((self.h / "node_config.json").read_text())
        (self.h / "node_config.json").write_text(json.dumps({**cfg, "carriers": ["tcp", "tor"], "service_port_base": free_base()}))
        self.cs = noderun.make_carriers(self.h, noderun.load_config(self.h), offline=True)
        self.other = Identity.generate("other").id
        for etype, c in self.cs.items():
            _, pub = c.new_credential()
            c.open_door("b-" + etype, "peer", credential=pub, agent=self.bid)
            _, pub = c.new_credential()
            c.open_door("o-" + etype, "peer", credential=pub, agent=self.other)
        _, pub = self.cs["tcp"].new_credential()
        self.cs["tcp"].open_door("nobody", "peer", credential=pub)
        self.cs["tcp"].open_door("pub", "read")

    def names(self, etype):
        return sorted(self.cs[etype].doors())

    def bound_to_b(self):
        return sorted((t, n) for t, c in self.cs.items() for n, d in c.doors().items() if d["agent"] == self.bid)


class PeerRm(Base):
    def test_rm_closes_every_door_bound_to_that_peer_on_every_carrier_and_nothing_else(self):
        before = self.bound_to_b()
        self.assertGreaterEqual(len(before), 3, before)                       # the rig's tcp door, b-tcp, b-onion
        rc, out, err = self.cli("a", "peer", "rm", self.bid)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines()[0], "removed")
        self.assertEqual(self.bound_to_b(), [])
        for t, n in before:
            self.assertIn(f"closed the {'tcp' if t == 'tcp' else 'onion'} door {n}", out)
        self.assertIn("o-tcp", self.names("tcp"))
        self.assertIn("nobody", self.names("tcp"), "a door bound to no agent is never touched")
        self.assertIn("pub", self.names("tcp"), "a public door is never touched")
        self.assertEqual([n for n in self.names("onion") if n.startswith("o-")], ["o-onion"])
        self.assertNotIn(self.bid, self.a.peers.all())

    def test_keep_doors_leaves_them(self):
        before = self.bound_to_b()
        rc, out, err = self.cli("a", "peer", "rm", self.bid, "--keep-doors")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.bound_to_b(), before)
        self.assertNotIn("closed", out)
        self.assertNotIn(self.bid, self.a.peers.all())

    def test_a_name_that_is_not_a_peer_closes_nothing(self):
        before = self.bound_to_b()
        rc, out, err = self.cli("a", "peer", "rm", self.other)                # the agent has a door but is not in the peer book
        self.assertEqual(out.strip(), "no such peer")
        self.assertEqual(self.bound_to_b(), before)
        self.assertIn("o-tcp", self.names("tcp"), "no peer record: the door stays, `node doors` shows it")

    def test_a_failure_on_one_carrier_never_blocks_the_removal_or_the_other_carrier(self):
        with mock.patch.object(self.cs["onion"].__class__, "close_door", side_effect=OSError("disk")):
            rc, out, err = self.cli("a", "peer", "rm", self.bid)
        self.assertEqual(rc, 0, err)
        self.assertNotIn(self.bid, self.a.peers.all())
        self.assertEqual([t for t, _ in self.bound_to_b()], ["onion"], "the tcp doors are closed, the onion door is left")

    def test_a_node_with_a_broken_config_still_removes_the_peer(self):
        (self.h / "node_config.json").write_text(json.dumps({"carriers": ["udp"]}))
        with self.assertRaises(ValueError):
            noderun.load_config(self.h)                                        # (the config really is unusable)
        rc, out, err = self.cli("a", "peer", "rm", self.bid)
        self.assertEqual(out.splitlines()[0], "removed")
        self.assertNotIn(self.bid, self.a.peers.all())

    def test_the_credential_we_hold_for_the_peer_is_still_dropped_too(self):
        dropped = []
        with mock.patch("sigilnet.noderun.carrier_for") as cf:
            car = mock.Mock(type="tcp")
            car.drop_credential.side_effect = lambda ep, agent=None: dropped.append(agent)
            cf.return_value = car
            rc, out, err = self.cli("a", "peer", "rm", self.bid)
        self.assertEqual(rc, 0, err)
        self.assertTrue(dropped and set(dropped) == {self.bid})


class NodeDoors(Base):
    def test_every_door_on_every_carrier_with_its_peer_or_a_warning(self):
        rc, out, err = self.cli("a", "node", "doors")
        self.assertEqual(rc, 0, err)
        lines = {l.split()[1]: l for l in out.splitlines()}
        self.assertIn("peer b", lines["b-tcp"])
        self.assertTrue(lines["b-tcp"].startswith("tcp"))
        self.assertTrue(lines["b-onion"].startswith("onion"))
        self.assertIn("peer b", lines["b-onion"])
        self.assertIn("NO PEER holds agent " + self.other[:8], lines["o-tcp"])
        self.assertIn("node revoke o-tcp", lines["o-tcp"])
        self.assertIn("bound to no agent", lines["nobody"])
        self.assertIn("public or join door", lines["pub"])

    def test_no_doors_says_so(self):
        for c in self.cs.values():
            for n in list(c.doors()):
                c.close_door(n)
        rc, out, err = self.cli("a", "node", "doors")
        self.assertEqual((rc, out.strip()), (0, "no doors"))

    def test_after_peer_rm_the_doors_of_that_peer_are_gone_from_the_list(self):
        self.cli("a", "peer", "rm", self.bid)
        rc, out, err = self.cli("a", "node", "doors")
        self.assertNotIn("b-tcp", out)
        self.assertNotIn("b-onion", out)
        self.assertIn("o-tcp", out)
