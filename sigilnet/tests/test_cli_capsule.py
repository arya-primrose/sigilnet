import base64
import threading
import time
import unittest
import tempfile
from pathlib import Path

from sigilnet.tests.test_cli_public import run


def fake_tor(home, stop):
    """Plays tor: gives every new onion service directory a hostname file."""
    n = [0]
    def loop():
        d = Path(home) / "tor" / "services"
        while not stop.is_set():
            if d.is_dir():
                for x in d.iterdir():
                    if x.is_dir() and not (x / "hostname").exists():
                        n[0] += 1
                        (x / "hostname").write_text(base64.b32encode(bytes([n[0] + hash(home) % 100]) * 35).decode().lower()[:56] + ".onion\n")
            time.sleep(0.05)
    th = threading.Thread(target=loop, daemon=True)
    th.start()
    return th


class CapsuleCli(unittest.TestCase):
    def setUp(self):
        self.o, self.j = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.stop = threading.Event()
        self.addCleanup(self.stop.set)
        fake_tor(self.o, self.stop)
        fake_tor(self.j, self.stop)
        run(self.o, "id", "init", "arya")
        run(self.j, "id", "init", "carol")
        self.tid = run(self.o, "new", "secret")[1].split("thread ")[1].split()[0]

    def test_create_accept_list(self):
        rc, out, err = run(self.o, "capsule", "create", self.tid[:8], "--wait", "10")
        self.assertEqual(rc, 0, (out, err))
        block = next(l for l in out.splitlines() if l.startswith("SIGILNET-CAPSULE-1"))
        fp = out.split("ANOTHER channel (phone, in person): ")[1].split("\n")[0].strip()
        rc, out, err = run(self.j, "capsule", "accept", block, "--fingerprint", "aaaa bbbb cccc dddd", "--wait", "10")
        self.assertNotEqual(rc, 0)
        self.assertIn("do NOT join", err)
        rc, out, err = run(self.j, "capsule", "accept", block, "--fingerprint", fp, "--wait", "10")
        self.assertEqual(rc, 0, (out, err))
        self.assertRegex(out, "NOT encrypted|ENCRYPTED")
        self.assertIn("YOUR fingerprint", out)
        rc, out, _ = run(self.j, "capsule", "list")
        self.assertIn("joiner", out)
        rc, out, _ = run(self.o, "capsule", "list")
        self.assertIn("open", out)
        cid = out.split()[1]
        self.assertEqual(run(self.o, "capsule", "confirm", cid, "--fingerprint", "x")[0] != 0, True)
        self.assertIn("rejected", run(self.o, "capsule", "reject", cid)[1])
        self.assertIn("no such", run(self.o, "capsule", "reject", cid)[1])

    def test_create_needs_running_node(self):
        self.stop.set()
        time.sleep(0.2)
        rc, out, err = run(self.o, "capsule", "create", self.tid[:8], "--wait", "1")
        self.assertNotEqual(rc, 0)
        self.assertIn("no address yet", err)
        self.assertEqual(run(self.o, "capsule", "list")[1].count("open"), 0)           # the failed attempt left nothing behind


class CapsuleCliTwoCarriers(unittest.TestCase):
    """M2: both homes run tcp (loopback) AND tor (offline, a thread plays tor); the primary is the first of `carriers`."""

    def setUp(self):
        import json
        from sigilnet.tests.test_tcplink import free_base
        self.o, self.j = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.stop = threading.Event()
        self.addCleanup(self.stop.set)
        fake_tor(self.o, self.stop)
        fake_tor(self.j, self.stop)
        run(self.o, "id", "init", "arya")
        run(self.j, "id", "init", "carol")
        for h in (self.o, self.j):
            Path(h, "node_config.json").write_text(json.dumps({"carriers": ["tcp", "tor"], "tcp": {"bind": "127.0.0.1", "port_base": free_base()}, "service_port_base": free_base()}))
        self.tid = run(self.o, "new", "secret")[1].split("thread ")[1].split()[0]

    def create(self, *flags):
        rc, out, err = run(self.o, "capsule", "create", self.tid[:8], "--wait", "10", *flags)
        block = next((l for l in out.splitlines() if l.startswith("SIGILNET-CAPSULE-1")), None)
        return rc, out, err, block

    def types(self, block):
        from sigilnet import capsule as C
        return [j["endpoint"]["type"] for j in C.decode_capsule(block)["joins"]]

    def test_the_default_is_the_primary_only(self):
        rc, out, err, block = self.create()
        self.assertEqual(rc, 0, (out, err))
        self.assertEqual(self.types(block), ["tcp"])
        self.assertIn("join doors on: tcp", out)
        self.assertIn("YOUR IP address", out)

    def test_carrier_flags_choose_the_doors_and_their_order(self):
        rc, out, err, block = self.create("--carrier", "tor", "--carrier", "tcp")
        self.assertEqual(rc, 0, (out, err))
        self.assertEqual(self.types(block), ["onion", "tcp"])
        self.assertIn("YOUR IP address", out)
        rc, out, err, block = self.create("--carrier", "tor")
        self.assertEqual(self.types(block), ["onion"])
        self.assertNotIn("YOUR IP address", out)
        rc, out, _ = run(self.o, "capsule", "list")
        self.assertIn("doors onion,tcp", out)
        self.assertIn("doors onion ", out)

    def test_a_carrier_this_node_does_not_run_is_an_error(self):
        import json
        Path(self.o, "node_config.json").write_text(json.dumps({"carriers": ["tor"], "service_port_base": 47900}))
        rc, out, err, block = self.create("--carrier", "tcp")
        self.assertNotEqual(rc, 0)
        self.assertIn("does not run the tcp carrier", err)

    def test_a_listed_carrier_that_is_down_refuses_the_create(self):
        from unittest import mock
        from sigilnet import cli
        with mock.patch.object(cli, "_node_says_down", side_effect=lambda h, t: "bootstrapping" if t == "onion" else None):
            rc, out, err, block = self.create("--carrier", "tcp", "--carrier", "tor")
            self.assertNotEqual(rc, 0)
            self.assertIn("the onion carrier is down", err)
            self.assertIn("--carrier", err)
            self.assertEqual(run(self.o, "capsule", "list")[1].count("open"), 0)
            rc, out, err, block = self.create("--carrier", "tcp")
            self.assertEqual(rc, 0, (out, err))

    def test_accept_says_which_carriers_it_uses_and_warns_about_the_ip_and_the_restriction_keeps_it_out(self):
        rc, out, err, block = self.create("--carrier", "tor", "--carrier", "tcp")
        fp = out.split("ANOTHER channel (phone, in person): ")[1].split("\n")[0].strip()
        rc, out, err = run(self.j, "capsule", "accept", block, "--fingerprint", fp, "--wait", "10", "--carrier", "tor")
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("This join will use: onion.", out)
        self.assertNotIn("learns this node's IP", out)
        self.assertIn("WARNING: this capsule names the owner's IP", out)
        rc, out, _ = run(self.j, "capsule", "list")
        self.assertIn("carriers onion", out)
        self.assertNotIn("tcp", out)

    def test_accept_over_both_carriers_tells_the_joiner_the_owner_learns_its_ip(self):
        rc, out, err, block = self.create("--carrier", "tor", "--carrier", "tcp")
        fp = out.split("ANOTHER channel (phone, in person): ")[1].split("\n")[0].strip()
        rc, out, err = run(self.j, "capsule", "accept", block, "--fingerprint", fp, "--wait", "10")
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("This join will use: onion, tcp. The owner learns this node's IP address", out)

    def test_accept_refuses_when_every_carrier_it_would_use_is_down(self):
        from unittest import mock
        from sigilnet import cli
        rc, out, err, block = self.create("--carrier", "tcp")
        fp = out.split("ANOTHER channel (phone, in person): ")[1].split("\n")[0].strip()
        with mock.patch.object(cli, "_node_says_down", side_effect=lambda h, t: "down" if t == "tcp" else None):
            rc, out, err = run(self.j, "capsule", "accept", block, "--fingerprint", fp, "--wait", "10")
        self.assertNotEqual(rc, 0)
        self.assertIn("every carrier this join would use is down", err)
        self.assertEqual(run(self.j, "capsule", "list")[1].strip(), "")

    def test_a_capsule_with_no_common_carrier_is_refused_with_both_sides_named(self):
        import json
        rc, out, err, block = self.create("--carrier", "tcp")
        fp = out.split("ANOTHER channel (phone, in person): ")[1].split("\n")[0].strip()
        Path(self.j, "node_config.json").write_text(json.dumps({"carriers": ["tor"], "service_port_base": 47950}))
        rc, out, err = run(self.j, "capsule", "accept", block, "--fingerprint", fp, "--wait", "10")
        self.assertNotEqual(rc, 0)
        self.assertIn("needs a carrier of one of ['tcp']", err)


if __name__ == "__main__":
    unittest.main()
