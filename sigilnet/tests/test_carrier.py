"""The carrier CONFORMANCE suite (Sansa round 26, Q3e): one set of tests run against EVERY carrier (Tor, offline; and the in-memory fake), so that the limits and the
admission rules provably survive the abstraction. Tier 1 = the API contract. Tier 2 = what a door that was served by the protocol layer must do (raw sockets to the
loopback port the carrier hands out: the guard is tcp.TcpServer, shared by all carriers). Tier 3 = delivery (only for carriers that deliver in-process: the fake;
Tor delivery is covered by the live tests)."""
import socket
import struct
import tempfile
import time
import unittest

from sigilnet import carrier as C
from sigilnet import canon, tcp
from sigilnet.carrier import Carrier, CarrierError, Secret
from sigilnet.tcp import TcpServer, TcpTransport
from sigilnet.tests.fake_carrier import FakeCarrier, FakeNet

AGENT = "a" * 32


class Conformance:
    """Mixin: a subclass defines make() -> Carrier and, optionally, DELIVERS = True."""
    DELIVERS = False

    def make(self) -> Carrier:
        raise NotImplementedError

    def setUp(self):
        self.c = self.make()
        self.servers = []
        self.addCleanup(lambda: [s.stop() for s in self.servers])

    def serve(self, port, handler=None):
        s = TcpServer("127.0.0.1", port, None, handler or (lambda req: {"t": "pong", "echo": req.get("n")})).start()
        self.servers.append(s)
        return s

    # ---- tier 1: the API contract
    def test_is_a_carrier_with_a_type_and_capabilities(self):
        self.assertIsInstance(self.c, Carrier)
        self.assertTrue(C.TYPE_RE.fullmatch(self.c.type))
        self.assertIsInstance(self.c.capabilities, frozenset)

    def test_credentials_are_typed_valid_and_secrets_never_print(self):
        secret, public = self.c.new_credential()
        self.assertIsInstance(secret, Secret)
        self.assertEqual(public["type"], self.c.type)
        C.check_credential(public)
        C.check_credential(secret, secret=True)
        self.assertNotIn(secret["key"], repr(secret))
        self.assertNotIn(secret["key"], str(secret))
        self.assertNotIn(secret["key"], f"{secret} {[secret]} {{'x': {secret!r}}}")
        self.assertNotEqual(secret["key"], public["key"])
        self.assertNotEqual(self.c.new_credential()[0]["key"], secret["key"])

    def test_door_lifecycle(self):
        _, pub = self.c.new_credential()
        port = self.c.open_door("peer-one", "peer", credential=pub, agent=AGENT)
        self.assertIsInstance(port, int)
        self.assertEqual(self.c.doors()["peer-one"], {"kind": "peer", "agent": AGENT, "port": port})
        _, pub2 = self.c.new_credential()
        self.assertEqual(self.c.open_door("peer-one", "peer", credential=pub2, agent=AGENT), port, "re-keying keeps the door (same port)")
        ep = self.c.door_endpoint("peer-one")
        self.assertTrue(ep is None or (C.check_endpoint(ep)["type"] == self.c.type))
        self.assertTrue(self.c.close_door("peer-one"))
        self.assertFalse(self.c.close_door("peer-one"))
        self.assertNotIn("peer-one", self.c.doors())
        self.assertIsNone(self.c.door_endpoint("peer-one"))

    def test_public_and_client_doors_have_different_rules(self):
        _, pub = self.c.new_credential()
        self.assertIsInstance(self.c.open_door("pub-read", "read"), int)
        self.assertIsInstance(self.c.open_door("pub-inbox", "inbox"), int)
        self.assertIsInstance(self.c.open_door("join-1", "join", credential=pub), int)
        with self.assertRaises(ValueError):
            self.c.open_door("pub-x", "read", credential=pub)             # a public door takes no credential
        with self.assertRaises(ValueError):
            self.c.open_door("pub-y", "inbox", agent=AGENT)               # ... and no agent
        with self.assertRaises(ValueError):
            self.c.open_door("peer-x", "peer")                            # a client door needs a credential
        with self.assertRaises(ValueError):
            self.c.open_door("join-2", "join", credential=pub, agent=AGENT)    # only peer doors are bound to an agent
        with self.assertRaises(ValueError):
            self.c.open_door("pub-read", "peer", credential=pub)          # a door cannot change kind
        self.assertEqual(sorted(self.c.doors()), ["join-1", "pub-inbox", "pub-read"])

    def test_bad_inputs_are_refused(self):
        _, pub = self.c.new_credential()
        for name in ("", "UPPER", "x" * 33, "a b", "../x", "a\nb"):
            with self.assertRaises(ValueError, msg=repr(name)):
                self.c.open_door(name, "peer", credential=pub)
        with self.assertRaises(ValueError):
            self.c.open_door("ok", "nonsense", credential=pub)
        with self.assertRaises(ValueError):
            self.c.open_door("ok", "peer", credential={"type": "onion"})
        with self.assertRaises(ValueError):
            self.c.open_door("ok", "peer", credential={"type": "zzz", "key": "x"})
        with self.assertRaises(ValueError):
            self.c.open_door("ok", "peer", credential=pub, agent="not-an-agent-id")

    def test_use_and_drop_credential(self):
        secret, _ = self.c.new_credential()
        other = self.other_endpoint()
        self.c.use_credential(other, secret)
        self.assertTrue(self.c.drop_credential(other))
        self.assertFalse(self.c.drop_credential(other))
        with self.assertRaises(ValueError):
            self.c.use_credential(other, {"type": self.c.type, "key": "short"})

    def test_dial_refuses_a_type_it_does_not_carry_without_retry(self):
        with self.assertRaises(CarrierError) as cm:
            self.c.dial({"type": "xyz", "addr": "whatever"}, timeout=1)
        self.assertFalse(cm.exception.retry)

    def test_lifecycle_calls_are_safe(self):
        self.assertIsInstance(self.c.healthy(), bool)
        self.assertIsInstance(self.c.reconfigure(), bool)

    # ---- tier 2: the guard in front of a served door survives (raw sockets to the loopback port the carrier handed out)
    def served_port(self):
        _, pub = self.c.new_credential()
        port = self.c.open_door("guarded", "peer", credential=pub, agent=AGENT)
        self.serve(port)
        return port

    def raw(self, port, data: bytes, wait: float = 1.5):
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            s.sendall(data)
            s.settimeout(wait)
            try:
                return s.recv(65536)
            except (socket.timeout, ConnectionResetError):
                return b""
        finally:
            s.close()

    def test_guard_answers_a_good_request(self):
        port = self.served_port()
        r = TcpTransport("127.0.0.1", port, None, 5).request({"t": "ping", "n": 7})
        self.assertEqual(r, {"t": "pong", "echo": 7})

    def test_guard_oversize_request_is_not_answered(self):
        port = self.served_port()
        self.assertEqual(self.raw(port, struct.pack(">I", tcp.MAX_REQ + 1) + b"x" * 100), b"")

    def test_guard_garbage_is_not_answered(self):
        port = self.served_port()
        for junk in (b"GET / HTTP/1.1\r\n\r\n", b"\x00\x00\x00\x05hello", struct.pack(">I", 10) + b"not json!!", b"\xff" * 64):
            self.assertEqual(self.raw(port, junk), b"", junk)

    def test_guard_slow_header_is_dropped(self):
        port = self.served_port()
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(b"\x00\x00")                                   # half a header, then silence
            s.settimeout(tcp.HEADER_DEADLINE + 2.5)
            t0 = time.time()
            try:
                got = s.recv(10)
            except socket.timeout:
                got = None
            self.assertEqual(got, b"", "the server must close an idle half-header connection")
            self.assertLess(time.time() - t0, tcp.HEADER_DEADLINE + 2.0)
        finally:
            s.close()

    def test_guard_concurrency_cap(self):
        port = self.served_port()
        held = [socket.create_connection(("127.0.0.1", port), timeout=3) for _ in range(tcp.PLAIN_CONNS)]
        try:
            time.sleep(0.3)
            extra = socket.create_connection(("127.0.0.1", port), timeout=3)
            extra.settimeout(1.5)
            extra.sendall(tcp._frame(canon.dumps({"t": "ping", "n": 1})))
            try:
                got = extra.recv(4096)
            except (socket.timeout, ConnectionResetError):
                got = b""
            extra.close()
            self.assertEqual(got, b"", "connections beyond the per-door cap must not be served")
        finally:
            for h in held:
                h.close()

    # ---- tier 3: delivery
    def need_delivery(self):
        if not self.DELIVERS:
            self.skipTest("this carrier does not deliver in-process (Tor delivery is covered by the live tests)")


class FakeConformance(Conformance, unittest.TestCase):
    DELIVERS = True

    def make(self):
        self.net = FakeNet()
        c = FakeCarrier(self.net, "alice")
        c.start()
        return c

    def other_endpoint(self):
        return {"type": "fake", "addr": "bob-door.fake:1"}

    def peer(self, name="bob"):
        c = FakeCarrier(self.net, name)
        c.start()
        return c

    def test_authorized_client_reaches_the_door_and_nobody_else_does(self):
        secret, pub = self.peer().new_credential()
        port = self.c.open_door("d1", "peer", credential=pub)
        self.serve(port)
        ep = self.c.door_endpoint("d1")
        bob = self.peer("bob")
        with self.assertRaises(CarrierError) as cm:
            bob.dial(ep, timeout=2)                                  # no credential held
        self.assertFalse(cm.exception.retry)
        bob.use_credential(ep, secret)
        self.assertEqual(bob.dial(ep, timeout=3).request({"t": "ping", "n": 1}), {"t": "pong", "echo": 1})
        eve = self.peer("eve")
        eve.use_credential(ep, eve.new_credential()[0])             # a credential that was never authorized
        with self.assertRaises(CarrierError) as cm:
            eve.dial(ep, timeout=2)
        self.assertFalse(cm.exception.retry)

    def test_rekeying_locks_out_the_old_key_and_close_makes_the_door_unreachable(self):
        s1, p1 = self.peer().new_credential()
        port = self.c.open_door("d2", "peer", credential=p1)
        self.serve(port)
        ep = self.c.door_endpoint("d2")
        bob = self.peer()
        bob.use_credential(ep, s1)
        self.assertEqual(bob.dial(ep, timeout=3).request({"t": "ping", "n": 2})["t"], "pong")
        _, p2 = self.c.new_credential()
        self.c.open_door("d2", "peer", credential=p2)
        with self.assertRaises(CarrierError):
            bob.dial(ep, timeout=2)
        self.c.close_door("d2")
        with self.assertRaises(CarrierError):
            bob.dial(ep, timeout=2)

    def test_public_door_needs_no_credential(self):
        port = self.c.open_door("pr", "read")
        self.serve(port)
        self.assertEqual(self.peer().dial(self.c.door_endpoint("pr"), timeout=3).request({"t": "ping", "n": 3})["echo"], 3)


class TorConformance(Conformance, unittest.TestCase):
    """The Tor carrier, OFFLINE (no tor process): door files, credentials and the contract. Delivery over real Tor is covered by the live tests."""

    def make(self):
        import random
        from sigilnet.torlink import TorNode
        return TorNode(tempfile.mkdtemp(), offline=True, service_port_base=random.randrange(20000, 31000))

    def other_endpoint(self):
        return {"type": "onion", "addr": "a" * 56 + ".onion:47200"}

    # ---- what the Tor carrier writes (Sansa B1 gap): the Tor side of "per-door cap", "unauthorized client reaches nothing", "closed door unreachable"
    def torrc(self):
        self.c.reconfigure()
        return self.c.torrc.read_text()

    def test_every_door_forwards_to_loopback_only_and_has_a_stream_cap(self):
        import re
        _, pub = self.c.new_credential()
        self.c.open_door("d-peer", "peer", credential=pub, agent=AGENT)
        self.c.open_door("d-join", "join", credential=pub)
        self.c.open_door("d-read", "read")
        self.c.open_door("d-inbox", "inbox")
        rc = self.torrc()
        ports = re.findall(r"^HiddenServicePort (\d+) (\S+)$", rc, re.M)
        self.assertEqual(len(ports), 4)
        for virt, target in ports:
            self.assertRegex(target, r"^127\.0\.0\.1:\d+$", target)
        self.assertEqual(sorted(int(t.split(":")[1]) for _, t in ports), sorted(d["port"] for d in self.c.doors().values()))
        self.assertEqual(rc.count("HiddenServiceMaxStreams 32\n"), 4)
        self.assertEqual(rc.count("HiddenServiceMaxStreamsCloseCircuit 1\n"), 4)
        self.assertNotIn("0.0.0.0", rc)
        self.assertIn("ControlPort 0", rc)

    def test_client_auth_file_holds_exactly_the_public_credential_and_public_doors_have_none(self):
        _, pub = self.c.new_credential()
        self.c.open_door("d-peer", "peer", credential=pub)
        self.c.open_door("d-read", "read")
        f = self.c.svc_dir / "d-peer" / "authorized_clients" / "client.auth"
        self.assertEqual(f.read_text(), f"descriptor:x25519:{pub['key']}\n")
        _, pub2 = self.c.new_credential()
        self.c.open_door("d-peer", "peer", credential=pub2)
        self.assertEqual(f.read_text(), f"descriptor:x25519:{pub2['key']}\n", "re-keying replaces the authorized key")
        self.assertEqual(len(list((self.c.svc_dir / "d-peer" / "authorized_clients").iterdir())), 1)
        self.assertFalse((self.c.svc_dir / "d-read" / "authorized_clients").exists(), "a public door authorizes no client")
        self.assertNotIn(pub["key"], f.read_text())

    def test_close_door_leaves_nothing_behind(self):
        _, pub = self.c.new_credential()
        self.c.open_door("d-gone", "peer", credential=pub)
        self.assertIn("d-gone", self.torrc())
        self.assertTrue(self.c.close_door("d-gone"))
        self.assertNotIn("d-gone", self.torrc())
        self.assertTrue(self.c.door_gone("d-gone"))
        self.assertFalse((self.c.svc_dir / "d-gone").exists())
        self.assertNotIn("d-gone", self.c.svc_file.read_text())

    def test_drop_credential_removes_the_client_auth_file(self):
        secret, _ = self.c.new_credential()
        ep = self.other_endpoint()
        self.c.use_credential(ep, secret)
        f = self.c.auth_in / f"{ep['addr'].split('.onion')[0]}.auth_private"
        self.assertEqual(f.read_text(), f"{ep['addr'].split('.onion')[0]}:descriptor:x25519:{secret['key']}\n")
        self.assertTrue(self.c.drop_credential(ep))
        self.assertFalse(f.exists())
        self.assertFalse(self.c.drop_credential(ep))

    def test_drop_credential_survives_a_racing_remover(self):
        secret, _ = self.c.new_credential()
        ep = self.other_endpoint()
        self.c.use_credential(ep, secret)
        f = self.c.auth_in / f"{ep['addr'].split('.onion')[0]}.auth_private"
        real = type(f).unlink
        calls = []

        def racing(self_, *a, **kw):                       # the CLI removes it between our look and our unlink
            calls.append(1)
            real(self_, *a, **kw)
            raise FileNotFoundError()
        import unittest.mock as mock
        with mock.patch.object(type(f), "unlink", racing):
            self.assertFalse(self.c.drop_credential(ep))


class RegistryRules(unittest.TestCase):
    def test_local_config_refuses_unknown_types_but_events_accept_them(self):
        with self.assertRaises(ValueError):
            C.check_endpoint({"type": "xyz", "addr": "foo"})
        self.assertEqual(C.check_endpoint({"type": "xyz", "addr": "foo"}, strict=False), {"type": "xyz", "addr": "foo"})
        with self.assertRaises(ValueError):
            C.check_endpoint({"type": "xyz", "addr": "foo", "extra": 1}, strict=False)
        with self.assertRaises(ValueError):
            C.check_endpoint({"type": "BAD TYPE", "addr": "foo"}, strict=False)

    def test_lookalike_and_non_ascii_inputs_are_refused(self):
        onion = "a" * 56 + ".onion"
        for addr in ("\u212a" + "a" * 55 + ".onion:47200",          # KELVIN SIGN lowers to ASCII 'k'
                     onion + ":\u00b2", onion + ":\u0664\u0667", onion.replace("a", "\u0430", 1) + ":1", onion + ":47200\u200b", onion + ":+1", onion + ":1_0"):
            with self.assertRaises(ValueError, msg=repr(addr)):
                C.check_endpoint({"type": "onion", "addr": addr})
        with self.assertRaises(ValueError):
            C.check_credential({"type": "onion", "key": "\u212a" * 52})

    def test_endpoint_validator_fuzz(self):
        onion = "a" * 56 + ".onion"
        bad = [None, [], "x", {}, {"type": "onion"}, {"type": "onion", "addr": onion}, {"type": "onion", "addr": onion + ":0"}, {"type": "onion", "addr": onion + ":65536"},
               {"type": "onion", "addr": onion + ":0047200"}, {"type": "onion", "addr": onion + ":47200 "}, {"type": "onion", "addr": "a" * 55 + ".onion:1"}, {"type": "onion", "addr": onion + ":1\n"}, {"type": "onion", "addr": onion + ":-1"},
               {"type": 5, "addr": onion + ":1"}, {"type": "onion", "addr": 5}, {"type": "onion", "addr": ""}, {"type": "", "addr": "x"},
               {"type": "onion", "addr": "x" * 300}, {"type": "o" * 17, "addr": "x"}, {"type": "onion", "addr": onion + ":١٢"}]
        for e in bad:
            with self.assertRaises(ValueError, msg=repr(e)):
                C.check_endpoint(e)
        ok = C.check_endpoint({"type": "onion", "addr": (onion + ":47200").upper()})            # case is normalized
        self.assertEqual(ok["addr"], onion + ":47200")


if __name__ == "__main__":
    unittest.main()
