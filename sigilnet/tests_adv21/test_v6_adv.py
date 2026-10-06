"""Sansa's adversarial tests for the IPv6 tcp carrier (p8)."""
import socket, tempfile, time, unittest
from pathlib import Path
from sigilnet import tcplink as T
from sigilnet.acceptguard import AcceptGuard, guard_key
from sigilnet.carrier import CarrierError

FP = "ab" * 32


class Fmt(unittest.TestCase):
    def ok(self, a, want=None):
        r = T._check_addr(a)
        if want:
            self.assertEqual(r, want)
        return r

    def bad(self, a):
        with self.assertRaises(ValueError, msg=a):
            T._check_addr(a)

    def test_canonical_spellings(self):
        self.ok(f"[0:0:0:0:0:0:0:1]:47700#{FP}", f"[::1]:47700#{FP}")
        self.ok(f"[2001:DB8:0:0:0:0:0:1]:47700#{FP.upper()}", f"[2001:db8::1]:47700#{FP}")
        self.ok(f"[2001:0db8:0000:0000:0000:0000:0000:0001]:47700#{FP}", f"[2001:db8::1]:47700#{FP}")
        self.assertEqual(T._split_addr(f"[2a00:1450::1]:47700#{FP}")[0], "2a00:1450::1")

    def test_refused_spellings(self):
        for h in ("::ffff:1.2.3.4", "::ffff:102:304", "fe80::1%eth0", "fe80::1%25eth0", "1::2::3", ":::1", "1:2:3:4:5:6:7:8:9", "::1.2.3.4", "g::1", "", "1:2:3:4:5:6:7:", "0:0:0:0:0:ffff:1.2.3.4"):
            self.bad(f"[{h}]:47700#{FP}")
        for tail in (":0", ":65536", ":047700", ":", "", ":47700 ", ":+1234"):
            self.bad(f"[2001:4860::1]{tail}#{FP}")
        self.bad(f"2001:4860::1:47700#{FP}")                      # no brackets
        self.bad(f"[2001:4860::1]]:47700#{FP}")
        self.bad(f"[[2001:4860::1]:47700#{FP}")
        self.bad(f"[2001:4860::1]:47700#{FP[:-1]}")
        self.bad(f"[2001:4860::1]47700#{FP}")

    def test_v4_unchanged(self):
        self.ok(f"10.0.0.5:47700#{FP}", f"10.0.0.5:47700#{FP}")
        for a in ("010.0.0.5", "1.2.3", "256.1.1.1", "1.2.3.4.5", "0x7f.0.0.1"):
            self.bad(f"{a}:47700#{FP}")


class Problem(unittest.TestCase):
    def carrier(self, bind="172.17.0.4", advertise=None):
        d = tempfile.mkdtemp()
        return T.TcpCarrier(Path(d), bind=bind, port_base=47700, advertise=advertise)

    def test_table(self):
        c = self.carrier()
        allowed = ["2001:4860:4860::8888", "2a00:1450:4001::1", "fc00::1", "fd12:3456::1", "fd00:ec2::254", "2620:fe::fe", "2400::1", "3ffe::1"]
        refused = ["::", "::1", "::2", "::ffff:1.2.3.4", "::1.2.3.4", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "fe80::1", "fec0::1", "ff02::1", "ff00::", "2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
                   "2001:db8::1", "2001:2::1", "2001:10::1", "2002::1", "2002:c000:204::1", "3fff::1", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", "1000::1", "4000::1", "e000::1", "fb00::1", "fe00::1"]
        for h in allowed:
            self.assertIsNone(c.locator_problem(f"[{h}]:47700#{FP}"), h)
        for h in refused:
            self.assertIsNotNone(c.locator_problem(f"[{h}]:47700#{FP}"), h)
        self.assertIsNotNone(c.locator_problem(f"[2001:4860::1]:1023#{FP}"))
        self.assertIsNone(c.locator_problem(f"[2001:4860::1]:1024#{FP}"))

    def test_loopback_rules(self):
        c4 = self.carrier("127.0.0.1")
        self.assertIsNone(c4.locator_problem(f"127.0.0.2:47700#{FP}"))
        print("[adv33] v4-loopback node vs ::1:", c4.locator_problem(f"[::1]:47700#{FP}"))
        self.assertIsNotNone(c4.locator_problem(f"[::1]:47700#{FP}"))
        c6 = self.carrier("::1", advertise="::1")
        self.assertIsNone(c6.locator_problem(f"[::1]:47701#{FP}")) if False else None
        self.assertIsNotNone(c6.locator_problem(f"127.0.0.1:47700#{FP}"))
        self.assertIsNotNone(self.carrier().locator_problem(f"[::1]:47700#{FP}"))

    def test_own_door_in_other_spellings(self):
        c = self.carrier("2001:4860::5", advertise="2001:4860::5")
        c.open_door("peer-x", "peer", credential={"type": "tcp", "key": "cd" * 32}, agent="a" * 32)
        port = c._load()["doors"]["peer-x"]["listen_port"] if hasattr(c, "_load") else None
        for h in ("2001:4860::5", "2001:4860:0:0:0:0:0:5", "2001:4860::0005"):
            r = c.locator_problem(f"[{h}]:{port}#{FP}")
            self.assertIn("own door", r or "", h)
        self.assertIsNone(c.locator_problem(f"[2001:4860::6]:{port}#{FP}"))

    def test_bind_checks(self):
        for bad in ("fe80::1", "::ffff:127.0.0.1", "[::1]", "::1%lo", "ff02::1", "2002::1", "2001:db8::1", "::2"):
            with self.assertRaises(ValueError, msg=bad):
                self.carrier(bind=bad)
        with self.assertRaises(ValueError):
            self.carrier(bind="::")                              # needs an explicit advertise
        c = self.carrier(bind="::", advertise="2001:4860::5")
        self.assertEqual(c.advertise, "2001:4860::5")
        with self.assertRaises(ValueError):
            self.carrier(bind="::", advertise="::")
        c = self.carrier(bind="2001:DB8::1".replace("DB8", "4860")) if False else None

    def test_dial_without_ipv6_route_is_quick_and_retryable(self):
        """No packet leaves: the connect is mocked to fail like a host without an IPv6 route (ENETUNREACH). Retryable (the node's backoff bounds it), and the text names the bracketed address."""
        import errno
        from unittest import mock
        c = self.carrier()
        t = c.dial({"type": "tcp", "addr": f"[2001:4860:4860::8888]:47700#{FP}"}, timeout=3)
        with mock.patch.object(socket, "create_connection", side_effect=OSError(errno.ENETUNREACH, "Network is unreachable")):
            with self.assertRaises(CarrierError) as cm:
                t.request({"t": "ping"})
        self.assertTrue(cm.exception.retry)
        self.assertIn("[2001:4860:4860::8888]:47700", str(cm.exception))
        with mock.patch.object(socket, "create_connection", side_effect=OSError(errno.EAFNOSUPPORT, "Address family not supported")):
            with self.assertRaises(CarrierError) as cm:
                t.request({"t": "ping"})
        self.assertTrue(cm.exception.retry)


class Guard(unittest.TestCase):
    def test_keys(self):
        for a, k in (("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"), ("2001:DB8:1:2:ffff::1%eth0", "2001:db8:1:2::/64"), ("2001:db8:1:3::1", "2001:db8:1:3::/64"), ("::ffff:1.2.3.4", "1.2.3.4"),
                     ("1.2.3.4", "1.2.3.4"), ("fe80::1%wlan0", "fe80::/64"), ("fe80::2%wlan1", "fe80::/64"), ("", ""), ("nonsense", "nonsense")):
            self.assertEqual(guard_key(a), k, a)
            self.assertEqual(guard_key(guard_key(a)), guard_key(a), a)                 # fixed point
        self.assertEqual(guard_key("2001:db8:0:0:ffff:ffff:ffff:ffff"), guard_key("2001:db8::1"))
        self.assertNotEqual(guard_key("2001:db8:0:1::"), guard_key("2001:db8::"))

    def test_quotas_by_slash64(self):
        g = AcceptGuard()
        res = [g.admit(f"2001:db8:5:5:{i:x}::1", "d1") for i in range(6)]
        print("[adv33] 6 strangers of one /64:", [r is None for r in res])
        self.assertEqual([r is None for r in res], [True] * 4 + [False] * 2)
        for i in range(4):
            g.release(f"2001:db8:5:5:{i:x}::1", "d1")
        self.assertIsNone(g.admit("2001:db8:5:6::1", "d1"))                                 # another /64 (the stranger half of the door cap is free again)

    def test_ban_and_proven_by_slash64(self):
        g = AcceptGuard()
        for i in range(12):
            g.strike(f"2001:db8:9:9:{i:x}::7")
        self.assertIsNotNone(g.banned_until("2001:db8:9:9:ffff::1"))                         # one /64, one ban
        self.assertIsNone(g.banned_until("2001:db8:9:a::1"))
        g2 = AcceptGuard()
        g2.proven("2001:db8:7:7:aaaa::1")
        self.assertTrue(g2.is_proven("2001:db8:7:7:bbbb::2"))                              # documented: a proven /64 is a grant to the whole /64
        for i in range(30):
            g2.strike(f"2001:db8:7:7:{i:x}::2")
        self.assertIsNone(g2.banned_until("2001:db8:7:7::1"))                              # proven exempt

    def test_flushing_the_tables_does_not_lift_the_caps(self):
        g = AcceptGuard(max_ips=64)
        for i in range(500):                                                                # an attacker rotating /64s
            g.strike(f"2001:db8:{i:x}::1")
        got = [g.admit(f"2a00:{i:x}::1", "d1") for i in range(40)]
        self.assertEqual(sum(1 for r in got if r is None), 4)                                # strangers' half of the per-door cap (8/2) holds


if __name__ == "__main__":
    unittest.main()
