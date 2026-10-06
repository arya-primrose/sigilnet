"""IPv6 on the tcp carrier (DESIGN_ipv6.md rev 0 + rev 1, Sansa's review 58025c1e and her clarification b3895fde). The format and the canonical form, the allow list for announced addresses, `guard_key`
(the ONE keying function of the accept guard: /64 for IPv6), `auto6`, a REAL carrier on ::1 (V6ONLY, the shared conformance suite, a full admission over IPv6), the no-route failure of a v4-only
dialer, the canonical form in every place an address is compared (held.json, the locator book, the notify value, capsules, `peer move`), and the rollback of the PARENT tree (r49n_cleanup) on files
that hold a v6 entry. Only ::1 exists in these containers: nothing here proves a routed IPv6 path."""
import errno
import io
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from sigilnet import capsule as CAP
from sigilnet import carrier as C
from sigilnet import locators as L
from sigilnet import tcplink as TL
from sigilnet.acceptguard import AcceptGuard, guard_key
from sigilnet.carrier import CarrierError
from sigilnet.keys import Identity
from sigilnet.tcp import TcpServer, TcpTransport

from .test_locators import AG, ME, PB, Clock
from .test_tcplink import AGENT, TcpConformance

FP = "ab" * 32
GLOBAL = "2606:4700:4700::1111"
ULA = "fd12:3456:789a::1"


def have_v6_loopback() -> bool:
    try:
        s = socket.socket(socket.AF_INET6)
        try:
            s.bind(("::1", 0))
        finally:
            s.close()
        return True
    except OSError:
        return False


V6 = have_v6_loopback()


def v6_base() -> int:
    """An even port base whose next 20 ports are free on ::1 AND 127.0.0.1 (best effort)."""
    import random
    while True:
        base = random.randrange(30000, 60000, 2)
        socks = []
        try:
            for p in range(base, base + 20):
                for fam, host in ((socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")):
                    s = socket.socket(fam)
                    socks.append(s)
                    s.bind((host, p))
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()


def carrier6(bind="::1", **kw):
    kw.setdefault("port_base", v6_base())
    return TL.TcpCarrier(Path(tempfile.mkdtemp()), bind=bind, **kw)


def ep6(host=ULA, port=47700):
    return {"type": "tcp", "addr": TL.fmt_addr(host, port, FP)}


# ------------------------------------------------------------------------------------------------------------------------------------- the format
class Format(unittest.TestCase):
    def test_a_v6_address_round_trips_in_brackets(self):
        self.assertEqual(TL._split_addr(f"[{ULA}]:47700#{FP}"), (ULA, 47700, FP))
        self.assertEqual(TL._check_addr(f"[{ULA}]:47700#{FP}"), f"[{ULA}]:47700#{FP}")

    def test_v4_is_unchanged(self):
        self.assertEqual(TL._split_addr(f"10.0.0.5:47700#{FP}"), ("10.0.0.5", 47700, FP))
        self.assertEqual(TL._check_addr(f"10.0.0.5:47700#{FP}"), f"10.0.0.5:47700#{FP}")

    def test_spellings_become_one_canonical_form(self):
        for spelling in ("[FD12:3456:789A:0:0:0:0:1]", "[fd12:3456:789a:0000:0000:0000:0000:0001]", "[fd12:3456:789a::0:1]", "[Fd12:3456:789a::1]"):
            self.assertEqual(TL._check_addr(f"{spelling}:47700#{FP}"), f"[{ULA}]:47700#{FP}", spelling)
        self.assertEqual(TL._check_addr(f"[0:0:0:0:0:0:0:1]:47700#{FP.upper()}"), f"[::1]:47700#{FP}")

    def test_the_result_is_a_fixed_point(self):
        a = TL._check_addr(f"[FD12:3456:789A::0001]:47700#{FP}")
        self.assertEqual(TL._check_addr(a), a)

    def test_refused_spellings(self):
        bad = [f"{ULA}:47700#{FP}",                         # no brackets
               f"[{ULA}:47700#{FP}", f"{ULA}]:47700#{FP}", f"[[{ULA}]]:47700#{FP}",
               f"[{ULA}]#{FP}", f"[{ULA}]:#{FP}", f"[{ULA}]47700#{FP}",
               f"[fe80::1%eth0]:47700#{FP}", f"[fe80::1%25eth0]:47700#{FP}",                         # zone ids
               f"[::ffff:1.2.3.4]:47700#{FP}", f"[::ffff:102:304]:47700#{FP}", f"[::1.2.3.4]:47700#{FP}",      # mapped, dotted tail
               f"[1::2::3]:47700#{FP}", f"[1:2:3:4:5:6:7:8:9]:47700#{FP}", f"[12345::1]:47700#{FP}", f"[g::1]:47700#{FP}", "[]:47700#" + FP,
               f"[{ULA}]:0#{FP}", f"[{ULA}]:65536#{FP}", f"[{ULA}]:047700#{FP}", f"[{ULA}]:-1#{FP}",
               f"[{ULA}]:47700", f"[{ULA}]:47700#{FP[:-2]}", f"[{ULA}]:47700#{FP}00", f"[{ULA}]:47700#{'zz' * 32}",
               f"[ {ULA}]:47700#{FP}", f"[{ULA} ]:47700#{FP}"]
        for a in bad:
            with self.assertRaises(ValueError, msg=a):
                TL._split_addr(a)
            with self.assertRaises(ValueError, msg=a):
                C.check_endpoint({"type": "tcp", "addr": a})

    def test_hostnames_and_odd_v4_forms_stay_refused(self):
        for a in ("example.com:47700", "010.0.0.1:47700", "1.2.3:47700", "0x7f.0.0.1:47700", "1.2.3.4.5:47700", "256.1.1.1:47700", "[1.2.3.4]:47700"):
            with self.assertRaises(ValueError, msg=a):
                TL._split_addr(f"{a}#{FP}")

    def test_the_error_text_names_both_families(self):
        with self.assertRaises(ValueError) as cm:
            TL._split_addr("nonsense")
        self.assertIn("ipv4", str(cm.exception))
        self.assertIn("ipv6", str(cm.exception))

    def test_endpoint_helper_brackets_v6_only(self):
        self.assertEqual(TL.endpoint(ULA, 47700, FP), {"type": "tcp", "addr": f"[{ULA}]:47700#{FP}"})
        self.assertEqual(TL.endpoint("10.1.2.3", 47700, FP), {"type": "tcp", "addr": f"10.1.2.3:47700#{FP}"})

    def test_fmt_hostport(self):
        self.assertEqual(TL.fmt_hostport("::1", 5), "[::1]:5")
        self.assertEqual(TL.fmt_hostport("1.2.3.4", 5), "1.2.3.4:5")

    def test_a_v6_address_fits_the_address_limit(self):
        longest = TL._check_addr(f"[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:65535#{FP}")
        self.assertLessEqual(len(longest), C.ADDR_MAX)
        C.check_endpoint({"type": "tcp", "addr": longest})


# ---------------------------------------------------------------------------------------------------------------- bind / advertise (_check_ip)
class CheckIp(unittest.TestCase):
    def test_a_v6_address_is_returned_canonical(self):
        self.assertEqual(TL._check_ip("FD12:3456:789A:0:0:0:0:1", "bind"), ULA)
        self.assertEqual(TL._check_ip("::1", "bind"), "::1")

    def test_global_and_ula_are_accepted(self):
        for ip in (GLOBAL, ULA, "2a00:1450:4001::200e", "fc00::1", "fdff::1"):
            self.assertEqual(TL._check_ip(ip, "bind"), ip)

    def test_the_unspecified_address_needs_an_explicit_advertise(self):
        with self.assertRaises(ValueError) as cm:
            TL._check_ip("::", "bind")
        self.assertIn("EVERY interface", str(cm.exception))
        self.assertEqual(TL._check_ip("::", "bind", allow_any_interface=True), "::")

    def test_refused_v6_addresses(self):
        for ip in ("fe80::1", "ff02::1", "fec0::1", "::ffff:1.2.3.4", "::ffff:102:304", "::1.2.3.4", "64:ff9b::1.2.3.4", "64:ff9b::102:304", "64:ff9b:1::1", "100::1", "2002:102:304::1", "2001::1",
                   "2001:db8::1", "3fff::1", "2001:2::1", "2001:1ff::1", "0::2", "1::1", "4000::1", "e000::1", "fe00::1"):
            with self.assertRaises(ValueError, msg=ip):
                TL._check_ip(ip, "advertise")

    def test_a_dotted_tail_is_refused_even_on_a_global_prefix(self):
        for ip in ("2606:4700:4700::1.2.3.4", "2606:4700::ffff:1.2.3.4", "fd12:3456:789a::1.2.3.4"):
            with self.assertRaises(ValueError, msg=ip):
                TL._check_ip(ip, "bind")
            with self.assertRaises(ValueError, msg=ip):
                TL._canon_v6(ip)

    def test_syntax_garbage_is_refused(self):
        for ip in ("[::1]", "::1%lo", "::g", "1::2::3", ":::", "1:2:3:4:5:6:7:8:9", ":", "::1::"):
            with self.assertRaises(ValueError, msg=ip):
                TL._check_ip(ip, "bind")

    def test_v4_rules_are_unchanged(self):
        self.assertEqual(TL._check_ip("10.1.2.3", "bind"), "10.1.2.3")
        for ip in ("0.0.0.0", "224.0.0.1", "240.0.0.1", "0.1.2.3", "010.0.0.1", "1.2.3"):
            with self.assertRaises(ValueError, msg=ip):
                TL._check_ip(ip, "bind")

    def test_the_carrier_canonicalises_bind_and_advertise(self):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="FD12:3456:789A:0:0:0:0:1", port_base=40000)
        self.assertEqual((c.bind, c.advertise), (ULA, ULA))
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="::", advertise="FD12:3456:789A::1", port_base=40000)
        self.assertEqual((c.bind, c.advertise), ("::", ULA))

    def test_bind_any_without_advertise_is_refused(self):
        with self.assertRaises(ValueError):
            TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="::", port_base=40000)

    def test_an_advertised_address_may_be_the_other_family(self):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="10.0.0.2", advertise=ULA, port_base=40000)
        self.assertEqual(c.advertise, ULA)
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="::", advertise="10.0.0.2", port_base=40000)
        self.assertEqual(c.advertise, "10.0.0.2")


# ------------------------------------------------------------------------------------------------------------- locator_problem (peer-announced)
class Problem(unittest.TestCase):
    def setUp(self):
        self.c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="10.0.0.2", port_base=40000)

    def why(self, host, port=47700, c=None):
        return (c or self.c).locator_problem(TL.fmt_addr(host, port, FP))

    def test_allowed_ranges(self):
        for ip in (GLOBAL, ULA, "2a00:1450::1", "2001:4860:4860::8888", "2400:cb00::1", "2001:200::1", "fc00::1", "fd00:ec2::254", "2620:fe::fe"):
            self.assertIsNone(self.why(ip), ip)

    def test_special_blocks_inside_global_unicast_are_refused(self):
        for ip in ("2001::1", "2001:0:1234::1", "2001:1::1", "2001:1ff:ffff::1", "2001:db8::1", "2001:db8:ffff::1", "2002::1", "2002:c000:204::1", "3fff::1", "3fff:fff::1"):
            self.assertIsNotNone(self.why(ip), ip)

    def test_the_boundaries_of_the_special_blocks(self):
        self.assertIsNone(self.why("2001:200::1"))                  # just above 2001::/23
        self.assertIsNone(self.why("2001:db7::1"))
        self.assertIsNone(self.why("2001:db9::1"))
        self.assertIsNone(self.why("2003::1"))
        self.assertIsNone(self.why("2001:ffff::1"))
        self.assertIsNone(self.why("3ffe::1"))
        self.assertIsNotNone(self.why("4000::1"))                   # outside 2000::/3 altogether
        self.assertIsNotNone(self.why("3fff:fff:ffff::1"))
        self.assertIsNone(self.why("3fff:1000::1"))                 # just above 3fff::/20

    def test_everything_outside_the_allow_list_is_refused(self):
        for ip in ("::", "::2", "::ffff:102:304", "64:ff9b::1", "64:ff9b:1::1", "100::1", "fe80::1", "febf::1", "fec0::1", "ff02::1", "ff00::", "4000::1", "8000::1", "c000::1", "e000::1",
                   "f000::1", "fe00::1"):
            self.assertIsNotNone(self.why(ip), ip)

    def test_reasons_are_stated(self):
        self.assertIn("link-local", self.why("fe80::1"))
        self.assertIn("unspecified or multicast", self.why("ff02::1"))
        self.assertIn("unspecified or multicast", self.why("::"))
        self.assertIn("allowed ranges", self.why("64:ff9b::808:808"))
        self.assertIn("allowed ranges", self.why("2002:808:808::1"))

    def test_v6_loopback_only_when_we_are_bound_on_it(self):
        self.assertIn("loopback", self.why("::1"))
        v6 = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="::1", port_base=40000)
        self.assertIsNone(self.why("::1", c=v6))
        self.assertIn("loopback", self.why("::1", c=TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="127.0.0.1", port_base=40000)))
        self.assertIn("loopback", self.why("::1", c=TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="::", advertise=ULA, port_base=40000)))

    def test_v4_loopback_needs_a_v4_loopback_bind(self):
        a = f"127.0.0.1:47700#{FP}"
        self.assertIn("loopback", self.c.locator_problem(a))
        self.assertIsNone(TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="127.0.0.1", port_base=40000).locator_problem(a))
        self.assertIn("loopback", TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="::1", port_base=40000).locator_problem(a))

    def test_v4_rules_are_unchanged(self):
        for host, frag in (("169.254.169.254", "link-local"), ("224.0.0.1", "multicast"), ("0.1.2.3", "reserved"), ("240.0.0.1", "reserved"), ("255.255.255.255", "reserved"), ("0.0.0.0", "unspecified")):
            self.assertIn(frag, self.why(host), host)
        self.assertIsNone(self.why("10.9.9.9"))
        self.assertIsNone(self.why("8.8.8.8"))

    def test_ports_below_1024_are_refused_in_both_families(self):
        self.assertIn("port below 1024", self.why(GLOBAL, 80))
        self.assertIn("port below 1024", self.why("8.8.8.8", 1023))
        self.assertIsNone(self.why(GLOBAL, 1024))

    def test_one_of_our_own_doors_is_refused_in_any_spelling(self):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="::1", advertise=ULA, port_base=v6_base() if V6 else 40000)
        c.start()
        self.addCleanup(c.stop)
        c.open_door("d1", "peer", credential=c.new_credential()[1])
        c.reconfigure()
        port = c._load()["doors"]["d1"]["listen_port"]
        for spelling in (ULA, "FD12:3456:789A:0:0:0:0:1", "fd12:3456:789a:0000::1"):
            self.assertEqual(c.locator_problem(f"[{spelling}]:{port}#{FP}"), "that is one of our own doors", spelling)
        self.assertIsNone(c.locator_problem(f"[{ULA}]:{port + 1}#{FP}"))

    def test_a_bad_format_is_a_problem_not_an_exception(self):
        for a in ("x", f"[::ffff:1.2.3.4]:5000#{FP}", f"[fe80::1%eth0]:5000#{FP}", f"[{ULA}]:5000"):
            self.assertIsInstance(self.c.locator_problem(a), str)

    def test_thirty_plus_addresses_table(self):
        table = {GLOBAL: True, ULA: True, "2001:db8::1": False, "2001::1": False, "2002::1": False, "3fff::1": False, "fe80::1": False, "ff02::1": False, "::": False, "::1": False,
                 "64:ff9b::1": False, "64:ff9b:1::1": False, "100::1": False, "fec0::1": False, "2a02:6b8::2:242": True, "2606:4700::6810:85e5": True, "fd00::": True, "fcff::1": True,
                 "febf:ffff::1": False, "2000::1": True, "3ffe:ffff::1": True, "2fff::1": True, "2100::1": True, "3000::1": True, "1fff::1": False, "4000::": False, "5555::1": False,
                 "7fff::1": False, "a000::1": False, "fbff::1": False, "fe7f::1": False, "ffff::1": False, "::2": False, "0:1::1": False, "1::": False}
        for ip, ok in table.items():
            self.assertEqual(self.why(ip) is None, ok, ip)
        self.assertGreaterEqual(len(table), 30)


# ----------------------------------------------------------------------------------------------------------------------------------- guard_key
class GuardKey(unittest.TestCase):
    def test_v4_is_the_address_itself(self):
        self.assertEqual(guard_key("10.1.2.3"), "10.1.2.3")
        self.assertNotEqual(guard_key("10.1.2.3"), guard_key("10.1.2.4"))

    def test_v6_is_its_slash_64(self):
        self.assertEqual(guard_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2::/64")
        self.assertEqual(guard_key("2001:db8:1:2::1"), guard_key("2001:db8:1:2:ffff:ffff:ffff:ffff"))
        self.assertNotEqual(guard_key("2001:db8:1:2::1"), guard_key("2001:db8:1:3::1"))

    def test_a_scope_is_stripped(self):
        self.assertEqual(guard_key("fe80::1%eth0"), guard_key("fe80::1"))
        self.assertEqual(guard_key("fe80::1%2"), guard_key("fe80::1%wlan0"))
        self.assertEqual(guard_key("fe80::a:b:c:d%eth0"), "fe80::/64")

    def test_spellings_are_canonicalised(self):
        self.assertEqual(guard_key("2001:DB8:0001:0002:0:0:0:1"), guard_key("2001:db8:1:2::1"))

    def test_a_mapped_form_keys_as_the_v4_address(self):
        self.assertEqual(guard_key("::ffff:1.2.3.4"), "1.2.3.4")
        self.assertEqual(guard_key("::ffff:102:304"), "1.2.3.4")

    def test_the_key_is_its_own_fixed_point(self):
        for a in ("10.1.2.3", "2001:db8:1:2:3:4:5:6", "fe80::1%eth0", "::1", "::ffff:1.2.3.4", "", "garbage"):
            self.assertEqual(guard_key(guard_key(a)), guard_key(a), a)

    def test_non_addresses_pass_through(self):
        self.assertEqual(guard_key(""), "")
        self.assertEqual(guard_key("not-an-address"), "not-an-address")
        self.assertEqual(guard_key("2001:db8::/48"), "2001:db8::/48")                # only a /64 key is rewritten

    def test_a_scope_is_stripped_before_anything_is_parsed(self):
        self.assertEqual(guard_key("1.2.3.4%x"), "1.2.3.4")

    def test_a_non_canonical_slash_64_key_is_normalised(self):
        self.assertEqual(guard_key("2001:DB8:1:2:0:0:0:5/64"), "2001:db8:1:2::/64")
        self.assertEqual(guard_key("2001:db8:1:2::/64"), "2001:db8:1:2::/64")

    def test_an_address_starting_with_zero_is_not_mangled(self):
        self.assertEqual(guard_key("0.1.2.3"), "0.1.2.3")
        self.assertEqual(guard_key("0.0.0.0"), "0.0.0.0")

    def test_odd_input_does_not_raise(self):
        for a in (None, 5, b"x", "::%", "%eth0", "1.2.3.4%x"):
            guard_key(a)


class GuardUsesTheKey(unittest.TestCase):
    """ONE keying function: every table (quotas, strikes, bans, proven, release, queries) goes through it."""

    def setUp(self):
        self.t = [1000.0]
        self.g = AcceptGuard(clock=lambda: self.t[0])

    def test_the_stranger_cap_is_per_slash_64_in_v6(self):
        net = "2001:db8:1:2:"
        for i in range(self.g.per_ip_stranger):
            self.assertIsNone(self.g.admit(f"{net}{i}::1", f"d{i}"))
        self.assertEqual(self.g.admit(f"{net}ffff::9", "dx"), "per-address cap")
        self.assertIsNone(self.g.admit("2001:db8:1:3::1", "dy"))          # another /64: its own quota

    def test_v4_cap_is_still_per_address(self):
        for i in range(self.g.per_ip_stranger):
            self.assertIsNone(self.g.admit("10.0.0.1", f"d{i}"))
        self.assertEqual(self.g.admit("10.0.0.1", "dx"), "per-address cap")
        self.assertIsNone(self.g.admit("10.0.0.2", "dy"))

    def test_release_with_another_spelling_frees_the_same_slot(self):
        for i in range(self.g.per_ip_stranger):
            self.assertIsNone(self.g.admit("2001:db8:1:2::1", "d"))
        self.assertIsNotNone(self.g.admit("2001:db8:1:2::2", "d"))
        self.g.release("2001:DB8:1:2:0:0:0:3", "d")
        self.assertIsNone(self.g.admit("2001:db8:1:2::4", "d"))

    def test_a_link_local_source_with_a_scope_maps_to_the_same_key_everywhere(self):
        for i in range(self.g.per_ip_stranger):
            self.assertIsNone(self.g.admit("fe80::1%eth0", "d"))
        self.assertEqual(self.g.admit("fe80::1", "d"), "per-address cap")
        self.assertEqual(self.g.admit("fe80::1%wlan0", "d"), "per-address cap")
        for _ in range(self.g.strikes_n):
            self.g.strike("fe80::7%eth0")
        self.assertIsNotNone(self.g.banned_until("fe80::9"))
        self.g.proven("fe80::5%eth1")
        self.assertTrue(self.g.is_proven("fe80::1"))
        self.assertTrue(self.g.is_proven("fe80::1%whatever"))

    def test_strikes_ban_a_whole_slash_64(self):
        for i in range(self.g.strikes_n):
            self.g.strike(f"2001:db8:1:2:{i}::1")
        until = self.g.banned_until("2001:db8:1:2::77")
        self.assertIsNotNone(until)
        self.assertEqual(self.g.admit("2001:db8:1:2:9::9", "d"), "banned")
        self.assertIsNone(self.g.banned_until("2001:db8:1:3::1"))
        self.assertIsNone(self.g.admit("2001:db8:1:3::1", "d"))

    def test_proven_is_a_trust_grant_to_the_whole_slash_64(self):
        self.g.proven("2001:db8:1:2:aaaa::1")
        self.assertTrue(self.g.is_proven("2001:db8:1:2:bbbb::2"))                  # the consequence the README states
        for i in range(self.g.strikes_n * 2):
            self.g.strike(f"2001:db8:1:2:{i}::5")
        self.assertIsNone(self.g.banned_until("2001:db8:1:2::1"))                    # exempt from the ban table
        self.assertFalse(self.g.is_proven("2001:db8:1:9::1"))

    def test_proven_gets_the_larger_quota_across_the_slash_64(self):
        g = AcceptGuard(per_door=64, global_cap=256, clock=lambda: self.t[0])
        g.proven("2001:db8:1:2::1")
        got = [g.admit(f"2001:db8:1:2:{i:x}::1", "d") for i in range(40)]
        self.assertEqual(sum(1 for a in got if a is None), g.per_ip_proven)
        self.assertGreater(g.per_ip_proven, g.per_ip_stranger)

    def test_a_successful_admission_clears_strikes_and_bans_of_the_slash_64(self):
        for i in range(self.g.strikes_n):
            self.g.strike(f"2001:db8:1:2:{i}::1")
        self.assertIsNotNone(self.g.banned_until("2001:db8:1:2::1"))
        self.g.proven("2001:db8:1:2:5::5")
        self.assertIsNone(self.g.banned_until("2001:db8:1:2::1"))

    def test_the_tables_hold_keys_not_addresses(self):
        self.g.admit("2001:db8:1:2::1", "d")
        self.g.strike("2001:db8:5:6::1")
        self.g.proven("2001:db8:7:8::1")
        self.assertEqual(set(self.g._ip), {"2001:db8:1:2::/64"})
        self.assertEqual(set(self.g._strikes), {"2001:db8:5:6::/64"})
        self.assertEqual(set(self.g._proven), {"2001:db8:7:8::/64"})

    def test_the_proven_table_on_disk_holds_slash_64_keys_and_reloads(self):
        store = Path(tempfile.mkdtemp()) / "proven.json"
        writes = []

        def writer(path, data):
            writes.append(data)
            path.write_bytes(data)
        t = [1000.0]
        g = AcceptGuard(clock=lambda: t[0], store=store, writer=writer)
        g.proven("2001:db8:7:8:1:2:3:4")
        g.proven("10.1.2.3")
        self.assertEqual(set(json.loads(store.read_text())["proven"]), {"2001:db8:7:8::/64", "10.1.2.3"})
        t[0] += 10
        g2 = AcceptGuard(clock=lambda: t[0], store=store, writer=writer)
        self.assertTrue(g2.is_proven("2001:db8:7:8:9:9:9:9"))
        self.assertTrue(g2.is_proven("10.1.2.3"))
        self.assertFalse(g2.is_proven("2001:db8:7:9::1"))

    def test_an_old_exact_address_entry_on_disk_is_keyed_on_load(self):
        store = Path(tempfile.mkdtemp()) / "proven.json"
        store.write_text(json.dumps({"proven": {"2001:db8:7:8::1": 990.0, "10.1.2.3": 990.0}}))
        g = AcceptGuard(clock=lambda: 1000.0, store=store)
        self.assertTrue(g.is_proven("2001:db8:7:8::ffff"))
        self.assertEqual(set(g._proven), {"2001:db8:7:8::/64", "10.1.2.3"})

    def test_rotating_slash_64s_to_flush_the_tables_does_not_break_the_door_and_global_caps(self):
        g = AcceptGuard(max_ips=16, clock=lambda: self.t[0])
        for i in range(500):
            g.strike(f"2001:db8:{i:x}::1")
        self.assertLessEqual(len(g._strikes), 16)
        admitted = [g.admit(f"2001:db8:{i:x}::1", "door") for i in range(200)]
        self.assertEqual(sum(1 for a in admitted if a is None), max(1, g.per_door - g.reserve_door))      # the per-door cap holds whatever the sources
        g2 = AcceptGuard(max_ips=16, clock=lambda: self.t[0])
        got = [g2.admit(f"2001:db8:{i:x}::1", f"door{i}") for i in range(200)]
        self.assertEqual(sum(1 for a in got if a is None), max(1, g2.global_cap - g2.reserve_global))    # and the global cap
        self.assertLessEqual(len(g2._ip), 200)

    def test_a_flooder_in_one_slash_64_cannot_take_more_than_its_quota(self):
        got = [self.g.admit(f"2001:db8:1:2:{i:x}::1", "d") for i in range(100)]
        self.assertEqual(sum(1 for a in got if a is None), self.g.per_ip_stranger)

    def test_stats_show_no_addresses(self):
        self.g.admit("2001:db8:1:2::1", "d")
        self.assertNotIn("2001", json.dumps(self.g.stats()))


# ---------------------------------------------------------------------------------------------------------------------------- interfaces and auto6
class Auto6(unittest.TestCase):
    def write(self, lines):
        p = Path(tempfile.mkdtemp()) / "if_inet6"
        p.write_text("".join(lines))
        return str(p)

    def test_the_proc_file_is_parsed_into_canonical_text(self):
        p = self.write(["20010db8000000010000000000000002 02 40 00 80 eth0\n", "fe800000000000000000000000000001 02 40 20 80 eth0\n", "00000000000000000000000000000001 01 80 10 80 lo\n"])
        self.assertEqual(TL._interfaces6(p), ["2001:db8:0:1::2", "fe80::1", "::1"])

    def test_tentative_and_dad_failed_addresses_are_skipped(self):
        p = self.write(["20010db8000000010000000000000002 02 40 00 40 eth0\n", "20010db8000000010000000000000003 02 40 00 08 eth0\n", "20010db8000000010000000000000004 02 40 00 80 eth0\n"])
        self.assertEqual(TL._interfaces6(p), ["2001:db8:0:1::4"])

    def test_garbage_lines_and_a_missing_file(self):
        self.assertEqual(TL._interfaces6(self.write(["nonsense\n", "zz 1 2 3 4 x\n", "\n"])), [])
        self.assertEqual(TL._interfaces6("/nonexistent/if_inet6"), [])

    def test_auto6_picks_a_global_address_and_never_a_ula_or_link_local(self):
        got = TL.resolve_bind("auto6", interfaces6=lambda: ["::1", "fe80::1", ULA, GLOBAL, "2001:db8::5", "2002::1"])
        self.assertEqual(got, GLOBAL)
        got = TL.resolve_bind("auto6", interfaces6=lambda: ["2001:db8::5", "2002::1", "2001::7", "3fff::1", "64:ff9b::1", GLOBAL])         # the special blocks inside 2000::/3 are no candidates either
        self.assertEqual(got, GLOBAL)
        with self.assertRaises(ValueError):
            TL.resolve_bind("auto6", interfaces6=lambda: ["2001:db8::5", "2002::1", "2001::7", "3fff::1"])

    def test_auto6_with_no_global_address_is_a_clear_error(self):
        with self.assertRaises(ValueError) as cm:
            TL.resolve_bind("auto6", interfaces6=lambda: ["::1", "fe80::1", ULA])
        self.assertIn("no global IPv6 address", str(cm.exception))
        self.assertIn("--bind", str(cm.exception))
        with self.assertRaises(ValueError):
            TL.resolve_bind("auto6", interfaces6=lambda: [])

    def test_auto6_prefers_the_address_the_route_to_a_peer_uses(self):
        other = "2a00:1450::5"
        route = lambda dest: other if dest == "2a00:1450::99" else GLOBAL      # noqa: E731
        got = TL.resolve_bind("auto6", hints=["10.0.0.1", "2a00:1450::99"], interfaces6=lambda: [GLOBAL, other], route=route)
        self.assertEqual(got, other)
        self.assertEqual(TL.resolve_bind("auto6", hints=["10.0.0.1"], interfaces6=lambda: [GLOBAL, other], route=route), GLOBAL)

    def test_auto_stays_ipv4_only(self):
        self.assertEqual(TL.resolve_bind("auto", interfaces=lambda: ["10.0.0.9"], route=lambda d: None), "10.0.0.9")
        with self.assertRaises(ValueError):
            TL.resolve_bind("auto", interfaces=lambda: [], route=lambda d: None)

    def test_auto_ignores_v6_hints(self):
        calls = []
        TL.resolve_bind("auto", hints=[GLOBAL, "10.0.0.1"], interfaces=lambda: ["10.0.0.9", "192.168.1.2"], route=lambda d: calls.append(d) or "192.168.1.2")
        self.assertEqual(calls, ["10.0.0.1"])

    def test_a_literal_address_is_returned_as_is(self):
        self.assertEqual(TL.resolve_bind("::1"), "::1")
        self.assertEqual(TL.resolve_bind("10.1.2.3"), "10.1.2.3")

    @unittest.skipUnless(V6, "no IPv6 loopback")
    def test_the_route_helper_picks_the_family_of_the_destination(self):
        self.assertEqual(TL._route_ip("::1"), "::1")
        self.assertEqual(TL._route_ip("127.0.0.1"), "127.0.0.1")

    def test_the_node_asks_again_before_a_restart_for_both_auto_forms(self):
        from sigilnet import noderun
        for mode in ("auto", "auto6"):
            cfg = {"carrier": "tcp", "carriers": ["tcp"], "tcp": {"bind": mode, "port_base": 40000, "advertise": ULA if mode == "auto6" else None}}
            if cfg["tcp"]["advertise"] is None:
                del cfg["tcp"]["advertise"]
            home = Path(tempfile.mkdtemp())
            with mock.patch.object(noderun, "resolve_bind", return_value=ULA if mode == "auto6" else "10.0.0.9"):
                c = noderun._build_carrier(home, cfg, "tcp")
            self.assertIsNotNone(c._resolver, mode)


# ----------------------------------------------------------------------------------------------------------------------- a REAL carrier on ::1
@unittest.skipUnless(V6, "no IPv6 loopback")
class TcpConformance6(TcpConformance):
    """The whole conformance suite and the carrier tests of the IPv4 carrier, on ::1."""

    def make(self):
        c = carrier6()
        c.start()
        self.addCleanup(c.stop)
        return c

    def other_endpoint(self):
        return {"type": "tcp", "addr": f"[::1]:47999#{FP}"}


@unittest.skipUnless(V6, "no IPv6 loopback")
class RealV6(unittest.TestCase):
    def setUp(self):
        self.servers = []
        self.addCleanup(lambda: [s.stop() for s in self.servers])

    def serve(self, port):
        s = TcpServer("127.0.0.1", port, None, lambda req: {"t": "pong", "echo": req.get("n")}).start()
        self.servers.append(s)
        return s

    def door(self, c, name="d1"):
        bob = carrier6()
        secret, pub = bob.new_credential()
        port = c.open_door(name, "peer", credential=pub)
        self.serve(port)
        c.reconfigure()
        ep = c.door_endpoint(name)
        bob.use_credential(ep, secret)
        return bob, ep

    def test_the_door_endpoint_is_a_bracketed_canonical_address(self):
        c = carrier6()
        c.start()
        self.addCleanup(c.stop)
        c.open_door("d1", "peer", credential=c.new_credential()[1])
        c.reconfigure()
        ep = c.door_endpoint("d1")
        self.assertTrue(ep["addr"].startswith("[::1]:"), ep)
        self.assertEqual(C.check_endpoint(ep), ep)

    def test_a_v6_client_does_the_full_admission_and_a_request(self):
        c = carrier6()
        c.start()
        self.addCleanup(c.stop)
        bob, ep = self.door(c)
        self.assertEqual(bob.dial(ep, timeout=5).request({"t": "ping", "n": 41}), {"t": "pong", "echo": 41})

    def test_the_listening_socket_is_v6_only(self):
        c = carrier6()
        c.start()
        self.addCleanup(c.stop)
        _, ep = self.door(c)
        _, port, _ = TL._split_addr(ep["addr"])
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2)                  # the same port on IPv4: nothing listens
        s = socket.create_connection(("::1", port), timeout=2)
        s.close()
        ls = next(iter(c._listeners.values()))["sock"]
        self.assertEqual(ls.family, socket.AF_INET6)
        self.assertEqual(ls.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY), 1)

    def test_bind_any_with_an_advertise_address_listens_on_v6_only(self):
        c = carrier6(bind="::", advertise="::1")
        c.start()
        self.addCleanup(c.stop)
        bob, ep = self.door(c)
        self.assertEqual(bob.dial(ep, timeout=5).request({"t": "ping", "n": 1})["echo"], 1)
        _, port, _ = TL._split_addr(ep["addr"])
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2)

    def test_a_v4_carrier_still_listens_on_v4_only(self):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="127.0.0.1", port_base=v6_base())
        c.start()
        self.addCleanup(c.stop)
        c.open_door("d1", "peer", credential=c.new_credential()[1])
        c.reconfigure()
        _, port, _ = TL._split_addr(c.door_endpoint("d1")["addr"])
        ls = next(iter(c._listeners.values()))["sock"]
        self.assertEqual(ls.family, socket.AF_INET)
        with self.assertRaises(OSError):
            socket.create_connection(("::1", port), timeout=2)

    def test_a_wrong_key_over_v6_is_refused_and_struck_by_slash_64(self):
        c = carrier6()
        c.start()
        self.addCleanup(c.stop)
        bob, ep = self.door(c)
        eve = carrier6()
        eve.use_credential(ep, eve.new_credential()[0])
        with self.assertRaises(CarrierError):
            eve.dial(ep, timeout=3).request({"t": "ping", "n": 2})
        t0 = time.time()
        while c.guard.counts["strikes"] < 1 and time.time() - t0 < 5:
            time.sleep(0.05)
        self.assertGreaterEqual(c.guard.counts["strikes"], 1)
        self.assertEqual(set(c.guard._strikes), {"::/64"})                             # ::1 keys as its /64

    def test_an_admitted_v6_peer_is_proven_by_its_slash_64(self):
        c = carrier6()
        c.start()
        self.addCleanup(c.stop)
        bob, ep = self.door(c)
        bob.dial(ep, timeout=5).request({"t": "ping", "n": 3})
        self.assertTrue(c.guard.is_proven("::1"))
        self.assertTrue(c.guard.is_proven("::2"))
        self.assertEqual(set(c.guard._proven), {"::/64"})

    def test_the_guard_slot_is_released_on_every_path(self):
        c = carrier6()
        c.start()
        self.addCleanup(c.stop)
        bob, ep = self.door(c)
        for n in range(3):
            bob.dial(ep, timeout=5).request({"t": "ping", "n": n})
        t0 = time.time()
        while c._unauth and time.time() - t0 < 5:
            time.sleep(0.05)
        self.assertEqual(c._unauth, 0)
        self.assertEqual(c.guard._ip, {})

    def test_the_address_book_round_trip_keys_credentials_by_canonical_address(self):
        c = carrier6()
        c.start()
        self.addCleanup(c.stop)
        bob, ep = self.door(c)
        spelled = {"type": "tcp", "addr": ep["addr"].replace("[::1]", "[0:0:0:0:0:0:0:1]")}
        self.assertTrue(bob.has_credential(spelled))
        self.assertEqual(set(json.loads((bob.dir / "held.json").read_text())), {ep["addr"]})


@unittest.skipUnless(V6, "no IPv6 loopback")
class EndToEnd6(unittest.TestCase):
    def test_the_whole_protocol_runs_over_ipv6(self):
        """Capsule join (v6 endpoints in the capsule), encrypted thread, posts both ways, removal with key rotation, closed door: the script that runs over the fake carrier and over tcp on 127.0.0.1."""
        from sigilnet.tests import fake_e2e

        def factory(name, state_dir):
            return TL.TcpCarrier(state_dir, bind="::1", port_base=v6_base())
        self.assertEqual(fake_e2e.run(factory), "E2E OK")


# ----------------------------------------------------------------------------------------------------------- no route: a v4-only dialer
class NoRoute(unittest.TestCase):
    def dial(self, addr, err):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="127.0.0.1", port_base=40000)
        secret, _ = c.new_credential()
        ep = {"type": "tcp", "addr": addr}
        c.use_credential(ep, secret)
        with mock.patch.object(TL.socket, "create_connection", side_effect=OSError(err, os.strerror(err))):
            with self.assertRaises(CarrierError) as cm:
                c.dial(ep, timeout=3).request({"t": "ping"})
        return cm.exception

    def test_no_route_to_a_v6_endpoint_is_a_clean_retryable_failure(self):
        """Sansa's review: the failure is instant and local (no packet leaves), so it is retryable: the node's ordinary backoff bounds it, and an interface that comes up later (boot) is used."""
        for err in (errno.ENETUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            e = self.dial(f"[{GLOBAL}]:47700#{FP}", err)
            self.assertTrue(e.retry, os.strerror(err))
            self.assertIn(f"[{GLOBAL}]:47700", str(e))
            self.assertIn(os.strerror(err), str(e))

    def test_the_same_errors_for_a_v4_endpoint_stay_retryable(self):
        for err in (errno.ENETUNREACH, errno.EAFNOSUPPORT):
            self.assertTrue(self.dial(f"8.8.8.8:47700#{FP}", err).retry)

    def test_an_ordinary_refusal_by_a_v6_peer_is_retryable(self):
        self.assertTrue(self.dial(f"[{GLOBAL}]:47700#{FP}", errno.ECONNREFUSED).retry)
        self.assertTrue(self.dial(f"[{GLOBAL}]:47700#{FP}", errno.EHOSTUNREACH).retry)

    @unittest.skipUnless(V6, "no IPv6 loopback")
    def test_a_real_dial_to_a_closed_v6_port_is_refused_and_retryable(self):
        c = carrier6()
        ep = {"type": "tcp", "addr": f"[::1]:{v6_base()}#{FP}"}
        c.use_credential(ep, c.new_credential()[0])
        with self.assertRaises(CarrierError) as cm:
            c.dial(ep, timeout=3).request({"t": "ping"})
        self.assertTrue(cm.exception.retry)
        self.assertIn("[::1]:", str(cm.exception))


# ---------------------------------------------------------------------------------------------------- canonical form in the places an address is compared
class Canonical(unittest.TestCase):
    SPELL = f"[FD12:3456:789A:0:0:0:0:1]:47700#{FP.upper()}"
    CANON = f"[{ULA}]:47700#{FP}"

    def test_held_json_is_keyed_by_the_canonical_form(self):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="10.0.0.2", port_base=40000)
        secret, _ = c.new_credential()
        c.use_credential({"type": "tcp", "addr": self.SPELL}, secret)
        self.assertEqual(set(json.loads(c.held_file.read_text())), {self.CANON})
        self.assertTrue(c.has_credential({"type": "tcp", "addr": self.CANON}))
        self.assertTrue(c.has_credential({"type": "tcp", "addr": f"[fd12:3456:789a::1]:47700#{FP}"}))
        self.assertTrue(c.drop_credential({"type": "tcp", "addr": f"[fd12:3456:789a:0::1]:47700#{FP}"}))
        self.assertFalse(c.has_credential({"type": "tcp", "addr": self.CANON}))

    def test_index_credentials_canonicalises_the_address(self):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="10.0.0.2", port_base=40000)
        secret, _ = c.new_credential()
        c.use_credential({"type": "tcp", "addr": self.CANON}, secret)
        self.assertEqual(c.index_credentials([(AGENT, self.SPELL)]), 1)
        self.assertIn("agent:" + AGENT, json.loads(c.held_file.read_text()))

    def test_the_locator_book_stores_and_compares_the_canonical_form(self):
        b = L.LocatorBook(Path(tempfile.mkdtemp()) / "locators" / "tcp.json", "tcp", clock=Clock())
        b.seed(AG, self.SPELL)
        b.seed(AG, self.CANON)
        self.assertEqual(b.ordered(AG), [self.CANON])
        raw = json.loads(b.path.read_text())["peers"][AG]
        self.assertEqual([l["addr"] for l in raw["locs"]], [self.CANON])
        b.set_notify(AG, self.SPELL)
        self.assertEqual(b.notify_addr(AG), self.CANON)
        self.assertFalse(b.set_notify(AG, self.CANON))                                  # the same value in another spelling: no write

    def test_a_file_with_a_non_canonical_spelling_reads_canonical(self):
        b = L.LocatorBook(Path(tempfile.mkdtemp()) / "locators" / "tcp.json", "tcp", clock=Clock())
        b.path.write_text(json.dumps({"v": 1, "peers": {AG: {"locs": [{"addr": self.SPELL}, {"addr": self.CANON}], "notify": {"addr": self.SPELL}, "ndrop": {"addr": self.SPELL, "until": 5e9}}}}))
        self.assertEqual(b.ordered(AG), [self.CANON])
        self.assertEqual(b.notify_addr(AG), self.CANON)
        self.assertTrue(b.notify_dropped(AG, self.CANON))

    def service(self):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="10.0.0.2", port_base=40000)
        b = L.LocatorBook(Path(tempfile.mkdtemp()) / "locators" / "tcp.json", "tcp", clock=Clock())
        clock = Clock()
        svc = L.LocatorService(ME, PB((AG,)), c, b, L.PeerDialer(c, b, request_timeout=5, connect_timeout=5), clock=clock)
        return svc, b, c, clock

    def test_an_announcement_in_another_spelling_of_a_held_address_is_nothing_new(self):
        svc, b, c, clock = self.service()
        b.seed(AG, self.CANON)
        self.assertEqual(svc.on_locator(AG, self.SPELL, 100), "ok")
        self.assertNotIn(AG, svc._pending)

    def test_the_notify_value_already_held_is_recognised_in_any_spelling(self):
        svc, b, c, clock = self.service()
        b.set_notify(AG, self.CANON)
        self.assertEqual(svc.on_notify_at(AG, {"type": "tcp", "addr": self.SPELL}), "ok")
        self.assertNotIn(AG, svc._npending)                                              # nothing was queued: it was already held
        self.assertNotIn(AG, svc._nseen)

    def test_a_dropped_notify_value_is_ignored_in_any_spelling(self):
        svc, b, c, clock = self.service()
        b.set_notify(AG, self.CANON)
        for _ in range(L.NOTIFY_FAILS):
            b.note_notify(AG, self.CANON, False)
        self.assertEqual(svc.on_notify_at(AG, {"type": "tcp", "addr": self.SPELL}), "ignored")
        self.assertEqual(svc.on_notify_at(AG, {"type": "tcp", "addr": f"[{GLOBAL}]:47701#{FP}"}), "ok")

    def test_a_new_v6_notify_value_is_checked_by_the_same_rules(self):
        svc, b, c, clock = self.service()
        for bad, frag in ((f"[fe80::1]:47700#{FP}", "refused"), (f"[::1]:47700#{FP}", "refused"), (f"[2001:db8::1]:47700#{FP}", "refused"), (f"[64:ff9b::808:808]:47700#{FP}", "refused"),
                          (f"[{ULA}]:80#{FP}", "refused"), (f"[{ULA}]:47700", "bad address"), (f"[::ffff:1.2.3.4]:47700#{FP}", "bad address")):
            self.assertTrue(svc.on_notify_at(AG, {"type": "tcp", "addr": bad}).startswith(frag), bad)
            clock.t += 100
        self.assertEqual(svc.on_notify_at(AG, {"type": "tcp", "addr": self.SPELL}), "ok")
        self.assertEqual(svc._npending[AG], self.CANON)

    def test_the_peer_book_keeps_a_canonical_v6_endpoint_and_equality_uses_it(self):
        from sigilnet.node import PeerBook
        pb = PeerBook(Path(tempfile.mkdtemp()) / "peers.json")
        pb.add(AG, "sansa", {"type": "tcp", "addr": self.CANON})
        rec = pb.all()[AG]
        self.assertEqual(rec["endpoint"], {"type": "tcp", "addr": self.CANON})
        self.assertEqual(C.check_endpoint({"type": "tcp", "addr": self.SPELL}), rec["endpoint"])

    def test_a_non_canonical_stored_endpoint_is_left_out_of_the_view_not_fatal(self):
        from sigilnet.node import PeerBook
        path = Path(tempfile.mkdtemp()) / "peers.json"
        path.write_text(json.dumps({"peers": {AG: {"name": "x", "endpoints": [{"type": "tcp", "addr": self.SPELL}], "threads": []}}}))
        rec = PeerBook(path).all()[AG]
        self.assertEqual(rec["endpoints"], [])                                           # (the same rule as for v4: only canonical text is a good endpoint)

    def test_a_capsule_offer_with_a_v6_endpoint_passes_the_same_check(self):
        c = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="10.0.0.2", port_base=40000)
        cr = c.new_credential()[1]
        svc = CAP.JoinServer.__new__(CAP.JoinServer)
        svc.by_type = {"tcp": c}
        ok = svc.offers_problem([{"endpoint": {"type": "tcp", "addr": self.SPELL}, "credential": cr}], ["tcp"])
        self.assertIsNone(ok)
        for bad in (f"[fe80::1]:47700#{FP}", f"[::1]:47700#{FP}", f"[::ffff:1.2.3.4]:47700#{FP}"):
            self.assertIsNotNone(svc.offers_problem([{"endpoint": {"type": "tcp", "addr": bad}, "credential": cr}], ["tcp"]), bad)


class CliPieces(unittest.TestCase):
    def run_cli(self, *args):
        from sigilnet import cli
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = cli.main(list(args))
            except SystemExit as e:
                rc = e.code if not isinstance(e.code, int) else e.code
        return rc, out.getvalue(), err.getvalue()

    def test_pull_refuses_a_v6_host_clearly(self):
        home = Path(tempfile.mkdtemp())
        self.assertEqual(self.run_cli("--home", str(home), "id", "init", "arya")[0], 0)
        kf = home / "k.key"
        self.assertEqual(self.run_cli("--home", str(home), "key", "new", "--file", str(kf))[0], 0)
        for peer in ("[::1]:47100", "::1:47100", "[fd00::1]:5"):
            rc, out, err = self.run_cli("--home", str(home), "sync", "pull", peer, "--key-file", str(kf))
            self.assertIn("does not take IPv6 hosts", str(rc) + out + err, peer)

    def test_free_range_probes_the_right_family(self):
        from sigilnet.cli import _free_range
        if V6:
            base = _free_range(41000, 4, ["::1", "127.0.0.1"])
            self.assertGreaterEqual(base, 41000)
        self.assertGreaterEqual(_free_range(42000, 4, ["127.0.0.1"]), 42000)

    def home_with_a_v4_peer(self):
        home = Path(tempfile.mkdtemp())
        os.chmod(home, 0o700)
        Identity.generate("me").save(home / "identity.json")
        (home / "node_config.json").write_text(json.dumps({"carrier": "tcp", "tcp": {"bind": "10.0.0.2", "port_base": 40000}}))
        self.peer = Identity.generate("b")
        (home / "peers.json").write_text(json.dumps({"peers": {self.peer.id: {"name": "b", "endpoints": [{"type": "tcp", "addr": f"10.0.0.5:47700#{FP}"}], "threads": []}}}))
        return home

    def endpoints(self, home):
        return json.loads((home / "peers.json").read_text())["peers"][self.peer.id]["endpoints"]

    def test_peer_move_ip_takes_a_v6_address_with_or_without_brackets_and_stores_it_canonical(self):
        for given in ("FD12:3456:789A:0:0:0:0:1", "[fd12:3456:789a::1]", ULA):
            home = self.home_with_a_v4_peer()
            rc, out, err = self.run_cli("--home", str(home), "peer", "move", "b", "--ip", given, "--no-verify")
            self.assertEqual(rc, 0, (given, out, err))
            self.assertEqual(self.endpoints(home), [{"type": "tcp", "addr": f"[{ULA}]:47700#{FP}"}], given)

    def test_peer_move_ip_refuses_a_mapped_or_scoped_address(self):
        for given in ("::ffff:1.2.3.4", "fe80::1%eth0", "1::2::3"):
            home = self.home_with_a_v4_peer()
            rc, out, err = self.run_cli("--home", str(home), "peer", "move", "b", "--ip", given, "--no-verify")
            self.assertNotEqual(rc, 0, given)
            self.assertEqual(self.endpoints(home), [{"type": "tcp", "addr": f"10.0.0.5:47700#{FP}"}], given)

    def test_peer_move_from_v6_back_to_v4_keeps_the_port_and_fingerprint(self):
        home = self.home_with_a_v4_peer()
        self.run_cli("--home", str(home), "peer", "move", "b", "--ip", ULA, "--no-verify")
        rc, out, err = self.run_cli("--home", str(home), "peer", "move", "b", "--ip", "10.9.9.9", "--no-verify")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.endpoints(home), [{"type": "tcp", "addr": f"10.9.9.9:47700#{FP}"}])

    def test_peer_move_with_an_endpoint_in_brackets(self):
        home = self.home_with_a_v4_peer()
        rc, out, err = self.run_cli("--home", str(home), "peer", "move", "b", "--endpoint", f"tcp:[FD12:3456:789A::1]:47800#{FP}", "--no-verify")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.endpoints(home), [{"type": "tcp", "addr": f"[{ULA}]:47800#{FP}"}])

    def init(self, *args):
        home = Path(tempfile.mkdtemp()) / "h"
        rc, out, err = self.run_cli("--home", str(home), "init", "arya", "--carrier", "tcp", *args)
        return home, rc, out, err

    def test_init_with_a_v6_bind_writes_it_and_finds_a_free_range(self):
        if not V6:
            self.skipTest("no IPv6 loopback")
        home, rc, out, err = self.init("--bind", "::1")
        self.assertEqual(rc, 0, err)
        cfg = json.loads((home / "node_config.json").read_text())["tcp"]
        self.assertEqual(cfg["bind"], "::1")
        self.assertGreaterEqual(cfg["port_base"], 47600)

    def test_init_with_auto6_and_no_global_address_is_a_clear_error(self):
        with mock.patch("sigilnet.tcplink._interfaces6", return_value=["::1", "fe80::1"]):
            home, rc, out, err = self.init("--bind", "auto6")
        self.assertNotEqual(rc, 0)
        self.assertIn("no global IPv6 address", err + out + str(rc))
        self.assertFalse((home / "node_config.json").exists())

    def test_init_bind_any_needs_an_advertise_address_and_listens_v6_only_probing(self):
        if not V6:
            self.skipTest("no IPv6 loopback")
        home, rc, out, err = self.init("--bind", "::")
        self.assertNotEqual(rc, 0)
        self.assertIn("EVERY interface", err + out + str(rc))
        home, rc, out, err = self.init("--bind", "::", "--advertise", "::1")
        self.assertEqual(rc, 0, err)                                    # (the v6 probe is V6ONLY: it does not collide with the v4 probe of the same port)
        self.assertEqual(json.loads((home / "node_config.json").read_text())["tcp"], {"bind": "::", "port_base": json.loads((home / "node_config.json").read_text())["tcp"]["port_base"], "advertise": "::1"})


# ------------------------------------------------------------------------------------------------ rollback: the PARENT tree on files with a v6 entry
PARENT_TAG = "r49n_cleanup"


def parent_tree():
    """The tree this one was built on (the m4b code that is deployed), exported with git into a temp directory; None if git or the tag is not available."""
    root = Path(__file__).resolve().parents[2]
    d = Path(tempfile.mkdtemp(prefix="sn_parent_"))
    try:
        tar = subprocess.run(["git", "-C", str(root), "archive", PARENT_TAG], capture_output=True, timeout=60)
        if tar.returncode != 0:
            shutil.rmtree(d, True)
            return None
        subprocess.run(["tar", "-x", "-C", str(d)], input=tar.stdout, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        shutil.rmtree(d, True)
        return None
    return d


class Rollback(unittest.TestCase):
    """Sansa d): a node rolled back to the m4b tree (no v6) that finds a v6 address in its peer book, locator book, held.json or proven.json must START and ignore it, never crash."""

    @classmethod
    def setUpClass(cls):
        cls.tree = parent_tree()
        if cls.tree is None:
            raise unittest.SkipTest("the parent tree is not available (git archive)")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "tree", None):
            shutil.rmtree(cls.tree, True)

    def run_old(self, code: str, home: Path) -> subprocess.CompletedProcess:
        env = dict(os.environ, PYTHONPATH=str(self.tree), HOME=str(home))
        return subprocess.run([sys.executable, "-c", textwrap.dedent(code), str(home)], env=env, capture_output=True, text=True, timeout=120, cwd=str(home))

    def home_with_v6_entries(self):
        home = Path(tempfile.mkdtemp())
        os.chmod(home, 0o700)
        a = f"[{ULA}]:47700#{FP}"
        (home / "peers.json").write_text(json.dumps({"peers": {AG: {"name": "sansa", "endpoints": [{"type": "tcp", "addr": a}], "threads": []}}}))
        (home / "locators").mkdir(mode=0o700)
        (home / "locators" / "tcp.json").write_text(json.dumps({"v": 1, "peers": {AG: {"locs": [{"addr": a}], "notify": {"addr": a}, "ndrop": {"addr": a, "until": 5e9}, "announced": a}}}))
        tcp = home / "tcp"
        tcp.mkdir(mode=0o700)
        (tcp / "held.json").write_text(json.dumps({a: {"type": "tcp", "key": "cd" * 32}, "agent:" + AG: {"type": "tcp", "key": "cd" * 32}}))
        (tcp / "proven.json").write_text(json.dumps({"proven": {"2001:db8:7:8::/64": time.time(), "10.1.2.3": time.time()}}))
        return home, a

    def test_the_old_tree_is_really_the_old_one(self):
        r = self.run_old("""
            from sigilnet import tcplink as T
            try:
                T._check_addr("[fd12::1]:47700#" + "ab" * 32)
                print("ACCEPTED")
            except ValueError as e:
                print("REFUSED", e)
        """, Path(tempfile.mkdtemp()))
        self.assertIn("REFUSED", r.stdout, r.stderr)

    def test_peer_book_keeps_the_peer_and_leaves_the_v6_endpoint_out(self):
        home, a = self.home_with_v6_entries()
        r = self.run_old("""
            import sys, json
            from pathlib import Path
            from sigilnet.node import PeerBook
            home = Path(sys.argv[1])
            rec = PeerBook(home / "peers.json").all()
            print(json.dumps({k: v["endpoints"] for k, v in rec.items()}))
        """, home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {AG: []})                                  # the peer stays, the endpoint is left out
        self.assertEqual(json.loads((home / "peers.json").read_text())["peers"][AG]["endpoints"][0]["addr"], a)       # the file keeps it

    def test_locator_book_drops_the_v6_values_without_crashing(self):
        home, a = self.home_with_v6_entries()
        r = self.run_old("""
            import sys
            from pathlib import Path
            from sigilnet import tcplink  # registers the tcp type
            from sigilnet.locators import LocatorBook
            home = Path(sys.argv[1])
            b = LocatorBook(home / "locators" / "tcp.json", "tcp")
            AG = %r
            print(b.ordered(AG), b.notify_addr(AG), b.count(AG), b.notify_dropped(AG, "x"))
        """ % AG, home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "[] None 0 False")

    def test_held_json_with_v6_keys_is_just_a_dict_and_has_credential_says_no(self):
        home, a = self.home_with_v6_entries()
        r = self.run_old("""
            import sys
            from pathlib import Path
            from sigilnet.tcplink import TcpCarrier
            home = Path(sys.argv[1])
            c = TcpCarrier(home / "tcp", bind="127.0.0.1", port_base=40000)
            print(sorted(c._held()), c.has_credential({"type": "tcp", "addr": %r}), c.has_credential({"type": "tcp", "addr": "10.0.0.1:47700#" + "ab" * 32}, agent=%r))
        """ % (a, AG), home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("False True", r.stdout)                                           # the v6 address: no; by node id: yes (the credential is still usable for a v4 address of that peer)

    def test_proven_json_with_slash_64_keys_loads(self):
        home, a = self.home_with_v6_entries()
        r = self.run_old("""
            import sys, time
            from pathlib import Path
            from sigilnet.tcplink import TcpCarrier
            home = Path(sys.argv[1])
            c = TcpCarrier(home / "tcp", bind="127.0.0.1", port_base=40000)
            print(c.guard.is_proven("10.1.2.3"), c.guard.is_proven("2001:db8:7:8::1"))
            c.guard.admit("2001:db8:7:8::1", "d"); c.guard.proven("10.9.9.9")
        """, home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("True "), r.stdout)

    def test_a_capsule_offer_with_a_v6_endpoint_is_refused_cleanly(self):
        r = self.run_old("""
            from sigilnet import tcplink
            from sigilnet.carrier import check_endpoint
            try:
                check_endpoint({"type": "tcp", "addr": "[%s]:47700#%s"})
                print("ACCEPTED")
            except ValueError as e:
                print("REFUSED")
        """ % (ULA, FP), Path(tempfile.mkdtemp()))
        self.assertEqual(r.stdout.strip(), "REFUSED", r.stderr)

    def test_a_v6_bind_in_the_config_is_a_clean_startup_error_not_a_crash(self):
        r = self.run_old("""
            from pathlib import Path
            import tempfile
            from sigilnet.tcplink import TcpCarrier
            try:
                TcpCarrier(Path(tempfile.mkdtemp()), bind="::1", port_base=40000)
                print("STARTED")
            except ValueError as e:
                print("VALUEERROR", e)
        """, Path(tempfile.mkdtemp()))
        self.assertIn("VALUEERROR", r.stdout, r.stderr)

    def test_the_new_tree_reads_the_old_files_with_v4_entries_unchanged(self):
        home = Path(tempfile.mkdtemp())
        a = f"10.0.0.5:47700#{FP}"
        (home / "tcp").mkdir(mode=0o700)
        (home / "tcp" / "held.json").write_text(json.dumps({a: {"type": "tcp", "key": "cd" * 32}}))
        (home / "tcp" / "proven.json").write_text(json.dumps({"proven": {"10.1.2.3": time.time()}}))
        c = TL.TcpCarrier(home / "tcp", bind="10.0.0.2", port_base=40000)
        self.assertTrue(c.has_credential({"type": "tcp", "addr": a}))
        self.assertTrue(c.guard.is_proven("10.1.2.3"))


if __name__ == "__main__":
    unittest.main()
