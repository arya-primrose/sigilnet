"""tests_adv11 part 1: constructor, formats, credentials, ports, state files (spec R1, R2, R5, A6-A12). Offline, no network."""
import hashlib
import json
import os
import stat
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from sigilnet import carrier as C
from sigilnet.carrier import CarrierError, Secret
from sigilnet.tcplink import TcpCarrier
from sigilnet.tests_adv11.h import Base, AGENT, addr_parts, free_base, spki_fp

FP = "ab" * 32


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


class Ctor(Base):
    def test_class_identity(self):
        self.assertEqual(TcpCarrier.type, "tcp")
        self.assertEqual(self.c.capabilities, frozenset())
        self.assertIsInstance(self.c, C.Carrier)

    def test_bind_and_advertise_rules(self):
        for bad in ("0.0.0.0", "224.0.0.1", "240.0.0.1", "0.1.2.3", "1.2.3", "localhost", "127.0.0.01", "", None, 5, "127.0.0.1 ", "300.1.1.1"):
            with self.subTest(bind=bad):
                with self.assertRaises(ValueError):
                    TcpCarrier(self.tmp / "x", bind=bad, port_base=self.base)
        TcpCarrier(self.tmp / "ok4", bind="127.0.0.1", advertise="8.8.8.8", port_base=self.base)     # M3a: any IPv4
        TcpCarrier(self.tmp / "ok5", bind="8.8.8.8", port_base=self.base)
        TcpCarrier(self.tmp / "ok6", bind="0.0.0.0", advertise="198.51.100.7", port_base=self.base)   # listen everywhere, advertise a host address
        TcpCarrier(self.tmp / "ok1", bind="127.0.0.1", advertise="10.1.2.3", port_base=self.base)
        TcpCarrier(self.tmp / "ok2", bind="172.17.0.4", port_base=self.base)
        TcpCarrier(self.tmp / "ok3", bind="192.168.1.1", port_base=self.base)
        TcpCarrier(self.tmp / "pub", bind="8.8.8.8", port_base=self.base, allow_public=True)        # constructing does not bind
        with self.assertRaises(ValueError):
            TcpCarrier(self.tmp / "z", bind="0.0.0.0", port_base=self.base, allow_public=True)       # never, even with allow_public
        with self.assertRaises(ValueError):
            TcpCarrier(self.tmp / "z", bind="127.0.0.1", advertise="0.0.0.0", port_base=self.base, allow_public=True)

    def test_port_base_range(self):
        for bad in (1023, 0, -5, 64001, 70000, True, "47600", 47600.0, None):
            with self.subTest(pb=bad):
                with self.assertRaises(ValueError):
                    TcpCarrier(self.tmp / "x", bind="127.0.0.1", port_base=bad)
        TcpCarrier(self.tmp / "lo", bind="127.0.0.1", port_base=1024)
        TcpCarrier(self.tmp / "hi", bind="127.0.0.1", port_base=64000)


class Formats(unittest.TestCase):
    def ep(self, addr):
        return C.check_endpoint({"type": "tcp", "addr": addr})

    def test_valid_and_normalized(self):
        self.assertEqual(self.ep(f"10.0.0.1:47600#{FP}")["addr"], f"10.0.0.1:47600#{FP}")
        self.assertEqual(self.ep(f"  10.0.0.1:1#{FP.upper()}  ")["addr"], f"10.0.0.1:1#{FP}")
        self.assertEqual(self.ep(f"0.0.0.0:65535#{FP}")["addr"], f"0.0.0.0:65535#{FP}")        # FORMAT check only: the private rule is the carrier's
        self.assertEqual(self.ep(f"8.8.8.8:80#{FP}")["addr"], f"8.8.8.8:80#{FP}")

    def test_invalid_addresses(self):
        bad = ["", "10.0.0.1:47600", f"10.0.0.1#{FP}", f"10.0.0.1:47600#{FP[:-1]}", f"10.0.0.1:47600#{FP}0", f"10.0.0.1:47600#{'g' * 64}",
               f"10.0.0.01:47600#{FP}", f"10.0.0.1:047600#{FP}", f"10.0.0.1:0#{FP}", f"10.0.0.1:65536#{FP}", f"10.0.0.256:1#{FP}", f"10.0.0:1#{FP}",
               f"10.0.0.1.1:1#{FP}", f"localhost:1#{FP}", f"10.0.0.1:1#{FP}#{FP}", f"10.0.0.1:1:2#{FP}", f"10.0.0.1:-1#{FP}",
               f"١٠.0.0.1:1#{FP}", f"10.0.0.1:١#{FP}", f"10.0.0.1:1#{'٠' * 64}", f"10.0.0.1 :1#{FP}", f"10.0.0.1:1 #{FP}", f"+10.0.0.1:1#{FP}",
               f"10.0.0.1:+1#{FP}", f"10.0.0.1:1e3#{FP}", f"0x0a.0.0.1:1#{FP}", f"10.0.0.1:1#{FP}\x00", f"10.0.0.1:1#{FP}é"]
        for a in bad:
            with self.subTest(addr=a):
                with self.assertRaises(ValueError):
                    self.ep(a)

    def test_endpoint_shape(self):
        with self.assertRaises(ValueError):
            C.check_endpoint({"type": "tcp", "addr": f"10.0.0.1:1#{FP}", "extra": 1})
        self.assertIn("tcp", C.supported_types())

    def test_credential_format(self):
        k = "cd" * 32
        self.assertEqual(C.check_credential({"type": "tcp", "key": k})["key"], k)
        for bad in ("", k[:-1], k + "0", "z" * 64, "٠" * 64):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    C.check_credential({"type": "tcp", "key": bad})
        self.assertIsInstance(C.check_credential({"type": "tcp", "key": k}, secret=True), Secret)


class Credentials(Base):
    def test_shape_and_derivation(self):
        s, p = self.c.new_credential()
        self.assertIsInstance(s, Secret)
        self.assertEqual(set(s), {"type", "key"})
        self.assertEqual(set(p), {"type", "key"})
        self.assertEqual((s["type"], p["type"]), ("tcp", "tcp"))
        C.check_credential(s, secret=True)
        C.check_credential(p)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s["key"]))
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertEqual(p["key"], hashlib.sha256(pub).hexdigest())
        s2, p2 = self.c.new_credential()
        self.assertNotEqual(s["key"], s2["key"])
        self.assertNotIn(s["key"], repr(s) + str(s) + repr([s]) + f"{s}")
        self.assertNotEqual(s["key"], p["key"])

    def test_secret_only_in_held_json_and_never_in_errors(self):
        d = self.c.open_door("p1", "peer", credential=self.c.new_credential()[1])
        ep = self.c.door_endpoint("p1")
        s, _ = self.c.new_credential()
        self.c.use_credential(ep, s)
        texts = []
        for f in (self.tmp / "a").rglob("*"):
            if f.is_file():
                texts.append((f.name, f.read_bytes()))
        hits = [n for n, b in texts if s["key"].encode() in b]
        self.assertEqual(hits, ["held.json"])
        for bad in (lambda: self.c.use_credential(ep, {"type": "tcp", "key": s["key"] + "zz"}), lambda: self.c.use_credential({"type": "tcp", "addr": "x"}, s),
                    lambda: self.c.use_credential(ep, {"type": "tcp", "key": s["key"][:-2]})):
            with self.assertRaises(ValueError) as cm:
                bad()
            self.assertNotIn(s["key"][:32], str(cm.exception))

    def test_held_json_format_normalization_drop(self):
        ep = {"type": "tcp", "addr": f"127.0.0.1:47000#{FP}"}
        s, _ = self.c.new_credential()
        self.c.use_credential(ep, s)
        h = self.tmp / "a" / "held.json"
        self.assertEqual(mode(h), 0o600)
        self.assertEqual(json.loads(h.read_text()), {f"127.0.0.1:47000#{FP}": {"type": "tcp", "key": s["key"]}})
        self.c.use_credential({"type": "tcp", "addr": f"  127.0.0.1:47000#{FP.upper()} "}, s)
        self.assertEqual(len(json.loads(h.read_text())), 1)                      # same key
        other = {"type": "tcp", "addr": f"127.0.0.1:47002#{FP}"}
        self.assertFalse(self.c.drop_credential(other))
        self.assertTrue(self.c.drop_credential({"type": "tcp", "addr": f" 127.0.0.1:47000#{FP.upper()}"}))
        self.assertFalse(self.c.drop_credential(ep))
        self.assertEqual(json.loads(h.read_text()), {})


class Doors(Base):
    def test_ports_and_indices(self):
        ports = [self.c.open_door(f"d{i}", "read") for i in range(3)]
        self.assertEqual(ports, [self.base + 1, self.base + 3, self.base + 5])
        for i in range(3):
            ip, port, fp = addr_parts(self.c.door_endpoint(f"d{i}"))
            self.assertEqual((ip, port), ("127.0.0.1", self.base + 2 * i))
        self.assertEqual(self.c.open_door("d1", "read"), self.base + 3)              # re-open: same port
        self.assertTrue(self.c.close_door("d0"))
        self.assertFalse(self.c.close_door("d0"))
        self.assertEqual(self.c.open_door("d3", "read"), self.base + 7)              # indices are never reused
        self.assertEqual(self.c.open_door("d0", "read"), self.base + 9)              # not even for the same name
        st = json.loads((self.tmp / "a" / "doors.json").read_text())
        self.assertEqual(st["version"], 1)
        self.assertEqual(st["next_index"], 5)
        d = st["doors"]["d1"]
        self.assertEqual(set(d), {"kind", "agent", "index", "listen_port", "loopback_port", "auth", "fp"})
        self.assertEqual((d["index"], d["listen_port"], d["loopback_port"], d["kind"], d["auth"], d["agent"]), (1, self.base + 2, self.base + 3, "read", None, None))

    def test_too_many_doors_boundary(self):
        base = 64000
        c = TcpCarrier(self.tmp / "many", bind="127.0.0.1", port_base=base)
        last = None
        for i in range(768):                       # 2i+1 < 65536-64000 = 1536  <=>  i <= 767
            last = c.open_door(f"n{i}", "read")
        self.assertEqual(last, base + 2 * 767 + 1)
        with self.assertRaises(ValueError):
            c.open_door("n768", "read")
        self.assertIsNone(c.door_endpoint("n768"))
        self.assertTrue(c.door_gone("n768"))

    def test_open_door_validation(self):
        _, pub = self.c.new_credential()
        for name in ("", "A", "a b", "a" * 33, "../x", "a/b", "é", None, 5):
            with self.subTest(name=name), self.assertRaises((ValueError, TypeError) if not isinstance(name, str) and name is not None else ValueError):   # (torlink: TypeError for a non-str name too)
                self.c.open_door(name, "read")
        with self.assertRaises(ValueError):
            self.c.open_door("k", "other")
        with self.assertRaises(ValueError):
            self.c.open_door("k", "read", credential=pub)
        with self.assertRaises(ValueError):
            self.c.open_door("k", "inbox", agent=AGENT)
        with self.assertRaises(ValueError):
            self.c.open_door("k", "peer")
        with self.assertRaises(ValueError):
            self.c.open_door("k", "join")
        for bad in ("a" * 31, "A" * 32, "a" * 33, "1" * 32, ""):
            with self.subTest(agent=bad), self.assertRaises(ValueError):
                self.c.open_door("k", "peer", credential=pub, agent=bad)
        with self.assertRaises(ValueError):
            self.c.open_door("k", "join", credential=pub, agent=AGENT)               # agent only on peer doors
        with self.assertRaises(ValueError):
            self.c.open_door("k", "peer", credential={"type": "onion", "key": pub["key"]})
        with self.assertRaises(ValueError):
            self.c.open_door("k", "peer", credential={"type": "tcp", "key": "xx"})
        self.assertEqual(self.c.doors(), {})
        self.assertTrue(self.c.door_gone("k"))
        self.assertFalse(list((self.tmp / "a").glob("door-k*")))                       # failed opens leave no key file behind

    def test_kind_change_refused_rekey_keeps_identity(self):
        _, p1 = self.c.new_credential()
        port = self.c.open_door("x", "peer", credential=p1, agent=AGENT)
        ep = self.c.door_endpoint("x")
        pem = (self.tmp / "a" / "door-x.pem").read_bytes()
        with self.assertRaises(ValueError):
            self.c.open_door("x", "join", credential=p1)
        with self.assertRaises(ValueError):
            self.c.open_door("x", "read")
        _, p2 = self.c.new_credential()
        self.assertEqual(self.c.open_door("x", "peer", credential=p2), port)
        self.assertEqual(self.c.door_endpoint("x"), ep)                                   # same address and pin
        self.assertEqual((self.tmp / "a" / "door-x.pem").read_bytes(), pem)                # same TLS key
        st = json.loads((self.tmp / "a" / "doors.json").read_text())["doors"]["x"]
        self.assertEqual(st["auth"], p2["key"])
        self.assertEqual(self.c.doors()["x"]["kind"], "peer")

    def test_doors_listing_and_endpoint_before_start(self):
        _, pub = self.c.new_credential()
        port = self.c.open_door("peer-one", "peer", credential=pub, agent=AGENT)
        self.assertEqual(self.c.doors(), {"peer-one": {"kind": "peer", "agent": AGENT, "port": port}})
        self.assertIsNotNone(self.c.door_endpoint("peer-one"))        # no start needed
        self.assertIsNone(self.c.door_endpoint("nope"))
        self.assertIsNone(self.c.shared_endpoint())
        self.assertIsNone(self.c.shared_port())
        self.assertFalse(self.c.healthy())
        C.check_endpoint(self.c.door_endpoint("peer-one"))

    def test_door_state_files(self):
        _, pub = self.c.new_credential()
        self.c.open_door("a1", "peer", credential=pub)
        self.c.open_door("a2", "read")
        a = self.tmp / "a"
        for f in ("doors.json", "door-a1.pem", "door-a2.pem"):
            self.assertEqual(mode(a / f), 0o600, f)
        fps = []
        for n in ("a1", "a2"):
            pem = (a / f"door-{n}.pem").read_bytes()
            key = serialization.load_pem_private_key(pem, None)
            cert = x509.load_pem_x509_certificate(pem)
            self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
            self.assertEqual(key.curve.name, "secp256r1")
            self.assertEqual(spki_fp(cert.public_key()), spki_fp(key.public_key()))
            self.assertEqual(addr_parts(self.c.door_endpoint(n))[2], spki_fp(cert.public_key()))
            self.assertEqual(cert.subject.rfc4514_string(), "CN=sigilnet-tcp")
            self.assertGreaterEqual((cert.not_valid_after_utc - cert.not_valid_before_utc).days, 365 * 99)
            fps.append(spki_fp(cert.public_key()))
        self.assertNotEqual(fps[0], fps[1])
        self.assertEqual(list(a.glob("*.tmp")), [])

    def test_close_removes_key_and_entry_together(self):
        self.c.open_door("g", "read")
        self.assertFalse(self.c.door_gone("g"))
        self.assertTrue(self.c.close_door("g"))
        self.assertTrue(self.c.door_gone("g"))
        self.assertFalse((self.tmp / "a" / "door-g.pem").exists())
        self.assertNotIn("g", json.loads((self.tmp / "a" / "doors.json").read_text())["doors"])
        self.c.open_door("g", "read")
        (self.tmp / "a" / "doors.json").write_text(json.dumps({"version": 1, "next_index": 5, "doors": {}}))
        self.assertFalse(self.c.door_gone("g"))                    # entry gone but the key file is still there: NOT gone
        self.assertIsNone(self.c.door_endpoint("g"))

    def test_fresh_reads_from_file(self):
        c2 = self.mk("a")                                          # a second object over the same state dir (the CLI process)
        port = c2.open_door("shared", "read")
        self.assertEqual(self.c.doors()["shared"]["port"], port)
        self.assertEqual(self.c.door_endpoint("shared"), c2.door_endpoint("shared"))
        c2.close_door("shared")
        self.assertTrue(self.c.door_gone("shared"))
        self.assertEqual(self.c.doors(), {})

    def test_symlink_planted_at_state_files_is_not_followed(self):
        victim = self.tmp / "victim"                                # dangling: a write THROUGH a symlink would create it
        a = self.tmp / "a"
        for n in ("doors.json", "held.json", "door-s.pem"):
            os.symlink(victim, a / n)
        self.c.open_door("s", "read")
        self.c.use_credential({"type": "tcp", "addr": f"127.0.0.1:47000#{FP}"}, self.c.new_credential()[0])
        self.assertFalse(victim.exists())
        for n in ("doors.json", "held.json", "door-s.pem"):
            self.assertFalse((a / n).is_symlink(), n)
            self.assertEqual(mode(a / n), 0o600)


if __name__ == "__main__":
    unittest.main()
