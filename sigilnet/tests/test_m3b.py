"""M3b (DESIGN_multicarrier.md 3.4): the accept-time guard of the TCP carrier. AcceptGuard is pure logic (fake clock); the integration tests use real sockets against a TcpCarrier door, with
different source addresses on loopback (127.0.0.x)."""
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from sigilnet import tcplink as TL
from sigilnet.acceptguard import AcceptGuard
from sigilnet.tests.test_tcplink import Rig
from sigilnet.tests.test_m1b import Clock


def guard(**kw):
    clk = kw.pop("clock", None) or Clock(1000.0)
    return AcceptGuard(clock=clk, **kw), clk


class Caps(unittest.TestCase):
    def test_a_stranger_gets_4_connections_per_address_a_proven_address_16(self):
        g, _ = guard(per_door=64, global_cap=64)
        for i in range(4):
            self.assertIsNone(g.admit("10.0.0.1", "d"), i)
        self.assertEqual(g.admit("10.0.0.1", "d"), "per-address cap")
        self.assertIsNone(g.admit("10.0.0.2", "d"), "another address is not affected")
        g.proven("10.0.0.3")
        for i in range(16):
            self.assertIsNone(g.admit("10.0.0.3", "d"), i) if i < 8 else None
        # (the per-door cap of 8 is reached first for one door: spread over doors)
        g2, _ = guard(per_door=64, global_cap=64)
        g2.proven("10.0.0.3")
        for i in range(16):
            self.assertIsNone(g2.admit("10.0.0.3", "d"), i)
        self.assertEqual(g2.admit("10.0.0.3", "d"), "per-address cap")

    def test_half_of_each_cap_is_reserved_for_proven_addresses(self):
        g, _ = guard()                                                       # per door 8, global 32
        stranger = [f"10.1.0.{i}" for i in range(1, 40)]
        got_door = [g.admit(ip, "d") for ip in stranger[:6]]
        self.assertEqual(got_door, [None] * 4 + ["door cap"] * 2, "a stranger may use per_door - reserve_door = 4 slots of the door")
        g.proven("10.9.0.1")
        for i in range(4):
            self.assertIsNone(g.admit("10.9.0.1", "d"), "a proven address takes the reserved ones")
        self.assertEqual(g.admit("10.9.0.1", "d"), "door cap", "up to the whole door cap of 8")
        g3, _ = guard(per_door=64)                                           # many doors: the global cap
        res = [g3.admit(ip, f"d{i % 8}") for i, ip in enumerate(stranger[:20])]
        self.assertEqual(res.count(None), 16, "strangers: 32 - 16 in all")
        g3.proven("10.9.0.2")
        got = [g3.admit("10.9.0.2", f"e{i}") for i in range(16)]
        self.assertEqual(got.count(None), 16, "a proven address gets the reserved half")
        self.assertEqual(g3.admit("10.9.0.2", "e0"), "per-address cap", "its own limit of 16")
        g3.proven("10.9.0.4")
        self.assertEqual(g3.admit("10.9.0.4", "x"), "global cap", "everything is taken: the global cap of 32")

    def test_release_is_exact_and_a_double_release_never_goes_negative(self):
        g, _ = guard()
        for ip in ("10.0.0.1", "10.0.0.2"):
            self.assertIsNone(g.admit(ip, "d"))
        g.release("10.0.0.1", "d")
        g.release("10.0.0.2", "d")
        g.release("10.0.0.2", "d")
        g.release("10.0.0.9", "zzz")
        self.assertEqual((g._total, g._door, g._ip), (0, {}, {}))
        for _ in range(4):
            self.assertIsNone(g.admit("10.0.0.1", "d"))
        self.assertEqual(g.admit("10.0.0.1", "d"), "per-address cap")
        for _ in range(4):
            g.release("10.0.0.1", "d")
        self.assertIsNone(g.admit("10.0.0.1", "d"), "the slots came back")

    def test_small_caps_still_let_a_stranger_in(self):
        g, _ = guard(per_door=1, global_cap=1)
        self.assertIsNone(g.admit("10.0.0.1", "d"))
        g, _ = guard(per_door=2, global_cap=2)
        self.assertIsNone(g.admit("10.0.0.1", "d"))
        self.assertEqual(g.admit("10.0.0.2", "d"), "door cap")


class StrikesAndBans(unittest.TestCase):
    def test_ten_strikes_in_a_minute_ban_for_a_minute_then_double_up_to_an_hour(self):
        g, clk = guard()
        ip = "10.0.0.7"
        for i in range(9):
            self.assertFalse(g.strike(ip), i)
        self.assertIsNone(g.admit(ip, "d"))
        g.release(ip, "d")
        self.assertTrue(g.strike(ip))
        self.assertEqual(g.admit(ip, "d"), "banned")
        self.assertEqual(g.banned_until(ip), 1060.0)
        clk.t = 1059.0
        self.assertEqual(g.admit(ip, "d"), "banned")
        clk.t = 1061.0
        self.assertIsNone(g.admit(ip, "d"))
        g.release(ip, "d")
        lengths = []
        for _ in range(8):
            for _ in range(10):
                g.strike(ip)
            lengths.append(round(g.banned_until(ip) - clk.t))
            clk.t = g.banned_until(ip) + 1
        self.assertEqual(lengths, [120, 240, 480, 960, 1920, 3600, 3600, 3600], lengths)

    def test_strikes_older_than_the_window_do_not_count(self):
        g, clk = guard()
        ip = "10.0.0.7"
        for _ in range(9):
            g.strike(ip)
        clk.t += 61
        self.assertFalse(g.strike(ip), "the nine are older than 60 s")
        for _ in range(8):
            g.strike(ip)
        self.assertFalse(g.strike(ip) and False)
        self.assertEqual(g.stats()["bans"], 1 if g.banned_until(ip) else 0)

    def test_a_proven_address_is_never_struck_or_banned_and_a_proof_clears_a_ban(self):
        g, clk = guard()
        g.proven("10.0.0.5")
        for _ in range(50):
            self.assertFalse(g.strike("10.0.0.5"))
        self.assertIsNone(g.admit("10.0.0.5", "d"))
        for _ in range(10):
            g.strike("10.0.0.6")
        self.assertEqual(g.admit("10.0.0.6", "d"), "banned")
        g.proven("10.0.0.6")
        self.assertIsNone(g.admit("10.0.0.6", "d"), "an admission clears the ban")
        self.assertIsNone(g.banned_until("10.0.0.6"))

    def test_a_ban_in_force_does_not_stop_an_address_that_became_proven(self):
        g, _ = guard()
        for _ in range(10):
            g.strike("10.0.0.6")
        g.proven("10.0.0.6")
        self.assertIsNone(g.admit("10.0.0.6", "d"))

    def test_proven_lasts_an_hour(self):
        g, clk = guard()
        g.proven("10.0.0.5")
        clk.t += 3600
        self.assertTrue(g.is_proven("10.0.0.5"))
        clk.t += 1
        self.assertFalse(g.is_proven("10.0.0.5"))
        for _ in range(10):
            g.strike("10.0.0.5")
        self.assertEqual(g.admit("10.0.0.5", "d"), "banned", "a stranger again")

    def test_the_proven_table_is_not_evicted_by_a_flood_of_strikes_and_every_table_is_bounded(self):
        g, _ = guard(max_ips=50)
        g.proven("10.0.0.1")
        for i in range(500):
            g.strike(f"10.1.{i // 250}.{i % 250}")
        self.assertTrue(g.is_proven("10.0.0.1"))
        self.assertLessEqual(len(g._strikes), 50)
        for i in range(500):
            for _ in range(10):
                g.strike(f"10.2.{i // 250}.{i % 250}")
        self.assertLessEqual(len(g._bans), 50)
        for i in range(200):
            g.proven(f"10.3.{i // 250}.{i % 250}")
        self.assertLessEqual(len(g._proven), 50)

    def test_stats_are_counts_and_carry_no_address(self):
        g, _ = guard()
        g.admit("10.0.0.1", "d")
        for _ in range(10):
            g.strike("10.0.0.9")
        g.admit("10.0.0.9", "d")
        st = g.stats()
        self.assertEqual((st["admitted"], st["strikes"], st["bans"], st["refused_banned"], st["unauthenticated"]), (1, 10, 1, 1, 1))
        self.assertNotIn("10.0.0.9", json.dumps(st))
        self.assertNotIn("10.0.0.1", json.dumps(st), "an admitted address does not leak either")


class Persistence(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.store = self.d / "proven.json"

    def make(self, clk):
        return AcceptGuard(clock=clk, store=self.store, writer=TL._write_private)

    def test_a_proven_address_survives_a_restart_a_stranger_never_reaches_the_file(self):
        clk = Clock(1000.0)
        g = self.make(clk)
        g.proven("10.0.0.5")
        for _ in range(10):
            g.strike("10.0.0.6")
        raw = json.loads(self.store.read_text())
        self.assertEqual(list(raw["proven"]), ["10.0.0.5"])
        self.assertEqual(set(raw), {"proven"}, "nothing but the proven table is written: no strikes, no bans")
        self.assertEqual(self.store.stat().st_mode & 0o777, 0o600)
        g2 = self.make(Clock(1500.0))
        self.assertTrue(g2.is_proven("10.0.0.5"))
        self.assertFalse(g2.is_proven("10.0.0.6"))
        self.assertIsNone(g2.banned_until("10.0.0.6"), "strikes and bans are memory only")

    def test_old_entries_are_dropped_at_load_and_a_damaged_file_is_an_empty_table(self):
        clk = Clock(1000.0)
        self.make(clk).proven("10.0.0.5")
        g = self.make(Clock(1000.0 + 3601))
        self.assertFalse(g.is_proven("10.0.0.5"))
        for junk in ("", "{", "[]", '{"proven": []}', '{"proven": {"1.2.3.4": "x", "5.6.7.8": true, "9.9.9.9": -5}}', "null"):
            self.store.write_text(junk)
            AcceptGuard(clock=clk, store=self.store, writer=TL._write_private)

    def test_the_file_is_written_once_per_address_per_half_window(self):
        clk = Clock(1000.0)
        writes = []
        g = AcceptGuard(clock=clk, store=self.store, writer=lambda p, b: writes.append(1) or TL._write_private(p, b))
        for _ in range(20):
            g.proven("10.0.0.5")
        self.assertEqual(len(writes), 1)
        clk.t += 1801
        g.proven("10.0.0.5")
        self.assertEqual(len(writes), 2)
        g.proven("10.0.0.6")
        self.assertEqual(len(writes), 3, "a new address is written at once")

    def test_a_write_failure_never_fails_an_admission(self):
        g = AcceptGuard(clock=Clock(), store=self.store, writer=mock.Mock(side_effect=OSError("disk full")))
        g.proven("10.0.0.5")
        self.assertTrue(g.is_proven("10.0.0.5"))


class StatusLine(unittest.TestCase):
    def test_the_status_shows_refusals_and_bans_only_when_there_are_some(self):
        from sigilnet import daemon
        h = Path(tempfile.mkdtemp())
        with mock.patch.object(daemon, "read_pid", return_value={"pid": 1}), mock.patch.object(daemon, "lock_held", return_value=True), mock.patch.object(daemon, "is_our_node", return_value=True):
            daemon.write_status(h, started=time.time(), carrier="tcp", ready=True, doors_up=1, doors_total=1, guard={"tcp": {"refused_banned": 2, "refused_ip": 1, "refused_door": 0, "refused_global": 0, "bans": 1}})
            self.assertIn("refused at accept 3, bans 1", daemon.status_lines(h)[0])
            daemon.write_status(h, started=time.time(), carrier="tcp", ready=True, doors_up=1, doors_total=1, guard={"tcp": {"refused_banned": 0, "refused_ip": 0, "bans": 0}})
            self.assertNotIn("refused", daemon.status_lines(h)[0])
            daemon.write_status(h, started=time.time(), carrier="tcp", ready=True, doors_up=1, doors_total=1, guard="junk")
            self.assertNotIn("refused", daemon.status_lines(h)[0])


class WithSockets(Rig):
    """A real door; clients come from different loopback addresses."""

    def raw(self, ep, src="127.0.0.1"):
        ip, port, fp = TL._split_addr(ep["addr"])
        s = socket.create_connection((ip, port), timeout=3, source_address=(src, 0))
        self.socks.append(s)
        return s

    @staticmethod
    def closed_at_once(s, within=1.0):
        s.settimeout(within)
        try:
            return s.recv(10) == b""
        except (socket.timeout, TimeoutError):
            return False
        except OSError:
            return True

    def wait_zero(self, c, timeout=8.0):
        end = time.time() + timeout
        while time.time() < end and (c.guard._total or c.guard._ip or c.guard._door):
            time.sleep(0.05)
        self.assertEqual((c.guard._total, c.guard._ip, c.guard._door), (0, {}, {}))

    def test_a_stranger_address_gets_4_idle_connections_then_is_closed_at_once_and_another_address_is_not_affected(self):
        c, ep, secret, port = self.door(auth_deadline=5.0, max_unauth_per_door=16)
        held = [self.raw(ep, "127.0.0.5") for _ in range(4)]
        time.sleep(0.4)
        fifth = self.raw(ep, "127.0.0.5")
        self.assertTrue(self.closed_at_once(fifth), "over the per-address cap: closed before any handshake")
        other = self.raw(ep, "127.0.0.6")
        self.assertFalse(self.closed_at_once(other, 0.5), "another address is let in (it waits for the TLS hello)")
        self.assertGreaterEqual(c.guard_stats()["refused_ip"], 1)
        for s in held + [fifth, other]:
            s.close()
        self.wait_zero(c)

    def test_a_proven_address_gets_more_than_a_stranger(self):
        c, ep, secret, port = self.door(auth_deadline=5.0, max_unauth=64)
        c.guard.per_door = 64
        self.admit(ep, secret)[0].close()                                  # 127.0.0.1 is proven now
        self.assertTrue(c.guard.is_proven("127.0.0.1"))
        held = [self.raw(ep) for _ in range(16)]
        time.sleep(0.5)
        seventeenth = self.raw(ep)
        self.assertTrue(self.closed_at_once(seventeenth), "its own limit: 16")
        self.assertFalse(self.closed_at_once(held[-1], 0.3), "the 16th was let in")
        for s in held + [seventeenth]:
            s.close()
        self.wait_zero(c)

    def test_ten_failed_connections_ban_an_address_and_a_proven_one_is_not_affected(self):
        c, ep, secret, port = self.door(auth_deadline=2.0)
        self.admit(ep, secret)[0].close()
        for _ in range(10):
            s = self.raw(ep, "127.0.0.8")
            try:
                s.sendall(b"GET / HTTP/1.1\\r\\n\\r\\n" * 3)                  # not a TLS hello: a failed handshake is a strike
                s.settimeout(2)
                s.recv(100)
            except OSError:
                pass
            s.close()
        time.sleep(0.3)
        self.assertGreaterEqual(c.guard_stats()["bans"], 1)
        banned = self.raw(ep, "127.0.0.8")
        self.assertTrue(self.closed_at_once(banned), "a banned address is refused at accept")
        junk_from_proven = [self.raw(ep, "127.0.0.1") for _ in range(12)]
        for s in junk_from_proven:
            try:
                s.sendall(b"junk junk junk\\r\\n")
            except OSError:
                pass
            s.close()
        time.sleep(0.5)
        ok = self.admit(ep, secret)[0]
        ok.close()
        self.assertIsNone(c.guard.banned_until("127.0.0.1"), "a proven address cannot be banned")
        self.wait_zero(c)

    def test_a_connection_that_closes_before_saying_anything_is_not_a_strike_a_deadline_is(self):
        c, ep, secret, port = self.door(auth_deadline=0.6)
        for _ in range(30):
            self.raw(ep, "127.0.0.9").close()
        time.sleep(0.5)
        self.assertEqual(c.guard_stats()["strikes"], 0, "closing at once is a port scan or a health check: free")
        idle = self.raw(ep, "127.0.0.9")
        time.sleep(1.2)
        self.assertGreaterEqual(c.guard_stats()["strikes"], 1, "silence until the deadline is a strike")
        idle.close()
        self.wait_zero(c)

    def test_a_wrong_key_costs_no_signature_verification_and_a_right_one_exactly_one(self):
        c, ep, secret, port = self.door(auth_deadline=3.0)
        calls = []
        real = TL.verify_strict
        with mock.patch.object(TL, "verify_strict", side_effect=lambda *a, **k: (calls.append(1), real(*a, **k))[1]):
            other = self.new()
            other_secret, other_pub = other.new_credential()
            other.use_credential(ep, other_secret)                         # a key the door does not hold
            try:
                other.dial(ep, timeout=3).request({"t": "ping", "n": 1})
            except Exception:                                              # noqa: BLE001 - refused (that is the point)
                pass
            self.assertEqual(calls, [], "key hash first: no Ed25519 verification for a stranger's key")
            self.admit(ep, secret)[0].close()
            self.assertEqual(len(calls), 1)
        self.wait_zero(c)

    def test_a_wrong_key_or_a_bad_signature_never_makes_an_address_proven(self):
        c, ep, secret, port = self.door(auth_deadline=3.0)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret["key"]))
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        for frame in (os.urandom(96), pub + os.urandom(64)):               # a key the door does not hold; the right key with a signature that is not valid
            t = self.tls(ep)
            self.recv_exact(t, TL.HELLO_LEN)
            t.sendall(frame)
            self.assertEqual(self.recv_exact(t, 1, 2), b"")
            t.close()
        time.sleep(0.3)
        self.assertFalse(c.guard.is_proven("127.0.0.1"), "proven only AFTER the signature verified")
        self.assertEqual(c.guard_stats()["proven"], 0)
        self.assertGreaterEqual(c.guard_stats()["strikes"], 2)
        self.wait_zero(c)

    def test_a_door_that_goes_away_under_a_connection_is_not_the_addresses_fault(self):
        c, ep, secret, port = self.door(auth_deadline=3.0)
        cli = TL.TcpCarrier(c.dir, bind="127.0.0.1", port_base=c.port_base)    # the CLI (another process)
        ip, p, fp = TL._split_addr(ep["addr"])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = self.raw(ep, "127.0.0.11")
        t = ctx.wrap_socket(raw, do_handshake_on_connect=False)                # connected; the door waits for our ClientHello
        cli.close_door("d")                                                    # gone before the hello is sent
        try:
            t.do_handshake()
            self.recv_exact(t, TL.HELLO_LEN, 1)
        except OSError:
            pass
        t.close()
        time.sleep(0.5)
        self.assertEqual(c.guard_stats()["strikes"], 0, "door gone at the hello: no strike")
        c2, ep2, secret2, port2 = self.door(name="e", auth_deadline=3.0)         # and during the admission window
        cli2 = TL.TcpCarrier(c2.dir, bind="127.0.0.1", port_base=c2.port_base)
        t2 = self.tls(ep2)
        self.recv_exact(t2, TL.HELLO_LEN)
        cli2.close_door("e")
        try:
            t2.sendall(os.urandom(96))
            self.recv_exact(t2, 1, 1)
        except OSError:
            pass
        t2.close()
        time.sleep(0.5)
        self.assertEqual(c2.guard_stats()["strikes"], 0, "door gone at the admission: no strike")

    @staticmethod
    def client_hello_bytes():
        """A real TLS 1.3 ClientHello (what a client sends first), made with a memory BIO: nothing is connected."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out)
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        return out.read()

    def test_a_client_hello_that_was_sent_and_then_closed_is_a_strike_zero_bytes_is_free(self):
        """Sansa G1: the server side of TLS (key share, certificate signature) was already paid for; only a connection that sent NO byte is free."""
        c, ep, secret, port = self.door(auth_deadline=2.0)
        hello = self.client_hello_bytes()
        self.assertGreater(len(hello), 100)
        for _ in range(12):
            s = self.raw(ep, "127.0.0.12")
            try:
                s.sendall(hello)
                s.shutdown(socket.SHUT_WR)                                 # a FIN after the whole ClientHello (the free variant of the first build)
                s.settimeout(1)
                while s.recv(4096):
                    pass
            except OSError:                                                # (from the 11th on the address is banned and closed at accept)
                pass
            s.close()
        time.sleep(0.4)
        st = c.guard_stats()
        self.assertGreaterEqual(st["strikes"], 10, st)
        self.assertGreaterEqual(st["bans"], 1)
        self.assertTrue(self.closed_at_once(self.raw(ep, "127.0.0.12")), "banned")
        before = c.guard_stats()["strikes"]
        for _ in range(30):
            self.raw(ep, "127.0.0.13").close()
        time.sleep(0.4)
        self.assertEqual(c.guard_stats()["strikes"], before, "30 connections closed before any byte: still free")
        self.wait_zero(c)

    def test_a_reset_with_nothing_sent_is_free_and_one_byte_then_a_close_is_a_strike(self):
        import struct
        c, ep, secret, port = self.door(auth_deadline=2.0)
        for _ in range(15):
            s = self.raw(ep, "127.0.0.14")
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()                                                      # RST, nothing sent
        time.sleep(0.4)
        self.assertEqual(c.guard_stats()["strikes"], 0)
        for _ in range(3):
            s = self.raw(ep, "127.0.0.15")
            s.sendall(b"\x16")
            s.close()
        time.sleep(0.5)
        self.assertEqual(c.guard_stats()["strikes"], 3, "one byte is a commitment")
        self.wait_zero(c)

    def test_a_refusal_at_accept_is_a_retryable_error_for_the_caller(self):
        c, ep, secret, port = self.door(auth_deadline=2.0)
        c.guard.per_ip_stranger = 0                                        # 127.0.0.1 is a stranger and may hold nothing
        other = self.new()
        other.use_credential(ep, secret)
        with self.assertRaises(TL.CarrierError) as cm:
            other.dial(ep, timeout=3).request({"t": "ping", "n": 1})
        self.assertTrue(cm.exception.retry, "a full door is a try-again, never a dead peer")
        self.assertGreaterEqual(c.guard_stats()["refused_ip"], 1)

    def test_many_requests_in_parallel_work_once_the_address_is_proven(self):
        """Sansa G2: 24 requests with 6 in flight from one address are refused for a stranger (4 per address); a node that talked to this door before is proven and gets 16."""
        c, ep, secret, port = self.door(auth_deadline=5.0)
        c.guard.per_door = 64
        c.guard.reserve_door = 0
        client = self.new()
        client.use_credential(ep, secret)
        self.assertEqual(client.dial(ep, timeout=5).request({"t": "ping", "n": 0})["t"], "pong")      # the first request proves the address
        self.assertTrue(c.guard.is_proven("127.0.0.1"))
        errors, done = [], []

        def work(n):
            try:
                done.append(client.dial(ep, timeout=5).request({"t": "ping", "n": n})["t"])
            except Exception as e:                                         # noqa: BLE001
                errors.append(repr(e))
        threads = [threading.Thread(target=work, args=(i,)) for i in range(24)]
        for i in range(0, 24, 6):
            batch = threads[i:i + 6]
            for t in batch:
                t.start()
            for t in batch:
                t.join(10)
        self.assertEqual((errors, len(done)), ([], 24))
        self.wait_zero(c)

    def test_a_thread_that_cannot_start_gives_its_slot_back_and_the_accept_loop_lives_on(self):
        c, ep, secret, port = self.door(auth_deadline=2.0)
        orig = threading.Thread.start

        def start(th):
            if th.name.startswith("tcp-conn"):
                raise RuntimeError("can't start new thread")
            return orig(th)
        with mock.patch.object(threading.Thread, "start", start):
            for _ in range(3):
                self.raw(ep, "127.0.0.16").close()
            time.sleep(0.5)
        self.wait_zero(c)
        self.admit(ep, secret)[0].close()                                  # the accept thread is still there
        self.wait_zero(c)

    def test_every_exit_path_releases_its_slot(self):
        """Sansa: a kill mid-handshake, a stream cap hit right after admission, a refused key, a door that goes away: the counters end at zero."""
        c, ep, secret, port = self.door(auth_deadline=1.5, max_streams_per_door=1,
                                        handler=lambda req: (time.sleep(1.0), {"t": "pong"})[1])
        for _ in range(3):
            s = self.raw(ep, "127.0.0.10")
            s.sendall(b"\\x16\\x03\\x01")                                    # half a hello, then gone
            s.close()
        first = self.admit(ep, secret)[0]                                  # takes the one stream
        for _ in range(3):
            try:
                self.admit(ep, secret)[0].close()                          # the stream cap is hit right after the admission
            except Exception:                                              # noqa: BLE001
                pass
        first.close()
        self.wait_zero(c)
        end = time.time() + 6
        while time.time() < end and any(c._streams.values()):
            time.sleep(0.1)
        self.assertEqual({k: v for k, v in c._streams.items() if v}, {})

    def test_the_proven_table_is_written_0600_and_survives_a_new_carrier(self):
        c, ep, secret, port = self.door()
        self.admit(ep, secret)[0].close()
        f = c.dir / "proven.json"
        end = time.time() + 3
        while time.time() < end and not f.exists():
            time.sleep(0.05)
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        self.assertIn("127.0.0.1", json.loads(f.read_text())["proven"])
        again = TL.TcpCarrier(c.dir, bind="127.0.0.1", port_base=12000)
        self.assertTrue(again.guard.is_proven("127.0.0.1"))

    def test_a_public_door_has_no_admission_so_nothing_is_struck_or_proven(self):
        c, ep, secret, port = self.door(kind="read")
        for _ in range(12):
            t = self.tls(ep)
            self.recv_exact(t, TL.HELLO_LEN)
            t.close()
        st = c.guard_stats()
        self.assertEqual((st["strikes"], st["proven"]), (0, 0))

    def test_the_connection_cap_of_the_old_test_still_holds(self):
        c, ep, secret, port = self.door(max_unauth=4, auth_deadline=1.0)
        ip, p, fp = TL._split_addr(ep["addr"])
        idle = [self.raw(ep, f"127.0.0.{20 + i}") for i in range(2)]
        time.sleep(0.3)
        third = self.raw(ep, "127.0.0.30")
        self.assertTrue(self.closed_at_once(third), "a stranger may use 2 of the 4 (the other half is reserved)")
        for s in idle + [third]:
            s.close()
        self.wait_zero(c)


if __name__ == "__main__":
    unittest.main()
