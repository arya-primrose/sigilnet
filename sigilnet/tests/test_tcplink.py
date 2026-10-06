"""The TCP carrier (DESIGN_tcp_carrier.md rev 1 / 1.1): conformance (the shared suite) + wire, admission, caps, deadlines, state. Everything on 127.0.0.1, no tor.
Sansa writes an independent suite (tests_adv11) from the same spec; these are the author's tests."""
import hashlib
import json
import os
import random
import socket
import ssl
import stat
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from sigilnet import carrier as C
from sigilnet import tcp
from sigilnet import tcplink as TL
from sigilnet.carrier import CarrierError
from sigilnet.tcp import TcpServer
from sigilnet.tests.test_carrier import Conformance

AGENT = "a" * 32


def free_base() -> int:
    """An even port base whose next 20 ports are free on 127.0.0.1 (best effort)."""
    while True:
        base = random.randrange(30000, 60000, 2)
        socks = []
        try:
            for p in range(base, base + 20):
                s = socket.socket()
                s.bind(("127.0.0.1", p))
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()


def carrier(tmp=None, **kw):
    kw.setdefault("bind", "127.0.0.1")
    kw.setdefault("port_base", free_base())
    return TL.TcpCarrier(Path(tmp or tempfile.mkdtemp()), **kw)


class TcpConformance(Conformance, unittest.TestCase):
    DELIVERS = True

    def make(self):
        c = carrier()
        c.start()
        self.addCleanup(c.stop)
        return c

    def other_endpoint(self):
        return {"type": "tcp", "addr": "127.0.0.1:47999#" + "ab" * 32}

    def test_authorized_client_reaches_the_door_and_nobody_else_does(self):
        bob = carrier()
        secret, pub = bob.new_credential()
        port = self.c.open_door("d1", "peer", credential=pub)
        self.serve(port)
        self.c.reconfigure()
        ep = self.c.door_endpoint("d1")
        with self.assertRaises(CarrierError) as cm:
            bob.dial(ep, timeout=3).request({"t": "ping", "n": 1})
        self.assertFalse(cm.exception.retry)                              # no credential held
        bob.use_credential(ep, secret)
        self.assertEqual(bob.dial(ep, timeout=5).request({"t": "ping", "n": 1}), {"t": "pong", "echo": 1})
        eve = carrier()
        eve.use_credential(ep, eve.new_credential()[0])
        with self.assertRaises(CarrierError) as cm:
            eve.dial(ep, timeout=3).request({"t": "ping", "n": 2})
        self.assertTrue(cm.exception.retry)

    def test_rekeying_locks_out_the_old_key_and_close_makes_the_door_unreachable(self):
        bob = carrier()
        s1, p1 = bob.new_credential()
        port = self.c.open_door("d2", "peer", credential=p1)
        self.serve(port)
        self.c.reconfigure()
        ep = self.c.door_endpoint("d2")
        bob.use_credential(ep, s1)
        self.assertEqual(bob.dial(ep, timeout=5).request({"t": "ping", "n": 2})["t"], "pong")
        _, p2 = self.c.new_credential()
        self.c.open_door("d2", "peer", credential=p2)                      # no reconfigure needed: the entry is re-read per connection
        with self.assertRaises(CarrierError):
            bob.dial(ep, timeout=3).request({"t": "ping", "n": 3})
        self.c.close_door("d2")
        with self.assertRaises(CarrierError):
            bob.dial(ep, timeout=3).request({"t": "ping", "n": 4})

    def test_public_door_needs_no_credential(self):
        port = self.c.open_door("pr", "read")
        self.serve(port)
        self.c.reconfigure()
        self.assertEqual(carrier().dial(self.c.door_endpoint("pr"), timeout=5).request({"t": "ping", "n": 3})["echo"], 3)


# ------------------------------------------------------------------ the wire, from a raw client
class Rig(unittest.TestCase):
    def setUp(self):
        self.servers, self.socks = [], []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        for s in self.servers:
            s.stop()
        for c in getattr(self, "carriers", []):
            c.stop()

    def new(self, **kw):
        self.carriers = getattr(self, "carriers", [])
        c = carrier(**kw)
        self.carriers.append(c)
        return c

    def door(self, c=None, kind="peer", name="d", handler=None, **kw):
        """-> (carrier, endpoint, client secret, loopback port); the door is started and served by the protocol's own guard."""
        c = c or self.new(**kw)
        secret, pub = c.new_credential()
        port = c.open_door(name, kind, credential=pub) if kind in ("peer", "join") else c.open_door(name, kind)
        self.servers.append(TcpServer("127.0.0.1", port, None, handler or (lambda req: {"t": "pong", "echo": req.get("n")})).start())
        c.start()
        c.reconfigure()
        return c, c.door_endpoint(name), secret, port

    def tls(self, ep, version=ssl.TLSVersion.TLSv1_3, deadline=5):
        ip, port, fp = TL._split_addr(ep["addr"])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = version
        if version == ssl.TLSVersion.TLSv1_3:
            ctx.minimum_version = version
        s = socket.create_connection((ip, port), timeout=deadline)
        t = ctx.wrap_socket(s)
        self.socks.append(t)
        return t

    @staticmethod
    def recv_exact(s, n, timeout=3):
        s.settimeout(timeout)
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                break
            buf += c
        return buf

    def admit(self, ep, secret, door_fp=None, seed=None):
        """Do the full admission by hand; -> (tls socket, hello, auth bytes, ack)."""
        t = self.tls(ep)
        hello = self.recv_exact(t, TL.HELLO_LEN)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed or secret["key"]))
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        fp = bytes.fromhex(door_fp or TL._split_addr(ep["addr"])[2])
        auth = pub + priv.sign(TL.auth_message(hello[7:], fp, hashlib.sha256(pub).digest()))
        t.sendall(auth)
        return t, hello, auth, self.recv_exact(t, 1, 2)


class WireAndAdmission(Rig):
    def test_good_client_is_admitted_and_the_exchange_works(self):
        c, ep, secret, port = self.door()
        t, hello, auth, ack = self.admit(ep, secret)
        self.assertEqual((hello[:6], hello[6], len(hello)), (b"SNTCP1", 1, 39))
        self.assertEqual(ack, b"\x01")
        from sigilnet import canon
        t.sendall(tcp._frame(canon.dumps({"t": "ping", "n": 5})))
        head = self.recv_exact(t, 4)
        body = self.recv_exact(t, struct.unpack(">I", head)[0])
        self.assertEqual(canon.loads(body), {"t": "pong", "echo": 5})

    def test_only_tls13_and_no_session_resumption(self):
        c, ep, secret, port = self.door()
        with self.assertRaises(ssl.SSLError):
            self.tls(ep, version=ssl.TLSVersion.TLSv1_2)
        t = self.tls(ep)
        self.assertEqual(t.version(), "TLSv1.3")
        self.assertFalse(t.session_reused)
        hello1 = self.recv_exact(t, TL.HELLO_LEN)
        hello2 = self.recv_exact(self.tls(ep), TL.HELLO_LEN)
        self.assertNotEqual(hello1[7:], hello2[7:])                          # a fresh nonce every connection

    def test_wrong_credential_gets_no_ack_and_no_bytes(self):
        c, ep, secret, port = self.door()
        other = TL.TcpCarrier(tempfile.mkdtemp(), bind="127.0.0.1", port_base=free_base()).new_credential()[0]
        t, hello, auth, ack = self.admit(ep, other)
        self.assertEqual(ack, b"")

    def test_replayed_admission_is_refused(self):
        c, ep, secret, port = self.door()
        t, hello, auth, ack = self.admit(ep, secret)
        self.assertEqual(ack, b"\x01")
        t2 = self.tls(ep)
        self.recv_exact(t2, TL.HELLO_LEN)
        t2.sendall(auth)                                                    # the old reply against a NEW nonce
        self.assertEqual(self.recv_exact(t2, 1, 2), b"")

    def test_admission_for_another_door_is_not_valid_here(self):
        c, ep, secret, port = self.door()
        c2, ep2, secret2, port2 = self.door(name="e")                       # another door (own key and credential)
        # the same client key authorized on both doors: a signature made for door 1's fp must not open door 2
        _, pub = c.new_credential()
        c2.open_door("e", "peer", credential={"type": "tcp", "key": hashlib.sha256(
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret["key"])).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()})
        t, hello, auth, ack = self.admit(ep2, secret, door_fp=TL._split_addr(ep["addr"])[2])
        self.assertEqual(ack, b"")
        t2, hello2, auth2, ack2 = self.admit(ep2, secret)                   # with the right fp the same key is admitted
        self.assertEqual(ack2, b"\x01")

    def test_a_door_removed_and_recreated_while_a_client_connects_answers_nothing(self):
        """The door entry is re-read after the handshake: a new door under the same name (another index) must not inherit a connection made to the old one."""
        c, ep, secret, port = self.door(kind="read", name="x")
        ip, p, fp = TL._split_addr(ep["addr"])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, p), timeout=3)
        self.socks.append(raw)
        t = ctx.wrap_socket(raw, do_handshake_on_connect=False)             # connected; the door is waiting for our ClientHello
        cli = TL.TcpCarrier(c.dir, bind="127.0.0.1", port_base=c.port_base)  # the CLI (another process)
        cli.close_door("x")
        cli.open_door("x", "read")                                           # same name, same kind, NEW index and key
        t.do_handshake()
        self.assertEqual(self.recv_exact(t, TL.HELLO_LEN, 2), b"", "nothing is answered on a connection made to the old door")

    def test_the_comparisons_are_constant_time_in_the_code(self):
        import inspect
        src = inspect.getsource(TL)
        self.assertGreaterEqual(src.count("hmac.compare_digest("), 2)         # the door's credential check and the client's pin check

    def test_a_credential_revoked_during_the_admission_window_is_refused(self):
        """Sansa F1: the door entry is re-read AFTER the 96 bytes, so a re-key that lands while a client is mid-admission wins."""
        c, ep, secret, port = self.door()
        t = self.tls(ep)
        hello = self.recv_exact(t, TL.HELLO_LEN)
        cli = TL.TcpCarrier(c.dir, bind="127.0.0.1", port_base=c.port_base)
        cli.open_door("d", "peer", credential=cli.new_credential()[1])       # re-key (same index): the old credential is revoked right now
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret["key"]))
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        t.sendall(pub + priv.sign(TL.auth_message(hello[7:], bytes.fromhex(TL._split_addr(ep["addr"])[2]), hashlib.sha256(pub).digest())))
        self.assertEqual(self.recv_exact(t, 1, 2), b"")
        # and a door that was closed in the window answers nothing either
        t2 = self.tls(ep)
        h2 = self.recv_exact(t2, TL.HELLO_LEN)
        cli.close_door("d")
        t2.sendall(pub + priv.sign(TL.auth_message(h2[7:], bytes.fromhex(TL._split_addr(ep["addr"])[2]), hashlib.sha256(pub).digest())))
        self.assertEqual(self.recv_exact(t2, 1, 2), b"")

    def test_a_door_recreated_in_the_window_does_not_admit_a_client_signing_for_the_new_door(self):
        """The index compare on the SECOND read: the old listener/cert must not admit a client that is valid for a door created under the same name meanwhile."""
        c, ep, secret, port = self.door()
        cli = TL.TcpCarrier(c.dir, bind="127.0.0.1", port_base=c.port_base)
        t = self.tls(ep)                                                    # connected to the OLD door (old cert, old index)
        hello = self.recv_exact(t, TL.HELLO_LEN)
        cli.close_door("d")
        sec2, pub2 = cli.new_credential()
        cli.open_door("d", "peer", credential=pub2)                         # a NEW door under the same name: new index, key and fp, credential B
        new_fp = bytes.fromhex(cli._load()["doors"]["d"]["fp"])
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec2["key"]))
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        t.sendall(pub + priv.sign(TL.auth_message(hello[7:], new_fp, hashlib.sha256(pub).digest())))      # a perfectly valid admission for the NEW door
        self.assertEqual(self.recv_exact(t, 1, 2), b"")

    def test_small_order_and_garbage_public_keys_are_refused(self):
        c, ep, secret, port = self.door()
        zero = b"\x00" * 32
        c.open_door("d", "peer", credential={"type": "tcp", "key": hashlib.sha256(zero).hexdigest()})
        t = self.tls(ep)
        self.recv_exact(t, TL.HELLO_LEN)
        t.sendall(zero + b"\x00" * 64)
        self.assertEqual(self.recv_exact(t, 1, 2), b"")

    def test_plain_tcp_garbage_and_early_bytes_get_nothing(self):
        c, ep, secret, port = self.door()
        ip, p, fp = TL._split_addr(ep["addr"])
        s = socket.create_connection((ip, p), timeout=3)
        self.socks.append(s)
        s.sendall(b"GET / HTTP/1.1\r\n\r\n" * 3)
        s.settimeout(3)
        try:
            data = s.recv(4096)
        except (socket.timeout, ConnectionResetError):
            data = b""
        self.assertNotIn(b"SNTCP1", data)

    def test_client_refuses_a_door_whose_key_is_not_the_pin_and_sends_nothing(self):
        pem, fp = TL._new_door_pem()
        d = Path(tempfile.mkdtemp()) / "x.pem"
        d.write_bytes(pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(d)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        self.socks.append(srv)
        got = []

        def run():
            conn, _ = srv.accept()
            try:
                t = ctx.wrap_socket(conn, server_side=True)
                t.sendall(TL.HELLO_MAGIC + b"\x01" + os.urandom(32))
                t.settimeout(2)
                try:
                    got.append(t.recv(200))
                except (socket.timeout, OSError):
                    got.append(b"")
            except OSError as e:
                got.append(repr(e).encode())
        th = threading.Thread(target=run, daemon=True)
        th.start()
        me = self.new()
        secret, _ = me.new_credential()
        wrong = f"127.0.0.1:{port}#{'cd' * 32}"
        ep = {"type": "tcp", "addr": wrong}
        me.use_credential(ep, secret)
        with self.assertRaises(CarrierError) as cm:
            me.dial(ep, timeout=3).request({"t": "ping"})
        self.assertFalse(cm.exception.retry)
        th.join(4)
        self.assertEqual(got[0] in (b"",) or b"SNTCP1" not in got[0], True)
        self.assertLess(len(got[0]), 90)                                    # at most a TLS-level close: never the 96 auth bytes

    def test_the_real_pin_is_accepted_by_the_same_client(self):
        c, ep, secret, port = self.door()
        me = self.new()
        me.use_credential(ep, secret)
        self.assertEqual(me.dial(ep, timeout=5).request({"t": "ping", "n": 9}), {"t": "pong", "echo": 9})

    def test_client_holding_a_credential_meets_a_public_door_and_sends_nothing(self):
        c, ep, secret, port = self.door(kind="read", name="pr")
        me = self.new()
        me.use_credential(ep, secret)                                       # irrelevant for a mode-0 door
        self.assertEqual(me.dial(ep, timeout=5).request({"t": "ping", "n": 1})["echo"], 1)
        t = self.tls(ep)
        hello = self.recv_exact(t, TL.HELLO_LEN)
        self.assertEqual(hello[6], 0)

    def test_bad_hello_from_a_hostile_door_is_retryable_failure(self):
        for hello in (b"XXXXXX" + b"\x01" + b"\x00" * 32, TL.HELLO_MAGIC + b"\x07" + b"\x00" * 32, b"short"):
            pem, fp = TL._new_door_pem()
            d = Path(tempfile.mkdtemp()) / "x.pem"
            d.write_bytes(pem)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(d)
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            self.socks.append(srv)

            def run(srv=srv, hello=hello):
                try:
                    conn, _ = srv.accept()
                    t = ctx.wrap_socket(conn, server_side=True)
                    t.sendall(hello)
                    time.sleep(1)
                except OSError:
                    pass
            threading.Thread(target=run, daemon=True).start()
            me = self.new()
            ep = {"type": "tcp", "addr": f"127.0.0.1:{srv.getsockname()[1]}#{fp}"}
            with self.assertRaises(CarrierError) as cm:
                me.dial(ep, timeout=3).request({"t": "ping"})
            self.assertTrue(cm.exception.retry, hello)


class Deadlines(Rig):
    def test_a_silent_connection_is_closed_within_the_auth_deadline(self):
        c, ep, secret, port = self.door(auth_deadline=1.0)
        ip, p, fp = TL._split_addr(ep["addr"])
        s = socket.create_connection((ip, p), timeout=3)
        self.socks.append(s)
        t0 = time.time()
        s.settimeout(4)
        self.assertEqual(s.recv(10), b"")
        self.assertLess(time.time() - t0, 2.5)

    def test_a_real_client_hello_trickled_slowly_is_cut_at_the_total_deadline(self):
        """A VALID ClientHello sent one byte at a time: per-read timeouts never fire, only the door's ONE total deadline can cut it."""
        c, ep, secret, port = self.door(auth_deadline=1.0)
        ip, p, fp = TL._split_addr(ep["addr"])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=None)
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = outgoing.read()
        self.assertGreater(len(hello), 100)
        s = socket.create_connection((ip, p), timeout=3)
        self.socks.append(s)
        t0 = time.time()
        closed = False
        try:
            for i in range(len(hello)):
                s.sendall(hello[i:i + 1])
                time.sleep(0.12)
                if time.time() - t0 > 6:
                    break
        except OSError:
            closed = True
        self.assertTrue(closed, "the door must cut a handshake that is still going after its deadline")
        self.assertLess(time.time() - t0, 3.0)

    def test_a_stalled_admission_after_the_hello_is_cut(self):
        c, ep, secret, port = self.door(auth_deadline=1.0)
        t = self.tls(ep)
        self.recv_exact(t, TL.HELLO_LEN)
        t.sendall(b"x" * 10)                                                # part of the 96, then silence
        t0 = time.time()
        t.settimeout(4)
        try:
            data = t.recv(10)
        except (OSError, ssl.SSLError):
            data = b""
        self.assertEqual(data, b"")
        self.assertLess(time.time() - t0, 2.5)

    def test_unauthenticated_cap_and_slots_are_released(self):
        c, ep, secret, port = self.door(max_unauth=4, auth_deadline=1.0)                  # (M3b: half of the 4 is reserved for proven addresses: a stranger gets 2)
        ip, p, fp = TL._split_addr(ep["addr"])
        idle = []
        for _ in range(2):
            s = socket.create_connection((ip, p), timeout=3)
            self.socks.append(s)
            idle.append(s)
        time.sleep(0.3)
        third = socket.create_connection((ip, p), timeout=3)
        self.socks.append(third)
        third.settimeout(1.0)
        t0 = time.time()
        self.assertEqual(third.recv(10), b"")                               # over the cap: closed at once, before TLS
        self.assertLess(time.time() - t0, 0.9)
        time.sleep(1.5)                                                     # the two idle ones hit their deadline: the slots come back
        self.assertEqual(c._unauth, 0)
        me = self.new()
        me.use_credential(ep, secret)
        self.assertEqual(me.dial(ep, timeout=5).request({"t": "ping", "n": 1})["t"], "pong")

    def test_counters_are_exact_after_failures_of_every_kind(self):
        c, ep, secret, port = self.door(auth_deadline=1.0, max_streams_per_door=2)
        ip, p, fp = TL._split_addr(ep["addr"])
        raw = socket.create_connection((ip, p), timeout=3)
        raw.sendall(b"junk" * 100)
        raw.close()
        t = self.tls(ep)
        self.recv_exact(t, TL.HELLO_LEN)
        t.sendall(b"\x00" * 96)
        t.close()
        self.admit(ep, secret)[0].close()
        time.sleep(1.5)
        self.assertEqual(c._unauth, 0)
        self.assertEqual({k: v for k, v in c._streams.items() if v}, {})

    def test_stream_cap_closes_before_the_ack_byte(self):
        slow = lambda req: (time.sleep(2.5), {"t": "pong", "echo": 1})[1]
        c, ep, secret, port = self.door(max_streams_per_door=1, handler=slow)
        t1, h1, a1, ack1 = self.admit(ep, secret)
        from sigilnet import canon
        t1.sendall(tcp._frame(canon.dumps({"t": "ping"})))                  # the backend now holds this stream for 2.5 s
        time.sleep(0.4)
        t2, h2, a2, ack2 = self.admit(ep, secret)
        self.assertEqual((ack1, ack2), (b"\x01", b""))
        self.assertEqual(c._streams["d"], 1)

    def silent_backend(self, port):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(4)
        self.socks.append(srv)

        def run():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                self.socks.append(conn)                                    # accepted and never closed, never answering (the protocol guard would hang up at 2 s and hide the carrier's own deadline)
        threading.Thread(target=run, daemon=True).start()

    def raw_door(self, **kw):
        c = self.new(**kw)
        secret, pub = c.new_credential()
        port = c.open_door("d", "peer", credential=pub)
        self.silent_backend(port)
        c.start()
        return c, c.door_endpoint("d"), secret

    def test_idle_deadline_of_the_pipe(self):
        c, ep, secret = self.raw_door(pipe_idle=1.0, pipe_total=100.0)
        t, h, a, ack = self.admit(ep, secret)
        self.assertEqual(ack, b"\x01")
        t0 = time.time()
        t.settimeout(5)
        try:
            data = t.recv(10)
        except (OSError, ssl.SSLError):
            data = b"closed"
        self.assertLess(time.time() - t0, 3.0, "the door itself must hang up on an idle stream")
        self.assertIn(data, (b"", b"closed"))

    def test_total_deadline_of_the_pipe_even_with_a_trickle(self):
        c, ep, secret = self.raw_door(pipe_idle=100.0, pipe_total=2.0)
        t, h, a, ack = self.admit(ep, secret)
        t0 = time.time()
        try:
            while time.time() - t0 < 7:
                t.sendall(b"\x00")                                         # keeps the idle timer fresh
                time.sleep(0.3)
        except (OSError, ssl.SSLError):
            pass
        self.assertLess(time.time() - t0, 4.5)


class PipeCaps(Rig):
    def counting_backend(self, port, answer=b""):
        """A raw loopback backend that counts the bytes it receives (instead of the protocol guard)."""
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(4)
        self.socks.append(srv)
        box = {"n": 0}

        def run():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            self.socks.append(conn)
            conn.settimeout(3)
            try:
                while True:
                    d = conn.recv(65536)
                    if not d:
                        break
                    box["n"] += len(d)
                    if answer:
                        conn.sendall(answer)
            except (OSError, socket.timeout):
                pass
        threading.Thread(target=run, daemon=True).start()
        return box

    def test_exactly_the_cap_passes_client_to_backend_and_one_more_byte_ends_the_connection(self):
        for extra, closed in ((0, False), (1, True)):
            c = self.new()
            secret, pub = c.new_credential()
            port = c.open_door("d", "peer", credential=pub)
            box = self.counting_backend(port)
            c.start()
            ep = c.door_endpoint("d")
            t, h, a, ack = self.admit(ep, secret)
            self.assertEqual(ack, b"\x01")
            data = b"\x00" * (TL.PIPE_UP + extra)
            try:
                t.sendall(data)
            except (OSError, ssl.SSLError):
                pass
            time.sleep(1.0)
            t.settimeout(1.5)
            try:
                got = t.recv(10)
                end = got == b""
            except (socket.timeout, ssl.SSLError, OSError):
                end = False
            self.assertEqual(end, closed, extra)
            self.assertEqual(box["n"], TL.PIPE_UP, extra)
            c.stop()

    def test_backend_to_client_cap(self):
        c = self.new()
        secret, pub = c.new_credential()
        port = c.open_door("d", "peer", credential=pub)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        self.socks.append(srv)

        def run():
            conn, _ = srv.accept()
            self.socks.append(conn)
            conn.recv(10)
            left = TL.PIPE_DOWN + 3                                        # three bytes too many
            try:
                while left:
                    n = min(60000, left)
                    conn.sendall(b"y" * n)
                    left -= n
            except OSError:
                pass
        threading.Thread(target=run, daemon=True).start()
        c.start()
        ep = c.door_endpoint("d")
        t, h, a, ack = self.admit(ep, secret)
        t.sendall(b"go")
        total = 0
        t.settimeout(3)
        try:
            while True:
                d = t.recv(65536)
                if not d:
                    break
                total += len(d)
        except (OSError, ssl.SSLError):
            pass
        self.assertEqual(total, TL.PIPE_DOWN)


class StateAndLifecycle(Rig):
    def test_formats(self):
        fp = "ab" * 32
        for good in (f"10.1.2.3:47600#{fp}", f"  127.0.0.1:1#{fp.upper()}  "):
            C.check_endpoint({"type": "tcp", "addr": good})
        for bad in (f"10.1.2.3:47600", f"10.1.2.3#{fp}", f"010.1.2.3:47600#{fp}", f"256.1.1.1:5#{fp}", f"1.1.1.1:0#{fp}", f"1.1.1.1:65536#{fp}",
                    f"1.1.1.1:05#{fp}", f"1.1.1.1:5#{fp[:-1]}", f"::1:5#{fp}", f"example.com:5#{fp}", f"1.1.1.1:5#{fp}x", f"1.1.1.1:5#"):
            with self.assertRaises(ValueError, msg=bad):
                C.check_endpoint({"type": "tcp", "addr": bad})
        with self.assertRaises(ValueError):
            C.check_credential({"type": "tcp", "key": "ab" * 31})
        with self.assertRaises(ValueError):
            C.check_credential({"type": "tcp", "key": "AB" * 32}) if False else C.check_credential({"type": "tcp", "key": "zz" * 32})

    def test_constructor_validation(self):
        d = tempfile.mkdtemp()
        for kw in ({"bind": "0.0.0.0"}, {"bind": "localhost"}, {"bind": "127.0.0.1", "advertise": "0.0.0.0"}, {"bind": "127.0.0.1", "advertise": "224.0.0.1"}, {"bind": "240.0.0.1"}, {"bind": "0.1.2.3"},
                   {"bind": "255.255.255.255"}, {"bind": "127.0.0.1", "port_base": 80},
                   {"bind": "127.0.0.1", "port_base": 64001}, {"bind": "127.0.0.1", "port_base": True}, {"bind": "224.0.0.1"}, {"bind": "127.0.0.1", "allow_public": 1},
                   {"bind": "127.0.0.1", "max_unauth": 0}):
            kw.setdefault("port_base", 40000)
            with self.assertRaises(ValueError, msg=kw):
                TL.TcpCarrier(d, **kw)
        c = TL.TcpCarrier(d, bind="8.8.8.8", port_base=40000)                                  # M3: any address is allowed, public too; allow_public is accepted and ignored
        self.assertEqual((c.bind, c.advertise), ("8.8.8.8", "8.8.8.8"))
        TL.TcpCarrier(d, bind="8.8.8.8", port_base=40000, allow_public=True)
        with self.assertRaises(ValueError):
            TL.TcpCarrier(d, bind="0.0.0.0", port_base=40000, allow_public=True)             # 0.0.0.0 without an address peers can dial: never
        c = TL.TcpCarrier(d, bind="0.0.0.0", advertise="203.0.113.7", port_base=40000)        # listen on every interface, advertise the public address
        self.assertEqual((c.bind, c.advertise), ("0.0.0.0", "203.0.113.7"))
        for ip in ("100.64.0.1", "169.254.1.1", "198.51.100.1", "10.0.0.1"):                   # (carrier-grade NAT, link-local, documentation, private: addresses of a machine)
            TL.TcpCarrier(d, bind=ip, port_base=40000)

    def test_dial_accepts_a_public_ip_M3(self):
        c = self.new()
        tr = c.dial({"type": "tcp", "addr": "8.8.8.8:5#" + "ab" * 32}, timeout=1)       # (a transport: it connects at the first request)
        self.assertTrue(hasattr(tr, "request"))

    def test_state_files_are_private_and_the_door_key_is_separate(self):
        tmp = Path(tempfile.mkdtemp())
        c = carrier(tmp)
        _, pub = c.new_credential()
        c.open_door("a", "peer", credential=pub)
        c.open_door("b", "read")
        for f in ("doors.json", "door-a.pem", "door-b.pem"):
            self.assertEqual(stat.S_IMODE((tmp / f).stat().st_mode), 0o600, f)
        self.assertEqual(stat.S_IMODE(tmp.stat().st_mode), 0o700)
        self.assertNotEqual((tmp / "door-a.pem").read_bytes(), (tmp / "door-b.pem").read_bytes())
        secret, pub2 = c.new_credential()
        c.use_credential({"type": "tcp", "addr": "10.0.0.1:47600#" + "cd" * 32}, secret)
        self.assertEqual(stat.S_IMODE((tmp / "held.json").stat().st_mode), 0o600)
        for f in tmp.iterdir():
            self.assertFalse(f.name.startswith(".tmp"), f.name)
        pems = [(tmp / f).read_text() for f in ("door-a.pem", "door-b.pem")]
        self.assertTrue(all("EC PRIVATE KEY" in x or "PRIVATE KEY" in x for x in pems))
        # the door key is not the client admission key and not any seed ever returned
        self.assertNotIn(secret["key"], "".join(pems))
        self.assertEqual(TL.spki_fp(ssl.PEM_cert_to_DER_cert(pems[0][pems[0].index("-----BEGIN CERTIFICATE"):])), c._load()["doors"]["a"]["fp"])

    def test_ports_are_deterministic_stable_and_never_reused(self):
        tmp = Path(tempfile.mkdtemp())
        base = free_base()
        c = TL.TcpCarrier(tmp, bind="127.0.0.1", port_base=base)
        _, pub = c.new_credential()
        p0 = c.open_door("a", "peer", credential=pub)
        p1 = c.open_door("b", "peer", credential=pub)
        self.assertEqual((p0, p1), (base + 1, base + 3))
        self.assertEqual(c.open_door("a", "peer", credential=pub), p0)
        c.close_door("a")
        self.assertEqual(c.open_door("c", "peer", credential=pub), base + 5)                  # index 0 is never reused
        self.assertEqual(c.open_door("d", "peer", credential=pub), base + 7)                  # nor does the next door collide with an earlier one
        d = c._load()["doors"]
        self.assertEqual((d["b"]["listen_port"], d["c"]["listen_port"]), (base + 2, base + 4))
        c2 = TL.TcpCarrier(tmp, bind="127.0.0.1", port_base=base + 1000, advertise="10.9.8.7", allow_public=False)                   # config change: stored ports win
        self.assertEqual(c2.doors()["b"]["port"], base + 3)
        ep = c2.door_endpoint("b")
        self.assertEqual(ep["addr"], f"10.9.8.7:{base + 2}#{d['b']['fp']}")
        c.close_door("b")
        self.assertEqual(c.open_door("e", "peer", credential=pub), base + 9)

    def test_door_gone_needs_no_entry_and_no_key_file(self):
        tmp = Path(tempfile.mkdtemp())
        c = carrier(tmp)
        _, pub = c.new_credential()
        c.open_door("j", "join", credential=pub)
        self.assertFalse(c.door_gone("j"))
        c.close_door("j")
        self.assertTrue(c.door_gone("j"))
        self.assertFalse((tmp / "door-j.pem").exists())
        c.open_door("k", "join", credential=pub)
        (tmp / "doors.json").write_text(json.dumps({"version": 1, "next_index": 1, "doors": {}}))
        self.assertFalse(c.door_gone("k"), "the key file is still there")

    def test_damaged_state_is_a_clear_nonretryable_error(self):
        tmp = Path(tempfile.mkdtemp())
        c = carrier(tmp)
        (tmp / "doors.json").write_text("{not json")
        with self.assertRaises(CarrierError) as cm:
            c.doors()
        self.assertFalse(cm.exception.retry)
        (tmp / "doors.json").write_text(json.dumps({"version": 1, "next_index": 0, "doors": {"a": {"kind": "peer"}}}))
        with self.assertRaises(CarrierError):
            c.doors()
        (tmp / "doors.json").write_text(json.dumps({"version": 2, "next_index": 0, "doors": {}}))
        with self.assertRaises(CarrierError):
            c.doors()

    def test_start_is_idempotent_and_a_busy_port_leaves_nothing_half_open(self):
        c = self.new()
        _, pub = c.new_credential()
        c.open_door("a", "peer", credential=pub)
        c.open_door("b", "peer", credential=pub)
        busy = socket.socket()
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        busy.bind(("127.0.0.1", c._load()["doors"]["b"]["listen_port"]))
        busy.listen(1)
        self.socks.append(busy)
        with self.assertRaises(CarrierError) as cm:
            c.start()
        self.assertFalse(cm.exception.retry)
        self.assertIn(str(c._load()["doors"]["b"]["listen_port"]), str(cm.exception))
        self.assertFalse(c.started)
        self.assertEqual(c._listeners, {})
        a_port = c._load()["doors"]["a"]["listen_port"]
        probe = socket.socket()
        probe.bind(("127.0.0.1", a_port))                                    # door a's listener was closed again
        probe.close()
        busy.close()
        c.start()
        c.start()
        self.assertTrue(c.healthy())

    def test_missing_or_damaged_key_file_fails_start_without_retry(self):
        tmp = Path(tempfile.mkdtemp())
        c = carrier(tmp)
        _, pub = c.new_credential()
        c.open_door("a", "peer", credential=pub)
        pem = (tmp / "door-a.pem").read_bytes()
        (tmp / "door-a.pem").write_bytes(pem[:pem.index(b"-----BEGIN CERTIFICATE")])          # the cert half is gone
        with self.assertRaises(CarrierError) as cm:
            c.start()
        self.assertFalse(cm.exception.retry)
        (tmp / "door-a.pem").unlink()
        with self.assertRaises(CarrierError):
            c.start()
        self.assertFalse(c.started)

    def test_one_unbindable_new_door_does_not_take_the_other_doors_down(self):
        """Sansa F2: reconfigure() runs every node tick; a new door whose port is taken is remembered and retried, the others keep serving, healthy() stays True."""
        c, ep, secret, port = self.door()
        cli = TL.TcpCarrier(c.dir, bind="127.0.0.1", port_base=c.port_base)
        _, pub = cli.new_credential()
        cli.open_door("bad", "peer", credential=pub)
        cli.open_door("later", "peer", credential=pub)                      # dict order: AFTER the bad one
        listen = cli._load()["doors"]["bad"]["listen_port"]
        busy = socket.socket()
        busy.bind(("127.0.0.1", listen))
        busy.listen(1)
        self.socks.append(busy)
        self.assertTrue(c.reconfigure() in (True, False))                    # no raise
        self.assertTrue(c.healthy())
        self.assertIn("bad", c.last_errors())
        self.assertIn(str(listen), c.last_errors()["bad"])
        self.assertIn("later", c._listeners)                                # the door after the bad one got its listener
        self.assertIn("d", c._listeners)
        me = self.new()
        me.use_credential(ep, secret)
        self.assertEqual(me.dial(ep, timeout=5).request({"t": "ping", "n": 1})["t"], "pong")      # the old door still serves
        busy.close()
        self.assertTrue(c.reconfigure())                                     # retried: it opens now
        self.assertEqual(c.last_errors(), {})
        self.assertIn("bad", c._listeners)
        with self.assertRaises(CarrierError):                                # start() stays fail-loud
            c2 = self.new(port_base=c.port_base)
            c2.dir.mkdir(exist_ok=True)
            (c2.dir / "doors.json").write_text((c.dir / "doors.json").read_text())
            for f in c.dir.glob("door-*.pem"):
                (c2.dir / f.name).write_bytes(f.read_bytes())
            c2.start()

    def test_damaged_state_in_reconfigure_keeps_the_node_alive_fails_closed_and_is_reported(self):
        c, ep, secret, port = self.door()
        good = (c.dir / "doors.json").read_text()
        (c.dir / "doors.json").write_text("{broken")
        self.assertFalse(c.reconfigure())
        self.assertTrue(c.healthy())
        self.assertIn("(state)", c.last_errors())
        me = self.new()
        me.use_credential(ep, secret)
        with self.assertRaises(CarrierError):                              # fail CLOSED: with the door entry unreadable no connection can be verified, so none is served
            me.dial(ep, timeout=3).request({"t": "ping", "n": 2})
        (c.dir / "doors.json").write_text(good)                            # repaired: the same listeners serve again, nothing was torn down
        c.reconfigure()
        self.assertEqual(c.last_errors(), {})
        self.assertEqual(me.dial(ep, timeout=5).request({"t": "ping", "n": 3})["t"], "pong")

    def test_a_damaged_held_credential_is_not_retryable(self):
        c, ep, secret, port = self.door()
        me = self.new()
        me.use_credential(ep, secret)
        held = json.loads((me.dir / "held.json").read_text())
        held[ep["addr"]] = {"type": "tcp", "key": "zz"}
        (me.dir / "held.json").write_text(json.dumps(held))
        with self.assertRaises(CarrierError) as cm:
            me.dial(ep, timeout=3).request({"t": "ping"})
        self.assertFalse(cm.exception.retry)

    def test_restart_rebinds_the_same_ports_and_peers_reconnect_at_once(self):
        c, ep, secret, port = self.door()
        me = self.new()
        me.use_credential(ep, secret)
        self.assertEqual(me.dial(ep, timeout=5).request({"t": "ping", "n": 1})["t"], "pong")
        c.stop()
        self.assertFalse(c.healthy())
        with self.assertRaises(CarrierError):
            me.dial(ep, timeout=2).request({"t": "ping"})
        c.start()
        self.assertTrue(c.healthy())
        self.assertEqual(me.dial(ep, timeout=5).request({"t": "ping", "n": 2})["echo"], 2)

    def test_threads_do_not_leak_after_stop(self):
        before = threading.active_count()
        c, ep, secret, port = self.door()
        me = self.new()
        me.use_credential(ep, secret)
        for i in range(5):
            me.dial(ep, timeout=5).request({"t": "ping", "n": i})
        c.stop()
        time.sleep(0.5)
        self.assertLessEqual(threading.active_count(), before + 1)

    def test_a_removed_door_ends_its_live_streams_on_reconfigure(self):
        slow = lambda req: (time.sleep(3), {"t": "pong", "echo": 1})[1]
        c, ep, secret, port = self.door(handler=slow)
        t, h, a, ack = self.admit(ep, secret)
        from sigilnet import canon
        t.sendall(tcp._frame(canon.dumps({"t": "ping"})))
        time.sleep(0.3)
        other_process_view = TL.TcpCarrier(c.dir, bind="127.0.0.1", port_base=c.port_base)       # the CLI, another process, shares only the state dir
        other_process_view.close_door("d")
        c.reconfigure()                                                                        # the running node notices
        t0 = time.time()
        t.settimeout(2.5)
        try:
            data = t.recv(10)
            ended = data == b""
        except socket.timeout:
            ended = False                                                                      # a client-side timeout is NOT the door hanging up
        except (OSError, ssl.SSLError):
            ended = True
        self.assertTrue(ended)
        self.assertLess(time.time() - t0, 1.5)
        self.assertNotIn("d", c._listeners)

    def test_reconfigure_opens_doors_added_by_another_process(self):
        c = self.new()
        c.start()
        cli = TL.TcpCarrier(c.dir, bind="127.0.0.1", port_base=c.port_base)
        secret, pub = cli.new_credential()
        port = cli.open_door("late", "peer", credential=pub)
        self.servers.append(TcpServer("127.0.0.1", port, None, lambda r: {"t": "pong", "echo": 1}).start())
        self.assertTrue(c.reconfigure())
        self.assertFalse(c.reconfigure())
        me = self.new()
        ep = cli.door_endpoint("late")
        me.use_credential(ep, secret)
        self.assertEqual(me.dial(ep, timeout=5).request({"t": "ping"})["t"], "pong")

    def test_secrets_never_leak_into_repr_or_errors(self):
        c, ep, secret, port = self.door()
        me = self.new()
        me.use_credential(ep, secret)
        seed = secret["key"]
        self.assertNotIn(seed, repr(secret))
        c.close_door("d")
        try:
            me.dial(ep, timeout=2).request({"t": "ping"})
        except CarrierError as e:
            self.assertNotIn(seed, str(e))
        for f in c.dir.iterdir():
            if f.name != "held.json":
                self.assertNotIn(seed, f.read_text(errors="replace"))
        self.assertIn(seed, (me.dir / "held.json").read_text())

    def test_held_key_is_the_normalized_endpoint_and_drop_reports_truthfully(self):
        c = self.new()
        secret, _ = c.new_credential()
        ep = {"type": "tcp", "addr": "10.0.0.1:47600#" + "cd" * 32}
        c.use_credential({"type": "tcp", "addr": " 10.0.0.1:47600#" + "CD" * 32 + " "}, secret)
        self.assertEqual(list(json.loads((c.dir / "held.json").read_text())), [ep["addr"]])
        self.assertTrue(c.drop_credential(ep))
        self.assertFalse(c.drop_credential(ep))


class ServerLimits(Rig):
    """Sansa F4-1: the protocol guard behind a door admits 240 connections/min (a Tor-sized default); the one-connection-per-request TCP carrier must not hit it on a
    peer/join door, while public doors keep the default."""

    def served(self, kind, name, **kw):
        c = self.new(**kw)
        secret, pub = c.new_credential()
        port = c.open_door(name, kind, credential=pub) if kind in ("peer", "join") else c.open_door(name, kind)
        self.servers.append(TcpServer("127.0.0.1", port, None, lambda req: {"t": "pong"}, max_conns=64, **c.server_limits(kind)).start())
        c.start()
        ep = c.door_endpoint(name)
        me = self.new()
        me.use_credential(ep, secret)
        return me.dial(ep, timeout=5)

    @staticmethod
    def hammer(tr, n):
        ok, first = 0, None
        for i in range(n):
            try:
                tr.request({"t": "ping"})
                ok += 1
            except ConnectionError:
                first = first or i + 1
        return ok, first

    def test_a_peer_door_answers_300_sequential_requests(self):
        ok, first = self.hammer(self.served("peer", "p"), 300)
        self.assertEqual((ok, first), (300, None))

    def test_a_join_door_keeps_the_default_limit(self):
        """Sansa: a join door is reachable by whoever holds the capsule block and the join flow needs ~30 requests/min: no raised limit there."""
        ok, first = self.hammer(self.served("join", "j"), 260)
        self.assertEqual((ok, first), (240, 241))

    def test_the_peer_limit_stays_above_the_typed_blob_budgets(self):
        """If it fell below blobserve's request budgets the silent drop would hide them again (F4-1)."""
        from sigilnet import blobserve
        self.assertGreater(TL.PEER_PER_MIN, blobserve.GLOBAL_REQS_PER_MIN)
        self.assertGreater(TL.PEER_PER_MIN, blobserve.PEER_REQS_PER_MIN)
        self.assertGreater(TL.PEER_PER_MIN, tcp.PLAIN_PER_MIN)

    def test_a_public_door_still_stops_at_240(self):
        ok, first = self.hammer(self.served("read", "r"), 260)
        self.assertEqual((ok, first), (240, 241))

    def test_limits_per_kind_and_other_carriers_keep_the_defaults(self):
        c = self.new()
        self.assertEqual(c.server_limits("peer"), {"plain_per_min": TL.PEER_PER_MIN})
        self.assertEqual(c.server_limits("join"), {})
        self.assertEqual(c.server_limits("read"), {})
        self.assertEqual(c.server_limits("inbox"), {})
        from sigilnet.tests.fake_carrier import FakeCarrier, FakeNet
        from sigilnet.torlink import TorNode
        for other in (FakeCarrier(FakeNet(), "x"), TorNode(tempfile.mkdtemp(), offline=True)):
            for kind in C.KINDS:
                self.assertEqual(other.server_limits(kind), {}, (type(other).__name__, kind))

    def test_tcpserver_default_is_unchanged_and_the_parameter_is_validated(self):
        s = TcpServer("127.0.0.1", 0, None, lambda r: {"t": "pong"})
        self.servers.append(s)
        self.assertEqual(s.plain_per_min, tcp.PLAIN_PER_MIN)
        for bad in (0, -1, True, "5", 1.5):
            with self.assertRaises(ValueError, msg=bad):
                TcpServer("127.0.0.1", 0, None, lambda r: {}, plain_per_min=bad)

    def test_the_doors_layer_hands_each_kind_its_own_limit(self):
        from sigilnet.doors import Doors
        c = self.new()
        _, pub = c.new_credential()
        c.open_door("pe", "peer", credential=pub)
        c.open_door("re", "read")
        c.start()

        class Sync:
            def handle(self, req):
                return {"t": "pong"}
        d = Doors(c, Sync(), lambda *a: None, {"read": lambda req: {"t": "pong"}}, allow_public_without_ip_hiding=True)
        d.sync()
        try:
            self.assertEqual(d.servers["pe"].plain_per_min, TL.PEER_PER_MIN)
            self.assertEqual(d.servers["re"].plain_per_min, tcp.PLAIN_PER_MIN)
        finally:
            d.stop()


if __name__ == "__main__":
    unittest.main()
