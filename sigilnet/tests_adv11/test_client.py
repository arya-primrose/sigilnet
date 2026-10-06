"""tests_adv11 part 3: the DIALER against hostile or odd doors (spec R3 steps 1-3, R4, A3, A13). A fake door speaks TLS by hand and records every byte the client sends."""
import datetime
import hashlib
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from sigilnet import canon, carrier as C, tcp
from sigilnet.carrier import CarrierError
from sigilnet.tests_adv11.h import Base, Raw, addr_parts, drain, msg, raw_pub, spki_fp, wait_for


def make_cert(key, serial=1):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(serial)
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))


class FakeDoor:
    """script(conn, rec) runs after a successful TLS handshake. rec.got collects bytes the script reads via rec.read()."""

    def __init__(self, tmp, script, *, version=ssl.TLSVersion.TLSv1_3, key=None, serial=1, min_version=None):
        self.key = key or ec.generate_private_key(ec.SECP256R1())
        cert = make_cert(self.key, serial)
        d = Path(tempfile.mkdtemp(dir=tmp))
        pem = d / "k.pem"
        pem.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + cert.public_bytes(serialization.Encoding.PEM))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pem)
        self.ctx.maximum_version = version
        if min_version is not None:
            self.ctx.minimum_version = min_version
        self.ctx.set_alpn_protocols(["h2", "http/1.1", "sntcp"])
        self.sni = []
        self.ctx.sni_callback = lambda s, name, c: self.sni.append(name)
        self.fp = spki_fp(self.key.public_key())
        self.script = script
        self.got = bytearray()
        self.alpn = []
        self.conns = 0
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(8)
        self.ls.settimeout(0.2)
        self.port = self.ls.getsockname()[1]
        self.stop_ev = threading.Event()
        self.th = threading.Thread(target=self.loop, daemon=True)
        self.th.start()

    @property
    def ep(self):
        return {"type": "tcp", "addr": f"127.0.0.1:{self.port}#{self.fp}"}

    def loop(self):
        while not self.stop_ev.is_set():
            try:
                c, _ = self.ls.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        t = c
        try:
            c.settimeout(5)
            t = self.ctx.wrap_socket(c, server_side=True)
            self.conns += 1
            self.alpn.append(t.selected_alpn_protocol())
            self.script(t, self)
        except (OSError, ssl.SSLError):
            pass
        finally:
            for x in (t, c):
                try:
                    x.close()
                except OSError:
                    pass

    def read(self, conn, n, t=3.0):
        buf = b""
        end = time.time() + t
        while len(buf) < n:
            conn.settimeout(max(0.05, end - time.time()))
            try:
                d = conn.recv(n - len(buf))
            except (socket.timeout, ssl.SSLError):
                break
            if not d:
                break
            buf += d
            self.got += d
        return buf

    def stop(self):
        self.stop_ev.set()
        self.ls.close()


def hello(mode=1, nonce=b"N" * 32, magic=b"SNTCP1"):
    return magic + bytes([mode]) + nonce


class Dialer(Base):
    def setUp(self):
        super().setUp()
        self.bob = self.mk("bob", port_base=self.base + 40)

    def fake(self, script, **kw):
        f = FakeDoor(self.tmp, script, **kw)
        self.cleanups.append(f.stop)
        return f

    def req(self, ep, **kw):
        return self.bob.dial(ep, timeout=kw.pop("timeout", 4), **kw).request({"t": "ping", "n": 1})

    def err(self, ep, retry, **kw):
        with self.assertRaises(CarrierError) as cm:
            self.req(ep, **kw)
        self.assertEqual(cm.exception.retry, retry, str(cm.exception))
        return cm.exception

    # ---- pin
    def test_wrong_pin_is_refused_before_a_single_byte_and_without_retry(self):
        f = self.fake(lambda c, f: (c.sendall(hello(0)), f.read(c, 100, 1)))
        bad = dict(f.ep, addr=f.ep["addr"].split("#")[0] + "#" + "0" * 64)
        self.err(bad, False)
        other = self.fake(lambda c, f: None)
        self.err(dict(f.ep, addr=f.ep["addr"].split("#")[0] + "#" + other.fp), False)
        self.assertEqual(bytes(f.got), b"")

    def test_pin_is_the_spki_not_the_certificate(self):
        key = ec.generate_private_key(ec.SECP256R1())
        for serial in (7, 8):
            f = self.fake(lambda c, f: (c.sendall(hello(0)), f.read(c, 4), c.sendall(tcp._frame(canon.dumps({"t": "pong", "echo": 1})))), key=key, serial=serial)
            self.assertEqual(self.req(f.ep), {"t": "pong", "echo": 1})

    def test_door_must_present_the_pinned_key_even_with_a_valid_looking_chain(self):
        f = self.fake(lambda c, f: c.sendall(hello(0)))
        ep = dict(f.ep, addr=f"127.0.0.1:{f.port}#" + hashlib.sha256(b"x").hexdigest())
        self.err(ep, False)

    # ---- hello
    def test_bad_hello_variants_are_retryable_and_the_client_has_said_nothing(self):
        variants = {"magic": hello(1, magic=b"SNTCP2"), "mode2": hello(2), "mode255": hello(255), "short": hello(0)[:10], "empty": b"", "http": b"HTTP/1.1 200 OK\r\n\r\n" + bytes(40),
                    "38": hello(0)[:38]}
        for name, h in variants.items():
            f = self.fake(lambda c, f, h=h: (c.sendall(h) if h else None, f.read(c, 200, 1.5)))
            with self.subTest(name):
                self.bob.use_credential(f.ep, self.bob.new_credential()[0])               # holding a credential changes nothing here
                self.err(f.ep, True)
                self.assertEqual(bytes(f.got), b"", name)

    def test_credential_needed_but_not_held_is_final_and_silent(self):
        f = self.fake(lambda c, f: (c.sendall(hello(1)), f.read(c, 200, 1.5)))
        self.err(f.ep, False)
        self.assertEqual(bytes(f.got), b"")
        # a credential held for ANOTHER door (other port / other fp) does not count
        sec, _ = self.bob.new_credential()
        self.bob.use_credential({"type": "tcp", "addr": f"127.0.0.1:{f.port + 1}#{f.fp}"}, sec)
        self.bob.use_credential({"type": "tcp", "addr": f"127.0.0.1:{f.port}#{'0' * 64}"}, sec)
        self.bob.use_credential({"type": "tcp", "addr": f"127.0.0.2:{f.port}#{f.fp}"}, sec)
        self.err(f.ep, False)
        self.assertEqual(bytes(f.got), b"")

    def test_mode0_door_gets_only_the_request_even_if_a_credential_is_held(self):
        f = self.fake(lambda c, f: (c.sendall(hello(0)), f.read(c, 4096, 1.0), c.sendall(tcp._frame(canon.dumps({"t": "pong", "echo": 1})))))
        self.bob.use_credential(f.ep, self.bob.new_credential()[0])
        self.assertEqual(self.req(f.ep), {"t": "pong", "echo": 1})
        self.assertEqual(bytes(f.got), tcp._frame(canon.dumps({"t": "ping", "n": 1})))

    # ---- admission as the client does it
    def _door_mode1(self, ack=b"\x01", seen=None, nonce=b"\x07" * 32):
        def script(c, f):
            c.sendall(hello(1, nonce))
            a = f.read(c, 96)
            if seen is not None:
                seen.append(a)
            if ack is None:
                time.sleep(3)
                return
            c.sendall(ack)
            if ack == b"\x01":
                f.read(c, 4096, 0.5)
                c.sendall(tcp._frame(canon.dumps({"t": "pong", "echo": 1})))
        return script

    def test_client_auth_is_exactly_the_spec_message_and_signature(self):
        seen = []
        f = self.fake(self._door_mode1(b"\x01", seen))
        sec, pub = self.bob.new_credential()
        self.bob.use_credential(f.ep, sec)
        self.assertEqual(self.req(f.ep), {"t": "pong", "echo": 1})
        a = seen[0]
        self.assertEqual(len(a), 96)
        cpub, sig = a[:32], a[32:]
        self.assertEqual(hashlib.sha256(cpub).hexdigest(), pub["key"])
        ed25519.Ed25519PublicKey.from_public_bytes(cpub).verify(sig, msg(b"\x07" * 32, bytes.fromhex(f.fp), cpub))      # raises if the layout differs from R3.3
        # and the request frame came only after the admission byte (checked by the script order); the door saw 96 bytes then the request
        self.assertEqual(bytes(f.got), a + tcp._frame(canon.dumps({"t": "ping", "n": 1}))[:len(f.got) - 96])

    def test_not_admitted_variants_are_retryable(self):
        for ack in (b"\x00", b"\x02", b"\xff", b"", None):
            f = self.fake(self._door_mode1(ack))
            self.bob.use_credential(f.ep, self.bob.new_credential()[0])
            with self.subTest(ack=ack):
                t0 = time.time()
                self.err(f.ep, True, timeout=1.5)
                self.assertLess(time.time() - t0, 3.5)

    # ---- tls shape
    def test_tls12_only_door_is_retryable_and_gets_nothing(self):
        f = self.fake(lambda c, f: (c.sendall(hello(0)), f.read(c, 100, 1)), version=ssl.TLSVersion.TLSv1_2, min_version=ssl.TLSVersion.TLSv1_2)
        self.err(f.ep, True)
        self.assertEqual(f.conns, 0)

    def test_client_sends_no_sni_no_alpn_and_no_certificate(self):
        f = self.fake(lambda c, f: (c.sendall(hello(0)), f.read(c, 4), c.sendall(tcp._frame(canon.dumps({"t": "pong", "echo": 1})))))
        self.req(f.ep)
        self.assertEqual(f.alpn, [None])
        self.assertTrue(all(n is None for n in f.sni), f.sni)

    # ---- relay by a malicious door
    def test_a_trusted_door_cannot_relay_the_clients_admission_to_another_door(self):
        dsec, dpub = self.c.new_credential()
        port = self.c.open_door("real", "peer", credential=dpub)
        self.echo(port)
        self.c.start()
        d_ep = self.c.door_endpoint("real")
        relay_result = []

        def script(c, f):
            up = Raw(d_ep)                                       # M dials the real door D as an ordinary client
            _, nonce_d = up.hello()
            c.sendall(hello(1, nonce_d))                         # and hands D's nonce to the victim
            a = f.read(c, 96)
            relay_result.append(up.admitted(a))                  # relays the victim's reply to D
            c.sendall(b"\x01" if relay_result[0] else b"\x00")
        m = self.fake(script)
        self.bob.use_credential(m.ep, dsec)                      # the victim holds the credential D accepts, because it trusts M with it
        with self.assertRaises(CarrierError):
            self.req(m.ep, timeout=3)
        self.assertEqual(relay_result, [False])

    # ---- timeouts and exceptions
    def test_hello_that_never_comes_honours_the_budget(self):
        f = self.fake(lambda c, f: time.sleep(4))
        t0 = time.time()
        self.err(f.ep, True, timeout=1.0)
        self.assertLess(time.time() - t0, 2.5)
        t0 = time.time()
        self.err(f.ep, True, timeout=30, connect_timeout=1.0)                # connect_timeout bounds connect+TLS+hello+admission
        self.assertLess(time.time() - t0, 2.5)

    def test_exchange_budget_starts_after_the_connect_phase_when_connect_timeout_is_given(self):
        port = self.c.open_door("slow", "read")
        self.backend(port, lambda conn, rec: (conn.recv(4096), time.sleep(3), conn.sendall(b"late")))
        self.c.start()
        ep = self.c.door_endpoint("slow")
        t0 = time.time()
        with self.assertRaises(ConnectionError):
            self.bob.dial(ep, timeout=0.8, connect_timeout=5).request({"t": "ping", "n": 1})
        self.assertLess(time.time() - t0, 2.5)

    def test_backend_eof_or_bad_frame_is_a_connectionerror(self):
        port = self.c.open_door("bad", "read")
        self.backend(port, lambda conn, rec: (conn.recv(4096), conn.sendall(b"\x00\x00\x00\x05zzzzz")))
        self.c.start()
        with self.assertRaises(ConnectionError):
            self.bob.dial(self.c.door_endpoint("bad"), timeout=3).request({"t": "ping", "n": 1})

    def test_dial_is_lazy_and_validates(self):
        dead = {"type": "tcp", "addr": f"127.0.0.1:{self.base + 50}#{'ab' * 32}"}
        tr = self.bob.dial(dead, timeout=2)                                  # nothing listens: dial itself must not connect
        self.assertTrue(hasattr(tr, "request"))
        with self.assertRaises(CarrierError) as cm:
            tr.request({"t": "ping", "n": 1})
        self.assertTrue(cm.exception.retry)
        for ep in ({"type": "tcp", "addr": f"8.8.8.8:80#{'ab' * 32}"}, {"type": "tcp", "addr": f"1.1.1.1:80#{'ab' * 32}"}):   # (M3a: any IPv4 is dialed; here only constructed, never connected)
            with self.subTest(ep=ep):
                self.assertTrue(hasattr(self.bob.dial(ep, timeout=2), "request"))
        for ep in ({"type": "onion", "addr": "x" * 56 + ".onion:80"}, {"type": "tcp"}, {"type": "tcp", "addr": "nonsense"}, {"type": "tcp", "addr": f"127.0.0.1:80#{'ab' * 31}"}, "str", None,
                   {"type": "tcp", "addr": f"127.0.0.1:80#{'ab' * 32}", "x": 1}):
            with self.subTest(ep=ep), self.assertRaises(CarrierError) as cm:
                self.bob.dial(ep, timeout=2)
            self.assertFalse(cm.exception.retry)

    def test_allow_public_lets_dial_accept_a_public_address_lazily(self):
        pub = self.mk("pubc", allow_public=True, bind="127.0.0.1", port_base=self.base + 44)
        tr = pub.dial({"type": "tcp", "addr": f"8.8.8.8:80#{'ab' * 32}"}, timeout=0.5)
        self.assertTrue(hasattr(tr, "request"))                               # constructed, never connected

    def test_credential_bound_to_the_full_address(self):
        a_sec, a_pub = self.c.new_credential()
        pa = self.c.open_door("a", "peer", credential=a_pub)
        pb = self.c.open_door("b", "peer", credential=a_pub)
        self.echo(pa)
        self.echo(pb)
        self.c.start()
        self.bob.use_credential(self.c.door_endpoint("a"), a_sec)
        self.assertEqual(self.req(self.c.door_endpoint("a"))["echo"], 1)
        self.err(self.c.door_endpoint("b"), False)                           # same key accepted at b, but this client holds it for a only
        self.assertTrue(self.bob.drop_credential(self.c.door_endpoint("a")))
        self.err(self.c.door_endpoint("a"), False)
