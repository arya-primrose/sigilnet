"""Helpers for tests_adv11 (Sansa, round 36): the TCP carrier spec (DESIGN_tcp_carrier rev 1.1) spoken from the OUTSIDE. Every wire format here is re-implemented from
the spec text (not imported from tcplink), so a bug shared by the carrier's client and door cannot hide."""
import hashlib
import os
import random
import socket
import ssl
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from sigilnet import canon, tcp
from sigilnet.carrier import CarrierError
from sigilnet.tcp import TcpServer
from sigilnet.tcplink import TcpCarrier

AGENT = "a" * 32
PIPE_UP = tcp.MAX_REQ + 64
PIPE_DOWN = tcp.MAX_RESP + 64
L = 2**252 + 27742317777372353535851937790883648493


def free_base(n=64):
    for _ in range(200):
        base = random.randrange(20000, 60000, 2)
        socks = []
        try:
            for p in range(base, base + n):
                s = socket.socket()
                s.bind(("127.0.0.1", p))
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no free port range")


def spki_fp(pub) -> str:
    return hashlib.sha256(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def msg(nonce: bytes, fp: bytes, pub: bytes, tag=b"sigilnet-tcp-auth-1") -> bytes:
    """M exactly as R3.3: four 2-byte-length-prefixed fields."""
    return b"".join(len(x).to_bytes(2, "big") + x for x in (tag, nonce, fp, hashlib.sha256(pub).digest()))


def raw_pub(priv) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def addr_parts(ep):
    hp, fp = ep["addr"].split("#")
    ip, port = hp.split(":")
    return ip, int(port), fp


def client_ctx(version=ssl.TLSVersion.TLSv1_3):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = c.maximum_version = version
    return c


def drain(s, t=3.0):
    """Everything the peer sends until EOF/error/timeout (never raises)."""
    out = b""
    end = time.time() + t
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try:
            d = s.recv(65536)
        except (OSError, ssl.SSLError):
            break
        if not d:
            break
        out += d
    return out


def closed_within(s, t=3.0):
    """True iff the peer ENDS the stream (EOF / reset / TLS error) within t seconds; a quiet timeout is False (drain() cannot tell the two apart)."""
    end = time.time() + t
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try:
            d = s.recv(65536)
        except socket.timeout:
            return False
        except (OSError, ssl.SSLError):
            return True
        if not d:
            return True
    return False


class Raw:
    """A hand-made client of a door: TLS 1.3 (or not), then the bytes of R3."""

    def __init__(self, ep, *, tls=True, timeout=5.0, version=ssl.TLSVersion.TLSv1_3, session=None):
        self.ip, self.port, self.fp = addr_parts(ep)
        self.s = socket.create_connection((self.ip, self.port), timeout=timeout)
        self.s.settimeout(timeout)
        self.t = timeout
        if tls:
            self.s = client_ctx(version).wrap_socket(self.s, server_hostname=None, session=session)

    def exact(self, n, t=None):
        buf = b""
        end = time.time() + (t or self.t)
        while len(buf) < n:
            self.s.settimeout(max(0.05, end - time.time()))
            d = self.s.recv(n - len(buf))
            if not d:
                raise EOFError(f"EOF after {len(buf)} of {n} bytes")
            buf += d
        return buf

    def hello(self):
        h = self.exact(39)
        assert h[:6] == b"SNTCP1", h[:6]
        return h[6], h[7:]

    def auth(self, priv, nonce, fp=None, *, tag=b"sigilnet-tcp-auth-1", sign_pub=None):
        pub = raw_pub(priv)
        fpb = bytes.fromhex(fp or self.fp)
        sig = priv.sign(msg(nonce, fpb, sign_pub or pub, tag))
        return pub + sig

    def admitted(self, data):
        """Send the 96 bytes; True iff the door answers 0x01. Any other outcome must carry NO byte."""
        self.s.sendall(data)
        got = drain(self.s, 3.0)
        if got[:1] == b"\x01":
            return True
        assert got == b"", f"a refused client received {got!r}"
        return False

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class RecBackend:
    """The protocol's side of a door, raw: records accepts, peers and bytes; reply = bytes to send once, or callable(conn)."""

    def __init__(self, port, reply=None, hold=False):
        self.accepts = 0
        self.peers = []
        self.received = bytearray()
        self.conns = []
        self.reply, self.hold = reply, hold
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", port))
        self.ls.listen(16)
        self.ls.settimeout(0.2)
        self.stop_ev = threading.Event()
        self.mu = threading.Lock()
        self.th = threading.Thread(target=self.loop, daemon=True)
        self.th.start()

    def loop(self):
        while not self.stop_ev.is_set():
            try:
                c, a = self.ls.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.mu:
                self.accepts += 1
                self.peers.append(a[0])
                self.conns.append(c)
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        try:
            if callable(self.reply):
                self.reply(c, self)
                return
            while True:
                c.settimeout(0.3)
                try:
                    d = c.recv(65536)
                except socket.timeout:
                    if self.stop_ev.is_set():
                        return
                    continue
                if not d:
                    return
                with self.mu:
                    self.received += d
                if self.reply is not None:
                    c.sendall(self.reply)
                    if not self.hold:
                        return
        except OSError:
            pass
        finally:
            if not self.hold:
                try:
                    c.close()
                except OSError:
                    pass

    def stop(self):
        self.stop_ev.set()
        try:
            self.ls.close()
        except OSError:
            pass
        for c in self.conns:
            try:
                c.close()
            except OSError:
                pass


def wait_for(fn, t=5.0, step=0.05):
    end = time.time() + t
    while time.time() < end:
        if fn():
            return True
        time.sleep(step)
    return fn()


class Base(unittest.TestCase):
    """A started TcpCarrier on 127.0.0.1 in a temp dir. self.mk(**kw) makes more carriers over the same or other dirs."""
    KW: dict = {}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.base = free_base()
        self.cleanups = []
        self.addCleanup(self._cleanup)
        self.c = self.mk()

    def _cleanup(self):
        for f in reversed(self.cleanups):
            try:
                f()
            except Exception:
                pass

    def mk(self, name="a", **kw):
        args = dict(bind="127.0.0.1", port_base=self.base)
        args.update(self.KW)
        args.update(kw)
        c = TcpCarrier(self.tmp / name, **args)
        self.cleanups.append(c.stop)
        return c

    def backend(self, port, reply=None, hold=False):
        b = RecBackend(port, reply, hold)
        self.cleanups.append(b.stop)
        return b

    def echo(self, port):
        s = TcpServer("127.0.0.1", port, None, lambda req: {"t": "pong", "echo": req.get("n")}).start()
        self.cleanups.append(s.stop)
        return s

    def door(self, name="d", kind="peer", echo=True, **kw):
        """Open a door on self.c; returns (endpoint, secret, loopback_port)."""
        secret = pub = None
        if kind in ("peer", "join"):
            secret, pub = self.c.new_credential()
            kw["credential"] = pub
        port = self.c.open_door(name, kind, **kw)
        self.c.reconfigure()                      # a running carrier learns of a door made by "another process" here (no-op when not started)
        if echo:
            self.echo(port)
        return self.c.door_endpoint(name), secret, port

    def priv(self, secret):
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret["key"]))
