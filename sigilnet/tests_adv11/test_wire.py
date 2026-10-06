"""tests_adv11 part 2: the door as seen by a HOSTILE client (spec R3 steps 0-5, A1-A5, A9). Real sockets on 127.0.0.1."""
import hashlib
import os
import socket
import ssl
import threading
import time

from cryptography.hazmat.primitives.asymmetric import ed25519

from sigilnet import canon, tcp
from sigilnet.carrier import CarrierError
from sigilnet.tests_adv11.h import (Base, Raw, L, PIPE_UP, PIPE_DOWN, addr_parts, client_ctx, drain, msg, raw_pub, wait_for)


class Good(Base):
    def test_peer_door_roundtrip_and_what_the_protocol_sees(self):
        ep, secret, port = self.door("p", echo=False)
        got = []

        def reply(conn, rec):
            d = conn.recv(65536)
            got.append(d)
            conn.sendall(tcp._frame(canon.dumps({"t": "pong", "echo": 7})))
        b = self.backend(port, reply)
        self.c.start()
        bob = self.mk("bob")
        bob.use_credential(ep, secret)
        self.assertEqual(bob.dial(ep, timeout=5).request({"t": "ping", "n": 7}), {"t": "pong", "echo": 7})
        self.assertEqual(got, [tcp._frame(canon.dumps({"t": "ping", "n": 7}))])       # exactly the protocol's frame: no hello, no TLS, no auth bytes
        self.assertEqual(b.peers, ["127.0.0.1"])
        self.assertEqual(b.accepts, 1)

    def test_public_and_join_doors(self):
        ep, _, _ = self.door("pr", "read")
        ep2, sec, _ = self.door("jn", "join")
        self.c.start()
        bob = self.mk("bob")
        self.assertEqual(bob.dial(ep, timeout=5).request({"t": "ping", "n": 1})["echo"], 1)
        bob.use_credential(ep2, sec)
        self.assertEqual(bob.dial(ep2, timeout=5).request({"t": "ping", "n": 2})["echo"], 2)

    def test_hello_layout_modes_nonce_and_tls13(self):
        epp, _, _ = self.door("p")
        epr, _, _ = self.door("r", "inbox")
        self.c.start()
        seen = set()
        for ep, mode in ((epp, 1), (epr, 0)):
            for _ in range(3):
                r = Raw(ep)
                self.assertEqual(r.s.version(), "TLSv1.3")
                self.assertIsNone(r.s.selected_alpn_protocol())
                m, nonce = r.hello()
                self.assertEqual(m, mode)
                self.assertEqual(len(nonce), 32)
                seen.add(nonce)
                r.close()
        self.assertEqual(len(seen), 6)                                                # a fresh nonce per connection, also for public doors

    def test_dialer_hello_is_exactly_39_bytes_and_nothing_extra_is_sent_first(self):
        ep, _, _ = self.door("r", "read")
        self.c.start()
        r = Raw(ep)
        h = r.exact(39)
        self.assertEqual(h[:7], b"SNTCP1\x00")
        r.s.settimeout(0.5)
        with self.assertRaises(socket.timeout):                                        # the door says nothing more until it is spoken to
            r.s.recv(1)

    def test_pipelined_request_behind_the_auth_is_served_after_admission(self):
        ep, secret, port = self.door("p")
        self.c.start()
        r = Raw(ep)
        mode, nonce = r.hello()
        self.assertEqual(mode, 1)
        frame = tcp._frame(canon.dumps({"t": "ping", "n": 5}))
        r.s.sendall(r.auth(self.priv(secret), nonce) + frame)                          # A1: request data behind the 96 bytes
        self.assertEqual(r.exact(1), b"\x01")
        n = int.from_bytes(r.exact(4), "big")
        self.assertEqual(canon.loads(r.exact(n)), {"t": "pong", "echo": 5})

    def test_two_connections_two_requests_and_many_in_parallel(self):
        ep, secret, port = self.door("p")
        self.c.start()
        bob = self.mk("bob")
        bob.use_credential(ep, secret)
        out, errs = [], []

        self.assertEqual(bob.dial(ep, timeout=10).request({"t": "ping", "n": -1})["echo"], -1)   # (M3b: a stranger gets 4 at a time: the first admission proves the address)
        sem = threading.Semaphore(6)                                  # the per-door default cap is 8 admitted streams

        def go(i):
            try:
                with sem:
                    out.append(bob.dial(ep, timeout=10).request({"t": "ping", "n": i})["echo"])
            except Exception as e:
                errs.append(repr(e))
        ts = [threading.Thread(target=go, args=(i,)) for i in range(24)]
        [t.start() for t in ts]
        [t.join(30) for t in ts]
        self.assertEqual(errs, [])
        self.assertEqual(sorted(out), list(range(24)))

    def test_request_too_large_is_a_valueerror_before_any_connect(self):
        ep, secret, _ = self.door("p")                       # NOT started: nothing may be dialled
        bob = self.mk("bob")
        bob.use_credential(ep, secret)
        with self.assertRaises(ValueError):
            bob.dial(ep, timeout=2).request({"t": "x", "blob": "a" * (tcp.MAX_REQ + 10)})


class Admission(Base):
    def setUp(self):
        super().setUp()
        self.ep, self.secret, self.port = self.door("p")
        self.nback = self.backend  # alias
        self.c.start()
        self.priv_ = self.priv(self.secret)

    def attempt(self, make, ep=None):
        """make(raw, nonce) -> the 96 bytes to send. Returns whether admitted."""
        r = Raw(ep or self.ep)
        try:
            mode, nonce = r.hello()
            return r.admitted(make(r, nonce))
        finally:
            r.close()

    def test_correct_reply_is_admitted_control(self):
        self.assertTrue(self.attempt(lambda r, n: r.auth(self.priv_, n)))

    def test_unauthorized_key(self):
        other = ed25519.Ed25519PrivateKey.generate()
        self.assertFalse(self.attempt(lambda r, n: r.auth(other, n)))

    def test_wrong_nonce_and_replay(self):
        self.assertFalse(self.attempt(lambda r, n: r.auth(self.priv_, os.urandom(32))))
        recorded = []
        self.assertTrue(self.attempt(lambda r, n: recorded.append(r.auth(self.priv_, n)) or recorded[0]))
        self.assertFalse(self.attempt(lambda r, n: recorded[0]))                         # replay of a recorded valid reply: new nonce
        self.assertFalse(self.attempt(lambda r, n: recorded[0]))

    def test_wrong_door_fingerprint_and_relay_to_another_door(self):
        epb, _, _ = self.door("q")                                                          # door B, same machine
        _, _, fp_b = addr_parts(epb)
        self.assertFalse(self.attempt(lambda r, n: r.auth(self.priv_, n, fp=fp_b)))          # signed for B, presented to A
        self.assertFalse(self.attempt(lambda r, n: r.auth(self.priv_, n, fp="00" * 32)))

    def test_relay_of_a_credential_valid_at_two_doors(self):
        # door B accepts the SAME client key; a client auth made for A must not open B (the fp is inside the signature)
        c2 = self.tmp / "unused"
        pub_hash = hashlib.sha256(raw_pub(self.priv_)).hexdigest()
        self.c.open_door("q", "peer", credential={"type": "tcp", "key": pub_hash})
        self.c.reconfigure()
        epb = self.c.door_endpoint("q")
        self.echo(self.c.doors()["q"]["port"])
        rb = Raw(epb)
        _, nb = rb.hello()
        ra = Raw(self.ep)
        _, na = ra.hello()
        self.assertTrue(ra.admitted(ra.auth(self.priv_, na)))                                # honest at A
        self.assertFalse(rb.admitted(ra.auth(self.priv_, nb)))                                # signed with A's fp, replayed live at B
        rb.close()
        self.assertTrue(self.attempt(lambda r, n: r.auth(self.priv_, n), epb))                # control: honest at B

    def test_domain_tag_and_field_encoding(self):
        self.assertFalse(self.attempt(lambda r, n: r.auth(self.priv_, n, tag=b"sigilnet-tcp-auth-2")))
        self.assertFalse(self.attempt(lambda r, n: r.auth(self.priv_, n, tag=b"")))

        def unprefixed(r, n):
            pub = raw_pub(self.priv_)
            return pub + self.priv_.sign(b"sigilnet-tcp-auth-1" + n + bytes.fromhex(r.fp) + hashlib.sha256(pub).digest())
        self.assertFalse(self.attempt(unprefixed))

        def one_byte_prefix(r, n):
            pub = raw_pub(self.priv_)
            m = b"".join(bytes([len(x)]) + x for x in (b"sigilnet-tcp-auth-1", n, bytes.fromhex(r.fp), hashlib.sha256(pub).digest()))
            return pub + self.priv_.sign(m)
        self.assertFalse(self.attempt(one_byte_prefix))

        def swapped(r, n):
            pub = raw_pub(self.priv_)
            m = b"".join(len(x).to_bytes(2, "big") + x for x in (b"sigilnet-tcp-auth-1", n, hashlib.sha256(pub).digest(), bytes.fromhex(r.fp)))
            return pub + self.priv_.sign(m)
        self.assertFalse(self.attempt(swapped))

        def signs_raw_pub_not_its_hash(r, n):
            pub = raw_pub(self.priv_)
            m = b"".join(len(x).to_bytes(2, "big") + x for x in (b"sigilnet-tcp-auth-1", n, bytes.fromhex(r.fp), pub))
            return pub + self.priv_.sign(m)
        self.assertFalse(self.attempt(signs_raw_pub_not_its_hash))

    def test_signature_vector(self):
        """A fixed vector pins R3.3 byte for byte: M = 4 x (2-byte BE length + field)."""
        seed = bytes(range(32))
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        pub = raw_pub(priv)
        nonce, fp = bytes(range(100, 132)), bytes(range(200, 232))
        m = msg(nonce, fp, pub)
        self.assertEqual(m[:2], b"\x00\x13")
        self.assertEqual(m[2:21], b"sigilnet-tcp-auth-1")
        self.assertEqual(m[21:23], b"\x00\x20")
        self.assertEqual(len(m), 2 + 19 + 2 + 32 + 2 + 32 + 2 + 32)
        ep2, sec2, _ = self.door("vec")

        # the same vector through the door: a credential made from this seed is admitted with exactly these bytes
        self.c.open_door("vec", "peer", credential={"type": "tcp", "key": hashlib.sha256(pub).hexdigest()})
        self.c.reconfigure()
        r = Raw(self.c.door_endpoint("vec"))
        _, n = r.hello()
        self.assertTrue(r.admitted(raw_pub(priv) + priv.sign(msg(n, bytes.fromhex(r.fp), pub))))

    def test_pub_hash_mismatch_small_order_and_noncanonical(self):
        # a pub whose sha256 is NOT the credential, with a valid signature under that pub
        other = ed25519.Ed25519PrivateKey.generate()
        self.assertFalse(self.attempt(lambda r, n: r.auth(other, n)))
        # small-order public key whose hash IS the credential: must be refused whatever the signature
        small = bytes([1]) + bytes(31)                                                       # the identity point
        self.c.open_door("so", "peer", credential={"type": "tcp", "key": hashlib.sha256(small).hexdigest()})
        self.c.reconfigure()
        self.echo(self.c.doors()["so"]["port"])
        epso = self.c.door_endpoint("so")
        self.assertFalse(self.attempt(lambda r, n: small + bytes(64), epso))
        self.assertFalse(self.attempt(lambda r, n: small + bytes([1]) + bytes(63), epso))
        # non-canonical S (S + L): a valid signature turned malleable
        def malleable(r, n):
            a = r.auth(self.priv_, n)
            sig = a[32:]
            s2 = (int.from_bytes(sig[32:], "little") + L).to_bytes(32, "little")
            return a[:32] + sig[:32] + s2
        self.assertFalse(self.attempt(malleable))
        # a pub that is not even a curve point, hash registered
        junk = b"\xff" * 32
        self.c.open_door("jk", "peer", credential={"type": "tcp", "key": hashlib.sha256(junk).hexdigest()})
        self.c.reconfigure()
        self.echo(self.c.doors()["jk"]["port"])
        self.assertFalse(self.attempt(lambda r, n: junk + bytes(64), self.c.door_endpoint("jk")))

    def test_failed_admission_reaches_no_backend_and_sends_no_application_byte(self):
        port = self.c.doors()["p"]["port"]
        rec = self.backend(port + 100) if False else None
        # replace the echo backend with a recorder on a fresh door
        ep, sec, p2 = self.door("rec", echo=False)
        b = self.backend(p2, b"x" * 10, hold=True)
        other = ed25519.Ed25519PrivateKey.generate()
        for bad in (lambda r, n: r.auth(other, n), lambda r, n: os.urandom(96), lambda r, n: bytes(96), lambda r, n: r.auth(self.priv(sec), os.urandom(32))):
            self.assertFalse(self.attempt(bad, ep))
        r = Raw(ep)
        r.hello()
        r.s.sendall(os.urandom(20))                                  # short auth, then request-looking junk: never reaches the backend
        self.assertEqual(drain(r.s, 1.5)[:1] != b"\x01", True)
        time.sleep(0.3)
        self.assertEqual(b.accepts, 0)
        self.assertEqual(bytes(b.received), b"")
        self.assertTrue(self.attempt(lambda r, n: r.auth(self.priv(sec), n), ep))               # control: admitted -> backend connected
        self.assertTrue(wait_for(lambda: b.accepts == 1))

    def test_nothing_is_forwarded_before_admission_and_extra_bytes_after_it_are(self):
        ep, sec, p2 = self.door("rec", echo=False)
        b = self.backend(p2, None, hold=True)
        r = Raw(ep)
        _, n = r.hello()
        r.s.sendall(os.urandom(40))                                  # request data before the auth completes = part of the 96
        time.sleep(0.5)
        self.assertEqual(b.accepts, 0)
        r.close()
        r = Raw(ep)
        _, n = r.hello()
        payload = b"PIPELINED-REQUEST"
        r.s.sendall(r.auth(self.priv(sec), n) + payload)
        self.assertEqual(r.exact(1), b"\x01")
        self.assertTrue(wait_for(lambda: bytes(b.received) == payload))

    def test_short_or_slow_auth_is_closed_within_the_deadline(self):
        self.c.stop()
        c = self.mk("dl", auth_deadline=1.0, port_base=self.base + 20)
        _, pub = c.new_credential()
        c.open_door("s", "peer", credential=pub)
        c.start()
        ep = c.door_endpoint("s")
        for nbytes in (0, 1, 95):
            r = Raw(ep, timeout=6)
            r.hello()
            if nbytes:
                r.s.sendall(os.urandom(nbytes))
            t0 = time.time()
            got = drain(r.s, 5)
            dt = time.time() - t0
            self.assertEqual(got, b"", nbytes)
            self.assertLess(dt, 2.6, f"{nbytes} bytes: not closed within the deadline ({dt:.1f}s)")

    def test_dribbled_auth_cannot_outlive_the_total_deadline(self):
        self.c.stop()
        c = self.mk("dr", auth_deadline=1.5, port_base=self.base + 20)
        _, pub = c.new_credential()
        c.open_door("s", "peer", credential=pub)
        c.start()
        r = Raw(c.door_endpoint("s"), timeout=8)
        r.hello()
        t0 = time.time()
        try:
            for _ in range(60):                                       # one byte every 0.2 s would take 12 s: a per-read timeout would never fire
                r.s.sendall(b"\x00")
                time.sleep(0.2)
        except (OSError, ssl.SSLError):
            pass
        self.assertLess(time.time() - t0, 3.5)


class Tls(Base):
    def test_tls12_only_client_refused_and_no_hello(self):
        ep, _, _ = self.door("r", "read")
        self.c.start()
        r = None
        try:
            r = Raw(ep, version=ssl.TLSVersion.TLSv1_2)
            self.fail("a TLS 1.2 handshake succeeded")
        except (ssl.SSLError, OSError):
            pass
        s = socket.create_connection(addr_parts(ep)[:2], timeout=3)
        ctx = client_ctx(ssl.TLSVersion.TLSv1_2)
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        t = ctx.wrap_socket(s, server_hostname=None)                  # offering 1.2 AND 1.3: must end up on 1.3
        self.assertEqual(t.version(), "TLSv1.3")

    def test_no_resumption_so_every_connection_is_admitted_again(self):
        ep, secret, _ = self.door("p")
        self.c.start()
        ctx = client_ctx()
        s0 = socket.create_connection(addr_parts(ep)[:2], timeout=3)
        r = Raw.__new__(Raw)
        r.s, r.t = ctx.wrap_socket(s0, server_hostname=None), 5.0
        r.hello()
        sess = r.s.session
        r.s.settimeout(1)
        try:
            r.s.recv(1)                                               # let any post-handshake ticket arrive
        except (socket.timeout, ssl.SSLError):
            pass
        sess = r.s.session
        r.close()
        s = socket.create_connection(addr_parts(ep)[:2], timeout=3)
        t = ctx.wrap_socket(s, server_hostname=None, session=sess)
        self.assertFalse(t.session_reused)
        m, n = Raw.__new__(Raw), None
        h = t.recv(39)
        self.assertEqual(h[:7], b"SNTCP1\x01")                         # still asks for admission

    def test_plaintext_and_garbage_clients_get_nothing_and_never_reach_the_backend(self):
        ep, _, port = self.door("p", echo=False)
        b = self.backend(port, b"X", hold=True)
        self.c.start()
        ip, p, _ = addr_parts(ep)
        for payload in (b"GET / HTTP/1.0\r\n\r\n", os.urandom(4096), b"\x16\x03\x01\x00\x05hello", b"SNTCP1" + bytes(100), b"\x00" * 100):
            s = socket.create_connection((ip, p), timeout=3)
            s.sendall(payload)
            got = drain(s, 2.5)
            s.close()
            self.assertNotIn(b"SNTCP1", got)
            self.assertTrue(got == b"" or got[0] == 0x15, got[:20])                  # nothing, or at most a TLS alert record
        time.sleep(0.2)
        self.assertEqual(b.accepts, 0)

    def test_one_mebibyte_of_junk_is_bounded_and_the_door_survives(self):
        ep, secret, _ = self.door("p")
        self.c.start()
        ip, p, _ = addr_parts(ep)
        s = socket.create_connection((ip, p), timeout=5)
        sent = 0
        t0 = time.time()
        try:
            while sent < (1 << 20):
                s.sendall(os.urandom(65536))
                sent += 65536
        except OSError:
            pass
        self.assertLess(time.time() - t0, 6)
        s.close()
        bob = self.mk("bob")
        bob.use_credential(ep, secret)
        self.assertEqual(bob.dial(ep, timeout=5).request({"t": "ping", "n": 3})["echo"], 3)

    def test_handshake_slow_loris_is_closed_within_the_deadline(self):
        self.c.stop()
        c = self.mk("sl", auth_deadline=1.0, port_base=self.base + 20)
        c.open_door("r", "read")
        c.start()
        ip, p, _ = addr_parts(c.door_endpoint("r"))
        s = socket.create_connection((ip, p), timeout=3)              # silent: no ClientHello at all
        t0 = time.time()
        self.assertEqual(drain(s, 5), b"")
        self.assertLess(time.time() - t0, 2.6)
        s2 = socket.create_connection((ip, p), timeout=3)             # a ClientHello prefix dribbled byte by byte
        t0 = time.time()
        try:
            for b in b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" * 3:
                s2.sendall(bytes([b]))
                time.sleep(0.25)
        except OSError:
            pass
        self.assertLess(time.time() - t0, 3.2)
        self.assertEqual(drain(s2, 0.5)[:1] in (b"", b"\x15"), True)


class Caps(Base):
    def test_max_unauth_cap_is_before_tls_and_does_not_leak(self):
        self.c.stop()
        c = self.mk("mu", max_unauth=3, auth_deadline=4.0, port_base=self.base + 20)
        sec, pub = c.new_credential()
        port = c.open_door("p", "peer", credential=pub)
        self.echo(port)
        c.start()
        ep = c.door_endpoint("p")
        ip, p, _ = addr_parts(ep)
        hold = [socket.create_connection((ip, p), timeout=3) for _ in range(3)]       # three silent sockets fill the cap
        time.sleep(0.4)
        extra = socket.create_connection((ip, p), timeout=3)
        t0 = time.time()
        self.assertEqual(drain(extra, 3), b"")
        self.assertLess(time.time() - t0, 1.5, "over the cap: accept and close at once, not after the auth deadline")
        extra.close()
        [s.close() for s in hold]
        bob = self.mk("bob")
        bob.use_credential(ep, sec)
        self.assertTrue(wait_for(lambda: self._ok(bob, ep), 6))                                   # slots come back

    def _ok(self, bob, ep):
        try:
            return bob.dial(ep, timeout=3).request({"t": "ping", "n": 1})["echo"] == 1
        except Exception:
            return False

    def test_failures_do_not_leak_unauth_slots(self):
        self.c.stop()
        c = self.mk("lk", max_unauth=3, auth_deadline=2.0, port_base=self.base + 20)
        sec, pub = c.new_credential()
        port = c.open_door("p", "peer", credential=pub)
        self.echo(port)
        c.start()
        ep = c.door_endpoint("p")
        ip, p, _ = addr_parts(ep)
        other = ed25519.Ed25519PrivateKey.generate()
        for i in range(12):
            kind = i % 4
            if kind == 0:
                s = socket.create_connection((ip, p), timeout=3)
                s.sendall(os.urandom(300))
                s.close()
            elif kind == 1:
                r = Raw(ep)
                r.hello()
                r.close()
            elif kind == 2:
                r = Raw(ep)
                _, n = r.hello()
                r.admitted(r.auth(other, n))
                r.close()
            else:
                socket.create_connection((ip, p), timeout=3).close()
        bob = self.mk("bob")
        bob.use_credential(ep, sec)
        for _ in range(8):
            self.assertTrue(wait_for(lambda: self._ok(bob, ep), 4))

    def test_max_streams_per_door_closed_before_the_admission_byte(self):
        self.c.stop()
        c = self.mk("ms", max_streams_per_door=2, port_base=self.base + 20)
        sec, pub = c.new_credential()
        port = c.open_door("p", "peer", credential=pub)
        c.open_door("r", "read")
        b = self.backend(port, None, hold=True)
        b2 = self.backend(c.doors()["r"]["port"], None, hold=True)
        c.start()
        ep, epr = c.door_endpoint("p"), c.door_endpoint("r")
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"]))
        held = []
        for _ in range(2):
            r = Raw(ep)
            _, n = r.hello()
            r.s.sendall(r.auth(priv, n))
            self.assertEqual(r.exact(1), b"\x01")
            held.append(r)
        self.assertTrue(wait_for(lambda: b.accepts == 2))
        r = Raw(ep)
        _, n = r.hello()
        self.assertFalse(r.admitted(r.auth(priv, n)))                 # third: no 0x01, closed
        self.assertEqual(b.accepts, 2)
        b.conns[0].close()                                                 # the protocol ends one exchange: its stream (and slot) is over
        self.assertTrue(wait_for(lambda: self._admit(ep, priv), 6))        # a slot is free again
        # public door: closed before piping
        pubs = [Raw(epr) for _ in range(2)]
        [x.hello() for x in pubs]
        for x in pubs:
            x.s.sendall(b"hold")
        self.assertTrue(wait_for(lambda: b2.accepts == 2))
        r3 = Raw(epr)
        r3.hello()
        r3.s.sendall(b"third")
        self.assertEqual(drain(r3.s, 2), b"")
        time.sleep(0.2)
        self.assertEqual(b2.accepts, 2)

    def _admit(self, ep, priv):
        r = Raw(ep)
        try:
            _, n = r.hello()
            r.s.sendall(r.auth(priv, n))
            return r.exact(1, 2) == b"\x01"
        except Exception:
            return False
        finally:
            r.close()

    def test_cap_counts_are_per_door(self):
        self.c.stop()
        c = self.mk("pd", max_streams_per_door=1, port_base=self.base + 20)
        c.open_door("r1", "read")
        c.open_door("r2", "read")
        b1 = self.backend(c.doors()["r1"]["port"], None, hold=True)
        b2 = self.backend(c.doors()["r2"]["port"], None, hold=True)
        c.start()
        for name, b in (("r1", b1), ("r2", b2)):
            r = Raw(c.door_endpoint(name))
            r.hello()
            r.s.sendall(b"x")
            self.assertTrue(wait_for(lambda: b.accepts == 1), name)
            self.cleanups.append(r.close)


class Pipe(Base):
    def _door(self, **kw):
        self.c.stop()
        c = self.mk("pp", port_base=self.base + 20, **kw)
        sec, pub = c.new_credential()
        port = c.open_door("p", "peer", credential=pub)
        return c, sec, port

    def _admitted(self, c, sec, port=None):
        r = Raw(c.door_endpoint("p"))
        _, n = r.hello()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"]))
        r.s.sendall(r.auth(priv, n))
        self.assertEqual(r.exact(1), b"\x01")
        return r

    def test_up_cap_boundary_exactly_pipe_up_passes_one_more_ends_the_connection(self):
        c, sec, port = self._door()
        done = threading.Event()

        def reply(conn, rec):
            tot = 0
            conn.settimeout(10)
            while True:
                d = conn.recv(65536)
                if not d:
                    break
                tot += len(d)
                rec.received += d[:0]
                rec.total = tot
                if tot == PIPE_UP:
                    conn.sendall(b"R")
            done.set()
        b = self.backend(port, reply)
        c.start()
        r = self._admitted(c, sec)
        r.s.sendall(os.urandom(PIPE_UP))
        self.assertEqual(r.exact(1, 8), b"R")                         # exactly PIPE_UP bytes got through and the stream is still open
        r.s.sendall(b"+")
        got = drain(r.s, 4)
        self.assertEqual(got, b"")                                    # the byte beyond the cap ends the connection
        self.assertTrue(done.wait(5))
        self.assertEqual(b.total, PIPE_UP)                            # and was never forwarded

    def test_up_cap_one_big_send_forwards_exactly_the_allowed_prefix(self):
        c, sec, port = self.door_kw = self._door()
        seen = []

        def reply(conn, rec):
            tot = 0
            conn.settimeout(10)
            while True:
                try:
                    d = conn.recv(65536)
                except OSError:
                    break
                if not d:
                    break
                tot += len(d)
            seen.append(tot)
        self.backend(port, reply)
        c.start()
        r = self._admitted(c, sec)
        try:
            r.s.sendall(os.urandom(PIPE_UP + 5000))
        except OSError:
            pass
        self.assertTrue(wait_for(lambda: seen == [PIPE_UP], 8), seen)

    def test_down_cap(self):
        c, sec, port = self._door()
        self.backend(port, lambda conn, rec: (conn.recv(2), conn.sendall(os.urandom(PIPE_DOWN + 4000))))
        c.start()
        r = self._admitted(c, sec)
        r.s.sendall(b"go")
        got = drain(r.s, 15)
        self.assertEqual(len(got), PIPE_DOWN)

    def test_backend_closing_after_its_reply_ends_the_stream_with_the_full_reply(self):
        c, sec, port = self._door()
        self.backend(port, lambda conn, rec: (conn.recv(1), conn.sendall(b"R" * 5000), conn.close()))
        c.start()
        r = self._admitted(c, sec)
        r.s.sendall(b"q")
        self.assertEqual(len(drain(r.s, 5)), 5000)

    def test_stalled_backend_frees_its_slot_at_pipe_idle(self):
        c, sec, port = self._door(pipe_idle=1.0, max_streams_per_door=1)
        self.backend(port, lambda conn, rec: time.sleep(30))
        c.start()
        r = self._admitted(c, sec)
        r.s.sendall(b"hello")
        t0 = time.time()
        self.assertEqual(drain(r.s, 6), b"")
        self.assertLess(time.time() - t0, 3.5)
        self.assertTrue(wait_for(lambda: self._try(c, sec), 4))

    def _try(self, c, sec):
        try:
            r = self._admitted(c, sec)
            r.close()
            return True
        except Exception:
            return False

    def test_pipe_total_ends_a_trickle_that_keeps_the_idle_timer_alive(self):
        c, sec, port = self._door(pipe_idle=2.0, pipe_total=2.5)

        def reply(conn, rec):
            try:
                for _ in range(40):
                    conn.sendall(b".")
                    time.sleep(0.3)
            except OSError:
                pass
        self.backend(port, reply)
        c.start()
        r = self._admitted(c, sec)
        t0 = time.time()
        got = drain(r.s, 10)
        self.assertLess(time.time() - t0, 4.5)
        self.assertGreater(len(got), 2)

    def test_unreachable_backend_looks_like_eof_to_the_client(self):
        c, sec, port = self._door()
        c.start()                                                      # nothing listens on the loopback port
        bob = self.mk("bob")
        bob.use_credential(c.door_endpoint("p"), sec)
        with self.assertRaises((ConnectionError, CarrierError)):
            bob.dial(c.door_endpoint("p"), timeout=4).request({"t": "ping", "n": 1})
