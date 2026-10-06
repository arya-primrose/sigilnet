"""Framing, connection exhaustion, key/TTL edge cases, size limits and binding rules of tcp.py."""
import socket
import struct
import tempfile
import time
import unittest

from cryptography.fernet import Fernet

from sigilnet import canon
from sigilnet import sync as S
from sigilnet import tcp
from sigilnet.mirror import Mirror

from sigilnet.tests.util import World
from sigilnet.thread import default_rules

from .h3 import all_events, big_world, mirror_with, vis

HUGE = {**default_rules(), "posts_per_author_per_hour": 10000, "max_event_bytes": 65536}


def recv_all(s, limit=5.0):
    s.settimeout(limit)
    out = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                return out
            out += c
    except socket.timeout:
        return out
    except ConnectionResetError:
        return out


class Base(unittest.TestCase):
    def setUp(self):
        self.old_deadline, tcp.DEADLINE = tcp.DEADLINE, 1.0
        self.addCleanup(lambda: setattr(tcp, "DEADLINE", self.old_deadline))
        self.w = big_world()
        for n in range(5):
            self.w.add(self.w.w("carol").post(str(n)))
        self.a = mirror_with(self.w.genesis, all_events(self.w))
        self.key = tcp.new_key()
        self.f = Fernet(self.key.encode())
        self.srv = tcp.TcpServer("127.0.0.1", 0, self.key, S.SyncServer(self.a).handle, max_conns=3).start()
        self.addCleanup(self.srv.stop)
        self.me = self.w.ids["sansa"]

    def conn(self):
        return socket.create_connection(("127.0.0.1", self.srv.port))

    def signed_frame(self, body=None, at=None):
        req = S.sign_request(self.me, body or {"t": "summary", "thread": self.w.t.id, "page": 0})
        tok = self.f.encrypt(canon.dumps(req)) if at is None else self.f.encrypt_at_time(canon.dumps(req), at)
        return struct.pack(">I", len(tok)) + tok

    def decode_reply(self, raw):
        (n,) = struct.unpack(">I", raw[:4])
        return canon.loads(self.f.decrypt(raw[4:4 + n]))


class Framing(Base):
    def test_zero_length_frame_closes_at_once(self):
        with self.conn() as s:
            s.sendall(b"\0\0\0\0")
            t0 = time.time()
            self.assertEqual(recv_all(s), b"")
            self.assertLess(time.time() - t0, 0.5)

    def test_short_header_and_partial_body_time_out_and_free_the_slot(self):
        for payload in (b"\0\0", b"\0\0\0\x64" + b"x" * 10):
            with self.conn() as s:
                s.sendall(payload)
                t0 = time.time()
                self.assertEqual(recv_all(s), b"")
                self.assertLess(time.time() - t0, tcp.DEADLINE + 1.0)
        self.assertEqual(S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), self.w.t.id, tcp.TcpTransport("127.0.0.1", self.srv.port, self.key), self.me)["ok"], True)

    def test_off_by_one_lengths(self):
        for n in (tcp.MAX_REQ + 1, 2 ** 32 - 1, 2 ** 31):
            with self.conn() as s:
                s.sendall(struct.pack(">I", n))
                t0 = time.time()
                self.assertEqual(recv_all(s), b"")
                self.assertLess(time.time() - t0, 0.5, n)

    def test_trailing_bytes_and_second_frame_never_produce_a_second_answer_or_break_the_server(self):
        with self.conn() as s:
            s.sendall(self.signed_frame() + b"GARBAGE" * 100 + self.signed_frame())
            raw = recv_all(s)                      # may be empty if the close of a socket with unread data resets the connection
        if len(raw) >= 4:
            n = struct.unpack(">I", raw[:4])[0]
            self.assertLessEqual(len(raw), 4 + n, "more than one response frame")
        with self.conn() as s:
            s.sendall(self.signed_frame())
            self.assertEqual(self.decode_reply(recv_all(s))["t"], "summary")

    def test_one_byte_at_a_time_valid_frame_within_deadline_is_served_and_beyond_is_not(self):
        frame = self.signed_frame()
        with self.conn() as s:
            for b in frame[:30]:
                s.sendall(bytes([b]))
            s.sendall(frame[30:])
            self.assertEqual(self.decode_reply(recv_all(s))["t"], "summary")
        with self.conn() as s:
            s.sendall(frame[:10])
            time.sleep(tcp.DEADLINE + 0.5)
            try:
                s.sendall(frame[10:])
            except OSError:
                pass
            self.assertEqual(recv_all(s), b"")

    def test_garbage_that_is_not_canonical_json_inside_a_valid_token_gets_no_answer(self):
        for body in (b'{"b":1,"a":2}', b'{"a":NaN}', b'{"a":1,"a":2}', b"[" * 100000, b"\xff\xfe", b"x" * 100000):
            tok = self.f.encrypt(body)
            with self.conn() as s:
                s.sendall(struct.pack(">I", len(tok)) + tok)
                self.assertEqual(recv_all(s), b"", body[:20])

    def test_valid_token_with_non_dict_json_does_not_kill_the_server(self):
        for body in (b"5", b"[]", b'"x"', b"null", b"true"):
            tok = self.f.encrypt(body)
            with self.conn() as s:
                s.sendall(struct.pack(">I", len(tok)) + tok)
                r = recv_all(s)
                if r:
                    self.assertEqual(self.decode_reply(r)["t"], "error")
        with self.conn() as s:
            s.sendall(self.signed_frame())
            self.assertEqual(self.decode_reply(recv_all(s))["t"], "summary")

    def test_client_disconnecting_before_the_response_does_not_leak_slots(self):
        for _ in range(20):
            s = self.conn()
            s.sendall(self.signed_frame())
            s.close()
        time.sleep(0.3)
        for _ in range(3):
            with self.conn() as s:
                s.sendall(self.signed_frame())
                self.assertTrue(recv_all(s))


class Exhaustion(Base):
    def test_idle_connections_do_not_lock_out_a_legitimate_peer_for_long(self):
        idle = [self.conn() for _ in range(3)]                   # max_conns=3
        try:
            tr = tcp.TcpTransport("127.0.0.1", self.srv.port, self.key, timeout=3)
            t0 = time.time()
            r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), self.w.t.id, tr, self.me)
            waited = time.time() - t0
        finally:
            [s.close() for s in idle]
        # documents the accepted trade-off: while 3 idle sockets sit there the peer is refused (not queued); after DEADLINE they are dropped
        self.assertFalse(r["ok"])
        time.sleep(tcp.DEADLINE + 0.5)
        self.assertTrue(S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), self.w.t.id, tr, self.me)["ok"])

    def test_the_server_never_runs_more_than_max_conns_handlers(self):
        import threading
        peak = [0]
        live = [0]
        lock = threading.Lock()
        base = S.SyncServer(self.a).handle

        def h(req):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
            time.sleep(0.2)
            with lock:
                live[0] -= 1
            return base(req)
        srv = tcp.TcpServer("127.0.0.1", 0, self.key, h, max_conns=3).start()
        self.addCleanup(srv.stop)
        socks = []
        for _ in range(12):
            s = socket.create_connection(("127.0.0.1", srv.port))
            s.sendall(self.signed_frame())
            socks.append(s)
        time.sleep(1)
        [s.close() for s in socks]
        self.assertLessEqual(peak[0], 3)

    def test_stop_releases_the_port_and_serve_thread(self):
        port = self.srv.port
        self.srv.stop()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)


class Binding(unittest.TestCase):
    def test_unspecified_address_counts_as_public_because_it_listens_on_every_interface(self):
        # BUG: ipaddress.is_private is True for 0.0.0.0, so "private addresses only" is bypassed by the most common all-interfaces bind
        try:
            s = tcp.TcpServer("0.0.0.0", 0, tcp.new_key(), lambda r: r)
        except ValueError:
            return
        s.stop()
        self.fail("0.0.0.0 accepted without allow_public")

    def test_public_and_odd_addresses(self):
        for host in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            with self.assertRaises(ValueError):
                tcp.TcpServer(host, 0, tcp.new_key(), lambda r: r)
        for host in ("localhost", "", "not-an-ip", "127.0.0.1/8"):
            with self.assertRaises(ValueError):                    # unfriendly but safe: hostnames are refused
                tcp.TcpServer(host, 0, tcp.new_key(), lambda r: r)

    def test_bad_key_is_rejected_at_construction_without_echoing_it(self):
        with self.assertRaises(Exception) as cm:
            tcp.TcpServer("127.0.0.1", 0, "SECRETSECRET-not-a-key", lambda r: r)
        self.assertNotIn("SECRETSECRET", str(cm.exception))


class FernetAndSizes(Base):
    def test_ttl_edges(self):
        now = int(time.time())
        for delta, served in ((0, True), (-50, True), (-70, True), (30, True), (90, True), (-600, True), (-700, False), (700, False), (-3600, False), (3600, False)):   # window = tcp.TTL (660 s) either way
            with self.conn() as s:
                s.sendall(self.signed_frame(at=now + delta))
                self.assertEqual(bool(recv_all(s)), served, delta)

    def test_a_peer_whose_clock_is_within_the_request_skew_still_works(self):
        # BUG (low, spec ambiguity): sync SKEW is 600 s but the Fernet ttl is 60 s (and future timestamps beyond 60 s are refused), so a peer 2 minutes
        # off is silently dropped with only "transport: ConnectionError" to go on.
        tr = tcp.TcpTransport("127.0.0.1", self.srv.port, self.key, timeout=3)
        real = tr.f.encrypt
        tr.f.encrypt = lambda d: tr.f.encrypt_at_time(d, int(time.time()) + 120)
        r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), self.w.t.id, tr, self.me)
        self.assertTrue(r["ok"], r)

    def test_wrong_key_client_and_server_fail_cleanly_and_quickly(self):
        tr = tcp.TcpTransport("127.0.0.1", self.srv.port, tcp.new_key(), timeout=3)
        t0 = time.time()
        r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), self.w.t.id, tr, self.me)
        self.assertFalse(r["ok"])
        self.assertLess(time.time() - t0, 2.5)
        self.assertNotIn(self.key, r["why"])

    def test_events_at_the_rule_maximum_size_survive_the_transport(self):
        w = World(rules=HUGE)
        for k in range(6):
            w.add(w.w("carol").post("x" * 60000 + str(k), parents=[w.t.id]))
        a = mirror_with(w.genesis, all_events(w))
        self.assertEqual(len(a.thread(w.t.id).resolved_ids()), 7)
        srv = tcp.TcpServer("127.0.0.1", 0, self.key, S.SyncServer(a).handle).start()
        self.addCleanup(srv.stop)
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, w.t.id, tcp.TcpTransport("127.0.0.1", srv.port, self.key, timeout=5), w.ids["sansa"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(vis(a, w.t.id), vis(b, w.t.id))

    def test_largest_legal_get_response_fits_canon_max_bytes(self):
        w = World(rules=HUGE)
        ids = []
        for k in range(64):
            e = w.w("carol").post("y" * 60000 + str(k), parents=[w.t.id])
            ids.append(w.add(e))
        a = mirror_with(w.genesis, all_events(w))
        r = S.SyncServer(a).handle(S.sign_request(w.ids["sansa"], {"t": "get", "thread": w.t.id, "ids": ids}))
        self.assertLess(len(canon.dumps(r)), canon.MAX_BYTES)
        self.assertGreater(len(r["more"]), 0)

    def test_oversized_response_becomes_a_short_error_the_client_handles(self):
        big = tcp.TcpServer("127.0.0.1", 0, self.key, lambda r: {"t": "events", "events": ["x" * 1000] * 2000, "more": []}).start()
        self.addCleanup(big.stop)
        tr = tcp.TcpTransport("127.0.0.1", big.port, self.key, timeout=5)
        try:
            resp = tr.request({"t": "x"})
            self.assertEqual(resp["t"], "error")
        except ConnectionError:
            pass

    def test_response_between_canon_limit_and_tcp_limit_is_unparseable_by_the_client(self):
        # a handler may legitimately answer up to MAX_RESP (1 MiB) but canon.loads refuses > 256 KiB, so those answers fail as "could not be decrypted"
        big = tcp.TcpServer("127.0.0.1", 0, self.key, lambda r: {"t": "events", "events": ["x" * 1000] * 400, "more": []}).start()
        self.addCleanup(big.stop)
        tr = tcp.TcpTransport("127.0.0.1", big.port, self.key, timeout=5)
        with self.assertRaises(ConnectionError) as cm:
            tr.request({"t": "x"})
        self.assertIn("decrypt", str(cm.exception))          # misleading message: nothing was wrong with decryption

    def test_replayed_old_response_is_accepted_by_the_client(self):
        # BUG (low): responses are not bound to the request (no nonce echo), so anyone who can replay a captured frame within the 60 s ttl makes
        # the client believe a stale summary and treat "no events" as the answer to its get: pull reports ok=True with nothing fetched.
        w = self.w
        with self.conn() as s:
            s.sendall(self.signed_frame())
            stale = recv_all(s)
        self.assertTrue(stale)
        mitm = socket.socket()
        mitm.bind(("127.0.0.1", 0))
        mitm.listen(8)
        mitm.settimeout(0.3)
        import threading
        stop = threading.Event()

        def run():
            while not stop.is_set():
                try:
                    c, _ = mitm.accept()
                except OSError:
                    continue
                try:
                    _read = c.recv(65536)
                    c.sendall(stale)
                finally:
                    c.close()
        th = threading.Thread(target=run, daemon=True)
        th.start()
        self.addCleanup(lambda: (stop.set(), mitm.close()))
        fresh = mirror_with(w.genesis, [])
        r = S.pull(fresh, w.t.id, tcp.TcpTransport("127.0.0.1", mitm.getsockname()[1], self.key, timeout=3), self.me)
        self.assertFalse(r["ok"] and vis(fresh, w.t.id) != vis(self.a, w.t.id), f"stale replay accepted as a successful pull: {dict(r)}")


if __name__ == "__main__":
    unittest.main()
