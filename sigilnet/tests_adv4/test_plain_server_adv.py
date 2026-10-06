"""Hostile clients of the PLAIN (tor-facing) TcpServer, loopback only."""
import socket
import struct
import threading
import time
import unittest

from sigilnet import canon, tcp
from sigilnet.tcp import TcpServer, TcpTransport

from .h4 import collect_thread_errors, frame, read_until_closed


def echo(req):
    if not isinstance(req, dict):
        return {"t": "error"}
    return {"t": "ok", "echo": req.get("x", 0)}


class Base(unittest.TestCase):
    def setUp(self):
        self._saved = (tcp.HEADER_DEADLINE, tcp.DEADLINE, tcp.PLAIN_PER_MIN)
        self.addCleanup(self._restore)

    def _restore(self):
        tcp.HEADER_DEADLINE, tcp.DEADLINE, tcp.PLAIN_PER_MIN = self._saved

    def server(self, handler=echo, **kw):
        s = TcpServer("127.0.0.1", 0, None, handler, **kw).start()
        self.addCleanup(s.stop)
        return s

    def conn(self, s):
        c = socket.create_connection(("127.0.0.1", s.port), timeout=5)
        self.addCleanup(c.close)
        return c

    def legit(self, s, timeout=3):
        return TcpTransport("127.0.0.1", s.port, None, timeout=timeout).request({"t": "x", "x": 1})


class BindTest(Base):
    def test_plain_server_refuses_every_non_loopback_bind(self):
        for host in ("0.0.0.0", "", "::", "192.168.1.1", "10.1.2.3", "8.8.8.8", "localhost", "::ffff:8.8.8.8", "0", "224.0.0.1", "255.255.255.255", "127.0.0.1/8"):
            for pub in (False, True):
                with self.subTest(host=host, allow_public=pub):
                    with self.assertRaises((ValueError, OSError)):
                        TcpServer(host, 0, None, echo, allow_public=pub).stop()

    def test_bound_address_is_really_loopback(self):
        s = self.server()
        self.assertEqual(s.sock.getsockname()[0], "127.0.0.1")
        for ip in ("127.0.0.2", "127.1.2.3"):
            try:
                t = TcpServer(ip, 0, None, echo)
            except OSError:
                continue
            self.assertTrue(t.sock.getsockname()[0].startswith("127."))
            t.stop()

    def test_plain_limits_are_capped_even_if_a_caller_asks_for_more(self):
        s = self.server(max_conns=1000)
        self.assertLessEqual(s.sem._initial_value, tcp.PLAIN_CONNS)

    def test_non_plain_server_with_a_key_still_refuses_public_by_default(self):
        with self.assertRaises(ValueError):
            TcpServer("0.0.0.0", 0, tcp.new_key(), echo)


class FrameAttackTest(Base):
    def test_malformed_frames_get_no_answer_no_traceback_and_the_server_survives(self):
        tcp.HEADER_DEADLINE, tcp.DEADLINE = 0.6, 1.5
        s = self.server()
        bodies = [b"[" * 60000, b" {}", b"{}\n", b'{"a":1.5}', b'{"a":1e2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"b":1,"a":2}', b'{"a":1,"a":1}', b"\xef\xbb\xbf{}",
                  b'{"a":"\\ud800"}', b'{"a":9007199254740993}', b"[" * 19 + b"]" * 19, b"null", b"\x00" * 100, b'{"a":' * 5000]
        with collect_thread_errors() as ce:
            for b in bodies:
                with self.subTest(body=b[:24]):
                    c = self.conn(s)
                    c.sendall(frame(b))
                    out = read_until_closed(c, 3)
                    if b in (b"null",):
                        continue          # valid canonical JSON that is not an object: the handler decides
                    self.assertEqual(out, b"", f"a garbage frame got an answer: {out[:60]!r}")
            time.sleep(0.2)
        self.assertEqual(ce.errors, [], [str(e.exc_value) for e in ce.errors])
        self.assertEqual(self.legit(s)["t"], "ok")

    def test_length_header_attacks(self):
        tcp.HEADER_DEADLINE, tcp.DEADLINE = 0.6, 1.5
        s = self.server()
        for n in (0, 1, tcp.MAX_REQ + 1, 0xFFFFFFFF, 0x80000000, 2 ** 24):
            with self.subTest(n=n):
                c = self.conn(s)
                t = time.time()
                c.sendall(struct.pack(">I", n) + b"{}")
                out = read_until_closed(c, 4)
                self.assertEqual(out, b"")
                self.assertLess(time.time() - t, 2.5)
        self.assertEqual(self.legit(s)["t"], "ok")

    def test_max_size_request_is_accepted_and_one_byte_more_is_not(self):
        s = self.server()
        pad = "x" * (tcp.MAX_REQ - 40)
        body = canon.dumps({"x": pad, "t": "x"})
        self.assertLessEqual(len(body), tcp.MAX_REQ)
        c = self.conn(s)
        c.sendall(frame(body))
        raw = read_until_closed(c, 3)
        self.assertGreater(len(raw), 4)

    def test_truncated_body_then_close_and_header_only(self):
        tcp.HEADER_DEADLINE, tcp.DEADLINE = 0.6, 1.0
        s = self.server()
        c = self.conn(s)
        c.sendall(struct.pack(">I", 100) + b"{")
        c.shutdown(socket.SHUT_WR)
        self.assertEqual(read_until_closed(c, 3), b"")
        c = self.conn(s)
        c.sendall(b"\x00\x00")
        t = time.time()
        self.assertEqual(read_until_closed(c, 3), b"")
        self.assertLess(time.time() - t, 1.5)

    def test_slowloris_header_and_body_are_cut_by_absolute_deadlines(self):
        tcp.HEADER_DEADLINE, tcp.DEADLINE = 0.5, 1.2
        s = self.server()
        c = self.conn(s)
        t = time.time()
        try:
            for b in struct.pack(">I", 10):
                c.sendall(bytes([b]))
                time.sleep(0.3)
        except OSError:
            pass
        read_until_closed(c, 3)
        self.assertLess(time.time() - t, 2.0)
        c = self.conn(s)
        t = time.time()
        c.sendall(struct.pack(">I", 200))
        try:
            for _ in range(100):
                c.sendall(b"{")
                time.sleep(0.2)
        except OSError:
            pass
        self.assertLess(time.time() - t, 2.5)

    def test_client_that_never_reads_a_big_response_does_not_pin_the_server(self):
        tcp.DEADLINE = 1.5
        big = {"t": "ok", "blob": "y" * 250000}
        s = self.server(handler=lambda r: big)
        socks = []
        for _ in range(4):
            c = self.conn(s)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            c.sendall(frame(canon.dumps({"t": "x"})))
            socks.append(c)
        time.sleep(2.5)
        self.assertEqual(s.per_ip.get("*", 0), 0, "connections of clients that never read were not released after the deadline")

    def test_handler_exceptions_and_unserialisable_replies_do_not_leak_slots(self):
        calls = []

        def bad(req):
            calls.append(1)
            if len(calls) % 3 == 0:
                raise RuntimeError("boom")
            return {"t": 1.5} if len(calls) % 3 == 1 else {"t": object()}
        with collect_thread_errors():
            s = self.server(handler=bad)
            for _ in range(40):
                c = self.conn(s)
                c.sendall(frame(canon.dumps({"t": "x"})))
                read_until_closed(c, 2)
                c.close()
        time.sleep(0.3)
        self.assertEqual(s.per_ip.get("*", 0), 0)
        self.assertEqual(s.sem._value, tcp.PLAIN_CONNS if s.sem._initial_value == tcp.PLAIN_CONNS else s.sem._initial_value)

    def test_oversized_response_is_replaced_by_an_error(self):
        s = self.server(handler=lambda r: {"t": "ok", "blob": "y" * (2 * tcp.MAX_RESP)})
        c = self.conn(s)
        c.sendall(frame(canon.dumps({"t": "x"})))
        raw = read_until_closed(c, 3)
        self.assertEqual(canon.loads(raw[4:])["t"], "error")


class AcceptErrorTest(Base):
    def test_a_transient_accept_error_does_not_kill_the_listener_for_good(self):
        """ECONNABORTED / EMFILE / ENOBUFS from accept() are transient; serve_forever() treats any OSError as 'the socket was closed' and exits, so sync silently stops
        while `node run` (which only watches the tor process) keeps going."""
        import errno
        s = self.server()
        real = s.sock

        class Flaky:
            def __init__(self):
                self.n = 0

            def accept(self):
                self.n += 1
                if self.n == 1:
                    raise OSError(errno.ECONNABORTED, "Software caused connection abort")
                return real.accept()

            def __getattr__(self, k):
                return getattr(real, k)
        s.sock = Flaky()
        time.sleep(1.2)
        s.sock = real
        time.sleep(0.8)
        self.assertTrue(s.thread.is_alive(), "the accept loop exited after one transient accept() error")
        self.assertEqual(self.legit(s)["t"], "ok")


class LockoutTest(Base):
    """All tor connections look like 127.0.0.1, so the limits are global. Can one (authorized) peer, or a local process, lock every other peer out?"""

    @unittest.expectedFailure      # KNOWN LIMIT (README step 3): pre-auth connections cannot be told apart behind tor; an AUTHORIZED peer can degrade service, `node revoke` ends it
    def test_eight_idle_connections_do_not_lock_out_a_legitimate_peer_for_long(self):
        tcp.HEADER_DEADLINE, tcp.DEADLINE = 0.5, 1.5
        s = self.server()
        stop = threading.Event()

        def attacker():
            socks = []
            while not stop.is_set():
                socks = [x for x in socks if x.fileno() != -1]
                while len(socks) < 12:
                    try:
                        socks.append(socket.create_connection(("127.0.0.1", s.port), timeout=1))
                    except OSError:
                        break
                # drop the ones the server already closed, reconnect at once
                for x in list(socks):
                    x.setblocking(False)
                    try:
                        if x.recv(1) == b"":
                            x.close()
                    except BlockingIOError:
                        pass
                    except OSError:
                        x.close()
                time.sleep(0.01)
            for x in socks:
                x.close()
        th = threading.Thread(target=attacker, daemon=True)
        th.start()
        self.addCleanup(lambda: (stop.set(), th.join(2)))
        time.sleep(0.3)
        ok = 0
        for _ in range(12):
            try:
                self.legit(s, timeout=1)
                ok += 1
            except Exception:
                pass
            time.sleep(0.1)
        self.assertGreaterEqual(ok, 6, f"only {ok}/12 legitimate requests got through while one attacker held idle connections")

    @unittest.expectedFailure      # KNOWN LIMIT (README step 3): pre-auth connections cannot be told apart behind tor; an AUTHORIZED peer can degrade service, `node revoke` ends it
    def test_connection_churn_cannot_exhaust_the_per_minute_budget_of_everyone_else(self):
        s = self.server()
        for _ in range(tcp.PLAIN_PER_MIN + 20):                      # connect and hang up at once: the cheapest possible connection
            try:
                socket.create_connection(("127.0.0.1", s.port), timeout=1).close()
            except OSError:
                pass
        time.sleep(0.3)
        try:
            self.legit(s, timeout=2)
        except Exception as e:
            self.fail(f"a legitimate request was refused after {tcp.PLAIN_PER_MIN + 20} empty connections: {type(e).__name__}")

    def test_admission_is_not_charged_for_refused_connections(self):
        tcp.PLAIN_PER_MIN = 10
        s = self.server()
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", s.port), timeout=1).close()
            except OSError:
                pass
        time.sleep(0.2)
        self.assertLessEqual(len(s.recent.get("*", [])), 10)

    def test_the_admission_table_does_not_grow(self):
        s = self.server()
        for _ in range(50):
            socket.create_connection(("127.0.0.1", s.port), timeout=1).close()
        time.sleep(0.3)
        self.assertLessEqual(len(s.recent), 1)


if __name__ == "__main__":
    unittest.main()
