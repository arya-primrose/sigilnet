"""Hostile SOCKS proxy and hostile peer behind the onion. Only loopback sockets."""
import socket
import struct
import threading
import time
import unittest

from sigilnet import sync as S
from sigilnet.keys import Identity
from sigilnet.tcp import TcpServer, TcpTransport
from sigilnet import tcp
from sigilnet.torlink import TorError, TorTransport, socks5_connect, check_onion

from .h4 import ONION, OK_REPLY, FakeSocks, frame, read_until_closed

BAD_NAMES = ["", "localhost", "127.0.0.1", "example.com", "1.2.3.4", "a" * 16 + ".onion", "a" * 55 + ".onion", "a" * 57 + ".onion",
             "a" * 56 + ".onion.com", "a" * 56 + ".onion\x00", "a" * 56 + ".onion\r\nX", "a" * 56, "a" * 56 + ".ONION2", "0" * 56 + ".onion",
             "1" * 56 + ".onion", "8" * 56 + ".onion", "a" * 56 + ".onion:80", "http://" + "a" * 56 + ".onion", "é" * 56 + ".onion", "a" * 56 + "․onion"]


class SocksNamesTest(unittest.TestCase):
    def test_nothing_but_a_v3_onion_name_ever_reaches_the_proxy(self):
        px = FakeSocks(lambda c, g, r: None)
        self.addCleanup(px.close)
        for name in BAD_NAMES:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    socks5_connect(px.socks, name, 80, timeout=1)
                with self.assertRaises(ValueError):
                    TorTransport(name, 80, px.socks)
        time.sleep(0.2)
        self.assertEqual(px.conns, 0, "a rejected name must not even open a connection to the proxy")

    def test_bad_ports_never_reach_the_proxy(self):
        px = FakeSocks(lambda c, g, r: None)
        self.addCleanup(px.close)
        for port in (0, -1, 65536, 10 ** 9, "x", "", None, 1e99):
            with self.subTest(port=port):
                with self.assertRaises((ValueError, TypeError, OverflowError)):
                    socks5_connect(px.socks, ONION, port, timeout=1)
        time.sleep(0.2)
        self.assertEqual(px.conns, 0)

    def test_exact_bytes_sent_to_proxy_are_method_negotiation_then_an_atyp3_onion(self):
        px = FakeSocks(lambda c, g, r: c.sendall(OK_REPLY))
        self.addCleanup(px.close)
        s = socks5_connect(px.socks, "  " + ONION.upper() + "\n", 47200, timeout=2)
        s.close()
        self.assertEqual(px.seen[0], b"\x05\x01\x00")
        self.assertEqual(px.seen[1], b"\x05\x01\x00\x03\x3e" + ONION.encode() + struct.pack(">H", 47200))
        self.assertTrue(px.seen[1][5:-2].isascii())

    def test_unicode_case_folding_cannot_smuggle_non_ascii(self):
        # 'K' (KELVIN SIGN) lower-cases to ASCII 'k': whatever is accepted must come out as pure ASCII
        name = "K" + "a" * 55 + ".onion"
        try:
            out = check_onion(name)
        except ValueError:
            return
        self.assertTrue(out.isascii())


class HostileProxyTest(unittest.TestCase):
    def dial(self, script, timeout=1.5, read_request=True):
        px = FakeSocks(script, read_request=read_request)
        self.addCleanup(px.close)
        t = time.time()
        with self.assertRaises(TorError) as cm:
            socks5_connect(px.socks, ONION, 47200, timeout=timeout)
        return cm.exception, time.time() - t

    def test_truncated_replies_fail_fast(self):
        for n in range(0, 10):
            with self.subTest(n=n):
                e, dt = self.dial(lambda c, g, r, n=n: c.sendall(OK_REPLY[:n]))
                self.assertLess(dt, 3)

    def test_wrong_version_and_method_refusal(self):
        e, _ = self.dial(lambda c, g, r: c.sendall(b"\x04\x5a\x00\x00\x00\x00\x00\x00"))
        self.assertFalse(e.retry)
        px = FakeSocks(lambda c, g, r: None, read_request=False)
        self.addCleanup(px.close)
        px.script = lambda c, g, r: None
        # method refusal: 05 FF
        px2 = FakeSocks(lambda c, g, r: None, read_request=False)
        self.addCleanup(px2.close)

        def refuse(c, g, r):
            c.sendall(b"\x05\xff")
        px2.script = refuse
        with self.assertRaises(TorError) as cm:
            socks5_connect(px2.socks, ONION, 47200, timeout=1.5)
        self.assertFalse(cm.exception.retry)

    def test_odd_address_types(self):
        for atyp in (0, 2, 5, 0x80, 0xFF):
            with self.subTest(atyp=atyp):
                e, _ = self.dial(lambda c, g, r, a=atyp: c.sendall(b"\x05\x00\x00" + bytes([a]) + b"\x00" * 40))
                self.assertFalse(e.retry)

    def test_domain_atyp_with_length_that_never_arrives(self):
        e, dt = self.dial(lambda c, g, r: (c.sendall(b"\x05\x00\x00\x03\xff" + b"x" * 10), time.sleep(3)))
        self.assertLess(dt, 3)

    def test_slowloris_reply_is_bounded_by_the_overall_timeout(self):
        def drip(c, g, r):
            for b in OK_REPLY:
                c.sendall(bytes([b]))
                time.sleep(0.4)
        e, dt = self.dial(drip, timeout=1.0)
        self.assertLess(dt, 2.5)

    def test_silent_proxy_after_greeting(self):
        e, dt = self.dial(lambda c, g, r: time.sleep(4), timeout=1.0)
        self.assertLess(dt, 2.5)

    def test_proxy_never_answers_the_greeting(self):
        e, dt = self.dial(lambda c, g, r: time.sleep(4), timeout=1.0, read_request=False)
        self.assertLess(dt, 2.5)

    def test_endless_garbage_after_a_good_reply_is_cut_off(self):
        def flood(c, g, r):
            c.sendall(OK_REPLY)
            try:
                while True:
                    c.sendall(b"\xff" * 65536)
            except OSError:
                pass
        px = FakeSocks(flood)
        self.addCleanup(px.close)
        tr = TorTransport(ONION, 47200, px.socks, timeout=2.0)
        t = time.time()
        with self.assertRaises(ConnectionError):
            tr.request({"t": "x"})
        self.assertLess(time.time() - t, 4)

    def test_reply_then_absurd_length_header(self):
        for n in (0, 0xFFFFFFFF, tcp.MAX_RESP + 4097):
            with self.subTest(n=n):
                px = FakeSocks(lambda c, g, r, n=n: (c.sendall(OK_REPLY + struct.pack(">I", n)), time.sleep(0.5)))
                self.addCleanup(px.close)
                t = time.time()
                with self.assertRaises(ConnectionError):
                    TorTransport(ONION, 47200, px.socks, timeout=2).request({"t": "x"})
                self.assertLess(time.time() - t, 2.5)

    def test_reply_and_response_in_one_segment_still_parse(self):
        # exact-read discipline: a proxy that coalesces its reply and the peer's first bytes must not lose or double-count anything
        from sigilnet import canon
        px = FakeSocks(lambda c, g, r: c.sendall(OK_REPLY + frame(canon.dumps({"t": "ok", "r": 1}))))
        self.addCleanup(px.close)
        self.assertEqual(TorTransport(ONION, 47200, px.socks, timeout=2).request({"t": "x"}), {"t": "ok", "r": 1})

    def test_proxy_that_closes_right_after_success_is_a_connection_error(self):
        px = FakeSocks(lambda c, g, r: c.sendall(OK_REPLY))
        self.addCleanup(px.close)
        with self.assertRaises(ConnectionError):
            TorTransport(ONION, 47200, px.socks, timeout=2).request({"t": "x"})

    def test_exchange_honours_the_timeout_it_was_given(self):
        """A transport timeout of T should bound the whole request() (connect + exchange) to about T, not 2T."""
        def slow(c, g, r):
            time.sleep(0.9)
            c.sendall(OK_REPLY)
            time.sleep(3)
        px = FakeSocks(slow)
        self.addCleanup(px.close)
        t = time.time()
        with self.assertRaises(Exception):
            TorTransport(ONION, 47200, px.socks, timeout=1.0).request({"t": "x"})
        self.assertLess(time.time() - t, 1.6, "request() took about twice its timeout (connect phase and exchange phase each get the full budget)")


class HostilePeerTest(unittest.TestCase):
    """A peer behind a perfectly good proxy that lies on the wire (scripted plain server, reached by TcpTransport(key=None))."""

    def serve(self, script):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.2)
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                def one(c=c):
                    try:
                        c.settimeout(3)
                        n = struct.unpack(">I", c.recv(4))[0]
                        data = b""
                        while len(data) < n:
                            ch = c.recv(n - len(data))
                            if not ch:
                                break
                            data += ch
                        script(c, data)
                    except OSError:
                        pass
                    finally:
                        c.close()
                threading.Thread(target=one, daemon=True).start()
        threading.Thread(target=loop, daemon=True).start()
        self.addCleanup(lambda: (stop.set(), srv.close()))
        return srv.getsockname()[1]

    def pull(self, script, timeout=1.5):
        from .h4 import Env
        env = Env()
        port = self.serve(script)
        tr = TcpTransport("127.0.0.1", port, None, timeout=timeout)
        t = time.time()
        r = S.pull(env.m, env.tid, tr, env.me, peer_id=env.peers[0].id, deadline=10)
        return r, time.time() - t, env

    def test_close_mid_frame(self):
        r, dt, env = self.pull(lambda c, d: c.sendall(struct.pack(">I", 1000) + b"{"))
        self.assertFalse(r["ok"])
        self.assertTrue(r.get("unreachable"))
        self.assertLess(dt, 3)

    def test_deep_and_huge_json(self):
        for body in (b"[" * 60000, b"[" * 17 + b"]" * 17, b'{"a":' * 1000 + b"1" + b"}" * 1000, b" " * 10 + b"{}", b'{"a":1.5}', b'{"a":NaN}', b'{"a":1,"a":2}',
                     b"\xff\xfe", b"", b'{"t":"ok"}' + b"\x00"):
            with self.subTest(body=body[:20]):
                r, dt, _ = self.pull(lambda c, d, b=body: c.sendall(frame(b)) if b else c.sendall(struct.pack(">I", 0)))
                self.assertFalse(r["ok"])
                self.assertLess(dt, 3)

    def test_nonce_reflection_and_wrong_r(self):
        from sigilnet import canon
        import json
        for mut in (lambda q: {"t": "summary", "nonce": "0" * 16, "r": 1}, lambda q: {"t": "summary", "nonce": q["nonce"]},
                    lambda q: {"t": "summary", "nonce": q["nonce"], "r": 2}):
            with self.subTest():
                r, dt, _ = self.pull(lambda c, d, m=mut: c.sendall(frame(canon.dumps(m(json.loads(d))))))
                self.assertFalse(r["ok"])
                self.assertIn("does not answer", r["why"])

    def test_r_true_is_not_the_response_marker(self):
        # `resp.get("r") != 1` is False for True (True == 1 in Python): a boolean passes as the response marker
        from sigilnet import canon
        import json
        r, dt, _ = self.pull(lambda c, d: c.sendall(frame(canon.dumps({"t": "summary", "nonce": json.loads(d)["nonce"], "r": True}))))
        self.assertFalse(r["ok"] and "does not answer" not in r["why"])
        self.assertIn("does not answer", r["why"])

    def test_reflected_request_is_not_taken_for_a_response(self):
        r, dt, _ = self.pull(lambda c, d: c.sendall(frame(d)))
        self.assertFalse(r["ok"])

    def test_slow_drip_response_hits_the_transport_timeout(self):
        def drip(c, d):
            c.sendall(struct.pack(">I", 500))
            for _ in range(50):
                c.sendall(b"x")
                time.sleep(0.2)
        r, dt, _ = self.pull(drip, timeout=1.0)
        self.assertFalse(r["ok"])
        self.assertLess(dt, 2.5)

    def test_a_peer_cannot_make_us_create_a_thread_we_did_not_name(self):
        """Peer is a member of our thread Y but also holds thread X (public). It answers every `get` with X's events and lists X's genesis."""
        from sigilnet.build import make_genesis
        from sigilnet.event import event_id, encode
        from sigilnet.mirror import Mirror
        from sigilnet import canon
        from .h4 import Env
        import tempfile
        env = Env()
        other = Identity.generate("other")
        gx = make_genesis(other, "unnamed", [(env.me, "member"), (env.peers[0], "member")], k=1)
        gxid = event_id(gx)
        import json

        def fn(req):
            if req["t"] == "summary":
                return {"t": "summary", "thread": env.tid, "head": gxid, "n": 2}
            if req["t"] == "list":
                return {"t": "list", "thread": env.tid, "n": 2, "pages": 1, "ids": [gxid, env.tid]}
            if req["t"] == "get":
                return {"t": "events", "events": [gx], "more": []}
            return {"t": "ok"}
        env.m.follow = lambda g: event_id(g) == env.tid
        r = S.pull(env.m, env.tid, __import__("sigilnet.tests_adv4.h4", fromlist=["Reply"]).Reply(fn), env.me, peer_id=env.peers[0].id, deadline=5)
        self.assertNotIn(gxid, env.m.threads)
        self.assertFalse((env.m._dir(gxid)).exists())
        self.assertNotIn(gxid, env.m.orphans)


if __name__ == "__main__":
    unittest.main()
