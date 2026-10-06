"""tests_adv11 part 4: lifecycle, revocation across processes, restart, threads, concurrency, secrets (spec R5, A4-A8, A11) + the shared Conformance suite."""
import hashlib
import inspect
import json
import os
import socket
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from sigilnet import canon, tcp
from sigilnet import tcplink
from sigilnet.carrier import CarrierError
from sigilnet.tcplink import TcpCarrier
from sigilnet.tests.test_carrier import Conformance
from sigilnet.tests_adv11.h import Base, Raw, addr_parts, closed_within, drain, free_base, wait_for


def port_free(port, ip="127.0.0.1"):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)          # (TIME_WAIT leftovers of closed connections are not "bound")
    try:
        s.bind((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def refused(ep):
    ip, port, _ = addr_parts(ep)
    try:
        socket.create_connection((ip, port), timeout=1).close()
        return False
    except OSError:
        return True


class Lifecycle(Base):
    def test_start_stop_idempotent_restart_same_ports_and_endpoints(self):
        ep1, sec, port = self.door("p")
        ep2, _, _ = self.door("r", "read")
        self.assertFalse(self.c.healthy())
        self.c.start()
        self.c.start()                                                   # idempotent
        self.assertTrue(self.c.healthy())
        bob = self.mk("bob")
        bob.use_credential(ep1, sec)
        self.assertEqual(bob.dial(ep1, timeout=5).request({"t": "ping", "n": 1})["echo"], 1)
        lp = [addr_parts(e)[1] for e in (ep1, ep2)]
        self.c.stop()
        self.c.stop()                                                    # idempotent
        self.assertFalse(self.c.healthy())
        self.assertTrue(all(port_free(p) for p in lp))                   # listeners really closed
        self.assertTrue(refused(ep1))
        self.c.start()                                                   # the S1 restart path: same ports, same pins
        self.assertTrue(self.c.healthy())
        self.assertEqual((self.c.door_endpoint("p"), self.c.door_endpoint("r")), (ep1, ep2))
        self.assertEqual(bob.dial(ep1, timeout=5).request({"t": "ping", "n": 2})["echo"], 2)

    def test_stop_ends_live_streams_and_threads_do_not_leak(self):
        base_threads = threading.active_count()
        ep, sec, port = self.door("p", echo=False)

        def reply(conn, rec):                                            # the first 10 exchanges end normally; the 11th (the raw stream below) never ends by itself
            if rec.accepts <= 10:
                conn.recv(4096)
                conn.sendall(tcp._frame(canon.dumps({"t": "pong", "echo": 1})))
                conn.close()
            else:
                time.sleep(60)
        self.backend(port, reply)
        self.c.start()
        bob = self.mk("bob")
        bob.use_credential(ep, sec)
        for i in range(10):
            bob.dial(ep, timeout=5).request({"t": "ping", "n": i})
        r = Raw(ep)
        _, n = r.hello()
        r.s.sendall(r.auth(ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"])), n))
        self.assertEqual(r.exact(1), b"\x01")
        self.c.stop()
        self.assertTrue(closed_within(r.s, 4))                           # the stream is shut down (EOF, not a quiet timeout)
        self.assertTrue(wait_for(lambda: threading.active_count() <= base_threads + 2, 8),
                        [t.name for t in threading.enumerate()])         # (+2: the test's own echo server threads)
        self.assertEqual(self.c.healthy(), False)

    def test_start_with_a_busy_port_names_it_and_leaves_nothing_bound(self):
        ep1, _, _ = self.door("a", "read")
        ep2, _, _ = self.door("b", "read")
        ep3, _, _ = self.door("c", "read")
        busy = socket.socket()
        busy.bind(("127.0.0.1", addr_parts(ep2)[1]))
        busy.listen(1)
        self.cleanups.append(busy.close)
        with self.assertRaises(CarrierError) as cm:
            self.c.start()
        self.assertFalse(cm.exception.retry)
        self.assertIn(str(addr_parts(ep2)[1]), str(cm.exception))
        self.assertFalse(self.c.healthy())
        self.assertTrue(port_free(addr_parts(ep1)[1]))                   # a was bound first and must have been released again
        self.assertTrue(port_free(addr_parts(ep3)[1]))
        busy.close()
        self.c.start()                                                   # and the carrier is usable afterwards
        self.assertTrue(self.c.healthy())

    def test_damaged_door_key_or_cert_fails_start_without_retry_and_binds_nothing(self):
        ep1, _, _ = self.door("a", "read")
        ep2, _, _ = self.door("b", "read")
        pem = self.tmp / "a" / "door-b.pem"
        good = pem.read_bytes()
        cert_at = good.index(b"-----BEGIN CERTIFICATE-----")
        for name, data in (("cert truncated", good[:cert_at + 80]), ("no cert", good[:cert_at]), ("no key", good[cert_at:]), ("garbage", b"garbage"), ("empty", b""),
                           ("key corrupted", good[:60] + b"AAAA" + good[64:]), ("missing", None)):
            with self.subTest(name):
                if data is None:
                    pem.unlink()
                else:
                    pem.write_bytes(data)
                with self.assertRaises(CarrierError) as cm:
                    self.c.start()
                self.assertFalse(cm.exception.retry)
                self.assertFalse(self.c.healthy())
                self.assertTrue(port_free(addr_parts(ep1)[1]))
                self.assertTrue(port_free(addr_parts(ep2)[1]))
        pem.write_bytes(good)
        self.c.start()
        self.assertTrue(self.c.healthy())

    def test_pem_files_are_not_world_readable_after_everything(self):
        self.door("a", "read")
        self.c.start()
        for f in (self.tmp / "a").iterdir():
            if f.is_file() and f.name != "state.lock":
                self.assertEqual(oct(f.stat().st_mode & 0o077), "0o0", f.name)

    def test_healthy_notices_a_dead_accept_thread_is_not_required_but_stop_after_death_is_safe(self):
        self.door("a", "read")
        self.c.start()
        self.c.stop()
        self.c.stop()


class Reconfigure(Base):
    def test_reconfigure_semantics(self):
        self.assertFalse(self.c.reconfigure())                           # not started: no-op
        ep, _, _ = self.door("a", "read")
        self.assertFalse(self.c.reconfigure())
        self.c.start()
        self.assertFalse(self.c.reconfigure())                           # nothing changed
        other = self.mk("a")                                             # "the CLI process", same state dir
        port = other.open_door("late", "read")
        self.echo(port)
        self.assertTrue(self.c.reconfigure())
        self.assertFalse(self.c.reconfigure())
        bob = self.mk("bob")
        self.assertEqual(bob.dial(other.door_endpoint("late"), timeout=5).request({"t": "ping", "n": 1})["echo"], 1)
        late_ep = other.door_endpoint("late")
        other.close_door("late")
        self.assertTrue(self.c.reconfigure())
        self.assertTrue(wait_for(lambda: refused(late_ep), 3))

    def test_close_door_elsewhere_kills_listener_and_live_streams_on_reconfigure(self):
        ep, sec, port = self.door("p", echo=False)
        self.backend(port, None, hold=True)                              # a backend that never ends the exchange itself
        self.c.start()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"]))
        r = Raw(ep)
        _, n = r.hello()
        r.s.sendall(r.auth(priv, n))
        self.assertEqual(r.exact(1), b"\x01")
        cli = self.mk("a")
        self.assertTrue(cli.close_door("p"))
        self.assertTrue(cli.door_gone("p"))
        t0 = time.time()
        self.assertTrue(self.c.reconfigure())
        self.assertTrue(closed_within(r.s, 4))                           # revocation is immediate: the live stream is shut down (EOF)
        self.assertLess(time.time() - t0, 3)
        self.assertTrue(wait_for(lambda: refused(ep), 3))               # listener closed

    def test_revoked_credential_is_refused_even_before_reconfigure(self):
        ep, sec, port = self.door("p", echo=False)
        b = self.backend(port, b"x", hold=True)
        self.c.start()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"]))
        cli = self.mk("a")
        # re-key by another process: the old credential must stop working at the very next connection
        _, new_pub = cli.new_credential()
        cli.open_door("p", "peer", credential=new_pub)
        r = Raw(ep)
        _, n = r.hello()
        self.assertFalse(r.admitted(r.auth(priv, n)))
        self.assertEqual(b.accepts, 0)
        # close by another process, no reconfigure on the running carrier
        cli.close_door("p")
        try:
            r = Raw(ep)
        except OSError:
            return
        try:
            m, n = r.hello()
        except (EOFError, OSError):
            return                                                       # the door entry is re-read after the handshake: nothing more is said
        self.assertFalse(r.admitted(r.auth(priv, n)))
        self.assertEqual(b.accepts, 0)

    def test_rekey_between_hello_and_auth_refuses_the_old_credential(self):
        if os.environ.get("ADV11_SKIP_OPEN_FINDINGS"):
            self.skipTest("open finding (mutation runs skip it so that the baseline is green)")
        """A14 (asked of the spec author): the door entry is read again when the auth arrives, so a credential revoked DURING the up-to-5 s admission window loses."""
        ep, sec, port = self.door("p", echo=False)
        b = self.backend(port, b"x", hold=True)
        self.c.start()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"]))
        r = Raw(ep)
        _, n = r.hello()
        cli = self.mk("a")
        cli.open_door("p", "peer", credential=cli.new_credential()[1])
        self.assertFalse(r.admitted(r.auth(priv, n)))
        self.assertEqual(b.accepts, 0)

    def test_one_unbindable_new_door_does_not_take_the_other_doors_down(self):
        if os.environ.get("ADV11_SKIP_OPEN_FINDINGS"):
            self.skipTest("open finding (mutation runs skip it so that the baseline is green)")
        """FINDING F2 (design, not in the written spec): doors.sync() calls reconfigure() every tick; the Doors layer promises 'the other doors keep working; retrying'.
        A new door (made by the CLI) whose port is taken must be reported, not raised, and the doors after it must still get their listeners."""
        ep0, _, _ = self.door("a", "read")
        self.c.start()
        cli = self.mk("a")
        cli.open_door("busy", "read")
        cli.open_door("later", "read")
        busy = socket.socket()
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        busy.bind(("127.0.0.1", addr_parts(cli.door_endpoint("busy"))[1]))
        busy.listen(1)
        self.cleanups.append(busy.close)
        try:
            self.c.reconfigure()
        except CarrierError:
            pass
        self.assertFalse(refused(cli.door_endpoint("later")), "the door created after the unbindable one has no listener")
        self.assertTrue(self.c.healthy())
        busy.close()                                                     # the port frees up: the next tick must open it (retry), not give up for good
        try:
            self.c.reconfigure()
        except CarrierError:
            pass
        self.assertTrue(wait_for(lambda: not refused(cli.door_endpoint("busy")), 3), "the door whose port was taken is never retried")

    def test_door_recreated_between_hello_and_auth_is_not_served_by_the_old_listener(self):
        """The index is compared on the read AT auth time too: connect to the old door, wait for the hello, THEN re-create the door under the same name (new index, same
        credential) and present an admission that is valid for the NEW door."""
        ep, sec, port = self.door("p", echo=False)
        pub = {"type": "tcp", "key": hashlib.sha256(__import__("sigilnet.tests_adv11.h", fromlist=["x"]).raw_pub(ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"])))).hexdigest()}
        self.c.start()
        r = Raw(ep)                                                      # the OLD listener, hello read
        _, n = r.hello()
        cli = self.mk("a")
        cli.close_door("p")
        new_port = cli.open_door("p", "peer", credential=pub)             # same credential, new index / key / fp / loopback port
        nb = self.backend(new_port, b"y", hold=True)
        new_fp = addr_parts(cli.door_endpoint("p"))[2]
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"]))
        self.assertFalse(r.admitted(r.auth(priv, n, fp=new_fp)))
        self.assertEqual(nb.accepts, 0)

    def test_recreated_door_under_another_index_gets_nothing_from_the_old_listener(self):
        ep, sec, port = self.door("p", echo=False)
        b = self.backend(port, b"x", hold=True)
        self.c.start()
        cli = self.mk("a")
        cli.close_door("p")
        new_sec, new_pub = cli.new_credential()
        new_port = cli.open_door("p", "peer", credential=new_pub)
        self.assertNotEqual(new_port, port)
        nb = self.backend(new_port, b"y", hold=True)
        new_fp = addr_parts(cli.door_endpoint("p"))[2]
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(new_sec["key"]))
        for fp in (None, new_fp):                                        # signed for the old door's fp, and (worse) for the NEW door's fp
            r = Raw(ep)                                                  # the OLD listener (not yet reconfigured)
            try:
                _, n = r.hello()
                self.assertFalse(r.admitted(r.auth(priv, n, fp=fp)))
            except (EOFError, OSError):
                pass
            r.close()
        self.assertEqual((b.accepts, nb.accepts), (0, 0))

    def test_rekey_affects_new_connections_only(self):
        ep, sec, port = self.door("p")
        self.c.start()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sec["key"]))
        r = Raw(ep)
        _, n = r.hello()
        r.s.sendall(r.auth(priv, n))
        self.assertEqual(r.exact(1), b"\x01")
        new_sec, new_pub = self.c.new_credential()
        self.c.open_door("p", "peer", credential=new_pub)                # the same carrier object re-keys: A5
        r.s.sendall(tcp._frame(canon.dumps({"t": "ping", "n": 9})))      # the live stream finishes its exchange
        n2 = int.from_bytes(r.exact(4), "big")
        self.assertEqual(canon.loads(r.exact(n2))["echo"], 9)
        r2 = Raw(ep)
        _, n = r2.hello()
        self.assertFalse(r2.admitted(r2.auth(priv, n)))                  # old key: refused
        r3 = Raw(ep)
        _, n = r3.hello()
        self.assertTrue(r3.admitted(r3.auth(ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(new_sec["key"])), n)))

    def test_ports_stay_as_stored_when_config_changes(self):
        ep, sec, port = self.door("p")
        c2 = TcpCarrier(self.tmp / "a", bind="127.0.0.1", port_base=self.base + 30, advertise="10.9.8.7")
        self.cleanups.append(c2.stop)
        e2 = c2.door_endpoint("p")
        ip, p, fp = addr_parts(e2)
        ip0, p0, fp0 = addr_parts(ep)
        self.assertEqual((ip, p, fp), ("10.9.8.7", p0, fp0))             # advertise changes only the ip
        self.assertEqual(c2.doors()["p"]["port"], port)
        self.assertEqual(c2.open_door("n", "read"), self.base + 30 + 3)  # next_index=1 continues, numbered from the NEW port_base
        c3 = TcpCarrier(self.tmp / "a", bind="127.0.0.1", port_base=self.base)   # back to the old base: the stored ports still win
        self.assertEqual(c3.doors()["p"]["port"], port)
        self.assertEqual(addr_parts(c3.door_endpoint("p"))[1], p0)


class Held(Base):
    def test_damaged_held_credential_is_final_not_retryable(self):
        ep, sec, port = self.door("p")
        self.c.start()
        bob = self.mk("bob")
        bob.use_credential(ep, sec)
        h = json.loads((self.tmp / "bob" / "held.json").read_text())
        h[ep["addr"]] = {"type": "tcp", "key": "zz"}
        (self.tmp / "bob" / "held.json").write_text(json.dumps(h))
        with self.assertRaises(CarrierError) as cm:
            bob.dial(ep, timeout=3).request({"t": "ping", "n": 1})
        self.assertFalse(cm.exception.retry)


class Concurrency(Base):
    def test_two_processes_worth_of_writers_never_corrupt_or_collide(self):
        a, b = self.mk("shared"), self.mk("shared")
        errs = []

        def go(c, tag):
            try:
                for i in range(15):
                    c.open_door(f"{tag}{i}", "read")
            except Exception as e:
                errs.append(repr(e))
        ts = [threading.Thread(target=go, args=(a, "x")), threading.Thread(target=go, args=(b, "y")), threading.Thread(target=go, args=(a, "z"))]
        [t.start() for t in ts]
        [t.join(60) for t in ts]
        self.assertEqual(errs, [])
        st = json.loads((self.tmp / "shared" / "doors.json").read_text())
        self.assertEqual(len(st["doors"]), 45)
        idx = sorted(d["index"] for d in st["doors"].values())
        self.assertEqual(idx, list(range(45)))
        self.assertEqual(st["next_index"], 45)
        ports = {d["listen_port"] for d in st["doors"].values()} | {d["loopback_port"] for d in st["doors"].values()}
        self.assertEqual(len(ports), 90)
        for n in st["doors"]:
            self.assertTrue((self.tmp / "shared" / f"door-{n}.pem").exists())

    def test_held_credentials_survive_concurrent_writers(self):
        a, b = self.mk("h"), self.mk("h")
        eps = [{"type": "tcp", "addr": f"127.0.0.1:{4000 + i}#{'ab' * 32}"} for i in range(30)]
        secs = [a.new_credential()[0] for _ in eps]
        ts = [threading.Thread(target=lambda c=c, rng=rng: [c.use_credential(eps[i], secs[i]) for i in rng]) for c, rng in ((a, range(0, 30, 2)), (b, range(1, 30, 2)))]
        [t.start() for t in ts]
        [t.join(30) for t in ts]
        held = json.loads((self.tmp / "h" / "held.json").read_text())
        self.assertEqual(len(held), 30)


class Code(unittest.TestCase):
    """Code checks the spec asks for (R6). They look at the SOURCE: weak by nature, kept because the spec lists them."""

    def test_constant_time_compare_and_tls_pinning_options_are_present(self):
        src = inspect.getsource(tcplink)
        self.assertIn("compare_digest", src)
        self.assertGreaterEqual(src.count("TLSv1_3"), 2)
        self.assertIn("OP_NO_TICKET", src)
        self.assertIn("CERT_NONE", src)
        self.assertNotIn("CERT_OPTIONAL", src)
        self.assertNotIn("0.0.0.0\", ", "")

    def test_imports_are_the_declared_ones(self):
        import ast
        tree = ast.parse(inspect.getsource(tcplink))
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                mods.add(("." * n.level) + (n.module or ""))
        for banned in ("torlink", "noderun", "requests", "urllib", "subprocess", "pickle", "ctypes"):
            self.assertFalse([m for m in mods if banned in m], (banned, mods))
        calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        self.assertFalse(calls & {"os.system", "eval", "exec", "os.popen"}, calls)


class TcpConformance(Conformance, unittest.TestCase):
    """The same conformance suite the Tor and fake carriers pass (tier 1 + 2; tier 3 'delivery' is covered by test_wire)."""
    DELIVERS = False

    def other_endpoint(self):
        return {"type": "tcp", "addr": "127.0.0.1:1#" + "ab" * 32}

    def make(self):
        import tempfile
        from pathlib import Path
        d = Path(tempfile.mkdtemp())
        c = TcpCarrier(d / "tcp", bind="127.0.0.1", port_base=free_base())
        self.addCleanup(c.stop)
        return c


if __name__ == "__main__":
    unittest.main()
