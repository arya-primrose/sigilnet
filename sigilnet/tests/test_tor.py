"""Step 3, offline parts: the SOCKS5 client, the plain-frame server, torrc and authorization files, and (with DisableNetwork) a real tor process.
No test here touches the tor network."""
import json
import os
import re
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sigilnet import sync as S
from sigilnet import tcp
from sigilnet import torlink as T
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror

from .test_sync import mirror_with
from .util import World

ONION = "a" * 56 + ".onion"


class FakeSocks:
    """A SOCKS5 proxy on loopback that records the requested name and forwards to one local port (or answers with an error code)."""

    def __init__(self, forward_to=None, reply=0, stall=False, delay=0.0):
        self.forward_to, self.reply, self.stall, self.delay = forward_to, reply, stall, delay
        self.asked = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.run, daemon=True).start()

    def close(self):
        self.sock.close()

    def asked_names(self):
        return list(self.asked)

    def run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        try:
            c.settimeout(5)
            if self.stall:
                time.sleep(30)
                return
            assert c.recv(3) == b"\x05\x01\x00"
            c.sendall(b"\x05\x00")
            head = c.recv(4)
            assert head == b"\x05\x01\x00\x03", head
            n = c.recv(1)[0]
            name = c.recv(n)
            port = struct.unpack(">H", c.recv(2))[0]
            self.asked.append((name.decode(), port))
            time.sleep(self.delay)                                # a slow rendezvous
            c.sendall(bytes([5, self.reply, 0, 1]) + b"\x00\x00\x00\x00\x00\x00")
            if self.reply != 0:
                return
            target = self.forward_to[name.decode()] if isinstance(self.forward_to, dict) else self.forward_to
            up = socket.create_connection(("127.0.0.1", target))
            for a, b in ((c, up), (up, c)):
                threading.Thread(target=self.pipe, args=(a, b), daemon=True).start()
            time.sleep(10)
        except Exception:                                   # noqa: BLE001
            pass

    @staticmethod
    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for x in (a, b):
                try:
                    x.close()
                except OSError:
                    pass


class Socks(unittest.TestCase):
    def setUp(self):
        self.w = World()
        for n in range(5):
            self.w.add(self.w.w("carol").post(str(n)))
        self.a = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        self.srv = tcp.TcpServer("127.0.0.1", 0, None, S.SyncServer(self.a).handle).start()
        self.addCleanup(self.srv.stop)

    def test_pull_through_a_socks_proxy_to_an_onion_name_over_plain_frames(self):
        proxy = FakeSocks(forward_to=self.srv.port)
        self.addCleanup(proxy.close)
        tr = T.TorTransport(ONION, 47200, ("127.0.0.1", proxy.port), timeout=10)
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, self.w.t.id, tr, self.w.ids["sansa"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(b.thread(self.w.t.id).resolved_ids()), len(self.a.thread(self.w.t.id).resolved_ids()))
        self.assertEqual({x for x in proxy.asked}, {(ONION, 47200)})                        # the NAME went to tor unresolved, never an IP

    def test_only_v3_onion_names_are_ever_dialed(self):
        proxy = FakeSocks(forward_to=self.srv.port)
        self.addCleanup(proxy.close)
        for bad in ("example.com", "a" * 16 + ".onion", ONION + ".evil.com", "1.2.3.4", "", ONION[:-1], "a" * 56 + ".onion\n.x"):
            with self.assertRaises(ValueError, msg=bad):
                T.TorTransport(bad, 47200, ("127.0.0.1", proxy.port))
        self.assertEqual(proxy.asked, [])
        self.assertEqual(T.TorTransport("A" * 56 + ".ONION", 47200, ("127.0.0.1", proxy.port)).host, ONION)       # names are case-insensitive: normalized

    def test_every_socks_error_becomes_a_tor_error_that_says_whether_to_retry(self):
        for code, (name, retry) in T.SOCKS_ERRORS.items():
            proxy = FakeSocks(reply=code)
            self.addCleanup(proxy.close)
            with self.assertRaises(T.TorError) as cm:
                T.TorTransport(ONION, 47200, ("127.0.0.1", proxy.port), timeout=5).request({"t": "summary"})
            self.assertEqual(cm.exception.retry, retry, name)
            self.assertIn(name.split(" (")[0], str(cm.exception))
        self.assertFalse(T.SOCKS_ERRORS[0xF4][1])                                           # "needs auth" and "wrong auth" cannot be fixed by waiting
        self.assertFalse(T.SOCKS_ERRORS[0xF5][1])
        self.assertTrue(T.SOCKS_ERRORS[0xF0][1])                                            # "descriptor not found" can (the peer may just be offline)

    def test_unknown_socks_error_code_is_retryable_and_named(self):
        proxy = FakeSocks(reply=0x99)
        self.addCleanup(proxy.close)
        with self.assertRaises(T.TorError) as cm:
            T.TorTransport(ONION, 47200, ("127.0.0.1", proxy.port), timeout=5).request({"t": "summary"})
        self.assertTrue(cm.exception.retry)
        self.assertIn("0x99", str(cm.exception))

    def test_a_stalled_proxy_and_a_dead_socks_port_fail_within_the_deadline(self):
        proxy = FakeSocks(stall=True)
        self.addCleanup(proxy.close)
        t0 = time.time()
        with self.assertRaises(T.TorError):
            T.TorTransport(ONION, 47200, ("127.0.0.1", proxy.port), timeout=1.5).request({"t": "summary"})
        self.assertLess(time.time() - t0, 4)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            dead = s.getsockname()[1]
        with self.assertRaises(T.TorError) as cm:
            T.TorTransport(ONION, 47200, ("127.0.0.1", dead), timeout=2).request({"t": "summary"})
        self.assertIn("is tor running", str(cm.exception))


class PlainServer(unittest.TestCase):
    def test_a_plain_server_binds_loopback_only(self):
        for host in ("0.0.0.0", "172.17.0.3", "8.8.8.8", "192.168.1.5"):
            with self.assertRaises(ValueError, msg=host):
                tcp.TcpServer(host, 0, None, lambda r: r)
        s = tcp.TcpServer("127.0.0.1", 0, None, lambda r: {"t": "ok"})
        s.sock.close()

    def test_plain_frames_roundtrip_and_garbage_gets_no_answer(self):
        srv = tcp.TcpServer("127.0.0.1", 0, None, lambda r: {"t": "echo", "got": r.get("x")}).start()
        self.addCleanup(srv.stop)
        self.assertEqual(tcp.TcpTransport("127.0.0.1", srv.port, None).request({"x": 7}), {"t": "echo", "got": 7})
        with socket.create_connection(("127.0.0.1", srv.port)) as c:
            junk = b"not json at all"
            c.sendall(struct.pack(">I", len(junk)) + junk)
            c.settimeout(2)
            self.assertEqual(c.recv(10), b"")

    def test_connections_are_limited_globally_not_per_address(self):
        srv = tcp.TcpServer("127.0.0.1", 0, None, lambda r: {"t": "ok"}).start()
        self.addCleanup(srv.stop)
        held = [socket.create_connection(("127.0.0.1", srv.port)) for _ in range(tcp.PLAIN_CONNS)]     # idle, never send a header
        try:
            time.sleep(0.3)
            extra = socket.create_connection(("127.0.0.1", srv.port))
            extra.settimeout(1.5)
            self.assertEqual(extra.recv(10), b"")                                        # the 9th is dropped at once
            extra.close()
            t0 = time.time()
            held[0].settimeout(tcp.DEADLINE)
            self.assertEqual(held[0].recv(10), b"")                                      # idle ones are dropped at the header deadline
            self.assertLess(time.time() - t0, tcp.HEADER_DEADLINE + 1.5)
            time.sleep(0.2)
            self.assertEqual(tcp.TcpTransport("127.0.0.1", srv.port, None, timeout=3).request({"t": "x"}), {"t": "ok"})     # and the slot is free again
        finally:
            for h in held:
                h.close()

    def test_a_burst_of_connections_hits_the_per_minute_cap(self):
        srv = tcp.TcpServer("127.0.0.1", 0, None, lambda r: {"t": "ok"}).start()
        self.addCleanup(srv.stop)
        ok = fail = 0
        for _ in range(tcp.PLAIN_PER_MIN + 40):
            try:
                tcp.TcpTransport("127.0.0.1", srv.port, None, timeout=3).request({"t": "x"})
                ok += 1
            except Exception:                                                            # noqa: BLE001
                fail += 1
        self.assertLessEqual(ok, tcp.PLAIN_PER_MIN)
        self.assertGreater(fail, 0)


class Config(unittest.TestCase):
    def node(self, **kw):
        return T.TorNode(tempfile.mkdtemp(), local_port=47201, offline=True, **kw)

    def test_torrc_has_no_public_listener_and_no_control_port(self):
        cfg = self.node().config()
        self.assertRegex(cfg, r"SocksPort 127\.0\.0\.1:\d+")
        self.assertIn("ControlPort 0", cfg)
        self.assertIn("HiddenServicePort 47200 127.0.0.1:47201", cfg)
        self.assertNotRegex(cfg, r"(?m)^(ORPort|DirPort|ExtORPort|TransPort|DNSPort|ControlPort [1-9]|SocksPort (0\.0\.0\.0|\[::\]))")
        self.assertIn("HiddenServiceVersion 3", cfg)
        self.assertIn("HiddenServicePoWDefensesEnabled 1", cfg)                              # tor's own proof-of-work defence against connection floods

    def test_ports_are_range_checked_and_control_characters_in_the_path_refused(self):
        for kw in ({"local_port": 70000}, {"local_port": -1}, {"virtual_port": 0}, {"virtual_port": 65536}, {"socks_port": 99999}, {"local_port": "12\nControlPort 9051"},
                   {"local_port": 12.5}, {"virtual_port": True}):
            with self.assertRaises(ValueError, msg=str(kw)):
                T.TorNode(tempfile.mkdtemp(), offline=True, **{"local_port": 4000, **kw})
        for bad in ("a\nSocksPort 0.0.0.0:1", "a\rb", "a\x00b"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                T.TorNode(Path(tempfile.mkdtemp()) / bad, local_port=4000, offline=True)

    def test_a_client_only_node_has_no_onion_service(self):
        n = T.TorNode(tempfile.mkdtemp(), offline=True)
        self.assertNotIn("HiddenService", n.config())
        with self.assertRaises(ValueError):
            n.authorize("bob", "A" * 52)

    def test_only_bridge_lines_can_be_added_to_the_configuration(self):
        n = self.node(bridge_lines=["Bridge webtunnel 1.2.3.4:443 FINGERPRINT url=https://x/y", "ClientTransportPlugin webtunnel exec /usr/bin/webtunnel"])
        self.assertIn("UseBridges 1", n.config())
        self.assertIn("Bridge webtunnel", n.config())
        for bad in ("ControlPort 9051", "SocksPort 0.0.0.0:9050", "Bridge x\nControlPort 9051", "HiddenServiceDir /etc", "Log debug file /etc/passwd"):
            with self.assertRaises(ValueError, msg=bad):
                self.node(bridge_lines=[bad])

    def test_authorize_revoke_and_client_keys(self):
        n = self.node()
        priv, pub = T.make_client_key()
        self.assertRegex(priv, r"^[A-Z2-7]{52}$")
        self.assertRegex(pub, r"^[A-Z2-7]{52}$")
        p = n.authorize("sansa", pub)
        self.assertEqual(p.read_text(), f"descriptor:x25519:{pub}\n")
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertEqual(n.authorized(), ["sansa"])
        for bad_name in ("../x", "A", "", "a" * 40, "a b", "a/b"):
            with self.assertRaises(ValueError, msg=bad_name):
                n.authorize(bad_name, pub)
        for bad_pub in ("", "abc", "A" * 51, "a" * 52, "A" * 52 + "\n" + "B" * 52, "1" * 52):
            with self.assertRaises(ValueError, msg=bad_pub):
                n.authorize("x", bad_pub)
        self.assertTrue(n.revoke("sansa"))
        self.assertFalse(n.revoke("sansa"))
        self.assertEqual(n.authorized(), [])
        q = n.add_client_auth(ONION, priv)
        self.assertEqual(q.read_text(), f"{'a' * 56}:descriptor:x25519:{priv}\n")
        self.assertEqual(q.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            n.add_client_auth("example.com", priv)

    def test_a_real_tor_process_creates_the_onion_identity_offline(self):
        root = tempfile.mkdtemp()
        n = T.TorNode(root, local_port=47201, offline=True)
        n.start(wait=True, timeout=60)
        try:
            host = n.hostname()
            self.assertRegex(host, r"^[a-z2-7]{56}\.onion$")
            self.assertEqual((Path(root) / "hs").stat().st_mode & 0o777, 0o700)
            priv, pub = T.make_client_key()
            n.authorize("sansa", pub)                                   # SIGHUP to a live tor must not kill it
            time.sleep(1.0)
            self.assertTrue(n.running())
        finally:
            n.stop()
        self.assertFalse(n.running())
        n2 = T.TorNode(root, local_port=47201, offline=True)            # the same directory keeps the same onion identity across restarts
        n2.start(wait=True, timeout=60)
        try:
            self.assertEqual(n2.hostname(), host)
        finally:
            n2.stop()

    def test_a_tor_that_fails_to_start_is_reported_not_hung(self):
        n = T.TorNode(tempfile.mkdtemp(), local_port=47201, offline=True, tor_bin="/bin/false")
        with self.assertRaises(T.TorError):
            n.start(wait=True, timeout=10)


class Wired(unittest.TestCase):
    """Two real nodes: plain TcpServer + SyncServer each, dialing each other through TorTransport and a fake SOCKS router (everything but tor itself)."""

    def test_two_nodes_sync_through_socks_and_notify_each_other(self):
        from sigilnet import node as N
        from sigilnet.build import Writer, make_genesis
        from sigilnet.event import event_id
        from sigilnet.keys import Identity
        ids = {"arya": Identity.generate("arya"), "sansa": Identity.generate("sansa")}
        onions = {"arya": "a" * 56 + ".onion", "sansa": "b" * 56 + ".onion"}
        mirrors = {n: Mirror(tempfile.mkdtemp() + "/m", rate_limit=False) for n in ids}
        homes = {n: Path(tempfile.mkdtemp()) for n in ids}
        nodes, servers, ports = {}, {}, {}
        router = FakeSocks(forward_to=ports)
        self.addCleanup(router.close)

        def transport_for(rec):
            onion, port = rec["endpoint"]["addr"].rsplit(":", 1)
            return T.TorTransport(onion, int(port), ("127.0.0.1", router.port), timeout=10)
        for n in ids:
            nodes[n] = N.Node(mirrors[n], ids[n], N.PeerBook(homes[n] / "peers.json"), homes[n] / "node.json", transport_for, pull_interval=3600)
            servers[n] = tcp.TcpServer("127.0.0.1", 0, None, S.SyncServer(mirrors[n], identity=ids[n], on_notify=nodes[n].on_notify).handle).start()
            self.addCleanup(servers[n].stop)
            ports[onions[n]] = servers[n].port
        g = make_genesis(ids["arya"], "wired", [(ids["sansa"], "member")], k=1)
        tid = event_id(g)
        mirrors["arya"].ingest(g)
        nodes["arya"].peers.add(ids["sansa"].id, "sansa", {"type": "onion", "addr": onions["sansa"] + ":47200"})
        nodes["sansa"].peers.add(ids["arya"].id, "arya", {"type": "onion", "addr": onions["arya"] + ":47200"}, threads=[tid])
        mirrors["arya"].ingest(Writer(ids["arya"], mirrors["arya"].thread(tid)).post("hello over socks"))
        for _ in range(4):
            for n in nodes:
                nodes[n].tick()
            time.sleep(0.05)
        t = mirrors["sansa"].thread(tid)
        self.assertEqual(sorted(e["body"].get("text", "") for e in t.stored.values() if e["kind"] == "post"), ["hello over socks"])
        mirrors["sansa"].ingest(Writer(ids["sansa"], t).post("and back"))
        end = time.time() + 15
        while time.time() < end and len([e for e in mirrors["arya"].thread(tid).stored.values() if e["kind"] == "post"]) < 2:
            for n in nodes:
                nodes[n].tick()
            time.sleep(0.2)                                                                        # (the hint makes arya pull, rate limited by the pull token bucket)
        texts = sorted(e["body"].get("text", "") for e in mirrors["arya"].thread(tid).stored.values() if e["kind"] == "post")
        self.assertEqual(texts, ["and back", "hello over socks"])
        self.assertEqual({a for a, _ in router.asked_names()}, set(onions.values()))                # only onion names ever went to the proxy


class Cli(unittest.TestCase):
    def run_cli(self, home, *args, expect=0):
        import subprocess
        import sys
        r = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(home), *args], capture_output=True, text=True, timeout=120,
                           cwd=str(Path(__file__).resolve().parents[2]))
        self.assertEqual(r.returncode, expect, (args, r.stdout, r.stderr))
        return r.stdout + r.stderr

    def test_node_and_peer_commands(self):
        home = Path(tempfile.mkdtemp())
        self.run_cli(home, "id", "init", "me")
        out = self.run_cli(home, "node", "init", "--service-port-base", "47391", "--virtual-port", "47200")
        self.assertIn("one onion service per peer", out)
        self.assertEqual((home / "node_config.json").stat().st_mode & 0o777, 0o600)
        self.run_cli(home, "node", "init", "--bridge", "ControlPort 9051", expect=1)
        self.run_cli(home, "node", "address", expect=1)                                                   # no service yet
        out = self.run_cli(home, "node", "auth", "sansa-key")
        pub = re.search(r"\n([A-Z2-7]{52})\s*$", out).group(1)
        self.assertEqual((home / "peerkeys" / "sansa-key.priv").stat().st_mode & 0o777, 0o600)
        self.assertNotIn((home / "peerkeys" / "sansa-key.priv").read_text().strip(), out)                # the private half is never printed
        self.run_cli(home, "node", "auth", "sansa-key", expect=1)                                          # never silently replaced
        agent = "a" * 32
        self.run_cli(home, "node", "authorize", "sansa", pub, "--agent", agent)
        f = home / "tor" / "services" / "sansa" / "authorized_clients" / "client.auth"
        self.assertEqual(f.read_text(), f"descriptor:x25519:{pub}\n")
        self.assertEqual(json.loads((home / "tor" / "services.json").read_text())["sansa"], {"agent": agent, "kind": "peer", "port": 47391})
        self.run_cli(home, "node", "authorize", "bob", pub)
        self.assertEqual(json.loads((home / "tor" / "services.json").read_text())["bob"]["port"], 47392)    # its own local port
        self.run_cli(home, "node", "authorize", "../evil", pub, expect=1)
        self.run_cli(home, "node", "authorize", "x", "short", expect=1)
        self.run_cli(home, "node", "authorize", "x", pub, "--agent", "not-an-agent", expect=1)
        self.assertIn("revoked", self.run_cli(home, "node", "revoke", "sansa"))
        self.assertFalse(f.exists())                                                                      # the whole door is gone
        agent = "b" * 32
        self.run_cli(home, "peer", "add", "bob", agent, "--onion", "c" * 56 + ".onion", "--thread", "d" * 32, "--key", "sansa-key")
        self.assertTrue(list((home / "tor" / "client_auth").glob("*.auth_private")))
        self.assertIn("bob", self.run_cli(home, "peer", "list"))
        self.run_cli(home, "peer", "add", "eve", agent, "--onion", "example.com", expect=1)
        self.run_cli(home, "peer", "add", "eve", agent, "--onion", "c" * 56 + ".onion", "--key", "nokey", expect=1)
        self.assertIn("removed", self.run_cli(home, "peer", "rm", agent))

    def test_node_run_offline_opens_a_door_per_peer_on_loopback_and_stops_cleanly(self):
        home = Path(tempfile.mkdtemp())
        self.run_cli(home, "id", "init", "me")
        self.run_cli(home, "node", "init", "--service-port-base", str(__import__("random").randint(20000, 30000)))        # (a fixed port collided under parallel suites)
        pub = T.make_client_key()[1]
        self.run_cli(home, "node", "authorize", "sansa", pub, "--agent", "a" * 32)
        self.run_cli(home, "node", "authorize", "bob", pub)
        out = self.run_cli(home, "node", "run", "--offline", "--seconds", "4")
        self.assertRegex(out, r"door for sansa: [a-z2-7]{56}\.onion:47200 \(only agent aaaaaaaa\)")
        self.assertRegex(out, r"door for bob: [a-z2-7]{56}\.onion:47200")
        self.assertIn("behind 2 door(s)", out)
        addr = self.run_cli(home, "node", "address")
        self.assertEqual(len(set(re.findall(r"[a-z2-7]{56}\.onion", addr))), 2)                            # two different addresses
        self.assertRegex(self.run_cli(home, "node", "address", "bob"), r"^bob\s+[a-z2-7]{56}\.onion:47200")
        import subprocess
        self.assertNotEqual(subprocess.run(["pgrep", "-f", str(home / "torrc")], capture_output=True).returncode, 0)   # no tor left behind


class RunningNode(unittest.TestCase):
    def test_a_running_node_binds_each_door_to_its_agent(self):
        import subprocess
        import sys
        from sigilnet.keys import Identity
        root = str(Path(__file__).resolve().parents[2])
        home = Path(tempfile.mkdtemp())
        base = [sys.executable, "-m", "sigilnet", "--home", str(home)]
        run = lambda *a: subprocess.run([*base, *a], capture_output=True, text=True, cwd=root, timeout=60)
        run("id", "init", "me")
        me = json.loads(run("id", "show", "--json").stdout)
        sansa, carol = Identity.generate("sansa"), Identity.generate("carol")
        files = {}
        for i in (sansa, carol):
            files[i.name] = home / f"{i.name}.json"
            files[i.name].write_text(json.dumps({"name": i.name, "agent": i.id, "sign": i.sign_pub, "kex": i.kex_pub}))
        out = run("new", "door test", "--member", f"member={files['sansa']}", "--member", f"member={files['carol']}").stdout
        tid = re.search(r"thread ([0-9a-f]{32})", out).group(1)
        pub = T.make_client_key()[1]
        self.assertEqual(run("node", "init", "--service-port-base", "47441").returncode, 0)
        self.assertEqual(run("node", "authorize", "sansa", pub, "--agent", sansa.id).returncode, 0)        # port 47441, bound to sansa
        self.assertEqual(run("node", "authorize", "open", pub).returncode, 0)                              # port 47442, not bound
        proc = subprocess.Popen([*base, "node", "run", "--offline", "--seconds", "14"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=root)
        try:
            end = time.time() + 30
            while time.time() < end:
                try:
                    socket.create_connection(("127.0.0.1", 47442), timeout=0.5).close()
                    socket.create_connection(("127.0.0.1", 47441), timeout=0.5).close()
                    break
                except OSError:
                    time.sleep(0.3)
            else:
                self.fail("the node never opened its doors")
            ask = lambda port, who: tcp.TcpTransport("127.0.0.1", port, None, timeout=5).request(S.sign_request(who, {"t": "summary", "thread": tid}, aud=me["agent"]))
            self.assertEqual(ask(47441, sansa)["t"], "summary")                                           # sansa, on sansa's door
            self.assertEqual(ask(47441, carol)["t"], "unknown")                                           # carol IS a member, but this door is sansa's
            self.assertEqual(ask(47442, carol)["t"], "summary")                                           # an unbound door serves any member
            self.assertEqual(ask(47442, Identity.generate("eve"))["t"], "unknown")
            self.assertTrue(S.response_signed_by(ask(47442, carol), me["agent"]))                           # and every answer is signed by the node's agent key
        finally:
            proc.wait(timeout=40)


class TorLifecycle(unittest.TestCase):
    def _alive(self, pid):
        try:
            return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] != "Z"
        except OSError:
            return False

    def test_a_killed_node_does_not_leave_its_tor_behind_and_restart_works(self):
        # live test 2026-09-30: kill -9 of the node left tor running; the restart died with 'another Tor process is running with the same data directory'
        import subprocess
        import sys
        root = tempfile.mkdtemp()
        code = ("import sys,time; sys.path.insert(0, %r); from sigilnet import torlink as T; "
                "n = T.TorNode(%r, offline=True); n.add_service('a', T.make_client_key()[1]); n.start(wait=True, timeout=60); "
                "print(n.proc.pid, flush=True); time.sleep(600)") % (str(Path(__file__).resolve().parents[2]), root)
        child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        tor_pid = int(child.stdout.readline())
        self.assertTrue(self._alive(tor_pid))
        child.kill()                                                                                  # kill -9
        child.wait()
        end = time.time() + 10
        while time.time() < end and self._alive(tor_pid):
            time.sleep(0.2)
        self.assertFalse(self._alive(tor_pid), "tor survived the death of the node that started it")
        n = T.TorNode(root, offline=True)
        n.start(wait=True, timeout=60)                                                                # the data directory is free again
        try:
            self.assertTrue(n.running())
            self.assertTrue(n.service_address("a"))
        finally:
            n.stop()

    def test_a_stale_tor_of_ours_is_stopped_on_start_but_nothing_else_is_touched(self):
        import subprocess
        root = tempfile.mkdtemp()
        n = T.TorNode(root, offline=True)
        n.add_service("a", T.make_client_key()[1])
        n.services = n._load_services()
        T._write_private(n.torrc, n.config())
        stale = subprocess.Popen(["tor", "-f", str(n.torrc)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        end = time.time() + 30
        while time.time() < end and not n.pidfile.exists():
            time.sleep(0.2)
        self.assertTrue(self._alive(stale.pid))
        n2 = T.TorNode(root, offline=True)                                                            # a NEW node object, as after a restart
        n2.start(wait=True, timeout=60)
        try:
            stale.wait(timeout=10)                                                                   # the stale one is gone (and reaped by us here)
            self.assertTrue(n2.running())
            self.assertTrue(n2.service_address("a"))
        finally:
            n2.stop()
        # a pid file that points at an unrelated process is never signalled
        bystander = subprocess.Popen(["sleep", "60"])
        try:
            n3 = T.TorNode(tempfile.mkdtemp(), offline=True)
            n3.pidfile.write_text(f"{bystander.pid}\n")
            self.assertFalse(n3.stop_stale())
            self.assertTrue(self._alive(bystander.pid))
        finally:
            bystander.kill()
            bystander.wait()

    def test_node_run_shows_its_progress_immediately_even_into_a_file(self):
        import subprocess
        import sys
        root = str(Path(__file__).resolve().parents[2])
        home = Path(tempfile.mkdtemp())
        base = [sys.executable, "-m", "sigilnet", "--home", str(home)]
        subprocess.run([*base, "id", "init", "me"], capture_output=True, cwd=root, timeout=180)
        subprocess.run([*base, "node", "init", "--service-port-base", "47461"], capture_output=True, cwd=root, timeout=180)
        subprocess.run([*base, "node", "authorize", "p", T.make_client_key()[1]], capture_output=True, cwd=root, timeout=180)
        log = home / "node.out"
        with open(log, "w") as f:
            proc = subprocess.Popen([*base, "node", "run", "--offline", "--seconds", "40"], stdout=f, stderr=subprocess.STDOUT, cwd=root)
        try:
            end = time.time() + 90
            while time.time() < end and "serving sync" not in log.read_text():
                time.sleep(0.3)
            self.assertIn("door for p:", log.read_text())                                               # visible while the node is still running
            self.assertIn("serving sync", log.read_text())
            self.assertIsNone(proc.poll())
        finally:
            proc.send_signal(2)
            proc.wait(timeout=120)

    def test_the_node_uses_the_short_request_budget(self):
        from sigilnet import noderun
        seen = {}

        class Stub:
            def __init__(self, m, me, peers, state, transport_for, **kw):
                seen["tf"] = transport_for
                raise ValueError("stop here")
        home = Path(tempfile.mkdtemp())
        old = noderun.Node
        noderun.Node = Stub
        try:
            from sigilnet.keys import Identity
            with self.assertRaises(ValueError):
                noderun.run(home, Identity.generate("me"), offline=True, seconds=1, out=lambda *a: None)
        finally:
            noderun.Node = old
        tr = seen["tf"]({"endpoint": {"type": "onion", "addr": "a" * 56 + ".onion:47200"}})
        self.assertEqual((tr.timeout, tr.connect_timeout), (noderun.REQUEST_TIMEOUT, noderun.CONNECT_TIMEOUT))
        self.assertLessEqual(noderun.REQUEST_TIMEOUT, 20.0)


class Round11(unittest.TestCase):
    def test_a_second_node_on_the_same_home_refuses_and_leaves_the_first_one_alone(self):
        # Sansa round 10, PoC: stop_stale could not tell a stale tor from a LIVE node's tor, so a second `node run` silently took the first one down
        import subprocess
        import sys
        from sigilnet import noderun
        root = str(Path(__file__).resolve().parents[2])
        home = Path(tempfile.mkdtemp())
        base = [sys.executable, "-u", "-m", "sigilnet", "--home", str(home)]
        subprocess.run([*base, "id", "init", "me"], capture_output=True, cwd=root, timeout=120)
        subprocess.run([*base, "node", "init", "--service-port-base", "47481"], capture_output=True, cwd=root, timeout=120)
        subprocess.run([*base, "node", "authorize", "p", T.make_client_key()[1]], capture_output=True, cwd=root, timeout=120)
        log = home / "a.out"
        with open(log, "w") as f:
            first = subprocess.Popen([*base, "node", "run", "--offline", "--seconds", "60"], stdout=f, stderr=subprocess.STDOUT, cwd=root)
        try:
            end = time.time() + 90
            while time.time() < end and "serving sync" not in log.read_text():
                time.sleep(0.3)
            self.assertIn("serving sync", log.read_text())
            pid = int((home / "tor" / "tor.pid").read_text())
            second = subprocess.run([*base, "node", "run", "--offline", "--seconds", "5"], capture_output=True, text=True, cwd=root, timeout=120)
            self.assertEqual(second.returncode, 1)
            self.assertIn("another node is already running", second.stdout + second.stderr)
            time.sleep(1)
            self.assertIsNone(first.poll())                                                            # the first node is still up ...
            self.assertEqual(os.kill(pid, 0), None)                                                    # ... and so is ITS tor
            self.assertEqual(int((home / "tor" / "tor.pid").read_text()), pid)
        finally:
            first.send_signal(2)
            first.wait(timeout=120)
        self.assertEqual(subprocess.run([*base, "node", "run", "--offline", "--seconds", "3"], capture_output=True, text=True, cwd=root, timeout=120).returncode, 0)   # lock released

    def test_the_instance_lock_is_exclusive_and_nonblocking(self):
        from sigilnet import noderun
        home = Path(tempfile.mkdtemp())
        fd = noderun._instance_lock(home)
        self.assertIsNotNone(fd)
        self.assertIsNone(noderun._instance_lock(home))
        os.close(fd)
        fd2 = noderun._instance_lock(home)
        self.assertIsNotNone(fd2)
        os.close(fd2)
        said = []
        fd3 = noderun._instance_lock(home)
        from sigilnet.keys import Identity
        self.assertEqual(noderun.run(home, Identity.generate("me"), offline=True, seconds=1, out=said.append), 1)
        self.assertIn("already running", said[0])
        os.close(fd3)

    def test_tor_must_be_started_from_the_main_thread_and_the_child_checks_its_parent(self):
        import subprocess
        import sys
        n = T.TorNode(tempfile.mkdtemp(), offline=True)
        err = []

        def go():
            try:
                n.start(wait=False)
            except RuntimeError as e:
                err.append(str(e))
        th = threading.Thread(target=go)
        th.start()
        th.join()
        self.assertEqual(len(err), 1)
        self.assertIn("main thread", err[0])
        self.assertFalse(n.running())
        self.assertIsNotNone(T._LIBC)                                                                   # loaded before any fork
        root = str(Path(__file__).resolve().parents[2])
        code = "import sys, os; sys.path.insert(0, %r); from sigilnet import torlink as T; T._die_with_parent(%s); print('alive')"
        ok = subprocess.run([sys.executable, "-c", code % (root, "os.getppid()")], capture_output=True, text=True, timeout=30)
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "alive"))                                # the real parent: carries on
        gone = subprocess.run([sys.executable, "-c", code % (root, "1234567")], capture_output=True, text=True, timeout=30)
        self.assertEqual((gone.returncode, gone.stdout.strip()), (1, ""))                                 # the parent "died" before prctl: exit at once

    def test_connecting_has_its_own_longer_budget_than_the_exchange(self):
        # Sansa round 10: a cold rendezvous to a fresh onion service needs 20-60 s; one 20 s budget for everything would tear every attempt down
        w = World()
        srv = tcp.TcpServer("127.0.0.1", 0, None, S.SyncServer(mirror_with(w.genesis, [])).handle).start()
        self.addCleanup(srv.stop)
        slow = FakeSocks(forward_to=srv.port, delay=1.6)                                                 # the rendezvous takes 1.6 s
        self.addCleanup(slow.close)
        req = lambda: S.sign_request(w.ids["sansa"], {"t": "summary", "thread": w.t.id})
        with self.assertRaises(Exception):
            T.TorTransport(ONION, 47200, ("127.0.0.1", slow.port), timeout=1.0).request(req())           # one 1 s budget: torn down
        r = T.TorTransport(ONION, 47200, ("127.0.0.1", slow.port), timeout=1.0, connect_timeout=5.0).request(req())
        self.assertEqual(r["t"], "summary")                                                               # separate budgets: connects, then 1 s is plenty
        stalled = FakeSocks(stall=True)
        self.addCleanup(stalled.close)
        t0 = time.time()
        with self.assertRaises(T.TorError):
            T.TorTransport(ONION, 47200, ("127.0.0.1", stalled.port), timeout=1.0, connect_timeout=2.0).request(req())
        self.assertLess(time.time() - t0, 4.5)                                                            # bounded by the connect budget
        hang = tcp.TcpServer("127.0.0.1", 0, None, lambda r: time.sleep(3) or {"t": "ok"}).start()        # connected, but the answer never comes
        self.addCleanup(hang.stop)
        fast = FakeSocks(forward_to=hang.port)
        self.addCleanup(fast.close)
        t0 = time.time()
        with self.assertRaises(Exception):
            T.TorTransport(ONION, 47200, ("127.0.0.1", fast.port), timeout=1.0, connect_timeout=30.0).request(req())
        self.assertLess(time.time() - t0, 3.0)                                                            # the EXCHANGE budget still applies once connected
        self.assertEqual(T.TorTransport(ONION, 47200, ("127.0.0.1", fast.port)).connect_timeout, None)    # default: unchanged single budget

    def test_the_node_gives_connecting_a_longer_budget_than_the_exchange(self):
        from sigilnet import noderun
        self.assertGreater(noderun.CONNECT_TIMEOUT, noderun.REQUEST_TIMEOUT)
        self.assertGreaterEqual(noderun.CONNECT_TIMEOUT, 45.0)


class PerPeerServices(unittest.TestCase):
    def test_ports_are_allocated_per_peer_and_the_config_has_one_service_each(self):
        n = T.TorNode(tempfile.mkdtemp(), offline=True)
        pub = T.make_client_key()[1]
        ports = [n.add_service(f"p{i}", pub) for i in range(5)]
        self.assertEqual(ports, list(range(T.SERVICE_BASE, T.SERVICE_BASE + 5)))
        self.assertEqual(n.add_service("p2", pub), ports[2])                                               # re-authorizing keeps the door (and its port)
        cfg = n.config()
        self.assertEqual(cfg.count("HiddenServiceDir"), 5)
        for p in ports:
            self.assertIn(f"HiddenServicePort 47200 127.0.0.1:{p}", cfg)
        self.assertEqual(cfg.count("HiddenServicePoWDefensesEnabled 1"), 5)
        n.remove_service("p1")
        self.assertEqual(n.add_service("new", pub), ports[1])                                              # a freed port is reused
        self.assertNotIn("/services/p1", n.config())
        self.assertEqual(n.services["p2"]["agent"], None)
        n.add_service("p2", pub, agent="c" * 32)
        self.assertEqual(T.TorNode(n.root, offline=True).services["p2"]["agent"], "c" * 32)                # persisted; a new process sees it

    def test_limits_and_hostile_files(self):
        n = T.TorNode(tempfile.mkdtemp(), offline=True)
        pub = T.make_client_key()[1]
        for i in range(T.MAX_SERVICES):
            n.add_service(f"p{i}", pub)
        with self.assertRaises(ValueError):
            n.add_service("one-too-many", pub)
        for bad in ("../x", "", "A", "a/b", "a" * 33):
            with self.assertRaises(ValueError, msg=bad):
                n.add_service(bad, pub)
            with self.assertRaises(ValueError, msg=bad):
                n.remove_service(bad)
        (n.root / "services.json").write_text(json.dumps({"ok": {"port": 47500, "agent": None}, "../evil": {"port": 1}, "b": {"port": "x"}, "c": {"port": 70000},
                                                          "d": {"port": 47501, "agent": "nope"}, "e": 5, "f": {"port": True}}))
        self.assertEqual(list(T.TorNode(n.root, offline=True).services), ["ok"])                             # anything odd is ignored, never a torrc line
        (n.root / "services.json").write_text("{not json")
        self.assertEqual(T.TorNode(n.root, offline=True).services, {})

    def test_remove_deletes_the_door_and_never_follows_a_symlink(self):
        n = T.TorNode(tempfile.mkdtemp(), offline=True)
        pub = T.make_client_key()[1]
        n.add_service("a", pub)
        victim = Path(tempfile.mkdtemp())
        (victim / "keep.txt").write_text("keep")
        (n.svc_dir / "b").symlink_to(victim)
        n.services["b"] = {"port": 47999, "agent": None}
        n._save_services()
        self.assertTrue(n.remove_service("a"))
        self.assertFalse((n.svc_dir / "a").exists())
        n.remove_service("b")
        self.assertTrue((victim / "keep.txt").exists())

    def test_real_tor_serves_distinct_addresses_picks_up_a_new_door_on_sighup_and_keeps_identities(self):
        root = tempfile.mkdtemp()
        n = T.TorNode(root, offline=True)
        pub = T.make_client_key()[1]
        n.add_service("a", pub)
        n.add_service("b", pub)
        n.start(wait=False)
        try:
            end = time.time() + 40
            while time.time() < end and not (n.service_address("a") and n.service_address("b")):
                time.sleep(0.3)
            a, b = n.service_address("a"), n.service_address("b")
            self.assertTrue(a and b and a != b)
            n.add_service("c", pub)
            self.assertTrue(n.reconfigure())                                                              # new torrc + SIGHUP to the running tor
            end = time.time() + 40
            while time.time() < end and not n.service_address("c"):
                time.sleep(0.3)
            self.assertTrue(n.service_address("c"))
            self.assertTrue(n.running())
            self.assertEqual((n.service_address("a"), n.service_address("b")), (a, b))                    # the others keep their addresses
            n.remove_service("b")
            self.assertTrue(n.reconfigure())
            self.assertNotIn("/services/b", n.config())
            self.assertFalse(n.reconfigure())                                                            # nothing changed: nothing rewritten, no signal
        finally:
            n.stop()
        n2 = T.TorNode(root, offline=True)
        n2.start(wait=False)
        try:
            end = time.time() + 40
            while time.time() < end and not n2.service_address("a"):
                time.sleep(0.3)
            self.assertEqual(n2.service_address("a"), a)                                                  # identity survives a restart
        finally:
            n2.stop()

    def test_replacing_a_doors_client_key_or_agent_reaches_a_running_tor(self):
        # Sansa round 9, PoC: add_service(peer1, key1); reconfigure() -> True; add_service(peer1, key2); reconfigure() used to stay False (no SIGHUP)
        n = T.TorNode(tempfile.mkdtemp(), offline=True)
        signals = []
        n.reload = lambda: signals.append(1) or True
        k1, k2 = T.make_client_key()[1], T.make_client_key()[1]
        n.add_service("peer1", k1)
        self.assertTrue(n.reconfigure())
        self.assertFalse(n.reconfigure())
        n.add_service("peer1", k2)                                                                        # a leaked key is replaced
        self.assertTrue(n.reconfigure())
        self.assertEqual(len(signals), 2)
        self.assertIn(k2, (n.svc_dir / "peer1" / "authorized_clients" / "client.auth").read_text())
        self.assertFalse(n.reconfigure())
        n.add_service("peer1", k2, agent="d" * 32)                                                         # re-bound to an agent
        self.assertTrue(n.reconfigure())
        self.assertFalse(n.reconfigure())

    def test_rebinding_a_door_takes_effect_without_a_restart_and_one_bad_port_does_not_stop_the_others(self):
        from sigilnet import noderun
        w = World()
        real = mirror_with(w.genesis, [])
        srv = S.SyncServer(real, identity=w.ids["arya"])
        base = T._free_port()
        n = T.TorNode(tempfile.mkdtemp(), offline=True, service_port_base=base)
        log = []
        doors = noderun.Doors(n, srv, log.append)
        self.addCleanup(doors.stop)
        pub = T.make_client_key()[1]
        n.add_service("a", pub, agent=w.ids["sansa"].id)
        n.add_service("b", pub)
        doors.sync()
        ask = lambda port, who: tcp.TcpTransport("127.0.0.1", port, None, timeout=5).request(S.sign_request(who, {"t": "summary", "thread": w.t.id}, aud=w.ids["arya"].id))["t"]
        pa, pb = n.services["a"]["port"], n.services["b"]["port"]
        self.assertEqual((ask(pa, w.ids["sansa"]), ask(pa, w.ids["carol"])), ("summary", "unknown"))
        n.add_service("a", pub, agent=w.ids["carol"].id)                                                   # re-bound to carol while the node runs
        doors.sync()
        self.assertEqual((ask(pa, w.ids["sansa"]), ask(pa, w.ids["carol"])), ("unknown", "summary"))
        n.add_service("b", pub, agent=w.ids["sansa"].id)                                                   # an unbound door gets bound
        doors.sync()
        self.assertEqual((ask(pb, w.ids["sansa"]), ask(pb, w.ids["carol"])), ("summary", "unknown"))
        # a door whose local port is taken by another process: reported once, the others keep working, retried until it opens
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        n.add_service("c", pub)
        c = n.services["c"]["port"]
        n.services["c"]["port"] = blocker.getsockname()[1]
        n._save_services()
        doors.sync()
        doors.sync()
        self.assertEqual(len([m for m in log if "door for c" in m]), 1)
        self.assertEqual(ask(pb, w.ids["sansa"]), "summary")
        self.assertNotIn("c", doors.servers)
        blocker.close()
        doors.sync()
        self.assertIn("c", doors.servers)                                                                 # the port is free now: the door opens by itself

    def test_concurrent_door_edits_lose_nothing(self):
        n = T.TorNode(tempfile.mkdtemp(), offline=True)
        pub = T.make_client_key()[1]
        errs = []

        def work(names):
            for nm in names:
                try:
                    T.TorNode(n.root, offline=True).add_service(nm, pub)                                   # separate handles, like separate CLI processes
                except Exception as e:                                                                     # noqa: BLE001
                    errs.append(repr(e))
        names = [f"p{i}" for i in range(30)]
        ts = [threading.Thread(target=work, args=(names[i::3],)) for i in range(3)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        got = T.TorNode(n.root, offline=True).services
        self.assertEqual(sorted(got), sorted(names))
        self.assertEqual(len({v["port"] for v in got.values()}), 30)                                     # and every door has its own port

    def test_flooding_one_peers_door_does_not_touch_another_peers_door(self):
        from sigilnet import noderun
        w = World()
        real = mirror_with(w.genesis, [])
        srv = S.SyncServer(real, identity=w.ids["arya"])
        door_a = tcp.TcpServer("127.0.0.1", 0, None, noderun.service_handler(srv, w.ids["sansa"].id)).start()
        door_b = tcp.TcpServer("127.0.0.1", 0, None, noderun.service_handler(srv, w.ids["carol"].id)).start()
        self.addCleanup(door_a.stop)
        self.addCleanup(door_b.stop)
        held = [socket.create_connection(("127.0.0.1", door_a.port)) for _ in range(tcp.PLAIN_CONNS)]     # the hostile peer fills ITS door
        try:
            time.sleep(0.3)
            req = S.sign_request(w.ids["carol"], {"t": "summary", "thread": w.t.id}, aud=w.ids["arya"].id)
            resp = tcp.TcpTransport("127.0.0.1", door_b.port, None, timeout=5).request(req)            # carol's door is unaffected
            self.assertEqual(resp["t"], "summary")
            self.assertTrue(S.response_signed_by(resp, w.ids["arya"].id))
            with self.assertRaises(Exception):                                                          # while the flooded door is full (for everybody, as designed)
                tcp.TcpTransport("127.0.0.1", door_a.port, None, timeout=2).request(S.sign_request(w.ids["sansa"], {"t": "summary", "thread": w.t.id}))
        finally:
            for h in held:
                h.close()

    def test_a_door_answers_only_the_agent_it_is_bound_to(self):
        from sigilnet import noderun
        w = World()
        real = mirror_with(w.genesis, [])
        srv = S.SyncServer(real, identity=w.ids["arya"])
        handle = noderun.service_handler(srv, w.ids["sansa"].id)
        body = {"t": "summary", "thread": w.t.id}
        ok = handle(S.sign_request(w.ids["sansa"], body, aud=w.ids["arya"].id))
        self.assertEqual(ok["t"], "summary")
        other = handle(S.sign_request(w.ids["carol"], body, aud=w.ids["arya"].id))                     # carol is a member of the thread, but this is sansa's door
        stranger = srv.handle(S.sign_request(Identity.generate("eve"), body, aud=w.ids["arya"].id))
        strip = lambda r: {k: v for k, v in r.items() if k not in ("nonce", "rsig")}
        self.assertEqual(strip(other), strip(stranger))                                                 # exactly what a stranger gets: nothing to learn
        for junk in (None, 5, [], "x", {"from": ["a"]}):
            self.assertEqual(strip(handle(junk)).get("t"), "unknown")
        unbound = noderun.service_handler(srv, None)
        self.assertEqual(unbound(S.sign_request(w.ids["carol"], body, aud=w.ids["arya"].id))["t"], "summary")


if __name__ == "__main__":
    unittest.main()
