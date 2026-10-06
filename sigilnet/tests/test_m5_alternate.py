"""M5 (DESIGN_multicarrier.md): the alternating tor/tcp test, with REAL Tor (throwaway homes, throwaway hidden services, deleted afterwards). Two nodes, both running tcp + tor:
node A runs in THIS process (the main thread: tor is forked from it), node B as a subprocess (`sigilnet start`). One thread, messages posted by A and B in turn. Before each message the harness
makes ONE carrier of A unavailable the way a real outage does (the carrier is stopped; the node's CarrierSet sees it down; the other side's dials to it fail): tor-only phases and tcp-only phases
alternate, every second message. Asserts: every message arrives exactly once and in order on both sides, `verify` is clean on both, in a tor phase the traffic went over tor and in a tcp phase over tcp
(the locator books' good-contact times of the carrier that had to carry it advance), and a thread is never tied to a carrier.

Slow (several minutes, needs the Tor network): runs only with SIGIL_M5=1 (`SIGIL_M5=1 python -m unittest sigilnet.tests.test_m5_alternate`)."""
import json
import os
import random
import re
import shutil
import signal
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import carrierset as CS
from sigilnet import cli, daemon, noderun
from sigilnet.tests.test_locator_cli import run_cli

MESSAGES = 8                    # four tor-only, four tcp-only
DELIVER_TIMEOUT = 240.0         # a message over a tor circuit that has to be rebuilt after a restart of tor


@unittest.skipUnless(os.environ.get("SIGIL_M5") == "1", "slow real-Tor test: SIGIL_M5=1")
class AlternatingTorTcp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.h = {"a": self.tmp / "a", "b": self.tmp / "b"}
        self.ip = {"a": "127.0.0.2", "b": "127.0.0.3"}
        self.addCleanup(self.reap)
        self.addCleanup(self.save_logs)                                    # (registered after the rmtree: runs before it)
        base = {n: cli._free_range(random.randint(20000, 55000), 128, ["127.0.0.1", "127.0.0.2", "127.0.0.3"]) for n in "ab"}
        for n in "ab":
            rc, out, err = run_cli("--home", str(self.h[n]), "init", "m5" + n, "--carrier", "tcp", "--bind", self.ip[n], "--tcp-port-base", str(base[n]))
            self.assertEqual(rc, 0, err)
            cfgp = self.h[n] / "node_config.json"
            cfg = json.loads(cfgp.read_text())
            cfg["carrier"], cfg["carriers"] = "tcp", ["tcp", "tor"]
            cfg["service_port_base"] = cli._free_range(random.randint(20000, 55000), 64, ["127.0.0.1"])
            cfgp.write_text(json.dumps(cfg))
        self.id = {n: json.loads(self.cli(n, "id", "show", "--json")[1])["agent"] for n in "ab"}
        (self.tmp / "b.pub").write_text(self.cli("b", "id", "show", "--json")[1])
        rc, out, err = self.cli("a", "new", "m5 alternating", "--member", f"member={self.tmp / 'b.pub'}")
        self.assertEqual(rc, 0, err)
        self.tid = re.search(r"thread ([0-9a-f]{32})", out).group(1)
        for me, other in (("a", "b"), ("b", "a")):                     # the tcp peering, by hand
            rc, out, err = self.cli(other, "node", "auth", "tkey" + me)
            self.assertEqual(rc, 0, err)
            pub = out.strip().splitlines()[-1].strip()
            rc, out, err = self.cli(me, "node", "authorize", other, pub, "--agent", self.id[other])
            self.assertEqual(rc, 0, err)
            rc, out, err = self.cli(me, "node", "address", other)
            addr = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+#[0-9a-f]{64})", out).group(1)
            rc, out, err = self.cli(other, "peer", "add", me, self.id[me], "--endpoint", "tcp:" + addr, "--key", "tkey" + me, "--thread", self.tid)
            self.assertEqual(rc, 0, err)

    def cli(self, n, *args):
        return run_cli("--home", str(self.h[n]), *args)

    def save_logs(self):
        dest = Path("/tmp/m5_logs")
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        for n in "ab":
            for rel in ("history.log", "node.err", "node.status.json", "peers.json", "locators/tcp.json", "locators/onion.json", "tor/tor.log", "node.json"):
                src = self.h[n] / ".sigilnet" / rel if (self.h[n] / ".sigilnet").exists() else self.h[n] / rel
                try:
                    shutil.copy(src, dest / f"{n}_{rel.replace('/', '_')}")
                except OSError:
                    pass

    def reap(self):
        for n in "ab":
            rec = daemon.read_pid(self.h[n])
            if rec and daemon.alive(rec["pid"]):
                try:
                    os.kill(rec["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def texts(self, n):
        out = self.cli(n, "show", self.tid)[1]
        return re.findall(r"m5-msg-(\d+)", out)

    def contact(self, n, ctype):
        """The newest good-contact time (our good dial or the peer reaching us) of the other node over carrier `ctype`, from n's locator book."""
        p = self.h[n] / "locators" / f"{ctype}.json"
        try:
            rec = json.loads(p.read_text())["peers"].get(self.id["b" if n == "a" else "a"], {})
        except (OSError, ValueError):
            return 0.0
        times = [l.get("ok") or 0.0 for l in rec.get("locs", [])] + [rec.get("in_at") or 0.0]
        return max(times)

    def test_the_thread_alternates_between_tor_and_tcp_every_second_message(self):
        holder = {}
        real_set = CS.CarrierSet

        class Capture(real_set):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                holder["cset"] = self

        real_doors = noderun.Doors
        holder["doors"] = {}

        class CaptureDoors(real_doors):
            def __init__(self, tor, *a, **k):
                super().__init__(tor, *a, **k)
                holder["doors"][tor.type] = self

        problems, log = [], []

        def say(s):
            log.append(f"{time.strftime('%H:%M:%S')} {s}")

        def scenario():
            try:
                self._scenario(holder, problems, say)
            except BaseException as e:                                  # noqa: BLE001
                problems.append(f"scenario crashed: {type(e).__name__}: {e}")
            finally:
                os.kill(os.getpid(), signal.SIGTERM)                       # ends noderun.run in the main thread (its handler raises KeyboardInterrupt)

        lines = []
        with mock.patch.object(noderun, "CarrierSet", Capture), mock.patch.object(noderun, "Doors", CaptureDoors), mock.patch.object(CS, "BACKOFF", (3600.0, 3600.0, 3600.0)), mock.patch.object(CS, "SLOW", 3600.0):
            self.assertEqual(self.start("b"), 0)
            t = threading.Thread(target=scenario)
            t.start()
            rc = noderun.run(self.h["a"], __import__("sigilnet.keys", fromlist=["Identity"]).Identity.load(self.h["a"] / "identity.json"), seconds=3000, offline=False, out=lines.append)
            t.join(30)
        self.assertEqual(problems, [], "\n".join(log[-60:]))
        self.assertEqual(rc, 0)

    def start(self, n):
        return daemon.start(self.h[n], wait=90, out=lambda s: None)

    # ------------------------------------------------------------------------------------------------------------------ the scenario (runs in a helper thread)
    def _wait(self, what, check, timeout, say=lambda s: None):
        end = time.time() + timeout
        while time.time() < end:
            v = check()
            if v:
                return v
            time.sleep(1.0)
        raise AssertionError(f"timed out waiting for {what}")

    def _outage(self, cs, holder, ctype):
        """Carrier `ctype` of A becomes unavailable, the way an outage looks from outside. tcp: the carrier is stopped (listeners closed; the other side is refused at once). tor: the node stops serving its
        onion doors (the loopback listeners close, the hidden service stays published, so the other side's streams are closed at once; killing tor itself would make the service unreachable for minutes
        after a restart: that is what the RunDegraded test covers)."""
        run = cs.runs[ctype]
        if run.state != "up":
            return
        if ctype == "tcp":
            run.carrier.stop()
            self._wait("A's tcp carrier seen down", lambda: run.state == "down", 60)
        else:
            run.next_try = time.monotonic() + 3600
            run.state, run.reason = "down", "M5: outage"
            cs._publish()
            holder["doors"]["onion"].stop()

    def _restore(self, cs, holder, ctype):
        run = cs.runs[ctype]
        if run.state == "up":
            return
        if ctype == "tcp":
            run.next_try = 0
            self._wait("A's tcp carrier up again", lambda: run.state == "up", 60)
        else:
            run.state, run.reason = "up", ""
            cs._publish()                                                  # the loop's next tick re-creates the onion door listeners
            self._wait("A's onion door served again", lambda: holder["doors"]["onion"].servers, 60)

    def _scenario(self, holder, problems, say):
        cs = self._wait("A's carrier set", lambda: holder.get("cset"), 60)
        self._wait("both of A's carriers up", lambda: sorted(cs.up_types()) == ["onion", "tcp"], 180)
        self._wait("both of B's carriers up", lambda: sorted(json.loads((self.h["b"] / "node.status.json").read_text()).get("carriers_up", [])) == ["onion", "tcp"] if (self.h["b"] / "node.status.json").exists() else False, 180)
        say("both nodes run tcp+tor")
        # the tor doors, both ways (the Sansa howto steps 2-5)
        for me, other in (("a", "b"), ("b", "a")):
            rc, out, err = self.cli(other, "node", "auth", "okey" + me, "--carrier", "tor")
            assert rc == 0, err
            pub = out.strip().splitlines()[-1].strip()
            rc, out, err = self.cli(me, "node", "authorize", other + "-tor", pub, "--agent", self.id[other], "--carrier", "tor")
            assert rc == 0, err
        addr = {}
        for n in "ab":
            def have(n=n):
                rc, out, err = self.cli(n, "node", "address", "--carrier", "tor")
                m = re.search(r"([a-z2-7]{56}\.onion:\d+)", out)
                return m.group(1) if m else None
            addr[n] = self._wait(f"{n}'s onion address", have, 180)
        say(f"onion addresses: a={addr['a'][:12]}.. b={addr['b'][:12]}..")
        for me, other in (("a", "b"), ("b", "a")):
            rc, out, err = self.cli(other, "peer", "add", me, self.id[me], "--endpoint", "onion:" + addr[me], "--key", "okey" + me, "--thread", self.tid)
            assert rc == 0, err
        # alternate: odd messages tor only (A's tcp carrier down), even messages tcp only (A's tor carrier down)
        sent = []
        for i in range(1, MESSAGES + 1):
            tor_phase = i % 2 == 1
            down, up = ("tcp", "onion") if tor_phase else ("onion", "tcp")
            self._restore(cs, holder, up)
            self._outage(cs, holder, down)
            say(f"message {i}: {'tor' if tor_phase else 'tcp'} phase, A's {down} carrier is down")
            t0 = time.time()
            poster, reader = ("a", "b") if i % 2 == 1 else ("b", "a")
            rc, out, err = self.cli(poster, "post", self.tid, f"m5-msg-{i:02d}")
            assert rc == 0, err
            self._wait(f"message {i} to arrive at {reader}", lambda: f"{i:02d}" in self.texts(reader), DELIVER_TIMEOUT)
            say(f"message {i} {poster}->{reader} delivered in {time.time() - t0:.1f} s")
            carrier_that_had_to_carry = "onion" if tor_phase else "tcp"
            moved = max(self.contact(reader, carrier_that_had_to_carry), self.contact(poster, carrier_that_had_to_carry))
            if moved < t0:
                problems.append(f"message {i}: no good contact over {carrier_that_had_to_carry} after {t0}: the traffic did not use it")
            sent.append(i)
        # every message exactly once, in order, on both sides
        for n in "ab":
            got = self._wait(f"all {MESSAGES} messages at {n}", lambda n=n: len(set(self.texts(n))) == MESSAGES and self.texts(n), 240)
            got = self.texts(n)
            if got != [f"{i:02d}" for i in sent]:
                problems.append(f"{n} holds {got}, expected {[f'{i:02d}' for i in sent]}")
        for n in "ab":
            rc, out, err = self.cli(n, "verify", self.tid)
            if rc != 0 or "replay cleanly" not in out + err:
                problems.append(f"verify on {n}: rc={rc} {out[-200:]}{err[-200:]}")
        say("done")


if __name__ == "__main__":
    unittest.main()
