"""M1c (DESIGN_multicarrier.md rev 7): a node that runs SEVERAL carriers DEGRADES instead of exiting. CarrierSet is the non-blocking state machine (up / starting / stopping / down, backoff as
timestamps); a down carrier is left out of the MultiDialer's order; NoCarrierUp is "nothing to try", not a failure of the peer; TorNode is safe to ask from several threads, does not signal a tor that
is still starting, and stops without blocking; TcpCarrier re-resolves `bind: auto` on a restart; the status says which carrier is down."""
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import carrierset as CS
from sigilnet import daemon
from sigilnet import locators as L
from sigilnet import noderun
from sigilnet import tcplink as TL
from sigilnet import torlink as TLK
from sigilnet.carrier import Carrier, CarrierError, NoCarrierUp
from sigilnet.keys import Identity
from sigilnet.tests.multirig import Rig2
from sigilnet.tests.test_m1b import Clock, StubDialer, oaddr, taddr
from sigilnet.tests.test_tcplink import free_base


class Flaky(Carrier):
    """A carrier whose start, readiness and health the test controls."""
    capabilities = frozenset()

    def __init__(self, ctype="onion"):
        self.type = ctype
        self.up = False
        self.start_error = None            # raised by begin_start
        self.ready_after = 0               # begin_start counts down; poll_ready says "ready" at 0 (while < 0 "starting")
        self.fail_with = None              # poll_ready says failed
        self.alive = False
        self.calls = []
        self.proc_alive_until_reaped = 0   # number of reaped() calls that say "not yet"
        self.reason = "it died"
        self._left = 0

    def start(self, wait=True): self.begin_start()
    def stop(self): self.calls.append("stop"); self.alive = False
    def healthy(self): return self.alive
    def reconfigure(self): return False
    def dial(self, *a, **k): raise CarrierError("no")
    def new_credential(self): raise NotImplementedError
    def use_credential(self, *a, **k): pass
    def drop_credential(self, *a, **k): return False
    def open_door(self, *a, **k): return 1
    def close_door(self, name): return False
    def door_endpoint(self, name): return None
    def doors(self): return {}
    def door_gone(self, name): return True

    def begin_start(self, *, stale=True):
        self.calls.append(f"begin_start(stale={stale})")
        if self.start_error is not None:
            raise self.start_error
        self.alive = True
        self._left = self.ready_after

    def poll_ready(self):
        if self.fail_with is not None:
            return ("failed", self.fail_with)
        if self._left > 0:
            self._left -= 1
            return ("starting", "")
        return ("ready", "")

    def stop_nowait(self):
        self.calls.append("stop_nowait")
        self._stopping = self.proc_alive_until_reaped

    def reaped(self, kill_after=10.0):
        n = getattr(self, "_stopping", 0)
        if n > 0:
            self._stopping = n - 1
            return False
        self.alive = False
        return True

    def down_reason(self):
        return self.reason


class Raising(Flaky):
    """A broken carrier: any call can raise anything."""
    def __init__(self, ctype="onion", **raises):
        super().__init__(ctype)
        self.raises = raises

    def _maybe(self, name):
        if name in self.raises:
            raise self.raises[name]

    def healthy(self):
        self._maybe("healthy")
        return super().healthy()

    def poll_ready(self):
        self._maybe("poll_ready")
        return super().poll_ready()

    def stop_nowait(self):
        self._maybe("stop_nowait")
        super().stop_nowait()

    def reaped(self, kill_after=10.0):
        self._maybe("reaped")
        return super().reaped(kill_after)

    def down_reason(self):
        self._maybe("down_reason")
        return super().down_reason()

    def begin_start(self, *, stale=True):
        self._maybe("begin_start")
        super().begin_start(stale=stale)


class BrokenCarrier(unittest.TestCase):
    """Sansa B2: in degrade mode a carrier that raises where it should not is down with the exception as its reason; the node (tick) never raises, the others never notice."""

    def setUp(self):
        self.clk = Clock(1000.0)

    def make(self, **raises):
        tcp, tor = Flaky("tcp"), Raising("onion", **raises)
        cs = CS.CarrierSet({"tcp": tcp, "onion": tor}, clock=self.clk)
        cs.start_all(order=["tcp", "onion"])
        return cs, tcp, tor

    def test_healthy_raising_makes_the_carrier_down_and_the_other_serves(self):
        cs, tcp, tor = self.make(healthy=RuntimeError("boom in healthy"))
        ev = cs.tick()
        self.assertEqual({t: r.state for t, r in cs.runs.items()}["tcp"], "up")
        self.assertEqual(cs.runs["onion"].state, "down")
        self.assertIn("RuntimeError: boom in healthy", cs.runs["onion"].reason)
        self.assertTrue(any("down (RuntimeError: boom in healthy)" in e for e in ev), ev)
        self.assertIn("stop_nowait", tor.calls, "a broken carrier is asked to stop (best effort)")

    def test_poll_ready_stop_nowait_reaped_and_down_reason_raising_are_all_just_down(self):
        for name, exc in (("poll_ready", AttributeError("no attr")), ("reaped", KeyError("k")), ("down_reason", ValueError("v")), ("stop_nowait", OSError("o"))):
            with self.subTest(call=name):
                tcp, tor = Flaky("tcp"), Raising("onion", **{name: exc})
                cs = CS.CarrierSet({"tcp": tcp, "onion": tor}, clock=self.clk)
                tor.ready_after = 1 if name == "poll_ready" else 0
                if name == "poll_ready":
                    cs.start_all(order=["tcp", "onion"])
                else:
                    cs.start_all(order=["tcp", "onion"])
                    tor.alive = False
                for _ in range(3):
                    cs.tick()                                              # never raises
                    self.clk.t += 1
                self.assertEqual(cs.runs["tcp"].state, "up")
                self.assertEqual(cs.runs["onion"].state, "down", (name, cs.runs["onion"].state, cs.runs["onion"].reason))
                self.assertTrue(cs.runs["onion"].reason)

    def test_begin_start_raising_anything_is_a_failed_start(self):
        for exc in (KeyError("k"), AttributeError("a"), ZeroDivisionError("z"), RuntimeError("r")):
            cs, tcp, tor = None, Flaky("tcp"), Raising("onion", begin_start=exc)
            cs = CS.CarrierSet({"tcp": tcp, "onion": tor}, clock=self.clk)
            cs.start_all(order=["tcp", "onion"])
            self.assertEqual((cs.runs["tcp"].state, cs.runs["onion"].state), ("up", "down"))
            self.assertIn("cannot start", cs.runs["onion"].reason)

    def test_the_broken_carrier_is_retried_on_the_schedule_and_comes_back_when_it_works(self):
        cs, tcp, tor = self.make(healthy=RuntimeError("x"))
        cs.tick()
        self.assertEqual(cs.runs["onion"].state, "down")
        del tor.raises["healthy"]
        self.clk.t = cs.runs["onion"].next_try
        cs.tick()
        self.assertEqual(cs.runs["onion"].state, "up")


class BlobWorkerWithADownCarrier(unittest.TestCase):
    """Sansa B1: a peer none of whose carriers is up is skipped; the others still serve the blob."""

    def make(self, down_peers, up_peers):
        from sigilnet import blobworker as BW
        from sigilnet.blobwant import Wants
        tid = "1" * 32
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        plan = {}
        for p in down_peers + up_peers:
            plan[p] = {"rec": {"agent": p}, "threads": {tid}}
        node = mock.Mock()
        node._plan.return_value = plan
        node.m = mock.Mock()

        def transport_for(rec):
            if rec["agent"] in down_peers:
                raise NoCarrierUp("no carrier is up that holds an address of this peer")
            return mock.Mock(name="tr-" + rec["agent"])
        node.transport_for = transport_for
        store = mock.Mock()
        store.has.return_value = False
        wants = mock.Mock()
        seen = {}

        def fetch(m, store, index, tid, cid, sources, me, **kw):
            seen["sources"] = [s.peer_id if hasattr(s, "peer_id") else s for s in sources]
            return {"ok": True, "why": "", "requests": 1, "bytes": 1}
        lines = []
        bw = BW.BlobWorker(node, store, mock.Mock(), wants, Identity.generate("me"), lines.append, fetch=fetch)
        return bw, wants, seen, lines, tid

    def test_a_down_peer_does_not_abort_the_fetch_from_the_others(self):
        a, b, c = (Identity.generate(n).id for n in "abc")
        bw, wants, seen, lines, tid = self.make([a], [b, c])
        bw._one(tid, "sha256:" + "0" * 64)
        self.assertEqual(len(seen["sources"]), 2, seen)
        wants.finish.assert_called_once()
        self.assertTrue(wants.finish.call_args[0][1])
        self.assertTrue(any("1 peer(s) skipped" in l for l in lines), lines)

    def test_when_no_source_is_left_the_want_fails_with_no_carrier_up(self):
        a = Identity.generate("a").id
        bw, wants, seen, lines, tid = self.make([a], [])
        bw._one(tid, "sha256:" + "0" * 64)
        self.assertNotIn("sources", seen)
        args = wants.finish.call_args[0]
        self.assertFalse(args[1])
        self.assertIn("no carrier up", args[2])


class StateMachine(unittest.TestCase):
    def setUp(self):
        self.clk = Clock(1000.0)
        self.tcp, self.tor = Flaky("tcp"), Flaky("onion")
        self.cs = CS.CarrierSet({"tcp": self.tcp, "onion": self.tor}, clock=self.clk, bootstrap_deadline=100.0)

    def states(self):
        return {t: r.state for t, r in self.cs.runs.items()}

    def test_both_start_and_come_up(self):
        ev = self.cs.start_all(order=["tcp", "onion"])
        self.assertEqual(self.states(), {"tcp": "up", "onion": "up"})
        self.assertEqual(ev, ["carrier tcp: up", "carrier onion: up"])
        self.assertTrue(self.cs.usable("tcp") and self.cs.usable("onion"))

    def test_a_carrier_that_is_still_bootstrapping_is_starting_and_does_not_block(self):
        self.tor.ready_after = 3
        self.cs.start_all(order=["tcp", "onion"])
        self.assertEqual(self.states(), {"tcp": "up", "onion": "starting"})
        self.assertFalse(self.cs.usable("onion"))
        self.assertTrue(self.cs.any_up() and self.cs.any_alive())
        for _ in range(3):
            self.clk.t += 1
            self.cs.tick()
        self.assertEqual(self.states()["onion"], "up")
        self.assertEqual(self.cs.changed, {"onion": ("starting", "up")})

    def test_a_carrier_that_cannot_start_is_down_and_retried_after_5_30_120_then_every_600_seconds_for_ever(self):
        self.tor.start_error = OSError("tor: not found")
        self.cs.start_all(order=["tcp", "onion"])
        self.assertEqual(self.states(), {"tcp": "up", "onion": "down"})
        self.assertIn("cannot start", self.cs.runs["onion"].reason)
        waits = []
        for _ in range(8):
            r = self.cs.runs["onion"]
            waits.append(round(r.next_try - self.clk.t))
            self.clk.t = r.next_try - 1
            self.cs.tick()
            self.assertEqual(self.states()["onion"], "down", "not before the time")
            self.clk.t += 1
            self.cs.tick()
        self.assertEqual(waits, [5, 30, 120, 600, 600, 600, 600, 600], waits)
        self.assertEqual(self.states()["tcp"], "up", "the other carrier never noticed")

    def test_the_slow_retries_end_when_the_restarts_leave_the_window_and_a_working_start_resets_nothing_it_must_not(self):
        self.tor.start_error = OSError("x")
        self.cs.start_all(order=["tcp", "onion"])
        for _ in range(4):
            self.clk.t = self.cs.runs["onion"].next_try
            self.cs.tick()
        self.assertEqual(round(self.cs.runs["onion"].next_try - self.clk.t), 600)
        self.clk.t += CS.WINDOW + 1
        self.tor.start_error = None
        self.cs.tick()
        self.cs.tick()
        self.assertEqual(self.states()["onion"], "up")

    def test_after_the_window_a_new_failure_starts_again_at_5_seconds(self):
        self.cs.start_all(order=["tcp", "onion"])
        for _ in range(4):
            self.tor.alive = False
            self.cs.tick()
            self.clk.t = self.cs.runs["onion"].next_try
            self.cs.tick()
        self.assertEqual(round(self.cs.runs["onion"].next_try - self.clk.t) if self.cs.runs["onion"].state == "down" else 600, 600)
        self.clk.t += CS.WINDOW + 10
        self.tor.alive = False
        self.cs.tick()
        r = self.cs.runs["onion"]
        self.assertEqual((r.state, round(r.next_try - self.clk.t)), ("down", 5), "the old restarts left the window")

    def test_a_carrier_that_dies_is_seen_reaped_and_restarted_while_the_other_serves(self):
        self.cs.start_all(order=["tcp", "onion"])
        self.tor.alive = False
        self.tor.reason = "tor exited: Bootstrapped 50%"
        ev = self.cs.tick()
        self.assertEqual(self.states(), {"tcp": "up", "onion": "down"})
        self.assertTrue(any("lost (tor exited: Bootstrapped 50%)" in e for e in ev) and any("down (tor exited" in e and "retry in 5 s" in e for e in ev), ev)
        self.assertEqual(self.cs.changed, {"onion": ("up", "down")})
        self.assertTrue(self.cs.usable("tcp") and not self.cs.usable("onion"))
        self.clk.t += 5
        self.cs.tick()
        self.assertEqual(self.states()["onion"], "up")
        self.assertIn("begin_start(stale=False)", self.tor.calls, "a restart skips the stale-tor cleanup (it takes seconds)")

    def test_stopping_waits_for_the_process_to_leave_over_later_ticks(self):
        self.cs.start_all(order=["tcp", "onion"])
        self.tor.alive = False
        self.tor.proc_alive_until_reaped = 3
        self.cs.tick()
        self.assertEqual(self.states()["onion"], "stopping")
        self.cs.tick()
        self.cs.tick()
        self.assertEqual(self.states()["onion"], "stopping")
        self.cs.tick()
        self.assertEqual(self.states()["onion"], "down")

    def test_a_start_that_never_becomes_ready_is_stopped_after_the_deadline(self):
        self.tor.ready_after = 10 ** 9
        self.cs.start_all(order=["tcp", "onion"])
        self.clk.t += 99
        self.cs.tick()
        self.assertEqual(self.states()["onion"], "starting")
        self.clk.t += 2
        ev = self.cs.tick()
        self.assertEqual(self.states()["onion"], "down")
        self.assertTrue(any("did not become ready within 100 s" in e for e in ev), ev)

    def test_a_start_that_fails_is_down_with_the_reason(self):
        self.tor.fail_with = "tor exited: Could not bind"
        ev = self.cs.start_all(order=["tcp", "onion"])
        self.assertEqual(self.states(), {"tcp": "up", "onion": "stopping"})
        self.cs.tick()
        self.assertEqual(self.states()["onion"], "down")
        self.assertIn("Could not bind", self.cs.runs["onion"].reason)

    def test_flapping_three_times_in_the_window_starts_the_slow_retry_and_the_other_carrier_never_pauses(self):
        self.cs.start_all(order=["tcp", "onion"])
        for i in range(4):
            self.tor.alive = False
            self.cs.tick()
            self.assertEqual(self.states()["tcp"], "up")
            r = self.cs.runs["onion"]
            if i < 3:
                self.assertEqual(round(r.next_try - self.clk.t), CS.BACKOFF[i])
            else:
                self.assertEqual(round(r.next_try - self.clk.t), 600)
            self.clk.t = r.next_try
            self.cs.tick()
            self.assertEqual(self.states()["onion"], "up")

    def test_status_for_the_status_file(self):
        self.tor.start_error = OSError("nope")
        self.cs.start_all(order=["tcp", "onion"])
        st = self.cs.status()
        self.assertEqual(st["tcp"], {"state": "up", "reason": "", "retry_in": None})
        self.assertEqual((st["onion"]["state"], st["onion"]["retry_in"]), ("down", 5))
        self.assertIn("nope", st["onion"]["reason"])

    def test_the_stale_tor_cleanup_runs_once_at_the_first_start_and_never_in_a_restart(self):
        calls = []
        self.tor.stop_stale = lambda: calls.append(1)
        self.cs.start_all(order=["tcp", "onion"])
        self.assertEqual(calls, [1])
        for _ in range(3):
            self.tor.alive = False
            self.cs.tick()
            self.clk.t = self.cs.runs["onion"].next_try
            self.cs.tick()
        self.assertEqual(calls, [1], "a restart never waits for a stale tor")

    def test_both_down_at_start_means_nothing_is_alive(self):
        self.tcp.start_error = OSError("address in use")
        self.tor.start_error = OSError("tor: not found")
        self.cs.start_all(order=["tcp", "onion"])
        self.assertFalse(self.cs.any_alive())
        reasons = self.cs.reasons()
        self.assertIn("address in use", reasons)
        self.assertIn("tor: not found", reasons)

    def test_none_up_for_too_long_ends_the_node_but_a_start_in_progress_does_not(self):
        self.tcp.start_error = OSError("x")
        self.tor.start_error = OSError("y")
        self.cs.start_all(order=["tcp", "onion"])
        self.cs.tick()
        self.assertFalse(self.cs.none_up_too_long())
        self.clk.t += CS.NONE_UP_EXIT + 1
        self.assertTrue(self.cs.none_up_too_long())
        tor2 = Flaky("onion")
        tor2.ready_after = 10 ** 9
        cs = CS.CarrierSet({"onion": tor2}, clock=self.clk)
        cs.start_all()
        cs.tick()
        self.clk.t += CS.NONE_UP_EXIT + 1
        cs.tick()
        self.assertFalse(cs.none_up_too_long(), "still starting")

    def test_a_tcp_restart_re_resolves_the_bind_address(self):
        self.tcp.refresh_bind = mock.Mock()
        self.cs.start_all(order=["tcp", "onion"])
        self.tcp.alive = False
        self.cs.tick()
        self.clk.t += 5
        self.cs.tick()
        self.tcp.refresh_bind.assert_called_once()

    def test_a_refused_new_address_keeps_the_carrier_down_with_the_reason(self):
        self.tcp.refresh_bind = mock.Mock(side_effect=ValueError("bind \"auto\": no private address"))
        self.cs.start_all(order=["tcp", "onion"])
        self.tcp.alive = False
        self.cs.tick()
        self.clk.t += 5
        self.cs.tick()
        self.assertEqual(self.states()["tcp"], "down")
        self.assertIn("no private address", self.cs.runs["tcp"].reason)

    def test_the_snapshot_other_threads_read_is_never_a_half_written_state(self):
        self.cs.start_all(order=["tcp", "onion"])
        stop = threading.Event()
        seen = set()

        def reader():
            while not stop.is_set():
                seen.add((self.cs.usable("tcp"), self.cs.usable("onion"), tuple(sorted(self.cs.up_types()))))
        ts = [threading.Thread(target=reader) for _ in range(4)]
        [t.start() for t in ts]
        for _ in range(200):
            self.tor.alive = False
            self.cs.tick()
            self.clk.t = self.cs.runs["onion"].next_try
            self.cs.tick()
        stop.set()
        [t.join() for t in ts]
        for tcp_up, onion_up, ups in seen:
            self.assertEqual(ups, tuple(sorted(t for t, u in (("tcp", tcp_up), ("onion", onion_up)) if u)) or ups)


# ---------------------------------------------------------------------------------------------------------------- the dialer and the node
class DownCarrier(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.clk = Clock()
        self.agent = Identity.generate("p").id
        self.tb = L.open_book(self.d, "tcp", clock=self.clk)
        self.ob = L.open_book(self.d, "onion", clock=self.clk)
        self.tb.seed(self.agent, taddr(1))
        self.ob.seed(self.agent, oaddr(1))
        self.t, self.o = StubDialer("tcp", self.tb, self.clk), StubDialer("onion", self.ob, self.clk)
        self.up = {"tcp": True, "onion": True}
        self.md = L.MultiDialer({"tcp": self.t, "onion": self.o}, clock=self.clk, usable=lambda c: self.up[c])
        self.rec = {"agent": self.agent, "endpoints": [{"type": "tcp", "addr": taddr(1)}, {"type": "onion", "addr": oaddr(1)}]}

    def test_a_down_carrier_is_left_out_of_the_order_and_comes_back_when_up(self):
        self.up["onion"] = False
        self.assertEqual(self.md._order(self.rec), ["tcp"])
        self.up["onion"] = True
        self.assertEqual(self.md._order(self.rec), ["tcp", "onion"])

    def test_a_down_carrier_is_never_probed_ahead_of_the_one_that_is_up(self):
        self.t.fail = CarrierError("blip", retry=True)
        self.md(self.rec).request({"t": "x"})
        self.up["tcp"] = False
        self.clk.t += L.CARRIER_RETRY + 1
        self.assertEqual(self.md._order(self.rec), ["onion"])
        self.assertEqual(self.md._probed.get((self.agent, "tcp")), 1000.0)

    def test_nothing_usable_raises_NoCarrierUp_not_the_dead_carriers_own_error(self):
        self.up.update(tcp=False, onion=False)
        with self.assertRaises(NoCarrierUp) as cm:
            self.md(self.rec)
        self.assertTrue(cm.exception.retry)
        self.assertIsInstance(cm.exception, CarrierError)
        self.assertEqual((self.t.lefts, self.o.lefts), ([], []), "nothing was dialed")

    def test_a_peer_whose_only_address_is_on_the_down_carrier_gets_NoCarrierUp(self):
        self.tb.remove(self.agent)
        self.up["onion"] = False
        with self.assertRaises(NoCarrierUp):
            self.md({"agent": self.agent, "endpoints": [{"type": "onion", "addr": oaddr(1)}]})

    def test_a_peer_with_no_address_at_all_still_gets_the_old_error(self):
        self.tb.remove(self.agent)
        self.ob.remove(self.agent)
        self.up.update(tcp=False, onion=False)
        self.md({"agent": self.agent, "endpoints": []})                     # (the first dialer's own "no address" error, as before: not NoCarrierUp)
        self.assertEqual(self.t.lefts, [None])

    def test_a_node_with_one_carrier_never_gets_NoCarrierUp(self):
        solo = L.MultiDialer({"tcp": self.t}, usable=lambda c: False)
        self.assertIsInstance(solo(self.rec), object)


class DoorsOfADownCarrier(unittest.TestCase):
    def test_the_loopback_listeners_close_with_the_carrier_and_come_back_on_the_same_ports_with_a_request_in_flight(self):
        """Sansa (a): a restart while a request is in flight on the down carrier's door; the re-bind at ready finds the ports free."""
        import socket
        from sigilnet.doors import Doors
        from sigilnet.mirror import Mirror
        from sigilnet.sync import SyncServer
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        me = Identity.generate("me")
        peer = Identity.generate("p")
        c = TL.TcpCarrier(d / "tcp", bind="127.0.0.2", port_base=free_base())
        c.start()
        sec, pub = c.new_credential()
        c.open_door("peer-p", "peer", credential=pub, agent=peer.id)
        lines = []
        doors = Doors(c, SyncServer(Mirror(d / "m"), identity=me), lines.append)
        doors.sync()
        ports = {n: svc["port"] for n, svc in c.doors().items()}
        self.assertEqual(len(doors.servers), 1)
        conn = socket.create_connection(("127.0.0.1", ports["peer-p"]), timeout=3)
        conn.sendall(b"\x00\x00")                                  # a request half sent: in flight
        t0 = time.time()
        doors.stop()
        c.stop_nowait()
        self.assertTrue(c.reaped())
        self.assertLess(time.time() - t0, 10.0, "stopping never waits for the request")
        conn.close()
        c.begin_start(stale=False)
        doors.sync()
        self.assertEqual({n: svc["port"] for n, svc in c.doors().items()}, ports)
        self.assertEqual(len(doors.servers), 1)
        self.assertFalse([l for l in lines if "cannot open" in l], lines)
        with socket.create_connection(("127.0.0.1", ports["peer-p"]), timeout=3):
            pass
        doors.stop()
        c.stop()


class NodeWithDownCarrier(unittest.TestCase):
    def setUp(self):
        self.r = Rig2()
        self.addCleanup(self.r.close)
        self.a, self.b = self.r.sides["a"], self.r.sides["b"]
        self.aid = self.r.ids["a"].id
        self.up = {"fake": True, "fakeb": True}
        self.b.dialer.usable = lambda c: self.up[c]

    def test_pulls_go_on_over_the_carrier_that_is_up_and_the_peer_is_never_down(self):
        self.up["fakeb"] = False
        self.r.post("a", "while fakeb is down")
        self.r.tick("b")
        self.assertIn("while fakeb is down", self.r.texts("b"))
        self.assertNotIn(self.aid, self.b.node.down)
        self.up["fakeb"] = True
        self.r.post("a", "after")
        self.b.dialer._skip.clear()
        self.r.tick("b")
        self.assertIn("after", self.r.texts("b"))

    def test_when_the_only_carrier_that_knows_the_peer_is_down_the_job_waits_without_a_failure(self):
        for ep in ("fake",):
            self.b.books[ep].remove(self.aid)
        rec = self.b.peers.all()[self.aid]
        self.b.peers.add(self.aid, "a", {"type": "fakeb", "addr": self.a.carriers["fakeb"].door_endpoint("peer-b")["addr"]}, [])
        raw = json.loads((self.b.home / "peers.json").read_text())
        raw["peers"][self.aid]["endpoints"] = [e for e in raw["peers"][self.aid]["endpoints"] if e["type"] == "fakeb"]
        (self.b.home / "peers.json").write_text(json.dumps(raw))
        self.up["fakeb"] = False
        self.r.post("a", "x")
        self.r.tick("b", rounds=2)
        self.assertNotIn(self.aid, self.b.node.down, "no carrier up is not the peer being unreachable")
        jobs = [j for k, j in self.b.node.jobs.items() if k.startswith(self.aid + "/") and k.endswith("/pull")]
        self.assertTrue(jobs and all(j["tries"] == 0 for j in jobs), jobs)
        self.assertIn("no carrier", jobs[0]["err"])
        self.assertGreater(jobs[0]["next"], self.b.node.clock())
        self.up["fakeb"] = True
        for j in self.b.node.jobs.values():
            j["next"] = 0
        self.r.tick("b")
        self.assertIn("x", self.r.texts("b"))

    def test_a_flapping_carrier_never_pauses_the_pulls_on_the_other(self):
        """Sansa (f): count what arrives per round across an outage that flaps."""
        got = []
        for i in range(24):
            self.up["fakeb"] = (i % 6) >= 3                                  # down 3 rounds, up 3, down 3, ...
            if not self.up["fakeb"]:
                self.r.blackhole("a", "fakeb")
            else:
                self.r.blackhole("a", "fakeb", False)
            self.b.dialer._skip.clear()
            self.r.post("a", f"m{i}")
            self.r.tick("b", rounds=2)
            got.append(f"m{i}" in self.r.texts("b"))
        self.assertEqual(got, [True] * 24, got)
        self.assertNotIn(self.aid, self.b.node.down)

    def test_a_ping_with_no_carrier_up_answers_at_once(self):
        from sigilnet import ping as P
        self.up.update(fake=False, fakeb=False)
        svc = P.PingService(self.b.node, self.b.home, self.b.dialer)
        svc.dir.mkdir(parents=True, exist_ok=True)
        (svc.dir / "abc.req").write_text("{}")
        t0 = time.time()
        svc._run("abc", {"peer": self.aid, "deadline": self.b.node.clock() + 10}, self.b.peers.all()[self.aid])
        res = json.loads((svc.dir / "abc.res").read_text())
        self.assertEqual((res["ok"], res["why"]), (False, "no carrier up"))
        self.assertLess(time.time() - t0, 2.0)


# ---------------------------------------------------------------------------------------------------------------- TorNode
class FakeProc:
    def __init__(self):
        self.rc = None
        self.pid = 4242
        self.terminated = self.killed = 0

    def poll(self):
        return self.rc

    def terminate(self):
        self.terminated += 1

    def kill(self):
        self.killed += 1
        self.rc = -9

    def wait(self, t=None):
        self.waits = getattr(self, "waits", 0) + 1
        return self.rc


class TorNodeSafety(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tn = TLK.TorNode(self.d / "tor", offline=False, service_port_base=free_base())

    def test_running_and_pid_read_the_process_once_while_stop_races(self):
        """Sansa C2: stop() set self.proc to None between the two reads of running()."""
        errors = []
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                try:
                    self.tn.running()
                    self.tn._running_pid()
                    self.tn.reload()
                except Exception as e:                                       # noqa: BLE001
                    errors.append(repr(e))
        ts = [threading.Thread(target=hammer) for _ in range(8)]
        [t.start() for t in ts]
        for _ in range(3000):
            self.tn.proc = FakeProc()
            self.tn.proc.rc = 0
            self.tn.stop()
        stop.set()
        [t.join() for t in ts]
        self.assertEqual(errors, [])

    def test_running_reads_the_process_attribute_exactly_once(self):
        """Deterministic form of the race: the attribute is the process the first time it is read and None the second time."""
        reads = []

        class Flicker(TLK.TorNode):
            @property
            def proc(self):
                reads.append(1)
                return FakeProc() if len(reads) % 2 == 1 else None

            @proc.setter
            def proc(self, v):
                pass
        tn = Flicker(self.d / "flick", service_port_base=free_base())
        reads.clear()
        self.assertTrue(tn.running())
        self.assertEqual(len(reads), 1)
        reads.clear()
        self.assertEqual(tn._running_pid(), 4242)

    def test_a_tor_that_is_still_starting_is_not_sent_sighup(self):
        """Sansa C3: before its handlers exist the default action of SIGHUP kills tor."""
        self.tn.proc = FakeProc()
        (self.d / "tor").mkdir(exist_ok=True)
        handled = [False]
        with mock.patch("os.kill") as kill, mock.patch.object(TLK.TorNode, "_handles_sighup", side_effect=lambda pid: handled[0]):
            self.assertFalse(self.tn.reload())
            kill.assert_not_called()
            self.assertTrue(self.tn._reload_due, "a refused reload is remembered for the node's next reconfigure()")
            handled[0] = True
            self.assertTrue(self.tn.reload())
            kill.assert_called_once_with(4242, signal.SIGHUP)

    def test_handles_sighup_reads_the_caught_signal_mask_of_the_process(self):
        self.assertTrue(TLK.TorNode._handles_sighup(os.getpid()) in (True, False))
        p = subprocess.Popen(["python3", "-c", "import time; time.sleep(30)"])
        try:
            time.sleep(0.3)
            self.assertFalse(TLK.TorNode._handles_sighup(p.pid), "a process with the default action")
        finally:
            p.kill()
            p.wait()
        p = subprocess.Popen(["python3", "-c", "import signal,time; signal.signal(signal.SIGHUP, lambda *a: None); print('ready', flush=True); time.sleep(30)"], stdout=subprocess.PIPE, text=True)
        try:
            p.stdout.readline()
            self.assertTrue(TLK.TorNode._handles_sighup(p.pid), "a process that installed a handler")
        finally:
            p.kill()
            p.wait()
        self.assertFalse(TLK.TorNode._handles_sighup(2 ** 22 + 12345), "no such process")

    def test_offline_tor_is_ready_when_its_onion_addresses_exist(self):
        tn = TLK.TorNode(self.d / "tor2", offline=True, local_port=free_base(), service_port_base=free_base())
        tn.proc = FakeProc()
        self.assertEqual(tn.poll_ready(), ("starting", ""))
        (tn.hs).mkdir(parents=True, exist_ok=True)
        (tn.hs / "hostname").write_text("a" * 56 + ".onion\n")
        self.assertEqual(tn.poll_ready()[0], "ready")

    def test_a_change_made_while_tor_starts_is_reloaded_once_tor_is_ready(self):
        tn = self.tn
        tn.proc = FakeProc()
        tn._applied = {"old": 1}
        tn.torrc.parent.mkdir(parents=True, exist_ok=True)
        handled = [False]
        with mock.patch("os.kill") as kill, mock.patch.object(TLK.TorNode, "_handles_sighup", side_effect=lambda pid: handled[0]):
            self.assertTrue(tn.reconfigure())
            kill.assert_not_called()
            self.assertTrue(tn._reload_due)
            self.assertFalse(tn.reconfigure())
            kill.assert_not_called()
            handled[0] = True
            self.assertFalse(tn.reconfigure())
            kill.assert_called_once()
            self.assertFalse(tn._reload_due)

    def test_poll_ready_reports_the_exit_reason_from_the_log_at_that_moment(self):
        self.tn.proc = FakeProc()
        self.tn.log.write_text("something broke: Could not bind to 127.0.0.1:9050\n")
        self.tn.proc.rc = 1
        state, why = self.tn.poll_ready()
        self.assertEqual(state, "failed")
        self.assertIn("Could not bind", why)
        self.assertIn("Could not bind", self.tn.down_reason())

    def test_the_reason_leads_with_how_the_process_ended(self):
        """Sansa B5: the log tail is start-up notices; the exit status is the cause."""
        p = self.tn.proc = FakeProc()
        self.tn.log.write_text("Oct 05 notice: Tor 0.4.9.11 running on Linux\n")
        p.rc = -9
        state, why = self.tn.poll_ready()
        self.assertEqual(state, "failed")
        self.assertTrue(why.startswith("tor exited (killed by signal 9 SIGKILL): "), why)
        self.assertTrue(self.tn.down_reason().startswith("tor exited (killed by signal 9 SIGKILL): "))
        p.rc = 1
        self.assertTrue(self.tn.down_reason().startswith("tor exited (exit status 1): "))
        p.rc = -250
        self.assertIn("signal 250", self.tn.down_reason())
        self.assertIn("running on Linux", self.tn.down_reason())

    def test_stop_nowait_terminates_at_once_and_reaped_kills_after_the_wait(self):
        p = self.tn.proc = FakeProc()
        self.tn.stop_nowait()
        self.assertEqual(p.terminated, 1)
        self.assertEqual(getattr(p, "waits", 0), 0, "stop_nowait never waits for the process")
        self.assertFalse(self.tn.reaped(kill_after=3600))
        self.assertEqual(p.killed, 0)
        self.assertFalse(self.tn.reaped(kill_after=0.0))
        self.assertEqual(p.killed, 1)
        self.assertTrue(self.tn.reaped())
        self.assertIsNone(self.tn.proc)

    def test_a_process_that_already_exited_is_reaped_at_once(self):
        p = self.tn.proc = FakeProc()
        p.rc = 1
        self.tn.stop_nowait()
        self.assertEqual(p.terminated, 0)
        self.assertTrue(self.tn.reaped())

    def test_start_without_stale_does_not_wait_for_a_stale_tor(self):
        with mock.patch.object(self.tn, "stop_stale") as stale, mock.patch("subprocess.Popen") as popen:
            popen.return_value = FakeProc()
            with mock.patch.object(threading, "current_thread", return_value=threading.main_thread()):
                self.tn.start(wait=False, stale=False)
            stale.assert_not_called()
            self.tn.proc = None
            with mock.patch.object(threading, "current_thread", return_value=threading.main_thread()):
                self.tn.start(wait=False)
            stale.assert_called_once()

    def test_a_reload_racing_the_start_window_never_kills_tor(self):
        """Sansa C3 (b): a reload() from another thread all through tor's start, repeated. Her run used 20 loops; the suite uses 8 to keep its time."""
        old_hup = signal.signal(signal.SIGHUP, signal.SIG_DFL)           # (a runner under nohup ignores SIGHUP and its children inherit that: then nothing could die and the test would prove nothing)
        self.addCleanup(signal.signal, signal.SIGHUP, old_hup)
        for i in range(8):
            tn = TLK.TorNode(self.d / f"race{i}", offline=True, local_port=free_base(), service_port_base=free_base())
            stop = threading.Event()
            sent = []

            def hammer():
                while not stop.is_set():
                    sent.append(tn.reload())
                    time.sleep(0.005)
            h = threading.Thread(target=hammer)
            tn.begin_start(stale=False)
            h.start()
            try:
                end = time.time() + 40
                while time.time() < end and tn.poll_ready()[0] == "starting":
                    time.sleep(0.05)
                self.assertEqual(tn.poll_ready()[0], "ready", f"round {i}: " + tn.down_reason())
                time.sleep(0.3)
                self.assertTrue(tn.running(), f"round {i}: tor died (a SIGHUP before its handlers exist kills it)")
            finally:
                stop.set()
                h.join()
                tn.stop()
            self.assertIn(True, sent, "the reloads only started to be delivered once tor was ready")

    def test_a_popen_failure_is_an_oserror_the_carrier_set_turns_into_down(self):
        with mock.patch("subprocess.Popen", side_effect=FileNotFoundError("tor")):
            with mock.patch.object(threading, "current_thread", return_value=threading.main_thread()):
                with self.assertRaises(OSError):
                    self.tn.begin_start(stale=False)
        cs = CS.CarrierSet({"tcp": Flaky("tcp"), "onion": self.tn})
        with mock.patch("subprocess.Popen", side_effect=FileNotFoundError("tor")):
            with mock.patch.object(threading, "current_thread", return_value=threading.main_thread()):
                cs.start_all(order=["tcp", "onion"])
        self.assertEqual(cs.runs["onion"].state, "down")
        self.assertIn("cannot start", cs.runs["onion"].reason)

    def test_start_off_the_main_thread_is_a_down_not_a_crash(self):
        cs = CS.CarrierSet({"tcp": Flaky("tcp"), "onion": self.tn})
        res = {}

        def go():
            cs.start_all(order=["tcp", "onion"])
            res["state"] = cs.runs["onion"].state
        t = threading.Thread(target=go)
        t.start()
        t.join()
        self.assertEqual(res["state"], "down")


class TcpRestart(unittest.TestCase):
    def test_a_restart_re_resolves_auto_and_follows_the_new_address(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        ips = ["127.0.0.2"]
        c = TL.TcpCarrier(d, bind="127.0.0.2", port_base=free_base(), resolver=lambda: ips[0])
        self.assertEqual((c.bind, c.advertise), ("127.0.0.2", "127.0.0.2"))
        ips[0] = "127.0.0.3"
        c.refresh_bind()
        self.assertEqual((c.bind, c.advertise), ("127.0.0.3", "127.0.0.3"))

    def test_an_advertise_that_was_given_stays(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        c = TL.TcpCarrier(d, bind="127.0.0.2", port_base=free_base(), advertise="127.0.0.4", resolver=lambda: "127.0.0.3")
        c.refresh_bind()
        self.assertEqual((c.bind, c.advertise), ("127.0.0.3", "127.0.0.4"))

    def test_without_a_resolver_nothing_changes_and_a_refused_address_raises(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        c = TL.TcpCarrier(d, bind="127.0.0.2", port_base=free_base())
        c.refresh_bind()
        self.assertEqual(c.bind, "127.0.0.2")
        c2 = TL.TcpCarrier(Path(tempfile.mkdtemp()), bind="127.0.0.2", port_base=free_base(), resolver=lambda: "224.0.0.1")
        with self.assertRaises(ValueError):
            c2.refresh_bind()

    def test_noderun_gives_auto_a_resolver_and_a_fixed_address_none(self):
        h = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, h, True)
        cfg = {"carrier": "tcp", "carriers": ["tcp"], "tcp": {"bind": "127.0.0.2", "port_base": free_base()}}
        self.assertIsNone(noderun.make_carrier(h, cfg, offline=True)._resolver)
        cfg["tcp"]["bind"] = "auto"
        with mock.patch.object(noderun, "resolve_bind", return_value="127.0.0.2"):
            self.assertIsNotNone(noderun.make_carrier(h, cfg, offline=True)._resolver)

    def test_a_tcp_carrier_goes_through_stop_nowait_and_begin_start_and_comes_back(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        c = TL.TcpCarrier(d, bind="127.0.0.2", port_base=free_base())
        c.begin_start()
        self.assertTrue(c.healthy())
        self.assertEqual(c.poll_ready(), ("ready", ""))
        c.stop_nowait()
        self.assertFalse(c.healthy())
        self.assertTrue(c.reaped())
        c.begin_start(stale=False)
        self.assertTrue(c.healthy())
        c.stop()


# ---------------------------------------------------------------------------------------------------------------- status, the CLI and the node
class StatusAndCli(unittest.TestCase):
    def setUp(self):
        self.h = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.h, True)

    def test_the_status_line_names_the_carrier_that_is_down(self):
        (self.h / "node.pid").write_text("{}")
        with mock.patch.object(daemon, "read_pid", return_value={"pid": 1}), mock.patch.object(daemon, "lock_held", return_value=True), mock.patch.object(daemon, "is_our_node", return_value=True):
            daemon.write_status(self.h, started=time.time(), carrier="tcp+onion", ready=True, doors_up=1, doors_total=2, carriers_up=["tcp"], down={"onion": "down: tor exited, retry in 28 s"})
            line = daemon.status_lines(self.h)[0]
            self.assertIn("carrier tcp (onion: down: tor exited, retry in 28 s)", line)
            self.assertIn("doors 1/2", line)
            daemon.write_status(self.h, started=time.time(), carrier="tcp+onion", ready=True, doors_up=3, doors_total=3, carriers_up=["tcp", "onion"], down={})
            self.assertIn("carrier tcp+onion", daemon.status_lines(self.h)[0])
            daemon.write_status(self.h, started=time.time(), carrier="tcp", ready=True, doors_up=2, doors_total=2)
            self.assertIn("carrier tcp,", daemon.status_lines(self.h)[0] + ",")

    def test_the_carrier_label_names_what_is_serving(self):
        """Sansa B5: `sigilnet start` says tcp+onion / tcp (onion down) from carriers_up, like `status`."""
        self.assertEqual(daemon.carrier_label({"carrier": "tcp+onion", "carriers_up": ["tcp", "onion"], "down": {}}), "tcp+onion")
        self.assertEqual(daemon.carrier_label({"carrier": "tcp+onion", "carriers_up": ["tcp"], "down": {"onion": "down: x"}}), "tcp (onion down)")
        self.assertEqual(daemon.carrier_label({"carrier": "tcp"}), "tcp")
        self.assertEqual(daemon.carrier_label({"carrier": "tcp+onion", "carriers_up": [], "down": {"onion": "x"}}), "tcp+onion")
        self.assertEqual(daemon.carrier_label({}), "None")

    def test_a_carrier_that_just_came_up_gets_one_reload(self):
        """Sansa B4: a client key written by a CLI process while tor was starting was refused its SIGHUP there; the node reloads once at "up"."""
        tor = mock.Mock()
        noderun._reload_after_up(tor)
        tor.reload.assert_called_once()
        noderun._reload_after_up(object())                                 # a carrier without reload(): nothing
        bad = mock.Mock()
        bad.reload.side_effect = OSError("x")
        noderun._reload_after_up(bad)                                      # never raises

    def test_node_says_down_reads_the_status_file_and_never_raises(self):
        from sigilnet import cli
        self.assertIsNone(cli._node_says_down(self.h, "onion"))
        daemon.write_status(self.h, started=time.time(), carrier="tcp+onion", ready=True, down={"onion": "down: x"})
        self.assertEqual(cli._node_says_down(self.h, "onion"), "down: x")
        self.assertIsNone(cli._node_says_down(self.h, "tcp"))
        (self.h / "node.status.json").write_text("not json")
        self.assertIsNone(cli._node_says_down(self.h, "onion"))

    def test_capsule_commands_say_the_carrier_is_down_instead_of_waiting(self):
        from sigilnet import cli
        import contextlib, io
        Identity.generate("me").save(self.h / "identity.json")
        self.h.chmod(0o700)
        (self.h / "node_config.json").write_text(json.dumps({"carriers": ["tor", "tcp"], "tcp": {"bind": "127.0.0.1", "port_base": free_base()}, "service_port_base": free_base()}))
        daemon.write_status(self.h, started=time.time(), carrier="onion+tcp", ready=True, carriers_up=["tcp"], down={"onion": "down: tor exited"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                cli.main(["--home", str(self.h), "capsule", "create", "0" * 32])
        self.assertIn("the onion carrier is down", str(cm.exception.code))

    def test_a_carrier_that_is_down_gets_no_locator_service_tick(self):
        a, b = mock.Mock(), mock.Mock()
        noderun._tick_locator_services({"tcp": a, "onion": b}, lambda t: t == "tcp")
        a.tick.assert_called_once()
        b.tick.assert_not_called()
        c = mock.Mock()
        noderun._tick_locator_services({"tcp": c})
        c.tick.assert_called_once()

    def test_the_join_worker_does_nothing_while_no_carrier_is_up(self):
        calls = []
        jw = noderun._JoinWorker(self.h, {"tcp": mock.Mock(), "onion": mock.Mock()}, Identity.generate("me"), mock.Mock(), calls.append, usable=lambda t: False)
        with mock.patch.object(noderun.capsule, "sweep", side_effect=lambda *a, **k: calls.append("sweep")):
            jw.tick()
        self.assertEqual(calls, [])
        self.assertFalse(jw.busy.is_set())


# ---------------------------------------------------------------------------------------------------------------- the node, for real
class RunDegraded(unittest.TestCase):
    """noderun.run with tcp + tor (tor offline): kill the tor process under the running node; the node, its tcp door and `status` go on; tor comes back by itself."""

    def setUp(self):
        self.h = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.h, True)
        self.h.chmod(0o700)
        self.me = Identity.generate("me")
        self.me.save(self.h / "identity.json")

    def _config(self, **extra):
        (self.h / "node_config.json").write_text(json.dumps({"carriers": ["tcp", "tor"], "tcp": {"bind": "127.0.0.1", "port_base": free_base()}, "service_port_base": free_base(), **extra}))

    def _tor_pids(self):
        r = subprocess.run(["pgrep", "-f", f"tor -f {self.h}/tor/torrc"], capture_output=True, text=True)
        return [int(x) for x in r.stdout.split()]

    def _run_in_thread(self, seconds):
        lines, res = [], {}

        def go():
            res["rc"] = noderun.run(self.h, self.me, seconds=seconds, offline=True, out=lines.append)
        t = threading.Thread(target=go)
        t.start()
        return t, lines, res

    def test_a_tor_that_never_starts_leaves_a_node_that_runs_on_tcp(self):
        self._config()
        with mock.patch.object(TLK.TorNode, "begin_start", side_effect=FileNotFoundError("tor: no such file")):
            rc_lines = []
            rc = noderun.run(self.h, self.me, seconds=3, offline=True, out=rc_lines.append)
        self.assertEqual(rc, 0, rc_lines)
        text = "\n".join(rc_lines)
        self.assertIn("carrier tcp: up", text)
        self.assertIn("carrier onion: down (cannot start", text)
        self.assertIn("serving sync on loopback behind", text)
        self.assertIn("on tcp", text)

    def test_ready_means_at_least_one_carrier_is_up(self):
        """Sansa C5: with tcp down and tor still bootstrapping the node is NOT ready; it is when tor is."""
        self._config()
        seen = []
        polls = [0]
        real_poll = TLK.TorNode.poll_ready

        def slow_poll(tn):
            polls[0] += 1
            return ("starting", "") if polls[0] < 3 else real_poll(tn)

        def watcher():
            end = time.time() + 30
            while time.time() < end:
                try:
                    st = json.loads((self.h / "node.status.json").read_text())
                    seen.append((st.get("ready"), tuple(st.get("carriers_up", []))))
                    if st.get("ready"):
                        return
                except (OSError, ValueError):
                    pass
                time.sleep(0.05)
        t = threading.Thread(target=watcher)
        with mock.patch.object(TL.TcpCarrier, "begin_start", side_effect=OSError("address in use")), mock.patch.object(TLK.TorNode, "poll_ready", slow_poll):
            t.start()
            lines = []
            rc = noderun.run(self.h, self.me, seconds=12, offline=True, out=lines.append)
        t.join(5)
        self.assertEqual(rc, 0, "\n".join(lines))
        self.assertIn((False, ()), seen, seen)
        self.assertIn((True, ("onion",)), seen, seen)
        self.assertLess(seen.index((False, ())), seen.index((True, ("onion",))))

    def test_both_carriers_failing_to_start_is_an_error_with_both_reasons(self):
        self._config()
        with mock.patch.object(TLK.TorNode, "begin_start", side_effect=FileNotFoundError("tor: gone")), mock.patch.object(TL.TcpCarrier, "begin_start", side_effect=OSError("address in use")):
            lines = []
            rc = noderun.run(self.h, self.me, seconds=3, offline=True, out=lines.append)
        self.assertEqual(rc, 1)
        text = "\n".join(lines)
        self.assertIn("no carrier could start", text)
        self.assertIn("tor: gone", text)
        self.assertIn("address in use", text)

    def test_the_tor_process_is_killed_under_a_running_node_and_the_node_keeps_going_and_tor_comes_back(self):
        """The node runs in THIS (the main) thread, as `node run` does (tor is forked from it); a helper thread watches the status file and kills the tor process."""
        self._config()
        cfg = noderun.load_config(self.h)
        tor = noderun.carrier_for(self.h, cfg, "onion", offline=True)
        tor.open_door("peer-x", "peer", credential=tor.new_credential()[1], agent=Identity.generate("x").id)      # a door of the tor carrier, so that "its listeners close with it" can be seen
        lines, obs = [], {}

        def status():
            try:
                return json.loads((self.h / "node.status.json").read_text())
            except (OSError, ValueError):
                return {}

        def watcher():
            end = time.time() + 40
            while time.time() < end and sorted(status().get("carriers_up", [])) != ["onion", "tcp"]:
                time.sleep(0.2)
            obs["both_up"] = sorted(status().get("carriers_up", []))
            obs["doors_before"] = (status().get("doors_up"), status().get("doors_total"))
            pids = self._tor_pids()
            obs["pids"] = pids
            for pid in pids:
                os.kill(pid, signal.SIGKILL)
            end = time.time() + 15
            while time.time() < end and not status().get("down", {}).get("onion"):
                time.sleep(0.1)
            time.sleep(0.5)
            st = status()
            obs["degraded"] = st
            time.sleep(2.5)
            obs["later_at"] = status().get("at")
            end = time.time() + 40
            while time.time() < end and sorted(status().get("carriers_up", [])) != ["onion", "tcp"]:
                time.sleep(0.3)
            obs["back"] = sorted(status().get("carriers_up", []))
        t = threading.Thread(target=watcher)
        t.start()
        reloads = []
        real_reload = TLK.TorNode.reload

        def counting_reload(tn):
            reloads.append(time.time())
            return real_reload(tn)
        with mock.patch.object(TLK.TorNode, "reload", counting_reload):
            rc = noderun.run(self.h, self.me, seconds=75, offline=True, out=lines.append)
        t.join(10)
        text = "\n".join(lines)
        self.assertEqual(rc, 0, text)
        self.assertGreaterEqual(len(reloads), 2, "one reload when tor first came up and one after each restart")
        self.assertEqual(obs.get("both_up"), ["onion", "tcp"], text)
        self.assertTrue(obs.get("pids"), "the node should have started tor: " + text)
        deg = obs.get("degraded") or {}
        self.assertTrue(deg.get("down", {}).get("onion"), "status should show onion down: " + text)
        self.assertEqual(deg.get("carriers_up"), ["tcp"])
        before = obs["doors_before"]
        self.assertEqual(before[1], 1, before)
        self.assertEqual(before[0], 1, "the tor door is served while tor is up")
        self.assertEqual((deg.get("doors_up"), deg.get("doors_total")), (0, 1), "a degraded node counts the doors of ALL carriers, and the down one's listener is closed")
        self.assertTrue(deg.get("ready"), "ready = at least one carrier is up")
        self.assertGreater(obs.get("later_at", 0), deg.get("at", 1e18), "the node loop kept running while tor was down")
        self.assertEqual(obs.get("back"), ["onion", "tcp"], "tor should come back by itself after the backoff: " + text)
        self.assertIn("carrier onion: lost (tor exited (killed by signal 9 SIGKILL)", text)
        self.assertEqual(text.count("carrier onion: up"), 2, text)


if __name__ == "__main__":
    unittest.main()
