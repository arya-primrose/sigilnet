"""#4: PingService (the node side of the ping/*.req/.res hand-off), ping_peer + the CLI (the agent side), watch.beat, and the loop wiring on a real tcp node."""
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import ping, wake
from sigilnet import sync as S
from sigilnet.carrier import CarrierError
from sigilnet.keys import Identity
from sigilnet.node import PeerBook
from sigilnet.tests.test_node import Sim
from sigilnet.tests.test_tcplink import free_base
from sigilnet.tests_adv13.test_ping_unit import pong_sim

REPO = str(Path(__file__).resolve().parents[2])
RES_KEYS = {"id", "ok", "why", "pong", "rtt_ms"}
PONG_KEYS = {"t", "up", "unread", "watching", "v"}


def write_req(home, peer, *, deadline=None, rid=None, raw=None, clock=time.time):
    d = Path(home) / "ping"
    d.mkdir(mode=0o700, exist_ok=True)
    rid = rid or os.urandom(8).hex()
    p = d / f"{rid}.req"
    if raw is not None:
        p.write_bytes(raw)
    else:
        p.write_text(json.dumps({"id": rid, "peer": peer, "deadline": clock() + 30 if deadline is None else deadline}))
    os.chmod(p, 0o600)
    return rid, p


def read_res(home, rid):
    try:
        return json.loads((Path(home) / "ping" / f"{rid}.res").read_text())
    except (OSError, ValueError):
        return None


class Svc:
    """A Sim pair where sansa pings arya through a dial function we control."""

    def __init__(self, dial=None):
        self.s = pong_sim(2)
        self.home = self.s.homes["sansa"]
        self.a = self.s.ids["arya"].id
        self.calls = []

        def default(rec):
            return self.s.transport("sansa", rec)

        self.dial = dial or default
        self.svc = ping.PingService(self.s.nodes["sansa"], self.home, lambda rec: self._d(rec), clock=self.s.clock)

    def _d(self, rec):
        self.calls.append(rec)
        return self.dial(rec)

    def tick(self):
        return self.svc.tick()


class ServiceBasics(unittest.TestCase):
    def test_a_request_gets_a_pong_result_with_the_pinned_shape(self):
        t = Svc()
        rid, p = write_req(t.home, t.a, clock=t.s.clock)
        self.assertEqual(t.tick(), 1)
        res = read_res(t.home, rid)
        self.assertEqual(set(res), RES_KEYS)
        self.assertEqual((res["id"], res["ok"], res["why"]), (rid, True, None))
        self.assertEqual(set(res["pong"]), PONG_KEYS)
        self.assertEqual((res["pong"]["t"], res["pong"]["up"], res["pong"]["v"]), ("pong", True, 1))
        self.assertIsInstance(res["rtt_ms"], float)
        self.assertGreaterEqual(res["rtt_ms"], 0.0)
        self.assertEqual(stat.S_IMODE((t.home / "ping" / f"{rid}.res").stat().st_mode), 0o600)

    def test_the_pong_content_is_what_the_peer_computed_for_us(self):
        t = Svc()
        t.s.post("arya", "hi")
        for _ in range(8):
            t.s.step(1.0)
        t.s.clock.t += ping.SNAPSHOT_EVERY + 0.5                              # the pinged side's snapshot expires
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        res = read_res(t.home, rid)
        self.assertTrue(res["ok"], res)
        self.assertGreaterEqual(res["pong"]["unread"], 0)                    # arya's unread of THE shared thread (sansa wrote nothing)
        self.assertIs(res["pong"]["watching"], False)

    def test_the_request_is_dialled_with_the_peer_record_once(self):
        t = Svc()
        write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        self.assertEqual(len(t.calls), 1)
        self.assertEqual(t.calls[0]["endpoint"], t.s.nodes["sansa"].peers.all()[t.a]["endpoint"])

    def test_the_request_sent_is_a_signed_ping(self):
        seen = []

        def dial(rec):
            class T:
                def request(self_, req):
                    seen.append(req)
                    return pong_sim_response(req)
            return T()

        def pong_sim_response(req):
            return {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1}

        t = Svc(dial)
        write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        self.assertEqual(len(seen), 1)
        r = seen[0]
        self.assertEqual((r["t"], r["from"], r["pub"]), ("ping", t.s.ids["sansa"].id, t.s.ids["sansa"].sign_pub))
        self.assertTrue(r["sig"] and r["nonce"] and isinstance(r["ts"], int))
        self.assertNotIn("thread", r)

    def test_two_simultaneous_requests_are_both_answered(self):
        t = Svc()
        with mock.patch.object(ping, "PING_MIN_GAP", 0.0):                    # (one peer, two quick pings: the peer's own 1/s gap is not what is tested here)
            r1, _ = write_req(t.home, t.a, clock=t.s.clock)
            r2, _ = write_req(t.home, t.a, clock=t.s.clock)
            self.assertEqual(t.tick(), 2)
            a, b = read_res(t.home, r1), read_res(t.home, r2)
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        self.assertEqual({a["id"], b["id"]}, {r1, r2})
        self.assertTrue(a["ok"] and b["ok"], (a, b))

    def counting_dial(self, t, advance_on):
        """A dial that hands out ONE transport whose request() calls are counted; request number `advance_on` first moves the peer's clock on."""
        calls = []
        real = t.s.transport

        def dial(rec):
            tr = real("sansa", rec)

            class T:
                def request(self_, req):
                    calls.append(time.time())
                    if len(calls) == advance_on:
                        t.s.clock.t += 2 * ping.PING_MIN_GAP
                    return tr.request(req)
            return T()

        t.dial = dial
        return calls

    def test_a_rate_limited_answer_is_asked_again_once_after_the_gap(self):
        """The peer's own 1/s gap answers 'rate limited' (signed): the node waits PING_MIN_GAP and asks ONCE more, so two quick pings by a human both work."""
        t = Svc()
        t.s.servers["arya"].handle(json.loads(json.dumps(S.sign_request(t.s.ids["sansa"], {"t": "ping"}, ts=int(t.s.clock())))))      # uses up sansa's slot at arya
        calls = self.counting_dial(t, advance_on=2)
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        deadline = time.time() + 5
        while read_res(t.home, rid) is None and time.time() < deadline:
            time.sleep(0.05)
        res = read_res(t.home, rid)
        self.assertEqual(len(calls), 2, "asked again exactly once")
        self.assertGreaterEqual(calls[1] - calls[0], ping.PING_MIN_GAP, "asked again before the gap")
        self.assertTrue(res["ok"], res)

    def test_a_peer_that_keeps_saying_rate_limited_is_asked_only_twice(self):
        t = Svc()
        t.s.servers["arya"].handle(json.loads(json.dumps(S.sign_request(t.s.ids["sansa"], {"t": "ping"}, ts=int(t.s.clock())))))
        calls = self.counting_dial(t, advance_on=99)                           # the peer's clock never moves: always rate limited
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        deadline = time.time() + 6
        while read_res(t.home, rid) is None and time.time() < deadline:
            time.sleep(0.05)
        res = read_res(t.home, rid)
        self.assertEqual(len(calls), 2)
        self.assertFalse(res["ok"])

    def test_nothing_to_do_returns_zero(self):
        t = Svc()
        self.assertEqual(t.tick(), 0)
        (t.home / "ping").mkdir(mode=0o700)
        self.assertEqual(t.tick(), 0)

    def test_the_result_file_is_complete_when_it_appears(self):
        t = Svc()
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        names = sorted(p.name for p in (t.home / "ping").iterdir() if p.name.startswith(rid) or rid in p.name)
        self.assertIn(f"{rid}.res", names)
        self.assertEqual([n for n in names if n.endswith(".tmp")], [], "a temp file was left behind (atomic tmp+rename)")
        json.loads((t.home / "ping" / f"{rid}.res").read_text())

    def test_history_log_gets_one_line_per_ping(self):
        t = Svc()
        write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        lines = (t.home / "history.log").read_text().splitlines()
        hit = [l for l in lines if re.search(r"node  ping arya: pong \d+ ms$", l)]
        self.assertEqual(len(hit), 1, lines)

    def test_a_failed_ping_is_logged_with_its_reason(self):
        def dial(rec):
            raise CarrierError("tcp connect to 1.2.3.4:47602 failed (Connection refused)", retry=True)
        t = Svc(dial)
        write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        self.assertTrue(any(re.search(r"node  ping arya: no answer \(connect refused\)$", l) for l in (t.home / "history.log").read_text().splitlines()))

    def test_the_pong_is_recorded_per_peer_in_node_json(self):
        t = Svc()
        t.s.clock.t = time.time()
        write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        t.s.nodes["sansa"]._save()
        st = json.loads((t.home / "node.json").read_text())

        def find(o):
            if isinstance(o, dict):
                if "last_pong" in o:
                    return o
                for v in o.values():
                    r = find(v)
                    if r:
                        return r
            return None
        rec = find(st)
        self.assertIsNotNone(rec, "no last_pong in node.json")
        self.assertIn("unread", rec)
        self.assertIn("watching", rec)
        self.assertAlmostEqual(rec["last_pong"], t.s.clock(), delta=5)


class FailureReasons(unittest.TestCase):
    def run_with(self, dial):
        t = Svc(dial)
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        return read_res(t.home, rid)

    def check(self, res, why):
        self.assertIsNotNone(res)
        self.assertEqual(set(res), RES_KEYS)
        self.assertEqual((res["ok"], res["why"], res["pong"], res["rtt_ms"]), (False, why, None, None))

    def test_connect_refused(self):
        def dial(rec):
            raise CarrierError("tcp connect to 172.17.0.3:47602 failed (Connection refused)", retry=True)
        self.check(self.run_with(dial), "connect refused")

    def test_timed_out_from_the_carrier(self):
        def dial(rec):
            raise CarrierError("tcp connect to 172.17.0.3:47602 failed (TimeoutError)", retry=True)
        self.check(self.run_with(dial), "timed out")

    def test_timed_out_from_a_python_timeout(self):
        def dial(rec):
            raise TimeoutError("timed out")
        self.check(self.run_with(dial), "timed out")

    def test_a_request_that_times_out_after_connecting(self):
        def dial(rec):
            class T:
                def request(self_, req):
                    raise CarrierError("tcp request timed out", retry=True)
            return T()
        self.check(self.run_with(dial), "timed out")

    @unittest.skipIf(os.environ.get("ADV13_SKIP_OPEN_FINDINGS") == "1", "open finding #4-F1: an admission refusal is reported as 'connect refused'")
    def test_a_door_that_does_not_admit_us_is_not_authorized_not_connect_refused(self):
        """What the REAL carriers raise when the peer does not know our key (tcplink.py:648/657, torlink: 'onion service needs authentication')."""
        for text, retry in (("not admitted (or the door went away)", True), ("the door needs a credential and none is held", False),
                            ("onion service needs authentication", False)):
            with self.subTest(text):
                def dial(rec, text=text, retry=retry):
                    raise CarrierError(text, retry=retry)
                self.check(self.run_with(dial), "refused: not authorized")

    def test_the_peer_gave_the_strangers_answer(self):
        s = Sim(2)                                                           # arya'"'"'s stock server has no pong callable: the stranger'"'"'s answer
        t = Svc(lambda rec: Sim.transport(t.s, "sansa", rec))
        t.s.servers["arya"] = S.SyncServer(t.s.mirrors["arya"], clock=t.s.clock, identity=t.s.ids["arya"])
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        self.check(read_res(t.home, rid), "refused: not authorized")

    def bad(self, answer):
        def dial(rec):
            class T:
                def request(self_, req):
                    return answer
            return T()
        self.check(self.run_with(dial), "bad answer")

    def test_bad_answers(self):
        good = {"t": "pong", "up": True, "unread": 1, "watching": False, "v": 1}
        for ans in (None, [], "pong", 7, {}, {"t": "pong"}, {"t": "error", "why": "x"},
                    {**good, "up": "yes"}, {**good, "up": False}, {**good, "unread": -1}, {**good, "unread": 1.5}, {**good, "unread": True},
                    {**good, "unread": 10 ** 12}, {**good, "watching": "no"}, {**good, "watching": None},
                    {**{k: v for k, v in good.items() if k != "v"}}, {**{k: v for k, v in good.items() if k != "unread"}},
                    {**good, "junk": "x" * 100_000}, {**good, "t": "ping"}):
            with self.subTest(ans=str(ans)[:60]):
                self.bad(ans)

    def test_a_dial_that_raises_something_unexpected_is_still_a_result_not_a_crash(self):
        def dial(rec):
            raise RuntimeError("boom")
        t = Svc(dial)
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        self.assertEqual(t.tick(), 1)
        res = read_res(t.home, rid)
        self.assertIsNotNone(res)
        self.assertFalse(res["ok"])
        self.assertIsInstance(res["why"], str)

    def test_the_pong_in_the_result_has_only_the_pinned_keys_even_with_the_envelope(self):
        t = Svc()
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        t.tick()
        self.assertEqual(set(read_res(t.home, rid)["pong"]), PONG_KEYS)


class RequestValidation(unittest.TestCase):
    def never_dialled(self, make):
        t = Svc()
        p = make(t)
        self.assertEqual(t.tick(), 0)
        self.assertEqual(t.calls, [], "a bad request was dialled")
        return t, p

    def test_malformed_requests_are_deleted_and_never_dialled(self):
        """Every case is valid EXCEPT for one defect, and names the real peer: only that defect can be why it is dropped."""
        def good(t, **over):
            d = {"id": "0123456789abcdef", "peer": t.a, "deadline": t.s.clock() + 99}
            d.update(over)
            return d

        def enc(d):
            return json.dumps(d).encode()

        cases = {
            "not json": lambda t: b"{{{",
            "empty": lambda t: b"",
            "list": lambda t: b"[]",
            "null": lambda t: b"null",
            "no deadline": lambda t: enc({k: v for k, v in good(t).items() if k != "deadline"}),
            "no peer": lambda t: enc({k: v for k, v in good(t).items() if k != "peer"}),
            "no id": lambda t: enc({k: v for k, v in good(t).items() if k != "id"}),
            "extra key": lambda t: enc(good(t, x=1)),
            "deadline is a string": lambda t: enc(good(t, deadline="soon")),
            "deadline is a bool": lambda t: enc(good(t, deadline=True)),
            "deadline is null": lambda t: enc(good(t, deadline=None)),
            "peer is a number": lambda t: enc(good(t, peer=7)),
            "id differs from the file name": lambda t: enc(good(t, id="ffffffffffffffff")),
            "id is not a string": lambda t: enc(good(t, id=1234567890123456)),
            "binary": lambda t: os.urandom(200),
            "infinite deadline": lambda t: b'{"id": "0123456789abcdef", "peer": "%s", "deadline": Infinity}' % t.a.encode(),
            "nan deadline": lambda t: b'{"id": "0123456789abcdef", "peer": "%s", "deadline": NaN}' % t.a.encode(),
        }
        for name, make in cases.items():
            with self.subTest(name):
                t, p = self.never_dialled(lambda t: write_req(t.home, t.a, rid="0123456789abcdef", raw=make(t))[1])
                self.assertFalse(p.exists(), "the bad request was left in place")

    def test_the_control_request_itself_is_dialled_so_the_cases_above_prove_something(self):
        t = Svc()
        rid, _ = write_req(t.home, t.a, rid="0123456789abcdef", clock=t.s.clock)
        self.assertEqual(t.tick(), 1)
        self.assertEqual(len(t.calls), 1)

    def test_a_request_past_its_deadline_is_dropped_never_dialled_late(self):
        t, p = self.never_dialled(lambda t: write_req(t.home, t.a, deadline=t.s.clock() - 1, clock=t.s.clock)[1])
        self.assertFalse(p.exists())

    def test_a_request_with_the_deadline_exactly_now_is_not_dialled(self):
        t, p = self.never_dialled(lambda t: write_req(t.home, t.a, deadline=t.s.clock(), clock=t.s.clock)[1])

    def test_an_oversized_request_is_deleted_even_when_it_is_otherwise_valid(self):
        def make(t):
            body = json.dumps({"id": "0123456789abcdef", "peer": t.a, "deadline": t.s.clock() + 99}) + " " * 6000          # valid JSON, 6 KB
            return write_req(t.home, t.a, rid="0123456789abcdef", raw=body.encode())[1]
        t, p = self.never_dialled(make)
        self.assertFalse(p.exists())

    def test_a_symlink_named_req_is_deleted_and_its_target_untouched(self):
        def make(t):
            d = t.home / "ping"
            d.mkdir(mode=0o700, exist_ok=True)
            target = t.home / "target.json"
            target.write_text(json.dumps({"id": "0123456789abcdef", "peer": t.a, "deadline": t.s.clock() + 99}))
            p = d / "0123456789abcdef.req"
            os.symlink(target, p)
            return p
        t, p = self.never_dialled(make)
        self.assertFalse(os.path.lexists(p))
        self.assertTrue((t.home / "target.json").exists())

    def test_a_directory_named_req_is_never_dialled_and_does_not_crash(self):
        def make(t):
            d = t.home / "ping"
            d.mkdir(mode=0o700, exist_ok=True)
            p = d / "0123456789abcdef.req"
            p.mkdir()
            return p
        self.never_dialled(make)

    def test_a_fifo_named_req_does_not_hang_the_node(self):
        def make(t):
            d = t.home / "ping"
            d.mkdir(mode=0o700, exist_ok=True)
            p = d / "0123456789abcdef.req"
            os.mkfifo(p)
            return p
        done = {}
        t = Svc()
        make(t)
        th = threading.Thread(target=lambda: done.update(n=t.tick()))
        th.start()
        th.join(5)
        self.assertFalse(th.is_alive(), "tick() blocked on a FIFO")
        self.assertEqual(t.calls, [])

    def test_a_bad_file_name_is_ignored_or_deleted_never_dialled(self):
        t = Svc()
        d = t.home / "ping"
        d.mkdir(mode=0o700)
        for name in ("short.req", "../escape.req", "0123456789abcdef.REQ", "zzzzzzzzzzzzzzzz.req", "0123456789abcdef.req.bak"):
            try:
                (d / name).write_text(json.dumps({"id": "0123456789abcdef", "peer": t.a, "deadline": t.s.clock() + 99}))
            except OSError:
                pass
        self.assertEqual(t.tick(), 0)
        self.assertEqual(t.calls, [])

    def test_a_peer_that_is_not_in_the_book_is_never_dialled(self):
        t = Svc()
        write_req(t.home, Identity.generate("eve").id, clock=t.s.clock)
        t.tick()
        self.assertEqual(t.calls, [])

    def test_a_bad_request_does_not_stop_the_good_one_next_to_it(self):
        t = Svc()
        write_req(t.home, t.a, rid="0123456789abcdef", raw=b"junk")
        rid, _ = write_req(t.home, t.a, clock=t.s.clock)
        self.assertEqual(t.tick(), 1)
        self.assertTrue(read_res(t.home, rid)["ok"])


class Sweeping(unittest.TestCase):
    def test_files_older_than_stale_file_age_are_swept_fresh_ones_stay(self):
        t = Svc()
        d = t.home / "ping"
        d.mkdir(mode=0o700)
        old = time.time() - ping.STALE_FILE_AGE - 60
        new = time.time() - 30
        made = {}
        for name, age in (("1111111111111111.res", old), ("2222222222222222.req", old), ("3333333333333333.res", new)):
            p = d / name
            p.write_text(json.dumps({"id": name[:16], "ok": True, "why": None, "pong": None, "rtt_ms": 1.0}) if name.endswith(".res") else "{}")
            os.utime(p, (age, age))
            made[name] = p
        t.s.clock.t = time.time()
        t.tick()
        self.assertFalse(made["1111111111111111.res"].exists())
        self.assertFalse(made["2222222222222222.req"].exists())
        self.assertTrue(made["3333333333333333.res"].exists())

    def test_the_stale_age_constant_is_read_at_call_time(self):
        t = Svc()
        d = t.home / "ping"
        d.mkdir(mode=0o700)
        p = d / "1111111111111111.res"
        p.write_text("{}")
        os.utime(p, (time.time() - 20, time.time() - 20))
        t.s.clock.t = time.time()
        with mock.patch.object(ping, "STALE_FILE_AGE", 5.0):
            t.tick()
        self.assertFalse(p.exists())


def make_home(peers):
    """A home with identity.json and peers.json (name -> (agent id, endpoint or None)); node.lock not held."""
    home = Path(tempfile.mkdtemp(prefix="adv13_ping_"))
    Identity.generate("me").save(home / "identity.json")
    os.chmod(home, 0o700)
    book = PeerBook(home / "peers.json")
    for name, (aid, ep) in peers.items():
        book.add(aid, name, ep)
    return home


TCP_EP = {"type": "tcp", "addr": "127.0.0.1:9#" + "ab" * 32}


class Responder:
    """Plays the node: answers every ping/*.req with the given result; holds node.lock like a running node."""

    def __init__(self, home, result=None, delay=0.0):
        self.home, self.result, self.delay = Path(home), result, delay
        self.stop = threading.Event()
        self.seen = []
        self.fd = os.open(self.home / "node.lock", os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        self.th = threading.Thread(target=self.loop, daemon=True)
        self.th.start()

    def loop(self):
        d = self.home / "ping"
        while not self.stop.is_set():
            if d.is_dir():
                for p in list(d.glob("*.req")):
                    try:
                        req = json.loads(p.read_text())
                    except (OSError, ValueError):
                        continue
                    self.seen.append((req, time.time(), stat.S_IMODE(os.stat(p).st_mode), stat.S_IMODE(os.stat(d).st_mode)))
                    time.sleep(self.delay)
                    if self.result is not None:
                        res = dict(self.result, id=req["id"])
                        tmp = d / f".{req['id']}.tmp"
                        tmp.write_text(json.dumps(res))
                        os.replace(tmp, d / f"{req['id']}.res")
                    p.unlink()
            time.sleep(0.01)

    def close(self):
        self.stop.set()
        self.th.join(2)
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


PONG_OK = {"ok": True, "why": None, "pong": {"t": "pong", "up": True, "unread": 3, "watching": True, "v": 1}, "rtt_ms": 47.4}
NO_ANSWER = {"ok": False, "why": "connect refused", "pong": None, "rtt_ms": None}
AID = "q" * 32


class PingPeer(unittest.TestCase):
    def setUp(self):
        self.aid = Identity.generate("sansa").id
        self.home = make_home({"sansa": (self.aid, TCP_EP)})

    def test_a_pong_comes_back_as_a_result_tuple(self):
        r = Responder(self.home, PONG_OK)
        try:
            res = ping.ping_peer(self.home, "sansa", 5.0)
        finally:
            r.close()
        self.assertEqual((res.ok, res.why, res.rtt_ms, res.peer_name, res.peer_id), (True, None, 47.4, "sansa", self.aid))
        self.assertEqual(res.pong, PONG_OK["pong"])

    def test_the_request_file_has_the_frozen_format(self):
        r = Responder(self.home, PONG_OK)
        try:
            t0 = time.time()
            ping.ping_peer(self.home, "sansa", 7.0)
        finally:
            r.close()
        req, seen_at, mode, dmode = r.seen[0]
        self.assertEqual(set(req), {"id", "peer", "deadline"})
        self.assertRegex(req["id"], r"^[0-9a-f]{16}$")
        self.assertEqual(req["peer"], self.aid)
        self.assertAlmostEqual(req["deadline"], t0 + 7.0, delta=0.5)
        self.assertEqual(mode, 0o600)
        self.assertEqual(dmode, 0o700)

    def test_the_peer_can_be_named_by_name_or_agent_id_prefix_or_the_whole_id(self):
        for ref in ("sansa", self.aid, self.aid[:8]):
            r = Responder(self.home, PONG_OK)
            try:
                res = ping.ping_peer(self.home, ref, 5.0)
            finally:
                r.close()
            self.assertTrue(res.ok, ref)

    def test_the_default_timeout_is_ping_default_timeout(self):
        r = Responder(self.home, PONG_OK)
        try:
            t0 = time.time()
            ping.ping_peer(self.home, "sansa")
        finally:
            r.close()
        self.assertAlmostEqual(r.seen[0][0]["deadline"], t0 + ping.PING_DEFAULT_TIMEOUT, delta=0.5)

    def test_no_answer_returns_timed_out_at_the_deadline_within_100_ms_and_cleans_up(self):
        r = Responder(self.home, None)                                       # a node that never answers
        try:
            t0 = time.time()
            res = ping.ping_peer(self.home, "sansa", 0.5)
            took = time.time() - t0
        finally:
            r.close()
        self.assertFalse(res.ok)
        self.assertEqual(res.why, "timed out")
        self.assertIsNone(res.pong)
        self.assertIsNone(res.rtt_ms)
        self.assertGreaterEqual(took, 0.5 - 0.01)
        self.assertLessEqual(took, 0.5 + 0.1 + 0.02)
        self.assertEqual([p.name for p in (self.home / "ping").iterdir() if p.suffix in (".req", ".res")], [])

    def test_the_node_failure_reason_is_passed_through(self):
        r = Responder(self.home, NO_ANSWER)
        try:
            res = ping.ping_peer(self.home, "sansa", 5.0)
        finally:
            r.close()
        self.assertEqual((res.ok, res.why, res.pong, res.rtt_ms), (False, "connect refused", None, None))

    def test_both_files_are_removed_after_a_successful_ping(self):
        r = Responder(self.home, PONG_OK)
        try:
            ping.ping_peer(self.home, "sansa", 5.0)
        finally:
            r.close()
        self.assertEqual([p.name for p in (self.home / "ping").iterdir() if p.suffix in (".req", ".res")], [])

    def test_the_node_is_poked_so_the_loop_wakes(self):
        r = Responder(self.home, PONG_OK)
        try:
            ping.ping_peer(self.home, "sansa", 5.0)
        finally:
            r.close()
        self.assertTrue((self.home / "node.poke").exists())

    def test_errors(self):
        r = Responder(self.home, PONG_OK)
        try:
            for bad in (0, -1, 0.0, ping.PING_MAX_TIMEOUT + 1, 10 ** 9):
                with self.subTest(timeout=bad), self.assertRaises(ping.PingError):
                    ping.ping_peer(self.home, "sansa", bad)
            with self.assertRaises(ping.PingError):
                ping.ping_peer(self.home, "nobody", 5.0)
            self.assertTrue(ping.ping_peer(self.home, "sansa", ping.PING_MAX_TIMEOUT).ok)       # the maximum itself is allowed
        finally:
            r.close()

    def test_the_node_not_running_is_an_error(self):
        with self.assertRaises(ping.PingError) as c:
            ping.ping_peer(self.home, "sansa", 5.0)                          # nobody holds node.lock
        self.assertIn("start", str(c.exception))
        self.assertFalse((self.home / "ping").exists() and any((self.home / "ping").iterdir()), "a request was left behind")

    def test_an_ambiguous_name_or_prefix_is_an_error(self):
        b = Identity.generate("b").id
        c = Identity.generate("c").id
        while c[0] != b[0]:
            c = Identity.generate("c").id                                    # two agents whose ids share their first character
        home = make_home({"twin": (b, TCP_EP), "twin ": (c, TCP_EP)})
        PeerBook(home / "peers.json").add(c, "twin", TCP_EP)                 # the same NAME on two agents
        PeerBook(home / "peers.json").add(b, "twin", TCP_EP)
        r = Responder(home, PONG_OK)
        try:
            with self.assertRaises(ping.PingError):
                ping.ping_peer(home, "twin", 5.0)
            with self.assertRaises(ping.PingError):
                ping.ping_peer(home, b[0], 5.0)
            self.assertTrue(ping.ping_peer(home, b[:12], 5.0).ok)             # a long enough prefix is unambiguous
        finally:
            r.close()

    def test_two_simultaneous_pings_do_not_mix_their_answers(self):
        other = Identity.generate("carol").id
        home = make_home({"sansa": (self.aid, TCP_EP), "carol": (other, TCP_EP)})
        pongs = {self.aid: dict(PONG_OK, rtt_ms=11.0), other: dict(PONG_OK, rtt_ms=22.0)}

        class R2(Responder):
            def loop(self_):
                d = self_.home / "ping"
                while not self_.stop.is_set():
                    if d.is_dir():
                        for p in list(d.glob("*.req")):
                            try:
                                req = json.loads(p.read_text())
                            except (OSError, ValueError):
                                continue
                            tmp = d / f".{req['id']}.tmp"
                            tmp.write_text(json.dumps(dict(pongs[req["peer"]], id=req["id"])))
                            os.replace(tmp, d / f"{req['id']}.res")
                            p.unlink()
                    time.sleep(0.01)

        r = R2(home, PONG_OK)
        out = {}
        try:
            th = [threading.Thread(target=lambda n=n: out.__setitem__(n, ping.ping_peer(home, n, 5.0))) for n in ("sansa", "carol")]
            [t.start() for t in th]
            [t.join(10) for t in th]
        finally:
            r.close()
        self.assertEqual((out["sansa"].rtt_ms, out["carol"].rtt_ms), (11.0, 22.0))
        self.assertEqual((out["sansa"].peer_name, out["carol"].peer_name), ("sansa", "carol"))


def run_cli(home, *args, timeout=60):
    r = subprocess.run([sys.executable, "-B", "-m", "sigilnet", "--home", str(home), *args], capture_output=True, text=True, timeout=timeout, cwd=REPO,
                       env={**os.environ, "PYTHONPATH": REPO, "PYTHONDONTWRITEBYTECODE": "1"})
    return r.returncode, r.stdout, r.stderr


class Cli(unittest.TestCase):
    def setUp(self):
        self.aid = Identity.generate("sansa").id
        self.home = make_home({"sansa": (self.aid, TCP_EP)})

    def test_pong_line_and_exit_0(self):
        r = Responder(self.home, PONG_OK)
        try:
            rc, out, err = run_cli(self.home, "ping", "sansa", "--timeout", "10")
        finally:
            r.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), f"pong from sansa ({self.aid[:8]}): up, unread 3, watching yes, rtt 47 ms")

    def test_watching_no_and_unread_zero(self):
        res = dict(PONG_OK, pong={"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1}, rtt_ms=1.2)
        r = Responder(self.home, res)
        try:
            rc, out, err = run_cli(self.home, "ping", "sansa")
        finally:
            r.close()
        self.assertEqual(out.strip(), f"pong from sansa ({self.aid[:8]}): up, unread 0, watching no, rtt 1 ms")

    def test_no_answer_line_and_exit_3(self):
        r = Responder(self.home, NO_ANSWER)
        try:
            rc, out, err = run_cli(self.home, "ping", "sansa", "--timeout", "4")
        finally:
            r.close()
        self.assertEqual(rc, 3, err)
        self.assertRegex(out.strip(), rf"^no answer from sansa \({self.aid[:8]}\) after \d+(\.\d+)? s: connect refused$")

    def test_a_timeout_is_exit_3_after_the_timeout(self):
        r = Responder(self.home, None)
        try:
            t0 = time.time()
            rc, out, err = run_cli(self.home, "ping", "sansa", "--timeout", "1")
            took = time.time() - t0
        finally:
            r.close()
        self.assertEqual(rc, 3)
        m = re.search(r"after (\d+(?:\.\d+)?) s: timed out$", out.strip())
        self.assertIsNotNone(m, out)
        self.assertTrue(0.9 <= float(m.group(1)) <= 1.6, out)                      # the time actually waited (<= the timeout plus the poll)
        self.assertLess(took, 4.0)

    def test_unknown_peer_is_exit_1_with_a_message_on_stderr(self):
        r = Responder(self.home, PONG_OK)
        try:
            rc, out, err = run_cli(self.home, "ping", "nobody")
        finally:
            r.close()
        self.assertEqual(rc, 1)
        self.assertTrue(err.strip())
        self.assertNotIn("Traceback", err)
        self.assertEqual(out.strip(), "")

    def test_the_node_not_running_is_exit_1_and_says_start(self):
        rc, out, err = run_cli(self.home, "ping", "sansa")
        self.assertEqual(rc, 1)
        self.assertIn("start", err)
        self.assertNotIn("Traceback", err)

    def test_a_bad_timeout_is_exit_1(self):
        r = Responder(self.home, PONG_OK)
        try:
            for bad in ("0", "-3", "121"):
                rc, out, err = run_cli(self.home, "ping", "sansa", "--timeout", bad)
                self.assertEqual(rc, 1, (bad, out, err))
                self.assertNotIn("Traceback", err)
        finally:
            r.close()


class WatchBeat(unittest.TestCase):
    def setUp(self):
        from sigilnet.tests_adv12.h import Env
        self.env = Env("public")

    def run_watch(self, seconds):
        from sigilnet.watch import Watcher

        class Clock:
            t = 1_700_000_000.0

            def __call__(self):
                return self.t

            def sleep(self, d):
                self.t += d

        clk = Clock()
        out = []
        w = Watcher(self.env.home, "beat", out=out.append, clock=clk, sleep=clk.sleep)
        w.run(seconds=seconds)
        return clk

    def test_watch_creates_watch_beat_0600(self):
        self.run_watch(1.0)
        p = self.env.home / "watch.beat"
        self.assertTrue(p.exists())
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_watch_beats_about_every_five_seconds(self):
        self.run_watch(12.0)
        n = (self.env.home / "watch.beat").stat().st_size                    # the same safe writer as the poke: one byte per beat
        self.assertTrue(3 <= n <= 4, n)                                       # t=0, 5, 10 (and 12.x is past the end)

    def test_a_short_run_beats_once(self):
        self.run_watch(2.0)
        self.assertEqual((self.env.home / "watch.beat").stat().st_size, 1)

    def test_the_beat_constant_is_read_at_call_time(self):
        with mock.patch.object(ping, "WATCH_BEAT_EVERY", 1.0):
            self.run_watch(5.0)
        self.assertGreaterEqual((self.env.home / "watch.beat").stat().st_size, 5)

    def test_a_symlinked_watch_beat_is_not_followed(self):
        d = self.env.home
        target = d / "precious"
        target.write_text("keep")
        os.symlink(target, d / "watch.beat")
        self.run_watch(7.0)
        self.assertEqual(target.read_text(), "keep")

    def test_no_beat_after_watch_ends_so_watching_goes_false(self):
        self.run_watch(1.0)
        old = time.time() - ping.WATCH_FRESH - 5
        os.utime(self.env.home / "watch.beat", (old, old))
        st = os.lstat(self.env.home / "watch.beat")
        self.assertGreater(time.time() - st.st_mtime, ping.WATCH_FRESH)


class PongWiring(unittest.TestCase):
    def test_the_running_node_gives_its_sync_server_a_pong_callable_built_from_its_snapshot(self):
        from sigilnet import noderun
        from sigilnet.tests_adv13.test_wake_node import tcp_home
        home = tcp_home()
        peer = Identity.generate("ghost").id
        PeerBook(home / "peers.json").add(peer, "ghost", {"type": "tcp", "addr": f"127.0.0.1:{free_base()}#" + "ab" * 32})
        servers = []
        real_init = S.SyncServer.__init__

        def spy(self_, *a, **k):
            real_init(self_, *a, **k)
            servers.append(self_)

        me = Identity.load(home / "identity.json")
        with mock.patch.object(S.SyncServer, "__init__", spy):
            th = threading.Thread(target=lambda: noderun.run(home, me, seconds=3, out=lambda s: None))
            th.start()
            t0 = time.time()
            while time.time() - t0 < 30:
                try:
                    if json.loads((home / "node.status.json").read_text()).get("ready"):
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.05)
        try:
            self.assertTrue(servers)
            pong = servers[0].pong
            self.assertTrue(callable(pong), "the node's SyncServer has no pong callable: peers could never ping it")
            got = pong(peer)
            self.assertEqual(set(got), PONG_KEYS)
            self.assertIsNone(pong(Identity.generate("eve").id))
        finally:
            th.join(30)


class LoopWiring(unittest.TestCase):
    """A real tcp node whose peer is a closed port: the loop picks the .req up through the poke (tick = 30 s) and answers 'connect refused' from the REAL carrier error."""

    def test_the_running_node_answers_a_ping_request_promptly_with_the_real_carrier_error(self):
        from sigilnet import noderun
        from sigilnet.tests_adv13.test_wake_node import tcp_home
        home = tcp_home()
        peer = Identity.generate("ghost").id
        closed = free_base()
        PeerBook(home / "peers.json").add(peer, "ghost", {"type": "tcp", "addr": f"127.0.0.1:{closed}#" + "ab" * 32})
        me = Identity.load(home / "identity.json")
        patch = mock.patch.object(noderun, "TICK", 30.0)
        patch.start()
        th = threading.Thread(target=lambda: noderun.run(home, me, seconds=4, out=lambda s: None))
        th.start()
        try:
            t0 = time.time()
            while time.time() - t0 < 30:
                try:
                    if json.loads((home / "node.status.json").read_text()).get("ready"):
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.05)
            else:
                self.fail("the node never became ready")
            t1 = time.time()
            res = ping.ping_peer(home, "ghost", 10.0)
            took = time.time() - t1
            self.assertFalse(res.ok)
            self.assertEqual(res.why, "connect refused")
            self.assertLess(took, 2.0, "the node did not pick the request up through the poke")
        finally:
            end = time.time() + 6
            while th.is_alive() and time.time() < end + 10:
                time.sleep(max(0.0, 4.2 - (time.time() - t0)) if time.time() - t0 < 4.2 else 0.05)
                wake.poke(home / "node.poke")
                th.join(1.5)
            patch.stop()


if __name__ == "__main__":
    unittest.main()
