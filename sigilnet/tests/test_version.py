"""Stage 1 of DESIGN_versioning.md (rev 3): the declaration (`ver`), its cache (peerver.json), `--version` and `peer list`; the 0.1.x wire bytes stay unchanged."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import canon
from sigilnet import ping as P
from sigilnet import sync as S
from sigilnet import version as V
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.peerver import MAX_PEERS, REFRESH, PeerVer

from .test_node import Sim
from .test_sync import mirror_with
from .util import World

AG = "a" * 32
AG2 = "b" * 32
GOOD = {"wire": "2.3", "majors": [2, 1], "formats": [1, 2], "sw": "2.3.1"}


def fake_pong(who):
    return {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1}


class Spy:
    def __init__(self, inner):
        self.inner, self.reqs = inner, []

    def request(self, req):
        self.reqs.append(req)
        return self.inner.request(req)


class Declarations(unittest.TestCase):
    def test_this_nodes_declaration_round_trips(self):
        d = V.decl()
        self.assertEqual(d, {"wire": f"{V.WIRE[0]}.{V.WIRE[1]}", "majors": list(V.MAJORS), "formats": list(V.FORMATS), "sw": V.SW})
        self.assertEqual(V.parse_decl(d), d)
        self.assertIsNot(V.decl(), V.decl())                               # a fresh dict each time: a caller cannot change the constants

    def test_an_unknown_extra_key_is_ignored_a_later_minor_may_add_some(self):
        self.assertEqual(V.parse_decl({**GOOD, "caps": ["x"]}), {"wire": "2.3", "majors": [2, 1], "formats": [2, 1], "sw": "2.3.1"})

    def test_malformed_declarations_are_none(self):
        bad = [None, [], "1.0", 7, {}, {**GOOD, "wire": "2"}, {**GOOD, "wire": "2.3.1"}, {**GOOD, "wire": "x.y"}, {**GOOD, "wire": 2.3}, {**GOOD, "wire": "1000.0"},
               {**GOOD, "wire": "-1.0"}, {**GOOD, "majors": []}, {**GOOD, "majors": [2, 2]}, {**GOOD, "majors": [True]}, {**GOOD, "majors": [2.0, 1]}, {**GOOD, "majors": "2"},
               {**GOOD, "majors": list(range(9))}, {**GOOD, "majors": [-1, 2]}, {**GOOD, "majors": [1000]}, {**GOOD, "majors": [2, True]}, {**GOOD, "formats": [1, True]}, {**GOOD, "majors": [1]},          # (the wire major 2 must be among them)
               {**GOOD, "formats": []}, {**GOOD, "formats": [0]}, {**GOOD, "formats": [1, 1]}, {**GOOD, "formats": [False]}, {**GOOD, "formats": list(range(1, 10))},
               {k: v for k, v in GOOD.items() if k != "sw"}, {k: v for k, v in GOOD.items() if k != "wire"}]
        for b in bad:
            self.assertIsNone(V.parse_decl(b), b)

    def test_sw_is_printable_short_and_has_no_spaces_or_urls(self):
        for sw in ["2.3.1 see https://evil", "https://evil.example/x", "a b", "1.0\n", "1.0\x1b[2J", "é1.0", "", "x" * 41, " 1.0", "-1.0", "1.0/../x", "1.0;rm", None, 3]:
            self.assertIsNone(V.parse_decl({**GOOD, "sw": sw}), repr(sw))
        for wire in ["١.٠", "1.0\n", "1.0 ", " 1.0", "1。0", "1.٠"]:                        # (non-ASCII digits and trailing whitespace are not wire numbers)
            self.assertIsNone(V.parse_decl({**GOOD, "wire": wire, "majors": [1, 0]}), repr(wire))
        for sw in ["0.2.0", "1.0.0-rc1", "2.3.1+local", "x" * 40, "v1_2"]:
            self.assertEqual(V.parse_decl({**GOOD, "sw": sw})["sw"], sw)

    def test_the_lists_are_sorted_highest_first(self):
        d = V.parse_decl({**GOOD, "majors": [1, 2], "formats": [1, 3, 2]})
        self.assertEqual((d["majors"], d["formats"]), ([2, 1], [3, 2, 1]))

    def test_describe_is_one_printable_line(self):
        self.assertEqual(V.describe(GOOD), "wire 2.3 sw 2.3.1")
        self.assertIn("0.1.x", V.describe(None))


class Negotiation(unittest.TestCase):
    """The human's rules: major = breaking, minor = backwards compatible, a node talks to its own major and the previous one."""

    def d(self, wire, majors, formats=(1,)):
        return {"wire": wire, "majors": list(majors), "formats": list(formats), "sw": "9.9.9"}

    def test_table(self):
        a = self.d("1.0", [1, 0])
        rows = [
            (self.d("1.5", [1, 0]), (1, 0)),                 # 1.0 and 1.5 talk (the lower minor's features)
            (self.d("1.0", [1, 0]), (1, 0)),
            (self.d("2.0", [2, 1]), (1, 0)),                 # 2.x falls back to 1.x
            (self.d("3.0", [3, 2]), None),                   # 3.x cannot talk to 1.x
            (self.d("2.4", [2, 1]), (1, 0)),
            (None, (0, 0)),                                  # an undeclared peer = the 0.1.x shapes (wire major 0): the first versioning release falls back to them
        ]
        for peer, want in rows:
            self.assertEqual(V.negotiate(a, peer), want, peer)

    def test_a_deprecated_major_is_refused(self):
        newer = self.d("3.1", [3])                            # 3.x after an exploit: it no longer lists 2
        self.assertIsNone(V.negotiate(newer, self.d("2.5", [2, 1])))
        self.assertIsNone(V.negotiate(newer, None))           # (and the legacy shapes: major 0)

    def test_the_lower_minor_of_the_shared_major_wins_both_ways(self):
        self.assertEqual(V.negotiate(self.d("2.7", [2, 1]), self.d("2.2", [2, 1])), (2, 2))
        self.assertEqual(V.negotiate(self.d("2.2", [2, 1]), self.d("2.7", [2, 1])), (2, 2))

    def test_a_fallback_major_runs_at_its_baseline_minor(self):
        self.assertEqual(V.negotiate(self.d("2.7", [2, 1]), self.d("1.4", [1, 0])), (1, 0))

    def test_an_old_peer_with_no_common_major_is_refused(self):
        self.assertIsNone(V.negotiate(self.d("2.0", [2, 1]), None))

    def test_thread_formats(self):
        self.assertTrue(V.serves_format(None, 1))              # undeclared = format 1 only
        self.assertFalse(V.serves_format(None, 2))
        self.assertTrue(V.serves_format(self.d("1.0", [1, 0], [2, 1]), 2))
        self.assertFalse(V.serves_format(self.d("1.0", [1, 0], [1]), 2))


class Cache(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "peerver.json"
        self.now = [1000.0]
        self.pv = PeerVer(self.path, clock=lambda: self.now[0])

    def test_note_get_and_persist_0600(self):
        self.assertIsNone(self.pv.get(AG))
        self.pv.note(AG, V.parse_decl(GOOD))
        e = self.pv.get(AG)
        self.assertEqual((e["wire"], e["sw"], e["legacy"]), ("2.3", "2.3.1", False))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        again = PeerVer(self.path)
        self.assertEqual(again.get(AG), e)
        self.assertEqual(again.decl_of(AG), V.parse_decl(GOOD))

    def test_legacy_is_recorded_and_replaced_when_the_peer_upgrades(self):
        self.pv.note(AG, None, legacy=True)
        self.assertTrue(self.pv.get(AG)["legacy"])
        self.assertIsNone(self.pv.decl_of(AG))                  # (negotiate sees None = the 0.1.x shapes)
        self.now[0] += 61
        self.pv.note(AG, V.parse_decl(GOOD))
        self.assertFalse(self.pv.get(AG)["legacy"])
        self.pv.note(AG, None)                                   # neither a declaration nor legacy: nothing recorded
        self.assertFalse(self.pv.get(AG)["legacy"])

    def test_a_peer_that_goes_back_to_0_1_x_is_recorded_as_legacy_again(self):
        self.pv.note(AG, V.parse_decl(GOOD))
        self.now[0] += 61
        self.pv.note(AG, None, legacy=True)
        self.assertTrue(self.pv.get(AG)["legacy"])
        self.assertIsNone(PeerVer(self.path).decl_of(AG))

    def test_a_bad_agent_id_is_never_recorded(self):
        fresh = PeerVer(self.dir / "fresh.json")
        for bad in ["short", "", 7, None, "z" * 33]:
            fresh.note(bad, V.parse_decl(GOOD))
            fresh.note(bad, None, legacy=True)
        self.assertEqual(fresh.d, {})

    def test_an_unchanged_declaration_is_not_rewritten_every_time(self):
        self.pv.note(AG, V.parse_decl(GOOD))
        m0 = os.stat(self.path).st_mtime_ns
        self.now[0] += 60
        self.pv.note(AG, V.parse_decl(GOOD))
        self.assertEqual(os.stat(self.path).st_mtime_ns, m0)
        self.now[0] += REFRESH
        self.pv.note(AG, V.parse_decl(GOOD))
        self.assertGreater(os.stat(self.path).st_mtime_ns, m0)
        self.assertEqual(self.pv.get(AG)["seen"], int(self.now[0]))

    def test_a_changed_declaration_is_written_after_the_minimum_interval(self):
        self.pv.note(AG, V.parse_decl(GOOD))
        self.now[0] += 61
        self.pv.note(AG, V.parse_decl({**GOOD, "sw": "2.4.0"}))
        self.assertEqual(PeerVer(self.path).get(AG)["sw"], "2.4.0")

    def test_a_peer_alternating_two_declarations_cannot_force_a_write_per_request(self):
        self.pv.note(AG, V.parse_decl(GOOD))
        writes = 0
        last = os.stat(self.path).st_mtime_ns
        for i in range(200):
            self.now[0] += 0.2                                       # 200 requests in 40 s
            self.pv.note(AG, V.parse_decl({**GOOD, "sw": "2.4.0" if i % 2 else "2.3.1"}))
            m = os.stat(self.path).st_mtime_ns
            writes += m != last
            last = m
        self.assertEqual(writes, 0)
        self.now[0] += 61
        self.pv.note(AG, V.parse_decl({**GOOD, "sw": "9.9.9"}))
        self.assertEqual(PeerVer(self.path).get(AG)["sw"], "9.9.9")

    def test_a_new_entry_is_always_written(self):
        for i in range(10):
            self.pv.note(f"{i:032x}", V.parse_decl(GOOD))
        self.assertEqual(len(PeerVer(self.path).d), 10)

    def test_prune_forgets_peers_that_left_the_book(self):
        self.pv.note(AG, V.parse_decl(GOOD))
        self.pv.note(AG2, None, legacy=True)
        self.pv.prune({AG})
        self.assertIsNone(PeerVer(self.path).get(AG2))
        self.assertIsNotNone(PeerVer(self.path).get(AG))

    def test_the_table_is_bounded_and_ids_are_checked(self):
        for i in range(MAX_PEERS + 20):
            self.pv.note(f"{i:032x}", V.parse_decl(GOOD))
        self.assertEqual(len(self.pv.d), MAX_PEERS)
        self.pv.note("short", V.parse_decl(GOOD))
        self.pv.note(7, V.parse_decl(GOOD))
        self.assertNotIn("short", self.pv.d)

    def test_a_damaged_or_hostile_file_reads_as_empty_or_partial(self):
        for raw in ["", "{", "[]", '{"peers": []}', '{"peers": {"%s": {"wire": "x"}}}' % AG, '{"peers": {"%s": 5}}' % AG, '{"peers": {"%s": {"legacy": true, "seen": "now"}}}' % AG,
                    '{"peers": {"%s": {"wire": "2.3", "majors": [2], "formats": [1], "sw": "a b", "seen": 1}}}' % AG, "\x00\x01"]:
            self.path.write_text(raw)
            self.assertIsNone(PeerVer(self.path).get(AG), raw)
        self.path.write_text('{"peers": {"%s": {"legacy": true, "seen": 5}}}' % AG)
        self.assertTrue(PeerVer(self.path).get(AG)["legacy"])

    def test_an_unwritable_directory_never_raises(self):
        pv = PeerVer(self.dir / "no" / "such" / "peerver.json")
        pv.note(AG, V.parse_decl(GOOD))                          # (the write fails silently; the cache still answers from memory)
        self.assertEqual(pv.get(AG)["wire"], "2.3")


class Wire(unittest.TestCase):
    """The pull client declares itself; a server answers a declared asker with its own declaration and every other asker with the exact old bytes."""

    def setUp(self):
        self.w = World()
        for n in range(3):
            self.w.post("sansa", f"post {n}")
        self.arya, self.sansa = self.w.ids["arya"], self.w.ids["sansa"]
        self.a = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        self.srv = S.SyncServer(self.a, identity=self.arya, pong=fake_pong)
        self.srv.set_peers([self.sansa.id])
        self.tid = self.w.t.id

    def pull(self, **kw):
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        spy = Spy(S.Loopback(self.srv))
        return S.pull(b, self.tid, spy, self.sansa, peer_id=self.arya.id, **kw), spy

    def test_only_summary_list_and_get_carry_the_declaration_and_the_pull_still_works(self):
        r, spy = self.pull()
        self.assertTrue(r["ok"], r)
        kinds = {q["t"] for q in spy.reqs}
        self.assertEqual(kinds, {"summary", "list", "get"})
        for q in spy.reqs:
            self.assertEqual(q["ver"], V.decl(), q["t"])
        self.assertTrue(r["peer_seen"])
        self.assertEqual(r["peer_ver"], V.decl())

    def test_the_contract_constants(self):
        self.assertEqual(S.VER_REQS, frozenset({"summary", "list", "get"}))                       # (push, locator, capsule and key requests are exact sets: never)
        self.assertEqual(S.VER_ANSWERS, frozenset({"summary", "list", "events", "pong"}))

    def test_an_unknown_thread_is_an_answer_without_a_declaration_and_says_nothing_about_the_peer(self):
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, "0" * 32, S.Loopback(self.srv), self.sansa, peer_id=self.arya.id)
        self.assertFalse(r["ok"])
        self.assertFalse(r["peer_seen"])
        self.assertIsNone(r["peer_ver"])

    def test_push_notify_key_and_locator_requests_never_carry_it(self):
        b = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        spy = Spy(S.Loopback(self.srv))
        S.notify(spy, self.sansa, self.tid, b, peer_id=self.arya.id)
        S.push(b, self.tid, spy, self.sansa, [self.w.t.order[1]], peer_id=self.arya.id)
        S.fetch_keys(b, self.tid, spy, self.sansa, peer_id=self.arya.id, need=["0" * 32])
        self.assertTrue(spy.reqs)
        for q in spy.reqs:
            self.assertNotIn("ver", q, q["t"])
        from sigilnet import locators
        src = Path(locators.__file__).read_text()
        self.assertIn('{"t": "locator", "addr": addr}', src)       # (the locator request is an exact set: no `ver`)

    def test_a_legacy_server_that_never_declares_is_recorded_as_legacy_and_the_pull_works(self):
        with mock.patch.object(S, "VER_ANSWERS", frozenset()):
            r, spy = self.pull()
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["peer_seen"])
        self.assertIsNone(r["peer_ver"])

    def test_a_garbage_declaration_in_an_answer_is_ignored_not_an_error(self):
        class Liar:
            def __init__(self, inner):
                self.inner = inner

            def request(self, req):
                resp = self.inner.request(req)
                resp["ver"] = {"wire": "x", "sw": "see https://evil"}
                return resp
        b = Mirror(tempfile.mkdtemp(), rate_limit=False)
        r = S.pull(b, self.tid, Liar(S.Loopback(self.srv)), self.sansa)                     # (no peer_id: an unsigned-check pull, so the tampered answer is read)
        self.assertTrue(r["ok"], r)
        self.assertIsNone(r["peer_ver"])
        self.assertTrue(r["peer_seen"])

    def req(self, body, who=None, ver=False):
        who = who or self.sansa
        q = S.sign_request(who, {**body, **({"ver": V.decl()} if ver else {})}, aud=self.arya.id)
        return q

    def test_a_declared_asker_gets_the_declaration_a_legacy_asker_gets_the_old_bytes(self):
        bodies = [{"t": "summary", "thread": self.tid}, {"t": "list", "thread": self.tid, "page": 0}, {"t": "get", "thread": self.tid, "ids": [self.tid]}, {"t": "ping"}]
        for body in bodies:
            def fresh():
                srv = S.SyncServer(self.a, identity=self.arya, pong=fake_pong)      # (a new server per request: a ping is answered once per second per requester)
                srv.set_peers([self.sansa.id])
                return srv
            plain = fresh().handle(self.req(body))
            self.assertNotIn("ver", plain, body["t"])
            declared = fresh().handle(self.req(body, ver=True))
            self.assertEqual(declared.get("ver"), V.decl(), body["t"])
            stripped = {k: v for k, v in declared.items() if k not in ("ver", "nonce", "rsig")}
            self.assertEqual(stripped, {k: v for k, v in plain.items() if k not in ("nonce", "rsig")}, body["t"])      # nothing else differs

    def test_a_stranger_with_a_declaration_gets_unknown_and_no_declaration(self):
        eve = self.w.ids["eve"]
        q = S.sign_request(eve, {"t": "summary", "thread": self.tid, "ver": V.decl()}, aud=self.arya.id)
        resp = self.srv.handle(q)
        self.assertEqual(resp["t"], "unknown")
        self.assertNotIn("ver", resp)
        p = S.sign_request(eve, {"t": "ping", "ver": V.decl()}, aud=self.arya.id)
        srv = S.SyncServer(self.a, identity=self.arya, pong=lambda who: None)               # (a server that answers no pings / a stranger's ping)
        r2 = srv.handle(p)
        self.assertNotIn("ver", r2)

    def test_a_malformed_declaration_is_not_answered_with_ours(self):
        q = S.sign_request(self.sansa, {"t": "summary", "thread": self.tid, "ver": {"wire": "?"}}, aud=self.arya.id)
        resp = self.srv.handle(q)
        self.assertEqual(resp["t"], "summary")
        self.assertNotIn("ver", resp)

    def test_the_callback_hears_known_peers_only_and_only_for_the_right_request_types(self):
        heard = []
        srv = S.SyncServer(self.a, identity=self.arya, pong=fake_pong, on_peer_ver=lambda who, d: heard.append((who, d)))
        srv.set_peers([self.sansa.id])
        srv.handle(self.req({"t": "summary", "thread": self.tid}, ver=True))
        srv.handle(S.sign_request(self.w.ids["eve"], {"t": "summary", "thread": self.tid, "ver": V.decl()}, aud=self.arya.id))       # a stranger
        srv.handle(self.req({"t": "ping"}, ver=True))
        srv.handle(S.sign_request(self.sansa, {"t": "notify", "thread": self.tid, "leaves": [], "ver": V.decl()}, aud=self.arya.id))   # (notify never carries it: not heard)
        srv.handle(S.sign_request(self.sansa, {"t": "summary", "thread": self.tid, "ver": {"wire": "bad"}}, aud=self.arya.id))        # malformed: not heard
        self.assertEqual([w for w, _ in heard], [self.sansa.id, self.sansa.id])
        self.assertEqual(heard[0][1], V.decl())

    def test_a_hostile_request_type_never_raises_even_with_a_valid_declaration(self):
        for t in [[], {}, [1], {"a": 1}, 5, None, True, "x", ["summary"], {"summary": 1}]:
            q = S.sign_request(self.sansa, {"t": t, "thread": self.tid, "ver": V.decl()}, aud=self.arya.id)
            resp = self.srv.handle(json.loads(json.dumps(q)))
            self.assertIsInstance(resp, dict)
            self.assertNotIn("ver", resp, repr(t))
            self.assertIsInstance(self.srv._reply(q, {"t": "error", "why": "x"}), dict)
        heard = []
        srv = S.SyncServer(self.a, identity=self.arya, pong=fake_pong, on_peer_ver=lambda who, d: heard.append(who))
        srv.set_peers([self.sansa.id])
        srv.handle(S.sign_request(self.sansa, {"t": ["summary"], "thread": self.tid, "ver": V.decl()}, aud=self.arya.id))
        self.assertEqual(heard, [])

    def test_a_failing_callback_never_fails_the_request(self):
        def boom(who, d):
            raise RuntimeError("cache broke")
        srv = S.SyncServer(self.a, identity=self.arya, pong=fake_pong, on_peer_ver=boom)
        srv.set_peers([self.sansa.id])
        self.assertEqual(srv.handle(self.req({"t": "summary", "thread": self.tid}, ver=True))["t"], "summary")


class PublicDoor(unittest.TestCase):
    """A public read door (strangers, no signature): it accepts and DROPS a declaring puller's `ver`, never answers with its own, and a guest pull does not declare."""

    def setUp(self):
        from sigilnet.publicread import PublicRead
        self.w = World(visibility="public")
        self.w.post("sansa", "public hello")
        m = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        self.srv = S.SyncServer(m, identity=self.w.ids["arya"])
        self.door = PublicRead(self.srv)
        self.tid = self.w.t.id

    def req(self, **extra):
        return {"t": "summary", "thread": self.tid, "nonce": os.urandom(8).hex(), **extra}

    def test_a_request_with_ver_is_answered_without_ver(self):
        resp = self.door.handle(self.req(ver=V.decl()))
        self.assertEqual(resp["t"], "summary")
        self.assertNotIn("ver", resp)
        self.assertEqual(resp["n"], len(self.w.t.resolved_ids()))

    def test_other_extra_fields_are_still_refused(self):
        self.assertEqual(self.door.handle(self.req(extra=1))["why"], "malformed request")
        self.assertEqual(self.door.handle(self.req(ver=V.decl(), extra=1))["why"], "malformed request")

    def test_a_pull_that_does_not_declare_sends_no_ver_and_a_declaring_pull_works_too(self):
        for declare in (False, True):
            spy = Spy(S.Loopback(self.door))
            b = Mirror(tempfile.mkdtemp(), rate_limit=False)
            r = S.pull(b, self.tid, spy, Identity.generate("stranger"), declare=declare)
            self.assertTrue(r["ok"], (declare, r))
            self.assertEqual(any("ver" in q for q in spy.reqs), declare)
            self.assertEqual(len(b.threads[self.tid].resolved_ids()), 2)

    def test_the_guest_pull_command_does_not_declare(self):
        src = (Path(__file__).resolve().parents[1] / "cli.py").read_text()
        self.assertIn("pull(m, tid, tr, me, peer_id=a.owner_id, declare=False)", src)


class PingVersion(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.arya, self.sansa = self.w.ids["arya"], self.w.ids["sansa"]
        self.m = mirror_with(self.w.genesis, [])
        self.srv = S.SyncServer(self.m, identity=self.arya, pong=fake_pong)
        self.srv.set_peers([self.sansa.id])

    def test_exchange_declares_and_returns_the_peers_declaration_inside_the_pong(self):
        ok, why, pong, rtt = P.exchange(S.Loopback(self.srv), self.sansa, self.arya.id)
        self.assertTrue(ok, why)
        self.assertEqual(pong["ver"], V.decl())
        self.assertEqual({k: v for k, v in pong.items() if k != "ver"}, fake_pong(None))

    def test_a_pong_without_a_declaration_is_still_the_five_keys(self):
        with mock.patch.object(S, "VER_ANSWERS", frozenset()):
            ok, why, pong, rtt = P.exchange(S.Loopback(self.srv), self.sansa, self.arya.id)
        self.assertTrue(ok, why)
        self.assertEqual(set(pong), P.PONG_KEYS)

    def test_the_pong_key_set_is_unchanged(self):
        self.assertEqual(P.PONG_KEYS, {"t", "up", "unread", "watching", "v"})

    def test_a_malformed_declaration_in_a_pong_is_dropped_but_another_extra_key_is_refused(self):
        def reply(extra):
            def answer(req):
                resp = {**fake_pong(None), "nonce": req["nonce"], "r": 1, **extra}
                resp["by"] = self.arya.sign_pub
                resp["rsig"] = self.arya.sign(S.RESP_CTX + canon.dumps(resp))
                return resp
            return answer

        class T:
            def __init__(self, f):
                self.f = f

            def request(self, req):
                return self.f(req)
        ok, why, pong, _ = P.exchange(T(reply({"ver": {"wire": "bad"}})), self.sansa, self.arya.id)
        self.assertTrue(ok, why)
        self.assertNotIn("ver", pong)
        ok, why, pong, _ = P.exchange(T(reply({"extra": 1})), self.sansa, self.arya.id)
        self.assertEqual((ok, why), (False, "bad answer"))
        ok, why, pong, _ = P.exchange(T(reply({"ver": V.decl(), "extra": 1})), self.sansa, self.arya.id)
        self.assertEqual((ok, why), (False, "bad answer"))


class NodeCache(unittest.TestCase):
    def sim(self):
        s = Sim(2)
        for x in s.nodes:
            s.nodes[x].pv = PeerVer(s.homes[x] / "peerver.json")
        return s

    def test_a_pull_records_what_the_peer_declared(self):
        s = self.sim()
        s.post("arya", "hello")
        s.step(1, 3)
        e = s.nodes["sansa"].pv.get(s.ids["arya"].id)
        self.assertIsNotNone(e)
        self.assertEqual((e["wire"], e["sw"], e["legacy"]), (f"{V.WIRE[0]}.{V.WIRE[1]}", V.SW, False))

    def test_a_peer_that_answers_without_a_declaration_is_recorded_as_legacy(self):
        s = self.sim()
        with mock.patch.object(S, "VER_ANSWERS", frozenset()):
            s.post("arya", "hello")
            s.step(1, 3)
        e = s.nodes["sansa"].pv.get(s.ids["arya"].id)
        self.assertTrue(e["legacy"])

    def test_a_pull_that_got_no_answer_records_nothing(self):
        s = self.sim()
        s.post("arya", "hello")
        s.up["arya"] = False
        s.step(1, 3)
        self.assertIsNone(s.nodes["sansa"].pv.get(s.ids["arya"].id))

    def test_a_node_without_a_cache_is_unaffected(self):
        s = Sim(2)
        self.assertIsNone(s.nodes["arya"].pv)
        s.post("arya", "hello")
        s.step(1, 3)
        self.assertEqual(len(s.mirrors["sansa"].threads[s.tid].resolved_ids()), 2)

    def test_the_cache_forgets_peers_that_left_the_book_after_an_hour(self):
        s = self.sim()
        s.post("arya", "hello")
        s.step(1, 3)
        sansa = s.nodes["sansa"]
        self.assertIsNotNone(sansa.pv.get(s.ids["arya"].id))
        sansa.tick()                                              # (the first look prunes nothing: the peer is in the book)
        sansa.peers.remove(s.ids["arya"].id)
        s.clock.t += 60
        sansa.tick()
        self.assertIsNotNone(sansa.pv.get(s.ids["arya"].id))      # (pruned at most once an hour)
        s.clock.t += 4000
        sansa.tick()
        self.assertIsNone(sansa.pv.get(s.ids["arya"].id))


class PingServiceVersion(unittest.TestCase):
    """The node's ping service (the file protocol between `ping` and the running node): the result file carries the peer's declaration beside the five-key pong, and the node's cache learns it."""

    def run_ping(self, legacy=False):
        import fcntl
        import threading
        s = Sim(2)
        for x in s.nodes:
            s.nodes[x].pv = PeerVer(s.homes[x] / "peerver.json")
            s.servers[x].pong = s.nodes[x].pong_for
        s.post("arya", "hello")
        s.step(1, 3)
        s.clock.t = time.time()
        ahome = s.homes["arya"]
        fd = os.open(ahome / "node.lock", os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, fd)
        s.nodes["sansa"].pong_snapshot(force=True)
        svc = P.PingService(s.nodes["arya"], ahome, lambda rec: s.transport("arya", rec))
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                svc.tick()
                time.sleep(0.02)
        th = threading.Thread(target=loop, daemon=True)
        th.start()
        try:
            if legacy:
                with mock.patch.object(S, "VER_ANSWERS", frozenset()):
                    r = P.ping_peer(ahome, "sansa", 5)
            else:
                r = P.ping_peer(ahome, "sansa", 5)
        finally:
            stop.set()
            th.join(5)
        return s, r

    def test_the_result_has_the_declaration_the_pong_stays_five_keys_and_the_node_caches_it(self):
        s, r = self.run_ping()
        self.assertTrue(r.ok, r.why)
        self.assertEqual(r.ver, V.decl())
        self.assertEqual(set(r.pong), P.PONG_KEYS)
        e = s.nodes["arya"].pv.get(s.ids["sansa"].id)
        self.assertEqual((e["wire"], e["legacy"]), (f"{V.WIRE[0]}.{V.WIRE[1]}", False))
        self.assertIn(f"sigilnet {V.SW} (wire {V.WIRE[0]}.{V.WIRE[1]})", P.format_result(r, 1.0))

    def test_a_peer_without_a_declaration_gives_no_ver_and_is_cached_as_legacy(self):
        s, r = self.run_ping(legacy=True)
        self.assertTrue(r.ok, r.why)
        self.assertIsNone(r.ver)
        self.assertEqual(set(r.pong), P.PONG_KEYS)
        self.assertTrue(s.nodes["arya"].pv.get(s.ids["sansa"].id)["legacy"])


    def test_a_mangled_ver_in_the_result_file_is_ignored_by_the_asker(self):
        import fcntl
        import threading
        s = Sim(2)
        ahome = s.homes["arya"]
        fd = os.open(ahome / "node.lock", os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, fd)
        stop = threading.Event()

        def fake_node():
            while not stop.is_set():
                for req in (ahome / "ping").glob("*.req"):
                    ident = req.stem
                    P._write_json(ahome / "ping" / f"{ident}.res", {"id": ident, "ok": True, "why": None, "pong": fake_pong(None), "rtt_ms": 1.0, "ver": {"wire": "x", "sw": "see https://evil"}})
                    req.unlink()
                time.sleep(0.02)
        th = threading.Thread(target=fake_node, daemon=True)
        th.start()
        try:
            r = P.ping_peer(ahome, "sansa", 5)
        finally:
            stop.set()
            th.join(5)
        self.assertTrue(r.ok, r.why)
        self.assertIsNone(r.ver)


class Cli(unittest.TestCase):
    def run_cli(self, home, *args):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2]))
        return subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(home), *args], capture_output=True, text=True, env=env, timeout=120)

    def test_version_prints_three_lines(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2]))
        r = subprocess.run([sys.executable, "-m", "sigilnet", "--version"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.strip().split("\n")
        self.assertEqual(len(lines), 3, r.stdout)
        self.assertEqual(lines[0], f"sigilnet {V.SW}")
        self.assertIn(f"wire protocol {V.WIRE[0]}.{V.WIRE[1]}", lines[1])
        self.assertIn("thread formats 2, 1", lines[2])

    def test_peer_list_shows_declared_legacy_and_unknown_peers(self):
        home = Path(tempfile.mkdtemp()) / "h"
        r = self.run_cli(home, "init", "me", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", "47990")
        self.assertEqual(r.returncode, 0, r.stderr)
        h = home / ".sigilnet" if (home / ".sigilnet").is_dir() else home
        peers = {AG: {"name": "decl", "endpoint": {"type": "tcp", "addr": "127.0.0.1:47991#" + "ab" * 32}, "threads": []},
                 AG2: {"name": "old", "endpoint": {"type": "tcp", "addr": "127.0.0.1:47992#" + "cd" * 32}, "threads": []},
                 "c" * 32: {"name": "new", "endpoint": {"type": "tcp", "addr": "127.0.0.1:47993#" + "ef" * 32}, "threads": []}}
        (h / "peers.json").write_text(json.dumps({"peers": peers}))
        pv = PeerVer(h / "peerver.json")
        pv.note(AG, V.parse_decl(GOOD))
        pv.note(AG2, None, legacy=True)
        r = self.run_cli(h, "peer", "list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("wire 2.3 sw 2.3.1", r.stdout)
        self.assertIn("0.1.x or older: it declares nothing", r.stdout)
        self.assertEqual(r.stdout.count("(recorded "), 2)                  # (each known entry says how long ago it was recorded)
        self.assertEqual(r.stdout.count("wire "), 2)                       # (the peer never heard from gets no line: the output stays what it was)


# ------------------------------------------------------------------------------------------------ the PARENT tree (the deployed 0.1.x code) on the new bytes
PARENT_TAG = "r49q_merged"


def parent_tree():
    root = Path(os.environ.get("SIGIL_PARENT_REPO") or Path(__file__).resolve().parents[2])            # (mutation runs copy the tree without .git: they point here)
    d = Path(tempfile.mkdtemp(prefix="sn_parent_"))
    try:
        tar = subprocess.run(["git", "-C", str(root), "archive", PARENT_TAG], capture_output=True, timeout=60)
        if tar.returncode != 0:
            shutil.rmtree(d, True)
            return None
        subprocess.run(["tar", "-x", "-C", str(d)], input=tar.stdout, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        shutil.rmtree(d, True)
        return None
    return d


class AgainstTheDeployedTree(unittest.TestCase):
    """The 0.1.x server and client (tag r49q_merged) next to this tree: the extra `ver` field is ignored by the old server (its answer does not change) and a new server's
    answer to an OLD-shaped request is byte-identical to the old server's."""

    @classmethod
    def setUpClass(cls):
        cls.tree = parent_tree()
        if cls.tree is None:
            raise unittest.SkipTest("the parent tree is not available (git archive)")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "tree", None):
            shutil.rmtree(cls.tree, True)

    def setUp(self):
        self.w = World()
        for n in range(3):
            self.w.post("sansa", f"post {n}")
        self.arya, self.sansa = self.w.ids["arya"], self.w.ids["sansa"]
        self.tid = self.w.t.id
        self.dir = Path(tempfile.mkdtemp())
        self.idfile = self.dir / "arya.json"
        self.arya.save(self.idfile)
        self.T = 1_900_000_000

    def old_server_answers(self, reqs):
        job = {"events": [canon.dumps(self.w.t.events[i]).decode() for i in self.w.t.order], "reqs": reqs, "id": str(self.idfile), "sansa": self.sansa.id, "T": self.T}
        code = textwrap.dedent("""
            import json, sys, tempfile
            from sigilnet import canon, sync as S
            from sigilnet.keys import Identity
            from sigilnet.mirror import Mirror
            job = json.load(sys.stdin)
            ident = Identity.load(job["id"])
            m = Mirror(tempfile.mkdtemp(), rate_limit=False)
            for _ in range(3):
                for e in job["events"]:
                    m.ingest(canon.loads(e.encode()), live=False)
            out = []
            for r in job["reqs"]:
                srv = S.SyncServer(m, identity=ident, clock=lambda: job["T"], pong=lambda who: {"t": "pong", "up": True, "unread": 0, "watching": False, "v": 1})
                srv.set_peers([job["sansa"]])
                out.append(srv.handle(r))
            print(json.dumps(out))
        """)
        env = dict(os.environ, PYTHONPATH=str(self.tree))
        p = subprocess.run([sys.executable, "-c", code], input=json.dumps(job), capture_output=True, text=True, env=env, timeout=120, cwd=str(self.dir))
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def new_server_answers(self, reqs):
        m = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        out = []
        for r in reqs:
            srv = S.SyncServer(m, identity=self.arya, clock=lambda: self.T, pong=fake_pong)
            srv.set_peers([self.sansa.id])
            out.append(json.loads(json.dumps(srv.handle(json.loads(json.dumps(r))))))
        return out

    def requests(self, ver):
        bodies = [{"t": "summary", "thread": self.tid}, {"t": "list", "thread": self.tid, "page": 0}, {"t": "get", "thread": self.tid, "ids": [self.tid]}, {"t": "ping"},
                  {"t": "summary", "thread": "0" * 32}]
        out = []
        for b in bodies:
            q = S.sign_request(self.sansa, b, ts=self.T, aud=self.arya.id)
            if ver:
                q = {k: v for k, v in q.items() if k != "sig"}
                q["ver"] = V.decl()
                q["sig"] = self.sansa.sign(S._req_bytes(q))
            out.append(q)
        return out

    def test_the_old_server_ignores_the_declaration_and_answers_exactly_as_before(self):
        plain = self.requests(False)
        decl = []
        for q in plain:                                              # the same request (same nonce, same time) with `ver` added and re-signed
            d = {k: v for k, v in q.items() if k != "sig"}
            d["ver"] = V.decl()
            d["sig"] = self.sansa.sign(S._req_bytes(d))
            decl.append(d)
        a, b = self.old_server_answers(plain), self.old_server_answers(decl)
        self.assertEqual(a, b)
        self.assertEqual([x["t"] for x in a], ["summary", "list", "events", "pong", "unknown"])
        for x in a:
            self.assertNotIn("ver", x)

    def test_the_new_server_answers_an_old_shaped_request_byte_for_byte_like_the_old_one(self):
        reqs = self.requests(False)
        self.assertEqual(self.new_server_answers(reqs), self.old_server_answers(reqs))

    def test_the_new_server_adds_only_ver_for_a_declared_asker(self):
        decl = self.requests(True)
        got = self.new_server_answers(decl)
        old = self.old_server_answers(decl)
        for g, o in zip(got, old):
            self.assertEqual({k: v for k, v in g.items() if k not in ("ver", "rsig")}, {k: v for k, v in o.items() if k != "rsig"})
        self.assertEqual([("ver" in g) for g in got], [True, True, True, True, False])       # (the `unknown` answer never carries it)

    def test_the_old_client_accepts_the_new_servers_answers_to_its_own_requests(self):
        """Old client (pull + ping check) against a new server, through a file of canned requests: the old code runs `pull` over a transport that calls the new server in this process."""
        m = mirror_with(self.w.genesis, [self.w.t.events[i] for i in self.w.t.order[1:]])
        srv = S.SyncServer(m, identity=self.arya, pong=fake_pong)
        srv.set_peers([self.sansa.id])
        # Replay the old client's three pull requests (summary, list, get) as the old code would build them, and check the old verifier accepts the new answers.
        old_reqs = []
        for b in [{"t": "summary", "thread": self.tid}, {"t": "list", "thread": self.tid, "page": 0}, {"t": "get", "thread": self.tid, "ids": [self.tid]}]:
            old_reqs.append(S.sign_request(self.sansa, b, ts=int(time.time()), aud=self.arya.id))
        new_answers = [json.loads(json.dumps(srv.handle(json.loads(json.dumps(q))))) for q in old_reqs]
        job = {"answers": new_answers, "reqs": old_reqs, "arya": self.arya.id}
        check = textwrap.dedent("""
            import json, sys
            from sigilnet import sync as S
            job = json.load(sys.stdin)
            ok = []
            for q, a in zip(job["reqs"], job["answers"]):
                good = a.get("nonce") == q["nonce"] and type(a.get("r")) is int and a["r"] == 1 and S.response_signed_by(a, job["arya"]) and a.get("t") in ("summary", "list", "events")
                ok.append(bool(good))
            print(json.dumps(ok))
        """)
        env = dict(os.environ, PYTHONPATH=str(self.tree))
        p = subprocess.run([sys.executable, "-c", check], input=json.dumps(job), capture_output=True, text=True, env=env, timeout=60, cwd=str(self.dir))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), [True, True, True])
        for a in new_answers:
            self.assertNotIn("ver", a)                                # (an old client never declared itself: it never gets one)

    def test_the_old_ping_check_accepts_the_new_pong_for_an_old_asker(self):
        m = mirror_with(self.w.genesis, [])
        srv = S.SyncServer(m, identity=self.arya, pong=fake_pong)
        srv.set_peers([self.sansa.id])
        q = S.sign_request(self.sansa, {"t": "ping"}, ts=int(time.time()), aud=self.arya.id)
        a = json.loads(json.dumps(srv.handle(q)))
        job = {"a": a, "nonce": q["nonce"], "arya": self.arya.id}
        code = textwrap.dedent("""
            import json, sys
            from sigilnet import ping as P
            job = json.load(sys.stdin)
            print(json.dumps(P.check_pong(job["a"], job["nonce"], job["arya"])[0]))
        """)
        env = dict(os.environ, PYTHONPATH=str(self.tree))
        p = subprocess.run([sys.executable, "-c", code], input=json.dumps(job), capture_output=True, text=True, env=env, timeout=60, cwd=str(self.dir))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), True)

    def test_rollback_the_old_tree_ignores_a_peerver_file_and_lists_its_peers(self):
        home = self.dir / "h"
        env = dict(os.environ, PYTHONPATH=str(self.tree))
        r = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(home), "init", "me", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", "47980"], capture_output=True, text=True, env=env, timeout=120, cwd=str(self.dir))
        self.assertEqual(r.returncode, 0, r.stderr)
        h = home / ".sigilnet" if (home / ".sigilnet").is_dir() else home
        (h / "peers.json").write_text(json.dumps({"peers": {AG: {"name": "x", "endpoint": {"type": "tcp", "addr": "127.0.0.1:47981#" + "ab" * 32}, "threads": []}}}))
        PeerVer(h / "peerver.json").note(AG, V.parse_decl(GOOD))
        PeerVer(h / "peerver.json").note(AG2, None, legacy=True)
        self.assertTrue((h / "peerver.json").exists())
        r = subprocess.run([sys.executable, "-m", "sigilnet", "--home", str(h), "peer", "list"], capture_output=True, text=True, env=env, timeout=120, cwd=str(self.dir))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(AG, r.stdout)

    def test_the_old_ping_check_refuses_a_pong_with_ver_which_is_why_it_is_sent_only_to_declared_askers(self):
        m = mirror_with(self.w.genesis, [])
        srv = S.SyncServer(m, identity=self.arya, pong=fake_pong)
        srv.set_peers([self.sansa.id])
        q = S.sign_request(self.sansa, {"t": "ping", "ver": V.decl()}, ts=int(time.time()), aud=self.arya.id)
        a = json.loads(json.dumps(srv.handle(q)))
        self.assertIn("ver", a)
        code = textwrap.dedent("""
            import json, sys
            from sigilnet import ping as P
            job = json.load(sys.stdin)
            print(json.dumps(P.check_pong(job["a"], job["nonce"], job["arya"])[0]))
        """)
        env = dict(os.environ, PYTHONPATH=str(self.tree))
        p = subprocess.run([sys.executable, "-c", code], input=json.dumps({"a": a, "nonce": q["nonce"], "arya": self.arya.id}), capture_output=True, text=True, env=env, timeout=60, cwd=str(self.dir))
        self.assertEqual(json.loads(p.stdout), False)                  # (documented: the extra key makes the OLD exact check say "bad answer"; no old asker ever receives it)


if __name__ == "__main__":
    unittest.main()
