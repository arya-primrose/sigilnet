"""Regression tests written from a mutation run (/tmp/mutate_r15.py): each test kills mutants that the earlier suites let survive.
Every test passes on the current code. The security rule each one pins is named in its docstring."""
import hashlib
import json
import os
import stat
import tempfile
import unittest

from sigilnet import canon
from sigilnet import pow as P
from sigilnet.build import Writer, make_genesis
from sigilnet.event import encode, event_id, make_event, sign_input
from sigilnet.guest import GuestError, MAX_ACCEPTED_BITS, _printable, request_admission
from sigilnet.inbox import Inbox, PERIOD
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.publicread import PublicRead
from sigilnet.sync import SyncServer
from sigilnet.tests.test_inbox import Base, Clock, policy


def exact(salt, tid, pub, eid, b):
    n = 0
    while P.achieved(salt, tid, pub, eid, n) != b:
        n += 1
    return n


# ------------------------------------------------------------------ pow
class PowRules(unittest.TestCase):
    S, T, K, E = b"s" * 16, "t" * 32, "a" * 64, "e" * 32

    def test_verify_has_no_bits_minus_one_tolerance(self):
        """verify() needs AT LEAST `bits` zero bits: a proof with exactly bits-1 is refused (the tolerance lives in the inbox only)."""
        n = exact(self.S, self.T, self.K, self.E, 5)
        self.assertTrue(P.verify(self.S, self.T, self.K, self.E, n, 5))
        self.assertTrue(P.verify(self.S, self.T, self.K, self.E, n, 4))
        self.assertFalse(P.verify(self.S, self.T, self.K, self.E, n, 6))

    def test_digest_is_domain_separated_known_answer(self):
        """The hash input starts with the context string and length-prefixes every part (independent re-computation)."""
        h = hashlib.sha256(b"sigilnet/v1/guest-pow\0")
        for part in (self.S, self.T.encode(), self.K.encode(), self.E.encode()):
            h.update(len(part).to_bytes(2, "big") + part)
        h.update((12345).to_bytes(8, "big"))
        self.assertEqual(P._digest(self.S, self.T, self.K, self.E, 12345), h.digest())


# ------------------------------------------------------------------ inbox
class M(Base):
    def sub(self, who=None, *, reply_to=None, bits=4, text="please", ev=None):
        """A submit frame whose proof has EXACTLY `bits` leading zero bits."""
        who = who or Identity.generate("g")
        if ev is None:
            ev = Writer(who, self.t).guest_request(text, reply_to or self.rid, ts=int(self.clock()))
        salt = self.inbox.salt(self.inbox.period())
        g = ev["body"]["guest"]["sign"] if isinstance(ev.get("body"), dict) and isinstance(ev["body"].get("guest"), dict) else who.sign_pub
        n = exact(salt, self.tid, g, event_id(ev), bits)
        return {"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": salt.hex(), "nonce": n}}, ev

    def member_post(self):
        sansa = Identity.generate("sansa")
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).add_member(sansa, "member")).ok)
        ev = Writer(sansa, self.t).post("a member post", ts=int(self.clock()))
        self.assertTrue(self.m.ingest(ev).ok)
        self.sansa = sansa
        return event_id(ev)

    def fill(self, n, *, reply_to=None, bits=4):
        ids = []
        for _ in range(n):
            r, ev = self.sub(reply_to=reply_to, bits=bits)
            self.assertEqual(self.inbox.handle(r)["t"], "ok")
            ids.append(event_id(ev))
        self.assertEqual(set(self.t.awaiting) >= set(ids), True)
        return ids

    def assert_untouched(self, ids):
        self.assertEqual(set(self.t.awaiting), set(ids), "a refused request changed the waiting pool")


class Salts(M):
    def test_future_salt_not_accepted(self):
        """Only the current and the previous salt period are accepted; the next one is stale."""
        r, _ = self.sub()
        r["pow"]["salt"] = self.inbox.salt(self.inbox.period() + 1).hex()
        out = self.inbox.handle(r)
        self.assertEqual((out["t"], out["why"]), ("stale", "salt"))

    def test_challenge_expiry_is_when_its_salt_stops_working(self):
        ch = self.chal()
        salt = bytes.fromhex(ch["salt"])

        def with_old_salt():
            r, ev = self.sub()
            r["pow"] = {"salt": ch["salt"], "nonce": exact(salt, self.tid, ev["body"]["guest"]["sign"], event_id(ev), 4)}
            return r
        a, b = with_old_salt(), with_old_salt()
        self.clock.t = ch["expires"] - 1
        self.assertEqual(self.inbox.handle(a)["t"], "ok")
        self.clock.t = ch["expires"]
        self.assertEqual(self.inbox.handle(b)["why"], "salt")

    def test_salt_depends_on_secret(self):
        other = Inbox(self.m, tempfile.mkdtemp(), clock=self.clock)
        self.assertNotEqual(other.salt(5), self.inbox.salt(5))
        self.assertEqual(Inbox(self.m, self.home, clock=self.clock).salt(5), self.inbox.salt(5))

    def test_short_secret_file_is_replaced(self):
        home = tempfile.mkdtemp()
        os.makedirs(home + "/guest")
        with open(home + "/guest/secret", "wb") as f:
            f.write(b"short")
        ib = Inbox(self.m, home, clock=self.clock)
        self.assertEqual(len(ib.secret), 32)
        with open(home + "/guest/secret", "rb") as f:
            self.assertEqual(f.read(), ib.secret)


class Files(M):
    def test_file_modes(self):
        self.fill(1)
        mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)
        self.assertEqual(mode(self.inbox.dir), 0o700)
        self.assertEqual(mode(self.inbox.dir / "secret"), 0o600)
        self.assertEqual(mode(self.inbox._side(self.tid)), 0o600)

    def test_sidecar_only_lists_live_requests(self):
        ids = self.fill(2)
        who = type("P", (), {})()
        ev = self.t.stored[ids[0]]
        who.id, who.sign_pub, who.kex_pub, who.name = ev["author"], ev["body"]["guest"]["sign"], ev["body"]["guest"]["kex"], "x"
        self.assertTrue(self.m.ingest(Writer(self.owner, self.t).add_member(who, "guest", admits=[ids[0]])).ok)   # admitted: no longer waiting
        self.assertNotIn(ids[0], self.t.awaiting)
        self.fill(1)
        side = json.loads(self.inbox._side(self.tid).read_text())
        self.assertEqual(set(side), set(self.t.awaiting))


class Door(M):
    def test_challenge_with_extra_frame_field_refused(self):
        r, _ = self.sub()
        self.assertEqual(self.inbox.handle({"t": "challenge", "thread": self.tid, "event": r["event"]})["t"], "refused")
        self.assertEqual(self.inbox.handle({"t": "challenge", "thread": self.tid, "pow": r["pow"]})["t"], "refused")

    def test_pow_object_with_extra_key_refused(self):
        r, ev = self.sub()
        r["pow"]["extra"] = 1
        self.assertEqual(self.inbox.handle(r)["t"], "refused")
        self.assertNotIn(event_id(ev), self.t.awaiting)

    def test_exception_inside_handle_becomes_refusal(self):
        def boom():
            raise RuntimeError("x")
        self.m.refresh = boom
        self.assertEqual(self.inbox.handle({"t": "challenge", "thread": self.tid}), {"t": "refused", "why": "internal"})

    def test_unknown_reply_to_reason_and_resolved_only(self):
        """reply_to must be a RESOLVED event of this thread (t.events), not just any stored event: a waiting request is not one."""
        (wid,) = self.fill(1)
        r, _ = self.sub(reply_to="a" * 32)
        self.assertEqual(self.inbox.handle(r)["why"], "unknown reply_to")
        r, _ = self.sub(reply_to=wid)
        self.assertEqual(self.inbox.handle(r)["why"], "unknown reply_to")
        self.assertEqual(len(self.t.awaiting), 1)

    def test_ok_answer_means_really_waiting(self):
        """An event the mirror does not queue (unknown admin_ref: parked) is refused, never answered ok."""
        who = Identity.generate("g")
        ev = make_event(who, thread=self.tid, kind="post", body={"text": "x", "reply_to": self.rid, "guest": {"name": "g", "sign": who.sign_pub, "kex": who.kex_pub}},
                        parents=[self.rid], seq=1, admin_ref="a" * 32, ts=int(self.clock()))
        r, _ = self.sub(who, ev=ev)
        out = self.inbox.handle(r)
        self.assertEqual(out["t"] == "ok", event_id(ev) in self.t.awaiting, out)
        self.assertEqual(out["t"], "refused")

    def test_idempotent_resubmit_does_not_evict_when_full(self):
        ids = self.fill(6)
        r, ev = self.sub(bits=4)
        self.assertEqual(self.inbox.handle(r)["why"], "queue full")
        # re-send an ALREADY waiting request (same proof, even with a stronger one): ok, and nothing else is displaced
        first = self.t.stored[ids[-1]]
        again = {"t": "submit", "thread": self.tid, "event": first, "pow": {"salt": self.inbox.salt(self.inbox.period()).hex(), "nonce": exact(
            self.inbox.salt(self.inbox.period()), self.tid, first["body"]["guest"]["sign"], ids[-1], 9)}}
        self.assertEqual(self.inbox.handle(again), {"t": "ok", "id": ids[-1]})
        self.assert_untouched(ids)

    def test_wake_only_for_owner_replies(self):
        calls = []
        self.inbox.on_wake = lambda tid, n: calls.append((tid, n))
        self.fill(1)
        self.assertEqual(calls, [(self.tid, 1)])
        pid = self.member_post()
        self.fill(1, reply_to=pid)
        self.assertEqual(calls, [(self.tid, 1)], "a general-lane request woke the owner")


class Precheck(M):
    """A request that fails any free-to-fake check must be refused BEFORE it displaces a legitimate waiting one, even with a very strong proof."""

    def setUp(self):
        super().setUp()
        self.ids = self.fill(6)

    def guest_ev(self, who, *, guest=None, kind="post", thread=None, author=None, extra=None, text="x"):
        g = guest if guest is not None else {"name": "g", "sign": who.sign_pub, "kex": who.kex_pub}
        ev = make_event(who, thread=thread or self.tid, kind=kind, body={"text": text, "reply_to": self.rid, "guest": g}, parents=[self.rid], seq=1,
                        admin_ref=self.t.head, ts=int(self.clock()))
        if author is not None:
            ev["author"] = author
        if extra:
            ev.update(extra)
        if author is not None or extra:
            ev["sig"] = who.sign(sign_input(ev))
        return ev

    def go(self, ev, who, why=None, bits=9):
        r, _ = self.sub(who, ev=ev, bits=bits)
        out = self.inbox.handle(r)
        self.assertEqual(out["t"], "refused", out)
        if why:
            self.assertEqual(out["why"], why)
        self.assert_untouched(self.ids)

    def test_author_must_be_guest_key(self):
        w = Identity.generate("w")
        self.go(self.guest_ev(w, author=Identity.generate("o").id), w, "bad guest keys")

    def test_invalid_kex_key(self):
        w = Identity.generate("w")
        self.go(self.guest_ev(w, guest={"name": "g", "sign": w.sign_pub, "kex": "00" * 32}), w, "bad guest keys")

    def test_bad_signature(self):
        w = Identity.generate("w")
        ev = self.guest_ev(w)
        ev["sig"] = ev["sig"][:-1] + ("0" if ev["sig"][-1] != "0" else "1")
        self.go(ev, w, "bad signature")

    def test_bad_structure(self):
        w = Identity.generate("w")
        self.go(self.guest_ev(w, extra={"zzz": 1}), w)

    def test_only_posts(self):
        w = Identity.generate("w")
        self.go(self.guest_ev(w, kind="digest"), w, "malformed")

    def test_event_of_another_thread(self):
        g2 = make_genesis(self.owner, "other", [], visibility="public", guest_policy=policy(), ts=int(self.clock()))
        self.assertTrue(self.m.ingest(g2).ok)
        w = Identity.generate("w")
        ev = Writer(w, self.m.threads[event_id(g2)]).guest_request("x", self.rid, ts=int(self.clock()))
        self.go(ev, w, "malformed")
        self.assertEqual(len(self.m.threads[event_id(g2)].awaiting), 0)

    def test_oversize_does_not_evict(self):
        w = Identity.generate("w")
        Base.setUp(self, max_bytes=1200)
        self.ids = self.fill(6)
        self.go(self.guest_ev(w, text="y" * 2000), w, "too large")


class Sizes(M):
    def test_size_limit_is_inclusive(self):
        probe = Writer(Identity.generate("g"), self.t).guest_request("please", self.rid, ts=int(self.clock()))
        size = len(encode(probe))
        Base.setUp(self, max_bytes=size)
        r, ev = self.sub(text="please")
        self.assertEqual(len(encode(ev)), size)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        r, _ = self.sub(text="pleasee")
        self.assertEqual(self.inbox.handle(r)["why"], "too large")


class Lanes(M):
    """queue_max 6, reserved_reply_slots 2: owner-reply lane up to 6, general lane up to 4, total 6; displacement only by strictly stronger proofs."""

    def test_general_lane_limit_and_equal_bits_refused(self):
        pid = self.member_post()
        ids = self.fill(4, reply_to=pid)
        r, _ = self.sub(reply_to=pid, bits=4)
        self.assertEqual(self.inbox.handle(r)["why"], "queue full")
        self.assert_untouched(ids)

    def test_owner_lane_items_do_not_fill_general_lane(self):
        pid = self.member_post()
        self.fill(4)
        r, ev = self.sub(reply_to=pid, bits=4)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertEqual(len(self.t.awaiting), 5)

    def test_general_request_cannot_displace_owner_reply(self):
        pid = self.member_post()
        ids = self.fill(6)
        r, _ = self.sub(reply_to=pid, bits=9)
        self.assertEqual(self.inbox.handle(r)["why"], "queue full")
        self.assert_untouched(ids)

    def test_owner_reply_displaces_general_not_owner_lane(self):
        pid = self.member_post()
        gen = self.fill(4, reply_to=pid, bits=4)
        own = self.fill(2, bits=7)
        r, ev = self.sub(bits=5)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertEqual(len(self.t.awaiting), 6)
        self.assertTrue(set(own) <= set(self.t.awaiting))
        self.assertIn(event_id(ev), self.t.awaiting)
        self.assertEqual(len(set(gen) & set(self.t.awaiting)), 3)

    def test_request_with_dependents_is_never_the_victim(self):
        ids = self.fill(1, bits=4) + self.fill(5, bits=5)
        dep = Writer(self.owner, self.t).post("a reply to a waiting request", reply_to=ids[0], ts=int(self.clock()))
        self.m.ingest(dep)
        self.assertTrue(self.t._has_dependents(ids[0]))
        r, ev = self.sub(bits=6)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertIn(ids[0], self.t.awaiting)
        self.assertIn(event_id(ev), self.t.awaiting)

    def test_failed_drop_means_refused(self):
        ids = self.fill(6)
        self.m.drop_awaiting = lambda *a: False
        r, _ = self.sub(bits=9)
        self.assertEqual(self.inbox.handle(r)["why"], "queue full")
        self.assert_untouched(ids)

    def test_pressure_raises_bits(self):
        """Admissions into a nearly full lane count as pressure; PRESSURE_N of them raise the challenge bits by one."""
        self.fill(4)
        for _ in range(12):
            r, ev = self.sub(bits=4)
            self.assertEqual(self.inbox.handle(r)["t"], "ok")
            self.assertTrue(self.inbox.reject(self.tid, event_id(ev)))
        self.assertEqual(self.chal()["bits"], 5)


# ------------------------------------------------------------------ publicread
class PR(unittest.TestCase):
    def setUp(self):
        from sigilnet.tests.test_public import setup
        self.m, self.owner, self.tid, self.rid = setup("public")
        self.srv = SyncServer(self.m, identity=self.owner)
        self.clock = Clock()

    def rq(self):
        return {"t": "summary", "thread": self.tid, "nonce": os.urandom(8).hex()}

    def test_defaults(self):
        pr = PublicRead(self.srv)
        self.assertEqual((pr.req_per_min, pr.bytes_per_min), (600, 40_000_000))

    def test_request_budget_window_edges(self):
        pr = PublicRead(self.srv, clock=self.clock, req_per_min=1)
        self.assertEqual(pr.handle(self.rq())["t"], "summary")
        self.clock.t += 59
        self.assertEqual(pr.handle(self.rq())["t"], "error")
        self.clock.t += 1                                      # exactly 60 s after the first hit: it has aged out
        self.assertEqual(pr.handle(self.rq())["t"], "summary")

    def test_byte_budget_edges(self):
        n = len(canon.dumps(PublicRead(self.srv, clock=self.clock).handle(self.rq())))
        pr = PublicRead(self.srv, clock=self.clock, bytes_per_min=n)
        self.assertEqual(pr.handle(self.rq())["t"], "summary")
        self.assertEqual(pr.handle(self.rq())["t"], "error")                # sent == budget: refused (>=)
        self.clock.t += 61                                                  # the bytes aged out after 60 s, not later
        self.assertEqual(pr.handle(self.rq())["t"], "summary")


# ------------------------------------------------------------------ guest
class FakeInbox:
    def __init__(self, tid, bits, answers):
        self.tid, self.bits, self.answers, self.sent = tid, bits, list(answers), []

    def ch(self):
        return {"t": "challenge", "thread": self.tid, "salt": "ab" * 16, "bits": self.bits}

    def request(self, req):
        if req["t"] == "challenge":
            return self.ch()
        self.sent.append(req)
        a = self.answers.pop(0) if self.answers else "stale"
        return {"t": "ok", "id": "x"} if a == "ok" else {**self.ch(), "t": "stale"}


class GuestRules(unittest.TestCase):
    def setUp(self):
        self.owner, self.me = Identity.generate("o"), Identity.generate("me")
        self.m = Mirror(tempfile.mkdtemp() + "/m", rate_limit=False)
        g = make_genesis(self.owner, "t", [], visibility="public", guest_policy=policy(max_bytes=4096))
        self.m.ingest(g)
        self.tid = event_id(g)
        root = Writer(self.owner, self.m.threads[self.tid]).post("hi")
        self.m.ingest(root)
        self.rid = event_id(root)

    def test_bits_limit_is_inclusive_and_solver_gets_full_bits(self):
        seen = []

        def solver(salt, tid, pub, eid, bits):
            seen.append(bits)
            return 7
        out = request_admission(FakeInbox(self.tid, MAX_ACCEPTED_BITS, ["ok"]), self.m, self.me, self.tid, "x", self.rid, solve=solver)
        self.assertEqual(out["t"], "ok")
        self.assertEqual(seen, [MAX_ACCEPTED_BITS])
        with self.assertRaises(GuestError):
            request_admission(FakeInbox(self.tid, MAX_ACCEPTED_BITS + 1, ["ok"]), self.m, self.me, self.tid, "x", self.rid, solve=solver)

    def test_attempts_are_bounded(self):
        fi = FakeInbox(self.tid, 4, [])
        with self.assertRaises(GuestError):
            request_admission(fi, self.m, self.me, self.tid, "x", self.rid, attempts=3, solve=lambda *a: 1)
        self.assertEqual(len(fi.sent), 3)

    def test_challenge_must_be_a_challenge_for_this_thread(self):
        class Bad(FakeInbox):
            def request(s, req):
                return s.resp
        for resp in ({"t": "refused", "why": "no"}, {"t": "ok", "thread": self.tid, "salt": "ab" * 16, "bits": 1},
                     {"t": "challenge", "thread": "f" * 32, "salt": "ab" * 16, "bits": 1}):
            b = Bad(self.tid, 1, [])
            b.resp = resp
            with self.assertRaises(GuestError):
                request_admission(b, self.m, self.me, self.tid, "x", self.rid, solve=lambda *a: 1)
            self.assertEqual(b.sent, [])

    def test_size_limit_is_inclusive(self):
        size = len(encode(Writer(self.me, self.m.threads[self.tid]).guest_request("x" * 10, "0" * 32)))
        m = Mirror(tempfile.mkdtemp() + "/m2", rate_limit=False)
        g = make_genesis(self.owner, "t2", [], visibility="public", guest_policy=policy(max_bytes=size))
        m.ingest(g)
        tid = event_id(g)
        root = Writer(self.owner, m.threads[tid]).post("hi")
        m.ingest(root)
        rid = event_id(root)
        self.assertEqual(request_admission(FakeInbox(tid, 1, ["ok"]), m, self.me, tid, "x" * 10, rid, solve=lambda *a: 1)["t"], "ok")
        with self.assertRaises(GuestError):
            request_admission(FakeInbox(tid, 1, ["ok"]), m, self.me, tid, "x" * 11, rid, solve=lambda *a: 1)

    def test_printable_is_bounded(self):
        self.assertEqual(len(_printable("x" * 500)), 80)
        self.assertEqual(_printable("a\x1b[31mb"), "a?[31mb")


# ------------------------------------------------------------------ capsule store
class StoreRecords(unittest.TestCase):
    def test_owner_door_name_is_validated(self):
        """A record whose owner_door is not exactly a peer door name is dropped on load (the name is later used as a path)."""
        from sigilnet.capsule import Store
        home = tempfile.mkdtemp()

        def rec(cid, **kw):
            return {"tok": "a" * 64, "thread": "b" * 32, "exp": 2_000_000_000, "door": f"join-{cid}", "types": ["onion"], "state": "confirmed", "at": 1,
                    "deadline": 2, "req": {"agent": "a" * 32, "sign": "c" * 64, "kex": "d" * 64, "name": "n",
                                           "offers": [{"endpoint": {"type": "onion", "addr": "a" * 56 + ".onion:1"}, "credential": {"type": "onion", "key": "A" * 52}}]}, **kw}
        recs = {"00000001": rec("00000001", owner_door="peer-" + "a" * 27), "00000002": rec("00000002", owner_door="../../x"),
                "00000003": rec("00000003", owner_door=5)}
        with open(home + "/capsules.json", "w") as f:
            json.dump(recs, f)
        got = Store(home).all()
        self.assertEqual(set(got), {"00000001"})


if __name__ == "__main__":
    unittest.main()
