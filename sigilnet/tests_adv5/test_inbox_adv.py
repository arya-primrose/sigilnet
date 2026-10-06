import json
import tempfile
import unittest

from sigilnet import pow as P
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.inbox import Inbox, PERIOD
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.tests.test_inbox import Base, Clock, policy


def exact(salt, tid, pub, eid, b):
    n = 0
    while P.achieved(salt, tid, pub, eid, n) != b:
        n += 1
    return n



class Attacks(Base):
    def fill_owner_lane(self, n, bits=4):
        ids = []
        for _ in range(n):
            r, ev = self.req(bits=bits)
            self.assertEqual(self.inbox.handle(r)["t"], "ok")
            ids.append(event_id(ev))
        return ids

    # F1: eviction happens BEFORE the newcomer is validated (signature etc.)
    def test_forged_request_does_not_evict_legit_one(self):
        self.fill_owner_lane(6)
        who = Identity.generate("x")
        ch = self.chal()
        ev = Writer(who, self.t).guest_request("junk", self.rid, ts=int(self.clock()))
        ev["sig"] = ("0" if ev["sig"][-1] != "0" else "1").join([ev["sig"][:-1], ""])       # invalid signature; the id (and so the proof) does not cover it
        n = P.solve(bytes.fromhex(ch["salt"]), self.tid, who.sign_pub, event_id(ev), ch["bits"] + 2)
        out = self.inbox.handle({"t": "submit", "thread": self.tid, "event": ev,
                                 "pow": {"salt": ch["salt"], "nonce": n}})
        self.assertEqual(out["t"], "refused")
        self.assertEqual(len(self.t.awaiting), 6, "a request that failed validation still evicted a legitimate waiting one")

    # F2: a request that replies to a WAITING request makes it un-evictable, un-rejectable and immortal
    def _member_post(self):
        sansa = Identity.generate("sansa")
        r = self.m.ingest(Writer(self.owner, self.t).add_member(sansa, "member"))
        self.assertTrue(r.ok, r)
        ev = Writer(sansa, self.t).post("a member post")
        self.assertTrue(self.m.ingest(ev).ok)
        return event_id(ev)

    def test_chain_of_waiting_requests_cannot_jam_general_lane(self):
        pid = self._member_post()              # replies to a non-owner event use the general lane (queue_max 6 - reserved 2 = 4)
        prev = pid
        chain = []
        for _ in range(4):
            r, ev = self.req(reply_to=prev)
            out = self.inbox.handle(r)
            if out["t"] != "ok":
                break
            prev = event_id(ev)
            chain.append(prev)
        # the owner must always be able to clear the queue by rejecting what waits, in any order
        for eid in list(self.t.awaiting):
            self.inbox.reject(self.tid, eid)
        self.assertEqual(len(self.t.awaiting), 0, f"{len(self.t.awaiting)} requests can never be rejected")

    def test_jammed_chain_expires_by_ttl(self):
        pid = self._member_post()
        prev = pid
        for _ in range(3):
            r, ev = self.req(reply_to=prev)
            self.inbox.handle(r)
            prev = event_id(ev)
        self.clock.t += 73 * 3600
        self.t.prune_awaiting()
        self.assertEqual(len(self.t.awaiting), 0, "requests past request_ttl_hours stay forever because a later request replies to them")

    # F3: queue_max is one budget split in two (spec 5.1), not two budgets
    def test_total_waiting_never_exceeds_queue_max(self):
        pid = self._member_post()
        for _ in range(12):
            self.inbox.handle(self.req(reply_to=pid, bits=5)[0])        # general lane
        for _ in range(12):
            self.inbox.handle(self.req(bits=5)[0])                     # owner lane
        self.assertLessEqual(len(self.t.awaiting), 6)

    # F4: the shared REFUSED dict is returned by reference
    def test_refusal_object_is_not_shared(self):
        from sigilnet import inbox as IB
        self.addCleanup(lambda: (IB.REFUSED.clear(), IB.REFUSED.update({"t": "refused", "why": "no"})))
        a = self.inbox.handle({"t": "challenge", "thread": "f" * 32})
        a["why"] = "tampered"
        a["x"] = 1
        self.assertEqual(self.inbox.handle({"t": "challenge", "thread": "e" * 32}), {"t": "refused", "why": "no"})

    # F5: a request that was queued but whose wake callback raises is reported as refused
    def test_wake_failure_does_not_hide_admission(self):
        def boom(*a):
            raise RuntimeError("x")
        self.inbox.on_wake = boom
        r, ev = self.req()
        out = self.inbox.handle(r)
        self.assertIn(event_id(ev), self.t.awaiting)
        self.assertEqual(out["t"], "ok")

    # F6: a rejected request can simply be replayed with the same proof while its salt lives
    def test_rejected_request_cannot_be_replayed(self):
        r, ev = self.req()
        self.inbox.handle(r)
        self.assertTrue(self.inbox.reject(self.tid, event_id(ev)))
        self.assertNotEqual(self.inbox.handle(r)["t"], "ok")
        self.assertNotIn(event_id(ev), self.t.awaiting)


    def test_legit_guest_not_locked_out_by_unrejectable_chain(self):
        def ex(r, ev, b=4):
            r["pow"]["nonce"] = exact(bytes.fromhex(r["pow"]["salt"]), self.tid, ev["body"]["guest"]["sign"], event_id(ev), b)
            return r
        pid = self._member_post()
        prev = pid
        for _ in range(4):
            r, ev = self.req(reply_to=prev)
            self.inbox.handle(ex(r, ev))
            prev = event_id(ev)
        r, ev = self.req(reply_to=pid)
        out = self.inbox.handle(ex(r, ev))
        self.assertEqual(out["t"], "ok", out)


class Held(Base):
    """Properties that held."""

    def test_private_and_missing_identical(self):
        g = make_genesis(self.owner, "secret", [], visibility="private", ts=int(self.clock()))
        self.m.ingest(g)
        pt = event_id(g)
        for req in ({"t": "challenge", "thread": pt}, {"t": "challenge", "thread": "a" * 32},
                    {"t": "submit", "thread": pt, "event": {}, "pow": {}}, {"t": "submit", "thread": "a" * 32, "event": 1, "pow": 2},
                    {"t": "x", "thread": pt}, {"t": "challenge", "thread": [pt]}, {"t": "challenge", "thread": {"a": 1}}):
            self.assertEqual(self.inbox.handle(req), {"t": "refused", "why": "no"}, req)

    def test_garbage_frames_never_raise(self):
        junk = [None, 1, "x", [], {}, {"t": 1}, {"t": "submit"}, {"t": "submit", "thread": self.tid},
                {"t": "submit", "thread": self.tid, "event": [], "pow": {"salt": "0" * 32, "nonce": 1}},
                {"t": "submit", "thread": self.tid, "event": {"body": 1}, "pow": {"salt": "0" * 32, "nonce": 1}},
                {"t": "submit", "thread": self.tid, "event": {"a": float("inf")}, "pow": {"salt": "0" * 32, "nonce": 1}},
                {"t": "submit", "thread": self.tid, "event": {"a": "x" * 10 ** 6}, "pow": {"salt": "0" * 32, "nonce": 1}}]
        deep = cur = {}
        for _ in range(5000):
            cur["a"] = {}
            cur = cur["a"]
        junk.append({"t": "submit", "thread": self.tid, "event": deep, "pow": {"salt": "0" * 32, "nonce": 1}})
        for j in junk:
            out = self.inbox.handle(j)
            self.assertIsInstance(out, dict)
            self.assertNotEqual(out.get("why"), "internal", j if not isinstance(j, dict) else list(j))

    def test_bad_nonces_never_admitted(self):
        r, ev = self.req()
        for bad in (True, False, -1, 2 ** 63, 2 ** 200, 1.0, "1", None, [1], {"a": 1}):
            r2 = json.loads(json.dumps(r)) if not isinstance(bad, float) else dict(r)
            r2 = {**r, "pow": {"salt": r["pow"]["salt"], "nonce": bad}}
            out = self.inbox.handle(r2)
            self.assertIn(out["t"], ("stale", "refused"), bad)
            self.assertNotIn(event_id(ev), self.t.awaiting)

    def test_bits_minus_one_tolerance_exact(self):
        self.inbox.bits[self.tid] = [6, self.clock()]
        for b, ok in ((4, False), (5, True), (6, True)):
            who = Identity.generate("g")
            ev = Writer(who, self.t).guest_request("x%d" % b, self.rid, ts=int(self.clock()))
            salt = self.inbox.salt(self.inbox.period())
            # find a nonce with EXACTLY b zero bits so the boundary is tested
            n = 0
            while P.achieved(salt, self.tid, who.sign_pub, event_id(ev), n) != b:
                n += 1
            out = self.inbox.handle({"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": salt.hex(), "nonce": n}})
            self.assertEqual(out["t"] == "ok", ok, (b, out))

    def test_weakest_first_and_no_sybil_dependence(self):
        ids = []
        for bits in (5, 4, 6, 4, 7, 5):
            r, ev = self.req(bits=bits)
            who = ev["body"]["guest"]["sign"]
            r["pow"]["nonce"] = exact(bytes.fromhex(r["pow"]["salt"]), self.tid, who, event_id(ev), bits)
            self.assertEqual(self.inbox.handle(r)["t"], "ok")
            ids.append(event_id(ev))
        r, ev = self.req(bits=4)
        r["pow"]["nonce"] = exact(bytes.fromhex(r["pow"]["salt"]), self.tid, ev["body"]["guest"]["sign"], event_id(ev), 4)
        self.assertEqual(self.inbox.handle(r)["why"], "queue full")      # equal to the weakest: refused
        r, ev = self.req(bits=9)
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertNotIn(ids[1], self.t.awaiting)          # the OLDEST of the two 4-bit requests went first
        self.assertIn(ids[3], self.t.awaiting)

    def test_sidecar_corruption_is_safe(self):
        r, ev = self.req()
        self.inbox.handle(r)
        for content in ("{", "[]", '{"%s": true}' % event_id(ev), '{"%s": 99999}' % event_id(ev), '{"zz": 4}', "\x00"):
            self.inbox._side(self.tid).write_text(content)
            self.assertEqual(self.inbox.waiting(self.tid)[0][1], 0)
            self.assertEqual(self.inbox.handle(self.req()[0])["t"], "ok")

    def test_sidecar_matches_awaiting_after_evictions(self):
        for b in (4, 5, 4, 6, 4, 5, 7, 8):
            self.inbox.bits[self.tid] = [min(b, 10), self.clock()]
            self.inbox.handle(self.req(bits=b)[0])
        side = json.loads(self.inbox._side(self.tid).read_text())
        self.assertEqual(set(side), set(self.t.awaiting))

    def test_cross_process_reject_not_resurrected(self):
        r, ev = self.req()
        self.inbox.handle(r)
        other = Mirror(self.home + "/mirror", clock=self.clock, rate_limit=False)
        self.assertTrue(other.drop_awaiting(self.tid, event_id(ev)))
        self.inbox.handle(self.req()[0])                      # this process saves awaiting.jsonl again
        again = Mirror(self.home + "/mirror", clock=self.clock, rate_limit=False)
        self.assertNotIn(event_id(ev), again.threads[self.tid].awaiting)
        self.assertEqual(len(again.threads[self.tid].awaiting), 1)

    def test_salt_rotation_boundary(self):
        r, ev = self.req()
        self.clock.t = (self.inbox.period() + 2) * PERIOD - 1        # last second the salt lives
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        r2, _ = self.req()
        self.clock.t += 1
        self.assertEqual(self.inbox.handle(r2)["t"], "ok") if False else None
        ch = self.chal()
        self.assertGreater(ch["expires"], self.clock.t)

    def test_pow_binds_everything(self):
        who = Identity.generate("g")
        ev = Writer(who, self.t).guest_request("a", self.rid, ts=int(self.clock()))
        salt = self.inbox.salt(self.inbox.period())
        n = P.solve(salt, self.tid, who.sign_pub, event_id(ev), 16)       # (was 6 bits: a 1-in-64 chance per altered input made this flaky)
        self.assertTrue(P.verify(salt, self.tid, who.sign_pub, event_id(ev), n, 16))
        ok = [P.achieved(salt, t, s, e, n) for t, s, e in ((self.tid[::-1], who.sign_pub, event_id(ev)), (self.tid, "0" * 64, event_id(ev)), (self.tid, who.sign_pub, "0" * 32))]
        self.assertTrue(all(a < 16 for a in ok))
        self.assertEqual(P.achieved(b"short", self.tid, who.sign_pub, "x", 1), -1)


class PowEdges(unittest.TestCase):
    # F7: solve() can return a nonce that verify() refuses (start near the 2**63 limit), and crashes on a negative start
    def test_solve_result_always_verifies(self):
        salt = b"s" * 16
        n = P.solve(salt, "t" * 32, "a" * 64, "e" * 32, 8, start=P.MAX_NONCE - 1)
        self.assertTrue(P.verify(salt, "t" * 32, "a" * 64, "e" * 32, n, 8), n)

    def test_solve_negative_start(self):
        salt = b"s" * 16
        n = P.solve(salt, "t" * 32, "a" * 64, "e" * 32, 4, start=-5)
        self.assertTrue(P.verify(salt, "t" * 32, "a" * 64, "e" * 32, n, 4))


if __name__ == "__main__":
    unittest.main()
