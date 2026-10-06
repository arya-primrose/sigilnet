"""Guest requests reach inbox.jsonl through Mirror.note_guest, with today's wake conditions and today's WAKE_GAP (section 13 point 1, 6)."""
import tempfile
import unittest
from pathlib import Path

from sigilnet import inboxlog
from sigilnet import pow as P
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.inbox import Inbox
from sigilnet.inboxlog import InboxLog
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror

from .h import entries


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


def policy(**kw):
    return {"mode": "moderated", "pow_bits": 4, "queue_max": 60, "reserved_reply_slots": 2, "request_ttl_hours": 72, "max_bytes": 4096, **kw}


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.home = Path(tempfile.mkdtemp(prefix="adv12_guest_"))
        self.m = Mirror(self.home / "mirror", clock=self.clock, rate_limit=False, me="a" * 32, inbox=InboxLog(self.home, clock=self.clock))
        self.owner = Identity.generate("arya")
        g = make_genesis(self.owner, "open topic", [], visibility="public", guest_policy=policy(), ts=int(self.clock()))
        self.tid = event_id(g)
        self.assertEqual(self.m.ingest(g).status, "accepted")
        self.t = self.m.threads[self.tid]
        self.root = Writer(self.owner, self.t).post("hello world")
        self.assertTrue(self.m.ingest(self.root).ok)
        self.rid = event_id(self.root)
        self.inbox = Inbox(self.m, self.home, clock=self.clock)

    def req(self, reply_to=None, text="please", who=None):
        who = who or Identity.generate("g")
        ch = self.inbox.handle({"t": "challenge", "thread": self.tid})
        ev = Writer(who, self.t).guest_request(text, reply_to or self.rid, ts=int(self.clock()))
        s = bytes.fromhex(ch["salt"])
        n = P.solve(s, self.tid, who.sign_pub, event_id(ev), ch["bits"])
        return {"t": "submit", "thread": self.tid, "event": ev, "pow": {"salt": s.hex(), "nonce": n}}, ev

    def guest_lines(self):
        return [d for d in entries(self.home) if d.get("guest")]


class Lines(Base):
    def test_a_request_replying_to_an_owner_event_writes_one_guest_line(self):
        r, ev = self.req()
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        got = entries(self.home)
        self.assertEqual([(d["thread"], d.get("guest")) for d in got if d.get("guest")], [(self.tid, True)])
        self.assertEqual(len(got), 2)                                                   # (the owner's root post is line 1: a peer event)
        self.assertTrue(all(set(d) <= {"seq", "t", "thread", "guest"} for d in got))

    def test_a_reply_to_a_guest_request_writes_none(self):
        from unittest import mock
        with mock.patch.object(inboxlog, "GUEST_GAP", 0.0):                              # no collapse at all: the CONDITION (owner event) is what is tested
            r, ev = self.req()
            self.inbox.handle(r)
            n = len(entries(self.home))
            self.clock.t += 1
            r2, _ = self.req(reply_to=event_id(ev))
            self.inbox.handle(r2)                                                         # (today the door refuses it; admitted or not, it is not an owner reply)
            self.assertEqual(len(entries(self.home)), n)

    def test_a_request_replying_to_an_accepted_guest_event_writes_no_guest_line(self):
        """The wake is for requests that answer an OWNER event. Once the owner admitted guest 1, guest 2 can reply to that guest event: admitted, but not a wake."""
        from unittest import mock
        with mock.patch.object(inboxlog, "GUEST_GAP", 0.0):                              # no collapse at all: the CONDITION is what is tested
            who = Identity.generate("g1")
            r, ev = self.req(who=who)
            self.assertEqual(self.inbox.handle(r)["t"], "ok")
            self.assertTrue(self.m.ingest(Writer(self.owner, self.t).add_member(who, "guest", admits=[event_id(ev)])).ok)
            self.clock.t += 1
            n = len(self.guest_lines())
            self.assertEqual(n, 1)
            r2, _ = self.req(reply_to=event_id(ev))
            out = self.inbox.handle(r2)
            self.assertEqual(out["t"], "ok", out)                                       # it IS admitted (awaiting) ...
            self.assertEqual(len(self.guest_lines()), n)                                # ... and is NOT a wake

    def test_a_refused_or_duplicate_request_writes_none(self):
        from unittest import mock
        r, ev = self.req()
        self.inbox.handle(r)
        n = len(entries(self.home))
        self.inbox.handle(r)                                                            # an idempotent resubmit
        bad = dict(r)
        bad["pow"] = {"salt": r["pow"]["salt"], "nonce": 0}
        with mock.patch.object(inboxlog, "GUEST_GAP", 0.0):
            self.inbox.handle(r)
            self.inbox.handle(bad)
        self.assertEqual(len(entries(self.home)), n)

    def test_no_wake_json_anywhere_any_more(self):
        r, ev = self.req()
        self.inbox.handle(r)
        names = {p.name for p in self.home.rglob("*") if p.is_file()}
        self.assertNotIn("wake.json", names)
        self.assertNotIn("wake_seen.json", names)

    def test_a_mirror_without_an_inbox_log_still_admits_requests(self):
        m = Mirror(self.home / "mirror", clock=self.clock, rate_limit=False)
        ib = Inbox(m, self.home, clock=self.clock)
        r, ev = self.req()
        self.assertEqual(ib.handle(r)["t"], "ok")


class Flood(Base):
    def test_a_flood_of_strangers_leaves_a_handful_of_lines(self):
        for _ in range(40):
            self.clock.t += 0.5
            r, ev = self.req()
            self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertEqual(len(self.t.awaiting), 40)
        self.assertEqual(len(self.guest_lines()), 1, "40 requests in 20 s must be ONE wake (the 300 s gap), not 40")
        self.clock.t += inboxlog.GUEST_GAP + 1
        r, ev = self.req()
        self.inbox.handle(r)
        self.assertEqual(len(self.guest_lines()), 2)

    def test_peer_lines_are_not_swallowed_by_the_guest_gap(self):
        r, ev = self.req()
        self.inbox.handle(r)
        self.m.note_guest(self.tid)
        self.assertEqual(len(self.guest_lines()), 1)
        head = self.m.inbox.head()
        self.assertEqual(self.m.inbox.append(self.tid), head + 1)


if __name__ == "__main__":
    unittest.main()
