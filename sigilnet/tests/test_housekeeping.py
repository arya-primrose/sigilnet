import os
import tempfile
import unittest

from sigilnet import mirror as MM
from sigilnet.event import event_id
from sigilnet.inbox import PERIOD, Inbox
from sigilnet.mirror import Mirror
from sigilnet.tests.test_inbox import Base


class Prune(Base):
    def dpath(self):
        return self.m._dir(self.tid) / "dropped.jsonl"

    def drop_one(self):
        r, ev = self.req()
        self.assertEqual(self.inbox.handle(r)["t"], "ok")
        self.assertTrue(self.inbox.reject(self.tid, event_id(ev)))
        return r, ev

    def test_lines_carry_a_time_and_replay_block_still_works(self):
        r, ev = self.drop_one()
        self.assertEqual(self.dpath().read_text().split(), [event_id(ev), str(int(self.clock()))])
        self.assertEqual(self.inbox.handle(r), {"t": "refused", "why": "rejected earlier"})

    def test_old_entries_are_pruned_and_a_replay_then_fails_on_its_salt(self):
        r, ev = self.drop_one()
        self.clock.t += MM.DROPPED_MAX_AGE + 60
        self.assertEqual(self.m.prune_dropped(self.tid), 1)
        self.assertEqual(self.dpath().read_text(), "")
        out = self.inbox.handle(r)                       # no replay block any more, but the proof is bound to a salt older than two periods
        self.assertEqual(out["t"], "stale")
        self.assertNotIn(event_id(ev), self.t.awaiting)

    def test_recent_entries_survive_and_cap_keeps_the_newest(self):
        old = MM.DROPPED_MAX_LINES
        MM.DROPPED_MAX_LINES = 3
        try:
            ids = []
            for _ in range(5):
                ids.append(event_id(self.drop_one()[1]))
            self.assertEqual(self.m.prune_dropped(self.tid), 3)           # over the cap: down to 80 % (2 of 3), newest kept
            self.assertEqual([l.split()[0] for l in self.dpath().read_text().splitlines()], ids[3:])
        finally:
            MM.DROPPED_MAX_LINES = old

    def test_legacy_lines_without_time_are_stamped_not_lost(self):
        r, ev = self.drop_one()
        self.dpath().write_text(event_id(ev) + "\n")
        self.m.prune_dropped(self.tid)
        self.assertEqual(self.dpath().read_text().split(), [event_id(ev), str(int(self.clock()))])
        self.assertEqual(self.inbox.handle(r), {"t": "refused", "why": "rejected earlier"})

    def test_other_process_notices_a_prune_and_still_applies_new_drops(self):
        m2 = Mirror(self.home + "/mirror", clock=self.clock, rate_limit=False)
        r1, e1 = self.drop_one()
        m2.refresh() if hasattr(m2, "refresh") else None
        self.clock.t += MM.DROPPED_MAX_AGE + 60
        self.m.prune_dropped(self.tid)
        r2, e2 = self.req()
        self.assertEqual(self.inbox.handle(r2)["t"], "ok")
        self.assertTrue(self.inbox.reject(self.tid, event_id(e2)))     # appended after the prune: m2 must read it from the NEW file
        m2.refresh()
        self.assertNotIn(event_id(e2), m2.threads[self.tid].awaiting)

    def test_auto_prune_when_the_file_grows(self):
        old = MM.DROPPED_PRUNE_AT
        MM.DROPPED_PRUNE_AT = 200
        try:
            self.drop_one()
            self.clock.t += MM.DROPPED_MAX_AGE + 60
            for _ in range(5):
                self.drop_one()
            self.assertLessEqual(len(self.dpath().read_text().splitlines()), 5)
        finally:
            MM.DROPPED_PRUNE_AT = old


class Generation(Base):
    def test_f3_generation_counts_prunes_and_stale_offset_resets_even_with_same_inode(self):
        dp = self.m._dir(self.tid) / "dropped.jsonl"
        for _ in range(2):
            r, ev = self.req()
            self.inbox.handle(r)
            self.inbox.reject(self.tid, event_id(ev))
        g0 = Mirror.drop_generation(dp)
        self.clock.t += MM.DROPPED_MAX_AGE + 60
        self.assertEqual(self.m.prune_dropped(self.tid), 2)
        self.assertEqual(Mirror.drop_generation(dp), g0 + 1)
        r, ev = self.req()
        self.inbox.handle(r)
        self.inbox.reject(self.tid, event_id(ev))
        self.clock.t += MM.DROPPED_MAX_AGE + 60
        self.assertEqual(self.m.prune_dropped(self.tid), 1)         # a second prune: an EVEN number, inode numbers may repeat, the counter does not
        self.assertEqual(Mirror.drop_generation(dp), g0 + 2)

    def test_f3_offset_beyond_file_size_resets(self):
        m2 = Mirror(self.home + "/mirror", clock=self.clock, rate_limit=False)
        dp = self.m._dir(self.tid) / "dropped.jsonl"
        r, ev = self.req()
        self.inbox.handle(r)
        m2.drop_offsets[self.tid] = 10_000                         # a stale offset from before a prune
        self.inbox.reject(self.tid, event_id(ev))
        m2.refresh()
        self.assertNotIn(event_id(ev), m2.threads[self.tid].awaiting)

    def test_cap_prune_goes_to_80_percent(self):
        old = MM.DROPPED_MAX_LINES
        MM.DROPPED_MAX_LINES = 10
        try:
            for _ in range(11):
                r, ev = self.req()
                self.inbox.handle(r)
                self.inbox.reject(self.tid, event_id(ev))
            dp = self.m._dir(self.tid) / "dropped.jsonl"
            self.m.prune_dropped(self.tid)
            self.assertEqual(len(dp.read_text().splitlines()), 8)
        finally:
            MM.DROPPED_MAX_LINES = old


if __name__ == "__main__":
    unittest.main()
