"""Conversation conventions (DESIGN_converse.md 3a): tags, strict opt-in quiet rule, awaiting, answered/overdue, sanitising. Pure functions."""
import unittest

from sigilnet import convo as C

ME, PEER, OTHER = "me", "peer", "other"


def ev(text, author=PEER, reply=None):
    return {"author": author, "text": text, "reply_to": reply}


class Parse(unittest.TestCase):
    def test_tags_are_exact_prefix_at_char_0_and_case_sensitive(self):
        for text, tag in (("[ASK] x", "[ASK]"), ("[DONE] x", "[DONE]"), ("[FYI] x", "[FYI]"), ("[STATUS?]", "[STATUS?]"), ("[STATUS] up", "[STATUS]"),
                          ("[ASK]nospace", "[ASK]")):
            self.assertEqual(C.parse(text)[0], tag, text)
        for text in (" [ASK] x", "\n[FYI] x", "[ask] x", "[Fyi] x", "[FYI x", "x [ASK]", "", "[STATUSX]", "[ASKS] x"):
            self.assertIsNone(C.parse(text)[0], repr(text))
        self.assertEqual(C.parse("[STATUS?] now"), ("[STATUS?]", " now"), "the probe is not mistaken for the answer tag")
        self.assertEqual(C.parse(None), (None, ""))
        self.assertEqual(C.parse(7), (None, ""))


class Classify(unittest.TestCase):
    def cl(self, text, author=PEER, reply=None, tags=None, wait=()):
        return C.classify(ev(text, author, reply), ME, tags or {}, set(wait))

    def test_wake_by_default_and_for_every_non_quiet_tag(self):
        for t in ("[ASK] do it", "[STATUS?]", "[STATUS] up", "plain words", "[WHAT] unknown tag", "", " [FYI] leading space is not a tag"):
            self.assertEqual(self.cl(t), "wake", t)

    def test_my_own_events_never_wake(self):
        self.assertEqual(self.cl("[ASK] x", author=ME), "own")
        self.assertEqual(self.cl("[FYI] x", author=ME), "own")

    def test_fyi_is_quiet_only_when_explicit_and_not_an_answer(self):
        self.assertEqual(self.cl("[FYI] phase 3 passed"), "quiet")
        self.assertEqual(self.cl("[FYI] phase 3 passed", reply="m1", tags={"m1": "[ASK]"}), "wake", "an FYI linked to my ask is the answer")
        self.assertEqual(self.cl("[FYI] phase 3 passed", reply="m2", tags={"m2": None}), "quiet", "linked to a non-ask of mine stays quiet")
        self.assertEqual(self.cl("[FYI] phase 3 passed", wait=[PEER]), "wake", "an awaited author's FYI wakes")
        self.assertEqual(self.cl("[FYI] phase 3 passed", wait=[OTHER]), "quiet", "someone else being awaited does not wake for this author")

    def test_done_quiet_only_when_linked_and_not_to_my_ask(self):
        self.assertEqual(self.cl("[DONE] ok"), "wake", "an unlinked DONE always wakes")
        self.assertEqual(self.cl("[DONE] ok", reply="m1", tags={"m1": "[ASK]"}), "wake")
        self.assertEqual(self.cl("[DONE] ok", reply="m2", tags={"m2": "[DONE]"}), "quiet")
        self.assertEqual(self.cl("[DONE] ok", reply="zzz"), "quiet", "linked to someone else's event")
        self.assertEqual(self.cl("[DONE] ok", reply=""), "wake", "an empty link is no link")
        self.assertEqual(self.cl("[DONE] ok", reply=5), "wake", "a junk link is no link")

    def test_an_awaited_authors_done_wakes_even_when_linked_to_something_else_of_mine(self):
        """Sansa's F1: same case as the r30a inbox fix: the answer arrives shaped like a quiet message."""
        self.assertEqual(self.cl("[DONE] ok", reply="old", tags={"old": "[FYI]"}, wait=[PEER]), "wake")
        self.assertEqual(self.cl("[DONE] ok", reply="old", tags={"old": "[FYI]"}, wait=[OTHER]), "quiet")

    def test_a_missing_id_in_my_tags_reads_as_not_my_ask(self):
        """Documented contract: callers pass ALL my events (a bounded subset would make a linked DONE to my ASK quiet)."""
        self.assertEqual(self.cl("[DONE] ok", reply="m1", tags={}), "quiet")
        many = {f"e{i}": None for i in range(5000)}
        many["m1"] = "[ASK]"
        self.assertEqual(self.cl("[DONE] ok", reply="m1", tags=many), "wake")

    def test_a_long_done_is_not_special(self):
        self.assertEqual(self.cl("[DONE] " + "x" * 5000, reply="m2", tags={"m2": None}), "quiet")
        self.assertEqual(self.cl("[DONE] " + "x" * 5000), "wake")

    def test_the_veto_is_an_extra_and_matches_whole_words_only(self):
        for t in ("[FYI] can you look at this?", "[FYI] Please look", "[FYI] URGENT", "[FYI] we are blocked"):
            self.assertEqual(self.cl(t), "wake", t)
        for t in ("[FYI] I reviewed it, needless to say fine", "[FYI] pleased with it", "[FYI] unblocked now", "[FYI] the review is done"):
            self.assertEqual(self.cl(t), "quiet", t)
        self.assertEqual(self.cl("[DONE] fine?", reply="m2", tags={"m2": None}), "wake")

    def test_junk_events_do_not_crash(self):
        for e in ({}, {"author": PEER}, {"author": PEER, "text": None}, {"author": PEER, "text": 5, "reply_to": ["x"]}):
            self.assertIn(C.classify(e, ME, {}, set()), ("wake", "quiet", "own"))
        self.assertEqual(C.classify({"author": PEER, "text": "[FYI] x", "reply_to": ["x"]}, ME, {}, set()), "quiet")


class Awaiting(unittest.TestCase):
    NOW = 10_000.0

    def ask(self, **kw):
        return {"id": "a1", "to": PEER, "at": self.NOW - 60, "answered": False, **kw}

    def test_only_an_addressed_unanswered_recent_ask_to_a_current_member_awaits(self):
        self.assertEqual(C.awaited([self.ask()], {PEER}, self.NOW), {PEER})
        self.assertEqual(C.awaited([self.ask(to=None)], {PEER}, self.NOW), set(), "an ask without --to awaits nobody")
        self.assertEqual(C.awaited([self.ask(answered=True)], {PEER}, self.NOW), set())
        self.assertEqual(C.awaited([self.ask(at=self.NOW - C.AWAIT_WINDOW - 1)], {PEER}, self.NOW), set(), "45 min of local time")
        self.assertEqual(C.awaited([self.ask(at=self.NOW - C.AWAIT_WINDOW)], {PEER}, self.NOW), {PEER}, "the boundary is inclusive")
        self.assertEqual(C.awaited([self.ask()], {OTHER}, self.NOW), set(), "a removed member is not awaited")
        self.assertEqual(C.awaited([self.ask(at=self.NOW + 500)], {PEER}, self.NOW), set(), "an ask stamped in the future (clock jump) awaits nothing")


class Answered(unittest.TestCase):
    def test_linked_reply_or_the_addressee_posting_after_it(self):
        ask = {"id": "a1", "to": PEER, "at": 0}
        self.assertTrue(C.answered(ask, [{"author": OTHER, "reply_to": "a1", "at": 5}], ME, {PEER, OTHER}))
        self.assertTrue(C.answered(ask, [{"author": PEER, "reply_to": None, "at": 5}], ME, {PEER}), "the awaited author's later event answers")
        self.assertFalse(C.answered(ask, [{"author": PEER, "reply_to": None, "at": 5}], ME, {OTHER}), "a removed addressee never answers")
        self.assertFalse(C.answered(ask, [{"author": OTHER, "reply_to": None, "at": 5}], ME, {PEER, OTHER}), "someone else posting is not an answer")
        self.assertFalse(C.answered(ask, [{"author": ME, "reply_to": "a1", "at": 5}], ME, {PEER}), "my own events answer nothing")
        self.assertFalse(C.answered({"id": "a2", "to": None, "at": 0}, [{"author": PEER, "reply_to": None, "at": 5}], ME, {PEER}), "no addressee: only links count")
        self.assertFalse(C.answered(ask, [], ME, {PEER}))
        self.assertFalse(C.answered({"id": "a3", "to": None, "at": 0}, [{"author": None, "reply_to": None, "at": 5}], ME, {None, PEER}), "a junk event never answers an unaddressed ask")

    def test_overdue_window_is_10_min_to_24_h_of_local_time(self):
        a = {"id": "a1", "at": 0}
        self.assertFalse(C.overdue(a, False, 599))
        self.assertTrue(C.overdue(a, False, 600))
        self.assertTrue(C.overdue(a, False, 86400))
        self.assertFalse(C.overdue(a, False, 86401))
        self.assertFalse(C.overdue(a, True, 3000))


class Sanitize(unittest.TestCase):
    def test_controls_bidi_zero_width_and_newlines_are_removed(self):
        s = "a\x00b\x1b[31mred‮txt​z⁦y﻿ q\r\nr\tz\x7f"
        out = C.sanitize(s)
        self.assertEqual(out, "ab[31mredtxtzy q r z")
        for bad in ("\x00", "\x1b", "‮", "​", "⁦", "﻿", "\x7f", "\n", "\r", "\t", " "):
            self.assertNotIn(bad, out)

    def test_truncation_marks_the_cut_and_never_exceeds_the_limit(self):
        self.assertEqual(C.sanitize("x" * 120), "x" * 120)
        out = C.sanitize("x" * 5000)
        self.assertEqual((len(out), out[-3:]), (120, "..."))
        self.assertEqual(len(C.sanitize("y " * 500, 10)), 10)
        self.assertEqual(C.sanitize("   \n  "), "")
        self.assertEqual(C.sanitize(None), "")
        self.assertEqual(C.sanitize(b"bytes"), "")

    def test_line_shows_only_a_12_char_id_and_the_sanitised_head(self):
        out = C.line("a" * 32, "[FYI] hello\x1b[0m‮" + "z" * 500)
        self.assertEqual(out[:14], "a" * 12 + ": ")
        self.assertLessEqual(len(out), 14 + C.LINE_MAX)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)
        self.assertEqual(C.line("ab\x1b\u202ecd", "x")[:6], "abcd: ", "the id is sanitised too")


if __name__ == "__main__":
    unittest.main()
