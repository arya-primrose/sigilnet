"""The text of a pull/push failure when the peer's answer is not a sync reply (found by the first-join dry run, 2026-10-07: "response does not answer this request" said nothing)."""
import tempfile
import unittest

from sigilnet import sync as S
from sigilnet.mirror import Mirror
from sigilnet.tests.util import World


class Why(unittest.TestCase):
    REQ = {"nonce": "a" * 16, "t": "summary"}

    def test_each_kind_of_bad_answer_is_described(self):
        f = S.not_a_sync_answer
        base = "response does not answer this request"
        t = f(None, self.REQ)
        self.assertTrue(t.startswith(base + ": the peer sent NoneType"), t)
        self.assertIn("the peer sent str", f("junk", self.REQ))
        self.assertIn("the peer sent list", f([1], self.REQ))
        self.assertIn("its nonce differs", f({"t": "ok", "nonce": "b" * 16, "r": 1}, self.REQ))
        self.assertIn("its nonce differs", f({"t": "ok", "r": 1}, self.REQ))
        for r in (None, 0, 2, True, "1"):
            ans = {"t": "ok", "nonce": "a" * 16}
            if r is not None:
                ans["r"] = r
            self.assertIn("not marked as a response", f(ans, self.REQ), r)
        self.assertIn("not signed by the expected peer", f({"t": "ok", "nonce": "a" * 16, "r": 1}, self.REQ))
        for s in (t, f({"t": "ok", "nonce": "b" * 16, "r": 1}, self.REQ)):
            self.assertIn("a minute or two after a join", s)

    def test_peer_text_in_it_is_printable_and_short(self):
        hostile = {"t": "\x1b[2J\x07bell\nFAKE LINE " + "x" * 500, "nonce": "b" * 16, "r": 1}
        s = S.not_a_sync_answer(hostile, self.REQ)
        for bad in ("\x1b", "\x07", "\n"):
            self.assertNotIn(bad, s)
        self.assertLess(len(s), 330, len(s))
        self.assertIn("FAKE", s)                                   # (shown, as data, inside the quotes of the type)
        self.assertNotIn("x" * 30, s)
        self.assertEqual(S.not_a_sync_answer({"t": 5, "nonce": "b" * 16, "r": 1}, self.REQ).count("its type is"), 0)

    def test_pull_and_push_report_it(self):
        w = World()
        me = w.ids["sansa"]

        class Junk:
            def request(self_, req):
                return {"t": "summary", "nonce": "0" * 16, "r": 1}
        r = S.pull(Mirror(tempfile.mkdtemp(), rate_limit=False), w.t.id, Junk(), me)
        self.assertFalse(r["ok"])
        self.assertIn("response does not answer this request: its nonce differs", r["why"])
        self.assertIn("its type is 'summary'", r["why"])

    def test_push_reports_it(self):
        w = World()
        w.add(w.w("sansa").post("something to push"))
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        m.ingest(w.genesis)
        for i in w.t.order[1:]:
            m.ingest(w.t.events[i], live=False)

        class Junk:
            def request(self_, req):
                return {"t": "ok", "nonce": req["nonce"], "r": 1}                                  # (right nonce, but not signed by the peer)
        res = S.push(m, w.t.id, Junk(), w.ids["sansa"], set(m.threads[w.t.id].stored) - {w.t.id}, peer_id=w.ids["arya"].id)
        self.assertGreater(res["requests"], 0, res)
        self.assertIn("response does not answer this request: it is not signed by the expected peer", res["why"])


if __name__ == "__main__":
    unittest.main()
