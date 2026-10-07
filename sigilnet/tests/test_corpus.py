"""The format-1 CONFORMANCE CORPUS (tests/corpus/, written by the genuine v0.1.1 package and frozen): every release must replay each frozen thread to exactly the derived state
the writer recorded, in any arrival order, and must keep refusing the frozen must-reject events. A change that alters any expected value is a format change and fails here
(DESIGN_versioning.md 5a.4)."""
import json
import random
import unittest
from pathlib import Path

from sigilnet import canon
from sigilnet.thread import Thread

from .corpus.make_corpus import summary

DIR = Path(__file__).parent / "corpus"
SCENARIOS = sorted(p.name for p in DIR.iterdir() if p.is_dir() and (p / "events.jsonl").exists())


def load(name):
    evs = [canon.loads(line) for line in (DIR / name / "events.jsonl").read_bytes().splitlines() if line]
    g = next(e for e in evs if e["kind"] == "genesis")
    return g, [e for e in evs if e is not g]


class Corpus(unittest.TestCase):
    def test_the_corpus_is_there(self):
        self.assertGreaterEqual(len(SCENARIOS), 7)

    def test_replay_equals_the_recorded_state_in_every_order(self):
        for name in SCENARIOS:
            want = json.loads((DIR / name / "expected.json").read_text())
            g, rest = load(name)
            for order in ("file", "reversed", "shuffled"):
                evs = list(rest)
                if order == "reversed":
                    evs.reverse()
                elif order == "shuffled":
                    random.Random(7).shuffle(evs)
                t = Thread(g)
                for _ in range(3):                                   # events parked behind a missing parent resolve on a later pass
                    for e in evs:
                        t.accept(e)
                self.assertEqual(summary(t), want, f"{name} ({order})")

    def test_bulk_load_from_disk_equals_the_recorded_state(self):
        for name in SCENARIOS:
            want = json.loads((DIR / name / "expected.json").read_text())
            g, rest = load(name)
            t = Thread(g)
            t.add_many(rest)
            self.assertEqual(summary(t), want, name)

    def test_the_must_reject_events_stay_rejected(self):
        n = 0
        for name in SCENARIOS:
            rej = json.loads((DIR / name / "reject.json").read_text())
            g, rest = load(name)
            t = Thread(g)
            for _ in range(3):
                for e in rest:
                    t.accept(e)
            for r in rej:
                n += 1
                self.assertEqual(t.accept(r["event"]).status, "rejected", f"{name}: {r['why']}")
        self.assertGreaterEqual(n, 10)


if __name__ == "__main__":
    unittest.main()
