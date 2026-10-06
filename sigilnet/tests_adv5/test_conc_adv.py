import json
import threading

from sigilnet.event import event_id
from sigilnet.tests.test_inbox import Base


class Conc(Base):
    def test_parallel_submissions_keep_bounds_and_sidecar(self):
        reqs = [self.req(bits=4 + (i % 4))[0] for i in range(40)]
        outs = []
        ts = [threading.Thread(target=lambda r=r: outs.append(self.inbox.handle(r))) for r in reqs]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertTrue(all(o["t"] in ("ok", "refused") and o.get("why") != "internal" for o in outs))
        self.assertLessEqual(len(self.t.awaiting), 6)
        side = json.loads(self.inbox._side(self.tid).read_text())
        self.assertEqual(set(side), set(self.t.awaiting))
        # survivors are the strongest ones
        self.assertGreaterEqual(min(side.values()), 4)
