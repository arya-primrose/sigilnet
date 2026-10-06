import tempfile
import unittest

from sigilnet import event as E
from sigilnet.event import event_id
from sigilnet.mirror import Mirror
from sigilnet.thread import MAX_PENDING_PER_AUTHOR as MAX_PENDING_PER_THREAD

from .util2 import Net


class PendingBuffer(unittest.TestCase):
    def test_pending_memory_is_bounded(self):
        net = Net()
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        m.ingest(net.genesis)
        for i in range(2500):
            ghost = format(i, "032x")
            m.ingest(E.make_event(net.ids["dave"], thread=net.tid, kind="post", body={"text": "x" * 200}, parents=[ghost], seq=i, admin_ref=net.tid, ts=i), live=False)
        self.assertLessEqual(len(m.pending), MAX_PENDING_PER_THREAD)

    def test_one_author_cannot_evict_another_authors_parked_event(self):
        # BUG (low): eviction is FIFO per thread, not per author: a member (or any known key: only the signature is checked before parking)
        # who parks 300 events with unknown parents pushes out an honest member's parked event, which is then lost when its parent arrives
        net = Net()
        m = Mirror(tempfile.mkdtemp(), rate_limit=False)
        m.ingest(net.genesis)
        parent = net.w("carol").post("parent")
        child = E.make_event(net.ids["sansa"], thread=net.tid, kind="post", body={"text": "reply", "reply_to": event_id(parent)}, parents=[event_id(parent)],
                             seq=0, admin_ref=net.tid, ts=5)
        self.assertEqual(m.ingest(child, live=False).status, "pending")
        for i in range(MAX_PENDING_PER_THREAD + 5):
            m.ingest(E.make_event(net.ids["dave"], thread=net.tid, kind="post", body={"text": "spam"}, parents=[format(i, "032x")], seq=i, admin_ref=net.tid, ts=i), live=False)
        m.ingest(parent, live=False)
        self.assertIn(event_id(child), m.thread(net.tid).events, "the honest parked reply was evicted by another author's spam")


if __name__ == "__main__":
    unittest.main()
