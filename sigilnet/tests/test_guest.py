import tempfile
import unittest

from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.guest import GuestError, post_as_guest, request_admission
from sigilnet.inbox import Inbox
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.publicread import PublicRead
from sigilnet.sync import SyncServer, pull
from sigilnet.tcp import TcpServer, TcpTransport


class E2E(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.m = Mirror(self.home + "/m", rate_limit=False)
        self.owner = Identity.generate("arya")
        gp = {"mode": "moderated", "pow_bits": 6, "queue_max": 10, "reserved_reply_slots": 2, "request_ttl_hours": 72, "max_bytes": 2048}
        g = make_genesis(self.owner, "open topic", [], visibility="public", guest_policy=gp)
        self.m.ingest(g)
        self.tid = event_id(g)
        root = Writer(self.owner, self.m.threads[self.tid]).post("who can help with X?")
        self.m.ingest(root)
        self.rid = event_id(root)
        srv = SyncServer(self.m, identity=self.owner)
        self.inbox = Inbox(self.m, self.home)
        self.read = TcpServer("127.0.0.1", 0, None, PublicRead(srv).handle).start()
        self.ib = TcpServer("127.0.0.1", 0, None, self.inbox.handle).start()
        self.addCleanup(self.read.stop)
        self.addCleanup(self.ib.stop)
        self.rt = TcpTransport("127.0.0.1", self.read.port, None, 20)
        self.it = TcpTransport("127.0.0.1", self.ib.port, None, 20)
        self.guest = Identity.generate("stranger")
        self.gm = Mirror(tempfile.mkdtemp() + "/g", rate_limit=False)
        self.gm.ingest(self.m.threads[self.tid].stored[self.tid])

    def test_whole_flow(self):
        r = pull(self.gm, self.tid, self.rt, self.guest, peer_id=self.owner.id)
        self.assertTrue(r["ok"], r)
        self.assertIn(self.rid, self.gm.threads[self.tid].stored)
        out = request_admission(self.it, self.gm, self.guest, self.tid, "I know X well", self.rid)
        self.assertEqual(out["t"], "ok")
        w = self.inbox.waiting(self.tid)
        self.assertEqual([x[0] for x in w], [out["id"]])
        # the stranger cannot read the queue or post directly through the inbox door
        self.assertEqual(self.it.request({"t": "list", "thread": self.tid, "nonce": "0" * 16})["t"], "refused")
        # the owner accepts by id: member_add role guest admits the request event
        t = self.m.threads[self.tid]
        ev = t.stored[out["id"]]
        who = type("P", (), {"id": ev["author"], "sign_pub": ev["body"]["guest"]["sign"], "kex_pub": ev["body"]["guest"]["kex"], "name": ev["body"]["guest"]["name"]})()
        res = self.m.ingest(Writer(self.owner, t).add_member(who, "guest", admits=[out["id"]]))
        self.assertTrue(res.ok, res)
        self.assertIn(out["id"], t.events)                                   # now a normal post in the thread, signed by the guest
        self.assertEqual(self.inbox.waiting(self.tid), [])
        # the guest catches up through the read door and sees itself admitted
        r = pull(self.gm, self.tid, self.rt, self.guest, peer_id=self.owner.id)
        self.assertTrue(r["ok"], r)
        gt = self.gm.threads[self.tid]
        self.assertEqual(gt.state()["members"][self.guest.id]["role"], "guest")
        self.assertIn(out["id"], gt.events)

    def test_needs_pull_first(self):
        with self.assertRaises(GuestError):
            request_admission(self.it, Mirror(tempfile.mkdtemp()), self.guest, self.tid, "x", self.rid)
        with self.assertRaises(GuestError):
            request_admission(self.it, self.gm, self.guest, self.tid, "x", self.rid)    # the root event is not in the guest mirror yet

    def test_refuses_absurd_bits(self):
        pull(self.gm, self.tid, self.rt, self.guest)
        class T:
            def request(s, q): return {"t": "challenge", "thread": self.tid, "salt": "0" * 32, "bits": 39}
        with self.assertRaises(GuestError):
            request_admission(T(), self.gm, self.guest, self.tid, "x", self.rid, solve=lambda *a: 0)

    def test_hostile_inbox_answers(self):
        pull(self.gm, self.tid, self.rt, self.guest)
        for bad in (None, [], {"t": "challenge"}, {"t": "challenge", "thread": self.tid, "salt": "zz" * 16, "bits": 4}, {"t": "challenge", "thread": self.tid, "salt": "0" * 32, "bits": True},
                    {"t": "challenge", "thread": self.tid, "salt": "0" * 32, "bits": -1}):
            class T:
                def request(s, q, bad=bad): return bad
            with self.assertRaises(GuestError, msg=str(bad)):
                request_admission(T(), self.gm, self.guest, self.tid, "x", self.rid, solve=lambda *a: 0)

    def test_inbox_keeps_changing_challenge(self):
        pull(self.gm, self.tid, self.rt, self.guest)
        class T:
            def request(s, q): return {"t": "stale", "why": "bits", "thread": self.tid, "salt": "0" * 32, "bits": 1}
        with self.assertRaises(GuestError):
            request_admission(T(), self.gm, self.guest, self.tid, "x", self.rid, solve=lambda *a: 0)

    def test_oversize_request_not_sent(self):
        pull(self.gm, self.tid, self.rt, self.guest)
        with self.assertRaises(GuestError):
            request_admission(self.it, self.gm, self.guest, self.tid, "x" * 3000, self.rid)


if __name__ == "__main__":
    unittest.main()


class LaterPosts(E2E):
    """Option (b): after the owner accepted the request, the guest posts again through the inbox door and the post lands in the owner's thread."""

    def admitted(self):
        pull(self.gm, self.tid, self.rt, self.guest, peer_id=self.owner.id)
        out = request_admission(self.it, self.gm, self.guest, self.tid, "I know X well", self.rid)
        t = self.m.threads[self.tid]
        ev = t.stored[out["id"]]
        who = type("P", (), {"id": ev["author"], "sign_pub": ev["body"]["guest"]["sign"], "kex_pub": ev["body"]["guest"]["kex"], "name": ev["body"]["guest"]["name"]})()
        self.assertTrue(self.m.ingest(Writer(self.owner, t).add_member(who, "guest", admits=[out["id"]])).ok)
        pull(self.gm, self.tid, self.rt, self.guest, peer_id=self.owner.id)

    def test_later_post_reaches_the_owner(self):
        self.admitted()
        out = post_as_guest(self.it, self.gm, self.guest, self.tid, "follow-up from the guest", self.rid)
        self.assertEqual(out["t"], "ok")
        self.assertIn(out["id"], self.m.threads[self.tid].events)
        self.assertEqual(self.m.threads[self.tid].events[out["id"]]["body"]["text"], "follow-up from the guest")
        pull(self.gm, self.tid, self.rt, self.guest, peer_id=self.owner.id)
        self.assertIn(out["id"], self.gm.threads[self.tid].events)            # and it comes back through the read door

    def test_second_later_post_chains_correctly(self):
        self.admitted()
        a = post_as_guest(self.it, self.gm, self.guest, self.tid, "one", self.rid)
        pull(self.gm, self.tid, self.rt, self.guest, peer_id=self.owner.id)
        b = post_as_guest(self.it, self.gm, self.guest, self.tid, "two", a["id"])
        self.assertEqual((a["t"], b["t"]), ("ok", "ok"))

    def test_not_admitted_yet(self):
        pull(self.gm, self.tid, self.rt, self.guest, peer_id=self.owner.id)
        with self.assertRaises(GuestError):
            post_as_guest(self.it, self.gm, self.guest, self.tid, "x", self.rid)


class TwoProcesses(unittest.TestCase):
    """The CLI rejects a request in one process while the node (another Mirror on the same files) holds it in memory: it must not come back."""

    def test_reject_in_another_process_sticks(self):
        home = tempfile.mkdtemp()
        node = Mirror(home + "/m", rate_limit=False)
        owner = Identity.generate("arya")
        g = make_genesis(owner, "t", [], visibility="public", guest_policy={"mode": "moderated", "pow_bits": 0, "queue_max": 10, "reserved_reply_slots": 2, "request_ttl_hours": 72, "max_bytes": 2048})
        node.ingest(g)
        tid = event_id(g)
        root = Writer(owner, node.threads[tid]).post("hi")
        node.ingest(root)
        inbox_node = Inbox(node, home)
        guest = Identity.generate("x")
        ev = Writer(guest, node.threads[tid]).guest_request("please", event_id(root))
        self.assertEqual(node.ingest(ev).status, "awaiting")
        cli = Mirror(home + "/m", rate_limit=False)                          # the CLI process
        self.assertTrue(Inbox(cli, home).reject(tid, event_id(ev)))
        self.assertEqual(inbox_node.waiting(tid), [])                        # the node noticed (refresh applies the drop)
        other = Identity.generate("y")
        ev2 = Writer(other, node.threads[tid]).guest_request("me too", event_id(root))
        node.ingest(ev2)                                                     # the node writes awaiting.jsonl again ...
        fresh = Mirror(home + "/m", rate_limit=False)
        self.assertEqual(set(fresh.threads[tid].awaiting), {event_id(ev2)})  # ... without the rejected one
