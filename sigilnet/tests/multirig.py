"""A rig for the multi-carrier tests (DESIGN_multicarrier.md M1b): two agents, each node runs TWO in-memory carriers ("fake" and "fakeb") the way `noderun.run` wires them: one
locator book and PeerDialer per carrier, ONE MultiDialer for the Node, one LocatorService and Doors per carrier, a SyncServer that tells the right book about an inbound request
(`on_inbound`) and sends an announcement to the right service (`on_locator`). Each side has a peer door FOR the other on each carrier and an endpoint of each type for the other."""
from __future__ import annotations

import random
import tempfile
from pathlib import Path

from sigilnet.build import Writer, make_genesis
from sigilnet.doors import Doors
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.locators import LocatorService, MultiDialer, NotifyDialer, PeerDialer, open_book, route_inbound, route_locator, route_notify_at
from sigilnet.mirror import Mirror
from sigilnet.node import Node, PeerBook
from sigilnet.sync import SyncServer
from sigilnet.tests.fake_carrier import FakeCarrier, FakeCarrierB, FakeNet

TYPES = ("fake", "fakeb")


class Side2:
    def __init__(self, rig, name: str, ident: Identity, home: Path):
        self.rig, self.name, self.me, self.home = rig, name, ident, home
        self.carriers = {"fake": FakeCarrier(rig.net, name), "fakeb": FakeCarrierB(rig.net, name)}
        for c in self.carriers.values():
            c.start()
        self.mirror = Mirror(home / "mirror", codec=EnvCodec(home / "keys"), rate_limit=False)
        self.peers = PeerBook(home / "peers.json")
        self.books = {t: open_book(home, t) for t in self.carriers}
        self.logs: list = []
        self.build()

    def build(self) -> None:
        log = lambda *a: self.logs.append(" ".join(str(x) for x in a))     # noqa: E731
        self.pdialers = {t: PeerDialer(c, self.books[t], request_timeout=5.0, connect_timeout=3.0) for t, c in self.carriers.items()}
        self.dialer = MultiDialer(self.pdialers, log=log)
        self.node = Node(self.mirror, self.me, self.peers, self.home / "node.json", self.dialer, pull_interval=3600, rng=random.Random(7), locators=self.dialer, retry_wait=0.0)
        self.notify_via = None                                           # M4b: the carrier TYPE on which this side wants notifies (None: no field is sent)
        self.node.notify_to = NotifyDialer(self.pdialers, log=log)
        self.node.notify_field = lambda agent: ({"type": self.notify_via, "addr": a} if self.notify_via and (a := self.svcs[self.notify_via]._our_address(agent)) else None)
        self.svcs = {t: LocatorService(self.me, self.peers, c, self.books[t], self.pdialers[t], log=log, on_adopt=self.node.address_changed) for t, c in self.carriers.items()}
        self.srv = SyncServer(self.mirror, identity=self.me, on_notify=self.node.on_notify, on_push=self.node.on_push, pong=self.node.pong_for,
                              on_locator=route_locator(self.svcs, "fake", lambda: self.srv.via()), on_inbound=route_inbound(self.books), on_notify_at=route_notify_at(self.svcs))
        self.srv.set_peers(self.peers.all())
        self.node.heard_from = self.srv.heard.get
        self.doors = {t: Doors(c, self.srv, lambda *a: None, {}) for t, c in self.carriers.items()}
        for d in self.doors.values():
            d.sync()

    def stop(self) -> None:
        for d in self.doors.values():
            d.stop()
        self.node.close()
        for c in self.carriers.values():
            c.stop()


class Rig2:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.net = FakeNet()
        a, b = Identity.generate("a"), Identity.generate("b")
        self.ids = {"a": a, "b": b}
        self.sides = {}
        for n, ident in (("a", a), ("b", b)):
            h = self.tmp / n
            h.mkdir()
            self.sides[n] = Side2(self, n, ident, h)
        A, B = self.sides["a"], self.sides["b"]
        for t in TYPES:                                                  # on each carrier: a door FOR the other side, the other side's secret for it
            sec_a, pub_a = A.carriers[t].new_credential()
            sec_b, pub_b = B.carriers[t].new_credential()
            A.carriers[t].open_door("peer-b", "peer", credential=pub_b, agent=b.id)
            B.carriers[t].open_door("peer-a", "peer", credential=pub_a, agent=a.id)
            A.doors[t].sync()
            B.doors[t].sync()
            A.peers.add(b.id, "b", B.carriers[t].door_endpoint("peer-a"), [])
            B.peers.add(a.id, "a", A.carriers[t].door_endpoint("peer-b"), [])
            A.carriers[t].use_credential(B.carriers[t].door_endpoint("peer-a"), sec_a, agent=b.id)
            B.carriers[t].use_credential(A.carriers[t].door_endpoint("peer-b"), sec_b, agent=a.id)
        A.peers.add(b.id, "b", B.carriers["fake"].door_endpoint("peer-a"), [])       # the fake endpoint is the primary (added last)
        B.peers.add(a.id, "a", A.carriers["fake"].door_endpoint("peer-b"), [])
        g = make_genesis(a, "multi rig", [(b, "member")])
        self.tid = event_id(g)
        A.mirror.ingest(g)
        B.mirror.ingest(g)
        for s in self.sides.values():
            s.srv.set_peers(s.peers.all())

    def post(self, n: str, text: str) -> dict:
        s = self.sides[n]
        ev = Writer(s.me, s.mirror.threads[self.tid]).post(text)
        assert s.mirror.ingest(ev).ok
        return ev

    def texts(self, n: str) -> list:
        return sorted(e["body"]["text"] for e in self.sides[n].mirror.threads[self.tid].events.values() if e["kind"] == "post")

    def tick(self, *names, rounds: int = 2) -> None:
        for _ in range(rounds):
            for n in (names or ("a", "b")):
                self.sides[n].node.tick()
                self.sides[n].node.refresh_snapshot()

    def blackhole(self, n: str, ctype: str, on: bool = True) -> None:
        """Side `n`'s doors on carrier `ctype` stop answering (the OTHER side cannot reach `n` over it)."""
        self.sides[n].carriers[ctype].blackhole(on)

    def close(self) -> None:
        for s in self.sides.values():
            s.stop()
