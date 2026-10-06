"""A rig for the locator-book tests: two agents (A = owner, B = member) with their own homes, carriers, peer books, locator books, nodes, sync servers, doors and locator services,
all in one process. `kind="fake"` uses the in-memory carrier (an address change is `move_door`); `kind="tcp"` uses two real TcpCarriers on loopback aliases (an address change is a
restart of that carrier on another 127.0.0.x, as a container restart with a new IP would be)."""
from __future__ import annotations

import random
import tempfile
import time
from pathlib import Path

from sigilnet import tcplink as TL
from sigilnet.build import Writer, make_genesis
from sigilnet.doors import Doors
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.locators import LocatorService, PeerDialer, open_book
from sigilnet.mirror import Mirror
from sigilnet.node import Node, PeerBook
from sigilnet.sync import SyncServer
from sigilnet.tests.fake_carrier import FakeCarrier, FakeNet
from sigilnet.tests.test_tcplink import free_base


class Side:
    def __init__(self, rig, name: str, ident: Identity, home: Path, carrier, peer_door: str):
        self.rig, self.name, self.me, self.home, self.carrier, self.peer_door = rig, name, ident, home, carrier, peer_door
        self.mirror = Mirror(home / "mirror", codec=EnvCodec(home / "keys"), rate_limit=False)
        self.peers = PeerBook(home / "peers.json")
        self.book = open_book(home, carrier.type)
        self.logs: list = []
        self.build()

    def build(self) -> None:
        c = self.carrier
        self.dialer = PeerDialer(c, self.book, request_timeout=5.0, connect_timeout=3.0)
        self.node = Node(self.mirror, self.me, self.peers, self.home / "node.json", self.dialer, pull_interval=3600, rng=random.Random(7), locators=self.book,
                         retry_wait=getattr(c, "retry_wait", 0.0))
        self.svc = LocatorService(self.me, self.peers, c, self.book, self.dialer, log=lambda *a: self.logs.append(" ".join(str(x) for x in a)), on_adopt=self.node.address_changed)
        self.srv = SyncServer(self.mirror, identity=self.me, on_notify=self.node.on_notify, pong=self.node.pong_for, on_locator=self.svc.on_locator)
        self.doors = Doors(c, self.srv, lambda *a: None, {})
        self.doors.sync()

    def stop(self) -> None:
        self.doors.stop()
        self.node.close()
        self.carrier.stop()


class Rig:
    def __init__(self, kind: str = "fake"):
        self.kind = kind
        self.tmp = Path(tempfile.mkdtemp())
        self.net = FakeNet()
        a, b = Identity.generate("a"), Identity.generate("b")
        self.ids = {"a": a, "b": b}
        self.bases = {"a": free_base(), "b": free_base()}
        self.ips = {"a": "127.0.0.2", "b": "127.0.0.3"}
        self.sides: dict = {}
        for n, ident in (("a", a), ("b", b)):
            h = self.tmp / n
            h.mkdir()
            self.sides[n] = Side(self, n, ident, h, self._carrier(n), f"peer-{('b' if n == 'a' else 'a')}")
        A, B = self.sides["a"], self.sides["b"]
        # each side offers the other a door that admits one client key, and holds the secret of that key for the other's door
        sec_a, pub_a = A.carrier.new_credential()
        sec_b, pub_b = B.carrier.new_credential()
        A.carrier.open_door("peer-b", "peer", credential=pub_b, agent=b.id)       # A's door FOR b (admits b's key)
        B.carrier.open_door("peer-a", "peer", credential=pub_a, agent=a.id)       # B's door FOR a
        A.doors.sync()
        B.doors.sync()
        A.peers.add(b.id, "b", B.carrier.door_endpoint("peer-a"), [])
        B.peers.add(a.id, "a", A.carrier.door_endpoint("peer-b"), [])
        A.carrier.use_credential(B.carrier.door_endpoint("peer-a"), sec_a, agent=b.id)
        B.carrier.use_credential(A.carrier.door_endpoint("peer-b"), sec_b, agent=a.id)
        g = make_genesis(a, "locator rig", [(b, "member")])
        self.tid = event_id(g)
        A.mirror.ingest(g)
        B.mirror.ingest(g)

    def _carrier(self, n: str):
        if self.kind == "fake":
            c = FakeCarrier(self.net, n)
        else:
            c = TL.TcpCarrier(self.tmp / n / "tcp", bind=self.ips[n], port_base=self.bases[n])
        c.start()
        return c

    # ------------------------------------------------------------ helpers
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
                self.sides[n].node.refresh_snapshot()                  # (what the node loop does each round: the pong snapshot a ping is answered from)

    def service(self, *names) -> None:
        for n in (names or ("a", "b")):
            self.sides[n].node.refresh_snapshot()
            self.sides[n].svc._work()

    def move(self, n: str, new_ip: str | None = None) -> str:
        """Side `n` now lives at another address; returns its new door address for the OTHER side's door."""
        s, other = self.sides[n], self.sides["a" if n == "b" else "b"]
        door = s.peer_door
        if self.kind == "fake":
            return s.carrier.move_door(door, f"{n}-moved-{random.randrange(10 ** 6)}.fake:1")
        s.doors.stop()
        s.carrier.stop()
        self.ips[n] = new_ip
        s.carrier = TL.TcpCarrier(self.tmp / n / "tcp", bind=new_ip, port_base=self.bases[n])
        s.carrier.start()
        s.build()
        return s.carrier.door_endpoint(door)["addr"]

    def close(self) -> None:
        for s in self.sides.values():
            s.stop()
