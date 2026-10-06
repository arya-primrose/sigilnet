"""End to end over the FAKE carrier: a capsule join (owner + joiner), thread keys delivered, posts both ways, then a removal with key rotation, all through the protocol
layer (capsule, node, sync, doors, envelopes) and carrier.Carrier ONLY. test_carrier_wiring.py runs it in a fresh interpreter in which `sigilnet.torlink` and
`sigilnet.noderun` cannot be imported: if any protocol module secretly needs Tor, the run fails."""
from __future__ import annotations

import random
import tempfile
import time
from pathlib import Path

from sigilnet import capsule as C
from sigilnet.build import Writer, make_genesis
from sigilnet.carrier import CarrierError
from sigilnet.doors import Doors
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.node import Node, PeerBook
from sigilnet.sync import SyncServer
from sigilnet.tests.fake_carrier import FakeCarrier, FakeNet


def _until(fn, what, nodes, tries=40):
    for _ in range(tries):
        if fn():
            return
        for n in nodes:
            n.tick()
        time.sleep(0.25)
    raise AssertionError("timed out: " + what)


def texts(m, tid):
    return sorted(e["body"]["text"] for e in m.threads[tid].events.values() if e["kind"] == "post")


def run(factory=None) -> str:
    """factory(name, state_dir) -> a carrier (default: the in-memory fake); the same script then proves the protocol over any carrier."""
    tmp = Path(tempfile.mkdtemp())
    net = FakeNet()
    owner, joiner = Identity.generate("owner"), Identity.generate("joiner")
    oh, jh = tmp / "o", tmp / "j"
    for h in (oh, jh):
        h.mkdir()
    om = Mirror(oh / "mirror", codec=EnvCodec(oh / "keys"), rate_limit=False)
    jm = Mirror(jh / "mirror", codec=EnvCodec(jh / "keys"), rate_limit=False)
    bystander = Identity.generate("bystander")                     # (a thread whose only other member is removed would be closed: keep it open)
    g = make_genesis(owner, "e2e over a fake carrier", [(bystander, "member")])
    tid = event_id(g)
    om.ingest(g)
    om.enable_encryption(tid, owner)
    A, B = (FakeCarrier(net, "owner"), FakeCarrier(net, "joiner")) if factory is None else (factory("owner", tmp / "oc"), factory("joiner", tmp / "jc"))
    A.start()
    B.start()
    obook, jbook = PeerBook(oh / "peers.json"), PeerBook(jh / "peers.json")
    onode = Node(om, owner, obook, oh / "node.json", lambda rec: A.dial(rec["endpoint"], timeout=5), pull_interval=3600, rng=random.Random(1))
    jnode = Node(jm, joiner, jbook, jh / "node.json", lambda rec: B.dial(rec["endpoint"], timeout=5), pull_interval=3600, rng=random.Random(2))
    osrv = SyncServer(om, identity=owner, on_notify=onode.on_notify)
    jsrv = SyncServer(jm, identity=joiner, on_notify=jnode.on_notify)
    odoors = Doors(A, osrv, lambda *a: None, {"join": C.JoinServer(oh, A, owner, om).handle})
    jdoors = Doors(B, jsrv, lambda *a: None, {})
    try:
        # ---- the capsule join
        block, cid, fp = C.create(oh, A, owner, om, tid, wait_address=lambda c, n: c.door_endpoint(n))
        odoors.sync()
        assert "join-" + cid in A.doors() and A.doors()["join-" + cid]["kind"] == "join"
        r = C.accept(jh, B, joiner, block, fp, wait_address=lambda c, n: c.door_endpoint(n))
        jdoors.sync()
        assert C.poll(jh, B, joiner, jbook, lambda ep: B.dial(ep, timeout=5), codec=jm.codec) == {r["cid"]: "requested"}
        assert list(C.pending(oh)) == [cid]
        C.confirm(oh, A, owner, om, obook, cid, C.fingerprint(joiner.id))
        odoors.sync()
        assert C.poll(jh, B, joiner, jbook, lambda ep: B.dial(ep, timeout=5), codec=jm.codec) == {r["cid"]: "joined"}
        assert jm.codec.ring(tid).ids(), "the joiner holds the thread key"
        C.sweep(oh, A)
        # ---- posts both ways, over the carrier, through envelopes
        onode.tick()
        jnode.tick()
        om.ingest(Writer(owner, om.threads[tid]).post("hello from the owner"))
        _until(lambda: tid in jm.threads and "hello from the owner" in texts(jm, tid), "the joiner reads the owner's post", [onode, jnode])
        jm.ingest(Writer(joiner, jm.threads[tid]).post("hello from the joiner"))
        _until(lambda: "hello from the joiner" in texts(om, tid), "the owner reads the joiner's post", [onode, jnode])
        raw = (oh / "mirror" / "threads" / tid / "events.jsonl").read_bytes()
        assert b"hello from the owner" not in raw and b"hello from the joiner" not in raw, "events are envelopes on disk"
        # ---- removal and key rotation: the removed member gets nothing new
        rm = Writer(owner, om.threads[tid]).admin("member_remove", {"agent": joiner.id})
        om.codec.ring(tid).create(event_id(rm), owner)
        assert om.ingest(rm).ok
        res = om.ingest(Writer(owner, om.threads[tid]).post("after the removal"))
        assert res.ok, f"the owner's post after the removal was refused: {res.status} {res.reason}"
        assert "after the removal" in texts(om, tid)
        # positive control first: the removed joiner DOES sync again (the owner's hint reaches it, it pulls) and the owner answers it as a stranger, so the absence
        # checked below is the removal at work and not a sync that is simply broken
        _until(lambda: any(row["job"] == "pull" and "does not have this thread" in str(row["error"]) for row in jnode.status()),
               "the removed joiner pulled and got the stranger's answer: " + str(jnode.status()), [onode, jnode], tries=120)
        assert "after the removal" not in texts(jm, tid), "a removed member must not read epoch 1"
        assert A.doors()[f"peer-{joiner.id[:27]}"]["agent"] == joiner.id
        # ---- closing a door makes it unreachable at the carrier level, too
        door = f"peer-{joiner.id[:27]}"
        ep = A.door_endpoint(door)
        assert ep is not None
        assert A.close_door(door) and A.door_gone(door)
        try:
            B.dial(ep, timeout=2).request({"t": "ping"})                  # (a lazy carrier fails at the first request, the fake already at dial)
            raise AssertionError("a closed door answered")
        except CarrierError:
            pass
    finally:
        odoors.stop()
        jdoors.stop()
        onode.close()
        jnode.close()
        if factory is not None:
            A.stop()
            B.stop()
    return "E2E OK"


if __name__ == "__main__":
    print(run())
