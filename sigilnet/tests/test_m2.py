"""M2 (DESIGN_multicarrier.md rev 8): capsules with several endpoints. Two in-memory carriers per side ("fake" and "fakeb"); the join doors, the requests and the answers go through the real
capsule code, the JoinServer is called directly (the transport is a function: a carrier can be switched off)."""
import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import canon
from sigilnet import capsule as C
from sigilnet.build import make_genesis
from sigilnet.carrier import CarrierError
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.node import PeerBook
from sigilnet.tests.fake_carrier import FakeCarrier, FakeCarrierB, FakeNet


class Strict(FakeCarrier):
    """Refuses (like tcplink would) an address that contains 'bad' and can hide a door's address (a carrier that is still creating it)."""
    hidden: set = None

    def locator_problem(self, addr):
        return "a bad address" if "bad" in addr else None

    def door_endpoint(self, name):
        return None if self.hidden and name in self.hidden else super().door_endpoint(name)


class StrictB(Strict, FakeCarrierB):
    type = "fakeb"
    suffix = ".fakeb"


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


def block_dict(block):
    return json.loads(base64.urlsafe_b64decode(block.split()[1] + "==").decode())


class Rig(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.net = FakeNet()
        self.oh, self.jh = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.owner, self.joiner = Identity.generate("arya"), Identity.generate("carol")
        self.O = {"fake": Strict(self.net, "own"), "fakeb": StrictB(self.net, "ownb")}
        self.J = {"fake": Strict(self.net, "jn"), "fakeb": StrictB(self.net, "jnb")}
        for c in list(self.O.values()) + list(self.J.values()):
            c.hidden = set()
        self.om = Mirror(self.oh + "/m", clock=self.clock, rate_limit=False)
        g = make_genesis(self.owner, "secret project", [], ts=int(self.clock()))
        self.om.ingest(g)
        self.tid = event_id(g)
        self.obook, self.jbook = PeerBook(Path(self.oh) / "peers.json"), PeerBook(Path(self.jh) / "peers.json")
        self.server = C.JoinServer(self.oh, self.O, self.owner, self.om, self.clock)
        self.down = set()                                           # carrier types the joiner cannot reach

        class T:
            def __init__(s, rig, ep):
                s.rig, s.ep = rig, ep

            def request(s, q):
                if s.ep["type"] in s.rig.down:
                    raise CarrierError("down", retry=True)
                return s.rig.server.handle(q)
        self.transport_for = lambda ep: T(self, ep)

    def create(self, types=("fake", "fakeb"), **kw):
        return C.create(self.oh, [self.O[t] for t in types], self.owner, self.om, self.tid, clock=self.clock, wait_address=lambda c, n: c.door_endpoint(n), **kw)

    def accept(self, block, fp=None, **kw):
        return C.accept(self.jh, self.J, self.joiner, block, fp or C.fingerprint(self.owner.id), clock=self.clock, wait_address=lambda c, n: c.door_endpoint(n), **kw)

    def poll(self):
        return C.poll(self.jh, self.J, self.joiner, self.jbook, self.transport_for, clock=self.clock)

    def confirm(self, cid, who=None):
        return C.confirm(self.oh, self.O, self.owner, self.om, self.obook, cid, C.fingerprint((who or self.joiner).id), clock=self.clock)

    def sweep(self, **kw):
        return C.sweep(self.oh, self.O, clock=self.clock, **kw)

    def rec(self, cid):
        return C.Store(self.oh).all()[cid]

    def peer_doors(self, agent=None):
        return sorted((t, n) for t, c in self.O.items() for n, d in c.doors().items() if d["kind"] == "peer" and (agent is None or d["agent"] == agent))

    def join_doors(self):
        return sorted((t, n) for t, c in self.O.items() for n, d in c.doors().items() if d["kind"] == "join")

    def request(self, who, tok, offers, **over):
        body = {"t": "join_request", "token": tok, "sign": who.sign_pub, "kex": who.kex_pub, "name": "x", "offers": offers, **over}
        body["sig"] = who.sign(C.JOINREQ_CTX + canon.dumps(body))
        return body

    def offers_for(self, types=("fake", "fakeb")):
        out = []
        for t in types:
            _, pub = self.J[t].new_credential()
            self.J[t].open_door("owner-x", "peer", credential=pub, agent=self.owner.id)
            out.append({"endpoint": self.J[t].door_endpoint("owner-x"), "credential": pub})
        return out


class Format(Rig):
    def test_a_two_door_capsule_round_trips_in_the_issuers_order(self):
        block, cid, _ = self.create(("fakeb", "fake"))
        c = C.decode_capsule(block, now=self.clock())
        self.assertEqual(c["v"], 2)
        self.assertEqual([j["endpoint"]["type"] for j in c["joins"]], ["fakeb", "fake"])
        for j in c["joins"]:
            self.assertEqual((j["boot"]["type"], j["dial"]["type"]), (j["endpoint"]["type"],) * 2)
        self.assertLess(len(block), C.MAX_CAPSULE)
        self.assertEqual(self.rec(cid)["types"], ["fakeb", "fake"])

    def test_one_carrier_one_entry(self):
        block, cid, _ = self.create(("fake",))
        self.assertEqual(len(C.decode_capsule(block, now=self.clock())["joins"]), 1)

    def test_bad_join_lists_are_refused(self):
        block, cid, _ = self.create()
        good = C.decode_capsule(block, now=self.clock())
        j0, j1 = good["joins"]
        for bad in ([], [j0, j0], [j0, j1, j0], [j0] * 5, [{**j0, "boot": j1["boot"]}], [{**j0, "dial": j1["dial"]}], [{**j0, "extra": 1}], [{"endpoint": j0["endpoint"]}], "x", None, [None]):
            with self.assertRaises(C.CapsuleError, msg=str(bad)[:60]):
                C.decode_capsule(C.encode_capsule({**good, "joins": bad}), now=self.clock())

    def test_a_v1_capsule_says_to_re_issue(self):
        block, cid, _ = self.create()
        good = C.decode_capsule(block, now=self.clock())
        old = {k: v for k, v in good.items() if k != "joins"}
        old.update(v=1, join={"endpoint": good["joins"][0]["endpoint"]}, boot=good["joins"][0]["boot"], dial=good["joins"][0]["dial"])
        with self.assertRaises(C.CapsuleError) as cm:
            C.decode_capsule(C.encode_capsule(old), now=self.clock())
        self.assertIn("issue a new one", str(cm.exception))

    def test_a_passphrase_wraps_every_entrys_boot_key_one_kdf_each(self):
        block, cid, _ = self.create(passphrase="correct horse")
        c = C.decode_capsule(block, now=self.clock())
        self.assertTrue(all(set(j["boot"]) == {"enc"} for j in c["joins"]))
        self.assertLess(len(block), C.MAX_CAPSULE)
        with self.assertRaises(C.CapsuleError):
            self.accept(block, passphrase="wrong")
        self.assertEqual(self.J["fake"].doors(), {})
        t0 = time.time()
        self.accept(block, passphrase="correct horse")
        self.assertLess(time.time() - t0, 5.0)


class Create(Rig):
    def test_a_join_door_on_every_listed_carrier_and_a_key_file_for_each(self):
        block, cid, _ = self.create()
        self.assertEqual(self.join_doors(), [("fake", f"join-{cid}"), ("fakeb", f"join-{cid}")])
        for t in ("fake", "fakeb"):
            f = Path(self.oh) / "peerkeys" / f"cap-{cid}-{t}.priv"
            self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_a_carrier_that_fails_tears_down_the_others_and_the_record(self):
        def wait(c, n):
            return None if c.type == "fakeb" else c.door_endpoint(n)
        with self.assertRaises(C.CapsuleError) as cm:
            C.create(self.oh, [self.O["fake"], self.O["fakeb"]], self.owner, self.om, self.tid, clock=self.clock, wait_address=wait)
        self.assertIn("fakeb", str(cm.exception))
        self.assertEqual(self.join_doors(), [])
        self.assertEqual(C.Store(self.oh).all(), {})
        self.assertEqual(list((Path(self.oh) / "peerkeys").glob("cap-*")), [])

    def test_the_same_carrier_twice_is_refused(self):
        with self.assertRaises(C.CapsuleError):
            C.create(self.oh, [self.O["fake"], self.O["fake"]], self.owner, self.om, self.tid, clock=self.clock)


class Sweep(Rig):
    def test_expiry_closes_every_door_and_keys_then_the_record_goes_after_keep(self):
        block, cid, _ = self.create(ttl=120)
        self.clock.t += 121
        self.assertEqual(self.sweep(), [cid])
        self.assertEqual(self.join_doors(), [])
        self.assertEqual(self.rec(cid)["door_gone"], {"fake": True, "fakeb": True})
        self.assertEqual(list((Path(self.oh) / "peerkeys").glob("cap-*")), [])
        self.clock.t += C.KEEP + 1
        self.sweep()
        self.assertNotIn(cid, C.Store(self.oh).all())

    def test_expiry_with_a_carrier_down_keeps_the_record_until_that_door_is_gone_too(self):
        block, cid, _ = self.create(ttl=120)
        self.clock.t += 121
        self.assertEqual(self.sweep(skip=["fakeb"]), [])               # fakeb is not up: its door is not touched
        self.assertEqual(self.join_doors(), [("fakeb", f"join-{cid}")])
        self.assertEqual(self.rec(cid)["door_gone"], {"fake": True})
        self.assertEqual(self.sweep(), [cid])                          # it is back: the first sweep removes the door
        self.assertEqual(self.join_doors(), [])
        self.assertEqual(self.rec(cid)["door_gone"], {"fake": True, "fakeb": True})
        self.assertEqual(self.server.handle({"t": "join_status", "token": block_dict(block)["token"]}), {"t": "refused"})

    def test_the_record_stays_while_one_door_is_still_there_even_after_keep(self):
        block, cid, _ = self.create(ttl=120)
        self.clock.t += 121
        self.sweep(skip=["fakeb"])
        self.clock.t += C.KEEP + 1
        self.sweep(skip=["fakeb"])
        self.assertIn(cid, C.Store(self.oh).all(), "a door we could not close yet needs its record")
        self.assertEqual(self.join_doors(), [("fakeb", f"join-{cid}")])

    def test_a_create_for_one_carrier_does_not_touch_an_expired_capsules_door_on_another(self):
        """Sansa H1: the sweep inside create() once marked the types of carriers absent from ITS call as gone while their doors were still served."""
        block, cid, _ = self.create(ttl=120)
        self.clock.t += 121
        self.create(("fake",))                                          # only the fake carrier listed, no all_carriers
        rec = self.rec(cid)
        self.assertEqual(rec["door_gone"], {"fake": True}, "fakeb's door is still there: it must not be marked")
        self.assertIn((("fakeb"), f"join-{cid}"), self.join_doors())
        self.assertEqual(self.sweep(), [cid])                           # the node's own sweep closes it at its next tick
        self.assertNotIn(("fakeb", f"join-{cid}"), self.join_doors())
        self.assertEqual(self.rec(cid)["door_gone"], {"fake": True, "fakeb": True})

    def test_create_with_all_carriers_sweeps_the_expired_capsule_on_every_one(self):
        block, cid, _ = self.create(ttl=120)
        self.clock.t += 121
        C.create(self.oh, [self.O["fake"]], self.owner, self.om, self.tid, clock=self.clock, wait_address=lambda c, n: c.door_endpoint(n), all_carriers=list(self.O.values()))
        self.assertEqual(self.rec(cid)["door_gone"], {"fake": True, "fakeb": True})
        self.assertEqual([d for d in self.join_doors() if d[1] == f"join-{cid}"], [])

    def test_served_and_absence(self):
        block, cid, _ = self.create(ttl=120)
        self.clock.t += 121
        self.assertEqual(C.sweep(self.oh, [self.O["fake"]], clock=self.clock, served=["fake", "fakeb"]), [])      # fakeb runs here but is not in the call: left alone, not marked
        self.assertEqual(self.rec(cid)["door_gone"], {"fake": True})
        self.assertEqual(C.sweep(self.oh, [self.O["fakeb"]], clock=self.clock, served=["fake", "fakeb"]), [cid])

    def test_an_orphan_door_on_a_carrier_that_is_down_is_left_for_later(self):
        _, pub = self.O["fakeb"].new_credential()
        self.O["fakeb"].open_door("join-deadbeef", "join", credential=pub)
        self.assertEqual(self.sweep(skip=["fakeb"]), [])
        self.assertEqual(self.join_doors(), [("fakeb", "join-deadbeef")])

    def test_the_join_server_answers_nothing_after_expiry_whatever_the_door(self):
        block, cid, _ = self.create(ttl=120)
        tok = block_dict(block)["token"]
        self.clock.t += 121
        self.assertEqual(self.server.handle(self.request(self.joiner, tok, self.offers_for())), {"t": "refused"})

    def test_an_orphan_join_door_on_the_second_carrier_is_swept(self):
        _, pub = self.O["fakeb"].new_credential()
        self.O["fakeb"].open_door("join-deadbeef", "join", credential=pub)
        self.assertEqual(self.sweep(), ["join-deadbeef"])
        self.assertEqual(self.join_doors(), [])

    def test_a_carrier_this_node_no_longer_runs_counts_as_gone(self):
        block, cid, _ = self.create(ttl=120)
        self.clock.t += 121
        self.assertEqual(C.sweep(self.oh, [self.O["fake"]], clock=self.clock), [cid])
        self.assertEqual(self.rec(cid)["door_gone"], {"fake": True, "fakeb": True})

    def test_reject_tears_down_both(self):
        block, cid, _ = self.create()
        self.assertTrue(C.reject(self.oh, self.O, cid, clock=self.clock))
        self.assertEqual(self.join_doors(), [])
        self.assertEqual(self.rec(cid)["door_gone"], {"fake": True, "fakeb": True})


class Records(Rig):
    def test_a_record_of_every_state_round_trips_through_a_fresh_store(self):
        block, cid, _ = self.create()
        tok = block_dict(block)["token"]
        self.assertEqual(self.server.handle(self.request(self.joiner, tok, self.offers_for()))["t"], "pending")
        for state in ("open", "pending", "confirming", "confirmed", "rejected", "expired"):
            extra = {"owner_door": "peer-" + "a" * 27, "deadline": 5, "partial": ["fakeb"], "door_gone": {"fake": True}} if state == "confirmed" else {}
            C.Store(self.oh).edit(lambda d, state=state, extra=extra: d[cid].update(state=state, **extra))
            self.assertIn(cid, C.Store(self.oh).all(), state)

    def test_a_record_with_a_field_removed_duplicated_or_wrong_is_dropped_and_no_door_is_touched(self):
        block, cid, _ = self.create()
        tok = block_dict(block)["token"]
        self.server.handle(self.request(self.joiner, tok, self.offers_for()))
        raw = json.loads((Path(self.oh) / "capsules.json").read_text())[cid]
        mutants = []
        for k in raw:
            if k not in ("req", "at"):
                mutants.append({kk: v for kk, v in raw.items() if kk != k})
        mutants += [{**raw, "types": ["fake", "fake"]}, {**raw, "types": []}, {**raw, "types": ["fake", "fakeb", "x", "y", "z"]}, {**raw, "types": "fake"}, {**raw, "door": "join-00000000"},
                    {**raw, "door_gone": {"zzz": True}}, {**raw, "door_gone": {"fake": False}}, {**raw, "partial": ["zzz"]}, {**raw, "dial": "x", "state": 5},
                    {**raw, "req": {**raw["req"], "offers": []}}, {**raw, "req": {**raw["req"], "offers": raw["req"]["offers"] * 3}},
                    {**raw, "req": {**raw["req"], "offers": [raw["req"]["offers"][0], raw["req"]["offers"][0]]}},
                    {**raw, "req": {**raw["req"], "endpoint": raw["req"]["offers"][0]["endpoint"]}},
                    {**raw, "req": {k: v for k, v in raw["req"].items() if k != "offers"}},
                    {**raw, "req": {**raw["req"], "offers": [{"endpoint": raw["req"]["offers"][0]["endpoint"], "credential": raw["req"]["offers"][1]["credential"]}]}}]
        before = self.join_doors()
        for m in mutants:
            (Path(self.oh) / "capsules.json").write_text(json.dumps({cid: m}))
            self.assertEqual(C.Store(self.oh).all(), {}, str(m)[:80])
            self.assertEqual(self.join_doors(), before, "loading a bad record touches no door")

    def test_the_joiners_record_round_trips_and_a_v1_record_is_dropped_without_touching_anything(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        recs = C.Joins(self.jh).all()
        self.assertEqual(set(recs), {r["cid"]})
        self.assertEqual((recs[r["cid"]]["used"], recs[r["cid"]]["offered"]), (["fake", "fakeb"], []))
        files = sorted(p.name for p in (Path(self.jh) / "peerkeys").iterdir())
        doors = {t: dict(c.doors()) for t, c in self.J.items()}
        raw = json.loads((Path(self.jh) / "joins.json").read_text())
        v1 = {"33c1a2eb": {"thread": "a" * 32, "owner": raw[r["cid"]]["owner"], "endpoint": {"type": "fake", "addr": "x.fake:1"}, "token": "b" * 32, "exp": 2_000_000_000, "door": "owner-x",
                           "mypub": {"type": "fake", "key": "c" * 64}, "key": "join-33c1a2eb", "state": "joined", "at": 1, "name": "n"}}
        (Path(self.jh) / "joins.json").write_text(json.dumps({**raw, **v1}))
        self.assertEqual(set(C.Joins(self.jh).all()), {r["cid"]}, "the v1 record is dropped, the v2 one stays")
        self.assertEqual(self.poll(), {r["cid"]: "requested"})          # (poll goes on as before)
        self.assertEqual(sorted(p.name for p in (Path(self.jh) / "peerkeys").iterdir()), files)
        self.assertEqual({t: dict(c.doors()) for t, c in self.J.items()}, doors)
        self.assertEqual(self.jbook.all(), {})

    def test_a_joiner_record_with_a_field_wrong_is_dropped(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        raw = json.loads((Path(self.jh) / "joins.json").read_text())[r["cid"]]
        mutants = [{k: v for k, v in raw.items() if k != f} for f in ("endpoints", "used", "offered", "mypub", "token", "door")]
        mutants += [{**raw, "used": ["fake", "fake"]}, {**raw, "used": ["zzz"]}, {**raw, "used": []}, {**raw, "offered": ["fakeb", "x"]}, {**raw, "mypub": {"fake": raw["mypub"]["fake"]}},
                    {**raw, "mypub": {"fake": raw["mypub"]["fakeb"], "fakeb": raw["mypub"]["fake"]}}, {**raw, "endpoints": [raw["endpoints"][0]] * 2}, {**raw, "endpoints": []}, {**raw, "key": "join-x"},
                    {**raw, "endpoint": raw["endpoints"][0]["endpoint"]}]
        for m in mutants[:-1]:
            (Path(self.jh) / "joins.json").write_text(json.dumps({r["cid"]: m}))
            self.assertEqual(C.Joins(self.jh).all(), {}, str(m)[:100])


class Request(Rig):
    def setUp(self):
        super().setUp()
        self.block, self.cid, _ = self.create()
        self.tok = block_dict(self.block)["token"]

    def req(self, offers, who=None, **over):
        return self.server.handle(self.request(who or self.joiner, self.tok, offers, **over))

    def test_a_good_request_is_pending_with_its_offers_in_the_capsules_order(self):
        offers = self.offers_for(("fakeb", "fake"))
        self.assertEqual(self.req(offers)["t"], "pending")
        got = [o["endpoint"]["type"] for o in self.rec(self.cid)["req"]["offers"]]
        self.assertEqual(got, ["fake", "fakeb"])

    def test_the_offers_matrix(self):
        good = self.offers_for()
        _, pubc = self.J["fake"].new_credential()
        other = {"endpoint": {"type": "fake", "addr": "z-1.fake:1"}, "credential": pubc}
        cases = {"none": [], "three": good + [other], "duplicate type": [good[0], other], "not a list": "x", "not offers": [{"endpoint": good[0]["endpoint"]}],
                 "extra key": [{**good[0], "x": 1}], "type mismatch": [{"endpoint": good[0]["endpoint"], "credential": good[1]["credential"]}], "bad address": [{"endpoint": {"type": "fake", "addr": "bad-1.fake:1"}, "credential": pubc}],
                 "bad address second": [good[0], {"endpoint": {"type": "fakeb", "addr": "bad-2.fakeb:1"}, "credential": good[1]["credential"]}]}
        for name, offers in cases.items():
            self.assertEqual(self.req(offers), {"t": "refused"}, name)
        self.assertEqual(C.pending(self.oh, self.clock), {}, "none of those burned the token")
        self.assertEqual(self.req(good)["t"], "pending")

    def test_an_offer_for_a_carrier_the_capsule_does_not_list_or_we_do_not_run_is_refused(self):
        block, cid, _ = self.create(("fake",))
        tok = block_dict(block)["token"]
        self.assertEqual(self.server.handle(self.request(self.joiner, tok, self.offers_for(("fakeb",)))), {"t": "refused"})
        small = C.JoinServer(self.oh, [self.O["fake"]], self.owner, self.om, self.clock)
        self.assertEqual(small.handle(self.request(self.joiner, self.tok, self.offers_for(("fakeb",)))), {"t": "refused"}, "a type we do not run")

    def test_the_signature_covers_the_offers(self):
        offers = self.offers_for(("fake",))
        body = self.request(self.joiner, self.tok, offers)
        other = self.offers_for(("fakeb",))
        self.assertEqual(self.server.handle({**body, "offers": other}), {"t": "refused"})
        self.assertEqual(self.server.handle(body)["t"], "pending")

    def test_the_same_joiner_again_is_idempotent_a_second_joiner_is_refused(self):
        offers = self.offers_for()
        self.assertEqual(self.req(offers)["t"], "pending")
        self.assertEqual(self.req(offers)["t"], "pending")
        self.assertEqual(self.req(offers, who=Identity.generate("x"))["t"], "refused")
        self.assertEqual(len(C.pending(self.oh, self.clock)), 1)

    def test_more_offers_may_be_added_while_pending_nothing_existing_changes(self):
        both = self.offers_for()
        self.assertEqual(self.req(both[:1])["t"], "pending")
        self.assertEqual(self.req(both)["t"], "pending")
        self.assertEqual(len(self.rec(self.cid)["req"]["offers"]), 2)
        block, cid, _ = self.create()
        tok = block_dict(block)["token"]
        o1 = self.offers_for(("fake",))
        self.server.handle(self.request(self.joiner, tok, o1))
        _, pub = self.J["fake"].new_credential()
        changed = [{"endpoint": o1[0]["endpoint"], "credential": pub}, self.offers_for(("fakeb",))[0]]
        self.assertEqual(self.server.handle(self.request(self.joiner, tok, changed))["t"], "pending")
        self.assertEqual(self.rec(cid)["req"]["offers"], o1, "an existing offer cannot be changed")
        smaller = self.offers_for(("fakeb",))
        self.server.handle(self.request(self.joiner, tok, o1 + smaller))
        self.assertEqual(len(self.rec(cid)["req"]["offers"]), 2)
        self.server.handle(self.request(self.joiner, tok, o1))
        self.assertEqual(len(self.rec(cid)["req"]["offers"]), 2, "offers are never removed")

    def test_no_resend_once_confirming_or_confirmed(self):
        both = self.offers_for()
        self.req(both[:1])
        self.confirm(self.cid)
        self.assertEqual(self.req(both), {"t": "refused"})
        self.assertEqual(len(self.rec(self.cid)["req"]["offers"]), 1)

    def test_two_joiners_racing_one_token_exactly_one_is_pending(self):
        import threading
        results = []

        def go(who, types):
            results.append(self.req(self.offers_for(types), who=who)["t"])
        ts = [threading.Thread(target=go, args=(Identity.generate(f"j{i}"), ("fake",) if i % 2 else ("fakeb",))) for i in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sorted(results), ["pending"] + ["refused"] * 5)


class Confirm(Rig):
    def setUp(self):
        super().setUp()
        self.block, self.cid, _ = self.create()
        self.tok = block_dict(self.block)["token"]

    def pend(self, types=("fake", "fakeb")):
        self.assertEqual(self.server.handle(self.request(self.joiner, self.tok, self.offers_for(types)))["t"], "pending")

    def test_a_peer_door_credential_and_book_entry_per_offered_carrier(self):
        self.pend()
        out = self.confirm(self.cid)
        door = out["door"]
        self.assertEqual(out["carriers"], ["fake", "fakeb"])
        self.assertEqual(self.peer_doors(self.joiner.id), [("fake", door), ("fakeb", door)])
        self.assertEqual(sorted(e["type"] for e in self.obook.all()[self.joiner.id]["endpoints"]), ["fake", "fakeb"])
        self.assertEqual(self.om.threads[self.tid].state()["members"][self.joiner.id]["role"], "member")
        self.assertEqual(self.rec(self.cid)["state"], "confirmed")
        self.assertEqual(list((Path(self.oh) / "peerkeys").glob("cap-*")), [])

    def test_one_offer_one_door(self):
        self.pend(("fakeb",))
        out = self.confirm(self.cid)
        self.assertEqual(out["carriers"], ["fakeb"])
        self.assertEqual(self.peer_doors(self.joiner.id), [("fakeb", out["door"])])

    def test_a_failure_on_the_second_carrier_closes_the_doors_of_the_attempt_and_a_retry_works(self):
        self.pend()
        real = self.O["fakeb"].open_door
        with mock.patch.object(self.O["fakeb"], "open_door", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                self.confirm(self.cid)
        self.assertEqual(self.peer_doors(), [], "the fake door opened by the failed attempt is closed again")
        self.assertNotIn(self.joiner.id, self.obook.all(), "and so is the peer entry it added")
        self.assertEqual(self.rec(self.cid)["state"], "pending")
        self.assertNotIn(self.joiner.id, self.om.threads[self.tid].state()["members"])
        self.confirm(self.cid)                                          # the human retries
        self.assertEqual(len(self.peer_doors(self.joiner.id)), 2)
        self.assertTrue(real)

    def test_a_failed_attempt_leaves_a_door_that_was_already_there(self):
        self.pend()
        _, pub = self.O["fake"].new_credential()
        door = f"peer-{self.joiner.id[:27]}"
        self.O["fake"].open_door(door, "peer", credential=pub, agent=self.joiner.id)             # an earlier attempt's door (idempotent steps: it is re-keyed, not ours to close)
        with mock.patch.object(self.O["fakeb"], "open_door", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                self.confirm(self.cid)
        self.assertEqual(self.peer_doors(self.joiner.id), [("fake", door)])

    def test_a_failure_then_reject_leaves_no_peer_door_on_either_carrier(self):
        self.pend()
        with mock.patch.object(self.O["fakeb"], "open_door", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                self.confirm(self.cid)
        self.assertTrue(C.reject(self.oh, self.O, self.cid, clock=self.clock, book=self.obook))
        self.assertEqual(self.peer_doors(), [])

    def test_reject_closes_a_stray_peer_door_of_the_requests_agent_not_in_the_book(self):
        self.pend()
        _, pub = self.O["fake"].new_credential()
        self.O["fake"].open_door("peer-stray", "peer", credential=pub, agent=self.joiner.id)            # what an old failed confirm left
        _, pub = self.O["fakeb"].new_credential()
        self.O["fakeb"].open_door("peer-other", "peer", credential=pub, agent=Identity.generate("o").id)
        self.assertTrue(C.reject(self.oh, self.O, self.cid, clock=self.clock, book=self.obook))
        self.assertEqual([n for _, n in self.peer_doors()], ["peer-other"], "only the door bound to the request's agent goes")

    def test_reject_keeps_the_doors_of_a_peer_that_is_in_the_book(self):
        self.pend()
        _, pub = self.O["fake"].new_credential()
        self.O["fake"].open_door("peer-stray", "peer", credential=pub, agent=self.joiner.id)
        self.obook.add(self.joiner.id, "carol", {"type": "fake", "addr": "c.fake:1"}, [])
        C.reject(self.oh, self.O, self.cid, clock=self.clock, book=self.obook)
        self.assertEqual([n for _, n in self.peer_doors()], ["peer-stray"])

    def test_confirm_checks_the_offers_addresses_again(self):
        self.pend()
        raw = json.loads((Path(self.oh) / "capsules.json").read_text())
        raw[self.cid]["req"]["offers"][0]["endpoint"] = {"type": "fake", "addr": "bad-1.fake:1"}      # (an old record, the carrier's rules changed since)
        (Path(self.oh) / "capsules.json").write_text(json.dumps(raw))
        with self.assertRaises(C.CapsuleError) as cm:
            self.confirm(self.cid)
        self.assertIn("refused", str(cm.exception))
        self.assertEqual(self.peer_doors(), [])
        self.assertEqual(self.rec(self.cid)["state"], "pending")

    def test_a_wrong_fingerprint_changes_nothing(self):
        self.pend()
        with self.assertRaises(C.CapsuleError):
            C.confirm(self.oh, self.O, self.owner, self.om, self.obook, self.cid, "aaaa bbbb cccc dddd", clock=self.clock)
        self.assertEqual(self.peer_doors(), [])

    def test_none_of_the_offers_on_a_carrier_we_run(self):
        self.pend(("fakeb",))
        with self.assertRaises(C.CapsuleError):
            C.confirm(self.oh, [self.O["fake"]], self.owner, self.om, self.obook, self.cid, C.fingerprint(self.joiner.id), clock=self.clock)
        self.assertEqual(self.rec(self.cid)["state"], "pending")


class Answer(Rig):
    def setUp(self):
        super().setUp()
        self.block, self.cid, _ = self.create()
        self.tok = block_dict(self.block)["token"]
        self.server.handle(self.request(self.joiner, self.tok, self.offers_for()))
        self.out = self.confirm(self.cid)

    def status(self):
        return self.server.handle({"t": "join_status", "token": self.tok})

    def test_the_answer_has_one_endpoint_per_offered_carrier_in_the_issuers_order_and_is_signed(self):
        a = self.status()
        self.assertEqual(a["t"], "joined")
        self.assertEqual([e["type"] for e in a["endpoints"]], ["fake", "fakeb"])
        self.assertNotIn("endpoint", a)
        self.assertTrue(canon.dumps(a))
        from sigilnet.keys import verify_strict
        self.assertTrue(verify_strict(a["by"], a["rsig"], C.JOIN_CTX + canon.dumps({k: v for k, v in a.items() if k != "rsig"})))

    def test_it_waits_for_a_carrier_whose_door_has_no_address_yet_then_answers_with_what_it_has(self):
        self.O["fakeb"].hidden = {self.out["door"]}
        self.assertEqual(self.status(), {"t": "wait"})
        before = self.rec(self.cid)["deadline"]
        self.clock.t += C.ANSWER_WAIT - 1
        self.assertEqual(self.status(), {"t": "wait"})
        self.assertEqual(self.rec(self.cid)["deadline"], before, "no answer delivered: the deadline is not shortened")
        self.clock.t += 2
        a = self.status()
        self.assertEqual([e["type"] for e in a["endpoints"]], ["fake"])
        self.assertEqual(self.rec(self.cid)["partial"], ["fakeb"])
        self.assertLessEqual(self.rec(self.cid)["deadline"], int(self.clock.t) + 120)

    def test_the_address_arriving_in_time_gives_a_full_answer(self):
        self.O["fakeb"].hidden = {self.out["door"]}
        self.assertEqual(self.status(), {"t": "wait"})
        self.O["fakeb"].hidden = set()
        self.clock.t += 10
        self.assertEqual(len(self.status()["endpoints"]), 2)
        self.assertNotIn("partial", self.rec(self.cid))

    def test_no_address_at_all_keeps_waiting(self):
        self.O["fake"].hidden = self.O["fakeb"].hidden = {self.out["door"]}
        self.clock.t += 500
        self.assertEqual(self.status(), {"t": "wait"})


class Joiner(Rig):
    def test_the_carriers_used_are_the_common_ones_and_the_restriction_narrows_them(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.assertEqual(r["used"], ["fake", "fakeb"])
        self.assertEqual(sorted(t for t, c in self.J.items() if c.doors()), ["fake", "fakeb"])

    def test_only_restricts_the_joiners_doors_and_its_dials(self):
        block, cid, _ = self.create()
        r = self.accept(block, only={"fakeb"})
        self.assertEqual(r["used"], ["fakeb"])
        self.assertEqual(self.J["fake"].doors(), {})
        self.assertEqual(self.poll(), {r["cid"]: "requested"})
        offers = self.rec(cid)["req"]["offers"]
        self.assertEqual([o["endpoint"]["type"] for o in offers], ["fakeb"])

    def test_a_node_with_one_of_the_two_carriers_joins_over_it(self):
        block, cid, _ = self.create()
        r = C.accept(self.jh, [self.J["fakeb"]], self.joiner, block, C.fingerprint(self.owner.id), clock=self.clock, wait_address=lambda c, n: c.door_endpoint(n))
        self.assertEqual(r["used"], ["fakeb"])

    def test_no_common_carrier_is_an_error_that_names_both_sides(self):
        block, cid, _ = self.create(("fake",))
        with self.assertRaises(C.CapsuleError) as cm:
            C.accept(self.jh, [self.J["fakeb"]], self.joiner, block, C.fingerprint(self.owner.id), clock=self.clock)
        self.assertIn("needs a carrier of one of ['fake']", str(cm.exception))
        self.assertIn("runs ['fakeb']", str(cm.exception))
        with self.assertRaises(C.CapsuleError):
            self.accept(self.create(("fake",))[0], only={"fakeb"})

    def test_a_capsule_address_the_carrier_refuses_is_refused_at_accept(self):
        block, cid, _ = self.create()
        good = C.decode_capsule(block, now=self.clock())
        evil = C.encode_capsule({**good, "joins": [{**good["joins"][0], "endpoint": {"type": "fake", "addr": "bad-1.fake:1"}}, good["joins"][1]]})
        with self.assertRaises(C.CapsuleError) as cm:
            self.accept(evil)
        self.assertIn("refused", str(cm.exception))
        self.assertEqual(self.J["fake"].doors(), {})
        self.assertEqual(C.Joins(self.jh).all(), {})

    def test_poll_falls_back_to_the_next_join_door_when_the_first_carrier_is_down(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.down = {"fake"}
        self.assertEqual(self.poll(), {r["cid"]: "requested"})
        self.assertEqual(C.Joins(self.jh).all()[r["cid"]]["offered"], ["fake", "fakeb"])
        self.assertEqual(self.poll(), {})
        self.down = {"fake", "fakeb"}
        self.assertEqual(self.poll(), {})                                # nothing reachable: try again next pass

    def test_a_slow_door_is_added_while_the_owner_still_has_the_request_pending(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.J["fakeb"].hidden = {f"owner-{self.owner.id[:26]}"}         # fakeb has no address yet
        self.assertEqual(self.poll(), {r["cid"]: "requested"})
        self.assertEqual([o["endpoint"]["type"] for o in self.rec(cid)["req"]["offers"]], ["fake"])
        self.J["fakeb"].hidden = set()
        self.poll()
        self.assertEqual([o["endpoint"]["type"] for o in self.rec(cid)["req"]["offers"]], ["fake", "fakeb"])
        self.assertEqual(C.Joins(self.jh).all()[r["cid"]]["offered"], ["fake", "fakeb"])

    def test_a_late_door_after_the_owner_confirmed_does_not_fail_the_join(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.J["fakeb"].hidden = {f"owner-{self.owner.id[:26]}"}
        self.assertEqual(self.poll(), {r["cid"]: "requested"})
        self.confirm(cid)                                                # the owner decided with one offer
        self.J["fakeb"].hidden = set()
        self.assertEqual(self.poll(), {r["cid"]: "joined"}, "the resend is refused (decided): the join goes on to the answer")
        self.assertEqual([e["type"] for e in self.jbook.all()[self.owner.id]["endpoints"]], ["fake"])

    def test_nothing_is_sent_until_one_of_our_doors_has_an_address(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.J["fake"].hidden = self.J["fakeb"].hidden = {f"owner-{self.owner.id[:26]}"}
        self.assertEqual(self.poll(), {})
        self.assertEqual(self.rec(cid)["state"], "open")

    def test_a_refused_request_fails_the_join_and_forgets_the_bootstrap_keys(self):
        block, cid, _ = self.create()
        self.server.handle(self.request(Identity.generate("m"), block_dict(block)["token"], self.offers_for(("fake",))))
        r = self.accept(block)
        self.assertEqual(self.poll(), {r["cid"]: "failed"})
        self.assertEqual(list((Path(self.jh) / "peerkeys").glob("join-*")), [])
        for t, c in self.J.items():
            self.assertFalse(c.drop_credential(C.decode_capsule(block, now=self.clock())["joins"][0]["endpoint"] if t == "fake" else C.decode_capsule(block, now=self.clock())["joins"][1]["endpoint"]))

    def test_a_joiner_restart_between_accept_and_poll_rereads_the_per_type_files(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        files = sorted(p.name for p in (Path(self.jh) / "peerkeys").iterdir())
        self.assertEqual(files, [f"join-{r['cid']}-fake.priv", f"join-{r['cid']}-fakeb.priv"])
        self.assertEqual(self.poll(), {r["cid"]: "requested"})           # (everything is read from joins.json and the key files: no memory)
        self.confirm(cid)
        self.assertEqual(self.poll(), {r["cid"]: "joined"})


class VerifyJoined(Rig):
    def setUp(self):
        super().setUp()
        self.block, self.cid, _ = self.create()
        self.r = self.accept(self.block)
        self.poll()
        self.rec_j = C.Joins(self.jh).all()[self.r["cid"]]
        self.eps = [self.O["fake"].door_endpoint(f"join-{self.cid}"), self.O["fakeb"].door_endpoint(f"join-{self.cid}")]

    def signed(self, **over):
        body = {"t": "joined", "token": self.rec_j["token"], "endpoints": self.eps, "thread": self.rec_j["thread"], "owner": self.owner.id, "enc": False, "keys": [], "by": self.owner.sign_pub, **over}
        body["rsig"] = self.owner.sign(C.JOIN_CTX + canon.dumps(body))
        return body

    def test_the_matrix(self):
        self.assertTrue(C._verify_joined(self.signed(), self.rec_j, self.J))
        e0, e1 = self.eps
        for name, eps in {"none": [], "three": self.eps + [e0], "duplicate": [e0, e0], "not a list": e0, "bad address": [{"type": "fake", "addr": "bad-1.fake:1"}]}.items():
            self.assertFalse(C._verify_joined(self.signed(endpoints=eps), self.rec_j, self.J), name)
        self.assertFalse(C._verify_joined(self.signed(endpoints=[{"type": "onion", "addr": "a" * 56 + ".onion:1"}]), self.rec_j, self.J), "a type outside the capsule")
        narrow = {**self.rec_j, "offered": ["fake"]}
        self.assertFalse(C._verify_joined(self.signed(endpoints=[e1]), narrow, self.J), "a type we did not offer")
        self.assertTrue(C._verify_joined(self.signed(endpoints=[e0]), narrow, self.J))
        self.assertFalse(C._verify_joined(self.signed(endpoints=[e0]), self.rec_j, {"fakeb": self.J["fakeb"]}), "a carrier we do not run")
        b = self.signed()
        self.assertFalse(C._verify_joined({**b, "endpoints": [e0]}, self.rec_j, self.J), "the signature covers the endpoints")

    def test_the_endpoints_are_installed_in_the_normalised_spelling(self):
        self.confirm(self.cid)
        upper = [{"type": e["type"], "addr": e["addr"].upper()} for e in self.eps]

        class T:
            def request(s, q):
                return self_.signed(endpoints=upper)
        self_ = self
        self.transport_for = lambda ep: T()
        self.assertEqual(self.poll(), {self.r["cid"]: "joined"})
        got = sorted(e["addr"] for e in self.jbook.all()[self.owner.id]["endpoints"])
        self.assertEqual(got, sorted(e["addr"] for e in self.eps))

    def test_an_end_to_end_join_over_both_carriers_gives_both_endpoints(self):
        self.confirm(self.cid)
        self.assertEqual(self.poll(), {self.r["cid"]: "joined"})
        peer = self.jbook.all()[self.owner.id]
        self.assertEqual(sorted(e["type"] for e in peer["endpoints"]), ["fake", "fakeb"])
        self.assertEqual(peer["threads"], [self.tid])
        self.assertEqual(sorted(p.name for p in (Path(self.jh) / "peerkeys").glob("join-*")), [f"join-{self.r['cid']}-fake.priv", f"join-{self.r['cid']}-fakeb.priv"])      # kept: they dial the owner's doors
        self.assertEqual(C.Joins(self.jh).all()[self.r["cid"]]["state"], "joined")

    def test_an_end_to_end_join_with_the_first_carrier_down_goes_over_the_second(self):
        self.down = {"fake"}
        self.confirm(self.cid)
        self.assertEqual(self.poll(), {self.r["cid"]: "joined"})
        self.assertEqual(sorted(e["type"] for e in self.jbook.all()[self.owner.id]["endpoints"]), ["fake", "fakeb"])


class RealTcp(unittest.TestCase):
    """A join through a REAL tcp join door (TLS, admission with the capsule's boot key) next to a fake carrier: the capsule lists both, the doors answer behind Doors, both endpoints arrive."""

    def test_a_join_over_the_real_tcp_door_and_the_fake_one_gives_both_endpoints(self):
        from sigilnet.doors import Doors
        from sigilnet.sync import SyncServer
        from sigilnet.tests.test_tcplink import carrier
        clock = Clock()
        net = FakeNet()
        oh, jh = tempfile.mkdtemp(), tempfile.mkdtemp()
        owner, joiner = Identity.generate("owner"), Identity.generate("joiner")
        O = {"tcp": carrier(Path(oh) / "tcp"), "fake": FakeCarrier(net, "own")}
        J = {"tcp": carrier(Path(jh) / "tcp"), "fake": FakeCarrier(net, "jn")}
        for c in list(O.values()) + list(J.values()):
            c.start()
        om = Mirror(oh + "/m", clock=clock, rate_limit=False)
        g = make_genesis(owner, "secret project", [], ts=int(clock()))
        om.ingest(g)
        tid = event_id(g)
        obook, jbook = PeerBook(Path(oh) / "peers.json"), PeerBook(Path(jh) / "peers.json")
        server = C.JoinServer(oh, O, owner, om, clock)
        srv = SyncServer(om, identity=owner)
        odoors = {t: Doors(c, srv, lambda *a: None, {"join": server.handle}) for t, c in O.items()}
        try:
            wait = lambda c, n: c.door_endpoint(n)                  # noqa: E731
            block, cid, fp = C.create(oh, [O["tcp"], O["fake"]], owner, om, tid, clock=clock, wait_address=wait)
            for d in odoors.values():
                d.sync()
            c = C.decode_capsule(block, now=clock())
            self.assertEqual([j["endpoint"]["type"] for j in c["joins"]], ["tcp", "fake"])
            r = C.accept(jh, J, joiner, block, fp, clock=clock, wait_address=wait)
            transport = lambda ep: J[ep["type"]].dial(ep, timeout=5)    # noqa: E731
            self.assertEqual(C.poll(jh, J, joiner, jbook, transport, clock=clock), {r["cid"]: "requested"})
            self.assertEqual(sorted(o["endpoint"]["type"] for o in C.Store(oh).all()[cid]["req"]["offers"]), ["fake", "tcp"])
            C.confirm(oh, O, owner, om, obook, cid, C.fingerprint(joiner.id), clock=clock)
            for d in odoors.values():
                d.sync()
            self.assertEqual(C.poll(jh, J, joiner, jbook, transport, clock=clock), {r["cid"]: "joined"})
            peer = jbook.all()[owner.id]
            self.assertEqual(sorted(e["type"] for e in peer["endpoints"]), ["fake", "tcp"])
            for ep in peer["endpoints"]:                             # the joiner reaches the owner's peer door on each carrier with the credential it was given
                resp = J[ep["type"]].dial(ep, timeout=5, agent=owner.id).request({"t": "ping", "n": 1})
                self.assertIsInstance(resp, dict, ep)
            self.assertEqual(sorted(e["type"] for e in obook.all()[joiner.id]["endpoints"]), ["fake", "tcp"])
        finally:
            for d in odoors.values():
                d.stop()
            for c in list(O.values()) + list(J.values()):
                c.stop()


class JoinWorker(unittest.TestCase):
    def test_a_tick_sweeps_only_the_carriers_that_are_up_and_polls_over_the_ones_that_are(self):
        from sigilnet import noderun
        calls = []
        carriers = {"tcp": mock.Mock(), "onion": mock.Mock()}
        jw = noderun._JoinWorker(Path(tempfile.mkdtemp()), carriers, Identity.generate("me"), mock.Mock(), calls.append, usable=lambda t: t == "tcp")
        with mock.patch.object(noderun.capsule, "sweep", side_effect=lambda home, cs, **k: calls.append((sorted(c for c in k.get("skip", [])), len(cs)))):
            jw.tick()
        self.assertEqual(calls, [(["onion"], 2)])
        with self.assertRaises(Exception):
            jw._transport({"type": "onion", "addr": "a" * 56 + ".onion:1"})
        carriers["tcp"].dial.return_value = "tr"
        self.assertEqual(jw._transport({"type": "tcp", "addr": "1.2.3.4:5000#" + "ab" * 32}), "tr")


if __name__ == "__main__":
    unittest.main()
