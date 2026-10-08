"""Sansa's adversarial suite for the open invitation (knock.py), review of knock_s2. Built on Arya's fixtures (test_knock.Base)."""
import hashlib
import json
import random
import threading
import time
import unittest
from pathlib import Path

from sigilnet import canon
from sigilnet import knock as K
from sigilnet import pow as P
from sigilnet.keys import Identity

from .test_capsule import onion_for
from .test_knock import Base, fast


def fb(path):
    p = Path(path)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


class Junk(Base):
    def test_random_junk_never_raises_never_writes_and_answers_from_a_small_set(self):
        block, cid, _ = self.card()
        files = [Path(self.oh) / "cards.json", Path(self.oh) / "knocks.json"]
        before = [fb(f) for f in files]
        rnd = random.Random(5)
        atoms = [None, 0, 1, -1, True, 1.5, "", "x", "challenge", "knock", "status", cid, "z" * 300, [], {}, [1], {"a": 1}, 10 ** 30, "\x00", "‮"]
        keys = ["t", "card", "owner", "thread", "ts", "sign", "kex", "name", "note", "offers", "salt", "pow", "sig", "x"]
        allowed = {json.dumps(K.REFUSED)}
        seen = set()
        for i in range(4000):
            req = {k: rnd.choice(atoms) for k in rnd.sample(keys, rnd.randint(0, 9))}
            if rnd.random() < .6:
                req["t"] = rnd.choice(["challenge", "knock", "status"])
            if rnd.random() < .6:
                req["card"] = cid
            if rnd.random() < .1:
                req = rnd.choice(atoms)
            r = self.server.handle(req)
            seen.add(json.dumps(r, sort_keys=True))
        # a bare challenge to the right card legitimately answers; everything else is the refusal
        extra = [s for s in seen if s not in allowed and json.loads(s).get("t") != "challenge"]
        self.assertEqual(extra, [])
        self.assertEqual([fb(f) for f in files], before)                         # not one byte written by 4000 junk requests
        self.assertGreater(self.server.bad[cid], 100)
        self.assertEqual(self.server.handle({"t": "challenge", "card": cid})["t"], "challenge")


class StatusOracle(Base):
    def test_every_wrong_status_is_the_same_bytes(self):
        block, cid, _ = self.card()
        block2, cid2, _ = self.card()
        self.server.handle(self.knock_req(cid))
        good = self.status_req(cid, self.joiner)
        ref = canon.dumps(K.REFUSED)
        bads = []
        bads.append(self.status_req(cid, self.stranger()))                                   # unknown key
        bads.append(self.status_req(cid2, self.joiner))                                      # right key, other card (no knock there)
        b = dict(good); b["sig"] = "00" * 64; bads.append(b)                                  # bad signature
        b = dict(good); b["ts"] += 1; bads.append(b)                                          # tampered ts
        b = dict(good); b["owner"] = self.stranger().id; bads.append(b)
        b = dict(good); b["thread"] = "ab" * 16; bads.append(b)
        b = dict(good); b["extra"] = 1; bads.append(b)
        b = dict(good); b["card"] = "ffffffff"; bads.append(b)                                # unknown card
        for r in bads:
            self.assertEqual(canon.dumps(self.server.handle(r)), ref, r)
        self.assertEqual(self.server.handle(good)["t"], "pending")


class Replay(Base):
    def test_replayed_knock_is_idempotent_and_a_tampered_one_is_not_taken(self):
        block, cid, _ = self.card()
        req = self.knock_req(cid)
        for _ in range(5):
            self.assertEqual(self.server.handle(dict(req))["t"], "pending")
        self.assertEqual(len(K.pending(self.oh, self.clock)), 1)
        self.assertEqual(len(self.woke), 1)                                                  # one wake, not five
        for field, val in (("name", "mallory"), ("note", "hi"), ("ts", req["ts"] + 1)):
            r = dict(req); r[field] = val
            out = self.server.handle(r)
            self.assertNotEqual(out.get("t"), "pending", field)                              # PoW and signature are bound to the body
        self.assertEqual(len(K.pending(self.oh, self.clock)), 1)

    def test_someone_elses_signature_with_my_key_is_refused(self):
        block, cid, _ = self.card()
        req = self.knock_req(cid)
        other = self.stranger()
        forged = dict(req); forged["sig"] = other.sign(K.KNOCK_CTX + canon.dumps({k: v for k, v in req.items() if k != "sig"}))
        self.assertEqual(self.server.handle(forged), K.REFUSED)
        self.assertEqual(K.pending(self.oh, self.clock), {})

    def test_a_proof_for_one_card_is_no_use_on_another(self):
        b1, c1, _ = self.card()
        b2, c2, _ = self.card()
        r = self.knock_req(c1)
        r2 = dict(r); r2["card"] = c2
        out = self.server.handle(r2)
        self.assertNotEqual(out.get("t"), "pending")                                         # the body (so card id) is what the proof and signature cover
        self.assertEqual(K.pending(self.oh, self.clock), {})


class Salt(Base):
    def test_salt_window(self):
        block, cid, _ = self.card()
        key = json.loads((Path(self.oh) / "cards.json").read_text())[cid]["salt_key"]
        period = int(self.clock()) // 3600
        for back, want in ((0, "pending"), (1, "pending"), (2, None), (5, None)):
            who = Identity.generate(f"s{back}")
            salt = K.salt_for(key, period - back).hex()
            r = self.server.handle(self.knock_req(cid, who=who, salt=salt))
            if want:
                self.assertEqual(r["t"], want, back)
            else:
                self.assertEqual(r, K.REFUSED, back)                                          # two or more periods old: the plain refusal
        self.assertEqual(self.server.handle(self.knock_req(cid, who=Identity.generate("rs"), salt="00" * 16)), K.REFUSED)


class Pool(Base):
    def fill(self, cid, n, start=0):
        ids = []
        for i in range(n):
            who = Identity.generate(f"n{start + i}")
            r = self.server.handle(self.knock_req(cid, who=who))
            self.assertEqual(r["t"], "pending", r)
            ids.append(who)
        return ids

    def test_cap_never_exceeded_and_a_knock_at_the_raised_cost_displaces_exactly_one(self):
        block, cid, _ = self.card()
        first = self.fill(cid, K.POOL_CAP)
        self.assertEqual(len(K.pending(self.oh, self.clock)), K.POOL_CAP)
        late = self.server.handle(self.knock_req(cid, who=Identity.generate("late")))          # solved at the RAISED cost (challenge says pow+4)
        self.assertEqual(late["t"], "pending")
        self.assertEqual(len(K.pending(self.oh, self.clock)), K.POOL_CAP)
        gone = [w for w in first if self.server.handle(self.status_req(cid, w))["t"] == "evicted"]
        self.assertEqual(len(gone), 1)
        # a flooder who keeps paying the raised cost can cycle the whole pool: pinned entries are the only protection
        kid = next(iter(K.pending(self.oh, self.clock)))
        self.assertTrue(K.pin(self.oh, kid, clock=self.clock))

    def test_the_finished_table_stays_small_on_disk(self):
        """Disk-cost review: what is the size of knocks.json after a flood that evicts/rejects 1000+ entries, and what one more knock writes?"""
        block, cid, _ = self.card()
        d = Path(self.oh) / "knocks.json"
        big = "n" * 32
        pool = K.pool_store(self.oh, self.clock)
        def add(dd):
            for i in range(K.MAX_FINISHED):
                dd[f"{i:08x}"] = {"card": cid, "agent": Identity.generate("q").id if i < 3 else "a" * 32, "sign": "bb" * 32, "kex": "cc" * 32, "name": big, "note": "N" * 512,
                                  "offers": [{"endpoint": {"type": "onion", "addr": onion_for(i % 50) + ":47200"}, "credential": {"type": "onion", "key": "A" * 52}}],
                                  "bits": 20, "state": "evicted", "at": int(self.clock()), "exp": int(self.clock()) + 100, "pinned": False}
                K.finish(dd[f"{i:08x}"], "evicted", self.clock())                       # what the server really does when a knock leaves the live set
        pool.edit(add)
        size = d.stat().st_size
        print(f"\n[sansa] knocks.json with {K.MAX_FINISHED} finished (evicted) entries: {size / 1024:.0f} KiB; every new valid knock rewrites it whole")
        t0 = time.perf_counter()
        r = self.server.handle(self.knock_req(cid, who=Identity.generate("z")))
        dt = time.perf_counter() - t0
        print(f"[sansa] one valid knock on that pool took {dt * 1000:.0f} ms")
        self.assertEqual(r["t"], "pending")
        self.assertGreater(size, 100 * 1024, "(the records must really be there: a vacuous test proves nothing)")
        self.assertEqual(len(K.pool_store(self.oh, self.clock).all()), K.MAX_FINISHED + 1)
        self.assertLess(size, 450 * 1024, "finished records keep no note and no offers")


class Sealing(Base):
    def setUp(self):
        super().setUp()
        self.block, self.cid, _ = self.card()

    def confirmed(self):
        self.join(self.block)
        self.poll()
        kid = next(iter(K.pending(self.oh, self.clock)))
        out = K.accept(self.oh, self.otor, self.owner, self.om, self.obook, kid, K.fingerprint(self.joiner.id), clock=self.clock)
        self.ofake(out["door"])
        self.clock.t += 30
        return kid

    def test_another_joiners_status_gets_nothing_and_the_box_is_not_transferable(self):
        self.confirmed()
        mine = self.server.handle(self.status_req(self.cid, self.joiner))
        self.assertEqual(mine["t"], "box")
        self.assertEqual(self.server.handle(self.status_req(self.cid, self.stranger())), K.REFUSED)
        other = self.stranger()
        with self.assertRaises(K.KnockError):
            K.open_box(other, K.ANSWER_CTX + self.cid.encode() + other.id.encode(), mine["box"])
        with self.assertRaises(K.KnockError):                                                # right key, wrong card context
            K.open_box(self.joiner, K.ANSWER_CTX + b"ffffffff" + self.joiner.id.encode(), mine["box"])
        flip = json.loads(json.dumps(mine["box"])); c = flip["c"]; flip["c"] = ("A" if c[0] != "A" else "B") + c[1:]
        with self.assertRaises(K.KnockError):
            K.open_box(self.joiner, K.ANSWER_CTX + self.cid.encode() + self.joiner.id.encode(), flip)

    def test_a_forged_owner_cannot_answer_a_joiner(self):
        """A box sealed to the joiner by someone who is NOT the pinned owner is refused by verify_answer."""
        self.confirmed()
        rec = json.loads((Path(self.jh) / "outknocks.json").read_text())[self.cid]
        mallory = Identity.generate("mallory")
        body = {"t": "joined", "card": self.cid, "thread": self.tid, "owner": self.owner.id, "name": "arya", "to": self.joiner.id, "endpoints": [{"type": "onion", "addr": onion_for(3) + ":47200"}],
                "enc": False, "keys": [], "by": mallory.sign_pub}
        body["rsig"] = mallory.sign(K.ANSWER_CTX + canon.dumps(body))
        box = K.seal_to(self.joiner.kex_pub, K.ANSWER_CTX + self.cid.encode() + self.joiner.id.encode(), canon.dumps(body))
        self.assertIsNone(K.verify_answer({"t": "box", "box": box}, rec, self.joiner, {c.type: c for c in K._carrier_list(self.jtor)}))
        body["by"] = self.owner.sign_pub                                                       # claims the owner's key, signs with her own
        body["rsig"] = mallory.sign(K.ANSWER_CTX + canon.dumps({k: v for k, v in body.items() if k != "rsig"}))
        box = K.seal_to(self.joiner.kex_pub, K.ANSWER_CTX + self.cid.encode() + self.joiner.id.encode(), canon.dumps(body))
        self.assertIsNone(K.verify_answer({"t": "box", "box": box}, rec, self.joiner, {c.type: c for c in K._carrier_list(self.jtor)}))

    def test_the_owner_signed_answer_for_joiner_a_is_refused_by_joiner_b(self):
        """Replay of a genuine answer to a different joiner (same card): `to` and the AAD bind it to A."""
        self.confirmed()
        mine = self.server.handle(self.status_req(self.cid, self.joiner))
        b = self.stranger()
        recb = {"card": K.decode_card(self.block, now=self.clock()), "mypub": {"onion": {"type": "onion", "key": "A" * 52}}}
        self.assertIsNone(K.verify_answer(mine, recb, b, {c.type: c for c in K._carrier_list(self.jtor)}))


class Grace(Base):
    def test_collect_window_after_an_immediate_close(self):
        """Owner accepts and closes the card at once: how long has the newcomer to collect, against the joiner's own backoff?"""
        block, cid, _ = self.card()
        self.join(block)
        self.poll()
        kid = next(iter(K.pending(self.oh, self.clock)))
        out = K.accept(self.oh, self.otor, self.owner, self.om, self.obook, kid, K.fingerprint(self.joiner.id), clock=self.clock)
        self.ofake(out["door"])
        K.close_card(self.oh, self.otor, cid, clock=self.clock)
        worst_wait = K.POLL_MAX * 1.2
        print(f"\n[sansa] GRACE {K.GRACE} s; the joiner's longest poll interval is {K.POLL_MAX} s x1.2 jitter = {worst_wait:.0f} s: only {K.GRACE - worst_wait:.0f} s of slack for one failed poll")
        self.clock.t += K.GRACE - 10
        self.assertEqual(self.server.handle(self.status_req(cid, self.joiner))["t"], "box")   # still collectable just inside the window
        self.clock.t += 20
        self.assertEqual(self.server.handle(self.status_req(cid, self.joiner)), K.REFUSED)    # and gone just after
        self.assertGreaterEqual(K.GRACE, K.POLL_MAX * 1.2 * 2, "a joiner that has backed off to the maximum gets one try inside the grace, no retry")


class Retry(Base):
    def test_a_failed_join_can_be_tried_again_with_the_same_card(self):
        """The failure texts say 'fix the clock and join again'; the same card must then be usable."""
        block, cid, _ = self.card()
        self.join(block)
        out = K.outbox(self.jh, self.clock)
        out.edit(lambda d: d[cid].update(state="failed", why="your clock is off"))
        try:
            self.join(block)
        except K.KnockError as e:
            self.fail(f"a failed join cannot be retried: {e}")


class Races(Base):
    def test_parallel_knocks_keep_the_pool_valid_and_bounded(self):
        block, cid, _ = self.card()
        reqs = [self.knock_req(cid, who=Identity.generate(f"p{i}")) for i in range(60)]
        out, errs = [], []

        def run(r):
            try:
                out.append(self.server.handle(r)["t"])
            except Exception as e:                                  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=run, args=(r,)) for r in reqs]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        raw = json.loads((Path(self.oh) / "knocks.json").read_text())
        live = [k for k, v in raw.items() if v["state"] in ("pending", "confirming")]
        self.assertLessEqual(len(live), K.POOL_CAP)
        self.assertEqual(out.count("pending") - sum(1 for v in raw.values() if v["state"] == "evicted"), len(live))
        self.assertEqual(len(self.woke), out.count("pending"))

    def test_two_accepts_of_one_knock_make_one_member(self):
        block, cid, _ = self.card()
        self.join(block)
        self.poll()
        kid = next(iter(K.pending(self.oh, self.clock)))
        res = []

        def run():
            try:
                K.accept(self.oh, self.otor, self.owner, self.om, self.obook, kid, K.fingerprint(self.joiner.id), clock=self.clock)
                res.append("ok")
            except Exception as e:                                  # noqa: BLE001
                res.append(type(e).__name__)
        ts = [threading.Thread(target=run) for _ in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sorted(res), ["KnockError", "ok"], res)
        members = [a for a in self.om.threads[self.tid].state()["members"] if a == self.joiner.id]
        self.assertEqual(len(members), 1)

    def test_close_during_accept_never_leaves_a_pending_knock_of_a_closed_card_decidable(self):
        block, cid, _ = self.card()
        self.join(block)
        self.poll()
        kid = next(iter(K.pending(self.oh, self.clock)))
        K.close_card(self.oh, self.otor, cid, clock=self.clock)
        with self.assertRaises(K.KnockError):
            K.accept(self.oh, self.otor, self.owner, self.om, self.obook, kid, K.fingerprint(self.joiner.id), clock=self.clock)
        self.assertNotIn(self.joiner.id, self.om.threads[self.tid].state()["members"])


class Strangers(Base):
    def test_hostile_text_is_refused_not_stored(self):
        block, cid, _ = self.card()
        for over in ({"name": "a\x1b[2Jb"}, {"name": "x" * 33}, {"name": ""}, {"name": "ab‮cd"}, {"name": "é"}, {"note": "n" * 513}, {"note": "a\nb"}, {"note": "\x07"},
                     {"name": 5}, {"note": None}):
            r = self.server.handle(self.knock_req(cid, who=Identity.generate("h"), **over))
            self.assertEqual(r, K.REFUSED, over)
        self.assertEqual(K.pending(self.oh, self.clock), {})

    def test_size_limit_and_clock_window(self):
        block, cid, _ = self.card()
        r = self.knock_req(cid, who=Identity.generate("s"), note="n" * 500)
        pad = dict(r); pad["pad"] = "x" * 4000
        self.assertEqual(self.server.handle(pad), K.REFUSED)
        for off, want in ((-599, "pending"), (599, "pending"), (-601, "clock"), (601, "clock")):
            who = Identity.generate("c")
            r = self.knock_req(cid, who=who, ts=int(self.clock()) + off)
            self.assertEqual(self.server.handle(r)["t"], want, off)

    def test_bad_offers(self):
        block, cid, _ = self.card()
        mine = {"type": "onion", "addr": onion_for(77) + ":47200"}
        cred = {"type": "onion", "key": "A" * 52}
        for offers in ([], [{"endpoint": mine, "credential": cred}] * 2, [{"endpoint": {"type": "onion", "addr": "127.0.0.1:47200"}, "credential": cred}],
                       [{"endpoint": {"type": "tcp", "addr": "127.0.0.1:47200"}, "credential": {"type": "tcp", "key": "A" * 52}}], [{"endpoint": mine}], "x", None,
                       [{"endpoint": mine, "credential": cred, "extra": 1}]):
            r = self.server.handle(self.knock_req(cid, who=Identity.generate("o"), offers=offers))
            self.assertEqual(r, K.REFUSED, offers)

    def test_a_member_and_the_owner_get_the_plain_refusal(self):
        block, cid, _ = self.card()
        self.assertEqual(self.server.handle(self.knock_req(cid, who=self.owner)), K.REFUSED)


class Restart(Base):
    def test_a_new_server_over_the_same_home_sees_pool_and_closed_cards(self):
        block, cid, _ = self.card()
        self.server.handle(self.knock_req(cid))
        K.close_card(self.oh, self.otor, cid, clock=self.clock)
        s2 = K.KnockServer(self.oh, self.otor, self.owner, self.om, self.clock)
        self.assertEqual(s2.handle({"t": "challenge", "card": cid}), K.REFUSED)
        self.assertEqual(s2.handle(self.status_req(cid, self.joiner))["t"], "rejected")        # pending ones of a closed card are told so within the grace


class TcpDoor(Base):
    def test_a_card_needs_a_carrier_that_hides_the_address_and_the_handler_is_wired_for_it_only(self):
        class Bare:
            type, capabilities = "tcp", frozenset()
        with self.assertRaises(K.KnockError):
            K.create_card(self.oh, [Bare()], self.owner, self.om, self.tid, wait_address=self.ofake)
        import sigilnet.noderun as NR
        src = Path(NR.__file__).read_text()
        self.assertIn('handlers if c is tor else {"join": join_handler}', src)               # documents: only the primary carrier carries the knock handler


if __name__ == "__main__":
    unittest.main()
