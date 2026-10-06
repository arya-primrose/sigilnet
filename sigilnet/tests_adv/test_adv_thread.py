"""Adversarial tests of thread rules (spec 4, 4.1, 5, 6). Tests marked `# BUG:` currently fail and expose a real defect."""
import copy
import time
import unittest

from sigilnet import event as E
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id, sign_input, signed_bytes
from sigilnet.keys import Identity
from sigilnet.thread import Thread

from .advutil import World, resign, st


class Genesis(unittest.TestCase):
    def test_genesis_signature_is_verified(self):
        # BUG: Thread.__init__ never verifies the genesis signature, so anyone can forge a thread "owned" by a victim
        # (public key is all that is needed) with a junk signature and every mirror will store it.
        w = World()
        g = copy.deepcopy(w.genesis)
        g["sig"] = "00" * 64
        try:
            Thread(g)
            accepted = True
        except E.EventError:
            accepted = False
        self.assertFalse(accepted, "forged genesis with a zero signature was accepted")

    def test_genesis_with_other_owners_sig_rejected(self):
        # BUG: same root cause as test_genesis_signature_is_verified
        w = World()
        g = copy.deepcopy(w.genesis)
        g["sig"] = w.ids["sansa"].sign(sign_input(g))       # signed by a non-owner
        with self.assertRaises(E.EventError):
            Thread(g)

    def test_malformed_genesis_never_raises_anything_but_eventerror(self):
        # BUG: unhashable items in successors / member ids make `set(...)`/`in dict` raise TypeError instead of EventError
        w = World()
        base = w.genesis["body"]
        variants = []
        b = copy.deepcopy(base); b["successors"] = [["x"]]; variants.append(b)
        b = copy.deepcopy(base); b["successors"] = [{"a": 1}]; variants.append(b)
        b = copy.deepcopy(base); b["members"][1]["id"] = ["x"]; variants.append(b)
        b = copy.deepcopy(base); b["members"][1]["role"] = ["x"]; variants.append(b)
        b = copy.deepcopy(base); b["visibility"] = ["private"]; variants.append(b)
        b = copy.deepcopy(base); b["keys"][w.ids["sansa"].id] = []; variants.append(b)
        b = copy.deepcopy(base); b["owner"] = ["x"]; variants.append(b)
        for i, body in enumerate(variants):
            g = E.make_event(w.ids["arya"], thread="", kind="genesis", body=body, parents=[], seq=0, admin_ref="")
            try:
                Thread(g)
            except E.EventError:
                pass
            except Exception as e:  # noqa
                self.fail(f"variant {i}: {type(e).__name__}: {e}")

    def test_mirror_ingest_never_raises_on_malformed_genesis(self):
        # BUG (same root cause): Mirror.ingest promises to never raise
        from sigilnet.mirror import Mirror
        import tempfile
        w = World()
        b = copy.deepcopy(w.genesis["body"]); b["successors"] = [["x"]]
        g = E.make_event(w.ids["arya"], thread="", kind="genesis", body=b, parents=[], seq=0, admin_ref="")
        m = Mirror(tempfile.mkdtemp())
        self.assertEqual(m.ingest(g).status, "rejected")

    def test_genesis_seq0_second_event_by_owner_is_conflict_not_accept(self):
        w = World()
        ev = E.make_event(w.ids["arya"], thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=0, admin_ref=w.t.id)
        self.assertEqual(st(w, ev).status, "conflict")

    def test_owner_equivocation_with_genesis_can_be_filed_as_evidence(self):
        # BUG (low): the genesis has thread == "" so `evidence` (which demands a["thread"] == thread id) can never carry it;
        # an owner who signs a second seq-0 event is recorded as a conflict but that proof cannot be broadcast.
        w = World()
        ev = E.make_event(w.ids["arya"], thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=0, admin_ref=w.t.id)
        self.assertEqual(st(w, ev).status, "conflict")
        evd = w.w("sansa").event("evidence", {"a": w.genesis, "b": ev, "reason": "owner seq 0"})
        self.assertTrue(st(w, evd).ok, st(w, evd))

    def test_kex_key_of_low_order_is_rejected(self):
        # BUG (low): kex is only checked to be 64 hex chars; an all-zero X25519 key makes every later ECIES seal to that member fail
        # (cryptography raises on the all-zero shared secret), so a member/guest can jam epoch rotation.
        from cryptography.hazmat.primitives.asymmetric import x25519
        z = bytes(32)
        with self.assertRaises(ValueError):
            Identity.generate().kex_key.exchange(x25519.X25519PublicKey.from_public_bytes(z))     # the premise
        w = World()
        d = w.ids["dave"]
        body = {"agent": d.id, "name": "dave", "role": "member", "sign": d.sign_pub, "kex": "00" * 32}
        self.assertEqual(st(w, w.w("arya").admin("member_add", body)).status, "rejected")


class Keys(unittest.TestCase):
    def test_noncanonical_small_order_encodings_never_verify(self):
        # BUG (high): see WeakKey; 0100..0080 verifies the universal signature
        from sigilnet.keys import verify_strict
        ident = bytes.fromhex("01" + "00" * 31)
        sig = (ident + bytes(32)).hex()
        cands = ["01" + "00" * 30 + "80", "ec" + "ff" * 30 + "ff", "ed" + "ff" * 30 + "7f", "ee" + "ff" * 30 + "7f",
                 "00" * 32, "01" + "00" * 31, "ec" + "ff" * 30 + "7f"]
        for c in cands:
            for msg in (b"", b"x", b"hello"):
                self.assertFalse(verify_strict(c, sig, msg), c)

    def test_signature_with_noncanonical_S_plus_L_rejected(self):
        from sigilnet.keys import L, verify_strict
        i = Identity.generate()
        sig = bytes.fromhex(i.sign(b"m"))
        s2 = (int.from_bytes(sig[32:], "little") + L).to_bytes(32, "little")
        self.assertFalse(verify_strict(i.sign_pub, (sig[:32] + s2).hex(), b"m"))


class WeakKey(unittest.TestCase):
    def test_noncanonical_identity_key_cannot_be_a_member(self):
        # BUG (high): the encoding y=1 with the sign bit set (0100..0080, x=0 "negative") is a non-canonical spelling of the identity
        # point. It is not in SMALL_ORDER, passes valid_sign_pub, and OpenSSL verifies the universal signature (R=identity, S=0) for
        # EVERY message. An agent registered with it has signatures anyone can forge (and equivocation evidence proves nothing).
        from sigilnet.keys import agent_id, verify_strict
        weak = "01" + "00" * 30 + "80"
        sig = ("01" + "00" * 31 + "00" * 32)
        self.assertFalse(verify_strict(weak, sig, b"any message at all"))

    def test_forged_post_from_weak_key_member(self):
        from sigilnet.keys import agent_id
        w = World()
        weak = "01" + "00" * 30 + "80"
        wid = agent_id(bytes.fromhex(weak))
        body = {"agent": wid, "name": "weak", "role": "member", "sign": weak, "kex": Identity.generate().kex_pub}
        r = st(w, w.w("arya").admin("member_add", body))
        if not r.ok:
            return                                    # fine: the key is refused at admission
        ev = {"v": 1, "thread": w.t.id, "author": wid, "seq": 0, "parents": [w.t.id], "admin_ref": w.t.head, "ts": 1, "kind": "post",
              "body": {"text": "forged by anyone"}, "sig": "01" + "00" * 31 + "00" * 32}
        self.assertNotEqual(st(w, ev).status, "accepted", "a post 'signed' with the universal signature was accepted")


class Cosigs(unittest.TestCase):
    def w3(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        return w

    def test_cosig_from_non_admin_member_does_not_count(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        ev = w.w("arya").add_member(w.ids["eve"], "member", cosigners=[w.ids["carol"]])       # carol is a plain member
        self.assertEqual(st(w, ev).status, "rejected")

    def test_cosig_from_observer_does_not_count(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        ev = w.w("arya").add_member(w.ids["eve"], "member", cosigners=[w.ids["hu"]])
        self.assertEqual(st(w, ev).status, "rejected")

    def test_cosig_over_different_bytes_does_not_count(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        ev = w.w("arya").add_member(w.ids["eve"], "member")
        other = w.w("arya").add_member(w.ids["eve"], "guest")       # same prev, different bytes
        good = E.add_cosig(other, w.ids["dave"])
        ev["cosigs"] = good["cosigs"]                               # dave's signature over the OTHER event
        self.assertEqual(st(w, ev).status, "rejected")

    def test_stripped_cosig_gives_same_id_and_valid_copy_still_accepted_after(self):
        w = World(k=2, extra_members=[("dave", "admin")])
        full = w.w("arya").add_member(w.ids["eve"], "member", cosigners=[w.ids["dave"]])
        stripped = {k: v for k, v in full.items() if k != "cosigs"}
        self.assertEqual(event_id(full), event_id(stripped))
        self.assertEqual(st(w, stripped).status, "rejected")
        self.assertTrue(st(w, full).ok)

    def test_cosig_by_removed_admin_does_not_count(self):
        w = World(k=2, extra_members=[("dave", "admin"), ("eve", "admin")])
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["dave"].id}, cosigners=[w.ids["eve"]]))
        f = Identity.generate("frank")
        ev = w.w("arya").add_member(f, "member", cosigners=[w.ids["dave"]])
        self.assertEqual(st(w, ev).status, "rejected")

    def test_junk_cosigs_on_a_post_are_rejected(self):
        # BUG (low): cosigs are outside the id, unauthenticated for non-admin kinds and unchecked: a relay can bolt up to 16 junk
        # cosigs onto any valid post; the stored bytes then differ between mirrors and the event can be pushed over the size cap.
        w = World()
        ev = w.w("sansa").post("hello")
        ev["cosigs"] = [{"author": w.ids["carol"].id, "sig": "ab" * 64}]
        r = st(w, ev)
        self.assertNotEqual(r.status, "accepted", "post with a junk cosig was accepted and stored with it")

    def test_junk_cosigs_can_make_a_valid_post_too_big(self):
        w = World()
        ev = w.w("sansa").post("x" * 15000)
        big = copy.deepcopy(ev)
        ids = sorted(Identity.generate().id for _ in range(16))
        big["cosigs"] = [{"author": a, "sig": "cd" * 64} for a in ids]
        self.assertEqual(event_id(big), event_id(ev))
        self.assertEqual(st(w, big).status, "rejected")           # size cap: fine, and the original must still be accepted after
        self.assertTrue(st(w, ev).ok)

    def test_cosig_is_replay_safe_across_threads(self):
        w1 = World(k=2, extra_members=[("dave", "admin")])
        ev = w1.w("arya").add_member(w1.ids["eve"], "member", cosigners=[w1.ids["dave"]])
        w2 = World(k=2, extra_members=[("dave", "admin")])
        w2.ids = w1.ids
        ev2 = copy.deepcopy(ev); ev2["thread"] = w2.t.id
        self.assertNotEqual(st(w2, ev2).status, "accepted")
        ev3 = copy.deepcopy(ev)
        self.assertEqual(st(w2, ev3).status, "rejected")           # wrong thread


class Removal(unittest.TestCase):
    def test_removed_member_cannot_create_admin_fork_evidence(self):
        # A removed admin signing an admin event on the old head must not be recorded as a "fork" (self-proving evidence).
        w = World(extra_members=[("dave", "admin")])
        head = w.t.head
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["dave"].id}))
        junk = E.make_event(w.ids["dave"], thread=w.t.id, kind="member_add", body={"prev_admin": head, "owner_epoch": 0, "agent": "x"},
                            parents=w.t.tips(), seq=0, admin_ref=head)
        r = st(w, junk)
        self.assertNotEqual(r.status, "conflict", "unauthorised admin event by a removed admin was recorded as a fork")

    def test_conflicts_are_bounded_and_deduplicated(self):
        # BUG (medium): every distinct equivocation and every REPLAY of one is appended to t.conflicts (and conflicts.jsonl).
        w = World()
        a = w.w("sansa").post("a", ts=1)
        w.add(a)
        n0 = len(w.t.conflicts)
        b = E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": "b"}, parents=[w.t.id], seq=0, admin_ref=w.t.head, ts=2)
        for _ in range(20):
            st(w, b)                                                   # the same conflicting event replayed
        self.assertLessEqual(len(w.t.conflicts) - n0, 1, "replaying one conflicting event appended the pair repeatedly")

    def test_many_distinct_equivocations_are_bounded(self):
        w = World()
        w.add(w.w("sansa").post("a", ts=1))
        for i in range(200):
            ev = E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": str(i)}, parents=[w.t.id], seq=0, admin_ref=w.t.head, ts=10 + i)
            st(w, ev)
        self.assertLessEqual(len(w.t.conflicts), 20, "one member can grow the conflict list without bound")

    def test_successor_can_not_spam_admin_forks(self):
        # BUG (low/medium): a plain member who is listed as a successor passes the "may write admin events" test, so an
        # UNAUTHORISED admin event on a stale prev_admin is recorded as a fork conflict, unlimited times.
        w = World()                                                      # sansa is a successor and a plain member
        old = w.t.head
        w.add(w.w("arya").add_member(w.ids["dave"], "member"))
        for i in range(10):
            junk = E.make_event(w.ids["sansa"], thread=w.t.id, kind="member_add", body={"prev_admin": old, "owner_epoch": 0, "agent": "x" * 32},
                                parents=w.t.tips(), seq=50 + i, admin_ref=old, ts=100 + i)
            st(w, junk)
        self.assertEqual(len(w.t.conflicts), 0)

    def test_voided_events_are_bounded(self):
        # BUG (medium): a removed member (still holding a valid key) can keep signing events on the pre-removal admin_ref;
        # each is quarantined forever, in memory and in quarantine.jsonl, with no cap.
        w = World()
        old = w.t.head
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id}))
        for i in range(1500):
            ev = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "spam"}, parents=[w.t.id], seq=i, admin_ref=old, ts=i)
            st(w, ev)
        self.assertLessEqual(len(w.t.void_ids), 1000)

    def test_observer_cannot_write_anything_but_may_self_revoke(self):
        # BUG (low): spec 3/4.1 lets "the agent itself" revoke; an observer (e.g. the human's leaked key) is refused by the blanket
        # "observers may not write" rule, so only the owner can revoke it.
        w = World()
        r = st(w, w.w("hu").admin("revoke", {"agent": w.ids["hu"].id}))
        self.assertTrue(r.ok, (r.status, r.reason))

    def test_guest_can_self_revoke(self):
        # BUG (low): same for a guest: _body_problem says "role may not write this kind" for a guest's revoke.
        w = World()
        d = w.ids["dave"]
        req = Writer(d, w.t).guest_request("hi", w.t.id)
        st(w, req)
        w.add(w.w("arya").add_member(d, "guest", admits=[event_id(req)]))
        r = st(w, Writer(d, w.t).admin("revoke", {"agent": d.id}))
        self.assertTrue(r.ok, (r.status, r.reason))

    def test_observer_posts_and_digests_rejected(self):
        w = World()
        self.assertEqual(st(w, w.w("hu").post("hello")).status, "rejected")
        self.assertEqual(st(w, w.w("hu").event("digest", {"text": "s", "covers": []})).status, "rejected")
        self.assertEqual(st(w, w.w("hu").event("evidence", {"a": {}, "b": {}})).status, "rejected")

    def test_observer_admin_ref_older_state_cannot_bypass(self):
        w = World()
        old = w.t.head
        w.add(w.w("arya").add_member(w.ids["dave"], "observer"))
        ev = E.make_event(w.ids["dave"], thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=0, admin_ref=old)
        self.assertEqual(st(w, ev).status, "rejected")
        ev = E.make_event(w.ids["dave"], thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=0, admin_ref=w.t.head)
        self.assertEqual(st(w, ev).status, "rejected")

    def test_observer_writes_nothing(self):
        # DECISION (2026-10-03): the `endpoint` kind is gone, so an observer's only write is revoking itself (test above).
        w = World()
        self.assertEqual(st(w, w.w("hu").post("hello")).status, "rejected")
        self.assertEqual(st(w, w.w("hu").event("digest", {"text": "x", "covers": []})).status, "rejected")

class Ownership(unittest.TestCase):
    def test_owner_transfer_with_unhashable_new_owner_does_not_raise(self):
        # BUG (medium): `b["new_owner"] not in st["members"]` raises TypeError for a list/dict, crashing accept() for anyone
        # who can sign an admin event (any admin/successor).
        w = World()
        ev = w.w("arya").admin("owner_transfer", {"new_owner": ["x"]}, epoch_delta=1)
        try:
            r = st(w, ev)
        except Exception as e:  # noqa
            self.fail(f"{type(e).__name__}: {e}")
        self.assertEqual(r.status, "rejected")

    def test_takeover_must_not_leave_the_admin_set_below_k(self):
        # BUG (medium): takeover demotes the old owner to member but never re-checks len(admin_set) >= k, so with k=2 and admin set
        # {owner, successor} the thread can never issue another admin event (permanent brick).
        i = {n: Identity.generate(n) for n in ("arya", "sansa", "carol", "dave", "eve")}
        g = make_genesis(i["arya"], "t", [(i["sansa"], "admin"), (i["carol"], "member"), (i["dave"], "member")], successors=[i["carol"].id], k=2)   # (successors are plain members since round 5)
        t = Thread(g)
        wr = lambda n: Writer(i[n], t)
        tk = wr("carol").admin("owner_takeover", {"last_checkpoint": t.id}, epoch_delta=1, cosigners=[i["dave"]])
        r = t.accept(tk)
        self.assertTrue(r.ok, (r.status, r.reason))
        if r.ok:
            self.assertFalse(len(t.admin_set(t.state())) < t.state()["admin_threshold"],
                             "after the takeover the admin set is smaller than k: every future admin event is impossible")

    def test_takeover_with_quorum_beats_a_later_owner_event_on_the_same_prev(self):
        # Sansa's rule #2: a takeover with valid acks outranks any other admin event on the same prev_admin, wherever it arrives.
        w = World(successors=("sansa",), extra_members=[("dave", "member")])
        old = w.t.head
        w.add(w.w("arya").add_member(w.ids["eve"], "member"))                          # the owner moved on from `old`
        tk = E.make_event(w.ids["sansa"], thread=w.t.id, kind="owner_takeover",
                          body={"prev_admin": old, "owner_epoch": 1, "last_checkpoint": w.t.id}, parents=w.t.tips(), seq=0, admin_ref=old)
        for c in (w.ids["carol"], w.ids["dave"]):
            tk = E.add_cosig(tk, c)
        r = st(w, tk)
        self.assertEqual((r.status, r.reorg), ("accepted", True))
        self.assertEqual(w.t.state()["owner"], w.ids["sansa"].id)
        self.assertNotIn(w.ids["eve"].id, w.t.state()["members"])                     # the owner's losing branch is gone
        self.assertIn(w.t.admin_children[old], (event_id(tk),))

    def test_takeover_ack_by_observer_or_guest_or_removed_does_not_count(self):
        w = World(successors=("sansa",))       # voters (non-owner admin/member): sansa, carol => need both
        tk = w.w("sansa").admin("owner_takeover", {"last_checkpoint": w.t.id}, epoch_delta=1, cosigners=[w.ids["hu"]])
        self.assertEqual(st(w, tk).status, "rejected")

    def test_takeover_with_only_successor_and_owner_ack_rejected(self):
        w = World(successors=("sansa",))
        tk = w.w("sansa").admin("owner_takeover", {"last_checkpoint": w.t.id}, epoch_delta=1, cosigners=[w.ids["arya"]])
        self.assertEqual(st(w, tk).status, "rejected")     # the owner's own ack is not a non-owner ack

    def test_old_owner_admin_events_after_takeover_rejected(self):
        w = World(successors=("sansa",))
        w.add(w.w("sansa").admin("owner_takeover", {"last_checkpoint": w.t.id}, epoch_delta=1, cosigners=[w.ids["carol"]]))
        self.assertEqual(w.t.state()["owner"], w.ids["sansa"].id)
        ev = w.w("arya").add_member(w.ids["eve"], "member")
        self.assertEqual(st(w, ev).status, "rejected")
        # even one that names the old head (in-flight) must never be accepted
        ev2 = E.make_event(w.ids["arya"], thread=w.t.id, kind="close", body={"prev_admin": w.t.id, "owner_epoch": 0}, parents=[w.t.id], seq=9, admin_ref=w.t.id)
        self.assertNotEqual(st(w, ev2).status, "accepted")

    def test_transfer_to_observer_or_guest_or_self_rejected(self):
        w = World()
        for who in ("hu", "arya"):
            self.assertEqual(st(w, w.w("arya").admin("owner_transfer", {"new_owner": w.ids[who].id}, epoch_delta=1, cosigners=[w.ids[who]] if who != "arya" else [])).status, "rejected")

    def test_owner_epoch_wrong_values(self):
        w = World()
        for e in (-1, 1, 2, 2 ** 40, True, "0", None, [], {}):
            ev = w.w("arya").admin("rules_update", {"rules": {"max_members": 8}})
            ev["body"]["owner_epoch"] = e
            ev = resign(ev, w.ids["arya"])
            try:
                r = st(w, ev)
            except Exception as ex:  # noqa
                self.fail(f"owner_epoch={e!r}: {type(ex).__name__}")
            self.assertNotEqual(r.status, "accepted", repr(e))

    def test_owner_epoch_true_is_not_zero(self):
        # BUG (low): owner_epoch/epoch are compared with `!=`, so JSON false/true pass as 0/1 (True == 1 makes a bool a valid transfer epoch).
        w = World()
        ev = w.w("arya").admin("rules_update", {"rules": {"max_members": 8}})
        ev["body"]["owner_epoch"] = False                         # False == 0 in python
        ev = resign(ev, w.ids["arya"])
        self.assertNotEqual(st(w, ev).status, "accepted", "boolean False accepted as owner_epoch 0")

    def test_pair_thread_that_grows_is_not_closed_by_a_departure(self):
        # BUG (medium/spec 6.5): `pair` is fixed at genesis. A 2-member thread that later admits a third member is still
        # treated as a pair: removing anyone closes it forever and no takeover is possible, although it is a 3+ member thread.
        from sigilnet.tests.util import World as W
        i = {n: Identity.generate(n) for n in ("a", "b", "c")}
        g = make_genesis(i["a"], "pair", [(i["b"], "member")], successors=[], k=1)
        t = Thread(g)
        Writer(i["a"], t)
        t.accept(Writer(i["a"], t).add_member(i["c"], "member"))
        self.assertEqual(len(t.state()["members"]), 3)
        r = t.accept(Writer(i["a"], t).admin("member_remove", {"agent": i["c"].id}))
        self.assertTrue(r.ok, r)
        # now removing c from a 3-member thread leaves 2; per 6.5 either way it should not have been closed by c leaving a 3+ thread
        self.assertFalse(t.state()["closed"], "thread closed by the departure of the third member of a grown thread")

    def test_close_needs_k_signatures_in_a_big_thread(self):
        # AMBIGUITY -> BUG (low): 4.1 lists admin events as carrying k signatures in 3+ member threads; `close` and `checkpoint`
        # are accepted from the owner alone even with k=2, so a single compromised owner key freezes the thread irreversibly.
        w = World(k=2, extra_members=[("dave", "admin")])
        r = st(w, w.w("arya").admin("close", {}))
        self.assertNotEqual(r.status, "accepted")

    def test_checkpoint_is_owner_only_even_in_a_big_thread(self):
        # DECISION (spec 6.2): a checkpoint is the owner's attestation; k signatures apply to admin CHANGES (member_*, rules_update,
        # owner_transfer, close), not to checkpoints. Equivocating checkpoints are caught as evidence instead.
        w = World(k=2, extra_members=[("dave", "admin")])
        r = st(w, w.w("arya").admin("checkpoint", {"count": 1, "heads": [w.t.id], "epoch": 0}))
        self.assertEqual(r.status, "accepted")
    def test_checkpoint_count_may_not_go_backwards(self):
        w = World()
        for x in "abc":
            w.post("sansa", x)
        w.add(w.w("arya").admin("checkpoint", {"count": 4, "heads": [w.t.id], "epoch": 0}))
        r = st(w, w.w("arya").admin("checkpoint", {"count": 0, "heads": [w.t.id], "epoch": 0}))
        self.assertNotEqual(r.status, "accepted", "checkpoint with a smaller count than the previous one accepted")

    def test_takeover_last_checkpoint_must_be_latest(self):
        w = World(successors=("sansa",))
        cp = w.add(w.w("arya").admin("checkpoint", {"count": 1, "heads": [w.t.id], "epoch": 0}))
        tk = w.w("sansa").admin("owner_takeover", {"last_checkpoint": w.t.id}, epoch_delta=1, cosigners=[w.ids["carol"]])
        self.assertEqual(st(w, tk).status, "rejected")
        tk = w.w("sansa").admin("owner_takeover", {"last_checkpoint": cp}, epoch_delta=1, cosigners=[w.ids["carol"]])
        self.assertTrue(st(w, tk).ok)


class Structure(unittest.TestCase):
    def test_admin_ref_naming_a_non_admin_event_is_rejected_not_pending_forever(self):
        # BUG (low): admin_ref pointing at a known post is not an admin state; it is parked as "pending" for ever
        # (and `missing` never lists it because we already have it), pinning a mirror's pending slot.
        w = World()
        p = w.post("sansa", "x")
        ev = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "y"}, parents=[p], seq=0, admin_ref=p)
        self.assertEqual(st(w, ev).status, "rejected")

    def test_children_of_voided_events_resolve_against_the_tombstone(self):
        # Sansa's finding #3: a voided event stays a known parent, so an honest reply to it is accepted (not pending forever).
        w = World()
        old = w.t.head
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id}))
        q = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "q"}, parents=[w.t.id], seq=0, admin_ref=old)
        self.assertEqual(st(w, q).status, "voided")
        child = w.w("sansa").post("reply to a voided post", parents=[event_id(q)])
        self.assertEqual(st(w, child).status, "accepted")
        self.assertNotIn(event_id(q), w.t.topo())                                     # tombstones are not in the reading order...
        self.assertIn(event_id(q), w.t.topo(include_void=True))                        # ...unless asked for

    def test_seq_zero_gap_and_huge_seq_do_not_hang_missing_seqs(self):
        # BUG (medium): missing_seqs() builds range(max_seq+1) with list membership: a member signing seq=2**31-1 makes any caller
        # hang / allocate GBs. (5M here to keep the test short.)
        w = World()
        ev = E.make_event(w.ids["sansa"], thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=5_000_000, admin_ref=w.t.head)
        w.add(ev)
        t0 = time.time()
        w.t.missing_seqs(w.ids["sansa"].id)
        self.assertLess(time.time() - t0, 0.5, "missing_seqs is O(max seq)")

    def test_post_with_reply_to_not_in_parents_and_bad_types(self):
        w = World()
        p = w.post("sansa", "x")
        for body in ({"text": "y", "reply_to": p}, {"text": "y", "to": "nobody"}, {"text": 5}, {"text": "y", "refs": [{"kind": "file", "cid": "sha256:" + "0" * 64, "size": True}]},
                     {"text": "y", "refs": [{"kind": "file", "cid": "sha256:" + "0" * 64, "size": -1}]}, {"text": "y", "guest": {}}):
            ev = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body=body, parents=[w.t.id], seq=len(w.t.by_author_seq), admin_ref=w.t.head)
            self.assertEqual(st(w, ev).status, "rejected", body)

    def test_bool_is_not_an_int_in_size_and_rules(self):
        w = World()
        ev = w.w("arya").admin("rules_update", {"rules": {"max_members": True}})
        self.assertEqual(st(w, ev).status, "rejected")

    def test_dict_input_with_float_does_not_leak_canonerror(self):
        # BUG (low): Thread.accept on an in-memory dict with a float/bytes value raises canon.CanonError from check_structure's
        # len(canon.dumps(ev)) instead of returning Result("rejected"). (Mirror.ingest catches it; direct users do not.)
        w = World()
        ev = w.w("sansa").post("x")
        ev["body"]["text2"] = 1.5
        try:
            r = st(w, ev)
        except Exception as e:  # noqa
            self.fail(f"{type(e).__name__} leaked from accept()")
        self.assertEqual(r.status, "rejected")

    def test_deeply_nested_body_rejected_without_recursion_error(self):
        w = World()
        d = cur = {}
        for _ in range(5000):
            cur["a"] = {}
            cur = cur["a"]
        ev = w.w("sansa").post("x")
        ev["body"]["extra"] = d
        try:
            r = st(w, ev)
        except RecursionError:
            self.fail("RecursionError")
        except Exception:
            pass

    def test_digest_pinned_must_be_a_real_boolean(self):
        # BUG (low/medium): only truthy `pinned` is owner-gated; a member's digest with pinned=0/""/[]/null passes, and a reader
        # that tests `"pinned" in body` (or `is not False`) would treat it as owner-pinned: a poisoning path around 9.
        w = World()
        p = w.post("arya", "x")
        for v in (0, "", [], None, {}):
            r = st(w, w.w("carol").event("digest", {"text": "s", "covers": [p], "pinned": v}))
            self.assertEqual(r.status, "rejected", f"pinned={v!r} accepted from a non-owner")

    def test_digest_covers_may_reference_unknown_ids(self):
        w = World()
        r = st(w, w.w("carol").event("digest", {"text": "s", "covers": ["ab" * 16]}))
        self.assertTrue(r.ok)     # documenting: spot-checkable, not enforced (spec: "carry covers so a reader can spot-check")

    def test_endpoint_only_about_self_shape(self):
        w = World()
        for body in ({"transports": [{"type": "tor", "addr": "x" * 257}]}, {"transports": [], "for": "x"}, {"transports": []}):
            ev = w.w("carol").post("x")                                              # signed like an old build's event of the removed kind
            ev["kind"], ev["body"] = "endpoint", body
            ev["sig"] = w.ids["carol"].sign(E.sign_input(ev))
            self.assertEqual(st(w, ev).status, "rejected")

    def test_evidence_can_carry_events_near_the_size_cap(self):
        # BUG (medium): evidence embeds two full events, but is itself limited to max_event_bytes, so an equivocator who signs two
        # ~9 KiB posts cannot be reported at all (the proof is > 16 KiB).
        w = World()
        a = w.w("carol").post("A" * 9000, ts=1)
        w.add(a)
        b = E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": "B" * 9000}, parents=[w.t.id], seq=0, admin_ref=w.t.head, ts=2)
        self.assertEqual(st(w, b).status, "conflict")                                  # deterministic: neither of the two is live
        r = st(w, w.w("sansa").event("evidence", {"a": a, "b": b}))
        self.assertTrue(r.ok, (r.status, r.reason))

    def test_evidence_about_unrelated_events_rejected(self):
        w = World()
        a = w.w("carol").post("A", ts=1)
        w.add(a)
        b = w.w("carol").post("B", ts=2)
        w.add(b)
        self.assertEqual(st(w, w.w("sansa").event("evidence", {"a": a, "b": b})).status, "rejected")

    def test_evidence_with_a_forged_event_rejected(self):
        w = World()
        a = w.w("carol").post("A", ts=1)
        w.add(a)
        forged = E.make_event(w.ids["eve"], thread=w.t.id, kind="post", body={"text": "B"}, parents=[w.t.id], seq=0, admin_ref=w.t.head)
        forged["author"] = w.ids["carol"].id
        self.assertEqual(st(w, w.w("sansa").event("evidence", {"a": a, "b": forged})).status, "rejected")

    def test_closed_thread_result_does_not_depend_on_arrival_order(self):
        # BUG (medium): a post created before `close` (its admin_ref predates it) is accepted if it arrives first and rejected
        # (and never stored) if it arrives after; two mirrors that see the same events end with different event sets.
        w = World()
        post = w.w("carol").post("last words")
        close = w.w("arya").admin("close", {})
        a = World.__new__(World); a.ids = w.ids; a.t = Thread(w.genesis)
        b = World.__new__(World); b.ids = w.ids; b.t = Thread(w.genesis)
        a.t.accept(post); a.t.accept(close)
        b.t.accept(close); b.t.accept(post)
        self.assertEqual(set(a.t.events), set(b.t.events))

    def test_size_cap_is_judged_as_of_admin_ref_not_arrival(self):
        # BUG (low/medium): max_event_bytes is read from the CURRENT head, so a big event valid at its admin_ref is accepted or
        # rejected depending on whether the shrinking rules_update arrived first.
        w = World()
        big = w.w("carol").post("z" * 5000)
        shrink = w.w("arya").admin("rules_update", {"rules": {"max_event_bytes": 1024}})
        a = Thread(w.genesis); b = Thread(w.genesis)
        a.accept(big); a.accept(shrink)
        b.accept(shrink); b.accept(big)
        self.assertEqual(set(a.events), set(b.events))

    def test_rate_limit_is_enforced(self):
        # DECISION: the per-author rate limit is a RECEIVER policy (author `ts` is advisory, so it cannot be a validity rule):
        # it lives in the Mirror, uses the receiver clock, and applies to live arrivals only (catch-up passes live=False).
        import tempfile
        from sigilnet.mirror import Mirror
        w = World(rules={"max_event_bytes": 16384, "posts_per_author_per_hour": 3, "max_members": 16, "checkpoint_every": 50,
                         "owner_silence_hours": 72, "retention": "forever"})
        m = Mirror(tempfile.mkdtemp())
        m.ingest(w.genesis)
        writer = w.w("carol")
        evs = [E.make_event(w.ids["carol"], thread=w.t.id, kind="post", body={"text": str(i)}, parents=[w.t.id], seq=i, admin_ref=w.t.head) for i in range(6)]
        res = [m.ingest(e).status for e in evs]
        self.assertEqual(res, ["accepted"] * 3 + ["rejected"] * 3)
        self.assertEqual(m.ingest(evs[3], live=False).status, "accepted")               # catch-up of old history is not rate limited

    def test_guest_max_bytes_is_enforced(self):
        # BUG (medium): guest_policy.max_bytes (default 4096) is not enforced: a 15 KB guest request is queued and admitted.
        w = World()
        d = w.ids["dave"]
        req = Writer(d, w.t).guest_request("g" * 12000, w.t.id)
        self.assertEqual(st(w, req).status, "rejected")

    def test_guest_queue_cannot_be_locked_by_strangers(self):
        # BUG (medium, spec 5.1 fair queue / request_ttl_hours): `awaiting` is capped at 200 with no expiry and no eviction, and
        # keys are free: 50 throwaway keys x 4 requests fill it for good; every honest guest is then refused. (PoW is out of scope
        # for this step, but the thread must at least age out / evict.)
        w = World()
        for n in range(50):
            k = Identity.generate(f"k{n}")
            for s in range(4):
                ev = E.make_event(k, thread=w.t.id, kind="post", body={"text": "x", "reply_to": w.t.id, "guest": {"name": "k", "sign": k.sign_pub, "kex": k.kex_pub}},
                                  parents=[w.t.id], seq=s, admin_ref=w.t.head)
                st(w, ev)
        honest = Writer(w.ids["dave"], w.t).guest_request("please", w.t.id)
        self.assertEqual(st(w, honest).status, "awaiting")

    def test_resending_an_awaiting_request_is_idempotent(self):
        w = World()
        d = w.ids["dave"]
        evs = []
        for s in range(4):
            evs.append(E.make_event(d, thread=w.t.id, kind="post", body={"text": str(s), "reply_to": w.t.id, "guest": {"name": "d", "sign": d.sign_pub, "kex": d.kex_pub}},
                                    parents=[w.t.id], seq=s, admin_ref=w.t.head))
            self.assertEqual(st(w, evs[-1]).status, "awaiting")
        self.assertNotEqual(st(w, evs[-1]).status, "rejected", "re-delivery of an already-queued request is 'rejected'")

    def test_guest_admits_naming_someone_elses_event_admits_nothing(self):
        w = World()
        d, e = w.ids["dave"], w.ids["eve"]
        re_ = Writer(e, w.t).guest_request("eve here", w.t.id)
        st(w, re_)
        w.add(w.w("arya").add_member(d, "guest", admits=[event_id(re_)]))
        self.assertNotIn(event_id(re_), w.t.events)
        # and eve is still not a member
        self.assertNotIn(e.id, w.t.state()["members"])
        # if eve later gets admitted her request is still valid
        w.add(w.w("arya").add_member(e, "guest", admits=[event_id(re_)]))
        self.assertIn(event_id(re_), w.t.events)

    def test_guest_request_replaying_admitted_id_in_second_member_add(self):
        w = World()
        d, e = w.ids["dave"], w.ids["eve"]
        rq = Writer(d, w.t).guest_request("hi", w.t.id)
        st(w, rq)
        w.add(w.w("arya").add_member(d, "guest", admits=[event_id(rq)]))
        w.add(w.w("arya").add_member(e, "guest", admits=[event_id(rq)]))       # same id named again for another agent
        self.assertEqual(list(w.t.events).count(event_id(rq)), 1)
        self.assertEqual(w.t.order.count(event_id(rq)), 1)

    def test_guest_request_with_unknown_reply_to_is_pending_not_awaiting(self):
        w = World()
        d = w.ids["dave"]
        ghost = "ab" * 16
        ev = E.make_event(d, thread=w.t.id, kind="post", body={"text": "x", "reply_to": ghost, "guest": {"name": "d", "sign": d.sign_pub, "kex": d.kex_pub}},
                          parents=[ghost], seq=0, admin_ref=w.t.head)
        self.assertEqual(st(w, ev).status, "pending")

    def test_guest_with_garbage_body_is_not_queued(self):
        # BUG (low): _await_admission runs before _body_problem, so invalid posts (bad refs, extra keys) occupy queue slots.
        w = World()
        d = w.ids["dave"]
        ev = E.make_event(d, thread=w.t.id, kind="post", body={"text": "x", "reply_to": w.t.id, "refs": "nope", "bogus": 1, "guest": {"name": "d", "sign": d.sign_pub, "kex": d.kex_pub}},
                          parents=[w.t.id], seq=0, admin_ref=w.t.head)
        self.assertEqual(st(w, ev).status, "rejected")

    def test_guest_cannot_post_before_admission_via_member_path(self):
        w = World()
        d = w.ids["dave"]
        ev = E.make_event(d, thread=w.t.id, kind="post", body={"text": "x"}, parents=[w.t.id], seq=0, admin_ref=w.t.head)
        self.assertEqual(st(w, ev).status, "rejected")

    def test_removed_member_can_not_use_guest_door_to_rejoin_with_same_key(self):
        w = World()
        w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id}))
        c = w.ids["carol"]
        rq = Writer(c, w.t).guest_request("let me back", w.t.id)
        st(w, rq)
        r = st(w, w.w("arya").add_member(c, "guest", admits=[event_id(rq)]))
        self.assertEqual(r.status, "rejected")
        self.assertNotIn(event_id(rq), w.t.events)

    def test_wrong_kind_in_guest_disguise(self):
        w = World()
        d = w.ids["dave"]
        ev = E.make_event(d, thread=w.t.id, kind="digest", body={"text": "x", "covers": [], "guest": {"name": "d", "sign": d.sign_pub, "kex": d.kex_pub}},
                          parents=[w.t.id], seq=0, admin_ref=w.t.head)
        self.assertEqual(st(w, ev).status, "rejected")


if __name__ == "__main__":
    unittest.main()
