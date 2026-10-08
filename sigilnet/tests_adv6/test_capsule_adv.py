import base64
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from sigilnet import canon
from sigilnet import capsule as C
from sigilnet.keys import Identity
from sigilnet.tests.test_capsule import Base, A32, CRED, EP
from sigilnet.tests.test_cli_public import run


def tokof(block):
    return C.decode_capsule(block, now=None)["token"]


def req_for(tok, who, name="x"):
    body = {"t": "join_request", "token": tok, "sign": who.sign_pub, "kex": who.kex_pub, "name": name, "offers": [{"endpoint": EP, "credential": CRED}]}
    from sigilnet import canon
    body["sig"] = who.sign(C.JOINREQ_CTX + canon.dumps(body))                # round 18: the joiner signs its own request
    return body


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def confirm(s, cid, who=None):
    return C.confirm(s.oh, s.otor, s.owner, s.om, s.obook, cid, C.fingerprint((who or s.joiner).id), clock=s.clock)


# ================================================================ FAILING regression tests (bugs)

class Bugs(Base):
    def test_BUG_describe_rules_key_terminal_injection(self):
        """capsule.py:158-159 describe() prints rule KEYS (stranger text, len<=40, any chars) raw: ESC / newline let a forged capsule paint fake lines."""
        block, cid, _ = self.create()
        good = C.decode_capsule(block)
        evil = C.encode_capsule({**good, "rules": {"\x1b[2J\nOwner fingerprint MATCHES": 1}})
        with self.assertRaises(C.CapsuleError):                       # fixed at the source: rule keys must be [a-z0-9_]{1,40}
            C.decode_capsule(evil)

    def test_BUG_nonascii_fingerprint_crashes(self):
        """capsule.py:59 hmac.compare_digest(str,str) raises TypeError for non-ASCII typed text: `capsule confirm/accept --fingerprint` tracebacks instead of CapsuleError."""
        self.assertFalse(C.same_fingerprint("é" * 16, self.owner.id))

    def test_BUG_join_request_retry_refused(self):
        """capsule.py:361: an identical retry of the SAME joiner's request is 'refused' (state no longer open). Over tor a lost reply => joiner marks itself failed."""
        block, cid, _ = self.create()
        q = req_for(tokof(block), self.joiner)
        self.assertEqual(self.server.handle(q)["t"], "pending")
        self.assertEqual(self.server.handle(q)["t"], "pending")

    def test_BUG_poll_lost_reply_kills_join(self):
        """capsule.py:527-529: reply to join_request lost (timeout) after the owner stored it; next poll retries and gets 'refused' => joiner state failed although the owner has a pending request."""
        block, cid, _ = self.create()
        r = self.accept(block)
        calls = []

        class T:
            def request(s, q):
                out = self.server.handle(q)
                calls.append(q["t"])
                if len(calls) == 1:
                    raise OSError("timeout after the owner processed it")
                return out
        C.poll(self.jh, self.jtor, self.joiner, self.jbook, lambda ep: T(), clock=self.clock)
        C.poll(self.jh, self.jtor, self.joiner, self.jbook, lambda ep: T(), clock=self.clock)
        st = json.loads((Path(self.jh) / "joins.json").read_text())[r["cid"]]["state"]
        self.assertNotEqual(st, "failed")

    def test_BUG_confirm_not_retryable_after_partial_failure(self):
        """capsule.py:414-421: member_add is committed before the door exists; if add_service fails (or the process dies) the capsule stays pending and every retry fails on 'member_add refused' (already a member): owner stuck, joiner member without a door."""
        block, cid, _ = self.create()
        self.accept(block)
        self.poll()
        orig, n = self.otor.add_service, [0]

        def flaky(name, pub, agent=None, kind="peer"):
            if kind == "peer":
                n[0] += 1
                if n[0] == 1:
                    raise ValueError("disk full")
            return orig(name, pub, agent=agent, kind=kind)
        self.otor.add_service = flaky
        with self.assertRaises(Exception):
            confirm(self, cid)
        out = confirm(self, cid)                                        # the human simply runs it again
        self.assertEqual(out["agent"], self.joiner.id)

    def test_BUG_confirm_vs_expiry_race_half_done(self):
        """capsule.py:414-419: confirm checks expiry once, adds the member, THEN reads the dial key; a sweep that expires the capsule in between deletes the key: FileNotFoundError, joiner already a member, no peer entry, record 'expired'."""
        block, cid, _ = self.create(ttl=60)
        self.accept(block)
        self.poll()
        self.clock.t += 58
        orig = self.otor.add_service

        def slow(name, pub, agent=None, kind="peer"):
            self.clock.t += 5
            C.sweep(self.oh, self.otor, clock=self.clock)
            return orig(name, pub, agent=agent, kind=kind)
        self.otor.add_service = slow
        err = None
        try:
            confirm(self, cid)
        except Exception as e:                                          # noqa: BLE001
            err = e
        member = self.joiner.id in self.om.threads[self.tid].state()["members"]
        if err is not None:
            self.assertIsInstance(err, C.CapsuleError)                  # a clean refusal ...
            self.assertFalse(member)                                    # ... must not leave a member behind
        else:
            self.assertIn(self.joiner.id, self.obook.all())

    def test_BUG_dial_key_file_survives_confirm_grace(self):
        """capsule.py:296-302: sweep of a confirmed capsule removes the door but never peerkeys/cap-<cid>.priv (only _teardown does that): a secret key file stays forever (then the record is dropped and it is orphaned)."""
        block, cid, _ = self.create()
        self.accept(block)
        self.poll()
        confirm(self, cid)
        kf = Path(self.oh) / "peerkeys" / f"cap-{cid}.priv"
        self.clock.t += C.GRACE + 1
        C.sweep(self.oh, self.otor, clock=self.clock)
        self.assertNotIn(f"join-{cid}", self.otor._load_services())
        self.assertFalse(kf.exists())

    def test_BUG_orphan_join_door_never_swept(self):
        """capsule.py:284: sweep only walks records; create() adds the door (l.240) BEFORE the record (l.248), so a kill -9 between them leaves a join door (and cap-*.priv) that no startup sweep ever removes."""
        pub = "A" * 52
        self.otor.add_service("join-deadbeef", pub, kind="join")
        C.sweep(self.oh, TorNode_fresh(self.oh), clock=self.clock)
        self.assertNotIn("join-deadbeef", TorNode_fresh(self.oh)._load_services())

    def test_BUG_create_partial_failure_leaves_door(self):
        """capsule.py:240-244: door is added before the key file; if the key file cannot be created (peerkeys unusable) the exception escapes the try block and the door stays with no record."""
        (Path(self.oh) / "peerkeys").write_text("not a dir")
        with self.assertRaises(Exception):
            self.create()
        self.assertEqual([k for k in self.otor._load_services() if k.startswith("join-")], [])

    def test_BUG_failed_teardown_is_recorded_as_done(self):
        """capsule.py:268-281,303-306: _teardown swallows remove_service errors and sweep then sets door_gone=True, so a failed removal is never retried (door + bootstrap key stay)."""
        block, cid, _ = self.create(ttl=60)
        orig = self.otor.remove_service
        fails = [1]

        def flaky(name):
            if fails[0]:
                fails[0] = 0
                raise OSError("EIO")
            return orig(name)
        self.otor.remove_service = flaky
        self.clock.t += 61
        C.sweep(self.oh, self.otor, clock=self.clock)
        C.sweep(self.oh, self.otor, clock=self.clock)
        self.assertNotIn(f"join-{cid}", self.otor._load_services())

    def test_BUG_max_open_not_atomic(self):
        """capsule.py:233-248: the MAX_OPEN count is taken outside the flock and the record is added later: two concurrent creates both pass at 7 open => 9."""
        for _ in range(C.MAX_OPEN - 1):
            self.create()
        orig, done = self.otor.add_service, []

        def nested(name, pub, agent=None, kind="peer"):
            if not done and name.startswith("join-"):
                done.append(1)
                self.create()                                           # the "other process" finishes first
            return orig(name, pub, agent=agent, kind=kind)
        self.otor.add_service = nested
        try:
            self.create()
        except C.CapsuleError:
            pass
        n = sum(1 for r in C.Store(self.oh).all().values() if r["state"] in ("open", "pending"))
        self.assertLessEqual(n, C.MAX_OPEN)

    def test_BUG_joiner_refused_keeps_bootstrap_key(self):
        """capsule.py:527-529: when join_request is refused (token burned by an attacker) poll marks failed but never calls _forget_join: bootstrap client key stays in ClientOnionAuthDir and join-<cid>.priv stays."""
        block, cid, _ = self.create()
        Mallory = Identity.generate("m")
        self.assertEqual(self.server.handle(req_for(tokof(block), Mallory))["t"], "pending")
        r = self.accept(block)
        self.assertEqual(self.poll(), {r["cid"]: "failed"})
        self.assertEqual(list(self.jtor.auth_in.glob("*.auth_private")), [])
        self.assertFalse((Path(self.jh) / "peerkeys" / f"join-{r['cid']}-onion.priv").exists())

    def test_BUG_uppercase_onion_bootstrap_key_not_forgotten(self):
        """capsule.py:551: _forget_join derives the auth file name from the RAW capsule onion, add_client_auth from the normalised one: a capsule with an upper-case onion (passes _check) leaves the key file behind."""
        block, cid, _ = self.create()
        good = C.decode_capsule(block)
        up = C.encode_capsule({**good, "joins": [{**good["joins"][0], "endpoint": {"type": "onion", "addr": good["joins"][0]["endpoint"]["addr"].upper()}}]})
        r = self.accept(up)
        self.assertEqual(len(list(self.jtor.auth_in.glob("*.auth_private"))), 1)

        class T:
            def request(s, q): return {"t": "pending"} if q["t"] == "join_request" else {"t": "refused"}
        for _ in range(2):
            C.poll(self.jh, self.jtor, self.joiner, self.jbook, lambda ep: T(), clock=self.clock)
        self.assertEqual(list(self.jtor.auth_in.glob("*.auth_private")), [])

    def test_BUG_hostile_capsules_json_crashes_sweep(self):
        """capsule.py:292-296: record fields are not type-checked: exp='x' => TypeError out of sweep(); noderun startup/tick only catch OSError/ValueError => node crash loop, and create() is blocked too."""
        (Path(self.oh) / "capsules.json").write_text(json.dumps({"abcdefgh": {"state": "open", "exp": "soon", "door": "join-x", "dial": "cap-x"}}))
        C.sweep(self.oh, self.otor, clock=self.clock)

    def test_BUG_dial_label_path_traversal_on_teardown(self):
        """capsule.py:279: rec['dial'] is joined into a path unvalidated; a record with dial='../victim' makes sweep delete <home>/victim.priv."""
        victim = Path(self.oh) / "victim.priv"
        victim.write_text("precious")
        (Path(self.oh) / "peerkeys").mkdir(exist_ok=True)
        (Path(self.oh) / "capsules.json").write_text(json.dumps({"abcdefgh": {"state": "expired", "exp": 0, "at": int(self.clock()), "door": "join-x", "dial": "../victim"}}))
        C.sweep(self.oh, self.otor, clock=self.clock)
        self.assertTrue(victim.exists())


def TorNode_fresh(home):
    from sigilnet.torlink import TorNode
    return TorNode(home + "/tor", offline=True)


class BugCli(unittest.TestCase):
    def test_BUG_cli_list_hostile_state_traceback(self):
        """cli.py:208-214: `capsule list` indexes r['req']['name'], r['thread'], r['exp'] without checks: a damaged capsules.json (pending w/o req) raises KeyError instead of a message."""
        h = tempfile.mkdtemp()
        run(h, "id", "init", "arya")
        (Path(h) / "capsules.json").write_text(json.dumps({"abcdefgh": {"state": "pending", "thread": "a" * 32, "exp": 10 ** 10}}))
        try:
            rc, out, err = run(h, "capsule", "list")
        except Exception as e:                                          # noqa: BLE001
            self.fail(f"traceback: {type(e).__name__}: {e}")


# ================================================================ PASSING: properties that held

class Held(Base):
    def test_forged_capsule_real_owner_id_attacker_door_cannot_join_joiner(self):
        """Attacker copies the REAL owner's public identity (fingerprint matches) but points at his own door and signs answers himself."""
        block, cid, _ = self.create()
        good = C.decode_capsule(block)
        mal = Identity.generate("mal")
        forged = C.encode_capsule({**good, "token": "ab" * 16})
        r = self.accept(forged)                                         # fingerprint passes (it is the owner's)
        rec = json.loads((Path(self.jh) / "joins.json").read_text())[r["cid"]]
        import sigilnet.canon as cn
        body = {"t": "joined", "token": rec["token"], "endpoints": [EP], "thread": rec["thread"], "owner": rec["owner"]["id"], "by": mal.sign_pub}
        body["rsig"] = mal.sign(C.JOIN_CTX + cn.dumps(body))
        self.assertFalse(C._verify_joined(body, rec))
        body["by"] = rec["owner"]["sign"]                               # claim to be the owner with mallory's signature
        self.assertFalse(C._verify_joined(body, rec))

    def test_forged_owner_capsule_rejected_and_nothing_built(self):
        block, cid, _ = self.create()
        good = C.decode_capsule(block)
        m = Identity.generate("m")
        forged = C.encode_capsule({**good, "owner": {"id": m.id, "sign": m.sign_pub, "kex": m.kex_pub, "name": "arya"}})
        with self.assertRaises(C.CapsuleError):
            self.accept(forged)
        self.assertEqual(self.jtor._load_services(), {})
        self.assertEqual(list(self.jtor.auth_in.glob("*")), [])
        self.assertFalse((Path(self.jh) / "joins.json").exists())

    def test_join_response_not_replayable_across_capsules_or_tamperable(self):
        b1, c1, _ = self.create()
        b2, c2, _ = self.create()
        r1, r2 = self.accept(b1), self.accept(b2)
        self.poll()
        confirm(self, c1)
        self.ofake(f"peer-{self.joiner.id[:27]}")
        resp = self.server.handle({"t": "join_status", "token": tokof(b1)})
        recs = json.loads((Path(self.jh) / "joins.json").read_text())
        self.assertEqual(resp["t"], "joined")
        self.assertTrue(C._verify_joined(resp, recs[r1["cid"]]))
        self.assertFalse(C._verify_joined(resp, recs[r2["cid"]]))
        for k, v in (("endpoints", [{"type": "onion", "addr": "c" * 56 + ".onion:47200"}]), ("endpoints", [{"type": "onion", "addr": A32 + ":1"}]), ("thread", "0" * 32), ("token", tokof(b2)), ("owner", self.joiner.id)):
            self.assertFalse(C._verify_joined({**resp, k: v}, recs[r1["cid"]]), k)
        self.assertFalse(C._verify_joined({**resp, "extra": 1}, recs[r1["cid"]]))
        # a signature without the domain prefix is not accepted
        b = {k: v for k, v in resp.items() if k != "rsig"}
        b["rsig"] = self.owner.sign(canon.dumps(b))
        self.assertFalse(C._verify_joined(b, recs[r1["cid"]]))

    def test_nothing_changes_without_matching_fingerprint(self):
        block, cid, _ = self.create()
        self.accept(block)
        self.poll()
        before = json.dumps(self.om.threads[self.tid].state()["members"], sort_keys=True)
        doors = dict(self.otor._load_services())
        for fp in ("", " ", "0000 0000 0000 0000", C.fingerprint(self.owner.id), C.fingerprint(self.joiner.id)[:-1], C.fingerprint(self.joiner.id) + "a", None, 5):
            with self.assertRaises(C.CapsuleError):
                C.confirm(self.oh, self.otor, self.owner, self.om, self.obook, cid, fp, clock=self.clock)
        self.assertEqual(before, json.dumps(self.om.threads[self.tid].state()["members"], sort_keys=True))
        self.assertEqual(doors, self.otor._load_services())
        self.assertEqual(self.obook.all(), {})

    def test_leaked_capsule_attacker_first_cannot_get_legit_joiner_in(self):
        block, cid, _ = self.create()
        mal = Identity.generate("mal")
        self.assertEqual(self.server.handle(req_for(tokof(block), mal, "friendly carol"))["t"], "pending")
        self.accept(block)
        self.assertEqual(self.poll(), {C.hashlib.sha256(bytes.fromhex(tokof(block))).hexdigest()[:8]: "failed"})
        # owner's human asked the REAL joiner for the fingerprint: it does not match the pending request
        with self.assertRaises(C.CapsuleError):
            confirm(self, cid, self.joiner)
        self.assertNotIn(self.joiner.id, self.om.threads[self.tid].state()["members"])

    def test_confirm_needs_pending_not_expired_not_rejected(self):
        block, cid, _ = self.create(ttl=60)
        with self.assertRaises(C.CapsuleError):
            confirm(self, cid)                                          # state open, no request
        self.server.handle(req_for(tokof(block), self.joiner))
        self.clock.t += 61
        with self.assertRaises(C.CapsuleError):
            confirm(self, cid)
        self.assertEqual(self.server.handle(req_for(tokof(block), Identity.generate("z")))["t"], "refused")

    def test_concurrent_requests_one_pending(self):
        block, cid, _ = self.create()
        tok, outs = tokof(block), []
        ids = [Identity.generate(f"i{i}") for i in range(6)]
        ts = [threading.Thread(target=lambda w=w: outs.append(self.server.handle(req_for(tok, w))["t"])) for w in ids]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sorted(outs), ["pending"] + ["refused"] * 5)

    def test_concurrent_confirms_one_wins(self):
        block, cid, _ = self.create()
        self.accept(block)
        self.poll()
        res = []

        def go():
            try:
                res.append(confirm(self, cid)["agent"])
            except C.CapsuleError as e:
                res.append(type(e).__name__)
            except Exception as e:                                      # noqa: BLE001
                res.append("OTHER " + repr(e))
        ts = [threading.Thread(target=go) for _ in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(res), 2)
        self.assertFalse([r for r in res if r.startswith("OTHER")], res)
        self.assertEqual(self.om.threads[self.tid].state()["members"][self.joiner.id]["role"], "member")

    def test_join_door_answers_only_join_types(self):
        from sigilnet.noderun import door_handler
        from sigilnet.sync import SyncServer
        block, cid, _ = self.create()
        tok = tokof(block)
        h = door_handler("join", None, SyncServer(self.om, identity=self.owner), {"join": self.server.handle})
        for t in ("summary", "list", "fetch", "read", "hello", "push", "notify", "threads", "public_list", "submit", "challenge", "", None, 5):
            for extra in ({}, {"token": tok}, {"thread": self.tid, "from": self.owner.id, "token": tok}):
                out = h({"t": t, "nonce": "0" * 16, **extra})
                self.assertEqual(out, {"t": "refused"}, (t, extra))
        self.assertEqual(h({"t": "join_status", "token": tok})["t"], "wait")
        self.assertEqual(h({"t": "join_status", "token": tok, "thread": self.tid}), {"t": "refused"})   # exact shape only
        self.assertIn(door_handler("join", None, SyncServer(self.om, identity=self.owner), {})({"t": "summary", "thread": self.tid}).get("t"), ("refused", "unknown"))

    def test_permissions(self):
        block, cid, _ = self.create()
        r = self.accept(block)
        self.poll()
        confirm(self, cid)
        for p in (Path(self.oh) / "capsules.json", Path(self.jh) / "joins.json", Path(self.jh) / "peerkeys" / f"join-{r['cid']}-onion.priv",
                  self.otor.svc_dir / f"join-{cid}" / "authorized_clients" / "client.auth", *self.jtor.auth_in.glob("*.auth_private"), *self.otor.auth_in.glob("*.auth_private")):
            self.assertEqual(mode(p), 0o600, p)
        for d in (Path(self.oh) / "peerkeys", Path(self.jh) / "peerkeys", self.otor.svc_dir, self.otor.svc_dir / f"join-{cid}"):
            self.assertEqual(mode(d), 0o700, d)

    def test_capsule_secrets_not_in_torrc_or_state(self):
        block, cid, _ = self.create()
        c = C.decode_capsule(block)
        self.assertNotIn(c["token"], (Path(self.oh) / "capsules.json").read_text())            # token stored hashed
        cfg = self.otor.config()
        for s in (c["token"], c["joins"][0]["dial"]["key"], c["joins"][0]["boot"]["key"]):
            self.assertNotIn(s, cfg)
            self.assertNotIn(s, (self.otor.svc_file).read_text())

    def test_torrc_injection_via_names_bridges_fails_closed(self):
        evil = Identity.generate("arya\nHiddenServiceDir /etc")
        for kw in ({"bridges": ["Bridge 1.2.3.4:5\nUseBridges 0"]}, {"bridges": ["Bridge x\\"]}):
            with self.assertRaises(C.CapsuleError):
                self.create(**kw)
        self.assertEqual([k for k in self.otor._load_services() if k.startswith("join-")], [])
        self.assertNotIn("\nUseBridges", self.otor.config())
        try:
            C.create(self.oh, self.otor, evil, self.om, self.tid, clock=self.clock, wait_address=self.ofake)
        except C.CapsuleError:
            pass
        self.assertNotIn("HiddenServiceDir /etc", self.otor.config())

    def test_only_plain_bridge_lines_accepted(self):
        block, cid, _ = self.create(bridges=["Bridge obfs4 1.2.3.4:443 ABCD cert=xx iat-mode=0", "ClientTransportPlugin obfs4 exec /bin/sh", "UseBridges 1"])
        self.assertEqual(C.decode_capsule(block)["bridges"], ["Bridge obfs4 1.2.3.4:443 ABCD cert=xx iat-mode=0"])
        good = C.decode_capsule(block)
        for b in ("Bridge x\x7f", "Bridge x\u0000", "Bridge x\r", "bridge x", " Bridge x", "Bridge" + "a" * 400, None, 5):
            with self.assertRaises(C.CapsuleError):
                C.decode_capsule(C.encode_capsule({**good, "bridges": [b]}))

    def test_decode_fuzz_only_capsule_error(self):
        import random
        block, cid, _ = self.create()
        good = C.decode_capsule(block)
        rnd = random.Random(6)
        junk = [None, 5, -1, 1.5, True, [], {}, "", "x" * 50, [1], {"a": 1}, 10 ** 30, "\u0000", float("nan") if False else 0]
        for _ in range(400):
            c = json.loads(json.dumps(good))
            k = rnd.choice(list(c))
            if isinstance(c[k], dict) and c[k] and rnd.random() < .6:
                c[k][rnd.choice(list(c[k]))] = rnd.choice(junk)
            else:
                c[k] = rnd.choice(junk)
            try:
                raw = json.dumps(c, sort_keys=True).encode()
                import hashlib
                C.decode_capsule(f"{C.PREFIX} {C._b64(raw)} {hashlib.sha256(raw).hexdigest()[:8]}")
            except C.CapsuleError:
                pass

    def test_tolerant_state_files_no_crash_in_server(self):
        block, cid, _ = self.create()
        tok = tokof(block)
        for content in ("", "{", "[]", "null", '{"abcdefgh": 5}', '{"abcdefgh": {"tok": 5, "state": []}}', "x" * 100000):
            (Path(self.oh) / "capsules.json").write_text(content)
            self.assertEqual(self.server.handle({"t": "join_status", "token": tok}), {"t": "refused"})
            self.assertEqual(self.server.handle(req_for(tok, self.joiner)), {"t": "refused"})
        (Path(self.jh) / "joins.json").write_text('{"abcdefgh": {"state": "door"}}')

    def test_lock_symlink_not_followed(self):
        target = Path(self.oh) / "victim"
        target.write_text("x")
        os.symlink(target, Path(self.oh) / "capsules.json.lock")
        (Path(self.oh) / "capsules.json").write_text("{}")                  # (a store with no data file reads as empty WITHOUT taking its lock: the protection is for a store that has data)
        with self.assertRaises(OSError):
            C.Store(self.oh).all()
        with self.assertRaises(OSError):
            C.Store(self.oh).edit(lambda d: None)                           # and an edit always takes the lock
        self.assertEqual(target.read_text(), "x")

    def test_slots_freed_by_reject_expiry_confirm(self):
        ids = [self.create(ttl=60)[1] for _ in range(C.MAX_OPEN)]
        with self.assertRaises(C.CapsuleError):
            self.create()
        self.assertTrue(C.reject(self.oh, self.otor, ids[0], clock=self.clock))
        self.create()
        self.clock.t += 61
        for _ in range(C.MAX_OPEN - 1):
            self.create()                                               # expiry frees all (create sweeps first)

    def test_reject_and_expiry_teardown_idempotent_and_crash_safe(self):
        block, cid, _ = self.create(ttl=60)
        self.accept(block)
        self.poll()
        self.assertTrue(C.reject(self.oh, self.otor, cid, clock=self.clock))
        kf = Path(self.oh) / "peerkeys" / f"cap-{cid}.priv"
        self.assertFalse(kf.exists())
        self.assertNotIn(f"join-{cid}", self.otor._load_services())
        self.assertFalse(C.reject(self.oh, self.otor, cid, clock=self.clock))
        self.assertEqual(C.sweep(self.oh, self.otor, clock=self.clock), [])
        # simulated kill -9 after state flip but before door removal: fresh objects finish the job
        b2, c2, _ = self.create(ttl=60)
        C.Store(self.oh).edit(lambda d: d[c2].update(state="rejected"))
        C.sweep(self.oh, TorNode_fresh(self.oh), clock=self.clock)
        self.assertNotIn(f"join-{c2}", TorNode_fresh(self.oh)._load_services())
        self.assertFalse((Path(self.oh) / "peerkeys" / f"cap-{c2}.priv").exists())

    def test_cli_output_sanitises_stranger_names(self):
        h = tempfile.mkdtemp()
        run(h, "id", "init", "arya")
        (Path(h) / "capsules.json").write_text(json.dumps({"abcdefgh": {"state": "pending", "thread": "a" * 32, "exp": 10 ** 10, "req": {"agent": "a" * 32, "name": "x\x1b[31m‮evil\nFAKE LINE"}}}))
        (Path(h) / "joins.json").write_text(json.dumps({"abcdefgh": {"state": "door", "thread": "a" * 32, "owner": {"name": "o\x1b]0;t\x07‮\nFAKE"}}}))
        rc, out, err = run(h, "capsule", "list")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)
        self.assertNotIn("FAKE LINE", out)                      # records with hostile names are now dropped on load (stricter than sanitising)

    def test_stranger_name_not_in_events_or_wake_paths(self):
        block, cid, _ = self.create()
        self.accept(block)
        self.poll()
        mem = self.om.threads[self.tid]
        confirm(self, cid)
        # the node's wake/attention dir (if any) must hold ids/counts only; nothing under home but state files mentions the name beyond peers/events
        for p in Path(self.oh).rglob("*"):
            if p.is_file() and ("wake" in p.name or "attention" in p.name):
                self.assertNotIn("carol", p.read_text())


if __name__ == "__main__":
    unittest.main()
