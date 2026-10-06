import json
import os
import tempfile
import unittest
from pathlib import Path

from sigilnet import envelope as V
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror


def fresh():
    root = tempfile.mkdtemp()
    codec = EnvCodec(root + "/keys")
    m = Mirror(root + "/m", codec=codec, rate_limit=False)
    owner = Identity.generate("arya")
    other = Identity.generate("carol")
    g = make_genesis(owner, "secret title", [(other, "member"), (Identity.generate("dave"), "member"), (Identity.generate("eve"), "member")])
    assert m.ingest(g).ok
    tid = event_id(g)
    return root, codec, m, owner, other, tid


def lines(root, tid):
    return (Path(root) / "m" / "threads" / tid / "events.jsonl").read_bytes().splitlines()


class Enc(unittest.TestCase):
    def test_enable_rewrites_files_as_envelopes_genesis_plain(self):
        root, codec, m, owner, other, tid = fresh()
        m.ingest(Writer(owner, m.threads[tid]).post("the launch code is 1234"))
        self.assertIn(b"the launch code", b"".join(lines(root, tid)))
        kid = m.enable_encryption(tid)
        self.assertEqual(kid, tid)
        ls = lines(root, tid)
        self.assertEqual(len(ls), 2)
        self.assertIn(b"secret title", ls[0])                                   # the genesis is plaintext by design
        self.assertNotIn(b"launch code", b"".join(ls))
        self.assertTrue(all(json.loads(l).get("v") == 1 for l in ls[1:]))
        m.ingest(Writer(owner, m.threads[tid]).post("a second secret"))
        self.assertNotIn(b"second secret", b"".join(lines(root, tid)))
        m2 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)       # a new process reads it back
        texts = [e["body"].get("text") for e in m2.threads[tid].events.values() if e["kind"] == "post"]
        self.assertEqual(sorted(texts), ["a second secret", "the launch code is 1234"])

    def test_idempotent_enable(self):
        root, codec, m, owner, other, tid = fresh()
        m.ingest(Writer(owner, m.threads[tid]).post("x"))
        m.enable_encryption(tid)
        m.enable_encryption(tid)
        self.assertEqual(len(lines(root, tid)), 2)
        self.assertEqual(len(codec.ring(tid).ids()), 1)

    def test_locked_without_key_never_plaintext(self):
        root, codec, m, owner, other, tid = fresh()
        m.enable_encryption(tid)
        m.ingest(Writer(owner, m.threads[tid]).post("hidden"))
        os.unlink(codec.ring(tid).path)                                          # the keyring is gone, the marker stays
        m2 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)
        self.assertNotIn(tid, m2.threads)
        self.assertIn(tid, m2.locked)
        r = m2.ingest(Writer(owner, m.threads[tid]).post("would be plaintext"))
        self.assertEqual((r.status, r.reason), ("rejected", "thread is locked (no key)"))
        self.assertNotIn(b"would be plaintext", b"".join(lines(root, tid)))

    def test_locked_thread_not_rescanned_until_the_keyring_changes(self):
        root, codec, m, owner, other, tid = fresh()
        m.enable_encryption(tid)
        saved = codec.ring(tid).path.read_bytes()
        os.unlink(codec.ring(tid).path)
        c2 = EnvCodec(root + "/keys")
        m2 = Mirror(root + "/m", codec=c2, rate_limit=False)
        calls = []
        orig = m2._load
        m2._load = lambda t: (calls.append(t), orig(t))[1]
        for _ in range(5):
            m2.refresh()
        self.assertEqual(calls, [])                                                # not retried while nothing changed
        codec.ring(tid).path.write_bytes(saved)
        os.chmod(codec.ring(tid).path, 0o600)
        m2.refresh()
        self.assertEqual(calls, [tid])
        self.assertIn(tid, m2.threads)
        self.assertNotIn(tid, m2.locked)

    def test_missing_epoch_key_skips_lines_and_reload_recovers(self):
        root, codec, m, owner, other, tid = fresh()
        m.enable_encryption(tid)
        m.ingest(Writer(owner, m.threads[tid]).post("epoch0 post"))
        rm = Writer(owner, m.threads[tid]).admin("member_remove", {"agent": other.id})
        self.assertTrue(m.ingest(rm).ok)
        e1 = event_id(rm)
        codec.ring(tid).create(e1)                                                 # the new epoch's key (the owner makes it)
        m.ingest(Writer(owner, m.threads[tid]).post("epoch1 post"))
        ls = [json.loads(l) for l in lines(root, tid)[1:]]
        self.assertEqual({l["ep"] for l in ls}, {tid, e1})                         # new events use the newest key
        # a reader that only holds epoch 0
        only0 = tempfile.mkdtemp()
        c0 = EnvCodec(only0 + "/keys")
        k0 = codec.ring(tid).get(tid)[0]
        c0.ring(tid).install(tid, k0, verified=True)
        c0.mark(tid)
        os.makedirs(only0 + "/m/threads/" + tid)
        import shutil
        shutil.copy(Path(root) / "m" / "threads" / tid / "events.jsonl", only0 + "/m/threads/" + tid + "/events.jsonl")
        m0 = Mirror(only0 + "/m", codec=c0, rate_limit=False)
        texts = {e["body"].get("text") for e in m0.threads[tid].events.values() if e["kind"] == "post"}
        self.assertEqual(texts, {"epoch0 post"})
        self.assertGreaterEqual(m0.skipped[tid], 1)
        c0.ring(tid).install(e1, codec.ring(tid).get(e1)[0], verified=True)
        self.assertTrue(m0.reload(tid))
        texts = {e["body"].get("text") for e in m0.threads[tid].events.values() if e["kind"] == "post"}
        self.assertEqual(texts, {"epoch0 post", "epoch1 post"})

    def test_plaintext_lines_in_an_encrypted_thread_are_ignored(self):
        root, codec, m, owner, other, tid = fresh()
        m.enable_encryption(tid)
        forged = Writer(owner, m.threads[tid]).post("injected plaintext")
        from sigilnet.event import encode
        with open(Path(root) / "m" / "threads" / tid / "events.jsonl", "ab") as f:
            f.write(encode(forged) + b"\n")
        m2 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)
        self.assertNotIn(event_id(forged), m2.threads[tid].events)
        self.assertGreaterEqual(m2.skipped[tid], 1)

    def test_torn_tail_and_offsets_with_encrypted_lines(self):
        root, codec, m, owner, other, tid = fresh()
        m.enable_encryption(tid)
        m2 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)
        m.ingest(Writer(owner, m.threads[tid]).post("one"))
        self.assertTrue(m2.refresh())                                              # another process appended: picked up through the offset
        self.assertEqual(sum(1 for e in m2.threads[tid].events.values() if e["kind"] == "post"), 1)
        path = Path(root) / "m" / "threads" / tid / "events.jsonl"
        with open(path, "ab") as f:
            f.write(b'{"v":1,"th":"')                                               # a torn last line
        m3 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)
        self.assertTrue(m3.recovered)
        self.assertEqual(sum(1 for e in m3.threads[tid].events.values() if e["kind"] == "post"), 1)
        m3.ingest(Writer(owner, m3.threads[tid]).post("two"))
        m4 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)
        self.assertEqual(sum(1 for e in m4.threads[tid].events.values() if e["kind"] == "post"), 2)

    def test_public_thread_cannot_be_encrypted(self):
        root = tempfile.mkdtemp()
        m = Mirror(root + "/m", codec=EnvCodec(root + "/keys"))
        owner = Identity.generate("a")
        g = make_genesis(owner, "open", [], visibility="public")
        m.ingest(g)
        with self.assertRaises(ValueError):
            m.enable_encryption(event_id(g))

    def test_plain_mirror_cannot_enable(self):
        m = Mirror(tempfile.mkdtemp())
        with self.assertRaises(ValueError):
            m.enable_encryption("a" * 32)

    def test_no_key_means_no_write_not_a_torn_file(self):
        root, codec, m, owner, other, tid = fresh()
        m.enable_encryption(tid)
        before = (Path(root) / "m" / "threads" / tid / "events.jsonl").read_bytes()
        os.unlink(codec.ring(tid).path)
        r = m.ingest(Writer(owner, m.threads[tid]).post("x"))
        self.assertEqual(r.status, "rejected")                                       # refused BEFORE anything is stored: no half-applied state
        self.assertNotIn(r.reason and "x", [e["body"].get("text") for e in m.threads[tid].events.values()])
        self.assertEqual((Path(root) / "m" / "threads" / tid / "events.jsonl").read_bytes(), before)




class Recovery(unittest.TestCase):
    """Sansa round 18: the AUTHOR of a member_remove makes the key of the epoch it starts; if that author never returns the epoch is key-less and encrypted writes stall
    until an owner/admin adopts the epoch (README recovery path)."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.codec = EnvCodec(self.root + "/keys")
        self.m = Mirror(self.root + "/m", codec=self.codec, rate_limit=False)
        self.owner, self.admin = Identity.generate("owner"), Identity.generate("admin")
        self.x, self.y = Identity.generate("x"), Identity.generate("y")
        g = make_genesis(self.owner, "t", [(self.admin, "admin"), (self.x, "member"), (self.y, "member")])
        self.m.ingest(g)
        self.tid = event_id(g)
        self.m.enable_encryption(self.tid)

    def test_keyless_epoch_stalls_writes_and_adoption_recovers(self):
        t = self.m.threads[self.tid]
        rm = Writer(self.admin, t).admin("member_remove", {"agent": self.x.id})            # authored by the admin, who then vanishes before making the key
        self.assertTrue(self.m.ingest(rm).ok)
        e1 = event_id(rm)
        self.assertIsNone(self.codec.ring(self.tid).get(e1))
        r = self.m.ingest(Writer(self.owner, t).post("stalled"))
        self.assertEqual(r.status, "rejected")
        self.assertIn("no key for this epoch", r.reason)
        r = self.m.ingest(Writer(self.owner, t).admin("member_remove", {"agent": self.y.id}))      # a fresh removal does not help: it is sealed under the keyless epoch
        self.assertEqual(r.status, "rejected")
        self.codec.ring(self.tid).create(e1)                                               # `envelope rotate --adopt` by the owner/admin
        self.assertTrue(self.m.ingest(Writer(self.owner, t).post("recovered")).ok)
        m2 = Mirror(self.root + "/m", codec=EnvCodec(self.root + "/keys"), rate_limit=False)
        self.assertIn("recovered", [e["body"].get("text") for e in m2.threads[self.tid].events.values()])

    def test_cli_rotate_only_authors_unless_adopt(self):
        from sigilnet.cli import main
        import io, contextlib
        home = tempfile.mkdtemp()
        def run(*a):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                try:
                    main(["--home", home, *a])
                except SystemExit as e:
                    out.write(str(e.code))
            return out.getvalue()
        run("id", "init", "arya")
        pub = Path(home) / "x.json"
        run("id", "show", "--json")
        out = run("new", "thread one")
        tid = out.split("thread ")[1].split()[0]
        self.assertIn("encrypted", out)
        self.assertIn("ENCRYPTED", run("envelope", "status"))
        self.assertIn("verified", run("envelope", "status", tid[:8]))
        self.assertIn("none missing", run("envelope", "rotate", tid[:8]))


if __name__ == "__main__":
    unittest.main()


class CrashSafety(unittest.TestCase):
    """adv9 findings: an interrupted migration loses nothing; a deleted marker does not downgrade the thread; a forged sample cannot make a member's own key the epoch's key."""

    def test_every_crash_point_of_enable_loses_nothing(self):
        for crash in ("after_keys", "after_marker", "after_rewrite"):
            root, codec, m, owner, other, tid = fresh()
            m.ingest(Writer(owner, m.threads[tid]).post("zebra-1"))
            m.ingest(Writer(owner, m.threads[tid]).post("zebra-2"))
            ring = codec.ring(tid)
            ring.create(tid, owner)
            if crash != "after_keys":
                codec.mark(tid, migrating=True)
            if crash == "after_rewrite":
                m._rewrite_encrypted(m.threads[tid])
            m2 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)         # a new process after the crash
            texts = sorted(e["body"]["text"] for e in m2.threads[tid].events.values() if e["kind"] == "post")
            self.assertEqual(texts, ["zebra-1", "zebra-2"], crash)
            m2.enable_encryption(tid, owner)                                                  # the rerun finishes the job
            m3 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)
            self.assertEqual(sorted(e["body"]["text"] for e in m3.threads[tid].events.values() if e["kind"] == "post"), ["zebra-1", "zebra-2"], crash)
            self.assertNotIn(b"zebra-1", b"".join(lines(root, tid)), crash)

    def test_deleted_marker_is_repaired_not_downgraded(self):
        root, codec, m, owner, other, tid = fresh()
        m.enable_encryption(tid, owner)
        m.ingest(Writer(owner, m.threads[tid]).post("alpha-one"))
        os.unlink(codec._marker(tid))
        m2 = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)
        self.assertTrue(m2.codec.is_encrypted(tid))
        m2.ingest(Writer(owner, m2.threads[tid]).post("alpha-two"))
        self.assertNotIn(b"alpha-", b"".join(lines(root, tid)))
        self.assertEqual(sorted(e["body"]["text"] for e in m2.threads[tid].events.values() if e["kind"] == "post"), ["alpha-one", "alpha-two"])
        self.assertFalse(m2.codec.migrating(tid))                                                # finalised by the load

    def test_confirmation_binds_key_to_epoch_and_creator(self):
        root, codec, m, owner, other, tid = fresh()
        m.enable_encryption(tid, owner)
        t = m.threads[tid]
        key, conf = codec.ring(tid).get(tid)[0], codec.ring(tid).conf(tid)
        self.assertTrue(V.check_confirmation(t, tid, key, conf))
        self.assertFalse(V.check_confirmation(t, tid, b"j" * 32, conf))                        # another key
        self.assertFalse(V.check_confirmation(t, "f" * 32, key, conf))                         # another epoch id
        self.assertFalse(V.check_confirmation(t, tid, key, V.make_confirmation(other, tid, tid, key)))      # signed by a plain member
        self.assertFalse(V.check_confirmation(t, tid, key, None))
        self.assertFalse(V.check_confirmation(t, tid, key, {"by": "zz", "sig": "00"}))
        # a member (not creator/admin) sealing a key of its own and confirming it itself is refused
        evil = os.urandom(32)
        self.assertFalse(V.check_confirmation(t, tid, evil, V.make_confirmation(other, tid, tid, evil)))


class RoleAndKeyOrder(unittest.TestCase):
    def test_only_owner_or_admin_may_enable(self):
        root, codec, m, owner, other, tid = fresh()
        with self.assertRaises(ValueError):
            m.enable_encryption(tid, other)                                           # a plain member: refused (round 21 F1)
        self.assertFalse(codec.is_encrypted(tid))
        m.enable_encryption(tid, owner)
        self.assertTrue(codec.is_encrypted(tid))

    def test_create_replaces_an_unverified_entry(self):
        d = tempfile.mkdtemp()
        r = V.Keyring(d + "/k", "a" * 32)
        r.install("b" * 32, b"x" * 32, verified=False)
        k = r.create("b" * 32)
        self.assertNotEqual(k, b"x" * 32)
        self.assertEqual(r.get("b" * 32), (k, True))


class Discard(unittest.TestCase):
    def test_discard(self):
        d = tempfile.mkdtemp()
        r = V.Keyring(d + "/k", "a" * 32)
        r.create("b" * 32)
        self.assertTrue(r.discard("b" * 32))
        self.assertFalse(r.discard("b" * 32))
        self.assertEqual(r.ids(), [])
