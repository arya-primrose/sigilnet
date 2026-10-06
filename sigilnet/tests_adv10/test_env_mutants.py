"""Regression tests added after a mutation run over the encrypted-envelope code (envelope.py, the envelope parts of mirror.py/sync.py/capsule.py/node.py/cli.py).
Each test kills at least one mutant that the earlier suites let survive; every test passes on the real code."""
import base64
import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sigilnet import canon
from sigilnet import envelope as V
from sigilnet import sync as S
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import EnvCodec, Keyring
from sigilnet.event import EventError, event_id
from sigilnet.keys import Identity, verify_strict
from sigilnet.mirror import Mirror
from sigilnet.sync import Loopback, SyncServer, fetch_keys, pull, sign_request


def node():
    root = tempfile.mkdtemp()
    codec = EnvCodec(root + "/keys")
    return root, codec, Mirror(root + "/m", codec=codec, rate_limit=False)


def lines(root, tid):
    return (Path(root) / "m" / "threads" / tid / "events.jsonl").read_bytes().splitlines()


def texts(m, tid):
    return sorted(e["body"]["text"] for e in m.threads[tid].events.values() if e["kind"] == "post")


def b64(s):
    return base64.b64decode(s)


class World(unittest.TestCase):
    """a = owner, b = admin, c and d = members; thread held by `ma` (encrypting codec), not yet encrypted."""

    def setUp(self):
        self.a, self.b, self.c, self.d = (Identity.generate(n) for n in "abcd")
        self.ra, self.ca, self.ma = node()
        self.g = make_genesis(self.a, "title", [(self.b, "admin"), (self.c, "member"), (self.d, "member")])
        self.ma.ingest(self.g)
        self.tid = event_id(self.g)

    @property
    def t(self):
        return self.ma.threads[self.tid]

    def w(self, who, m=None):
        return Writer(who, (m or self.ma).threads[self.tid])

    def remove(self, by, victim, m=None, codec=None, key=True):
        ev = self.w(by, m).admin("member_remove", {"agent": victim.id})
        self.assertTrue((m or self.ma).ingest(ev).ok)
        return event_id(ev)


# ---------------------------------------------------------------- wire format, fixed to the spec (known answers)

class KnownAnswers(unittest.TestCase):
    def test_envelope_aad_is_context_thread_keyid(self):
        key, tid, kid = os.urandom(32), "ab" * 16, "cd" * 16
        env = V.seal_event(key, tid, kid, {"x": 1})
        plain = ChaCha20Poly1305(key).decrypt(b64(env["n"]), b64(env["c"]), b"sigilnet/v1/env\0" + tid.encode() + b"\0" + kid.encode())
        self.assertEqual(plain[:4], (len(canon.dumps({"x": 1}))).to_bytes(4, "big"))

    def test_padding_bucket_is_256(self):
        key, tid, kid = os.urandom(32), "ab" * 16, "cd" * 16
        for n in (1, 10, 100, 240, 300, 1000):
            ct = b64(V.seal_event(key, tid, kid, {"a": "x" * n})["c"])
            self.assertEqual((len(ct) - 16) % 256, 0, n)
        self.assertEqual(len(b64(V.seal_event(key, tid, kid, {"a": "x"})["c"])) - 16, 256)
        self.assertEqual(len(b64(V.seal_event(key, tid, kid, {"a": "x" * 260})["c"])) - 16, 512)

    def test_sealed_key_kdf_and_aad_are_spec(self):
        me = Identity.generate("m")
        tid, kid, key = "ab" * 16, "cd" * 16, os.urandom(32)
        s = V.seal_key(me.kex_pub, me.id, tid, kid, key)
        eph = bytes.fromhex(s["e"])
        shared = me.kex_key.exchange(x25519.X25519PublicKey.from_public_bytes(eph))
        info = b"sigilnet/v1/keyseal\0" + eph + bytes.fromhex(me.kex_pub) + tid.encode() + b"\0" + kid.encode()
        k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
        aad = b"sigilnet/v1/keyseal\0" + tid.encode() + b"\0" + kid.encode() + b"\0" + me.id.encode()
        self.assertEqual(ChaCha20Poly1305(k).decrypt(b64(s["n"]), b64(s["c"]), aad), key)

    def test_confirmation_signs_context_thread_keyid_keyhash(self):
        a = Identity.generate("a")
        tid, kid, key = "ab" * 16, "cd" * 16, os.urandom(32)
        conf = V.make_confirmation(a, tid, kid, key)
        msg = b"sigilnet/v1/keyconfirm\0" + tid.encode() + b"\0" + kid.encode() + b"\0" + hashlib.sha256(key).digest()
        self.assertTrue(verify_strict(a.sign_pub, conf["sig"], msg))

    def test_seal_size_limit_is_inclusive(self):
        key, tid, kid = os.urandom(32), "ab" * 16, "cd" * 16
        n = V.MAX_ENV_PLAIN - len(canon.dumps({"a": ""}))
        env = V.seal_event(key, tid, kid, {"a": "x" * n})              # exactly the limit: allowed
        self.assertEqual(len(V.open_envelope(key, env, tid)["a"]), n)
        with self.assertRaises(V.EnvelopeError):
            V.seal_event(key, tid, kid, {"a": "x" * (n + 1)})

    def crafted(self, padded):
        key, tid, kid = os.urandom(32), "ab" * 16, "cd" * 16
        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(key).encrypt(nonce, padded, b"sigilnet/v1/env\0" + tid.encode() + b"\0" + kid.encode())
        env = {"v": 1, "th": tid, "ep": kid, "n": base64.b64encode(nonce).decode(), "c": base64.b64encode(ct).decode()}
        return V.open_envelope(key, env, tid)

    def test_padding_is_checked_strictly_on_open(self):
        def padded(plain, extra=0):
            body = len(plain).to_bytes(4, "big") + plain
            return body + b"\0" * (-len(body) % 256 + extra)
        plain = canon.dumps({"x": 1})
        self.assertEqual(self.crafted(padded(plain)), {"x": 1})
        exact = canon.dumps({"a": "x" * 244})                                                 # 4 + 252 = exactly one bucket: no padding needed
        self.assertEqual(len(exact) + 4, 256)
        self.assertEqual(self.crafted(padded(exact)), {"a": "x" * 244})
        for bad in (b"", b"\0\0\0", padded(exact, 256), padded(plain, 256), padded(plain, 512)):     # empty, short, exactly a whole spare bucket, more
            with self.assertRaises(V.EnvelopeError):
                self.crafted(bad)
        with self.assertRaises(V.EnvelopeError):
            self.crafted(padded(plain)[:-1] + b"\1")                                         # non-zero padding
        big = canon.dumps({"a": "x" * (V.MAX_ENV_PLAIN + 5000)})
        with self.assertRaises(V.EnvelopeError):
            self.crafted(padded(big))                                                         # a ciphertext beyond the largest event

    def test_noncanonical_encodings_are_refused(self):
        key, tid = os.urandom(32), "ab" * 16
        env = V.seal_event(key, tid, "cd" * 16, {"x": 1})
        self.assertEqual(V.open_envelope(key, env, tid), {"x": 1})
        bad = dict(env, c=env["c"][:8] + "\n" + env["c"][8:])          # a stray character that a lenient base64 decoder would skip
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(key, bad, tid)
        bad = dict(env, n=env["n"][:4] + "!" + env["n"][4:])
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(key, bad, tid)
        env2 = V.seal_event(key, tid, "g" * 32, {"x": 1})              # a key id must be 32 hex chars
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(key, env2, tid)

    def test_sealed_key_ephemeral_must_be_lowercase_hex(self):
        me = Identity.generate("m")
        s = V.seal_key(me.kex_pub, me.id, "ab" * 16, "cd" * 16, os.urandom(32))
        V.open_key(me, "ab" * 16, "cd" * 16, s)
        up = dict(s, e=s["e"].upper())
        self.assertNotEqual(up["e"], s["e"])
        with self.assertRaises(V.EnvelopeError):
            V.open_key(me, "ab" * 16, "cd" * 16, up)


# ---------------------------------------------------------------- confirmations and epochs

class Confirmations(World):
    def test_shape_and_key_checks(self):
        key = os.urandom(32)
        conf = V.make_confirmation(self.a, self.tid, self.tid, key)
        self.assertTrue(V.check_confirmation(self.t, self.tid, key, conf))
        self.assertFalse(V.check_confirmation(self.t, self.tid, key, dict(conf, x=1)))                  # extra field
        self.assertFalse(V.check_confirmation(self.t, self.tid, key, dict(conf, sig=conf["sig"].upper())))
        short = os.urandom(31)
        self.assertFalse(V.check_confirmation(self.t, self.tid, short, V.make_confirmation(self.a, self.tid, self.tid, short)))     # valid signature, wrong key length
        self.assertFalse(V.check_confirmation(self.t, self.tid, None, conf))                              # never raises
        self.assertFalse(V.check_confirmation(self.t, self.tid, key, None))

    def test_admin_may_confirm_the_owners_epoch(self):
        key = os.urandom(32)
        self.assertTrue(V.check_confirmation(self.t, self.tid, key, V.make_confirmation(self.b, self.tid, self.tid, key)))      # admin
        self.assertFalse(V.check_confirmation(self.t, self.tid, key, V.make_confirmation(self.c, self.tid, self.tid, key)))     # plain member

    def test_creator_of_the_epoch_may_confirm_even_after_losing_the_role(self):
        r1 = self.remove(self.b, self.c)                                     # admin b starts epoch 1
        self.remove(self.a, self.b)                                          # ... and is removed afterwards
        key = os.urandom(32)
        self.assertTrue(V.check_confirmation(self.t, r1, key, V.make_confirmation(self.b, self.tid, r1, key)))
        self.assertFalse(V.check_confirmation(self.t, self.tid, key, V.make_confirmation(self.b, self.tid, self.tid, key)))      # not the creator of epoch 0, not an admin any more


class Epochs(World):
    def test_epoch_id_at_a_non_epoch_admin_event_is_the_genesis(self):
        add = self.w(self.a).add_member(Identity.generate("e"), "member")
        self.assertTrue(self.ma.ingest(add).ok)
        self.assertEqual(V.epoch_id_at(self.t, event_id(add)), self.tid)
        self.assertEqual(V.epoch_id_at(self.t, self.tid), self.tid)
        r1 = self.remove(self.a, self.c)
        self.assertEqual(V.epoch_id_at(self.t, r1), r1)
        add2 = self.w(self.a).add_member(Identity.generate("f"), "member")
        self.assertTrue(self.ma.ingest(add2).ok)
        self.assertEqual(V.epoch_id_at(self.t, event_id(add2)), r1)
        self.assertEqual(V.chain_epoch_ids(self.t), [self.tid, r1])


# ---------------------------------------------------------------- the keyring

class KeyringRules(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp()) / "keys"
        self.tid = "ab" * 16
        self.ring = Keyring(self.dir, self.tid)

    def raw(self, d):
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ring.path.write_text(json.dumps(d))

    def entry(self, ok=True, c=None, key=None):
        e = {"k": base64.b64encode(key or os.urandom(32)).decode(), "ok": ok}
        if c is not None:
            e["c"] = c
        return e

    def test_lock_file_is_private_and_not_followed(self):
        self.ring.create("cd" * 16)
        self.assertEqual(stat.S_IMODE(os.stat(self.ring.lockp).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.ring.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        os.unlink(self.ring.lockp)
        victim = self.dir / "victim"
        victim.write_text("x")
        os.symlink(victim, self.ring.lockp)
        with self.assertRaises(OSError):
            self.ring.create("ef" * 16)

    def test_load_validation(self):
        good, other = "cd" * 16, "ef" * 16
        conf = {"by": "ab" * 32, "sig": "cd" * 64}
        self.raw({good: self.entry(), "nothex": self.entry(), "gg" * 16: self.entry(),
                  other: self.entry(c={"by": "ab" * 32, "sig": "cd" * 64, "x": 1}), "01" * 16: self.entry(c="junk"),
                  "02" * 16: self.entry(c={"by": "zz" * 32, "sig": "cd" * 64}), "03" * 16: self.entry(c={"by": "ab" * 32, "sig": "zz" * 64}),
                  "04" * 16: self.entry(c=conf)})
        self.assertEqual(self.ring.ids(), sorted([good, "04" * 16]))
        self.assertEqual(self.ring.conf("04" * 16), conf)
        self.assertIsNone(self.ring.conf(good))

    def test_load_caps_the_number_of_keys(self):
        d = {f"{i:032x}": self.entry() for i in range(V.MAX_KEYS + 5)}
        self.raw(d)
        self.assertEqual(len(self.ring.ids()), V.MAX_KEYS)

    def test_create_and_install_cap_and_ids(self):
        with self.assertRaises(V.EnvelopeError):
            self.ring.create("not-a-key-id")
        self.raw({f"{i:032x}": self.entry(ok=(i != 0)) for i in range(V.MAX_KEYS)})        # full; key 0 is unverified
        with self.assertRaises(V.EnvelopeError):
            self.ring.create("f" * 32)
        with self.assertRaises(V.EnvelopeError):
            self.ring.install("f" * 32, os.urandom(32))
        self.assertTrue(self.ring.install(f"{0:032x}", os.urandom(32), verified=True))     # replacing an unverified key at the cap is fine
        self.assertEqual(len(self.ring.ids()), V.MAX_KEYS)

    def test_install_rules(self):
        kid, k1, k2 = "cd" * 16, os.urandom(32), os.urandom(32)
        conf = {"by": "ab" * 32, "sig": "cd" * 64}
        self.assertTrue(self.ring.install(kid, k1, verified=False, conf=conf))
        self.assertFalse(self.ring.install(kid, k1, verified=False, conf=conf))             # no change: False
        self.assertEqual(self.ring.conf(kid), conf)                                          # the confirmation is kept
        self.assertEqual(self.ring.get(kid), (k1, False))
        self.assertTrue(self.ring.install(kid, k2, verified=True))                           # unverified may be replaced
        self.assertEqual(self.ring.get(kid), (k2, True))
        self.assertFalse(self.ring.install(kid, k1, verified=True))                          # verified is never overwritten
        self.assertFalse(self.ring.install(kid, k1, verified=False))
        self.assertEqual(self.ring.get(kid), (k2, True))
        with self.assertRaises(V.EnvelopeError):
            self.ring.install("nothex", k1)
        with self.assertRaises(V.EnvelopeError):
            self.ring.install("ee" * 16, os.urandom(31))

    def test_install_unverified_stays_unverified(self):
        self.ring.install("cd" * 16, os.urandom(32))
        self.assertFalse(self.ring.get("cd" * 16)[1])
        self.ring.mark_verified("cd" * 16)
        self.assertTrue(self.ring.get("cd" * 16)[1])

    def test_load_ignores_a_symlinked_ring_and_exists_says_no(self):
        self.ring.create("cd" * 16)
        real = self.dir / "real.json"
        shutil.move(self.ring.path, real)
        os.symlink(real, self.ring.path)
        self.assertEqual(self.ring.ids(), [])
        self.assertFalse(self.ring.exists())

    def test_create_signs_when_given_a_signer_and_is_idempotent(self):
        a = Identity.generate("a")
        k = self.ring.create("cd" * 16, a)
        self.assertEqual(self.ring.create("cd" * 16), k)
        c = self.ring.conf("cd" * 16)
        self.assertTrue(verify_strict(c["by"], c["sig"], V._confirm_msg(self.tid, "cd" * 16, k)))
        self.assertTrue(self.ring.get("cd" * 16)[1])


# ---------------------------------------------------------------- the codec: marker, usable, sig, genesis exception

class CodecRules(World):
    def test_marker_dir_is_private_and_garbage_marker_is_not_migrating(self):
        codec = EnvCodec(tempfile.mkdtemp() + "/fresh")
        codec.mark("ab" * 16)
        self.assertEqual(stat.S_IMODE(os.stat(codec.dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(codec._marker("ab" * 16)).st_mode), 0o600)
        self.assertEqual(codec._marker("ab" * 16).read_bytes(), b"")
        self.assertFalse(codec.migrating("ab" * 16))
        codec._marker("ab" * 16).write_bytes(b"whatever")                       # neither "" nor "migrating": not a migration, plain lines are NOT accepted
        self.assertFalse(codec.migrating("ab" * 16))
        codec.mark("ab" * 16, migrating=True)
        self.assertTrue(codec.migrating("ab" * 16))
        self.assertEqual(stat.S_IMODE(os.stat(codec._marker("ab" * 16)).st_mode), 0o600)

    def test_empty_keyring_locks_the_thread(self):
        self.ma.enable_encryption(self.tid, self.a)
        ring = self.ca.ring(self.tid)
        ring.path.write_text("{}")
        self.assertTrue(ring.exists())
        self.assertFalse(self.ca.usable(self.tid))
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertIn(self.tid, m2.locked)
        self.assertNotIn(self.tid, m2.threads)

    def test_sig_follows_the_ring_file(self):
        codec = EnvCodec(tempfile.mkdtemp() + "/k")
        tid = "ab" * 16
        codec.mark(tid)
        missing = codec.sig(tid)
        ring = codec.ring(tid)
        ring.path.write_text("")
        os.utime(ring.path, ns=(0, 0))
        self.assertNotEqual(codec.sig(tid), missing)                                 # an empty file with mtime 0 is not "no file"
        self.assertEqual(codec.sig(tid), (True, 0, 0))
        ring.path.write_text("{}")
        os.utime(ring.path, ns=(0, 0))
        self.assertEqual(codec.sig(tid), (True, 0, 2))
        ring.path.write_text("{ }")
        os.utime(ring.path, ns=(0, 0))
        self.assertNotEqual(codec.sig(tid), (True, 0, 2))                            # same mtime, other size
        ring.path.write_text("{}")
        os.utime(ring.path, ns=(10 ** 9, 10 ** 9))
        self.assertNotEqual(codec.sig(tid), (True, 0, 2))                            # same size, other mtime

    def test_encode_and_decode_only_this_threads_genesis_plain(self):
        self.ma.enable_encryption(self.tid, self.a)
        foreign = make_genesis(self.a, "another thread", [(self.b, "member")])
        self.assertNotEqual(event_id(foreign), self.tid)
        with self.assertRaises(V.EnvelopeError):
            self.ca.encode(self.t, foreign)                                         # never written plain
        with self.assertRaises(EventError):
            self.ca.decode(self.tid, canon.dumps(foreign))                          # never accepted plain
        self.assertEqual(self.ca.decode(self.tid, canon.dumps(self.g))["kind"], "genesis")

    def test_decode_failures_are_event_errors(self):
        self.ma.enable_encryption(self.tid, self.a)
        env = self.ca.encode(self.t, self.w(self.a).post("x"))
        other = Identity.generate("o")
        # a key that exists but is the wrong one for this envelope: still an EventError, not an EnvelopeError leaking out
        ring = self.ca.ring(self.tid)
        raw = json.loads(ring.path.read_text())
        raw[self.tid]["k"] = base64.b64encode(os.urandom(32)).decode()
        ring.path.write_text(json.dumps(raw))
        with self.assertRaises(EventError):
            self.ca.decode(self.tid, env)
        with self.assertRaises(EventError):
            self.ca.decode(self.tid, b"{not json")

    def test_decode_checks_the_inner_structure(self):
        self.ma.enable_encryption(self.tid, self.a)
        key = self.ca.ring(self.tid).get(self.tid)[0]
        env = V.seal_event(key, self.tid, self.tid, {"v": 1, "kind": "post"})        # decrypts fine but is not an event
        with self.assertRaises(EventError):
            self.ca.decode(self.tid, canon.dumps(env))

    def test_sig_changes_when_the_marker_goes_even_without_a_ring(self):
        codec = EnvCodec(tempfile.mkdtemp() + "/k")
        codec.mark("ab" * 16)
        s1 = codec.sig("ab" * 16)
        os.unlink(codec._marker("ab" * 16))
        self.assertNotEqual(s1, codec.sig("ab" * 16))

    def test_can_encode_and_encode_need_a_verified_key(self):
        self.ma.enable_encryption(self.tid, self.a)
        ev = self.w(self.a).post("x")
        self.assertTrue(self.ca.can_encode(self.t, ev))
        ring = self.ca.ring(self.tid)
        ring.path.write_text(json.dumps({self.tid: {"k": base64.b64encode(os.urandom(32)).decode(), "ok": False, "c": None}}))
        self.assertFalse(self.ca.can_encode(self.t, ev))
        with self.assertRaises(V.EnvelopeError):
            self.ca.encode(self.t, ev)
        with self.assertRaises(V.EnvelopeError):
            self.ca.key_for(self.t, ev)
        ring.path.write_text(json.dumps({"ee" * 16: {"k": base64.b64encode(os.urandom(32)).decode(), "ok": True, "c": None}}))     # a key, but not this epoch's
        self.assertFalse(self.ca.can_encode(self.t, ev))
        self.assertTrue(EnvCodec(tempfile.mkdtemp()).can_encode(self.t, ev))        # a codec that does not hold the thread as encrypted writes anything
        stray = dict(ev, admin_ref="ff" * 16)                                       # an event whose admin state we lack is the thread layer's business (parked)
        self.assertTrue(self.ca.can_encode(self.t, stray))

    def test_decode_needs_no_verified_key_to_open_but_requires_a_key(self):
        self.ma.enable_encryption(self.tid, self.a)
        ev = self.w(self.a).post("x")
        raw = self.ca.encode(self.t, ev)
        ring = self.ca.ring(self.tid)
        d = json.loads(ring.path.read_text())
        d[self.tid]["ok"] = False                                                   # an unverified key still opens what we hold (verification is about authorship of the key)
        ring.path.write_text(json.dumps(d))
        self.assertEqual(self.ca.decode(self.tid, raw)["body"]["text"], "x")
        os.unlink(ring.path)
        os.unlink(self.ca._marker(self.tid))
        self.ca.mark(self.tid)
        with self.assertRaises(EventError):
            self.ca.decode(self.tid, raw)


# ---------------------------------------------------------------- mirror: enable_encryption, load, reload, persist

class MirrorEnc(World):
    def two_epochs(self, signer=True):
        self.ma.ingest(self.w(self.a).post("p0"))
        r1 = self.remove(self.a, self.d)
        self.ma.ingest(self.w(self.a).post("p1"))
        return r1

    def test_enable_confirms_every_epoch_key_with_the_signer(self):
        r1 = self.two_epochs()
        self.assertEqual(self.ma.enable_encryption(self.tid, self.a), r1)
        ring = self.ca.ring(self.tid)
        self.assertEqual(ring.ids(), sorted([self.tid, r1]))
        for kid in (self.tid, r1):
            got = ring.get(kid)
            self.assertTrue(got[1])
            self.assertTrue(V.check_confirmation(self.t, kid, got[0], ring.conf(kid)), kid)
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(texts(m2, self.tid), ["p0", "p1"])
        for raw in lines(self.ra, self.tid)[1:]:
            self.assertTrue(V.looks_like_envelope(canon.loads(raw)))
        self.assertFalse(self.ca.migrating(self.tid))

    def test_enable_ignores_parked_events(self):
        pm = Mirror(tempfile.mkdtemp())
        pm.ingest(self.g)
        r = Writer(self.a, pm.threads[self.tid]).admin("member_remove", {"agent": self.d.id})
        pm.ingest(r)
        parked = Writer(self.a, pm.threads[self.tid]).post("parked")                 # its admin_ref is the removal we do not hold
        self.assertNotEqual(parked["admin_ref"], self.tid)
        self.ma.ingest(self.w(self.a).post("p0"))
        self.assertIn(self.ma.ingest(parked).status, ("pending", "awaiting"))
        self.ma.enable_encryption(self.tid, self.a)                                  # must not choke on it, nor write it
        self.assertEqual(len(lines(self.ra, self.tid)), 2)

    def test_enable_picks_up_what_another_handle_appended(self):
        self.ma.ingest(self.w(self.a).post("mine"))
        other = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertTrue(other.ingest(Writer(self.b, other.threads[self.tid]).post("theirs")).ok)       # appended behind our back
        self.ma.enable_encryption(self.tid, self.a)
        m3 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(texts(m3, self.tid), ["mine", "theirs"])

    def test_enable_sees_a_thread_that_only_exists_on_disk(self):
        other = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        g2 = make_genesis(self.a, "second", [(self.b, "member")])
        other.ingest(g2)
        self.assertNotIn(event_id(g2), self.ma.threads)
        self.ma.enable_encryption(event_id(g2), self.a)
        self.assertTrue(self.ca.is_encrypted(event_id(g2)))

    def test_enable_leaves_offsets_right_for_the_next_refresh(self):
        self.ma.ingest(self.w(self.a).post("p0"))
        self.ma.enable_encryption(self.tid, self.a)
        self.assertFalse(self.ma.refresh())
        self.assertEqual(self.ma.skipped.get(self.tid, 0), 0)
        self.assertTrue(self.ma.ingest(self.w(self.a).post("p1")).ok)
        self.assertFalse(self.ma.refresh())
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(texts(m2, self.tid), ["p0", "p1"])

    def test_enable_marks_migrating_only_after_the_keys_exist(self):
        self.ma.ingest(self.w(self.a).post("p0"))
        orig = Keyring.create
        Keyring.create = lambda *a, **k: (_ for _ in ()).throw(V.EnvelopeError("disk full"))
        try:
            with self.assertRaises(V.EnvelopeError):
                self.ma.enable_encryption(self.tid, self.a)
        finally:
            Keyring.create = orig
        self.assertFalse(self.ca._marker(self.tid).exists())                         # no marker without keys: the thread would be locked for good
        self.assertFalse(self.ca.is_encrypted(self.tid))

    def test_enable_failing_in_the_rewrite_leaves_the_marker_migrating(self):
        self.ma.ingest(self.w(self.a).post("p0"))
        orig = self.ca.encode
        self.ca.encode = lambda *a, **k: (_ for _ in ()).throw(V.EnvelopeError("boom"))
        try:
            with self.assertRaises(V.EnvelopeError):
                self.ma.enable_encryption(self.tid, self.a)
        finally:
            self.ca.encode = orig
        self.assertTrue(self.ca.migrating(self.tid))                                 # plaintext lines stay readable
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(texts(m2, self.tid), ["p0"])
        self.assertFalse(m2.codec.migrating(self.tid))                               # ... and loading finishes the job
        for raw in lines(self.ra, self.tid)[1:]:
            self.assertTrue(V.looks_like_envelope(canon.loads(raw)))

    def test_loading_a_migrating_thread_rewrites_and_finalises(self):
        self.ma.ingest(self.w(self.a).post("p0"))
        self.ma.ingest(self.w(self.a).post("p1"))
        self.ca.ring(self.tid).create(self.tid, self.a)
        self.ca.mark(self.tid, migrating=True)
        self.assertIn(b"p0", b"".join(lines(self.ra, self.tid)))
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(texts(m2, self.tid), ["p0", "p1"])
        self.assertNotIn(b'"text"', b"".join(lines(self.ra, self.tid)[1:]))
        self.assertFalse(m2.codec.migrating(self.tid))
        self.assertEqual(self.ca._marker(self.tid).read_bytes(), b"")

    def test_a_failed_migration_on_load_does_not_finalise(self):
        self.ma.ingest(self.w(self.a).post("p0"))
        self.ca.ring(self.tid).create("ee" * 16, self.a)                             # a key, but none for this thread's epoch: the rewrite cannot encode
        self.ca.mark(self.tid, migrating=True)
        with self.assertRaises(V.EnvelopeError):
            Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertTrue(self.ca.migrating(self.tid))
        self.assertIn(b"p0", b"".join(lines(self.ra, self.tid)))

    def test_reload_replaces_state_and_resets_counters(self):
        self.ma.enable_encryption(self.tid, self.a)
        self.ma.ingest(self.w(self.a).post("p0"))
        ring = self.ca.ring(self.tid)
        saved = ring.path.read_bytes()
        os.unlink(ring.path)                                                         # marker stays: LOCKED
        self.assertFalse(self.ma.reload(self.tid))
        self.assertNotIn(self.tid, self.ma.threads)
        self.assertIn(self.tid, self.ma.locked)
        ring.path.write_bytes(saved)
        self.assertTrue(self.ma.reload(self.tid))
        self.assertNotIn(self.tid, self.ma.locked)
        self.assertEqual(texts(self.ma, self.tid), ["p0"])
        self.ma.skipped[self.tid] = 5
        self.assertTrue(self.ma.reload(self.tid))
        self.assertEqual(self.ma.skipped.get(self.tid, 0), 0)                        # recounted from the lines of this load

    def test_reload_clears_a_stale_lock_even_if_the_thread_is_gone(self):
        self.ma.enable_encryption(self.tid, self.a)
        ring = self.ca.ring(self.tid)
        os.unlink(ring.path)
        self.assertFalse(self.ma.reload(self.tid))
        self.assertIn(self.tid, self.ma.locked)
        os.unlink(self.ca._marker(self.tid))
        (Path(self.ra) / "m" / "threads" / self.tid / "events.jsonl").write_bytes(b"")
        self.assertFalse(self.ma.reload(self.tid))
        self.assertNotIn(self.tid, self.ma.locked)

    def test_locked_thread_is_rescanned_only_when_its_signature_changes(self):
        self.ma.enable_encryption(self.tid, self.a)
        ring = self.ca.ring(self.tid)
        saved = ring.path.read_bytes()
        os.unlink(ring.path)
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertIn(self.tid, m2.locked)
        calls = []
        orig = m2._load
        m2._load = lambda tid: (calls.append(tid), orig(tid))[1]
        m2.refresh()
        self.assertEqual(calls, [])                                                  # nothing changed: not retried
        ring.path.write_bytes(saved)
        m2.refresh()
        self.assertEqual(calls, [self.tid])
        self.assertIn(self.tid, m2.threads)
        self.assertNotIn(self.tid, m2.locked)
        m2.refresh()
        self.assertEqual(calls, [self.tid])                                          # a loaded thread is not reloaded

    def test_marker_removed_while_locked_is_noticed_by_the_rescan(self):
        self.ma.enable_encryption(self.tid, self.a)
        saved = self.ca.ring(self.tid).path.read_bytes()
        os.unlink(self.ca.ring(self.tid).path)
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertIn(self.tid, m2.locked)
        os.unlink(self.ca._marker(self.tid))
        m2.refresh()
        self.assertNotIn(self.tid, m2.locked)

    def test_ingest_into_a_locked_thread_is_refused(self):
        self.ma.enable_encryption(self.tid, self.a)
        ev = self.w(self.a).post("x")
        os.unlink(self.ca.ring(self.tid).path)
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        r = m2.ingest(ev)
        self.assertEqual((r.status, "locked" in r.reason), ("rejected", True))
        self.assertEqual(m2.orphans, {})

    def test_event_without_its_epoch_key_is_refused_and_nothing_is_written(self):
        self.ma.enable_encryption(self.tid, self.a)
        r1 = self.remove(self.a, self.d)                                            # the key for epoch r1 is NOT made yet
        before = lines(self.ra, self.tid)
        post = self.w(self.a).post("after")
        res = self.ma.ingest(post)
        self.assertEqual(res.status, "rejected")
        self.assertIn("need_key", res.reason)
        self.assertEqual(lines(self.ra, self.tid), before)


class ParkedNeedsKey(World):
    """P was parked behind the removal R; R resolves it, but we hold no key for epoch R yet: P is in memory only, counted, and written once the key exists."""

    def setUp(self):
        super().setUp()
        self.ma.enable_encryption(self.tid, self.a)
        pm = Mirror(tempfile.mkdtemp())
        pm.ingest(self.g)
        self.r = Writer(self.a, pm.threads[self.tid]).admin("member_remove", {"agent": self.d.id})
        pm.ingest(self.r)
        self.rid = event_id(self.r)
        self.p1 = Writer(self.b, pm.threads[self.tid]).post("needle-one")
        pm.ingest(self.p1)
        self.p2 = Writer(self.c, pm.threads[self.tid]).post("needle-two")
        pm.ingest(self.p2)
        for p in (self.p1, self.p2):
            self.assertIn(self.ma.ingest(p).status, ("pending", "awaiting"))

    def test_skipped_counted_not_written_then_written_after_key(self):
        self.assertTrue(self.ma.ingest(self.r).ok)
        self.assertEqual(self.ma.skipped.get(self.tid), 2)
        self.assertEqual(len(lines(self.ra, self.tid)), 2)                          # genesis + R only
        self.ca.ring(self.tid).create(self.rid, self.a)
        self.assertTrue(self.ma.ingest(Writer(self.a, self.t).post("p3")).ok)
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(texts(m2, self.tid), ["needle-one", "needle-two", "p3"])

    def test_enable_again_marks_what_it_wrote_as_persisted(self):
        self.assertTrue(self.ma.ingest(self.r).ok)
        self.ma.enable_encryption(self.tid, self.a)                                 # makes the missing epoch key and writes the parked events too
        self.assertEqual(len(lines(self.ra, self.tid)), 4)
        self.assertTrue(self.ma.ingest(Writer(self.a, self.t).post("p3")).ok)
        self.assertEqual(len(lines(self.ra, self.tid)), 5)                           # nothing is written twice
        m2 = Mirror(self.ra + "/m", codec=EnvCodec(self.ra + "/keys"), rate_limit=False)
        self.assertEqual(texts(m2, self.tid), ["needle-one", "needle-two", "p3"])

    def test_server_never_serves_it_in_plaintext(self):
        self.assertTrue(self.ma.ingest(self.r).ok)
        srv = Loopback(SyncServer(self.ma, identity=self.a))
        ids = [event_id(self.p1), event_id(self.p2), self.rid]
        resp = srv.request(sign_request(self.b, {"t": "get", "thread": self.tid, "ids": ids}, aud=self.a.id))
        self.assertEqual(resp["t"], "events")
        self.assertNotIn("needle", repr(resp))
        self.assertEqual(len(resp["events"]), 1)                                    # only R (sealed under epoch 0); P1/P2 wait for the key
        self.assertTrue(V.looks_like_envelope(resp["events"][0]))


# ---------------------------------------------------------------- sync: serving, pulling and fetching keys

class Rogue(SyncServer):
    """A server that answers key requests the way a hostile or sloppy peer might: `edit(resp, req)` changes the (re-signed) answer."""
    edit = None
    ignore_ids = False

    def _keys(self, req, t, tid):
        if self.ignore_ids:
            req = {**req, "ids": []}
        resp = super()._keys(req, t, tid)
        if self.edit is not None:
            resp = {k: v for k, v in resp.items() if k not in ("rsig",)}
            self.edit(resp, req)
            resp["rsig"] = self.identity.sign(S.RESP_CTX + canon.dumps(resp))
        return resp


class SyncBase(World):
    def setUp(self):
        super().setUp()
        self.ma.ingest(self.w(self.a).post("p0"))
        self.ma.enable_encryption(self.tid, self.a)
        self.r1 = self.remove(self.a, self.d)
        self.ca.ring(self.tid).create(self.r1, self.a)
        self.ma.ingest(self.w(self.a).post("p1"))
        self.srv = Rogue(self.ma, identity=self.a)
        self.tr = Loopback(self.srv)
        self.rb, self.cb, self.mb = node()
        self.mb.ingest(self.g)

    def pull_b(self, **kw):
        return pull(self.mb, self.tid, self.tr, self.b, peer_id=self.a.id, **kw)

    def fetch(self, need=None, tr=None, m=None, me=None, peer=None, **kw):
        return fetch_keys(m or self.mb, self.tid, tr or self.tr, me or self.b, peer_id=(peer or self.a).id, need=need if need is not None else {self.tid, self.r1}, **kw)

    def keyreq(self, who, ids, tr=None):
        return (tr or self.tr).request(sign_request(who, {"t": "key", "thread": self.tid, "ids": ids}, aud=self.a.id))

    def learn(self):
        """b gets epoch 0's key, reads the removal, so its chain now has epoch R (whose key it does not hold yet)."""
        r = self.pull_b()
        got = self.fetch(need=r["need_keys"], unopened=r["unopened"])
        self.assertEqual(got["installed"], 1, got)
        self.pull_b()
        self.assertEqual(V.chain_epoch_ids(self.mb.threads[self.tid]), [self.tid, self.r1])

    def clone(self, ident, skip=()):
        """A mirror holding the thread as `ma` does (keys copied), minus the events in `skip`."""
        root = tempfile.mkdtemp()
        shutil.copytree(self.ra + "/keys", root + "/keys")
        m = Mirror(root + "/m", codec=EnvCodec(root + "/keys"), rate_limit=False)
        m.ingest(self.g)
        for i in self.t.arrival:
            if i != self.tid and i not in skip:
                self.assertTrue(m.ingest(self.t.stored[i]).ok, i)
        return m


class SyncEnc(SyncBase):
    # ---- client side of a pull
    def test_pull_without_keys_is_complete_but_locked(self):
        r = self.pull_b()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["need_keys"], {self.tid, self.r1})
        self.assertGreaterEqual(len(r["unopened"]), 3)                              # p0, R, p1 (a retry may add copies)
        self.assertEqual(r["rejected"], 0)

    def test_pull_with_a_key_the_server_withholds_is_incomplete(self):
        for i in range(70):
            self.assertTrue(self.ma.ingest(self.w((self.a, self.b, self.c)[i % 3]).post(f"x{i}")).ok)
        ring = self.ca.ring(self.tid)
        d = json.loads(ring.path.read_text())
        del d[self.r1]                                                              # the server lost epoch R's key: it cannot serve what is sealed under it
        ring.path.write_text(json.dumps(d))
        r = self.pull_b()
        self.assertEqual(r["need_keys"], {self.tid})
        self.assertFalse(r["ok"])
        self.assertIn("incomplete", r["why"])

    def test_unopened_envelopes_are_capped(self):
        who = [self.a, self.b, self.c]
        for i in range(70):
            self.assertTrue(self.ma.ingest(self.w(who[i % 3]).post(f"x{i}")).ok)
        r = self.pull_b()
        self.assertEqual(len(r["unopened"]), S.MAX_UNOPENED)

    def test_wrong_key_for_an_epoch_makes_the_envelope_junk_not_a_key_request(self):
        self.learn()
        ring = self.cb.ring(self.tid)
        d = json.loads(ring.path.read_text())
        d[self.tid]["k"] = base64.b64encode(os.urandom(32)).decode()                # a verified key that is not the epoch's key
        ring.path.write_text(json.dumps(d))
        rb = tempfile.mkdtemp()
        shutil.copytree(self.rb + "/keys", rb + "/keys")
        mb2 = Mirror(rb + "/m", codec=EnvCodec(rb + "/keys"), rate_limit=False)
        mb2.ingest(self.g)
        r2 = pull(mb2, self.tid, self.tr, self.b, peer_id=self.a.id)
        self.assertGreater(r2["rejected"], 0)                                       # junk, counted
        self.assertNotIn(self.tid, r2["need_keys"])

    def test_plaintext_event_in_an_encrypted_thread_is_junk_but_the_genesis_is_fine(self):
        class Plain(SyncServer):                                                     # an old server that sends everything raw
            def handle(s, req):
                resp = super().handle(req)
                if resp.get("t") == "events":
                    resp = {k: v for k, v in resp.items() if k != "rsig"}
                    st = s.m.threads[tid_].stored
                    resp["events"] = [st[i] for i in req["ids"] if i in st]
                    resp["rsig"] = s.identity.sign(S.RESP_CTX + canon.dumps(resp))
                return resp
        tid_ = self.tid
        tr = Loopback(Plain(self.ma, identity=self.a))
        self.fetch(need={self.tid})                                                 # b holds a key, so the thread is encrypted for it
        self.assertTrue(self.cb.is_encrypted(self.tid))
        r = pull(self.mb, self.tid, tr, self.b, peer_id=self.a.id)
        self.assertGreater(r["rejected"], 0)
        self.assertEqual(texts(self.mb, self.tid), [])

    def test_a_joiner_with_keys_but_no_thread_still_gets_the_plain_genesis(self):
        self.learn()
        self.fetch(need={self.r1})
        rj = tempfile.mkdtemp()
        shutil.copytree(self.rb + "/keys", rj + "/keys")                           # keys that arrived with the capsule, before the thread
        cj = EnvCodec(rj + "/keys")
        mj = Mirror(rj + "/m", codec=cj, rate_limit=False)
        self.assertTrue(cj.is_encrypted(self.tid))
        self.assertNotIn(self.tid, mj.threads)
        r = pull(mj, self.tid, self.tr, self.b, peer_id=self.a.id)
        self.assertTrue(r["ok"], r)
        self.assertEqual(texts(mj, self.tid), ["p0", "p1"])

    # ---- the serving side
    def test_server_get_seals_each_event_under_its_own_epoch_and_never_plain(self):
        ids = list(self.t.stored)
        resp = self.tr.request(sign_request(self.b, {"t": "get", "thread": self.tid, "ids": ids}, aud=self.a.id))
        env = [x for x in resp["events"] if V.looks_like_envelope(x)]
        self.assertEqual(len(resp["events"]), len(env) + 1)                         # all sealed but the genesis
        self.assertEqual({x["ep"] for x in env}, {self.tid, self.r1})
        ring = self.ca.ring(self.tid)
        for x in env:
            inner = V.open_envelope(ring.get(x["ep"])[0], x, self.tid)
            self.assertEqual(x["ep"], V.epoch_id_at(self.t, inner["admin_ref"]))

    def test_server_response_size_counts_the_envelope_not_the_plain_event(self):
        ids = [i for i in self.t.stored if i != self.tid][:2]
        plain = sum(len(canon.dumps(self.t.stored[i])) for i in ids)
        old = S.MAX_RESPONSE_BYTES
        S.MAX_RESPONSE_BYTES = plain + 1                                            # the envelopes (padded, base64) are bigger than the plain events
        try:
            resp = self.tr.request(sign_request(self.b, {"t": "get", "thread": self.tid, "ids": ids}, aud=self.a.id))
        finally:
            S.MAX_RESPONSE_BYTES = old
        self.assertEqual(len(resp["events"]), 1)
        self.assertEqual(len(resp["more"]), 1)

    def test_key_answer_serves_only_current_members_verified_chain_keys(self):
        resp = self.keyreq(self.b, [])
        self.assertEqual(resp["t"], "keys")
        self.assertEqual([k["id"] for k in resp["keys"]], [self.tid, self.r1])
        for k in resp["keys"]:
            self.assertIsNotNone(k["conf"])                                         # the confirmation travels with the key
        self.assertEqual([k["id"] for k in self.keyreq(self.b, [self.r1])["keys"]], [self.r1])
        self.assertEqual(self.keyreq(self.d, [])["t"], "unknown")                   # removed
        self.assertEqual(self.keyreq(Identity.generate("z"), [])["t"], "unknown")   # stranger

    def test_key_answer_ignores_unverified_and_off_chain_keys(self):
        ring = self.ca.ring(self.tid)
        d = json.loads(ring.path.read_text())
        d[self.r1]["ok"] = False
        d["ee" * 16] = {"k": base64.b64encode(os.urandom(32)).decode(), "ok": True, "c": None}      # a verified key of an abandoned branch
        ring.path.write_text(json.dumps(d))
        self.assertEqual([k["id"] for k in self.keyreq(self.b, [])["keys"]], [self.tid])

    def test_key_request_shape_is_checked(self):
        self.assertEqual(self.keyreq(self.b, {})["t"], "unknown")
        self.assertEqual(self.keyreq(self.b, "abc")["t"], "unknown")
        self.assertEqual(self.keyreq(self.b, ["ab" * 16] * (S.MAX_IDS + 1))["t"], "unknown")
        self.assertEqual(self.keyreq(self.b, ["ab" * 16] * S.MAX_IDS)["t"], "keys")
        self.assertEqual(self.keyreq(self.b, ["zz"])["t"], "unknown")

    def test_public_thread_is_never_sealed_even_with_a_stray_keyring(self):
        rp, cp, mp = node()
        g = make_genesis(self.a, "pub", [(self.b, "member")], visibility="public")
        mp.ingest(g)
        pid = event_id(g)
        cp.ring(pid).create(pid, self.a)
        cp.mark(pid)                                                                # a keyring and a marker for a public thread: not our doing, but it must not break readers
        self.assertTrue(mp.ingest(Writer(self.a, mp.threads[pid]).post("open words")).ok)
        tr = Loopback(SyncServer(mp, identity=self.a))
        ids = list(mp.threads[pid].stored)
        resp = tr.request(sign_request(self.b, {"t": "get", "thread": pid, "ids": ids}, aud=self.a.id))
        self.assertEqual(len(resp["events"]), len(ids))
        for x in resp["events"]:
            self.assertIn("kind", x)                                                # plain signed events
        self.assertEqual(tr.request(sign_request(self.b, {"t": "key", "thread": pid, "ids": []}, aud=self.a.id))["t"], "unknown")

    def test_guest_gets_no_keys_and_a_plain_thread_none_either(self):
        gst = Identity.generate("g")
        self.assertTrue(self.ma.ingest(self.w(self.a).add_member(gst, "guest")).ok)
        self.assertEqual(self.keyreq(gst, [])["t"], "unknown")
        rp, cp, mp = node()                                                         # a thread that is not encrypted: nothing to hand out
        g2 = make_genesis(self.a, "plain", [(self.b, "member")])
        mp.ingest(g2)
        tr = Loopback(SyncServer(mp, identity=self.a))
        resp = tr.request(sign_request(self.b, {"t": "key", "thread": event_id(g2), "ids": []}, aud=self.a.id))
        self.assertEqual(resp["t"], "unknown")

    # ---- fetch_keys
    def test_fetch_keys_happy_path_and_idempotence(self):
        r = self.pull_b()
        got = self.fetch(need=r["need_keys"], unopened=r["unopened"])
        self.assertEqual((got["ok"], got["installed"], got["rejected"]), (True, 1, 1))     # R is not on our chain until we can read the removal
        self.assertTrue(self.cb._marker(self.tid).exists())
        self.assertEqual(self.cb._marker(self.tid).read_bytes(), b"")               # finalised, not "migrating"
        ring = self.cb.ring(self.tid)
        self.assertTrue(ring.get(self.tid)[1])
        self.assertEqual(ring.conf(self.tid), self.ca.ring(self.tid).conf(self.tid))
        again = self.fetch(need={self.tid})
        self.assertEqual((again["ok"], again["installed"]), (True, 0))              # nothing new
        r = self.pull_b()
        self.assertEqual(r["need_keys"], {self.r1})
        got = self.fetch(need=r["need_keys"], unopened=r["unopened"])
        self.assertEqual((got["installed"], got["rejected"]), (1, 0))
        self.assertEqual(ring.conf(self.r1), self.ca.ring(self.tid).conf(self.r1))
        self.assertTrue(self.pull_b()["ok"])
        self.assertEqual(texts(self.mb, self.tid), ["p0", "p1"])

    def test_fetch_keys_asks_for_nothing_it_does_not_need(self):
        calls = []
        tr_ = self.tr

        class Spy:
            def request(s, q):
                calls.append(q)
                return tr_.request(q)
        for need in ([], set(), ["zz"], [5, None]):
            got = self.fetch(need=need, tr=Spy())
            self.assertFalse(got["ok"])
            self.assertEqual(got["why"], "nothing to ask for")
        self.assertEqual(calls, [])
        got = fetch_keys(Mirror(tempfile.mkdtemp(), codec=EnvCodec(tempfile.mkdtemp())), self.tid, Spy(), self.b, peer_id=self.a.id, need={self.tid})
        self.assertFalse(got["ok"])
        self.assertEqual(calls, [])

    def test_replayed_answer_is_refused(self):
        saved = []
        tr_ = self.tr

        class Replay:
            def request(s, q):
                if not saved:
                    saved.append(tr_.request(q))
                return saved[0]
        tr = Replay()
        self.assertTrue(self.fetch(tr=tr)["ok"])
        got = self.fetch(tr=tr)                                                     # the old answer carries the old nonce
        self.assertFalse(got["ok"])
        self.assertIn("not signed by the peer", got["why"])

    def test_answer_must_be_a_response_for_this_thread_with_few_keys(self):
        def mk(**ch):
            return lambda resp, req: resp.update(ch)
        self.srv.edit = mk(r=2)
        self.assertEqual((self.fetch()["ok"], self.mb.codec.ring(self.tid).ids()), (False, []))
        self.srv.edit = mk(thread="ab" * 16)
        self.assertEqual((self.fetch()["ok"], self.mb.codec.ring(self.tid).ids()), (False, []))

        def many(resp, req):
            resp["keys"] = resp["keys"] * (S.MAX_IDS + 1)
        self.srv.edit = many
        got = self.fetch()
        self.assertEqual((got["ok"], got["installed"]), (False, 0))
        self.assertEqual(self.mb.codec.ring(self.tid).ids(), [])
        self.srv.edit = None
        self.assertTrue(self.fetch()["ok"])

    def test_only_requested_chain_keys_are_installed(self):
        self.learn()
        d = json.loads(self.cb.ring(self.tid).path.read_text())
        del d[self.tid]                                                             # forget epoch 0's key; ask only for R's
        self.cb.ring(self.tid).path.write_text(json.dumps(d))
        self.srv.ignore_ids = True                                                  # the peer sends both although we asked for one
        got = self.fetch(need={self.r1})
        self.assertEqual((got["ok"], got["installed"], got["rejected"]), (True, 1, 1))
        self.assertEqual(self.cb.ring(self.tid).ids(), [self.r1])

    def test_garbage_and_off_chain_keys_are_rejected_and_counted(self):
        self.learn()

        def junk(resp, req):
            resp["keys"] = resp["keys"] + [{"id": self.tid, "sealed": {"e": "00" * 32, "n": "AAAA", "c": "AAAA"}}, {"id": "ee" * 16, "sealed": {}}, "junk"]
        self.srv.edit = junk
        got = self.fetch(need={self.tid, self.r1, "ee" * 16})
        self.assertEqual((got["ok"], got["installed"], got["rejected"]), (True, 1, 3))

    def test_confirmation_is_required(self):
        self.learn()

        def strip(resp, req):
            for k in resp["keys"]:
                k["conf"] = None
        self.srv.edit = strip
        got = self.fetch(need={self.r1})
        self.assertEqual((got["ok"], got["installed"], got["rejected"]), (True, 0, 1))
        self.assertEqual(self.cb.ring(self.tid).ids(), [self.tid])

    def keyless_b(self):
        m = self.clone(self.b)
        shutil.rmtree(m.codec.dir)                                                  # b holds no keys
        m.codec = EnvCodec(m.codec.dir)
        return m

    def test_the_peer_must_be_a_current_member_in_our_state(self):
        rm = self.remove(self.a, self.c)                                            # b learns that c was removed ...
        stale = Loopback(SyncServer(self.clone(self.c, skip={rm}), identity=self.c))        # ... c's own mirror never saw it, and still answers
        mb2 = self.keyless_b()
        got = fetch_keys(mb2, self.tid, stale, self.b, peer_id=self.c.id, need={self.tid, self.r1})
        self.assertFalse(got["ok"])
        self.assertIn("not a member", got["why"])
        self.assertEqual(mb2.codec.ring(self.tid).ids(), [])
        ok = fetch_keys(mb2, self.tid, Loopback(SyncServer(self.clone(self.a), identity=self.a)), self.b, peer_id=self.a.id, need={self.tid, self.r1})
        self.assertEqual((ok["ok"], ok["installed"]), (True, 2))

    def test_a_guest_peer_is_not_trusted_with_keys(self):
        gst = Identity.generate("g")
        self.assertTrue(self.ma.ingest(self.w(self.a).add_member(gst, "guest")).ok)
        tr = Loopback(SyncServer(self.clone(gst), identity=gst))
        mb2 = self.keyless_b()
        got = fetch_keys(mb2, self.tid, tr, self.b, peer_id=gst.id, need={self.tid, self.r1})
        self.assertFalse(got["ok"])
        self.assertIn("not a member", got["why"])


# ---------------------------------------------------------------- capsule: keys in the owner's answer

from sigilnet import capsule as CAP                                    # noqa: E402
from sigilnet.tests import test_capsule_enc as TCE                     # noqa: E402


class CapsuleKeys(unittest.TestCase):
    def setUp(self):
        TCE.EncJoin.setUp(self)                                              # an owner with an encrypted thread, a joiner, a JoinServer (no network)
        self.t = self.om.threads[self.tid]
        self.rec = {"thread": self.tid, "enc": True, "req": {"kex": self.joiner.kex_pub, "agent": self.joiner.id}}

    def two_epochs(self):
        ev = Writer(self.owner, self.t).admin("member_remove", {"agent": [m for m in self.t.state()["members"] if m != self.owner.id][0]})
        self.assertTrue(self.om.ingest(ev).ok)
        self.r1 = event_id(ev)
        self.ocodec.ring(self.tid).create(self.r1, self.owner)

    def answer(self, kids=None, **over):
        ring = self.ocodec.ring(self.tid)
        out = []
        for kid in kids or ring.ids():
            got = ring.get(kid)
            out.append({"id": kid, "sealed": V.seal_key(self.joiner.kex_pub, self.joiner.id, self.tid, kid, got[0]), "conf": ring.conf(kid)})
        return out

    def test_sealed_keys_cover_exactly_the_verified_chain_epochs_with_confirmations(self):
        self.two_epochs()
        ring = self.ocodec.ring(self.tid)
        out = self.server._sealed_keys(self.rec)
        self.assertEqual([k["id"] for k in out], [self.tid, self.r1])               # all chain epochs, oldest first (a joiner reads the whole history)
        for k in out:
            key = V.open_key(self.joiner, self.tid, k["id"], k["sealed"])
            self.assertEqual(key, ring.get(k["id"])[0])
            self.assertEqual(k["conf"], ring.conf(k["id"]))
            self.assertIsNotNone(k["conf"])
        d = json.loads(ring.path.read_text())
        d["ee" * 16] = {"k": base64.b64encode(os.urandom(32)).decode(), "ok": True, "c": None}      # an abandoned branch's key
        d[self.r1]["ok"] = False
        ring.path.write_text(json.dumps(d))
        self.assertEqual([k["id"] for k in self.server._sealed_keys(self.rec)], [self.tid])
        d = {k: v for k, v in d.items() if k == "ee" * 16}
        ring.path.write_text(json.dumps(d))
        self.assertIsNone(self.server._sealed_keys(self.rec))                       # an encrypted thread is never answered without keys

    def test_sealed_keys_for_plain_or_unknown_threads_are_empty(self):
        self.assertEqual(self.server._sealed_keys({**self.rec, "thread": "ab" * 16}), [])
        plain = Mirror(tempfile.mkdtemp(), codec=EnvCodec(tempfile.mkdtemp()), rate_limit=False)
        g = make_genesis(self.owner, "plain", [])
        plain.ingest(g)
        srv = CAP.JoinServer(self.oh, self.otor, self.owner, plain, self.clock)
        self.assertEqual(srv._sealed_keys({**self.rec, "thread": event_id(g)}), [])

    def test_sealed_keys_are_sealed_to_the_joiner_agent_id(self):
        out = self.server._sealed_keys(self.rec)
        other = Identity.generate("o")
        with self.assertRaises(V.EnvelopeError):
            V.open_key(other, self.tid, out[0]["id"], out[0]["sealed"])
        k = out[0]
        s = V.seal_key(self.joiner.kex_pub, "0" * 32, self.tid, k["id"], os.urandom(32))
        with self.assertRaises(V.EnvelopeError):
            V.open_key(self.joiner, self.tid, k["id"], s)                           # sealed for another agent id: does not open

    def test_capsule_enc_flag_must_be_a_boolean(self):
        block, cid, _ = CAP.create(self.oh, self.otor, self.owner, self.om, self.tid, clock=self.clock, wait_address=self.ofake)
        c = CAP.decode_capsule(block, now=self.clock())
        self.assertIs(c["enc"], True)
        for bad in (1, "yes", None, 0):
            with self.assertRaises(Exception) as cm:
                CAP.decode_capsule(CAP.encode_capsule({**c, "enc": bad}), now=self.clock())
            self.assertIsInstance(cm.exception, (ValueError, CAP.CapsuleError))

    def test_install_keys_refusals(self):
        jc = EnvCodec(tempfile.mkdtemp())
        good = self.answer()
        self.assertIsNone(CAP._install_keys({"keys": good}, {"thread": self.tid, "enc": True}, self.joiner, jc))
        for bad in ([], None, {}, "abc", 5):
            jc2 = EnvCodec(tempfile.mkdtemp())
            self.assertIsInstance(CAP._install_keys({"keys": bad}, {"thread": self.tid, "enc": True}, self.joiner, jc2), str, bad)
        jc3 = EnvCodec(tempfile.mkdtemp())
        self.assertIsNone(CAP._install_keys({"keys": []}, {"thread": self.tid, "enc": False}, self.joiner, jc3))      # plaintext thread, no keys: fine
        self.assertFalse(jc3.is_encrypted(self.tid))
        self.assertIsInstance(CAP._install_keys({"keys": good * 65}, {"thread": self.tid, "enc": True}, self.joiner, EnvCodec(tempfile.mkdtemp())), str)
        self.assertIsNone(CAP._install_keys({"keys": good * 64}, {"thread": self.tid, "enc": True}, self.joiner, EnvCodec(tempfile.mkdtemp())))
        for codec in (None, __import__("sigilnet.envelope", fromlist=["PlainCodec"]).PlainCodec()):
            self.assertIsInstance(CAP._install_keys({"keys": good}, {"thread": self.tid, "enc": True}, self.joiner, codec), str)

    def test_install_keys_all_or_nothing_and_malformed_entries(self):
        for bad in ({"id": self.tid}, {"sealed": {}}, {"id": self.tid, "sealed": {"e": "00" * 32, "n": "AAAA", "c": "AAAA"}}, "junk", None):
            jc = EnvCodec(tempfile.mkdtemp())
            self.assertIsInstance(CAP._install_keys({"keys": self.answer() + [bad]}, {"thread": self.tid, "enc": False}, self.joiner, jc), str, bad)
            self.assertEqual(jc.ring(self.tid).ids(), [])                           # nothing was installed, nothing marked
            self.assertFalse(jc._marker(self.tid).exists())

    def test_install_keys_installs_verified_with_confirmation_and_marks_encrypted_even_if_capsule_said_plain(self):
        self.two_epochs()
        jc = EnvCodec(tempfile.mkdtemp())
        self.assertIsNone(CAP._install_keys({"keys": self.answer()}, {"thread": self.tid, "enc": False}, self.joiner, jc))     # keys in the answer win over enc=false
        ring, oring = jc.ring(self.tid), self.ocodec.ring(self.tid)
        self.assertEqual(ring.ids(), sorted([self.tid, self.r1]))
        for kid in ring.ids():
            self.assertEqual(ring.get(kid), oring.get(kid))                        # (key, verified=True)
            self.assertEqual(ring.conf(kid), oring.conf(kid))
        self.assertTrue(jc._marker(self.tid).exists())
        self.assertEqual(jc._marker(self.tid).read_bytes(), b"")
        self.assertFalse(jc.migrating(self.tid))


# ---------------------------------------------------------------- node: key rounds

import random                                                           # noqa: E402
from sigilnet import node as NODE                                        # noqa: E402


class NodeKeyRounds(SyncBase):
    def node_b(self, server=None):
        home = Path(tempfile.mkdtemp())
        tr = Loopback(server or self.srv)
        self.nd = NODE.Node(self.mb, self.b, NODE.PeerBook(home / "peers.json"), home / "node.json", lambda rec: tr, clock=__import__("time").time, rng=random.Random(1), pull_interval=300.0)
        self.key = f"{self.a.id}/{self.tid}/pull"

    def run_pull(self):
        self.nd._run(self.a.id, self.tid, "pull", {"rec": {}, "threads": {self.tid}})
        return self.nd.jobs[self.key]

    def test_each_key_round_can_reveal_the_next_epoch(self):
        self.node_b()
        j = self.run_pull()
        self.assertEqual(j["err"], "")
        self.assertEqual(texts(self.mb, self.tid), ["p0", "p1"])                    # epoch 0's key opens the removal, which reveals epoch 1: a second round
        self.assertEqual(self.mb.codec.ring(self.tid).ids(), sorted([self.tid, self.r1]))

    def test_peer_that_gives_no_keys_is_a_retryable_failure(self):
        def empty(resp, req):
            resp["keys"] = []
        self.srv.edit = empty
        self.node_b()
        j = self.run_pull()
        self.assertIn("need keys the peer did not give", j["err"])
        self.assertEqual(j["tries"], 1)
        self.assertFalse(j["blocked"])                                              # retry later, not blocked for good
        self.assertIsNone(j["ok"])
        self.assertEqual(texts(self.mb, self.tid), [])


# ---------------------------------------------------------------- cli: new / remove / envelope enable|rotate|status

from sigilnet.tests import test_cli_public as TCP                       # noqa: E402


class CliBase(unittest.TestCase):
    def setUp(self):
        self.h = {n: tempfile.mkdtemp() for n in ("arya", "bob", "carol", "dave")}
        self.id = {}
        for n, home in self.h.items():
            TCP.run(home, "id", "init", n)
            out = TCP.run(home, "id", "show", "--json")[1]
            Path(home, "pub.json").write_text(out)
            self.id[n] = json.loads(out)["agent"]

    def new(self, *extra, title="t"):
        rc, out, err = TCP.run(self.h["arya"], "new", title, "--member", f"admin={self.h['bob']}/pub.json", "--member", f"member={self.h['carol']}/pub.json",
                               "--member", f"member={self.h['dave']}/pub.json", *extra)
        self.assertEqual(rc, 0, (out, err))
        self.tid = out.split("thread ")[1].split()[0]
        return out

    def ring(self, who):
        return Keyring(Path(self.h[who]) / "keys", self.tid)

    def thread(self, who):
        m = Mirror(Path(self.h[who]) / "mirror", codec=EnvCodec(Path(self.h[who]) / "keys"), rate_limit=False)
        return m, m.threads[self.tid]

    def sync_homes(self, src, dst):
        for d in ("mirror", "keys"):
            shutil.rmtree(Path(self.h[dst]) / d, ignore_errors=True)
            shutil.copytree(Path(self.h[src]) / d, Path(self.h[dst]) / d)

    def edit_ring(self, who, fn):
        r = self.ring(who)
        d = json.loads(r.path.read_text())
        fn(d)
        r.path.write_text(json.dumps(d))

    def confirmed(self, who, kid):
        m, t = self.thread(who)
        got, conf = self.ring(who).get(kid), self.ring(who).conf(kid)
        return got is not None and conf is not None and V.check_confirmation(t, kid, got[0], conf)


class CliEnvelope(CliBase):
    # ---- new / enable / remove
    def test_new_encrypts_with_confirmed_keys_and_plaintext_flag_is_respected(self):
        out = self.new()
        self.assertIn("encrypted:", out)
        self.assertTrue(self.confirmed("arya", self.tid))
        self.assertIn("ENCRYPTED", TCP.run(self.h["arya"], "envelope", "status")[1])
        plain_home = self.h["arya"]
        rc, out, err = TCP.run(plain_home, "new", "p", "--plaintext")
        pid = out.split("thread ")[1].split()[0]
        self.assertNotIn("encrypted:", out)
        self.assertFalse((Path(plain_home) / "keys" / f"{pid}.json").exists())
        self.assertFalse((Path(plain_home) / "keys" / f"{pid}.enc").exists())
        self.assertIn("PLAINTEXT", TCP.run(plain_home, "envelope", "status")[1])
        for _ in range(3):                                                          # the same genesis again (same second): refused as a duplicate, and NOT encrypted behind our back
            rc, out, err = TCP.run(plain_home, "new", "p")
            if rc != 0:
                self.assertIn("duplicate", out)
                self.assertFalse((Path(plain_home) / "keys" / f"{pid}.json").exists())
                break
        rc, out, err = TCP.run(plain_home, "new", "pub", "--public")
        pub = out.split("thread ")[1].split()[0]
        self.assertFalse((Path(plain_home) / "keys" / f"{pub}.json").exists())

    def test_envelope_enable_confirms_the_keys(self):
        self.new("--plaintext")
        self.assertFalse(self.ring("arya").exists())
        rc, out, err = TCP.run(self.h["arya"], "envelope", "enable", self.tid[:8])
        self.assertEqual(rc, 0, (out, err))
        self.assertTrue(self.confirmed("arya", self.tid))

    def test_remove_makes_a_confirmed_epoch_key_only_for_encrypted_threads(self):
        self.new("--plaintext")
        rc, out, err = TCP.run(self.h["arya"], "remove", self.tid[:8], self.id["carol"])
        self.assertEqual(rc, 0, (out, err))
        self.assertNotIn("new epoch key", out)
        self.assertFalse(self.ring("arya").exists())                                # a plaintext thread must not grow a keyring (that would make it "encrypted")
        self.assertFalse(Path(self.h["arya"], "keys", f"{self.tid}.enc").exists())
        self.new(title="second")
        rc, out, err = TCP.run(self.h["arya"], "remove", self.tid[:8], self.id["carol"])
        self.assertIn("new epoch key created", out)
        m, t = self.thread("arya")
        r1 = V.chain_epoch_ids(t)[-1]
        self.assertNotEqual(r1, self.tid)
        self.assertTrue(self.confirmed("arya", r1))
        before = self.ring("arya").ids()
        rc, out, err = TCP.run(self.h["arya"], "remove", self.tid[:8], self.id["carol"])     # already removed: refused, no key made
        self.assertEqual(self.ring("arya").ids(), before)

    # ---- rotate
    def removal_by_bob(self):
        self.new()
        TCP.run(self.h["arya"], "post", self.tid[:8], "hello")
        self.sync_homes("arya", "bob")
        rc, out, err = TCP.run(self.h["bob"], "remove", self.tid[:8], self.id["carol"])
        self.assertEqual(rc, 0, (out, err))
        m, t = self.thread("bob")
        self.r1 = V.chain_epoch_ids(t)[-1]
        self.assertTrue(self.confirmed("bob", self.r1))
        self.sync_homes("bob", "arya")                                              # the owner now holds the removal but not its key
        self.edit_ring("arya", lambda d: d.pop(self.r1))
        self.assertEqual(self.ring("arya").ids(), [self.tid])

    def test_rotate_only_the_author_makes_the_key_unless_an_owner_or_admin_adopts(self):
        self.removal_by_bob()
        rc, out, err = TCP.run(self.h["arya"], "envelope", "rotate", self.tid[:8])
        self.assertIn("none missing", out)
        self.assertEqual(self.ring("arya").ids(), [self.tid])                       # arya is not the removal's author
        self.sync_homes("arya", "dave")
        rc, out, err = TCP.run(self.h["dave"], "envelope", "rotate", self.tid[:8], "--adopt")
        self.assertIn("none missing", out)                                          # a plain member cannot adopt
        self.assertNotIn("warning", out)
        self.assertEqual(self.ring("dave").ids(), [self.tid])
        rc, out, err = TCP.run(self.h["arya"], "envelope", "rotate", self.tid[:8], "--adopt")
        self.assertIn(self.r1[:8], out)
        self.assertIn("warning", out)
        self.assertEqual(self.ring("arya").ids(), sorted([self.tid, self.r1]))      # only chain epochs, never the ids of ordinary events
        self.assertTrue(self.confirmed("arya", self.r1))
        rc, out, err = TCP.run(self.h["arya"], "envelope", "rotate", self.tid[:8], "--adopt")
        self.assertIn("none missing", out)
        self.assertNotIn("warning", out)

    def test_rotate_by_the_author_recreates_a_lost_key_confirmed(self):
        self.removal_by_bob()
        self.edit_ring("bob", lambda d: d.pop(self.r1))
        rc, out, err = TCP.run(self.h["bob"], "envelope", "rotate", self.tid[:8])
        self.assertIn(self.r1[:8], out)
        self.assertNotIn("warning", out)
        self.assertTrue(self.confirmed("bob", self.r1))
        self.assertEqual(self.ring("bob").ids(), sorted([self.tid, self.r1]))

    def test_rotate_never_makes_the_genesis_key_and_never_replaces_an_existing_key(self):
        self.removal_by_bob()
        self.edit_ring("arya", lambda d: d.pop(self.tid))
        self.ring("arya").install(self.r1, os.urandom(32), verified=True)           # some key for epoch 1 (arya is not its author)
        mine = self.ring("arya").get(self.r1)
        rc, out, err = TCP.run(self.h["arya"], "envelope", "rotate", self.tid[:8], "--adopt")
        self.assertIn("none missing", out)
        self.assertEqual(self.ring("arya").get(self.r1), mine)
        self.assertNotIn(self.tid, self.ring("arya").ids())

    # ---- status
    def test_status_reports_key_state_skipped_lines_and_locked_threads(self):
        self.new()
        TCP.run(self.h["arya"], "remove", self.tid[:8], self.id["carol"])
        TCP.run(self.h["arya"], "post", self.tid[:8], "after the removal")
        m, t = self.thread("arya")
        r1 = V.chain_epoch_ids(t)[-1]
        out = TCP.run(self.h["arya"], "envelope", "status", self.tid[:8])[1]
        self.assertIn("epoch 0 (genesis)  key: verified", out)
        self.assertIn(f"{r1[:8]}  removal  key: verified", out)
        self.assertIn(": 0\n", out)
        self.edit_ring("arya", lambda d: d[r1].update(ok=False))
        self.assertIn(f"{r1[:8]}  removal  key: UNVERIFIED", TCP.run(self.h["arya"], "envelope", "status", self.tid[:8])[1])
        self.edit_ring("arya", lambda d: d.pop(r1))
        out = TCP.run(self.h["arya"], "envelope", "status", self.tid[:8])[1]
        self.assertIn(f"{r1[:8]}  removal  key: MISSING", out)
        self.assertIn("lines skipped on load (missing keys or damage): 1", out)     # the post sealed under the key we no longer hold
        os.unlink(self.ring("arya").path)
        out = TCP.run(self.h["arya"], "envelope", "status")[1]
        self.assertIn(f"{self.tid[:8]}  LOCKED", out)


# ---------------------------------------------------------------- cli: sync pull of an encrypted thread (key rounds)

from sigilnet.tcp import TcpServer                                       # noqa: E402


class CliSyncPull(CliBase):
    def setUp(self):
        super().setUp()
        self.new()
        a = self.h["arya"]
        TCP.run(a, "post", self.tid[:8], "p0")
        TCP.run(a, "remove", self.tid[:8], self.id["carol"])                # epoch 1: its key can only be asked for after the removal has been read
        TCP.run(a, "post", self.tid[:8], "p1")
        self.keyf = Path(a) / "sync.key"
        self.assertEqual(TCP.run(a, "key", "new")[0], 0)
        shutil.copy(self.keyf, Path(self.h["bob"]) / "sync.key")
        os.chmod(Path(self.h["bob"]) / "sync.key", 0o600)

    def serve(self, cls=SyncServer, **attrs):
        a = self.h["arya"]
        m = Mirror(Path(a) / "mirror", codec=EnvCodec(Path(a) / "keys"), rate_limit=False)
        srv = cls(m, identity=Identity.load(Path(a) / "identity.json"))
        for k, v in attrs.items():
            setattr(srv, k, v)
        ts = TcpServer("127.0.0.1", 0, self.keyf.read_text().strip(), srv.handle).start()
        self.addCleanup(ts.stop)
        return ts

    def pull(self, ts, *extra):
        return TCP.run(self.h["bob"], "sync", "pull", f"127.0.0.1:{ts.port}", "--thread", self.tid, "--deadline", "30", *extra)

    def test_pull_takes_a_key_round_per_epoch_and_reads_everything(self):
        ts = self.serve()
        rc, out, err = self.pull(ts, "--peer-id", self.id["arya"])
        self.assertEqual(rc, 0, (out, err))
        self.assertNotIn("FAILED", out)
        shown = TCP.run(self.h["bob"], "show", self.tid[:8])[1]
        self.assertIn("p0", shown)
        self.assertIn("p1", shown)
        self.assertEqual(len(self.ring("bob").ids()), 2)

    def test_pull_of_an_encrypted_thread_needs_the_peer_id(self):
        ts = self.serve()
        rc, out, err = self.pull(ts)
        self.assertEqual(rc, 1, (out, err))
        self.assertIn("pass --peer-id", out)
        self.assertEqual(self.ring("bob").ids(), [])

    def test_pull_fails_when_the_peer_gives_no_keys(self):
        def empty(resp, req):
            resp["keys"] = []
        ts = self.serve(Rogue, edit=empty)
        rc, out, err = self.pull(ts, "--peer-id", self.id["arya"])
        self.assertEqual(rc, 1, (out, err))
        self.assertIn("keys not obtained", out)
        self.assertEqual(self.ring("bob").ids(), [])
