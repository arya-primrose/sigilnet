import json
import os
import stat
import tempfile
import unittest

from sigilnet import canon, envelope as V
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.tests.util import World

T, K = "a" * 32, b"k" * 32


class SealOpen(unittest.TestCase):
    def test_roundtrip_and_padding_buckets(self):
        ev = {"a": 1, "b": "x" * 10}
        env = V.seal_event(K, T, "b" * 32, ev)
        self.assertEqual(V.open_envelope(K, env, T), ev)
        for n in (0, 1, 200, 251, 252, 253, 500, 5000):
            e = V.seal_event(K, T, "b" * 32, {"t": "x" * n})
            self.assertEqual(len(V._unb64(e["c"])) % V.BUCKET, 16)             # bucket + 16-byte tag
            self.assertEqual(V.open_envelope(K, e, T), {"t": "x" * n})

    def test_same_bucket_same_length(self):
        a = V.seal_event(K, T, "b" * 32, {"t": "x" * 10})
        b = V.seal_event(K, T, "b" * 32, {"t": "y" * 100})
        self.assertEqual(len(V._unb64(a["c"])), len(V._unb64(b["c"])))

    def test_wrong_key_thread_epoch_fail(self):
        env = V.seal_event(K, T, "b" * 32, {"a": 1})
        for key, tid, mut in ((b"x" * 32, T, None), (K, "c" * 32, None), (K, T, {"ep": "d" * 32}), (K, T, {"th": "c" * 32})):
            e = {**env, **(mut or {})}
            with self.assertRaises(V.EnvelopeError):
                V.open_envelope(key, e, tid)

    def test_damage_fails(self):
        env = V.seal_event(K, T, "b" * 32, {"a": 1})
        raw = bytearray(V._unb64(env["c"]))
        for i in (0, len(raw) // 2, len(raw) - 1):
            r = bytearray(raw)
            r[i] ^= 1
            with self.assertRaises(V.EnvelopeError):
                V.open_envelope(K, {**env, "c": V._b64(bytes(r))}, T)
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(K, {**env, "c": V._b64(bytes(raw[:-1]))}, T)
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(K, {**env, "n": V._b64(os.urandom(12))}, T)

    def test_shapes_refused(self):
        env = V.seal_event(K, T, "b" * 32, {"a": 1})
        for bad in (None, [], "x", {}, {**env, "v": 2}, {**env, "x": 1}, {k: v for k, v in env.items() if k != "n"}, {**env, "c": 5}, {**env, "n": "!!"}, {**env, "ep": "zz"},
                    {**env, "c": "A" * 10 ** 6}):
            with self.assertRaises(V.EnvelopeError, msg=str(bad)[:40]):
                V.open_envelope(K, bad, T)
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(b"short", env, T)
        with self.assertRaises(V.EnvelopeError):
            V.seal_event(b"short", T, "b" * 32, {})

    def test_bad_padding_refused(self):
        # an authentic ciphertext whose plaintext has non-zero padding or a lying length must not open
        import struct
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        for plain in (struct.pack(">I", 5) + b"{}" + b"\0" * 250, struct.pack(">I", 2) + b"{}" + b"\1" + b"\0" * 249, b"\0\0\0\2{}" + b"\0" * 10):
            n = os.urandom(12)
            c = ChaCha20Poly1305(K).encrypt(n, plain, V._aad(T, "b" * 32))
            with self.assertRaises(V.EnvelopeError):
                V.open_envelope(K, {"v": 1, "th": T, "ep": "b" * 32, "n": V._b64(n), "c": V._b64(c)}, T)

    def test_inside_must_be_canonical_json(self):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        n = os.urandom(12)
        c = ChaCha20Poly1305(K).encrypt(n, V._pad(b'{"b": 1, "a": 2}'), V._aad(T, "b" * 32))        # not canonical (space, order)
        with self.assertRaises(V.EnvelopeError):
            V.open_envelope(K, {"v": 1, "th": T, "ep": "b" * 32, "n": V._b64(n), "c": V._b64(c)}, T)

    def test_too_large_refused(self):
        with self.assertRaises(V.EnvelopeError):
            V.seal_event(K, T, "b" * 32, {"t": "x" * (V.MAX_ENV_PLAIN + 10)})

    def test_nonces_differ(self):
        self.assertNotEqual(V.seal_event(K, T, "b" * 32, {})["n"], V.seal_event(K, T, "b" * 32, {})["n"])


class Sealing(unittest.TestCase):
    def test_key_sealed_to_one_recipient(self):
        a, b = Identity.generate("a"), Identity.generate("b")
        s = V.seal_key(a.kex_pub, a.id, T, "b" * 32, K)
        self.assertEqual(V.open_key(a, T, "b" * 32, s), K)
        for me, tid, kid in ((b, T, "b" * 32), (a, "c" * 32, "b" * 32), (a, T, "d" * 32)):
            with self.assertRaises(V.EnvelopeError):
                V.open_key(me, tid, kid, s)

    def test_bound_to_recipient_id(self):
        a = Identity.generate("a")
        s = V.seal_key(a.kex_pub, "x" * 32, T, "b" * 32, K)            # sealed for a different id with a's kex key
        with self.assertRaises(V.EnvelopeError):
            V.open_key(a, T, "b" * 32, s)

    def test_hostile_sealed_blobs(self):
        a = Identity.generate("a")
        s = V.seal_key(a.kex_pub, a.id, T, "b" * 32, K)
        for bad in (None, {}, {**s, "e": "00" * 32}, {**s, "e": "zz"}, {**s, "c": V._b64(b"x" * 10)}, {**s, "n": "A"}, {**s, "extra": 1}, []):
            with self.assertRaises(V.EnvelopeError, msg=str(bad)[:40]):
                V.open_key(a, T, "b" * 32, bad)
        with self.assertRaises(V.EnvelopeError):
            V.seal_key("00" * 32, a.id, T, "b" * 32, K)             # a low-order kex key
        with self.assertRaises(V.EnvelopeError):
            V.seal_key(a.kex_pub, a.id, T, "b" * 32, b"short")


class Ring(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.r = V.Keyring(self.d + "/keys", T)

    def test_create_get_idempotent_and_modes(self):
        k = self.r.create("b" * 32)
        self.assertEqual(self.r.create("b" * 32), k)
        self.assertEqual(self.r.get("b" * 32), (k, True))
        self.assertEqual(stat.S_IMODE(os.stat(self.r.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.d + "/keys").st_mode), 0o700)
        self.assertIsNone(self.r.get("c" * 32))

    def test_install_rules(self):
        self.assertTrue(self.r.install("b" * 32, K))
        self.assertEqual(self.r.get("b" * 32), (K, False))
        self.assertTrue(self.r.install("b" * 32, b"j" * 32))                # an unverified key is replaceable
        self.assertEqual(self.r.get("b" * 32), (b"j" * 32, False))
        self.r.mark_verified("b" * 32)
        self.assertFalse(self.r.install("b" * 32, b"z" * 32, verified=True))       # a verified key is never overwritten
        self.assertEqual(self.r.get("b" * 32), (b"j" * 32, True))
        with self.assertRaises(V.EnvelopeError):
            self.r.install("zz", K)
        with self.assertRaises(V.EnvelopeError):
            self.r.install("b" * 32, b"x")

    def test_corrupt_file_is_empty_not_crash(self):
        self.r.create("b" * 32)
        self.r.path.write_text("{ nope")
        self.assertEqual(self.r.ids(), [])
        self.r.path.write_text(json.dumps({"b" * 32: {"k": "zz", "ok": True}, "c" * 32: {"k": V._b64(K), "ok": "yes"}, "d" * 32: {"k": V._b64(K), "ok": True, "x": 1}, "e" * 32: {"k": V._b64(K), "ok": True}}))
        self.assertEqual(self.r.ids(), ["e" * 32])

    def test_symlinked_keyfile_ignored(self):
        self.r.create("b" * 32)
        target = self.d + "/elsewhere.json"
        os.rename(self.r.path, target)
        os.symlink(target, self.r.path)
        self.assertEqual(self.r.ids(), [])
        self.assertFalse(self.r.exists())

    def test_two_handles_no_lost_update(self):
        r2 = V.Keyring(self.d + "/keys", T)
        self.r.create("b" * 32)
        r2.create("c" * 32)
        self.assertEqual(self.r.ids(), ["b" * 32, "c" * 32])


class EpochIds(unittest.TestCase):
    def test_epoch_ids_follow_the_removals(self):
        w = World()
        t = w.t
        self.assertEqual(V.chain_epoch_ids(t), [t.id])
        self.assertEqual(V.epoch_id_at(t, t.head), t.id)
        rm1 = w.add(w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id}))
        self.assertEqual(V.chain_epoch_ids(t), [t.id, rm1])
        self.assertEqual(V.epoch_id_at(t, rm1), rm1)
        add = w.add(w.w("arya").add_member(Identity.generate("z"), "member"))         # no epoch bump
        self.assertEqual(V.epoch_id_at(t, add), rm1)
        rm2 = w.add(w.w("arya").admin("member_remove", {"agent": w.ids["sansa"].id}))
        self.assertEqual(V.chain_epoch_ids(t), [t.id, rm1, rm2])
        self.assertEqual(V.epoch_id_at(t, rm2), rm2)
        self.assertEqual(V.epoch_id_at(t, add), rm1)                                      # an older admin_ref keeps its own epoch

    def test_forked_removals_get_different_key_ids_for_the_same_epoch_number(self):
        """Sansa round-18 must-fix 1: two branches can both reach epoch 1 with different removals; the keys must not be the same."""
        w = World()
        t = w.t
        e1 = w.w("arya").admin("member_remove", {"agent": w.ids["carol"].id})
        e2 = w.w("arya").admin("member_remove", {"agent": w.ids["sansa"].id})            # built from the same head: a fork
        t.accept(e1)
        t.accept(e2)
        i1, i2 = event_id(e1), event_id(e2)
        self.assertEqual({t.states[i1]["epoch"], t.states[i2]["epoch"]}, {1})
        self.assertNotEqual(V.epoch_id_at(t, i1), V.epoch_id_at(t, i2))
        self.assertEqual({V.epoch_id_at(t, i1), V.epoch_id_at(t, i2)}, {i1, i2})
        self.assertEqual(len(V.chain_epoch_ids(t)), 2)                                    # only the winning branch's key is ever served

    def test_unknown_admin_state(self):
        w = World()
        with self.assertRaises(V.EnvelopeError):
            V.epoch_id_at(w.t, "f" * 32)


if __name__ == "__main__":
    unittest.main()
