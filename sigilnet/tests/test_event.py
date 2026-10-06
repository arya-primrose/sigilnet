import copy
import unittest

from sigilnet import canon, event as E, keys
from sigilnet.keys import Identity, L


def sample(ident=None, **kw):
    ident = ident or Identity.generate("x")
    return ident, E.make_event(ident, thread="a" * 32, kind="post", body={"text": "hello"}, parents=["b" * 32], seq=3, admin_ref="c" * 32, ts=1000, **kw)


class Events(unittest.TestCase):
    def test_id_ignores_signature_material(self):
        i, ev = sample()
        i2 = Identity.generate("y")
        ev2 = dict(ev, sig="0" * 128)
        self.assertEqual(E.event_id(ev), E.event_id(ev2))
        with_cosig = E.add_cosig(ev, i2)
        self.assertEqual(E.event_id(ev), E.event_id(with_cosig))
        self.assertEqual(len(E.event_id(ev)), 32)

    def test_every_field_is_covered_by_the_signature(self):
        i, ev = sample()
        good = lambda e: keys.verify_strict(i.sign_pub, e["sig"], E.sign_input(e))
        self.assertTrue(good(ev))
        muts = {"v": 2, "thread": "d" * 32, "author": "a" * 32, "seq": 4, "parents": ["e" * 32], "admin_ref": "d" * 32, "ts": 1001,
                "kind": "digest", "body": {"text": "hellp"}}
        for k, v in muts.items():
            e = dict(ev); e[k] = v
            self.assertFalse(good(e), k)
        e = copy.deepcopy(ev); e["body"]["extra"] = 1
        self.assertFalse(good(e))

    def test_signature_malleability_rejected(self):
        i, ev = sample()
        sig = bytes.fromhex(ev["sig"])
        s = int.from_bytes(sig[32:], "little")
        mall = (sig[:32] + ((s + L) % 2 ** 256).to_bytes(32, "little")).hex()
        self.assertFalse(keys.verify_strict(i.sign_pub, mall, E.sign_input(ev)))
        # even if a lenient verifier accepted it, the event id would not change (id excludes sig)
        self.assertEqual(E.event_id(ev), E.event_id(dict(ev, sig=mall)))

    def test_small_order_and_noncanonical_keys_rejected(self):
        i, ev = sample()
        for pk in sorted(keys.SMALL_ORDER):
            self.assertFalse(keys.valid_sign_pub(pk.hex()))
        y_ge_p = ((1 << 255) - 19 + 1).to_bytes(32, "little").hex()    # non-canonical y = p + 1
        self.assertFalse(keys.valid_sign_pub(y_ge_p))
        self.assertFalse(keys.verify_strict("00" * 32, ev["sig"], b"x"))
        self.assertFalse(keys.verify_strict(i.sign_pub, "zz" * 64, b"x"))
        self.assertFalse(keys.verify_strict(i.sign_pub.upper(), ev["sig"], b"x"))

    def test_mixed_order_torsion_key_rejected(self):
        """A key P+T (prime-order part plus a small-order point) is not in the prime-order subgroup: verifiers disagree on it."""
        i = Identity.generate("x")
        P = keys._decompress(bytes.fromhex(i.sign_pub))
        T = keys._decompress(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"))   # order 8
        self.assertIsNotNone(T)
        x, y, z, _ = keys._add(P, T)
        zi = pow(z, keys.P - 2, keys.P)
        x, y = x * zi % keys.P, y * zi % keys.P
        mixed = (y | ((x & 1) << 255)).to_bytes(32, "little").hex()
        self.assertNotEqual(mixed, i.sign_pub)
        self.assertIsNotNone(keys._decompress(bytes.fromhex(mixed)))          # a perfectly decodable point...
        self.assertFalse(keys.valid_sign_pub(mixed))                          # ...that we refuse
        self.assertTrue(keys.valid_sign_pub(i.sign_pub))

    def test_agent_id_shape(self):
        i = Identity.generate("x")
        self.assertRegex(i.id, r"^[a-z2-7]{32}$")
        self.assertEqual(i.id, keys.agent_id(bytes.fromhex(i.sign_pub)))

    def test_structure_rejections(self):
        i, ev = sample()
        E.check_structure(ev)
        bad = []
        for k in list(ev):
            e = dict(ev); del e[k]; bad.append(("missing " + k, e))
        bad += [("extra", dict(ev, extra=1)), ("kind", dict(ev, kind="nope")), ("thread", dict(ev, thread="xyz")), ("admin_ref", dict(ev, admin_ref="")),
                ("seq neg", dict(ev, seq=-1)), ("seq bool", dict(ev, seq=True)), ("seq float", dict(ev, seq=1.0)), ("ts big", dict(ev, ts=2 ** 41)),
                ("parents empty", dict(ev, parents=[])), ("parents unsorted", dict(ev, parents=["c" * 32, "b" * 32])),
                ("parents dup", dict(ev, parents=["b" * 32, "b" * 32])), ("parents many", dict(ev, parents=sorted({f"{n:032x}" for n in range(17)}))),
                ("body list", dict(ev, body=[])), ("sig short", dict(ev, sig="ab")), ("sig upper", dict(ev, sig=ev["sig"].upper())),
                ("author bad", dict(ev, author="NOPE")), ("v bool", dict(ev, v=True)),
                ("cosig unsorted", dict(ev, cosigs=[{"author": "b" * 32, "sig": "0" * 128}, {"author": "a" * 32, "sig": "0" * 128}])),
                ("cosig self", dict(ev, cosigs=[{"author": ev["author"], "sig": "0" * 128}])), ("cosig shape", dict(ev, cosigs=[{"author": "a" * 32}]))]
        for name, e in bad:
            with self.assertRaises(E.EventError, msg=name):
                E.check_structure(e)

    def test_genesis_shape_and_size_cap(self):
        i = Identity.generate("x")
        g = E.make_event(i, thread="", kind="genesis", body={}, parents=[], seq=0, admin_ref="")
        E.check_structure(g)
        for bad in (dict(g, thread="a" * 32), dict(g, parents=["a" * 32]), dict(g, seq=1), dict(g, admin_ref="a" * 32)):
            with self.assertRaises(E.EventError):
                E.check_structure(bad)
        _, big = sample()
        big["body"] = {"text": "x" * 20000}
        with self.assertRaises(E.EventError):
            E.check_structure(big, 16384)

    def test_decode_requires_canonical_bytes(self):
        i, ev = sample()
        raw = E.encode(ev)
        self.assertEqual(E.decode(raw), ev)
        for bad in (raw + b"\n", raw.replace(b",", b", ", 1), b"{}", b"[]", b"null", raw[:-1]):
            with self.assertRaises(E.EventError):
                E.decode(bad)

    def test_cosig_is_over_same_bytes_and_sorted(self):
        i, ev = sample()
        c1, c2 = Identity.generate("c1"), Identity.generate("c2")
        e = E.add_cosig(E.add_cosig(ev, c2), c1)
        E.check_structure(e)
        self.assertEqual([c["author"] for c in e["cosigs"]], sorted([c1.id, c2.id]))
        for c, ident in ((e["cosigs"][0], c1 if c1.id < c2.id else c2),):
            self.assertTrue(keys.verify_strict(ident.sign_pub, c["sig"], E.cosign_input(ev)))
        self.assertEqual(len(E.add_cosig(e, c1)["cosigs"]), 2)       # re-adding replaces, never duplicates


if __name__ == "__main__":
    unittest.main()
