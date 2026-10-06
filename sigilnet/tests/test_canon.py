import unittest

from sigilnet import canon


class Canon(unittest.TestCase):
    def test_vectors_valid(self):
        vec = [({"b": 2, "a": 1}, b'{"a":1,"b":2}'), ([], b"[]"), ({}, b"{}"), (None, b"null"), (True, b"true"), (0, b"0"), (-7, b"-7"),
               ({"a": [1, {"z": None, "y": False}]}, b'{"a":[1,{"y":false,"z":null}]}'),
               ("é", b'"\\u00e9"'), ("\U0001f600", b'"\\ud83d\\ude00"'), ("a\nb", b'"a\\nb"'), ('q"\\', b'"q\\"\\\\"'),
               # RFC 8785 order is by UTF-16 code units: U+1F600 (D83D DE00) sorts BEFORE U+FFFF, unlike code point order
               ({"￿": 1, "\U0001f600": 2}, b'{"\\ud83d\\ude00":2,"\\uffff":1}')]
        for obj, want in vec:
            self.assertEqual(canon.dumps(obj), want, obj)
            self.assertEqual(canon.loads(want), obj)

    def test_rejects_on_dump(self):
        for bad in (1.0, float("nan"), {"a": 1.5}, {1: 2}, b"x", {1, 2}, 2 ** 53, -2 ** 53 - 1, "\ud800", {"a": {"b": object()}}):
            with self.assertRaises(canon.CanonError, msg=repr(bad)):
                canon.dumps(bad)

    def test_rejects_non_canonical_input(self):
        for raw in (b'{"a": 1}', b'{"b":1,"a":2}', b'{"a":1.0}', b'{"a":1e3}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1,"a":2}',
                    b'{"a":"\xc3\xa9"}', b'{"a":"\\u00E9"}', b'01', b'-0', b'[1,]', b'', b'  {}', b'{}\n', b'\xff', b'{"a":9007199254740993}',
                    b'"\\ud800"', b'{"a":"\\/"}', b'{"a":"\\u0041"}'):
            with self.assertRaises(canon.CanonError, msg=raw):
                canon.loads(raw)

    def test_depth_and_size(self):
        ok = b"[" * canon.MAX_DEPTH + b"]" * canon.MAX_DEPTH
        self.assertEqual(canon.loads(ok), canon.loads(ok))
        with self.assertRaises(canon.CanonError):
            canon.loads(b"[" * (canon.MAX_DEPTH + 2) + b"]" * (canon.MAX_DEPTH + 2))
        with self.assertRaises(canon.CanonError):
            canon.loads(b"[" * 100000 + b"]" * 100000)
        with self.assertRaises(canon.CanonError):
            canon.loads(b'"' + b"a" * canon.MAX_BYTES + b'"')

    def test_roundtrip_property(self):
        import random
        rnd = random.Random(7)

        def gen(d=0):
            r = rnd.random()
            if d > 3 or r < 0.3:
                return rnd.choice([None, True, False, rnd.randint(-10 ** 6, 10 ** 6), "".join(rnd.choice("aé \U0001f600\"\\\n z") for _ in range(rnd.randint(0, 6)))])
            if r < 0.6:
                return [gen(d + 1) for _ in range(rnd.randint(0, 4))]
            return {"".join(rnd.choice("abé￿\U0001f600") for _ in range(rnd.randint(0, 3))): gen(d + 1) for _ in range(rnd.randint(0, 4))}
        for _ in range(500):
            o = gen()
            b = canon.dumps(o)
            self.assertEqual(canon.loads(b), o)
            self.assertEqual(canon.dumps(canon.loads(b)), b)


if __name__ == "__main__":
    unittest.main()
