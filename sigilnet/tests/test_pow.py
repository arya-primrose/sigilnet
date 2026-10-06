import unittest

from sigilnet import pow as P

S, T, K, E = b"s" * 16, "t" * 64, "k" * 64, "e" * 64


class Pow(unittest.TestCase):
    def test_solve_verify(self):
        n = P.solve(S, T, K, E, 12)
        self.assertTrue(P.verify(S, T, K, E, n, 12))
        self.assertGreaterEqual(P.achieved(S, T, K, E, n), 12)

    def test_zero_bits_always_ok(self):
        self.assertTrue(P.verify(S, T, K, E, 0, 0))

    def test_bound_to_every_input(self):
        n = P.solve(S, T, K, E, 14, start=0)
        # a proof for one tuple is (almost surely) not valid for another at high bits: check at 14 bits over several variants
        bad = sum(P.verify(*a, n, 14) for a in [(bytes([i]) * 16, T, K, E) for i in range(1, 40)])
        self.assertLessEqual(bad, 2)

    def test_length_prefix_no_ambiguity(self):
        # moving a byte between adjacent fields must change the digest
        self.assertNotEqual(P._digest(b"ab" * 8, "c" * 4, "d", "e", 1), P._digest(b"ab" * 8 + b"c", "c" * 3, "d", "e", 1))

    def test_bad_nonce_and_salt(self):
        for bad in (-1, 2 ** 63, 1.5, "1", None):
            self.assertEqual(P.achieved(S, T, K, E, bad), -1, bad)
        self.assertEqual(P.achieved(b"short", T, K, E, 1), -1)
        self.assertEqual(P.achieved(b"x" * 65, T, K, E, 1), -1)
        self.assertFalse(P.verify(S, T, K, E, 1, 41))
        self.assertFalse(P.verify(S, T, K, E, 1, -1))
        with self.assertRaises(ValueError):
            P.solve(S, T, K, E, 41)

    def test_bool_nonce_rejected(self):
        self.assertEqual(P.achieved(S, T, K, E, True), -1)

    def test_leading_zero_bits(self):
        self.assertEqual(P.leading_zero_bits(b"\x00\x01"), 15)
        self.assertEqual(P.leading_zero_bits(b"\x80"), 0)
        self.assertEqual(P.leading_zero_bits(b"\x00\x00"), 16)

    def test_max_tries(self):
        with self.assertRaises(RuntimeError):
            P.solve(S, T, K, E, 40, start=0, max_tries=10)


if __name__ == "__main__":
    unittest.main()
