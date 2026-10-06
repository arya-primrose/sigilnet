"""Blob format properties (DESIGN_blobs.md rev 1): truncation at EVERY chunk boundary (and every byte), swapped chunks, a flipped bit anywhere,
header lies, the zero-length file, canonical layout, wrong thread/key/kid."""
import os
import random
import struct
import unittest

from sigilnet import blob as B

TID = "t" * 64
KID = "ab" * 16
ROOT = bytes(range(32))
CH = B.MIN_CHUNK                                      # small chunks keep the exhaustive tests fast


def root_for(kid):
    return ROOT if kid == KID else None


def sealed(n, chunk=CH, seed=1):
    plain = random.Random(seed).randbytes(n)
    return plain, B.seal(ROOT, TID, KID, plain, chunk)


def chunk_bounds(stored, chunk=CH):
    h = B.parse_header(stored)
    n, _ = B.layout(len(stored), h.chunk)
    out, pos = [], B.HEADER_LEN
    for i in range(n):
        ln = B.Opener(h, len(stored), ROOT, TID).sealed_len(i)
        out.append((pos, pos + ln))
        pos += ln
    return out


class RoundTrip(unittest.TestCase):
    def test_sizes_around_the_chunk_boundaries(self):
        for n in (0, 1, 2, CH - 1, CH, CH + 1, 2 * CH - 1, 2 * CH, 2 * CH + 1, 5 * CH, 5 * CH + 17):
            plain, st = sealed(n)
            self.assertEqual(len(st), B.stored_size(n, CH), n)
            self.assertEqual(B.open_blob(root_for, TID, st), plain, n)
            self.assertEqual(B.layout(len(st), CH)[1], n)

    def test_default_chunk_size(self):
        plain = os.urandom(3 * B.DEFAULT_CHUNK + 5)
        st = B.seal(ROOT, TID, KID, plain)
        self.assertEqual(B.open_blob(root_for, TID, st), plain)

    def test_zero_length_file_is_one_final_chunk(self):
        _, st = sealed(0)
        self.assertEqual(len(st), B.HEADER_LEN + B.TAG)
        self.assertEqual(B.layout(len(st), CH), (1, 0))
        self.assertEqual(B.open_blob(root_for, TID, st), b"")
        # ... and dropping that single chunk (a header alone) is not a valid blob
        with self.assertRaises(B.BlobError):
            B.open_blob(root_for, TID, st[:B.HEADER_LEN])

    def test_two_seals_differ_and_share_no_nonce(self):
        a, b = B.seal(ROOT, TID, KID, b"x" * 100, CH), B.seal(ROOT, TID, KID, b"x" * 100, CH)
        self.assertNotEqual(a, b)
        self.assertNotEqual(B.parse_header(a).salt, B.parse_header(b).salt)

    def test_no_plaintext_in_the_stored_bytes(self):
        plain = b"SECRET-MARKER-" * 200
        self.assertNotIn(b"SECRET-MARKER", B.seal(ROOT, TID, KID, plain, CH))

    def test_cid(self):
        _, st = sealed(10)
        c = B.cid_of(st)
        self.assertEqual(B.check_cid(c), c)
        h = B.Hasher()
        h.update(st[:7])
        h.update(st[7:])
        self.assertEqual((h.cid(), h.size), (c, len(st)))
        for bad in (None, 5, "", "sha256:" + "A" * 64, "sha256:" + "a" * 63, "sha256:" + "a" * 65, "md5:" + "a" * 64, "sha256:" + "a" * 63 + "g", c + "\n"):
            with self.assertRaises(B.BlobError, msg=repr(bad)):
                B.check_cid(bad)


class Truncation(unittest.TestCase):
    def test_truncated_at_every_chunk_boundary(self):
        plain, st = sealed(4 * CH + 10)
        bounds = chunk_bounds(st)
        self.assertEqual(len(bounds), 5)
        for _, end in bounds[:-1]:                        # a clean cut after chunk k: every earlier chunk is intact, the cut is still caught
            with self.assertRaises(B.BlobError, msg=end):
                B.open_blob(root_for, TID, st[:end])

    def test_truncated_at_every_byte(self):
        _, st = sealed(2 * CH + 3)
        for cut in range(len(st)):
            with self.assertRaises(B.BlobError, msg=cut):
                B.open_blob(root_for, TID, st[:cut])

    def test_streaming_truncation_is_not_done(self):
        _, st = sealed(3 * CH)
        h = B.parse_header(st)
        op = B.Opener(h, len(st), ROOT, TID)
        b = chunk_bounds(st)
        op.feed(st[b[0][0]:b[0][1]])
        op.feed(st[b[1][0]:b[1][1]])
        self.assertFalse(op.done)
        with self.assertRaises(B.BlobError):
            op.finish()

    def test_a_blob_whose_final_chunk_was_sealed_non_final(self):
        # a stream that really ended after chunk 1 but whose chunk 1 was sealed with final=0 (an attacker cannot rebuild it either way)
        plain, st = sealed(3 * CH)
        b = chunk_bounds(st)
        h = B.parse_header(st)
        key = B._key(ROOT, TID, h)
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        forged = st[:b[1][1]]                             # header + chunks 0 and 1, both sealed non-final... except we re-seal chunk 1 as final
        c1 = ChaCha20Poly1305(key).encrypt(B._nonce(h, 1), plain[CH:2 * CH], B._aad(TID, h, 1, True))
        forged = st[:b[1][0]] + c1                        # the attacker CAN do this only with the key: here we prove the honest opener accepts it
        self.assertEqual(B.open_blob(root_for, TID, forged), plain[:2 * CH])
        # without the key the original chunk 1 (non-final) cannot serve as a final one
        with self.assertRaises(B.BlobError):
            B.open_blob(root_for, TID, st[:b[1][1]])


class Tampering(unittest.TestCase):
    def test_swap_two_chunks(self):
        _, st = sealed(5 * CH)
        b = chunk_bounds(st)
        for i in range(len(b)):
            for j in range(i + 1, len(b)):
                if b[i][1] - b[i][0] != b[j][1] - b[j][0]:
                    continue                              # unequal lengths would shift offsets; equal-length swaps are the subtle ones
                parts = [st[x:y] for x, y in b]
                parts[i], parts[j] = parts[j], parts[i]
                with self.assertRaises(B.BlobError, msg=(i, j)):
                    B.open_blob(root_for, TID, st[:B.HEADER_LEN] + b"".join(parts))

    def test_duplicate_a_chunk(self):
        _, st = sealed(4 * CH)
        b = chunk_bounds(st)
        parts = [st[x:y] for x, y in b]
        dup = st[:B.HEADER_LEN] + b"".join(parts[:2] + [parts[1]] + parts[2:])
        with self.assertRaises(B.BlobError):
            B.open_blob(root_for, TID, dup)

    def test_flip_one_bit_anywhere(self):
        _, st = sealed(2 * CH + 5, seed=3)
        for pos in range(len(st)):
            bad = bytearray(st)
            bad[pos] ^= 1 << (pos % 8)
            with self.assertRaises(B.BlobError, msg=pos):
                B.open_blob(root_for, TID, bytes(bad))

    def test_flip_every_bit_of_the_header(self):
        _, st = sealed(CH + 1)
        for pos in range(B.HEADER_LEN):
            for bit in range(8):
                bad = bytearray(st)
                bad[pos] ^= 1 << bit
                with self.assertRaises(B.BlobError, msg=(pos, bit)):
                    B.open_blob(root_for, TID, bytes(bad))

    def test_trailing_bytes_and_appended_chunk(self):
        _, st = sealed(2 * CH)
        for extra in (b"\0", os.urandom(B.TAG), os.urandom(CH + B.TAG)):
            with self.assertRaises(B.BlobError):
                B.open_blob(root_for, TID, st + extra)

    def test_other_thread_other_key_unknown_kid(self):
        plain, st = sealed(CH + 1)
        with self.assertRaises(B.BlobError):
            B.open_blob(root_for, "u" * 64, st)
        with self.assertRaises(B.BlobError):
            B.open_blob(lambda k: bytes(32), TID, st)
        with self.assertRaises(B.BlobError):
            B.open_blob(lambda k: None, TID, st)
        # the kid is bound by the header (AAD + KDF): a header naming another kid fails even if the reader holds that key
        other = "cd" * 16
        bad = bytearray(st)
        bad[34:50] = bytes.fromhex(other)
        with self.assertRaises(B.BlobError):
            B.open_blob(lambda k: ROOT, TID, bytes(bad))

    def test_opener_is_dead_after_one_failure(self):
        _, st = sealed(3 * CH)
        h = B.parse_header(st)
        b = chunk_bounds(st)
        op = B.Opener(h, len(st), ROOT, TID)
        with self.assertRaises(B.BlobError):
            op.feed(st[b[1][0]:b[1][1]])                  # chunk 1 first: wrong index
        with self.assertRaises(B.BlobError):
            op.feed(st[b[0][0]:b[0][1]])                  # even the right chunk is refused now
        with self.assertRaises(B.BlobError):
            op.finish()

    def test_data_after_the_final_chunk(self):
        _, st = sealed(CH)
        h = B.parse_header(st)
        op = B.Opener(h, len(st), ROOT, TID)
        op.feed(st[B.HEADER_LEN:])
        self.assertTrue(op.done)
        with self.assertRaises(B.BlobError):
            op.feed(b"\0" * 16)


class HeaderLies(unittest.TestCase):
    def hdr(self, **kw):
        f = dict(ver=1, flags=0, chunk=CH, salt=b"s" * 16, np=b"n" * 8, kid=bytes.fromhex(KID), magic=B.MAGIC)
        f.update(kw)
        return f["magic"] + struct.pack(">BBI", f["ver"], f["flags"], f["chunk"]) + f["salt"] + f["np"] + f["kid"]

    def test_good_header_parses(self):
        h = B.parse_header(self.hdr())
        self.assertEqual((h.chunk, h.kid_hex), (CH, KID))

    def test_bad_headers(self):
        for kw in (dict(magic=b"XXXX"), dict(ver=0), dict(ver=2), dict(flags=1), dict(chunk=0), dict(chunk=1), dict(chunk=B.MIN_CHUNK - 1),
                   dict(chunk=B.MAX_CHUNK + 1), dict(chunk=0xFFFFFFFF)):
            with self.assertRaises(B.BlobError, msg=kw):
                B.parse_header(self.hdr(**kw))
        for n in range(B.HEADER_LEN):
            with self.assertRaises(B.BlobError):
                B.parse_header(self.hdr()[:n])
        for junk in (None, "str", 5):
            with self.assertRaises(B.BlobError):
                B.parse_header(junk)

    def test_declared_size_lies(self):
        # the reader derives the layout from the DECLARED size before it allocates anything
        for size in (-1, 0, 1, B.HEADER_LEN, B.HEADER_LEN + B.TAG - 1, True, None, 1.5, "100"):
            with self.assertRaises(B.BlobError, msg=size):
                B.layout(size, CH)
        # a size whose last chunk would be shorter than a tag, or an empty chunk after data, is not canonical
        full = CH + B.TAG
        for size in (B.HEADER_LEN + full + B.TAG - 1, B.HEADER_LEN + full + B.TAG):
            with self.assertRaises(B.BlobError, msg=size):
                B.layout(size, CH)
        # a huge declared size is refused by the chunk-count bound, not by allocating
        with self.assertRaises(B.BlobError):
            B.layout(B.HEADER_LEN + (B.MAX_CHUNKS + 1) * (CH + B.TAG), CH)

    def test_size_matches_every_plain_length(self):
        for n in range(0, 3 * CH + 40, 7):
            self.assertEqual(B.layout(B.stored_size(n, CH), CH)[1], n)
        sizes = {B.stored_size(n, CH) for n in range(0, 3 * CH + 40)}
        self.assertEqual(len(sizes), 3 * CH + 40)         # injective: one stored size per plaintext length

    def test_header_claims_a_different_chunk_size_than_the_data(self):
        plain, st = sealed(3 * CH)
        bad = bytearray(st)
        bad[6:10] = struct.pack(">I", 2 * CH)             # consistent header, wrong for the bytes: the AEAD (header in AAD) refuses
        with self.assertRaises(B.BlobError):
            B.open_blob(root_for, TID, bytes(bad))

    def test_make_header_and_seal_arguments(self):
        for kid in (None, "", "ab" * 15, "AB" * 32, "zz" * 32, KID + "00"):
            with self.assertRaises(B.BlobError, msg=kid):
                B.seal(ROOT, TID, kid, b"x", CH)
        for ch in (0, CH - 1, B.MAX_CHUNK + 1):
            with self.assertRaises(B.BlobError, msg=ch):
                B.seal(ROOT, TID, KID, b"x", ch)
        for root in (b"", b"x" * 31, None):
            with self.assertRaises(B.BlobError, msg=root):
                B.seal(root, TID, KID, b"x", CH)

    def test_seal_iter_rejects_bad_pieces(self):
        for pieces in ([b"a" * CH, b""], [b"a" * (CH - 1), b"a" * 5], [b"a" * (CH + 1)], [b""] * 2):
            with self.assertRaises(B.BlobError, msg=[len(p) for p in pieces]):
                list(B.seal_iter(ROOT, TID, KID, pieces, CH))

    def test_seal_iter_streams_and_matches(self):
        plain = os.urandom(3 * CH + 9)
        pieces = [plain[i:i + CH] for i in range(0, len(plain), CH)]
        st = b"".join(B.seal_iter(ROOT, TID, KID, iter(pieces), CH))
        self.assertEqual(B.open_blob(root_for, TID, st), plain)
        self.assertEqual(b"".join(B.seal_iter(ROOT, TID, KID, iter([]), CH))[:4], B.MAGIC)


class KeyDerivationPins(unittest.TestCase):
    """Sansa's pins (r29a review): each input of the nonce and the key must matter, or one blob/epoch reuses keystream."""

    def zeros(self, tid=TID, kid=KID, salt=b"s" * 16, root=ROOT, n=3):
        vals = iter([salt, b"n" * 8])
        return B.seal(root, tid, kid, b"\0" * (n * CH), CH, rng=lambda k: next(vals))     # plaintext zero: the ciphertext IS the keystream

    def test_keystream_differs_per_chunk(self):
        st = self.zeros()
        bodies = [st[a:b][:-B.TAG] for a, b in chunk_bounds(st)]
        self.assertEqual(len(set(bodies)), 3)

    def test_salt_tid_kid_root_each_change_the_keystream(self):
        base = self.zeros(n=1)[B.HEADER_LEN:]
        for what, other in (("salt", self.zeros(salt=b"S" * 16, n=1)), ("tid", self.zeros(tid="u" * 64, n=1)),
                            ("kid", self.zeros(kid="cd" * 16, n=1)), ("root", self.zeros(root=bytes(32), n=1))):
            self.assertNotEqual(base[:CH], other[B.HEADER_LEN:][:CH], what)


class WrongTypes(unittest.TestCase):
    def test_only_blob_errors_escape(self):
        _, st = sealed(CH + 1)
        for tid in (None, 5, "", "\ud800", "t\u00e9"):
            with self.assertRaises(B.BlobError, msg=repr(tid)):
                B.open_blob(root_for, tid, st)
            with self.assertRaises(B.BlobError, msg=repr(tid)):
                B.seal(ROOT, tid, KID, b"x", CH)
        with self.assertRaises(B.BlobError):
            B.seal(ROOT, TID, KID, "text", CH)
        def boom(k):
            raise RuntimeError("keyring broke")
        with self.assertRaises(B.BlobError):
            B.open_blob(boom, TID, st)
        op = B.Opener(B.parse_header(st), len(st), ROOT, TID)
        with self.assertRaises(B.BlobError):
            op.feed(None)
        with self.assertRaises(B.BlobError):                      # dead after the wrong-typed feed
            op.feed(st[B.HEADER_LEN:B.HEADER_LEN + CH + B.TAG])


if __name__ == "__main__":
    unittest.main()
