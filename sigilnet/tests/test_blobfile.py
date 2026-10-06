"""Author side (blobauthor.attach) and reader side (blobout.export) of an attachment: sealed under the right epoch key, plain for public threads, safe file handling."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from sigilnet import blob as B
from sigilnet import blobauthor as A
from sigilnet import blobout as O
from sigilnet.blobstore import BlobStore
from sigilnet.build import Writer, make_genesis
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror


class Base(unittest.TestCase):
    enc = True

    def setUp(self):
        self.a, self.b = Identity.generate("a"), Identity.generate("b")
        root = tempfile.mkdtemp()
        self.codec = EnvCodec(root + "/keys")
        self.m = Mirror(root + "/m", codec=self.codec, rate_limit=False)
        g = make_genesis(self.a, "t", [(self.b, "member")], visibility="private" if self.enc else "public")
        self.m.ingest(g)
        self.tid = event_id(g)
        if self.enc:
            self.m.enable_encryption(self.tid, self.a)
        self.t = self.m.threads[self.tid]
        self.store = BlobStore(Path(tempfile.mkdtemp()) / "blobs")
        self.dir = Path(tempfile.mkdtemp())

    def file(self, data, name="f.bin"):
        p = self.dir / name
        p.write_bytes(data)
        return p

    def attach(self, data, **kw):
        return A.attach(self.store, self.m, self.t, self.file(data), referenced=set(), **kw)


class Encrypted(Base):
    def test_roundtrip_through_store_and_export(self):
        for n in (0, 1, 5000, 65536, 65537, 3 * 65536 + 11):
            data = os.urandom(n)
            ref = self.attach(data)
            self.assertEqual(ref["kind"], "file")
            self.assertEqual(ref["size"], B.stored_size(n, A.CHUNK), n)
            self.assertEqual(self.store.size(ref["cid"]), ref["size"])
            stored = self.store.read(ref["cid"], 0, 10 ** 9)
            self.assertEqual(B.cid_of(stored), ref["cid"])
            self.assertNotIn(data[:32], stored) if n >= 32 else None
            out = self.dir / f"out{n}"
            self.assertEqual(O.export(self.store, self.m, self.tid, ref["cid"], out), n)
            self.assertEqual(out.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)

    def test_sealed_under_the_current_epoch_key(self):
        ref = self.attach(b"hello")
        hdr = B.parse_header(self.store.read(ref["cid"], 0, B.HEADER_LEN))
        self.assertEqual(hdr.kid_hex, self.tid)
        self.assertEqual(self.store.listing()[ref["cid"]]["authored"], True)

    def test_after_a_removal_new_blobs_use_the_new_epoch(self):
        rm = Writer(self.a, self.t).admin("member_remove", {"agent": self.b.id})
        c = Identity.generate("c")
        self.codec.ring(self.tid).create(event_id(rm), self.a)
        self.assertTrue(self.m.ingest(rm).ok)
        ref = self.attach(b"after")
        self.assertEqual(B.parse_header(self.store.read(ref["cid"], 0, B.HEADER_LEN)).kid_hex, event_id(rm))

    def test_no_verified_key_is_refused_and_nothing_is_stored(self):
        p = self.codec.ring(self.tid).path
        p.write_text("{}")
        with self.assertRaisesRegex(A.AuthorError, "no verified key"):
            self.attach(b"x")
        self.assertEqual((self.store.listing(), list(self.store.tmp.iterdir())), ({}, []))

    def test_export_refuses_without_the_key_and_leaves_no_file(self):
        ref = self.attach(b"secret words")
        self.codec.ring(self.tid).path.write_text("{}")
        out = self.dir / "o"
        with self.assertRaisesRegex(O.OutError, "no verified key"):
            O.export(self.store, self.m, self.tid, ref["cid"], out)
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".sigilnet") or p.name == "o"], [])

    def test_tampered_store_is_caught_before_decrypting(self):
        ref = self.attach(os.urandom(3000))
        p = self.store._path(ref["cid"])
        raw = bytearray(p.read_bytes())
        raw[B.HEADER_LEN + 3] ^= 1
        p.write_bytes(bytes(raw))
        with self.assertRaisesRegex(O.OutError, "do not match their cid"):
            O.export(self.store, self.m, self.tid, ref["cid"], self.dir / "o")
        self.assertFalse((self.dir / "o").exists())

    def test_wrong_thread_cannot_decrypt(self):
        ref = self.attach(b"bound to the thread")
        other = make_genesis(self.a, "other", [(self.b, "member")])
        self.m.ingest(other)
        otid = event_id(other)
        self.m.enable_encryption(otid, self.a)
        with self.assertRaises(O.OutError):
            O.export(self.store, self.m, otid, ref["cid"], self.dir / "o2")


class Plain(Base):
    enc = False

    def test_public_blob_is_the_file(self):
        data = os.urandom(70000)
        ref = self.attach(data)
        self.assertEqual((ref["size"], ref["cid"]), (len(data), B.cid_of(data)))
        out = self.dir / "o"
        self.assertEqual(O.export(self.store, self.m, self.tid, ref["cid"], out), len(data))
        self.assertEqual(out.read_bytes(), data)

    def test_a_store_file_that_shrinks_after_hashing_cannot_loop_forever(self):
        ref = self.attach(b"payload" * 100)
        real, calls = os.pread, []
        os.pread = lambda fd, n, off: real(fd, n, off) if not calls.append(1) and len(calls) <= 1 else b""
        try:
            with self.assertRaisesRegex(O.OutError, "changed while"):
                O.export(self.store, self.m, self.tid, ref["cid"], self.dir / "s")
        finally:
            os.pread = real

    def test_empty_public_file(self):
        ref = self.attach(b"")
        self.assertEqual(ref, {"kind": "file", "cid": B.cid_of(b""), "size": 0})
        out = self.dir / "e"
        self.assertEqual(O.export(self.store, self.m, self.tid, ref["cid"], out), 0)
        self.assertEqual(out.read_bytes(), b"")


class Files(Base):
    def test_only_regular_files_and_no_symlinks(self):
        real = self.file(b"data")
        link = self.dir / "link"
        os.symlink(real, link)
        fifo = self.dir / "fifo"
        os.mkfifo(fifo)
        for bad in (link, fifo, self.dir, self.dir / "missing"):
            with self.assertRaises(A.AuthorError, msg=str(bad)):
                A.attach(self.store, self.m, self.t, bad, referenced=set())
        self.assertEqual(self.store.listing(), {})

    def test_too_large_is_refused_before_reading(self):
        self.store.max_blob = 1000
        with self.assertRaisesRegex(A.AuthorError, "too large"):
            self.attach(b"x" * 2000)
        self.assertEqual((self.store.listing(), list(self.store.tmp.iterdir())), ({}, []))

    def test_quota_refusal(self):
        self.store.quota = 100
        with self.assertRaisesRegex(A.AuthorError, "quota"):
            self.attach(b"x" * 500)

    def test_a_file_that_grows_while_being_read_fails_cleanly(self):
        p = self.file(b"a" * 1000)
        real = A._read_full
        calls = []

        def growing(fd, n):
            calls.append(1)
            if len(calls) == 1:
                with open(p, "ab") as f:
                    f.write(b"b" * 100000)
            return real(fd, n)
        A._read_full = growing
        try:
            with self.assertRaises(A.AuthorError):
                A.attach(self.store, self.m, self.t, p, referenced=set(), chunk=1024)
        finally:
            A._read_full = real
        self.assertEqual((self.store.listing(), list(self.store.tmp.iterdir())), ({}, []))


class IoErrors(Base):
    def test_a_shrinking_store_file_and_a_full_disk_are_plain_errors(self):
        ref = self.attach(b"payload" * 100)
        real = os.pread
        calls = []

        def shrinking(fd, n, off):
            calls.append(1)
            return real(fd, n, off) if len(calls) <= 1 else b""
        os.pread = shrinking
        try:
            with self.assertRaises(O.OutError):
                O.export(self.store, self.m, self.tid, ref["cid"], self.dir / "s")
        finally:
            os.pread = real
        realw = os.write
        os.write = lambda fd, b: (_ for _ in ()).throw(OSError(28, "No space left on device"))
        try:
            with self.assertRaisesRegex(O.OutError, "I/O error"):
                O.export(self.store, self.m, self.tid, ref["cid"], self.dir / "w")
        finally:
            os.write = realw
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".sigilnet") or p.name in ("s", "w")], [])

    def test_attach_read_error_is_an_author_error_and_leaves_nothing(self):
        p = self.file(b"x" * 5000)
        real = os.read
        os.read = lambda fd, n: (_ for _ in ()).throw(OSError(5, "Input/output error"))
        try:
            with self.assertRaisesRegex(A.AuthorError, "I/O error"):
                A.attach(self.store, self.m, self.t, p, referenced=set())
        finally:
            os.read = real
        self.assertEqual((self.store.listing(), list(self.store.tmp.iterdir())), ({}, []))


class Export(Base):
    def test_never_overwrites_and_leaves_no_temp(self):
        ref = self.attach(b"payload")
        out = self.dir / "exists"
        out.write_bytes(b"precious")
        with self.assertRaisesRegex(O.OutError, "already exists"):
            O.export(self.store, self.m, self.tid, ref["cid"], out)
        self.assertEqual(out.read_bytes(), b"precious")
        link = self.dir / "dangling"
        os.symlink(self.dir / "nowhere", link)
        with self.assertRaisesRegex(O.OutError, "already exists"):
            O.export(self.store, self.m, self.tid, ref["cid"], link)
        self.assertFalse((self.dir / "nowhere").exists())
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".sigilnet")], [])

    def test_not_in_the_store_bad_cid_unknown_thread_and_unwritable_dir(self):
        ref = self.attach(b"x")
        for args, msg in (((self.tid, B.cid_of(b"nope"), self.dir / "a"), "not in the local store"), ((self.tid, "zz", self.dir / "b"), "bad cid"),
                          (("0" * 32, ref["cid"], self.dir / "c"), "unknown thread"), ((self.tid, ref["cid"], self.dir / "no" / "dir" / "d"), "cannot write")):
            with self.assertRaisesRegex(O.OutError, msg):
                O.export(self.store, self.m, *args)

    def test_a_name_that_appears_during_the_export_is_not_overwritten(self):
        ref = self.attach(b"payload")
        out = self.dir / "race"
        real = os.link

        def racing(src, dst, **kw):
            Path(dst).write_bytes(b"someone else")
            return real(src, dst, **kw)
        os.link = racing
        try:
            with self.assertRaisesRegex(O.OutError, "already exists"):
                O.export(self.store, self.m, self.tid, ref["cid"], out)
        finally:
            os.link = real
        self.assertEqual(out.read_bytes(), b"someone else")
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".sigilnet")], [])


if __name__ == "__main__":
    unittest.main()
