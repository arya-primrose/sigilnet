"""Turning a stored blob into a file the user asked for (`blob get ... --out PATH`). The stored bytes are re-hashed first (hash before decrypt), an encrypted blob is
decrypted chunk by chunk (nothing is written until a chunk authenticates), the plaintext goes to a 0600 temp file in the target directory and only a complete,
verified file is linked to the final name WITHOUT overwriting anything (os.link fails if the name exists). The content is DATA: nothing here opens, runs or
interprets it, and no name comes from the thread (refs carry none)."""
from __future__ import annotations

import os
import stat
import hashlib

from . import blob as B


class OutError(Exception):
    pass


def export(store, mirror, tid: str, cid: str, out_path, *, chunk_read: int = 1 << 20) -> int:
    """Write the blob `cid` of thread `tid` to `out_path`; returns the number of bytes written. OutError with a plain reason on any problem."""
    try:
        B.check_cid(cid)
    except B.BlobError:
        raise OutError("bad cid") from None
    t = mirror.threads.get(tid)
    if t is None:
        raise OutError("unknown thread")
    try:
        src = os.open(store._path(cid), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise OutError("this blob is not in the local store (fetch it first)") from None
    out_path = os.path.abspath(os.fspath(out_path))
    if os.path.lexists(out_path):
        os.close(src)
        raise OutError(f"{out_path} already exists (nothing is overwritten)")
    tmp = os.path.join(os.path.dirname(out_path), f".sigilnet-blob-{os.urandom(6).hex()}.part")
    dst = -1
    try:
        st = os.fstat(src)
        if not stat.S_ISREG(st.st_mode):
            raise OutError("stored object is not a regular file")
        h = hashlib.sha256()
        pos = 0
        while pos < st.st_size:
            b = os.pread(src, min(chunk_read, st.st_size - pos), pos)
            if not b:
                break
            h.update(b)
            pos += len(b)
        if pos != st.st_size or "sha256:" + h.hexdigest() != cid:
            raise OutError("the stored bytes do not match their cid (corrupt store; removing it is safe)")
        enc = t.state()["visibility"] == "private" and mirror.codec.is_encrypted(tid)
        try:
            dst = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as e:
            raise OutError(f"cannot write next to {out_path}: {e.strerror}") from None
        written = 0
        if not enc:
            pos = 0
            while pos < st.st_size:
                b = os.pread(src, min(chunk_read, st.st_size - pos), pos)
                if not b:
                    raise OutError("the stored blob changed while it was being read")
                os.write(dst, b)
                pos += len(b)
            written = pos
        else:
            ring = mirror.codec.ring(tid)

            def root_for(kid):
                got = ring.get(kid)
                return got[0] if got is not None and got[1] else None
            try:
                head = B.parse_header(os.pread(src, B.HEADER_LEN, 0))
                root = root_for(head.kid_hex)
                if root is None:
                    raise OutError("no verified key for this blob's key id (fetch the thread's keys first)")
                op = B.Opener(head, st.st_size, root, tid)
                pos = B.HEADER_LEN
                for i in range(op.n):
                    ln = op.sealed_len(i)
                    ct = os.pread(src, ln, pos)
                    if len(ct) != ln:
                        raise OutError("stored blob is truncated")
                    pt = op.feed(ct)
                    os.write(dst, pt)
                    written += len(pt)
                    pos += ln
                op.finish()
            except B.BlobError as e:
                raise OutError(f"cannot decrypt: {e}") from None
        os.fsync(dst)
        os.close(dst)
        dst = -1
        try:
            os.link(tmp, out_path)                           # fails if the name appeared meanwhile: never overwrites
        except FileExistsError:
            raise OutError(f"{out_path} already exists (nothing is overwritten)") from None
        except OSError as e:
            raise OutError(f"cannot create {out_path}: {e.strerror}") from None
        return written
    except OSError as e:                                     # a full disk or an I/O error mid-copy: a plain reason, and the temp file is removed below
        raise OutError(f"I/O error while writing: {e.strerror}") from None
    finally:
        os.close(src)
        if dst >= 0:
            os.close(dst)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
