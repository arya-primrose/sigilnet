"""Author side of an attachment (DESIGN_blobs.md rev 1, finding 6): read a LOCAL file, build its stored form, publish it into the local blob store, and return the
`refs` entry for the post. The post itself is the caller's job; if it is refused (or the process dies) the blob stays unreferenced and the garbage collector removes it
after the grace period (so: post within 24 h). Never follows a symlink, accepts only regular files, refuses before reading when the stored size would exceed
max_blob_bytes, and never reads a byte more than the size declared to the store (a file that grows while we read it fails instead of overflowing).

Encrypted thread (private + envelopes here): chunks are sealed under the epoch key in force at the thread's CURRENT admin head (the epoch the new post will use);
no verified key = refusal. Public thread: the file's bytes are stored as they are (public blobs are world-readable by design)."""
from __future__ import annotations

import os
import stat

from . import blob as B
from .blobstore import StoreError
from .envelope import EnvelopeError, epoch_id_at

CHUNK = B.DEFAULT_CHUNK


class AuthorError(Exception):
    pass


def _read_full(fd: int, n: int) -> bytes:
    out = b""
    while len(out) < n:
        b = os.read(fd, n - len(out))
        if not b:
            break
        out += b
    return out


def attach(store, mirror, t, path, *, referenced, chunk: int = CHUNK) -> dict:
    """Store `path` for thread `t` and return its ref `{"kind": "file", "cid", "size"}` (size = STORED bytes). Raises AuthorError with a plain reason."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        raise AuthorError(f"cannot open {os.fspath(path)!r}: {e.strerror} (symlinks are refused)") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AuthorError(f"{os.fspath(path)!r} is not a regular file")
        codec = mirror.codec
        enc = t.state()["visibility"] == "private" and codec.is_encrypted(t.id)
        stored = B.stored_size(st.st_size, chunk) if enc else st.st_size
        if stored > store.max_blob:
            raise AuthorError(f"{os.fspath(path)!r} is too large: {stored} bytes stored, limit {store.max_blob} (max_blob_bytes)")
        root = kid = None
        if enc:
            try:
                kid = epoch_id_at(t, t.head)
            except EnvelopeError as e:
                raise AuthorError(f"cannot tell which key to seal under: {e}") from None
            got = codec.ring(t.id).get(kid)
            if got is None or not got[1]:
                raise AuthorError("no verified key for the current epoch of this thread yet (fetch keys from a member first)")
            root = got[0]
        try:
            store.make_room(stored, referenced)
            inc = store.begin(None, size=stored)
        except StoreError as e:
            raise AuthorError(f"blob store: {e}") from None
        try:
            if enc:
                def pieces():
                    while True:
                        b = _read_full(fd, chunk)
                        if not b:
                            return
                        yield b
                        if len(b) < chunk:
                            return
                for part in B.seal_iter(root, t.id, kid, pieces(), chunk):
                    inc.write(part)
            else:
                while True:
                    b = os.read(fd, chunk)
                    if not b:
                        break
                    inc.write(b)
            cid = inc.commit(referenced=referenced, authored=True)
        except StoreError as e:
            inc.abort()
            raise AuthorError(f"blob store: {e}") from None
        except OSError as e:
            inc.abort()
            raise AuthorError(f"I/O error while reading {os.fspath(path)!r}: {e.strerror}") from None
        except BaseException:
            inc.abort()
            raise
        return {"kind": "file", "cid": cid, "size": os.stat(store._path(cid)).st_size}
    finally:
        os.close(fd)
