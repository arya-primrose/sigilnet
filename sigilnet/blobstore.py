"""Local blob store (DESIGN_blobs.md rev 1): content-addressed files, a quota, partial downloads, and garbage collection. No network, no thread knowledge:
the caller says which cids are still referenced (blobindex.py computes that from the mirror).

    <root>/objects/<hex[:2]>/<hex>   the STORED bytes of a blob (sha256 of them = the name); only validated cids ever become a path
    <root>/tmp/<hex>.part            a resumable download of that cid;  <root>/tmp/<random>.part  an authoring temp
    <root>/meta.json                 {"v":1,"blobs":{hex: {"size", "authored", "added", "unref"}}}  advisory: the object files are the truth, a damaged
                                     meta is rebuilt from them (everything then counts as fetched and unreferenced-since-now, i.e. gets the grace again)

Limits worth knowing: the quota is enforced when a blob is published, not per write, so up to max_partials * max_blob bytes of partials can sit above it (a bound,
not a leak); an AUTHORED blob whose post never lands is collected after the grace like any unreferenced blob (the author must post within it).
A blob becomes visible only by an atomic rename after its size and sha256 were checked, so nothing partial is ever readable as a blob. All state changes
run under one flock on <root>/lock (the CLI and the node are different processes). Files are 0600, directories 0700, nothing follows a symlink."""
from __future__ import annotations

import fcntl
import json
import os
import stat
import threading
import time
from pathlib import Path

from . import blob as B

GIB = 1 << 30
MIB = 1 << 20
DAY = 86400.0
MAX_READ = MIB                                  # read() never returns more than this, whatever a peer asked for


class StoreError(Exception):
    pass


class QuotaError(StoreError):
    pass


class TooBig(StoreError):
    pass


class PartialLimit(StoreError):
    pass


class Incoming:
    """A download or authoring temp. write() bytes in order; commit() checks and publishes, abort() deletes (keep() leaves a resumable partial)."""

    def __init__(self, store: "BlobStore", cid, limit: int, resume: bool):
        self.store, self.cid, self.limit = store, cid, limit
        self.hasher = B.Hasher()
        name = (B.cid_hex(cid) if cid else os.urandom(12).hex()) + ".part"
        self.path = store.tmp / name
        self._closed = False
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC      # NONBLOCK: a planted FIFO fails (ENXIO) instead of hanging us
        fd = os.open(self.path, flags, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise StoreError("partial is not a regular file")
            if resume and st.st_size:
                if st.st_size > limit:
                    os.ftruncate(fd, 0)                       # a kept partial larger than what we now expect is not ours: start over
                else:
                    with open(self.path, "rb") as f:          # re-hash the kept prefix: never trust an old file's bytes
                        while True:
                            b = f.read(1 << 16)
                            if not b:
                                break
                            self.hasher.update(b)
            else:
                os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_END)
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd

    @property
    def offset(self) -> int:
        return self.hasher.size

    def write(self, b: bytes) -> None:
        if self._closed:
            raise StoreError("closed")
        if self.hasher.size + len(b) > self.limit:
            self.abort()
            raise TooBig("more bytes than declared")
        try:
            mv = memoryview(b)
            while mv:
                n = os.write(self.fd, mv)
                mv = mv[n:]
        except OSError as e:                                     # ENOSPC and friends: nothing half-written stays behind
            self.abort()
            raise StoreError(f"write failed: {e.strerror}") from None
        self.hasher.update(b)

    def keep(self) -> None:
        """Close but leave the partial for a later resume (it expires after partial_ttl). An EMPTY partial has nothing to resume: it is deleted (a live test showed that
        failed fetches of different cids left empty files that filled max_partials and locked the home out for 24 h)."""
        if not self._closed and self.offset == 0:
            self.abort()
        elif not self._closed:
            self._closed = True
            os.close(self.fd)

    def abort(self) -> None:
        if not self._closed:
            self._closed = True
            os.close(self.fd)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def commit(self, *, referenced, expect_cid=None, expect_size=None, authored: bool = False) -> str:
        """Verify size and sha256 of everything written, then publish atomically. On any failure the temp is deleted. Returns the cid.
        `referenced` (cids the events still name) is REQUIRED: it orders the eviction that makes room, and an empty default would silently mark everything evictable."""
        if self._closed:
            raise StoreError("closed")
        try:
            cid, size = self.hasher.cid(), self.hasher.size
            want = expect_cid or self.cid
            if want is not None and cid != want:
                raise StoreError("sha256 does not match the cid")
            if expect_size is not None and size != expect_size:
                raise StoreError("size does not match")
            if size > self.store.max_blob:
                raise TooBig("blob exceeds max_blob_bytes")
            os.fsync(self.fd)
            os.close(self.fd)
            self._closed = True
            self.store._publish(self.path, cid, size, authored, referenced)
            return cid
        except BaseException:
            self.abort()
            raise


class BlobStore:
    def __init__(self, root, *, quota: int = GIB, max_blob: int = 64 * MIB, grace: float = DAY, partial_ttl: float = DAY, max_partials: int = 8,
                 clock=time.time):
        self.root = Path(root)
        self.quota, self.max_blob, self.grace, self.partial_ttl, self.max_partials, self.clock = quota, max_blob, grace, partial_ttl, max_partials, clock
        self.objects, self.tmp = self.root / "objects", self.root / "tmp"
        for d in (self.root, self.objects, self.tmp):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._mu = threading.RLock()
        self._lockf = self.root / "lock"
        self.sweep()

    # ------------------------------------------------------------ locking and meta
    def _locked(self):
        store = self

        class L:
            def __enter__(s):
                store._mu.acquire()
                s.fd = os.open(store._lockf, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
                fcntl.flock(s.fd, fcntl.LOCK_EX)
                return s

            def __exit__(s, *a):
                os.close(s.fd)
                store._mu.release()
        return L()

    def _path(self, cid: str) -> Path:
        h = B.cid_hex(cid)
        return self.objects / h[:2] / h

    def _load(self) -> dict:
        try:
            d = json.loads((self.root / "meta.json").read_text())
            if d.get("v") == 1 and isinstance(d.get("blobs"), dict) and all(
                    B.CID_RE.fullmatch("sha256:" + h) and self._entry_ok(v) for h, v in d["blobs"].items()):
                return d["blobs"]
        except (OSError, ValueError, AttributeError):
            pass
        return self._rebuild()

    @staticmethod
    def _entry_ok(v) -> bool:
        """Every field of a meta entry, strictly: a damaged or hostile meta must not wedge gc() or fake the usage; anything off means 'rebuild from the files'."""
        def num(x):
            return type(x) in (int, float) and x == x and abs(x) != float("inf")
        return isinstance(v, dict) and set(v) == {"size", "authored", "added", "unref"} and type(v["size"]) is int and 0 <= v["size"] <= 2 ** 40 \
            and type(v["authored"]) is bool and num(v["added"]) and (v["unref"] is None or num(v["unref"]))

    def _rebuild(self) -> dict:
        now = self.clock()
        out = {}
        for sub in self.objects.iterdir():
            if sub.is_dir() and not sub.is_symlink():
                for f in sub.iterdir():
                    if f.is_file() and not f.is_symlink() and len(f.name) == 64 and f.name[:2] == sub.name and B.CID_RE.fullmatch("sha256:" + f.name):
                        out[f.name] = {"size": f.stat().st_size, "authored": False, "added": now, "unref": now}
        self._save(out)
        return out

    def _save(self, blobs: dict) -> None:
        tmp = self.root / f"meta.json.{os.getpid()}.{threading.get_ident()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"v": 1, "blobs": blobs}, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.root / "meta.json")

    # ------------------------------------------------------------ queries
    def has(self, cid: str) -> bool:
        p = self._path(cid)
        return p.is_file() and not p.is_symlink()

    def size(self, cid: str):
        try:
            st = os.lstat(self._path(cid))
        except FileNotFoundError:
            return None
        return st.st_size if stat.S_ISREG(st.st_mode) else None

    def read(self, cid: str, offset: int, n: int) -> bytes:
        """A plain read for serving (never under the mirror lock): b"" past the end, None if we do not hold it. A GC unlink mid-read is harmless on POSIX."""
        if type(offset) is not int or type(n) is not int or offset < 0 or n < 0 or offset > 2 ** 62:
            raise StoreError("bad range")
        try:
            fd = os.open(self._path(cid), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:                                          # missing, or a planted symlink (ELOOP): we do not hold it
            return None
        try:
            return os.pread(fd, min(n, MAX_READ), offset)
        finally:
            os.close(fd)

    def listing(self) -> dict:
        with self._locked():
            return {"sha256:" + h: dict(v) for h, v in self._load().items()}

    def partials(self) -> list:
        out = []
        for f in self.tmp.iterdir():
            if f.name.endswith(".part") and f.is_file() and not f.is_symlink():
                st = f.stat()
                out.append((f, st.st_size, st.st_mtime))
        return out

    def usage(self) -> int:
        with self._locked():
            return self._usage(self._load())

    def _usage(self, blobs: dict) -> int:
        return sum(v["size"] for v in blobs.values()) + sum(s for _, s, _ in self.partials())

    # ------------------------------------------------------------ writing
    def begin(self, cid=None, *, size: int, resume: bool = False) -> Incoming:
        """Start a download of `cid` (declared stored `size`) or an authoring temp (cid None). Refused up front when the size is over the per-blob limit or
        there are too many partials; the quota is enforced by make_room()/commit()."""
        if cid is not None:
            B.check_cid(cid)
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise StoreError("bad size")
        if size > self.max_blob:
            raise TooBig("declared size exceeds max_blob_bytes")
        with self._locked():
            self.expire_partials()
            existing = (self.tmp / (B.cid_hex(cid) + ".part")).exists() if cid else False
            if not existing and sum(1 for _, size, _ in self.partials() if size) >= self.max_partials:     # empty files hold nothing: they do not count
                raise PartialLimit("too many partial downloads")
            return Incoming(self, cid, size, resume)

    def put(self, stored: bytes, *, referenced, authored: bool = False) -> str:
        """Store a whole blob given as bytes (authoring and tests)."""
        inc = self.begin(None, size=len(stored))
        inc.write(stored)
        return inc.commit(authored=authored, referenced=referenced)

    def _publish(self, tmp: Path, cid: str, size: int, authored: bool, referenced) -> None:
        with self._locked():
            blobs = self._load()
            h = B.cid_hex(cid)
            if h in blobs and self.has(cid):
                tmp.unlink()                                  # already held: the same bytes
                if authored:
                    blobs[h]["authored"] = True
                    self._save(blobs)
                return
            self._make_room(blobs, size - self._part_size(tmp), referenced)
            p = self._path(cid)
            p.parent.mkdir(exist_ok=True, mode=0o700)
            os.replace(tmp, p)
            blobs[h] = {"size": size, "authored": bool(authored), "added": self.clock(), "unref": None}
            self._save(blobs)

    @staticmethod
    def _part_size(tmp: Path) -> int:
        try:
            return tmp.stat().st_size                         # the partial is already counted in usage: only the difference needs room
        except FileNotFoundError:
            return 0

    def make_room(self, need: int, referenced=()) -> None:
        with self._locked():
            self._make_room(self._load(), need, referenced)

    def _make_room(self, blobs: dict, need: int, referenced) -> None:
        if self._usage(blobs) + need <= self.quota:
            return
        ref = {B.cid_hex(c) for c in referenced}
        # 1: unreferenced blobs (oldest first), whatever their grace; 2: fetched (not authored) referenced blobs, oldest first. Authored blobs are never evicted.
        order = sorted((h for h in blobs if h not in ref and not blobs[h]["authored"]), key=lambda h: blobs[h]["added"]) \
            + sorted((h for h in blobs if h in ref and not blobs[h]["authored"]), key=lambda h: blobs[h]["added"])
        dirty = False
        for h in order:
            if self._usage(blobs) + need <= self.quota:
                break
            self._unlink(h)
            del blobs[h]
            dirty = True
        if dirty:
            self._save(blobs)
        if self._usage(blobs) + need > self.quota:
            raise QuotaError("blob store quota exceeded")

    def _unlink(self, h: str) -> None:
        try:
            (self.objects / h[:2] / h).unlink()
        except FileNotFoundError:
            pass

    def remove(self, cid: str) -> bool:
        with self._locked():
            blobs = self._load()
            h = B.cid_hex(cid)
            had = h in blobs or self.has(cid)
            self._unlink(h)
            if blobs.pop(h, None) is not None:
                self._save(blobs)
            return had

    # ------------------------------------------------------------ maintenance
    def expire_partials(self) -> int:
        now, n = self.clock(), 0
        for f, _, mt in self.partials():
            if now - mt > self.partial_ttl:
                try:
                    f.unlink()
                    n += 1
                except FileNotFoundError:
                    pass
        return n

    def sweep(self) -> None:
        """At start: expire partials, delete stray temp files, reconcile meta with the object files."""
        with self._locked():
            self.expire_partials()
            for f in self.tmp.iterdir():
                if not f.name.endswith(".part") or f.is_symlink() or not f.is_file():
                    try:
                        f.unlink()
                    except (IsADirectoryError, PermissionError):
                        pass
            for f in self.root.glob("meta.json.*"):
                f.unlink()
            blobs = self._load()
            on_disk = set()
            for sub in self.objects.iterdir():
                if sub.is_dir() and not sub.is_symlink():
                    for f in sub.iterdir():
                        if f.is_file() and not f.is_symlink() and len(f.name) == 64 and f.name[:2] == sub.name:
                            on_disk.add(f.name)
            changed = False
            for h in list(blobs):
                if h not in on_disk:
                    del blobs[h]
                    changed = True
                else:
                    real = (self.objects / h[:2] / h).stat().st_size
                    if blobs[h]["size"] != real:
                        blobs[h]["size"] = real                  # the file is the truth
                        changed = True
            for h in on_disk - set(blobs):
                blobs[h] = {"size": (self.objects / h[:2] / h).stat().st_size, "authored": False, "added": self.clock(), "unref": self.clock()}
                changed = True
            if changed:
                self._save(blobs)

    def gc(self, referenced) -> list:
        """`referenced` = cids named by any LIVE or VOIDED event of any thread we hold. A blob that lost its last reference lives `grace` more seconds
        (a reorg can revive a voided event, an event can arrive late); a blob that is referenced again has its clock reset. Returns the removed cids."""
        ref = {B.cid_hex(c) for c in referenced}
        now, gone = self.clock(), []
        with self._locked():
            blobs = self._load()
            dirty = False
            for h in list(blobs):
                v = blobs[h]
                if h in ref:
                    if v.get("unref") is not None:
                        v["unref"] = None
                        dirty = True
                elif v.get("unref") is None:
                    v["unref"] = now
                    dirty = True
                elif now - v["unref"] > self.grace:
                    self._unlink(h)
                    del blobs[h]
                    gone.append("sha256:" + h)
                    dirty = True
            if dirty:
                self._save(blobs)
        return gone
