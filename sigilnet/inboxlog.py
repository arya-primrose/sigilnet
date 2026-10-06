"""`inbox.jsonl`: the wake file (DESIGN_node_daemon.md section 5, P2). One POINTER per event that should wake the agent: `{"seq": N, "t": time, "thread": tid}`, plus
`"guest": true` for a guest request waiting for the owner. Never a sender, a kind, an event id or any text: the file leaks nothing on disk. The first line of every
generation is `{"gen": "<16 hex>"}`; a consumer's cursor holds (gen, seq), and a different generation means "start from 0" (it may announce twice, never miss).
Append-only, one `os.write` per line with fsync. Writers hold the Mirror lock (the caller does; this class takes none). A torn last line is skipped by readers and cut
off by the next writer. The wake decision itself is made by the Mirror from the plaintext it holds at that moment and is not recorded."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterable

FILE = "inbox.jsonl"
MAX_BYTES = 8 * 1024 * 1024            # past this the writer rebuilds the file with a new generation (only still-unread events survive)
GUEST_GAP = 300.0                      # a thread gets at most one guest line per this many seconds (a stranger's flood must not wake the session in a loop)


def _line(d: dict) -> bytes:
    return (json.dumps(d, separators=(",", ":")) + "\n").encode("ascii")


def _entry(raw: bytes):
    """One parsed seq line, or None for anything that is not one (the gen line, a damaged line)."""
    try:
        d = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(d, dict) or isinstance(d.get("seq"), bool) or not isinstance(d.get("seq"), int) or d["seq"] < 1 or not isinstance(d.get("thread"), str):
        return None
    t = d.get("t")
    if isinstance(t, bool) or not isinstance(t, (int, float)):
        return None
    out = {"seq": d["seq"], "t": float(t), "thread": d["thread"]}
    if d.get("guest") is True:
        out["guest"] = True
    return out


def _gen_of(raw: bytes):
    try:
        d = json.loads(raw)
    except ValueError:
        return None
    g = d.get("gen") if isinstance(d, dict) else None
    return g if isinstance(g, str) and g else None


class InboxLog:
    def __init__(self, home, *, clock=time.time):
        self.path = Path(home) / FILE
        self.clock = clock
        self._cache = None            # (inode, offset, last_seq, {thread: last guest t}) of the part of the file already scanned

    # ---------- reading ----------
    def _raw(self) -> bytes:
        try:
            return self.path.read_bytes()
        except OSError:
            return b""

    def _head_gen(self):
        """The generation named by the first line (read: at most 4 KiB, never the whole file), or None if missing/damaged."""
        try:
            with open(self.path, "rb") as f:
                head = f.read(4096)
        except OSError:
            return None
        return _gen_of(head.split(b"\n", 1)[0]) if b"\n" in head else None

    def valid(self) -> bool:
        """The file exists and its first line is a generation line."""
        return self._head_gen() is not None

    @property
    def gen(self) -> str:
        g = self._head_gen()
        if g is None:
            return self._write_new([])                                  # missing or damaged: an empty file with a fresh generation
        return g

    def read_from(self, gen, seq: int) -> tuple:
        """(current generation, entries with seq greater than `seq`); a different generation (or None) returns ALL entries."""
        raw = self._raw()
        head = raw.split(b"\n", 1)[0] if raw else b""
        cur = _gen_of(head) or ""
        entries = [e for e in (_entry(l) for l in raw.split(b"\n")[1:]) if e is not None]
        if cur == "" or gen != cur:
            return cur, entries
        return cur, [e for e in entries if e["seq"] > seq]

    def head(self) -> int:
        raw = self._raw()
        seqs = [e["seq"] for e in (_entry(l) for l in raw.split(b"\n")[1:]) if e is not None]
        return max(seqs) if seqs else 0

    # ---------- writing (caller holds the Mirror lock) ----------
    def _write_new(self, threads_guest: Iterable) -> str:
        g = os.urandom(8).hex()
        now = self.clock()
        data = _line({"gen": g}) + b"".join(_line({"seq": n, "t": round(now, 3), "thread": tid}) for n, tid in enumerate(threads_guest, 1))
        tmp = self.path.with_name(f".{FILE}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        self._cache = None
        return g

    def rebuild(self, threads: Iterable) -> str:
        """Replace the file (new inode, no temp file left, 0600) with a NEW generation and one non-guest line per thread id given, in the given order."""
        return self._write_new(list(threads))

    def _scan(self) -> tuple:
        """(last seq, {thread: last guest time}) of the file, incremental while the file only grows."""
        try:
            st = os.stat(self.path)
        except OSError:
            return 0, {}
        c = self._cache
        if c is None or c[0] != st.st_ino or st.st_size < c[1]:
            c = (st.st_ino, 0, 0, {})
        ino, off, last, guests = c
        guests = dict(guests)
        if st.st_size > off:
            with open(self.path, "rb") as f:
                f.seek(off)
                data = f.read()
            cut = data.rfind(b"\n") + 1
            for l in data[:cut].split(b"\n"):
                e = _entry(l) if l else None
                if e is not None:
                    last = max(last, e["seq"])
                    if e.get("guest"):
                        guests[e["thread"]] = e["t"]
            off += cut
        self._cache = (ino, off, last, guests)
        return last, guests

    def append(self, thread: str, guest: bool = False):
        """Write one line; returns its seq, or None when a GUEST line is collapsed (the last guest line of that thread is newer than GUEST_GAP)."""
        if not self.valid():
            self._write_new([])
        last, guests = self._scan()
        now = self.clock()
        if guest:
            prev = guests.get(thread)
            if prev is not None and 0 <= now - prev < GUEST_GAP:         # (a line from the future never silences a wake)
                return None
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            size = os.fstat(fd).st_size
            if size:
                with open(self.path, "rb") as f:
                    f.seek(size - 1)
                    torn = f.read(1) != b"\n"
                if torn:                                                 # a crash mid-write: cut the torn tail so the next line starts clean
                    with open(self.path, "rb") as f:
                        data = f.read()
                    os.ftruncate(fd, data.rfind(b"\n") + 1)
                    self._cache = None
                    last, guests = self._scan()
            d = {"seq": last + 1, "t": round(now, 3), "thread": thread}
            if guest:
                d["guest"] = True
            line = _line(d)
            os.write(fd, line)
            os.fsync(fd)
            ino, new_size = os.fstat(fd).st_ino, os.fstat(fd).st_size
        finally:
            os.close(fd)
        g2 = dict(guests)
        if guest:
            g2[thread] = d["t"]
        self._cache = (ino, new_size, last + 1, g2)                  # the scan state moves with our own write: no rescan of the whole file at the next append
        return last + 1

    def stamp(self):
        """(inode, size, mtime_ns) of the file, or None if it does not exist: a cheap 'did anything change'."""
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        return (st.st_ino, st.st_size, st.st_mtime_ns)

    def size(self) -> int:
        try:
            return os.stat(self.path).st_size
        except OSError:
            return 0


def wait_guest(home, timeout: float, *, clock=time.time, sleep=time.sleep, poll: float = 2.0, consumer: str = "requests") -> list:
    """`requests wait`: block until a guest line (a guest request replying to an owner event) arrives past this consumer's cursor, at most once per GUEST_GAP
    (a stranger's flood must not wake the session in a loop; a time in the future in the cursor file must not silence it either). Returns the thread ids (in order,
    unique), or [] on timeout. Non-guest lines are skipped silently (they are for `watch`)."""
    from . import cursors
    log = InboxLog(home)
    end = clock() + timeout
    while True:
        cur = cursors.load(home, consumer)
        gen, seq, at = (cur or {}).get("gen"), (cur or {}).get("seq", 0), (cur or {}).get("at", 0.0)
        now = clock()
        if not isinstance(at, (int, float)) or isinstance(at, bool) or at > now:
            at = 0.0                                                     # a future time (clock set back, damaged file) must not silence the wake for ever
        cgen, entries = log.read_from(gen, seq)
        guests = [e for e in entries if e.get("guest")]
        if guests and now - at >= GUEST_GAP:
            cursors.save(home, consumer, cgen, max(e["seq"] for e in entries), at=now)
            return list(dict.fromkeys(e["thread"] for e in guests))
        if not guests and entries and cgen:
            cursors.save(home, consumer, cgen, max(e["seq"] for e in entries), at=at)
        if clock() >= end:
            return []
        sleep(poll)
