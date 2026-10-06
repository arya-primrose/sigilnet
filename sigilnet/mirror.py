"""Local mirror: every thread this agent follows, as append-only files, plus read state (spec 7, 9).

A Thread is a pure function of the SET of events it holds (thread.py), so persistence is simple: store the events, re-derive on load.
root/threads/<thread id>/events.jsonl    every RESOLVED event (live, voided, chain and lost admin events, equivocation losers), canonical bytes,
                                         one per line, appended when an event becomes resolved. Line order does not matter.
                        /awaiting.jsonl  guest requests waiting for admission ({at, ev}), rewritten when the set changes; bounded
                        /read.json       ids the reader has processed
Parked events (missing parents or admin head) live in memory only: they do not affect anything until they resolve, and a peer can resend.
Single-writer by convention, but ingest takes a file lock and picks up lines other processes appended, so a daemon and a CLI can share it.
Receiver-side policies live here (they use the receiver's clock): the per-author rate limit, the thread-count limit, `follow`.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
import unicodedata
from collections import deque
from pathlib import Path

from . import canon, inboxlog
from . import wake as wakefile
from .envelope import PlainCodec
from .event import EventError, check_structure, decode, encode, event_id
from .thread import Result, Thread

MAX_WIRE = 3 * 65536 + 4096              # evidence may carry two events; nothing else comes near this
DROPPED_MAX_AGE = 3 * 3600               # dropped.jsonl is a replay block for the inbox door; a proof of work is bound to an hour salt (current + previous accepted: <= 2 h), so older entries cannot be replayed anyway
DROPPED_MAX_LINES = 50000                # hard cap under a flood: the OLDEST entries go first (a replay of one still needs a fresh proof of work)
DROPPED_PRUNE_AT = 65536                 # prune check when the file is larger than this many bytes
MAX_ORPHANS = 64                         # events for threads we have no genesis for: unverifiable, so a small pool
UNREAD_KINDS = frozenset({"post", "evidence", "member_add", "member_remove", "revoke", "rules_update", "owner_transfer", "owner_takeover", "close"})
PREVIEW = 200
BODY_CAP = 600                           # `show` and `unread` print at most this many characters of one post unless asked for --full (an 8000-character post cost a reader ~8 KB: live test 2, W1)
MAX_INDENT = 16
_STRIP = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def _safe(text: str, limit: int) -> str:
    """Peer text made safe to print: control, format (bidi, zero-width), private and separator characters become spaces."""
    out = "".join(" " if unicodedata.category(c) in _STRIP or (unicodedata.category(c) == "Zs" and c != " ") else c for c in text)
    return " ".join(out.split())[:limit]


def cap_text(text: str, cap) -> str:
    """The first `cap` characters of `text` plus a marker saying how much was left out; unchanged when it fits or `cap` is None."""
    if cap is None or len(text) <= cap:
        return text
    return f"{text[:cap]} ... (+{len(text) - cap} more characters; use --full)"


def _attachments(refs) -> str:
    """` [attachment sha256:ab12cd34.. 1.2 MB]` per valid ref (admission validated them; this only shows them, nothing is fetched)."""
    out = ""
    for r in refs if isinstance(refs, list) else ():
        try:
            n = int(r["size"])
            out += f" [attachment {r['cid'][:15]}.. {n} B]" if n < 1024 else f" [attachment {r['cid'][:15]}.. {n / 1024:.1f} KiB]" if n < 1 << 20 else f" [attachment {r['cid'][:15]}.. {n / (1 << 20):.1f} MiB]"
        except (KeyError, TypeError, ValueError):
            continue
    return out


class Mirror:
    def __init__(self, root, *, follow=None, max_threads: int = 256, clock=time.time, rate_limit: bool = True, codec=None, me: str | None = None, inbox=None, poke=None):
        if (me is None) != (inbox is None):
            raise ValueError("me and inbox go together: the wake file needs to know whose events are not wake-worthy")
        self.me, self.inbox = me, inbox                 # inbox: an inboxlog.InboxLog (DESIGN_node_daemon.md P2); without it this mirror writes NO wake lines
        self.inbox_off = inbox is None
        self.poke = None if poke is None else Path(poke)   # DESIGN_node_wake.md W2: appended to after every events.jsonl append so a running node wakes at once (explicit, never derived from the root)
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.root / "threads").mkdir(exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.follow, self.max_threads, self.clock, self.rate_limit = follow, max_threads, clock, rate_limit
        self.codec = codec or PlainCodec()             # how events.jsonl lines are written and read (envelope.EnvCodec encrypts private threads)
        self.locked: dict[str, object] = {}            # thread id -> codec signature when it could not be opened (no key); retried only when that changes
        self.skipped: dict[str, int] = {}              # thread id -> lines that could not be read (missing epoch key, damaged)
        self.lockf = self.root / "mirror.lock"
        self.threads: dict[str, Thread] = {}
        self.offsets: dict[str, int] = {}
        self.drop_inodes: dict[str, int] = {}        # thread id -> inode of dropped.jsonl when drop_offsets was taken (a prune replaces the file: offsets then restart)
        self.drop_offsets: dict[str, int] = {}       # thread id -> how much of dropped.jsonl (guest requests another process rejected) we have applied
        self.persisted: dict[str, set] = {}          # thread id -> ids already written to events.jsonl
        self.orphans: dict[str, dict] = {}           # event id -> event, for threads we do not have (memory only, bounded)
        self.recovered: list[str] = []               # torn tails truncated on load
        self.recv: dict[tuple, deque] = {}           # (thread, author) -> receipt times, for the rate limit
        with self._lock():
            for d in sorted((self.root / "threads").iterdir()):
                if d.is_dir():
                    self._load(d.name)
            if self.inbox is not None and not self.inbox.valid():
                self._rebuild_inbox_locked()                       # a missing or damaged wake file is rebuilt from the events (new generation)

    # ---------- the wake file (inbox.jsonl) ----------
    def _wake_kind(self, t: Thread, i: str) -> bool:
        """The O(1) part of the `unread` predicate for an event that is not read yet: a kind unread counts, live, by someone else."""
        e = t.events.get(i)
        return e is not None and i not in t.void_ids and e["kind"] in UNREAD_KINDS and e["author"] != self.me

    def _inbox_append(self, tid: str, guest: bool = False) -> None:
        self.inbox.append(tid, guest)
        if self.inbox.size() > inboxlog.MAX_BYTES:
            self._rebuild_inbox_locked()

    def _rebuild_inbox_locked(self) -> str:
        """Replay every thread (sorted by id, then reading order) under the wake rule = `unread`: one line per still-unread event, new generation."""
        tids = []
        for tid in sorted(self.threads):
            tids.extend([tid] * len(self.unread(tid, self.me)))
        return self.inbox.rebuild(tids)

    def rebuild_inbox(self) -> str:
        if self.inbox is None:
            raise ValueError("this mirror has no wake file")
        with self._lock():
            self._discover()
            for tid in list(self.threads):
                self._refresh(tid)
            return self._rebuild_inbox_locked()

    def note_guest(self, tid: str) -> None:
        """A guest request waiting for the owner (it never reaches events.jsonl, so `_persist` cannot see it): one wake line, collapsed per thread by GUEST_GAP."""
        if self.inbox is None:
            return
        with self._lock():
            self._inbox_append(tid, True)

    # ---------- locking and files ----------
    def _lock(self):
        class L:
            def __init__(s, path): s.fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            def __enter__(s): fcntl.flock(s.fd, fcntl.LOCK_EX); return s
            def __exit__(s, *a): os.close(s.fd)
        return L(self.lockf)

    def busy(self) -> bool:
        """True if something holds the mirror lock right now (a sync, a post): never waits (autorotate.py skips its tick instead of queueing behind a sync)."""
        fd = os.open(self.lockf, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True
        finally:
            os.close(fd)

    def _dir(self, tid: str) -> Path:
        return self.root / "threads" / tid

    def _append(self, path: Path, evs: list, t=None) -> None:
        if not evs:
            return
        data = b"".join(self.codec.encode(t, e) + b"\n" for e in evs)       # (before the file is touched: a missing key must not leave a torn line)
        with open(path, "ab") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        path.chmod(0o600)

    def _append_line(self, path: Path, text: str) -> None:
        with open(path, "ab") as f:
            f.write(text.encode("ascii") + b"\n")
            f.flush()
            os.fsync(f.fileno())
        path.chmod(0o600)

    def _read_lines(self, path: Path, start: int = 0) -> tuple[list[bytes], int]:
        """Complete lines from byte offset `start`; a torn tail (no newline) is truncated away and reported."""
        if not path.exists():
            return [], start
        with open(path, "rb") as fh:
            fh.seek(start)
            data = fh.read()
        if data and not data.endswith(b"\n"):
            cut = data.rfind(b"\n") + 1
            self.recovered.append(f"{path}: dropped {len(data) - cut} torn bytes")
            with open(path, "r+b") as f:
                f.truncate(start + cut)
            data = data[:cut]
        return [l for l in data.split(b"\n") if l], start + len(data)

    def _rewrite(self, path: Path, lines: list[bytes]) -> None:
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "wb") as f:
            f.write(b"".join(l + b"\n" for l in lines))
            f.flush()
            os.fsync(f.fileno())
        tmp.chmod(0o600)
        os.replace(tmp, path)

    # ---------- loading ----------
    def _decode_lines(self, lines: list, tid: str | None = None) -> list:
        out = []
        for raw in lines:
            try:
                out.append(self.codec.decode(tid, raw) if tid else decode(raw, MAX_WIRE))
            except EventError:
                if tid:
                    self.skipped[tid] = self.skipped.get(tid, 0) + 1     # e.g. an epoch key we do not hold (yet)
        return out

    def _load(self, tid: str) -> None:
        if not self.codec.usable(tid):
            self.locked[tid] = self.codec.sig(tid)                 # encrypted thread without a readable verified key: LOCKED, not readable, never plaintext
            return
        self.locked.pop(tid, None)
        self.skipped.pop(tid, None)
        lines, off = self._read_lines(self._dir(tid) / "events.jsonl")
        evs = self._decode_lines(lines, tid)
        genesis = next((e for e in evs if e["kind"] == "genesis" and event_id(e) == tid), None)
        if genesis is None:
            return                                               # a corrupt or foreign thread directory is ignored, not fatal
        try:
            t = Thread(genesis, clock=self.clock)
        except EventError:
            return
        self.threads[tid], self.offsets[tid] = t, off
        self._sync_drop_offset(tid)                           # awaiting.jsonl already reflects everything dropped so far
        t.add_many([e for e in evs if e is not genesis])
        self.persisted[tid] = t.resolved_ids()
        self._load_awaiting(t)
        if hasattr(self.codec, "migrating") and self.codec.migrating(tid):      # an interrupted migration: everything is in memory now, finish it
            self._rewrite_encrypted(t)
            self.codec.mark(tid)

    def _load_awaiting(self, t: Thread) -> None:
        evs, times = [], {}
        for raw in self._read_lines(self._dir(t.id) / "awaiting.jsonl")[0]:
            try:
                rec = json.loads(raw)
                check_structure(rec["ev"], MAX_WIRE)
                evs.append(rec["ev"])
                times[event_id(rec["ev"])] = float(rec["at"])
            except (ValueError, KeyError, TypeError, EventError):
                pass
        if evs:
            t.add_many(evs, times)
        t.prune_awaiting()
        self._save_awaiting(t)

    def _save_awaiting(self, t: Thread) -> None:
        self._rewrite(self._dir(t.id) / "awaiting.jsonl",
                      [json.dumps({"at": t.arrived_at[i], "ev": e}, sort_keys=True).encode() for i, e in t.awaiting.items()])

    def _refresh(self, tid: str) -> bool:
        """Pick up lines another process appended since we last looked. True if anything new arrived."""
        t = self.threads.get(tid)
        if t is None:
            return False
        self._apply_drops(t)
        lines, off = self._read_lines(self._dir(tid) / "events.jsonl", self.offsets[tid])
        self.offsets[tid] = off
        if not lines:
            return False
        t.add_many(self._decode_lines(lines, tid))
        self.persisted[tid] |= t.resolved_ids()
        return True

    def _discover(self) -> None:
        for d in sorted((self.root / "threads").iterdir()):
            if d.is_dir() and d.name not in self.threads and (d.name not in self.locked or self.locked[d.name] != self.codec.sig(d.name)):
                self._load(d.name)

    def refresh(self) -> bool:
        """Pick up what other processes (the CLI, another handle) appended since we last looked. True if anything new arrived."""
        with self._lock():
            self._discover()
            return any([self._refresh(tid) for tid in list(self.threads)])

    def enable_encryption(self, tid: str, signer=None) -> str:
        """Turn a private thread's files into envelopes (owner-side migration, also used for a NEW private thread): keys for the epochs the stored events belong to
        (confirmed by `signer`, so other members can verify them), the marker in state "migrating" (plaintext lines still readable), events.jsonl rewritten line by line
        under the keys, then the marker finalised. A crash anywhere leaves a readable thread; loading a "migrating" thread finishes the job. Returns the current key id."""
        from .envelope import chain_epoch_ids, epoch_id_at
        if not hasattr(self.codec, "mark"):
            raise ValueError("this mirror has no encrypting codec")
        with self._lock():
            self._discover()
            for i in list(self.threads):
                self._refresh(i)
            t = self.threads.get(tid)
            if t is None:
                raise ValueError("no such thread")
            if t.state()["visibility"] != "private":
                raise ValueError("only private threads are encrypted (a public thread is signed, plaintext)")
            if signer is not None and t.state()["members"].get(signer.id, {}).get("role") not in ("owner", "admin"):
                raise ValueError("only an owner or admin of the thread may turn encryption on (keys signed by anyone else are accepted by nobody)")
            ring = self.codec.ring(tid)
            for i, ev in t.stored.items():                          # a key for every epoch any stored event belongs to (chain epochs, and abandoned branches' own)
                if i != tid and ev.get("admin_ref") in t.states:
                    ring.create(epoch_id_at(t, ev["admin_ref"]), signer)
            kid = chain_epoch_ids(t)[-1]
            ring.create(kid, signer)
            self.codec.mark(tid, migrating=True)
            self._rewrite_encrypted(t)
            self.codec.mark(tid)
            return kid

    def _rewrite_encrypted(self, t: Thread) -> None:
        resolved = t.resolved_ids()
        lines = [self.codec.encode(t, t.stored[i]) for i in t.arrival if i in resolved and i in t.stored]
        path = self._dir(t.id) / "events.jsonl"
        self._rewrite(path, lines)
        self.offsets[t.id] = path.stat().st_size
        self.persisted[t.id] = set(resolved)

    def reload(self, tid: str) -> bool:
        """Re-read a thread from disk (after a key arrived that opens lines we had to skip). True if it is loaded afterwards."""
        with self._lock():
            self.threads.pop(tid, None)
            self.offsets.pop(tid, None)
            self.persisted.pop(tid, None)
            self.locked.pop(tid, None)
            self._load(tid)
            return tid in self.threads

    def _apply_drops(self, t: Thread) -> None:
        """Another process (the CLI) rejected waiting guest requests: forget them here too, or this process would write them back."""
        path = self._dir(t.id) / "dropped.jsonl"
        gen = self.drop_generation(path)
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if self.drop_inodes.get(t.id, gen) != gen or self.drop_offsets.get(t.id, 0) > size:      # pruned by another process: read it all again (forgetting twice is harmless)
            self.drop_offsets[t.id] = 0
        self.drop_inodes[t.id] = gen
        lines, off = self._read_lines(path, self.drop_offsets.get(t.id, 0))
        self.drop_offsets[t.id] = off
        gone = False
        for raw in lines:
            eid = (raw.decode("ascii", "replace").split() or [""])[0]
            if eid in t.awaiting and not t._has_dependents(eid):
                t._forget(eid)
                gone = True
        if gone:
            t._derive()

    def drop_awaiting(self, tid: str, eid: str) -> bool:
        """Remove one guest request from the waiting pool (an inbox eviction or a moderator's reject). Never removes one that something already replies to."""
        with self._lock():
            self._discover()
            for i in list(self.threads):
                self._refresh(i)
            t = self.threads.get(tid)
            if t is None or eid not in t.awaiting or t._has_dependents(eid):
                return False
            t._forget(eid)
            t._derive()
            self._save_awaiting(t)
            dp = self._dir(tid) / "dropped.jsonl"
            self._append_line(dp, f"{eid} {int(self.clock())}")
            self._prune_dropped(dp)
            self._sync_drop_offset(tid)
            return True

    @staticmethod
    def drop_generation(path: Path) -> int:
        """The prune counter beside dropped.jsonl (bumped by every prune under the lock). Inode numbers are reused by some filesystems, so they cannot tell a pruned file from the old one."""
        try:
            return int((path.with_name("dropped.gen")).read_text().strip() or 0)
        except (OSError, ValueError):
            return 0

    def _sync_drop_offset(self, tid: str) -> None:
        path = self._dir(tid) / "dropped.jsonl"
        self.drop_offsets[tid] = self._read_lines(path)[1]
        self.drop_inodes[tid] = self.drop_generation(path)

    def _prune_dropped(self, path: Path, *, force: bool = False) -> int:
        """Drop old lines of dropped.jsonl (caller holds the lock). Lines are `<id> <unix time>`; a legacy line without a time is stamped now (it lives one more
        period). The file is replaced atomically; readers notice the new inode. Returns how many lines were removed."""
        try:
            if not force and path.stat().st_size <= DROPPED_PRUNE_AT:
                return 0
        except OSError:
            return 0
        now = int(self.clock())
        keep, total, legacy = [], 0, False
        for raw in self._read_lines(path)[0]:
            parts = raw.decode("ascii", "replace").split()
            if not parts:
                continue
            total += 1
            try:
                ts = int(parts[1])
            except (IndexError, ValueError):
                ts, legacy = now, True
            if now - ts <= DROPPED_MAX_AGE:
                keep.append((parts[0], ts))
        if len(keep) > DROPPED_MAX_LINES:
            keep = keep[-(DROPPED_MAX_LINES * 4 // 5):]          # down to 80 % of the cap: the rewrite then happens once per cap/5 drops, not on every drop
        if len(keep) == total and not legacy:
            return 0
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "wb") as f:
            f.write(b"".join(f"{i} {ts}\n".encode("ascii") for i, ts in keep))
            f.flush()
            os.fsync(f.fileno())
        tmp.chmod(0o600)
        os.replace(tmp, path)
        gp = path.with_name("dropped.gen")
        gtmp = gp.with_name("dropped.gen.tmp")
        with open(gtmp, "w") as f:
            f.write(str(self.drop_generation(path) + 1))
            f.flush()
            os.fsync(f.fileno())
        gtmp.chmod(0o600)
        os.replace(gtmp, gp)
        return total - len(keep)

    def prune_dropped(self, tid: str) -> int:
        """Explicit prune of one thread's replay block (the node calls it at startup; `drop_awaiting` does it when the file grows)."""
        with self._lock():
            n = self._prune_dropped(self._dir(tid) / "dropped.jsonl", force=True)
            self._sync_drop_offset(tid)
            return n

    # ---------- ingest ----------
    def ingest(self, data, *, live: bool = True) -> Result:
        """Take one event (canonical bytes, or an already-parsed dict). Never raises on bad input; returns a Result.
        live=False is for catching up on history (sync): the per-author rate limit only applies to live arrivals."""
        try:
            ev = decode(data, MAX_WIRE) if isinstance(data, (bytes, bytearray)) else data
            check_structure(ev, MAX_WIRE)
        except (EventError, canon.CanonError, TypeError, ValueError) as e:
            return Result("rejected", str(e))
        with self._lock():
            self._discover()
            for tid in list(self.threads):
                self._refresh(tid)
            return self._ingest_locked(ev, live)

    def _rate_ok(self, t: Thread, ev: dict) -> bool:
        limit = t.state()["rules"]["posts_per_author_per_hour"]
        q = self.recv.setdefault((t.id, ev["author"]), deque())
        now = self.clock()
        while q and now - q[0] > 3600:
            q.popleft()
        return len(q) < limit

    def _ingest_locked(self, ev: dict, live: bool) -> Result:
        if ev["kind"] == "genesis":
            tid = event_id(ev)
            if tid in self.threads:
                return Result("duplicate")
            if self.follow is not None and not self.follow(ev):
                return Result("rejected", "thread is not followed")
            if len(self.threads) >= self.max_threads:
                return Result("rejected", "too many threads in this mirror")
            try:
                t = Thread(ev, clock=self.clock)
            except EventError as e:
                return Result("rejected", str(e))
            self._dir(tid).mkdir(parents=True, exist_ok=True, mode=0o700)
            self._append(self._dir(tid) / "events.jsonl", [ev], t)
            self.threads[tid] = t
            self.offsets[tid] = (self._dir(tid) / "events.jsonl").stat().st_size
            self.persisted[tid] = {tid}
            if self.poke is not None:
                wakefile.poke(self.poke)                             # a new thread is an append too
            for oid in [i for i, e in self.orphans.items() if e["thread"] == tid]:
                self._ingest_locked(self.orphans.pop(oid), False)
            return Result("accepted", accepted=[tid])
        t = self.threads.get(ev["thread"])
        if t is None and ev["thread"] in self.locked:
            return Result("rejected", "thread is locked (no key)")
        if t is None:
            return self._orphan(ev)
        if not self.codec.can_encode(t, ev) if hasattr(self.codec, "can_encode") else False:
            return Result("rejected", "no key for this epoch yet (need_key): nothing is written in plaintext and nothing is half-stored")
        if live and self.rate_limit and ev["kind"] in ("post", "digest", "evidence") and event_id(ev) not in t.stored and not self._rate_ok(t, ev):
            return Result("rejected", "rate limited (posts_per_author_per_hour)")
        n_wait = set(t.awaiting)
        void_before = set(t.void_ids) if self.inbox is not None else None
        res = t.accept(ev)
        if res.status in ("accepted", "voided") and ev["kind"] in ("post", "digest", "evidence"):
            self.recv.setdefault((t.id, ev["author"]), deque()).append(self.clock())
        self._persist(t, n_wait, void_before)
        return res

    def _persist(self, t: Thread, awaiting_before: set, void_before: set | None = None) -> None:
        d = self._dir(t.id)
        resolved = t.resolved_ids()
        fresh = [i for i in t.arrival if i in resolved and i not in self.persisted[t.id]]
        if fresh and hasattr(self.codec, "can_encode"):
            ok = [i for i in fresh if self.codec.can_encode(t, t.stored[i])]
            if len(ok) != len(fresh):
                self.skipped[t.id] = self.skipped.get(t.id, 0) + len(fresh) - len(ok)       # in memory but not on disk until its epoch key arrives (retried on the next persist)
            fresh = ok
        if self.inbox is not None:
            wake = [i for i in fresh if self._wake_kind(t, i)]
            if void_before is not None and t.void_ids != void_before:       # a removal voided something or a competing admin branch revived it: the revived (persisted) ones are unread again
                read = self._read_set(t.id)                           # the wake rule IS the unread predicate: a revived event the reader already read is not unread
                wake += [i for i in void_before - t.void_ids if i in self.persisted[t.id] and i not in read and self._wake_kind(t, i)]
            for _ in wake:
                self._inbox_append(t.id)                          # BEFORE the events.jsonl append: a crash gives a spurious wake, never an event nobody is told about
        if fresh:
            self._append(d / "events.jsonl", [t.stored[i] for i in fresh], t)
            self.persisted[t.id] |= set(fresh)
            self.offsets[t.id] = (d / "events.jsonl").stat().st_size
            if self.poke is not None:
                wakefile.poke(self.poke)
        if set(t.awaiting) != awaiting_before:
            self._save_awaiting(t)

    def _orphan(self, ev: dict) -> Result:
        eid = event_id(ev)
        if eid not in self.orphans:
            self.orphans[eid] = ev
            while len(self.orphans) > MAX_ORPHANS:
                self.orphans.pop(next(iter(self.orphans)))
        return Result("pending", "unknown thread (need the genesis)", missing=[ev["thread"]])

    def missing(self, tid: str | None = None) -> list:
        """Ids worth fetching: what parked events, admissions and checkpoints name that we do not hold; genesis ids for orphans."""
        need = set()
        for t in ([self.threads[tid]] if tid and tid in self.threads else ([] if tid else list(self.threads.values()))):
            need |= set(t.missing())
        if not tid:
            need |= {e["thread"] for e in self.orphans.values()}
        return sorted(need)

    @property
    def pending(self) -> dict:
        """Parked events across all threads (id -> (event, missing ids)), for inspection."""
        out = {i: (e, list(t.miss.get(i, []))) for t in self.threads.values() for i, e in t.stored.items() if t.status.get(i) == "pending"}
        out.update({i: (e, [e["thread"]]) for i, e in self.orphans.items()})
        return out

    # ---------- reading ----------
    def thread(self, tid: str) -> Thread:
        return self.threads[tid]

    def _read_file(self, tid: str) -> Path:
        return self._dir(tid) / "read.json"

    def _read_set(self, tid: str) -> set:
        try:
            return {i for i in json.loads(self._read_file(tid).read_text())["ids"] if isinstance(i, str)}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return set()

    def cursor(self, tid: str) -> int:
        """How many of the thread's events (in reading order) the reader has processed."""
        r = self._read_set(tid)
        return sum(1 for i in self.threads[tid].order if i in r)

    def unread(self, tid: str, me: str | None = None) -> list:
        t = self.threads[tid]
        r = self._read_set(tid)
        return [t.events[i] for i in t.order if i not in r and i not in t.void_ids and t.events[i]["kind"] in UNREAD_KINDS and t.events[i]["author"] != me]

    def mark_read(self, tid: str, upto: int | None = None) -> int:
        t = self.threads[tid]
        ids = t.order if upto is None else t.order[:max(0, min(upto, len(t.order)))]
        p = self._read_file(tid)
        tmp = p.with_name("read.json.tmp")
        tmp.write_text(json.dumps({"ids": sorted(set(ids) | self._read_set(tid))}))
        tmp.chmod(0o600)
        os.replace(tmp, p)
        return len(ids)

    @staticmethod
    def label(t: Thread, agent: str) -> str:
        """`name (abcdef)`: a display name is a claim, the id prefix is the identity; two members can never look the same."""
        m = t.state()["members"].get(agent) or next((s["members"][agent] for s in t.states.values() if agent in s["members"]), None)
        name = _safe(m["name"], 40) if m else ""
        return f"{name} ({agent[:6]})" if name else f"({agent[:6]})"

    def addressees(self, t: Thread, e: dict) -> list:
        """The labels of the signed `to` of a post (FRAMEWORK: nothing but `to` is read; `you` = this mirror's agent): at most 16, [] for a post without one (a broadcast), whatever is stored."""
        to = e["body"].get("to") if e["kind"] == "post" else None
        if not isinstance(to, list):
            return []
        return ["you" if a == self.me else self.label(t, a) for a in to[:16] if isinstance(a, str)]

    def addressing(self, t: Thread, e: dict) -> str:
        """` -> you, dave (a1b2c3)` for a post with a signed `to`; `` when it has none (a broadcast); at most 4 names, then `+N more`."""
        names = self.addressees(t, e)
        return (" -> " + ", ".join(names[:4]) + (f" +{len(names) - 4} more" if len(names) > 4 else "")) if names else ""

    def brief(self, tid: str, me: str | None = None) -> dict:
        """Deterministic thread summary (no model): counts, authors, unread previews. The cheap default for a returning reader."""
        t = self.threads[tid]
        st = t.state()
        kinds: dict[str, int] = {}
        authors: dict[str, int] = {}
        for i in t.order:
            e = t.events[i]
            kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
            lab = self.label(t, e["author"])
            authors[lab] = authors.get(lab, 0) + 1
        un = self.unread(tid, me)
        return {"thread": tid, "title": _safe(st["title"], 200), "owner": self.label(t, st["owner"]), "epoch": st["epoch"],
                "owner_epoch": st["owner_epoch"], "closed": st["closed"],
                "members": {self.label(t, a): m["role"] for a, m in st["members"].items()},
                "events": len(t.order), "kinds": kinds, "authors": authors,
                "unread": [{"id": event_id(e), "from": self.label(t, e["author"]), "kind": e["kind"], "to": self.addressees(t, e),
                            "preview": _safe(e["body"].get("text", "") if e["kind"] == "post" else json.dumps(e["body"], sort_keys=True), PREVIEW)} for e in un],
                "conflicts": len(t.conflicts), "voided": len(t.void_ids), "awaiting": len(t.awaiting),
                "missing": self.missing(tid), "owner_equivocated": t.owner_equivocated}

    def render(self, tid: str, *, full: bool = True, cap=None) -> list:
        """Readable transcript in deterministic order, replies indented under what they answer. Text is DATA, shown quoted and escaped."""
        t = self.threads[tid]
        depth: dict[str, int] = {}
        lines = []
        for i in t.topo(include_void=True):
            e = t.events[i]
            rt = e["body"].get("reply_to") if e["kind"] == "post" else None
            depth[i] = depth[rt] + 1 if rt in depth else 0
            body = e["body"].get("text", "") if e["kind"] == "post" else f"({e['kind']}) " + json.dumps(e["body"], sort_keys=True)[:160]
            body = _safe(body, 10 ** 6) if full else _safe(body, PREVIEW)
            body = cap_text(body, cap)
            if e["kind"] == "post" and i not in t.void_ids:
                body += _attachments(e["body"].get("refs"))
            if i in t.void_ids:
                body = "[voided: beyond a cut; text withheld]"
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(e["ts"]))
            lines.append(f"{'  ' * min(depth[i], MAX_INDENT)}[{i[:8]}] {when}Z {self.label(t, e['author'])}{self.addressing(t, e)}: {body!r}")
        return lines
