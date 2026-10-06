"""The want queue between the CLI and the running node (DESIGN_blobs.md rev 1: never auto-fetched, only on purpose). `blob get` cannot reach peers itself (the node owns
the carrier), so it writes a small request file; the node's blob worker picks it up, runs blobfetch and writes a status file; the CLI waits for the blob to appear in the
store. Files live in <blobs>/want/ (0700 dir, 0600 files, named by the cid's hex, so a request is idempotent) and expire after 24 h; a status file after 1 h."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import blob as B
from .keys import is_hex

WANT_TTL = 86400.0
STATUS_TTL = 3600.0
MAX_WANTS = 64


class Wants:
    def __init__(self, blobs_root, clock=time.time):
        self.dir = Path(blobs_root) / "want"
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.clock = clock

    def _p(self, cid: str, ext: str) -> Path:
        return self.dir / (B.cid_hex(cid) + ext)

    def _write(self, path: Path, obj: dict) -> None:
        tmp = self.dir / f".tmp.{os.getpid()}.{os.urandom(4).hex()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, separators=(",", ":"))
        os.replace(tmp, path)

    def add(self, tid: str, cid: str) -> bool:
        """Queue a fetch. False if the queue is full. Clears an old status for this cid."""
        if not is_hex(tid, 32):
            raise ValueError("bad thread id")
        B.check_cid(cid)
        self.expire()
        if not self._p(cid, ".want").exists() and len(list(self.dir.glob("*.want"))) >= MAX_WANTS:
            return False
        try:
            self._p(cid, ".status").unlink()
        except FileNotFoundError:
            pass
        self._write(self._p(cid, ".want"), {"thread": tid, "cid": cid, "at": self.clock()})
        return True

    @staticmethod
    def _read(path: Path):
        try:
            d = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        return d if isinstance(d, dict) else None

    def pending(self) -> list:
        """Valid requests, oldest first; malformed files are deleted."""
        self.expire()
        out = []
        for p in self.dir.glob("*.want"):
            d = self._read(p)
            try:
                ok = d is not None and is_hex(d["thread"], 32) and B.check_cid(d["cid"]) == d["cid"] and p.name == B.cid_hex(d["cid"]) + ".want" \
                    and isinstance(d["at"], (int, float))
            except (KeyError, B.BlobError):
                ok = False
            if ok:
                out.append(d)
            else:
                p.unlink(missing_ok=True)
        return sorted(out, key=lambda d: d["at"])

    def finish(self, cid: str, ok: bool, why: str = "") -> None:
        self._write(self._p(cid, ".status"), {"ok": bool(ok), "why": str(why)[:300], "at": self.clock()})
        self._p(cid, ".want").unlink(missing_ok=True)

    def status(self, cid: str):
        d = self._read(self._p(cid, ".status"))
        return d if d is not None and isinstance(d.get("ok"), bool) else None

    def queued(self, cid: str) -> bool:
        return self._p(cid, ".want").exists()

    def expire(self) -> None:
        now = self.clock()
        for ext, ttl in ((".want", WANT_TTL), (".status", STATUS_TTL)):
            for p in self.dir.glob("*" + ext):
                try:
                    if now - p.stat().st_mtime > ttl:
                        p.unlink(missing_ok=True)
                except OSError:
                    pass
        for p in self.dir.glob(".tmp.*"):
            try:
                if now - p.stat().st_mtime > 600:
                    p.unlink(missing_ok=True)
            except OSError:
                pass
