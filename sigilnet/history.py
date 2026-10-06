"""`history.log`: the plain-text record of a node (DESIGN_node_daemon.md section 6, P2). One line per record: `YYYY-MM-DD HH:MM:SS TZ  who  text` (local time with the
zone abbreviation). Replaces `node.log`; nothing parses it. Hygiene: text only, control/format characters become spaces, one line, capped at MAX_LINE characters
(prefix included), never peer text (callers pass ids and counts). Concurrency: ONE `os.write` in O_APPEND mode per record (atomic with respect to the file offset on a
local filesystem: ext4, overlayfs, tmpfs; NOT on NFS), the file is opened per record so a rotation by another process is followed at the next write. Rotation: past
MAX_BYTES the writer takes `history.lock`, re-stats the size INSIDE the lock (two rotators) and renames to `history.log.1` (one old file is kept)."""
from __future__ import annotations

import fcntl
import os
import time
import unicodedata
from pathlib import Path

FILE = "history.log"
MAX_BYTES = 5 * 1024 * 1024
MAX_LINE = 1000


def _clean(text) -> str:
    t = "".join(" " if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") else c for c in str(text))
    return " ".join(t.split())


class History:
    def __init__(self, home, *, clock=time.time):
        self.home = Path(home)
        self.path = self.home / FILE
        self.clock = clock

    def _stamp(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(self.clock()))

    def _rotate(self) -> None:
        lock = os.open(self.home / "history.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                size = os.stat(self.path).st_size
            except OSError:
                return
            if size > MAX_BYTES:                                         # re-checked inside the lock: another process may have rotated already
                os.replace(self.path, self.home / (FILE + ".1"))
        finally:
            os.close(lock)

    def log(self, who: str, text: str) -> None:
        line = f"{self._stamp()}  {_clean(who)}  {_clean(text)}"[:MAX_LINE] + "\n"
        try:
            if os.path.exists(self.path) and os.stat(self.path).st_size > MAX_BYTES:
                self._rotate()
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, line.encode("utf-8", "replace"))
            finally:
                os.close(fd)
        except OSError:
            pass                                                         # a log that cannot be written must never take a command or the node down

    def tail(self, n: int = 20) -> list:
        try:
            return self.path.read_text(errors="replace").splitlines()[-n:]
        except OSError:
            return []
