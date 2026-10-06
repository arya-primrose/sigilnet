"""One-time layout migration of a home: `inbox/` (the guest door's state) became `guest/` (DESIGN_node_daemon.md section 8, P0).

`Inbox.__init__` used to mkdir("inbox") and `_secret()` makes a NEW secret when none exists: running the new code on an old home without this step would
have replaced the door's secret (the stateless proof-of-work salts and bits are lost) and left both directories behind. So ONE function does the move, every command
and `node run` call it first, and `Inbox`/`WakeFile` refuse (`check_layout`) to open an old-layout home instead of silently starting fresh.
`migrate_home` is idempotent and race-safe (a dedicated flock; a lost race is a success), refuses while a node holds `node.lock` (an old-code node would recreate
`inbox/` by path and leave both again), and never merges: both directories present is an error that names both."""
from __future__ import annotations

import fcntl
import os
import stat
import time
from pathlib import Path


class MigrationError(ValueError):
    pass


def check_layout(home) -> None:
    """Loud, never a fresh start: an old-layout home (inbox/ without guest/) must be migrated first."""
    home = Path(home)
    if os.path.lexists(home / "inbox") and not os.path.lexists(home / "guest"):
        raise MigrationError(f"{home} still has the old layout (inbox/): run any sigilnet command once with the node stopped, it renames inbox/ to guest/")


def drop_wake_files(home) -> None:
    """P2: `guest/wake.json` and `guest/wake_seen.json` (the old guest-request counters behind `inbox wait`) are gone: their job is a line in `inbox.jsonl`. Best effort, never through a symlink."""
    g = Path(home) / "guest"
    if os.path.islink(g):
        return
    for name in ("wake.json", "wake_seen.json"):
        try:
            os.unlink(g / name)
        except OSError:
            pass


def migrate_home(home) -> bool:
    """Rename home/inbox to home/guest. True if it did, False if there was nothing to do."""
    home = Path(home)
    old, new = home / "inbox", home / "guest"
    if not os.path.lexists(old):
        drop_wake_files(home)
        return False
    try:
        lock = os.open(home / ".migrate.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        raise MigrationError(f"cannot open {home / '.migrate.lock'}: {e.strerror}") from None
    node = -1
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not os.path.lexists(old):
            return False                                           # another process did it while we waited: success
        if not stat.S_ISDIR(os.lstat(old).st_mode):
            raise MigrationError(f"{old} is not a plain directory (a symlink or a file): not touching it")
        if os.path.lexists(new):
            raise MigrationError(f"both {old} and {new} exist: not merging them; decide which one is the guest door's state and remove the other")
        try:
            node = os.open(home / "node.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            end = time.monotonic() + 1.0                              # a probe (`status`, `stop`) holds the lock for microseconds: retry for about a second before calling it a running node
            while True:
                try:
                    fcntl.flock(node, fcntl.LOCK_EX | fcntl.LOCK_NB)       # held through the rename: a node cannot start in the middle of it
                    break
                except BlockingIOError:
                    if time.monotonic() >= end:
                        raise MigrationError("a node is running on this home: stop it first (an old-code node would recreate inbox/ by path)") from None
                    time.sleep(0.02)
        except MigrationError:
            raise
        except OSError as e:
            raise MigrationError(f"cannot check node.lock: {e.strerror}") from None
        try:
            os.rename(old, new)
            drop_wake_files(home)
        except FileNotFoundError:
            return False
        except OSError as e:                                       # read-only / wrong-owner home (EROFS, EACCES), a non-empty guest/ that appeared meanwhile (ENOTEMPTY, EEXIST)
            raise MigrationError(f"cannot rename {old} to {new}: {e.strerror}") from None
        return True
    finally:
        if node >= 0:
            os.close(node)
        os.close(lock)
