"""Local state of `wait` and the open [ASK]s (DESIGN_converse.md 3b): ONE small JSON file under <home>/wait/, 0600 in a 0700 dir, written atomically, guarded by an flock so two
`wait` processes (or `ask` + `wait`) never lose each other's update. A missing, unreadable or malformed file is rebuilt as empty (never an exception: `wait` must not crash on it);
every field is validated and bounded on load, a bad field resets only that field.

  threads : {thread id: {"mark": n, "tip": event id}}   high-water mark in the thread's ARRIVAL order (Thread.arrival): the first `mark` events are already reported; `tip` is the id at
            position mark-1, so a reordered/rebuilt arrival list is detected (see waitcmd.new_slice)
  asks    : [{"id", "thread", "to" (agent id or null), "at" (local time)}]  open asks I posted (<= MAX_ASKS, oldest dropped)
  reported: [ask ids already announced as overdue]
  wakes   : [local times of the last returns of `wait`]   (the hourly wake limit)
  held    : [{"thread", "id"}]  wake-worthy events found while the limit was reached: kept and listed, never dropped (<= MAX_HELD; `unread` stays the full record)
  seeded  : bool, True after the first completed scan (even with zero threads): only a state that was never seeded baselines its first threads (a home that ran `wait` before it held any
            thread must still report an [ASK] that arrives with its first thread)
  coalesced_at / reminded_at : local times (one COALESCED line per hour, one REMINDER per 10 min)"""
from __future__ import annotations

import fcntl
import json
import os
import re
import time
from pathlib import Path

MAX_ASKS = 200
MAX_REPORTED = 400
MAX_WAKES = 100
MAX_HELD = 1000
MAX_THREADS = 500
ID_RE = re.compile(r"[0-9a-f]{32}")


def _num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and x == x and x not in (float("inf"), float("-inf"))


def _id(x) -> bool:
    return isinstance(x, str) and ID_RE.fullmatch(x) is not None


def clean(d) -> dict:
    """Validate an arbitrary decoded JSON value into a state dict: every field checked, bad entries dropped."""
    out = {"threads": {}, "asks": [], "reported": [], "wakes": [], "held": [], "seeded": False, "coalesced_at": 0.0, "reminded_at": 0.0}
    if not isinstance(d, dict):
        return out
    th = d.get("threads")
    if isinstance(th, dict):
        for k, v in list(th.items())[:MAX_THREADS]:
            if _id(k) and isinstance(v, dict) and type(v.get("mark")) is int and v["mark"] >= 0 and (v.get("tip") is None or _id(v.get("tip"))):
                out["threads"][k] = {"mark": v["mark"], "tip": v.get("tip")}
    for a in (d.get("asks") if isinstance(d.get("asks"), list) else [])[-MAX_ASKS:]:
        if isinstance(a, dict) and _id(a.get("id")) and _id(a.get("thread")) and (a.get("to") is None or (isinstance(a.get("to"), str) and 0 < len(a["to"]) <= 64)) and _num(a.get("at")):
            out["asks"].append({"id": a["id"], "thread": a["thread"], "to": a.get("to"), "at": float(a["at"])})
    out["reported"] = [x for x in (d.get("reported") if isinstance(d.get("reported"), list) else []) if _id(x)][-MAX_REPORTED:]
    out["wakes"] = [float(x) for x in (d.get("wakes") if isinstance(d.get("wakes"), list) else []) if _num(x)][-MAX_WAKES:]
    for h in (d.get("held") if isinstance(d.get("held"), list) else [])[-MAX_HELD:]:
        if isinstance(h, dict) and _id(h.get("thread")) and _id(h.get("id")):
            out["held"].append({"thread": h["thread"], "id": h["id"]})
    out["seeded"] = d.get("seeded") is True
    for k in ("coalesced_at", "reminded_at"):
        out[k] = float(d[k]) if _num(d.get(k)) else 0.0
    return out


class WaitState:
    def __init__(self, home, clock=time.time):
        self.dir = Path(home) / "wait"
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path, self.lockp = self.dir / "state.json", self.dir / "lock"
        self.clock = clock
        self.rebuilt = False                                   # set when a file existed but could not be used

    def _read(self) -> dict:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return clean(None)
        except OSError:
            self.rebuilt = True
            return clean(None)
        try:
            d = json.loads(raw.decode("utf-8"))                # UnicodeDecodeError and JSONDecodeError are both ValueErrors
        except ValueError:
            self.rebuilt = True
            return clean(None)
        if not isinstance(d, dict):
            self.rebuilt = True
        return clean(d)

    def _write(self, st: dict) -> None:
        tmp = self.dir / f".tmp.{os.getpid()}.{os.urandom(4).hex()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(st, f, separators=(",", ":"))
        os.replace(tmp, self.path)

    def load(self) -> dict:
        with self.locked():
            return self._read()

    def locked(self):
        return _Lock(self.lockp)

    def update(self, fn) -> dict:
        """Read-modify-write under the lock; `fn(state)` mutates it in place. The result is re-validated before it is written (a bug in a caller cannot write junk), and nothing is
        written when the validated state equals what was read (an idle `wait` polling every 2 s must not rewrite the file 900 times an hour)."""
        with self.locked():
            st = self._read()
            before = json.dumps(st, sort_keys=True)
            fn(st)
            st = clean(st)
            if json.dumps(st, sort_keys=True) != before:
                self._write(st)
            return st


class _Lock:
    def __init__(self, p: Path):
        self.p = p

    def __enter__(self):
        self.fd = os.open(self.p, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        os.close(self.fd)
