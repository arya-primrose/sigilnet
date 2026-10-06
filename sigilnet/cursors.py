"""Consumer cursors (DESIGN_node_daemon.md section 7): `home/cursors/<consumer>.json` = `{"gen": str, "seq": int}` (+ extras), 0600, written tmp+rename into a 0700
directory. Each reader of `inbox.jsonl` owns its cursor (two readers = two files). Missing = never seen (None); damaged = start from 0 (too many announcements, never too few)."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _path(home, consumer: str) -> Path:
    if not NAME_RE.match(consumer or ""):
        raise ValueError("a consumer name is 1-32 letters, digits, - or _")
    return Path(home) / "cursors" / f"{consumer}.json"


def load(home, consumer: str):
    """None if the cursor file does not exist; {"gen": None, "seq": 0} if it is damaged; else the dict."""
    p = _path(home, consumer)
    try:
        raw = p.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        return {"gen": None, "seq": 0}
    try:
        d = json.loads(raw)                                      # (bytes: a file that is not valid UTF-8 is a ValueError too, i.e. damaged = from 0)
        if not isinstance(d, dict) or not isinstance(d.get("gen"), str) or isinstance(d.get("seq"), bool) or not isinstance(d.get("seq"), int) or d["seq"] < 0:
            raise ValueError
    except ValueError:
        return {"gen": None, "seq": 0}
    return d


def save(home, consumer: str, gen: str, seq: int, **extra) -> None:
    p = _path(home, consumer)
    p.parent.mkdir(mode=0o700, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps({"gen": gen, "seq": seq, **extra}))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
