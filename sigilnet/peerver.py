"""What each peer last declared of its protocol (version.py), kept next to the peer book in `peerver.json` (0600). A separate file on purpose: peers.json keeps the shape
every 0.1.x loader expects. A peer that answered a signed request WITHOUT a declaration is recorded as `legacy` (0.1.x or older): the explanation of an incompatibility
(DESIGN_versioning.md, stage 2) needs to know the difference between 'unknown yet' and 'old'. Never raises into the node: a damaged file reads as empty."""
import json
import os
import threading
import time
from pathlib import Path

from . import version as V

MAX_PEERS = 256
REFRESH = 6 * 3600                 # `seen` is rewritten at most this often when nothing else changed
REFUSE_GAP = 600                   # a refusal is recorded at most once per peer per 10 minutes, whatever the text (it carries the peer's own declared wire and sw)
MIN_REWRITE = 60                   # and an entry is never rewritten more often than this (a known peer alternating two valid declarations must not force a write per request)


def _refused(r):
    """{'at': int, 'why': printable str <= 200} or None: the last time WE refused this peer (the text it was given)."""
    if isinstance(r, dict) and type(r.get("at")) is int and isinstance(r.get("why"), str) and 0 < len(r["why"]) <= 200 and r["why"].isprintable():
        return {"at": r["at"], "why": r["why"]}
    return None


class PeerVer:
    def __init__(self, path: Path, clock=time.time):
        self.path, self.clock = Path(path), clock
        self.mu = threading.Lock()
        self.d: dict = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text())
            peers = raw.get("peers", {}) if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            peers = {}
        out = {}
        for a, e in (peers.items() if isinstance(peers, dict) else []):
            if not (isinstance(a, str) and len(a) == 32 and isinstance(e, dict)) or len(out) >= MAX_PEERS:
                continue
            seen = e.get("seen")
            if type(seen) is not int:
                continue
            ref = _refused(e.get("refused"))
            if e.get("legacy") is True:
                out[a] = {"legacy": True, "seen": seen, **({"refused": ref} if ref else {})}
                continue
            d = V.parse_decl(e)
            if d:
                out[a] = {**d, "legacy": False, "seen": seen, **({"refused": ref} if ref else {})}
        self.d = out

    def get(self, agent: str):
        """{'wire','majors','formats','sw','legacy','seen'} or None (never heard)."""
        with self.mu:
            e = self.d.get(agent)
            return dict(e) if e else None

    def decl_of(self, agent: str):
        """The peer's declaration for negotiate(): a dict, or None = undeclared (legacy or never heard)."""
        e = self.get(agent)
        return {k: e[k] for k in ("wire", "majors", "formats", "sw")} if e and not e["legacy"] else None

    def note(self, agent: str, decl, *, legacy: bool = False) -> None:
        """Record what a peer declared (`decl`, already parse_decl'ed) or, with legacy=True, that it answered without declaring."""
        if not isinstance(agent, str) or len(agent) != 32:
            return
        now = int(self.clock())
        with self.mu:
            old = self.d.get(agent)
            if decl is not None:
                new = {**decl, "legacy": False, "seen": now}
            elif legacy:
                new = {"legacy": True, "seen": now}
            else:
                return
            if old is not None and 0 <= now - old["seen"] < MIN_REWRITE:
                return
            if old is not None and old.get("refused"):
                new["refused"] = old["refused"]                         # (what we last told this peer survives a new declaration)
            same = old is not None and {k: v for k, v in old.items() if k != "seen"} == {k: v for k, v in new.items() if k != "seen"}
            if same and now - old["seen"] < REFRESH:
                return
            if old is None and len(self.d) >= MAX_PEERS:
                return
            self.d[agent] = new
            self._save()

    def refused_count(self, now: float, window: float = 7 * 86400) -> int:
        with self.mu:
            return sum(1 for e in self.d.values() if e.get("refused") and 0 <= now - e["refused"]["at"] < window)

    def refuse(self, agent: str, why: str, decl=None) -> None:
        """Record that we refused this peer (version.refusal) with `why`: at most one write per peer per REFUSE_GAP whatever the text, and the same text not more than once a day. `decl`
        = the declaration the refused request carried (already parse_decl'ed): it is recorded, so a peer that declared wire 7.0 is not shown as 0.1.x. A peer we know nothing else about
        and that declared nothing becomes `legacy` (a request without a declaration is what a 0.1.x node sends)."""
        if not isinstance(agent, str) or len(agent) != 32 or not isinstance(why, str):
            return
        why = "".join(c if c.isprintable() else "?" for c in why)[:200]
        now = int(self.clock())
        with self.mu:
            old = self.d.get(agent)
            if old is not None and old.get("refused"):
                gap = now - old["refused"]["at"]
                if 0 <= gap < REFUSE_GAP or (old["refused"]["why"] == why and 0 <= gap < 86400):
                    return
            if old is None and len(self.d) >= MAX_PEERS:
                return
            if decl is not None:
                base = {**decl, "legacy": False, "seen": now}
            else:
                base = old if old is not None else {"legacy": True, "seen": now}
            self.d[agent] = {**base, "refused": {"at": now, "why": why}}
            self._save()

    def prune(self, keep) -> None:
        with self.mu:
            gone = [a for a in self.d if a not in keep]
            for a in gone:
                del self.d[a]
            if gone:
                self._save()

    def _save(self) -> None:
        try:
            tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump({"v": 1, "peers": self.d}, fh, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            pass                                                        # a version cache that cannot be written never fails the node
