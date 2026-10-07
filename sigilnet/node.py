"""The node: what keeps a mirror in step with its peers over a transport that may be slow, offline or down for an hour (spec 7.6, step 3).

Sync itself is PULL (sync.py). Around it the node keeps, persistently:
  * a PEER BOOK (`peers.json`): who we talk to, at which endpoint ({type, addr}, carrier.py); a thread is synced with a peer when that peer is a current member of it in OUR mirror
    (plus threads named explicitly, e.g. a public thread we want to read);
  * JOBS per (peer, thread): `pull` (anti-entropy: every PULL_INTERVAL and whenever a notify hint says the peer has news) and `notify` (the OUTBOX: a hint that
    WE have news, retried until the peer acknowledged it or it is older than NOTIFY_TTL). Both back off exponentially with jitter after a failure (a peer that
    is down for an hour costs one cheap attempt every BACKOFF_MAX), a failure that waiting cannot fix (we are not authorized) backs off at the maximum and is
    shown as BLOCKED. A restarted node starts every job at once, so catching up after a restart or a peer's return takes one round trip, not a timeout.
Nothing here decides validity: every event still goes through Mirror.ingest and the thread rules. A notify is only a hint and can at worst make us pull
from a peer that is already a member of the thread (at most PULL_BURST pulls at once, then PULL_REFILL per second, per peer and thread)."""
from __future__ import annotations

import fcntl
import json
import math
import os
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import event as E
from . import sync as S
from .keys import AGENT_ID_RE, Identity, is_hex
from .mirror import Mirror
from .carrier import CarrierError, NoCarrierUp, check_endpoint, endpoints_of
from . import locators as L

PULL_INTERVAL = 300.0          # anti-entropy: pull every peer this often even without a hint
BACKOFF_BASE = 15.0            # first retry after a failure
BACKOFF_MAX = 900.0            # never wait longer than this between attempts (a peer that comes back is found within ~15 min)
BLOCKED_DELAY = 900.0          # a failure that waiting cannot fix (not authorized)
NOTIFY_TTL = 24 * 3600.0       # an unacknowledged hint older than this is dropped (anti-entropy covers it)
PULL_BURST = 3                 # a hint makes the pull due at once; a known peer can do that this many times in a row for one (peer, thread) ...
PULL_REFILL = 1.0              # ... and then once per 1/PULL_REFILL seconds (token bucket, in memory)
CLEAR_EVERY = 60.0             # a hint ends a peer's unreachable backoff at most this often
JITTER = 0.2
MAX_PEERS = 64
MAX_ENDPOINTS = 8              # carrier types one peer record can hold an endpoint for
MAX_JOBS = 4096
WORKERS = 4
NEVER = 10 ** 12               # "nothing scheduled" (kept as a number so the state file stays plain JSON)
LOCATOR_WAIT = 15.0            # default wait between dial cycles when a peer has several addresses and every one failed (a carrier says its own: Carrier.retry_wait)
FOLLOW_WAIT = 20.0             # we told a peer about news and it acknowledged: if it has not come to pull within this long (it may be unable to dial us: outbound-only), WE pull it, which pushes
RATE_RETRIES = 3               # a peer that answers "rate limited": wait a few seconds, then back off like any other failure (the pull default waits a minute)


MAX_TRIES = 10 ** 6            # the failure count saturates here (and its exponent below): arithmetic must stay total over a 3-week outage
MAX_EXP = 30
HORIZON = 1.3 * max(PULL_INTERVAL, BACKOFF_MAX, BLOCKED_DELAY) + 1     # no job is ever scheduled further ahead than this (a clock that stepped back cannot freeze it)


def jittered(base: float, rng) -> float:
    return base * (1 + JITTER * (2 * rng.random() - 1))


def backoff(tries: int, rng) -> float:
    tries = min(max(0, int(tries)), MAX_TRIES)
    return min(BACKOFF_MAX, jittered(min(BACKOFF_MAX, BACKOFF_BASE * 2 ** min(max(0, tries - 1), MAX_EXP)), rng))     # jitter never pushes past the cap


def clean(x, limit: int = 200) -> str:
    """Text that came from a peer (or anywhere else we do not control) before it is stored, logged or printed: printable characters only."""
    t = x if isinstance(x, str) else repr(x)
    return "".join(c if c.isprintable() else "?" for c in t)[:limit]


def _num(x, lo: float, hi: float, default: float) -> float:
    """A number from a file we do not fully trust: real int/float, finite, in range; anything else is the default."""
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x):
        return default
    return min(max(x, lo), hi)


def _atomic(path: Path, data: dict) -> None:
    """Write-then-rename with a unique temp file created fresh (O_EXCL, never through a symlink or onto a stale file; a name that happens to exist is skipped)."""
    for _ in range(5):
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            break
        except FileExistsError:
            continue
    else:
        raise OSError("cannot create a temporary file next to " + path.name)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load(path: Path) -> dict:
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            return {}
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError, RecursionError):
        return {}


def valid_port(p):
    """An int 1..65535 (a digit string is accepted); otherwise None. Never raises."""
    if isinstance(p, bool):
        return None
    if isinstance(p, str) and p.isascii() and p.isdigit() and len(p) <= 5:
        p = int(p)
    return p if isinstance(p, int) and 0 < p < 65536 else None


class PeerBook:
    """peers.json: agent id -> {name, endpoints ([{type, addr}], one per carrier type, the primary first; [] = the peer dials us), threads}. A record from before M1a has one
    `endpoint` instead: it reads as a list of one and is rewritten as `endpoints` the next time the record is edited. Records handed out by `all()` carry `endpoints` and, for display
    only, `endpoint` (the primary); code that decides anything reads `carrier.endpoints_of(rec)` / `endpoint_of(rec, type)`. In a record that has `endpoints`, a stale old `endpoint` key is ignored
    (`endpoints` wins, even when it is []). A peer whose endpoint is malformed or of a type no carrier here knows STAYS a peer (known to the sync server, pingable) with that endpoint left out
    of the view; the file keeps it. To disable a peer use `peer rm`; breaking its endpoint by hand no longer does it. Edited by the CLI, read by the node (reloaded on every tick).
    Reading is tolerant (a bad record is skipped, never fatal); editing changes ONLY the record it is about and keeps everything else in the file as it
    was, under a file lock, so two edits at once lose nothing."""

    def __init__(self, path):
        self.path = Path(path)

    def _raw(self) -> dict:
        raw = _load(self.path).get("peers", {})
        return raw if isinstance(raw, dict) else {}

    @staticmethod
    def _raw_endpoints(p) -> list:
        """The endpoints a raw record holds, in order, one per type (the first of a type wins), shape-checked only: an endpoint of a type no carrier in THIS process knows is kept
        (a CLI that did not load the Tor module must not lose an onion address when it edits the record)."""
        raw = p.get("endpoints") if isinstance(p.get("endpoints"), list) else ([p["endpoint"]] if p.get("endpoint") is not None else [])
        out, seen = [], set()
        for e in raw:
            if isinstance(e, dict) and set(e) == {"type", "addr"} and isinstance(e["type"], str) and isinstance(e["addr"], str) and e["type"] not in seen and len(out) < MAX_ENDPOINTS:
                seen.add(e["type"])
                out.append({"type": e["type"], "addr": e["addr"]})
        return out

    def all(self) -> dict:
        out = {}
        for aid, p in self._raw().items():
            if len(out) >= MAX_PEERS:
                break
            try:
                if not (isinstance(aid, str) and AGENT_ID_RE.fullmatch(aid) and isinstance(p, dict)):
                    continue
                eps = []
                for e in self._raw_endpoints(p):
                    try:
                        if check_endpoint(e) == e:
                            eps.append(e)
                    except ValueError:
                        continue                                   # (an endpoint of a type no carrier here supports is left out of the view, never fatal; the peer and its other endpoints stay)
                th = p.get("threads", [])
                out[aid] = {"name": clean(p.get("name", ""), 32), "endpoints": eps, "endpoint": eps[0] if eps else None, "agent": aid,
                            "threads": [t for t in (th if isinstance(th, list) else []) if isinstance(t, str) and is_hex(t, 32)][:64]}
            except (AttributeError, TypeError, ValueError):
                continue
        return out

    def _edit(self, fn) -> bool:
        lock = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            data = _load(self.path)
            raw = data.get("peers") if isinstance(data.get("peers"), dict) else {}
            changed = fn(raw)
            if changed:
                data["peers"] = raw
                _atomic(self.path, data)
            return changed
        finally:
            os.close(fd)

    def add(self, agent: str, name: str, endpoint: dict | None, threads=()) -> None:
        """Add or update a peer: name and threads are replaced; the endpoint is ADDED: it becomes the primary and replaces the endpoint of its own carrier type, the endpoints of the
        other types stay (a second `peer add` with the other carrier's address does not overwrite the first). endpoint=None leaves the endpoints as they are ([] for a new peer)."""
        if not isinstance(agent, str) or not AGENT_ID_RE.fullmatch(agent):
            raise ValueError("bad agent id")
        if endpoint is not None:
            endpoint = check_endpoint(endpoint)
        threads = list(threads)
        if any(not (isinstance(t, str) and is_hex(t, 32)) for t in threads):
            raise ValueError("a thread id is 32 hex characters")

        prev_types: list = []

        def fn(raw):
            if agent not in raw and len(raw) >= MAX_PEERS:
                raise ValueError("too many peers")
            old = self._raw_endpoints(raw[agent]) if isinstance(raw.get(agent), dict) else []
            prev_types[:] = [e["type"] for e in old]
            eps = old if endpoint is None else ([endpoint] + [e for e in old if e["type"] != endpoint["type"]])[:MAX_ENDPOINTS]
            raw[agent] = {"name": clean(name, 32), "endpoints": eps, "threads": sorted(set(threads))[:64]}
            return True
        self._edit(fn)
        if endpoint is not None:                                   # an explicit address (the human, a capsule): the locator book dials it first (DESIGN_locator_book.md)
            try:
                book = L.open_book(self.path.parent, endpoint["type"])
                new_carrier = bool(prev_types) and endpoint["type"] not in prev_types and book.count(agent) == 0
                book.seed(agent, endpoint["addr"], front=not new_carrier)       # the FIRST address of an additional carrier is not evidence of contact: the carrier that last worked stays first until the new one proves itself
            except (ValueError, OSError):
                pass                                               # (the book is a cache of where the peer lives: a failure here must not fail the add)

    def invite(self, agent: str, threads) -> bool:
        """Add thread ids to an EXISTING peer's invitations (the threads we sync with it even if we do not hold them yet); the endpoint, the name and the other threads are untouched.
        True if something was added. (What `sigilnet rotate` asks every other member to run, DESIGN_retention.md.)"""
        threads = list(threads)
        if any(not (isinstance(t, str) and is_hex(t, 32)) for t in threads):
            raise ValueError("a thread id is 32 hex characters")

        def fn(raw):
            rec = raw.get(agent)
            if not isinstance(rec, dict):
                raise ValueError("no such peer")
            cur = rec.get("threads") if isinstance(rec.get("threads"), list) else []
            new = sorted(set(t for t in cur if isinstance(t, str) and is_hex(t, 32)) | set(threads))
            if len(new) > 64:
                raise ValueError("too many invitations for one peer (64)")
            auto = rec.get("auto") if isinstance(rec.get("auto"), dict) else {}
            flipped = [t for t in threads if t in auto]            # a hand invitation for a thread an automatic follow added: it is MANUAL from now on (never removed by the verification or the expiry)
            for t in flipped:
                del auto[t]
            if flipped:
                if auto:
                    rec["auto"] = auto
                else:
                    rec.pop("auto", None)
            if set(new) == set(cur):
                return bool(flipped)
            rec["threads"] = new
            return True
        return self._edit(fn)

    # ---- automatic follows (autorotate.py): `auto` = {thread id: {"at", "owner", "old"}} in a peer record marks the invitations the NODE added by itself, so that only those can be removed again
    def follow_auto(self, agents, tid: str, owner: str, old: str, now: float) -> list:
        """Invite each of `agents` to `tid` as an AUTOMATIC follow (not for one that already has it, automatic or by hand). The agents that were changed."""
        if not (isinstance(tid, str) and is_hex(tid, 32)):
            raise ValueError("a thread id is 32 hex characters")
        done = []

        def fn(raw):
            for agent in agents:
                rec = raw.get(agent)
                if not isinstance(rec, dict):
                    continue
                cur = rec.get("threads") if isinstance(rec.get("threads"), list) else []
                if tid in cur or len(cur) >= 64:
                    continue
                auto = rec.get("auto") if isinstance(rec.get("auto"), dict) else {}
                auto[tid] = {"at": float(now), "owner": owner, "old": old}
                rec["threads"], rec["auto"] = sorted(set(cur) | {tid}), auto
                done.append(agent)
            return bool(done)
        self._edit(fn)
        return done

    def auto_entries(self) -> list:
        """[(agent id, thread id, {"at", "owner", "old"})] for every automatic follow still unresolved."""
        out = []
        for aid, rec in self._raw().items():
            auto = rec.get("auto") if isinstance(rec, dict) and isinstance(rec.get("auto"), dict) else {}
            for tid, info in auto.items():
                if isinstance(tid, str) and is_hex(tid, 32) and isinstance(info, dict) and isinstance(info.get("owner"), str):
                    out.append((aid, tid, {"at": _num(info.get("at"), 0, 1e13, 0.0), "owner": info["owner"], "old": info.get("old") if isinstance(info.get("old"), str) else ""}))
        return out

    def settle_auto(self, tid: str, keep: bool) -> int:
        """The automatic follows of `tid` are resolved: keep=True makes them ordinary invitations (verified), keep=False removes them (an invitation added by hand is never touched). Records changed."""
        n = [0]

        def fn(raw):
            for rec in raw.values():
                auto = rec.get("auto") if isinstance(rec, dict) and isinstance(rec.get("auto"), dict) else {}
                if tid not in auto:
                    continue
                del auto[tid]
                if not auto:
                    rec.pop("auto", None)
                if not keep and isinstance(rec.get("threads"), list):
                    rec["threads"] = [t for t in rec["threads"] if t != tid]
                n[0] += 1
            return n[0] > 0
        self._edit(fn)
        return n[0]

    def remove(self, agent: str) -> bool:
        gone = self._edit(lambda raw: raw.pop(agent, None) is not None)
        d = self.path.parent / "locators"
        try:
            names = [f.name[:-5] for f in d.iterdir() if f.name.endswith(".json")] if d.is_dir() else []
        except OSError:
            names = []
        for etype in names:
            try:
                L.open_book(self.path.parent, etype).remove(agent)
            except (ValueError, OSError):
                pass
        return gone


REFUSAL_LOG_GAP = 3600                              # one history line per refused peer per hour

class Node:
    """`transport_for(peer_record) -> object with request(dict)` (a carrier's dial in production, loopback/fakes in tests). `clock` and `rng` are injectable."""

    def __init__(self, mirror: Mirror, me: Identity, peers: PeerBook, state_path, transport_for, *, clock=time.time, rng=None,
                 pull_interval: float = PULL_INTERVAL, log=None, locators=None, retry_wait: float = LOCATOR_WAIT, notify_field=None, notify_to=None):
        self.m, self.me, self.peers, self.transport_for = mirror, me, peers, transport_for
        self.notify_field = notify_field                           # callable(peer id) -> {"type", "addr"} or None: where WE want this peer to notify us (M4b: our peer door for that peer on the notify carrier); None = no field is sent
        self.notify_to = notify_to                                 # callable(peer record) -> NotifyPath or None: the notify address THIS peer asked for (locators.NotifyDialer); None = the pull addresses only, as before
        self.locators, self.retry_wait = locators, retry_wait       # locators: the carrier's LocatorBook (a peer with 2+ addresses is retried per DESIGN_locator_book.md 3.3); None = one address per peer
        self.state_path, self.clock, self.rng = Path(state_path), clock, rng or random.Random()
        self.pull_interval, self.log = pull_interval, log or (lambda *a: None)
        self.mu = threading.RLock()
        self.busy: set = set()                                     # peers with a job in flight (single flight per peer)
        self.jobs: dict = {}
        self._cleared: dict = {}
        self._tokens: dict = {}                                    # (peer, thread) -> [tokens, time of the last refill]: the hint rate limit
        self.wake = threading.Event()                              # set when the loop should run a round now (noderun hands it to the Waker)
        self._executor = None
        self._queued: set = set()                                  # (peer, thread, kind) submitted and not finished: never queued twice
        self.down: dict = {}                                       # peer -> {"tries", "until", "err", "blocked"}: the peer itself cannot be reached
        self.sigs: dict = {}                                       # thread -> signature of its leaves when we last told the peers
        self._wanted: set = set()
        self._snap_wanted = False                                  # set by pong_for: somebody pinged, so the next round recomputes
        self._snap: dict | None = None                             # the pong snapshot (ping.py): refreshed by the loop, read lock-free by the server
        self.pongs: dict = {}                                      # peer -> {"last_pong", "unread", "watching"}: what its last pong said (node.json)
        self.nopush: dict = {}                                     # peer -> until: it answered a push with a type-level error (an old node): not pushed to until then (memory only)
        self.push_off: dict = {}                                   # (peer, thread) -> until: it does not have the thread / does not take our pushes, or asked us to wait
        self.push_held: dict = {}                                  # (peer, thread) -> {"head", "rej": ids, "park": {id: until}}: events it answered rejected / parked / unopened (P4)
        self.pushes: dict = {}                                     # (peer, thread) -> text of the last push (status)
        self.heard_from = None                                     # callable(peer) -> time of its last sync request to us (SyncServer.heard), or None = never / unknown; None here = no follow-up pulls
        self._follow: dict = {}                                    # (peer, thread) -> (due, when its notify was acknowledged)
        self.rot = None                                            # autorotate.AutoRotator (noderun wires it): its slow tick runs from `tick`
        self._refused_at: dict = {}                                # peer -> when we last logged a refusal of it
        self.pv = None                                             # peerver.PeerVer (noderun wires it): what each peer declared of its protocol (version.py); a cache, never a gate in stage 1
        self._pv_pruned = 0.0
        self._load_state()

    # ------------------------------------------------------------ state
    def _load_state(self) -> None:
        """A state file we wrote ourselves, but tolerate anything: a torn, truncated or hand-edited file must never stop the node from starting."""
        st = _load(self.state_path)
        now = self.clock()
        down = st.get("down", {})
        for p, d in (down.items() if isinstance(down, dict) else []):
            if isinstance(p, str) and AGENT_ID_RE.fullmatch(p) and isinstance(d, dict) and len(self.down) < MAX_PEERS:
                self.down[p] = {"tries": int(_num(d.get("tries"), 0, MAX_TRIES, 0)), "until": now, "err": clean(d.get("err", "")), "blocked": d.get("blocked") is True}
        pongs = st.get("pongs", {})
        for p, d in (pongs.items() if isinstance(pongs, dict) else []):
            if isinstance(p, str) and AGENT_ID_RE.fullmatch(p) and isinstance(d, dict) and len(self.pongs) < MAX_PEERS:
                self.pongs[p] = {"last_pong": _num(d.get("last_pong"), 0, 1e13, 0.0), "unread": int(_num(d.get("unread"), 0, 10 ** 9, 0)), "watching": d.get("watching") is True}
        jobs = st.get("jobs", {})
        for k, j in (jobs.items() if isinstance(jobs, dict) else []):
            if len(self.jobs) >= MAX_JOBS:
                break
            parts = k.split("/") if isinstance(k, str) else []
            if not (isinstance(j, dict) and len(parts) == 3 and AGENT_ID_RE.fullmatch(parts[0]) and is_hex(parts[1], 32) and parts[2] in ("pull", "notify")):
                continue
            # a restarted node tries everything at once (a hint or a pull costs one round trip), but keeps the history of failures
            ok, since = j.get("ok"), j.get("since")
            self.jobs[k] = {"next": now, "tries": int(_num(j.get("tries"), 0, MAX_TRIES, 0)), "err": clean(j.get("err", "")),
                            "ok": _num(ok, 0, 1e13, None) if ok is not None else None, "since": _num(since, 0, 1e13, None) if since is not None else None,
                            "blocked": j.get("blocked") is True}

    def _save(self) -> None:
        with self.mu:
            _atomic(self.state_path, {"jobs": self.jobs, "down": self.down, "pongs": self.pongs})

    # ------------------------------------------------------------ ping / pong (ping.py)
    def pong_snapshot(self, *, force: bool = False) -> dict:
        """{"unread": {peer agent: n}, "watching": bool, "at": t}: for every peer in the book, the unread events in the threads THAT peer is a current member of (never a global
        count). Recomputed (under the Mirror lock) at most every SNAPSHOT_EVERY seconds; the server reads `cached_snapshot()` and never touches the lock."""
        from . import ping as P
        now = self.clock()
        with self.mu:
            snap = self._snap
            if snap is not None and not force and 0 <= now - snap["at"] < P.SNAPSHOT_EVERY:
                return snap
        unread = {a: 0 for a in self.peers.all() if a != self.me.id}
        with self.m._lock():
            for tid, t in self.m.threads.items():
                members = t.state()["members"]
                who = [a for a in unread if a in members]
                if who:
                    n = len(self.m.unread(tid, self.me.id))
                    for a in who:
                        unread[a] += n
        snap = {"unread": unread, "watching": P.watching(self.state_path.parent, now), "at": now}
        with self.mu:
            self._snap = snap
        return snap

    def refresh_snapshot(self) -> dict | None:
        """Called by the loop each round: recompute (O(events) under the Mirror lock) only if the first snapshot is missing, a ping asked since the last refresh (`pong_for`), or the
        snapshot is older than SNAPSHOT_MAX_AGE. An idle node with a big mirror does not pay for pings nobody sends; an answer is at most one round stale."""
        from . import ping as P
        with self.mu:
            snap, wanted, self._snap_wanted = self._snap, self._snap_wanted, False
        if snap is None or wanted or not 0 <= self.clock() - snap["at"] < P.SNAPSHOT_MAX_AGE:
            return self.pong_snapshot()
        return snap

    def cached_snapshot(self) -> dict:
        with self.mu:
            return self._snap if self._snap is not None else {"unread": {}, "watching": False, "at": 0.0}

    def pong_for(self, requester: str):
        """The `pong=` callable of the SyncServer: lock-free (cached snapshot only)."""
        from . import ping as P
        self._snap_wanted = True                                   # (a plain flag: the loop refreshes at its next round)
        snap = dict(self.cached_snapshot())
        snap["watching"] = P.watching(self.state_path.parent, self.clock())      # live: one lstat, no lock (the unread counts come from the snapshot)
        return P.handle_ping(snap, requester)

    def note_pong(self, peer: str, pong: dict) -> None:
        with self.mu:
            if peer not in self.pongs and len(self.pongs) >= MAX_PEERS:
                return
            self.pongs[peer] = {"last_pong": self.clock(), "unread": int(pong["unread"]), "watching": bool(pong["watching"])}
        self._save()

    @staticmethod
    def _key(peer: str, tid: str, kind: str) -> str:
        return f"{peer}/{tid}/{kind}"

    def _job(self, peer: str, tid: str, kind: str) -> dict:
        k = self._key(peer, tid, kind)
        j = self.jobs.get(k)
        if j is None:
            j = self.jobs[k] = {"next": self.clock(), "tries": 0, "err": "", "ok": None, "since": self.clock() if kind == "notify" else None, "blocked": False}
        return j

    # ------------------------------------------------------------ what to sync with whom
    def _plan(self) -> dict:
        """{peer agent id: {"rec": peer record, "threads": set of thread ids}} for every peer we hold an address for (an endpoint in the record, or an address in the locator book)."""
        plan = {}
        for aid, rec in self.peers.all().items():
            if aid == self.me.id or not (endpoints_of(rec) or (self.locators is not None and self.locators.count(aid))):
                continue
            tids = set(t for t in rec["threads"])
            for tid, t in list(self.m.threads.items()):
                if aid in t.state()["members"]:
                    tids.add(tid)
            plan[aid] = {"rec": rec, "threads": tids}
        self._wanted = {t for p in plan.values() for t in p["threads"]}
        self.m.follow = lambda g: E.event_id(g) in self._wanted      # a pull may only ever CREATE a thread we named
        return plan

    def _signature(self, tid: str) -> tuple:
        t = self.m.threads[tid]
        return (t.head, tuple(t.leaves()))

    # ------------------------------------------------------------ hints we receive
    def _token(self, agent: str, tid: str, now: float) -> float:
        """Spend one pull token for (agent, tid): 0.0 if one was available, else the seconds until the next one."""
        if len(self._tokens) > MAX_JOBS:                           # only full buckets hold no information
            full = [k for k, (n, t) in self._tokens.items() if n + (now - t) * PULL_REFILL >= PULL_BURST]
            for k in full:
                del self._tokens[k]
        n, t = self._tokens.get((agent, tid), (float(PULL_BURST), now))
        n = min(float(PULL_BURST), n + max(0.0, now - t) * PULL_REFILL)
        if n >= 1.0:
            self._tokens[(agent, tid)] = (n - 1.0, now)
            return 0.0
        self._tokens[(agent, tid)] = (n, now)
        return (1.0 - n) / PULL_REFILL

    def on_notify(self, agent: str, tid: str, leaves: list) -> None:
        """A member says it has news. It is also proof that the peer is reachable (whatever backoff we had for it is over); if the hint names something
        we do not hold, make the pull due now (a token bucket per peer and thread bounds a flood of hints) and wake the loop."""
        with self.mu:
            if agent not in self.peers.all():
                return
            now = self.clock()
            made_due = False
            if agent in self.down and now - self._cleared.get(agent, -1e18) >= CLEAR_EVERY:   # (a flood of hints cannot force a stream of attempts)
                self._cleared[agent] = now
                del self.down[agent]
                for k, j in self.jobs.items():
                    if k.startswith(agent + "/"):
                        j["next"] = min(j["next"], self.clock())
                        made_due = True
            t = self.m.threads.get(tid)
            if t is None or not all(i in t.stored for i in leaves):
                j = self._job(agent, tid, "pull")
                j["next"] = min(j["next"], now + self._token(agent, tid, now))
                made_due = made_due or j["next"] <= now
            if made_due:
                self.wake.set()

    def address_changed(self, agent: str) -> None:
        """A new address of `agent` was VERIFIED (locators.LocatorService): whatever backoff its old, dead address earned is over, so every job for it is due now and goes to the new one."""
        with self.mu:
            self.down.pop(agent, None)
            now = self.clock()
            for k, j in self.jobs.items():
                if k.startswith(agent + "/"):
                    j["next"] = min(j["next"], now)
        self.wake.set()

    # ------------------------------------------------------------ one round
    def tick(self, parallel: bool = False) -> int:
        """Detect local changes, run every due job once. Returns how many jobs ran."""
        self.m.refresh()                                           # events the CLI appended since the last tick
        plan = self._plan()
        now = self.clock()
        if self.rot is not None:
            self.rot.tick(now, plan)                               # (never raises, never waits for the mirror lock)
        if self.pv is not None and now - self._pv_pruned > 3600:
            self._pv_pruned = now
            try:
                self.pv.prune(set(self.peers.all()))               # (forget peers that left the book)
            except Exception:                                       # noqa: BLE001
                pass
        with self.mu:
            for j in self.jobs.values():                           # a clock that stepped BACK must not freeze the schedule: such a job is due now
                if NEVER > j["next"] > now + HORIZON:
                    j["next"] = now
            for d in self.down.values():
                if d["until"] > now + HORIZON:
                    d["until"] = now
            self._drop_stale_backoffs(now)
            for aid, p in plan.items():
                for tid in p["threads"]:
                    self._job(aid, tid, "pull")
                    if tid in self.m.threads and self.sigs.get(tid) != self._signature(tid):       # we have news (or this is the first round): tell the peer
                        j = self._job(aid, tid, "notify")
                        j["next"], j["since"] = now, j["since"] or now
            for tid in self.m.threads:
                self.sigs[tid] = self._signature(tid)
            for (fp, ft), (due, since) in list(self._follow.items()):          # a notify was acknowledged: did the peer come to pull?
                if due > now:
                    continue
                del self._follow[(fp, ft)]
                heard = self.heard_from(fp) if self.heard_from is not None else None
                if fp in plan and ft in plan[fp]["threads"] and self._may_push(ft) and (heard is None or heard < since):
                    j = self._job(fp, ft, "pull")                              # it did not: pull it ourselves (the push that follows a pull carries what it lacks)
                    j["next"] = min(j["next"], now)
            live = {self._key(a, t, k) for a, p in plan.items() for t in p["threads"] for k in ("pull", "notify")}
            for k in [k for k in self.jobs if k not in live]:
                del self.jobs[k]                                   # peer or thread gone from the plan
            due = [(k, j) for k, j in self.jobs.items() if j["next"] <= now]
        due.sort(key=lambda kj: kj[1]["next"])
        ran = 0
        work = []
        for k, j in due:
            peer, tid, kind = k.split("/")
            if kind == "notify" and tid not in self.m.threads:
                continue
            work.append((peer, tid, kind, plan.get(peer)))
        if parallel:                                               # do NOT wait: a slow exchange with one peer must not stall the loop (or the other peers)
            for w in work:
                key = (w[0], w[1], w[2])
                with self.mu:
                    if key in self._queued:
                        continue
                    self._queued.add(key)
                self._pool().submit(self._run_queued, key, *w)
                ran += 1
        else:
            for w in work:
                self._run(*w)
                ran += 1
        self._save()
        return ran

    def _pool(self) -> ThreadPoolExecutor:
        with self.mu:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(WORKERS)
            return self._executor

    def _run_queued(self, key, peer: str, tid: str, kind: str, info) -> None:
        try:
            self._run(peer, tid, kind, info)
        finally:
            with self.mu:
                self._queued.discard(key)

    def close(self) -> None:
        """Stop taking work; exchanges already running finish or time out on their own."""
        with self.mu:
            ex, self._executor = self._executor, None
        if ex is not None:
            ex.shutdown(wait=False, cancel_futures=True)

    def _run(self, peer: str, tid: str, kind: str, info) -> None:
        if info is None:
            return
        with self.mu:
            if peer in self.busy:                                  # one exchange per peer at a time (Tor circuits are slow; be gentle)
                return
            if self._backed_off(peer):
                return                                             # the peer itself was unreachable: every job for it waits for the same backoff
            self.busy.add(peer)
            j = self._job(peer, tid, kind)
            j["started"] = self.clock()
        outcome = (False, "internal error", True, False, "")       # (ok, why, retry, unreachable, note); exactly ONE outcome is recorded per run
        try:
            tr = self.transport_for(info["rec"])
            if kind == "pull":
                res = S.pull(self.m, tid, tr, self.me, peer_id=peer, deadline=S.PULL_DEADLINE, stamp=self.clock, rate_retries=RATE_RETRIES, notify_at=self._notify_at(peer))
                for _ in range(3):                                     # envelopes for epochs whose key we lack: ask THIS peer, then pull again (each round can reveal the next epoch)
                    if not (res.get("need_keys") and tid in self.m.threads):
                        break
                    got = S.fetch_keys(self.m, tid, tr, self.me, peer_id=peer, need=res["need_keys"], unopened=res["unopened"], stamp=self.clock)
                    self.log(peer[:8], tid[:8], "key", f"installed {got['installed']}" if got["ok"] else f"FAIL {got['why']}")
                    if not got["installed"]:
                        res["ok"], res["why"], res["retry"] = False, "need keys the peer did not give", True
                        break
                    res = S.pull(self.m, tid, tr, self.me, peer_id=peer, deadline=S.PULL_DEADLINE, stamp=self.clock, rate_retries=RATE_RETRIES, notify_at=self._notify_at(peer))
                if self.pv is not None and res.get("peer_seen"):
                    self.pv.note(peer, res.get("peer_ver"), legacy=res.get("peer_ver") is None)    # (a signed successful answer: it declared its protocol, or it is 0.1.x)
                ok, why, retry = res["ok"], res["why"], res.get("retry", True)
                if not ok and why == "unknown":                    # an invited peer that has not fetched the thread yet (or does not share it): try again later, quietly
                    outcome = (True, "", True, False, "peer does not have this thread (yet)")
                else:
                    if ok and res["resolved"] and tid in self.m.threads:
                        self._after_pull(tid, peer)
                    if ok and tid in self.m.threads:
                        self._push(peer, tid, tr, res)                 # (M4a: offer what the peer's listing lacks; never fails or changes the outcome of the pull)
                    outcome = (ok, why, retry, bool(res.get("unreachable")), "")
            else:
                ans, bad = self._notify_at_address(peer, info["rec"], tid)
                if ans is None:                                    # (no notify address of this peer, or it did not work: the pull addresses, exactly as before)
                    ans = S.notify(tr, self.me, tid, self.m, peer_id=peer, stamp=self.clock, raise_errors=True, detail=True, notify_at=self._notify_at(peer))
                    if bad is not None and ans in ("ok", "unknown"):
                        bad.done(False)                            # the peer IS reachable by its pull addresses, so the notify address is what failed
                if ans == "ok" and self.heard_from is not None:
                    with self.mu:
                        self._follow[(peer, tid)] = (self.clock() + FOLLOW_WAIT, self.clock())
                if ans == "unknown":                               # the peer does not have the thread yet: it will pull when it is ready, nothing to retry
                    outcome = (True, "", True, False, "peer does not have this thread (yet)")
                else:
                    outcome = (ans == "ok", "" if ans == "ok" else "peer did not acknowledge", True, False, "")
        except NoCarrierUp as e:                                   # every carrier that holds an address of the peer is down: nothing was tried, so the PEER is not unreachable (no backoff, no failure count)
            outcome = None
            self._defer(peer, tid, kind, str(e))
        except CarrierError as e:
            outcome = (False, str(e), e.retry, True, "")
        except OSError as e:                                       # socket-level trouble (timeouts, resets): the peer is not reachable right now
            outcome = (False, f"{type(e).__name__}: {e}", True, True, "")
        except Exception as e:                                     # noqa: BLE001 - a bug or a hostile peer must not stop the node
            outcome = (False, f"{type(e).__name__}: {e}", True, False, "")
        finally:
            with self.mu:
                self.busy.discard(peer)
        if outcome is None:
            return
        ok, why, retry, unreachable, note = outcome
        self._finish(peer, tid, kind, ok, why, retry, unreachable, note)

    def note_refusal(self, peer: str, text: str, decl=None) -> None:
        """The server refused a KNOWN peer (its protocol, or a thread's format, is not served: version.py): one history line per peer per hour WHATEVER the text (the text carries the
        peer's own declared wire and sw: a peer varying them must not flood the log), and the cache entry that `peer list` shows (the peer's declaration is recorded with it)."""
        now = self.clock()
        with self.mu:
            last = self._refused_at.get(peer)
            if last is not None and 0 <= now - last < REFUSAL_LOG_GAP:
                return
            if len(self._refused_at) >= 256:
                self._refused_at.clear()
            self._refused_at[peer] = now
        self.log(peer[:8], "-", "refused", clean(text))
        if self.pv is not None:
            self.pv.refuse(peer, text, decl)

    def _defer(self, peer: str, tid: str, kind: str, why: str) -> None:
        """Nothing could be tried (no carrier up for this peer): look again in LOCATOR_WAIT seconds; no try is counted, `down` is not touched."""
        with self.mu:
            j = self._job(peer, tid, kind)
            j["err"], j["next"] = clean(why), self.clock() + LOCATOR_WAIT

    def _after_pull(self, tid: str, source: str) -> None:
        """New events arrived from `source`: tell the OTHER peers of this thread (the source already has them)."""
        self.sigs[tid] = self._signature(tid)
        now = self.clock()
        with self.mu:
            for aid, p in self._plan().items():
                if aid != source and tid in p["threads"]:
                    j = self._job(aid, tid, "notify")
                    j["next"], j["since"] = min(j["next"], now), j["since"] or now
        self.wake.set()                                            # one wake per finished pull: the next round tells the other peers (the Event coalesces any number)

    def _notify_at(self, peer: str):
        """The `notify_at` field for a request to `peer` (None: not configured, or no door with an address yet). Never raises."""
        if self.notify_field is None:
            return None
        try:
            return self.notify_field(peer)
        except Exception:                                          # noqa: BLE001 - an extra field must never break a pull or a notify
            return None

    def _notify_at_address(self, peer: str, rec: dict, tid: str):
        """Tell `peer` about news at the notify address it announced (M4b). Returns (answer as S.notify gives it or None, path or None): None = there is no notify address, or it failed (the caller
        falls back to the pull addresses); a path comes back only for a FAILURE, and the caller reports it to the book only if the fallback then delivered (a peer that is simply offline fails
        the pull addresses too: that tells nothing about its notify address)."""
        if self.notify_to is None:
            return None, None
        try:
            path = self.notify_to(rec)
        except Exception:                                          # noqa: BLE001
            return None, None
        if path is None:
            return None, None
        try:
            ans = S.notify(path, self.me, tid, self.m, peer_id=peer, stamp=self.clock, raise_errors=True, detail=True, notify_at=self._notify_at(peer))
        except Exception:                                          # noqa: BLE001 - a dead notify address is a fact for the book, not an error of the job
            return None, path
        if ans in ("ok", "unknown"):
            path.done(True)
            return ans, None
        return None, path

    def on_push(self, agent: str, tid: str, accepted: list) -> None:
        """A member PUSHED events and the server stored them (sync.SyncServer.on_push): the other peers of the thread are told, exactly as after a pull (the pusher already has them)."""
        if accepted and tid in self.m.threads and agent in self.peers.all():
            self._after_pull(tid, agent)

    def _may_push(self, tid: str) -> bool:
        """Only a current owner, admin or member of the thread may push (an observer or a guest would send a push the peer answers with `unknown`): such a node neither pushes nor pulls a peer to push."""
        t = self.m.threads.get(tid)
        try:
            m = t.state()["members"].get(self.me.id) if t is not None else None
        except Exception:                                          # noqa: BLE001
            return False
        return bool(m) and m["role"] in ("owner", "admin", "member")

    def _push(self, peer: str, tid: str, tr, res) -> None:
        """After a successful pull: push the events we hold and the peer's listing did not name (P4: not the ones it answered parked/rejected/unopened lately). Never raises."""
        try:
            if not self._may_push(tid):
                return
            now = self.clock()
            key = (peer, tid)
            with self.mu:
                if self.nopush.get(peer, 0) > now or self.push_off.get(key, 0) > now:
                    return
                held = self.push_held.get(key)
                t = self.m.threads[tid]
                if held is not None and held["head"] != t.head:
                    held["rej"] = set()                                # a membership event may change what the peer accepts
                    held["head"] = t.head
                skip = set()
                if held is not None:
                    held["park"] = {i: u for i, u in held["park"].items() if u > now}
                    skip = set(held["rej"]) | set(held["park"])
            ids = (t.resolved_ids() - set(res.get("peer_ids", ()))) - skip
            if not ids:
                return
            out = S.push(self.m, tid, tr, self.me, ids, peer_id=peer, stamp=self.clock)
            with self.mu:
                if out["unsupported"]:
                    self.nopush[peer] = now + S.PUSH_NO_PEER
                if out["unknown"]:
                    self.push_off[key] = now + S.PUSH_UNKNOWN
                elif out["retry"]:
                    self.push_off[key] = now + out["retry"]
                if out["held"]:
                    h = self.push_held.setdefault(key, {"head": t.head, "rej": set(), "park": {}})
                    for i, how in out["held"].items():
                        if how == "rejected":
                            h["rej"].add(i)
                        else:
                            h["park"][i] = now + S.PUSH_PARKED
                    if len(self.push_held) > MAX_JOBS:
                        self.push_held.pop(next(iter(self.push_held)))
                text = f"sent {out['sent']}: accepted {out['accepted']}, duplicate {out['duplicate']}, parked {out['parked']}, rejected {out['rejected']}, unopened {out['unopened']}, deferred {out['deferred']}" + (f" ({out['why']})" if out["why"] else "")
                self.pushes[key] = text
            if out["sent"] or out["why"]:
                self.log(peer[:8], tid[:8], "push", text)
        except Exception as e:                                         # noqa: BLE001 - a push is an extra: whatever goes wrong here, the pull stands
            self.log(peer[:8], tid[:8], "push", f"FAIL {type(e).__name__}")

    def _primary(self, peer: str):
        """The address dialed first for this peer right now (None: no book, or nothing known)."""
        try:
            return (self.locators.ordered(peer) or [None])[0] if self.locators is not None else None
        except Exception:                                          # noqa: BLE001 - a damaged book must not break the schedule
            return None

    def _addrs(self, peer: str):
        """The SET of addresses known for this peer (every carrier), as a sorted tuple. A backoff is about THESE: the order they are dialed in changes whenever the other carrier answers, and
        that must not end a backoff (a flapping first address would be a retry storm); only a different set does (None: no book, or damaged)."""
        try:
            return tuple(sorted(self.locators.ordered(peer))) if self.locators is not None else None
        except Exception:                                          # noqa: BLE001 - a damaged book must not break the schedule
            return None

    def _backed_off(self, peer: str) -> bool:
        d = self.down.get(peer)
        return bool(d) and d.get("until", 0) > self.clock()

    def _drop_stale_backoffs(self, now: float) -> None:
        """A peer whose SET of known addresses CHANGED since its failure (a human ran `peer move` / `peer add`, or an announced address was adopted) is not backed off any more: the
        backoff, and the jobs' own retry times, were earned by the OLD addresses. A change of ORDER alone is not a change (M1b). Caller holds self.mu."""
        for peer, d in list(self.down.items()):
            if "loc" in d and d["loc"] != self._addrs(peer):
                del self.down[peer]
                for k, j in self.jobs.items():
                    if k.startswith(peer + "/"):
                        j["next"] = min(j["next"], now)

    def _several(self, peer: str) -> bool:
        """Does this peer have more than one known address (so a failed round is a failed CYCLE over all of them)?"""
        try:
            return self.locators is not None and self.locators.count(peer) >= 2
        except Exception:                                          # noqa: BLE001 - a damaged book must not break the schedule
            return False

    def _finish(self, peer: str, tid: str, kind: str, ok: bool, why, retry: bool, unreachable: bool = False, note: str = "") -> None:
        now = self.clock()
        why = clean(why)                                           # peer-supplied text: printable only, bounded, always a string
        with self.mu:
            j = self._job(peer, tid, kind)
            if unreachable:                                        # tor could not reach the peer: one backoff for all of its jobs
                d = self.down.setdefault(peer, {"tries": 0, "until": now, "err": "", "blocked": False})
                d["tries"] = min(d["tries"] + 1, MAX_TRIES)
                d["err"], d["blocked"] = why, not retry
                d["loc"] = self._addrs(peer)                       # (the addresses this backoff is about; see _backed_off)
                if not retry:
                    d["until"] = now + min(BLOCKED_DELAY, jittered(BLOCKED_DELAY, self.rng))
                elif d["tries"] <= L.LOCATOR_RETRIES and self._several(peer):
                    d["until"] = now + self.retry_wait             # every address of this peer failed: wait a fixed time, then a new cycle (the first LOCATOR_RETRIES times) ...
                else:
                    d["until"] = now + backoff(d["tries"], self.rng)     # ... then the ordinary backoff (it still tries every BACKOFF_MAX)
            elif ok or kind == "pull":
                self.down.pop(peer, None)                          # it answered (even with an error): it is reachable
            if ok:
                j.update(tries=0, err=note, ok=None if note else now, blocked=False)
                if kind == "pull":
                    j["next"] = now + jittered(self.pull_interval, self.rng)
                else:
                    j["next"], j["since"] = NEVER, None              # acknowledged: nothing to send until the thread changes again
            else:
                j["tries"] = min(j["tries"] + 1, MAX_TRIES)
                j["err"], j["blocked"] = why, not retry
                if kind == "notify" and j.get("since") and now - j["since"] > NOTIFY_TTL:
                    j.update(next=NEVER, since=None, err="expired (anti-entropy will carry it)")
                elif unreachable:
                    j["next"] = self.down[peer]["until"]
                else:
                    j["next"] = now + (min(BLOCKED_DELAY, jittered(BLOCKED_DELAY, self.rng)) if not retry else backoff(j["tries"], self.rng))
            self.log(peer[:8], tid[:8], kind, "ok" if ok else f"FAIL {why}")

    # ------------------------------------------------------------ inspection
    def status(self) -> list:
        now = self.clock()
        rows = []
        peers = self.peers.all()
        for k, j in sorted(self.jobs.items()):
            peer, tid, kind = k.split("/")
            if kind == "notify" and j["next"] >= NEVER:
                continue
            rows.append({"peer": peers.get(peer, {}).get("name") or peer[:8], "thread": tid[:8], "job": kind, "tries": j["tries"],
                         "in": max(0, round(j["next"] - now)) if j["next"] < NEVER else None, "last_ok": j["ok"],
                         "state": "BLOCKED" if j["blocked"] else ("failing" if j["tries"] else "ok"), "error": j["err"]})
        return rows
