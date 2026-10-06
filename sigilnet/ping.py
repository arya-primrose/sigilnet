"""PING / PONG between nodes (DESIGN_ping.md rev 1, AGENT_NETWORK_SPEC.md 7.5): `sigilnet ping PEER` is BLOCKING and answered by the peer's NODE, never by its agent.

Three parts:
  * the server side (`handle_ping`): a pong built from a cached snapshot, so a ping never takes the Mirror lock;
  * the node side (`PingService`): the CLI cannot hold the carrier, so it writes `home/ping/<id>.req` and pokes the node; the service dials the peer in a pool thread with the
    node's own carrier and writes `<id>.res` (the same hand-off pattern as the blob want queue);
  * the CLI side (`ping_peer`): writes the request, polls for the result until its own deadline, removes both files.
The pong carries `{"t","up","unread","watching","v"}` and nothing else: no heads, thread ids, names or text. `unread` counts only the threads the REQUESTER is a member of."""
from __future__ import annotations

import inspect
import json
import math
import os
import re
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait as wait_futures
from pathlib import Path
from typing import NamedTuple

from . import wake as wakefile
from .carrier import CarrierError, NoCarrierUp
from .keys import AGENT_ID_RE, is_hex
from .sync import response_signed_by, sign_request

PING_MIN_GAP = 1.0             # one answered ping per requester per second (its own counter; the usual request budgets also apply)
PING_DEFAULT_TIMEOUT = 15.0
PING_MAX_TIMEOUT = 120.0
SNAPSHOT_EVERY = 2.0           # the node loop refreshes the pong snapshot at most this often
WATCH_BEAT_EVERY = 5.0         # `watch` touches home/watch.beat this often ...
WATCH_FRESH = 30.0             # ... and a beat younger than this means "an agent session is attached"
STALE_FILE_AGE = 600.0         # request / result files older than this are swept by the node
DEADLINE_SLACK = 5.0           # a request whose deadline is further ahead than PING_MAX_TIMEOUT + this is refused
REQ_MAX_BYTES = 4096
MAX_UNREAD = 10 ** 9           # a pong that claims more than this is not believed
SNAPSHOT_MAX_AGE = 30.0        # the loop refreshes the pong snapshot when somebody asked since the last refresh, or at least this often
GRACE = 0.25                   # tick() waits this long for the pings it dispatched (a fast answer lands in the same round)
POOL = 4                       # pings in flight at once

PONG_KEYS = {"t", "up", "unread", "watching", "v"}
ENVELOPE_KEYS = {"nonce", "r", "by", "rsig"}
WHY = ("connect refused", "timed out", "refused: not authorized", "bad answer", "rate limited", "no carrier up")
BEAT = "watch.beat"
POKE = "node.poke"
DIR = "ping"


class PingError(ValueError):
    pass


class PingResult(NamedTuple):
    ok: bool
    why: str | None
    pong: dict | None
    rtt_ms: float | None
    peer_name: str
    peer_id: str
    via: str | None = None          # the carrier type that answered (only a node that runs several carriers can say)


# ------------------------------------------------------------------ the server side
def handle_ping(snapshot, requester) -> dict | None:
    """The pong for `requester`, or None = give the stranger's answer (the requester is not in the peer book)."""
    if not isinstance(snapshot, dict):
        return None
    unread = snapshot.get("unread")
    if not isinstance(unread, dict) or not isinstance(requester, str) or requester not in unread:
        return None
    n = unread[requester]
    return {"t": "pong", "up": True, "unread": n if type(n) is int and n >= 0 else 0, "watching": snapshot.get("watching") is True, "v": 1}


def make_ping_log(out, *, clock=time.monotonic, refused_gap: float = 60.0):
    """The SyncServer's `ping_log`: one line per ping this node answered (a known peer is held to one per PING_MIN_GAP anyway) and at most one `refused` line per `refused_gap`
    seconds in all (a stranger with a valid signature must not be able to fill history.log)."""
    last = {"refused": None}

    def log(who: str, what: str) -> None:
        if what == "refused":
            now = clock()
            if last["refused"] is not None and 0 <= now - last["refused"] < refused_gap:
                return
            last["refused"] = now
        out(f"ping from {str(who)[:8]} {what}")
    return log


def watching(home, now: float) -> bool:
    """True while a `watch` process beats: lstat + mtime only (a symlink counts by its own mtime, never its target's)."""
    try:
        age = now - os.lstat(Path(home) / BEAT).st_mtime
    except OSError:
        return False
    return -WATCH_FRESH < age < WATCH_FRESH


def beat(home) -> None:
    """The `watch` heartbeat: the poke writer (0600, no-follow, one byte per beat, never raises)."""
    wakefile.poke(Path(home) / BEAT)


# ------------------------------------------------------------------ the client exchange
NOT_AUTHORIZED = ("not admitted", "needs a credential", "needs authentication")      # what the carriers say when the peer's door does not know OUR key
BAD_PEER = ("does not match the endpoint", "did not speak")                           # a key pin mismatch (changed key, or someone else behind the address) / not our protocol


def _why_from(e: BaseException) -> str:
    text = f"{type(e).__name__} {e}".lower()
    if isinstance(e, NoCarrierUp):
        return "no carrier up"
    if isinstance(e, TimeoutError) or "timed out" in text or "timeout" in text:
        return "timed out"
    if isinstance(e, CarrierError):
        if any(t in text for t in NOT_AUTHORIZED):
            return "refused: not authorized"
        if any(t in text for t in BAD_PEER):
            return "bad answer"
    if isinstance(e, (OSError, CarrierError)):
        return "connect refused"                                  # the door or the node is not there (tor: the service cannot be found)
    return "bad answer"


def check_pong(resp, nonce: str, peer_id: str) -> tuple:
    """(ok, why, pong): the answer must be signed by the peer we asked and bound to our nonce; a pong is exactly the five keys with the right types."""
    if not isinstance(resp, dict) or resp.get("nonce") != nonce or type(resp.get("r")) is not int or resp["r"] != 1:
        return False, "bad answer", None
    try:
        if not response_signed_by(resp, peer_id):
            return False, "bad answer", None
    except Exception:                                             # noqa: BLE001
        return False, "bad answer", None
    if resp.get("t") == "unknown":
        return False, "refused: not authorized", None
    body = {k: v for k, v in resp.items() if k not in ENVELOPE_KEYS}
    if resp.get("t") != "pong" or set(body) != PONG_KEYS or body["up"] is not True or type(body["v"]) is not int or body["v"] != 1 \
            or type(body["unread"]) is not int or not 0 <= body["unread"] <= MAX_UNREAD or type(body["watching"]) is not bool:
        return False, "bad answer", None
    return True, None, body


def _rate_limited(resp, peer_id: str) -> bool:
    try:
        return isinstance(resp, dict) and resp.get("t") == "error" and resp.get("why") == "rate limited" and response_signed_by(resp, peer_id)
    except Exception:                                             # noqa: BLE001
        return False


def exchange(transport, me, peer_id: str, stamp=time.time, *, deadline: float | None = None, sleep=time.sleep) -> tuple:
    """One signed ping over `transport`: (ok, why, pong, rtt_ms). Never raises. A signed "rate limited" answer (we pinged inside the peer's PING_MIN_GAP) is asked again ONCE
    after the gap if `deadline` (wall clock) still leaves room; the rtt is that of the answered request."""
    for attempt in (0, 1):
        t0 = time.monotonic()
        try:
            req = sign_request(me, {"t": "ping"}, ts=int(stamp()), aud=peer_id)
            resp = transport.request(req)
        except Exception as e:                                    # noqa: BLE001 - the dial is a carrier, anything can come out of it
            return False, _why_from(e), None, None
        rtt = round((time.monotonic() - t0) * 1000.0, 1)
        ok, why, pong = check_pong(resp, req["nonce"], peer_id)
        if not ok and _rate_limited(resp, peer_id):
            if attempt == 0 and deadline is not None and stamp() + PING_MIN_GAP + 0.1 < deadline:
                sleep(PING_MIN_GAP + 0.05)
                continue
            return False, "rate limited", None, None               # the peer is limiting us: say so (not "bad answer")
        return ok, why, pong, rtt if ok else None
    return False, "bad answer", None, None


# ------------------------------------------------------------------ files
def _write_json(path: Path, obj) -> None:
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(obj))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _unlink(path) -> None:
    try:
        os.unlink(path)
    except IsADirectoryError:
        try:
            os.rmdir(path)
        except OSError:
            pass
    except OSError:
        pass


def _read_req(path: Path):
    """The parsed request (a dict) or None: only a regular file of at most REQ_MAX_BYTES, opened without following a link and without blocking on a FIFO."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > REQ_MAX_BYTES:
            return None
        raw = os.read(fd, REQ_MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(raw) > REQ_MAX_BYTES:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


def _valid_req(obj: dict, name_id: str, now: float):
    if set(obj) != {"id", "peer", "deadline"} or obj["id"] != name_id or not is_hex(name_id, 16) or not isinstance(obj["peer"], str) \
            or not AGENT_ID_RE.fullmatch(obj["peer"]):
        return None
    d = obj["deadline"]
    if isinstance(d, bool) or not isinstance(d, (int, float)) or not math.isfinite(d) or d <= now or d > now + PING_MAX_TIMEOUT + DEADLINE_SLACK:
        return None
    return obj


# ------------------------------------------------------------------ the node side
class PingService:
    """Called by the node loop each round (`tick`): picks up `home/ping/*.req`, dials the peer with the node's carrier in a pool thread, writes `<id>.res`."""

    def __init__(self, node, home, carrier_dial, *, clock=time.time):
        self.node, self.home, self.dial, self.clock = node, Path(home), carrier_dial, clock
        self.dir = self.home / DIR
        self._active: set = set()
        self._mu = threading.Lock()
        self._pool: ThreadPoolExecutor | None = None
        from .history import History
        self.history = History(self.home, clock=clock)

    def _dial(self, rec: dict, remaining: float):
        """The carrier's dial, told how long we still have (a dial that takes `remaining` as a second argument stops waiting when the CLI has given up)."""
        try:
            params = inspect.signature(self.dial).parameters
            takes = len([p for p in params.values() if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]) >= 2 or any(p.kind == p.VAR_POSITIONAL for p in params.values())
        except (TypeError, ValueError):
            takes = False
        return self.dial(rec, max(remaining, 0.1)) if takes else self.dial(rec)

    def _log(self, text: str) -> None:
        try:
            self.history.log("node", text)
        except Exception:                                         # noqa: BLE001 - a log line must never stop a ping
            pass

    def _sweep(self, now: float) -> None:
        try:
            names = os.listdir(self.dir)
        except OSError:
            return
        for n in names:
            p = self.dir / n
            try:
                if now - os.lstat(p).st_mtime > STALE_FILE_AGE:
                    with self._mu:
                        if n.partition(".")[0] in self._active:
                            continue
                    _unlink(p)
            except OSError:
                pass

    def tick(self) -> int:
        """Returns how many requests were taken on this round. Never raises, never blocks longer than GRACE."""
        try:
            names = sorted(os.listdir(self.dir))
        except OSError:
            return 0
        now = self.clock()
        self._sweep(now)
        book = self.node.peers.all()
        futs = []
        for n in names:
            if not n.endswith(".req"):
                continue
            ident = n[:-4]
            p = self.dir / n
            with self._mu:
                if ident in self._active:
                    continue
            obj = _read_req(p)
            req = _valid_req(obj, ident, now) if obj is not None else None
            if req is None or req["peer"] not in book or req["peer"] == self.node.me.id:
                _unlink(p)                                        # malformed, stale, or a peer we do not know: never dialled
                continue
            with self._mu:
                if len(self._active) >= POOL:
                    break
                self._active.add(ident)
                if self._pool is None:
                    self._pool = ThreadPoolExecutor(POOL)
                pool = self._pool
            futs.append(pool.submit(self._run, ident, req, book[req["peer"]]))
        if futs:
            wait_futures(futs, timeout=GRACE)
        return len(futs)

    def _run(self, ident: str, req: dict, rec: dict) -> None:
        peer = req["peer"]
        name = rec.get("name") or peer[:8]
        try:
            ok, why, pong, rtt, via = False, "bad answer", None, None, None
            if self.clock() < req["deadline"]:
                try:
                    tr = self._dial(rec, req["deadline"] - self.clock())
                except Exception as e:                            # noqa: BLE001
                    ok, why, pong, rtt = False, _why_from(e), None, None
                else:
                    ok, why, pong, rtt = exchange(tr, self.node.me, peer, self.clock, deadline=req["deadline"])
                    via = getattr(tr, "via", None) if ok else None
            else:
                why = "timed out"
            if ok:
                self._log(f"ping {name}: pong {rtt:.0f} ms")
                self.node.note_pong(peer, pong)
            else:
                self._log(f"ping {name}: no answer ({why})")
            if (self.dir / f"{ident}.req").exists():              # the CLI removes the request when it gives up: then nobody reads a result
                try:
                    _write_json(self.dir / f"{ident}.res", {"id": ident, "ok": ok, "why": why, "pong": pong, "rtt_ms": rtt, **({"via": via} if via else {})})
                except OSError:
                    pass
            _unlink(self.dir / f"{ident}.req")
        finally:
            with self._mu:
                self._active.discard(ident)

    def close(self) -> None:
        with self._mu:
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)


# ------------------------------------------------------------------ the CLI side
def _resolve(book: dict, peer: str):
    if not isinstance(peer, str) or not peer:
        raise PingError("give a peer name or agent id")
    by_name = [a for a, r in book.items() if r.get("name") == peer]
    hits = by_name or [a for a in book if a.startswith(peer)]
    if not hits:
        raise PingError(f"no such peer: {peer} (see `sigilnet peer list`)")
    if len(hits) > 1:
        raise PingError(f"{peer} matches {len(hits)} peers; give more of the agent id")
    return hits[0], book[hits[0]].get("name") or hits[0][:8]


def ping_peer(home, peer: str, timeout: float = PING_DEFAULT_TIMEOUT, *, clock=time.time, sleep=time.sleep) -> PingResult:
    """BLOCKING: returns the pong or, at the deadline, `timed out`. Raises PingError for what is wrong before anything is sent."""
    from . import daemon
    from . import tcplink  # noqa: F401  (registers the "tcp" endpoint type: without it PeerBook.all() skips a tcp peer, in this process)
    from .node import PeerBook
    home = Path(home)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= PING_MAX_TIMEOUT:
        raise PingError(f"--timeout must be more than 0 and at most {PING_MAX_TIMEOUT:g} seconds")
    aid, name = _resolve(PeerBook(home / "peers.json").all(), peer)
    if not daemon.lock_held(home):
        raise PingError("no node is running here: start it with `sigilnet start`")
    d = home / DIR
    d.mkdir(mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    ident = os.urandom(8).hex()
    deadline = clock() + timeout
    reqp, resp_ = d / f"{ident}.req", d / f"{ident}.res"
    tmpp = d / f"{ident}.tmp"                                      # written whole under a name the node ignores, then renamed: the node never reads a half-written request
    fd = os.open(tmpp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps({"id": ident, "peer": aid, "deadline": deadline}))
        os.replace(tmpp, reqp)
    except BaseException:
        _unlink(tmpp)
        raise
    wakefile.poke(home / POKE)                                    # the node picks it up at once (DESIGN_node_wake.md)
    try:
        while True:
            try:
                raw = resp_.read_text()
            except OSError:
                raw = None
            if raw is not None:
                try:
                    r = json.loads(raw)
                    if not isinstance(r, dict) or r.get("id") != ident:
                        raise ValueError
                except (ValueError, RecursionError):
                    return PingResult(False, "bad answer", None, None, name, aid)
                rtt = r.get("rtt_ms")
                rtt = rtt if isinstance(rtt, (int, float)) and not isinstance(rtt, bool) else None
                pong = r.get("pong")
                if r.get("ok") is True and isinstance(pong, dict) and set(pong) == PONG_KEYS:
                    via = r.get("via")
                    via = via if isinstance(via, str) and re.fullmatch(r"[a-z0-9]{1,16}", via) else None
                    return PingResult(True, None, pong, rtt if rtt is not None else 0.0, name, aid, via)
                why = r.get("why") if r.get("ok") is False and r.get("why") in WHY else "bad answer"
                return PingResult(False, why, None, None, name, aid)
            now = clock()
            if now >= deadline:
                return PingResult(False, "timed out", None, None, name, aid)
            sleep(min(0.02, deadline - now))
    finally:
        _unlink(reqp)
        _unlink(resp_)


def format_result(res: PingResult, elapsed: float) -> str:
    if res.ok:
        p = res.pong
        return f"pong from {res.peer_name} ({res.peer_id[:8]}): up, unread {p['unread']}, watching {'yes' if p['watching'] else 'no'}, rtt {res.rtt_ms:.0f} ms" + (f", via {res.via}" if res.via else "")
    return f"no answer from {res.peer_name} ({res.peer_id[:8]}) after {round(elapsed, 1):g} s: {res.why}"
