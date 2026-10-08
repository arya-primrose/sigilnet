"""`node run`: one process that starts our tor, serves sync on loopback behind the onion service, and runs the node loop (node.py)."""
from __future__ import annotations

import fcntl
import json
import os
import signal
import sys
import threading
import time
import unicodedata
from pathlib import Path

from .blobindex import BlobIndex
from .blobserve import BlobService
from .blobwant import Wants
from .blobworker import BlobWorker
from .blobstore import BlobStore
from .carrier import Carrier, CarrierError, endpoints_of
from .doors import SHARED, Doors, door_handler, service_handler      # (re-exported: the doors live in doors.py, which has no Tor in it)
from .keys import Identity
from . import capsule
from . import knock
from .envelope import EnvCodec
from .inbox import Inbox
from .mirror import Mirror
from .node import Node, PeerBook
from .publicblob import PublicBlob
from .publicread import PublicRead
from .sync import SyncServer
from . import daemon
from .history import History
from .home import open_mirror
from .ping import PingService, make_ping_log
from .wake import TICK, Waker
from .migrate import migrate_home
from .carrierset import CarrierSet
from .locators import LocatorService, MultiDialer, NotifyDialer, PeerDialer, open_book, route_inbound, route_locator, route_notify_at
from .autorotate import AutoRotator
from .peerver import PeerVer
from .tcplink import TcpCarrier, resolve_bind           # (registers the "tcp" endpoint/credential types; the TCP carrier, see DESIGN_tcp_carrier.md)
from .torlink import BOOTSTRAP_TIMEOUT, TorNode           # the composition root: the ONLY protocol-side module that names the Tor carrier

NOTIFY_TYPES = {"tor": "onion", "tcp": "tcp"}                       # config name -> carrier type (endpoint type)
DEFAULTS = {"local_port": None, "virtual_port": 47200, "service_port_base": 47210, "bridges": [], "carrier": "tor", "carriers": ["tor"], "notify_via": None, "auto_rotate": False, "follow_rotation": False}      # local_port: the legacy ONE shared service (off)
TOR_RESTARTS, TOR_RESTART_WINDOW = 3, 1800.0    # a dead carrier is restarted at most this many times inside any rolling window (DESIGN_tor_restart.md); then the node exits, loudly
TOR_BACKOFF = (5.0, 30.0, 120.0)     # seconds before restart 1, 2, 3 of the window
BLOB_GC_EVERY = 3600.0               # seconds between blob garbage collections (and one at start)


def load_config(home: Path) -> dict:
    """node_config.json, validated: a hostile or hand-damaged file is an error message, never a traceback or a torrc line."""
    cfg = dict(DEFAULTS)
    try:
        raw = json.loads((home / "node_config.json").read_text())
    except (OSError, ValueError):
        return cfg
    if not isinstance(raw, dict):
        raise ValueError("node_config.json is not an object")
    for k in ("local_port", "virtual_port", "service_port_base"):
        if k in raw and not (k == "local_port" and raw[k] is None):
            p = raw[k]
            if isinstance(p, bool) or not isinstance(p, int) or not 0 < p < 65536:
                raise ValueError(f"node_config.json: {k} must be a port number (1-65535)")
            cfg[k] = p
    if "carrier" in raw:
        if raw["carrier"] not in ("tor", "tcp"):
            raise ValueError("node_config.json: carrier must be \"tor\" or \"tcp\"")
        cfg["carrier"] = raw["carrier"]
        cfg["carriers"] = [raw["carrier"]]
    if "carriers" in raw:                                          # M1b: the carriers this node runs AT ONCE, the first one is the primary (capsules, public doors, the door commands of the CLI)
        cs = raw["carriers"]
        if not isinstance(cs, list) or not cs or len(cs) > 2 or any(not isinstance(c, str) or c not in ("tor", "tcp") for c in cs) or len(set(cs)) != len(cs):
            raise ValueError("node_config.json: carriers must be a list of \"tor\" and/or \"tcp\", each once (the first is the primary)")
        cfg["carriers"] = list(cs)
        cfg["carrier"] = cs[0]
    if "notify_via" in raw and raw["notify_via"] is not None:       # M4b: the carrier on which THIS node wants its notifies (absent = the pull addresses, as before)
        if raw["notify_via"] not in ("tor", "tcp"):
            raise ValueError("node_config.json: notify_via must be \"tor\", \"tcp\" or absent")
        cfg["notify_via"] = raw["notify_via"]
    for k in ("auto_rotate", "follow_rotation"):                   # DESIGN_autorotate.md: both OFF unless set (`node auto-rotate on`, `node follow-rotation on`)
        if k in raw:
            if not isinstance(raw[k], bool):
                raise ValueError(f"node_config.json: {k} must be true or false")
            cfg[k] = raw[k]
    if "tcp" in raw:
        t = raw["tcp"]
        if not isinstance(t, dict) or not set(t) <= {"bind", "port_base", "advertise", "allow_public"} or "bind" not in t or "port_base" not in t:
            raise ValueError("node_config.json: tcp must be an object with bind and port_base (and optionally advertise, allow_public)")
        cfg["tcp"] = t
    if "tcp" in cfg["carriers"] and "tcp" not in cfg:
        raise ValueError("node_config.json: carrier \"tcp\" needs a tcp section")
    if "bridges" in raw:
        b = raw["bridges"]
        if not isinstance(b, list) or len(b) > 32 or any(not isinstance(x, str) or len(x) > 1000 for x in b):
            raise ValueError("node_config.json: bridges must be a list of strings")
        cfg["bridges"] = b
    return cfg


def save_config(home: Path, cfg: dict) -> None:
    p = home / "node_config.json"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)                               # (a file that already existed keeps its old mode otherwise)
        json.dump(cfg, f, sort_keys=True, indent=1)


def tor_node(home: Path, cfg: dict, offline: bool = False) -> Carrier:
    """The carrier this node runs on (Tor is the only one). Everything after this call talks to the carrier.Carrier contract."""
    return TorNode(home / "tor", local_port=cfg.get("local_port"), virtual_port=int(cfg["virtual_port"]), bridge_lines=cfg.get("bridges", []), offline=offline,
                   service_port_base=int(cfg["service_port_base"]))


def _build_carrier(home: Path, cfg: dict, name: str, offline: bool = False) -> Carrier:
    if name == "tcp":
        t = cfg["tcp"]
        allow_public = t.get("allow_public", False)
        bind = resolve_bind(t["bind"], allow_public, _tcp_peer_ips(home))    # "auto": this machine's address NOW (a container that got a new IP must still start)
        resolver = (lambda: resolve_bind(t["bind"], allow_public, _tcp_peer_ips(home))) if t["bind"] in ("auto", "auto6") else None      # asked again before a RESTART of this carrier (M1c)
        return TcpCarrier(home / "tcp", bind=bind, port_base=t["port_base"], advertise=t.get("advertise"), allow_public=allow_public, resolver=resolver)
    return tor_node(home, cfg, offline)


def make_carrier(home: Path, cfg: dict, offline: bool = False) -> Carrier:
    """The PRIMARY carrier (the first of `carriers`): Tor (default) or TCP. Everything that has one carrier in mind (the door commands of the CLI, capsules) uses this."""
    return _build_carrier(home, cfg, cfg.get("carrier", "tor"), offline)


def make_carriers(home: Path, cfg: dict, offline: bool = False) -> dict:
    """{carrier type ("tcp", "onion"): carrier} for every carrier the node runs, the primary first. The ONLY place that chooses; everything after talks to the carrier.Carrier contract."""
    out = {}
    for name in cfg.get("carriers") or [cfg.get("carrier", "tor")]:
        c = _build_carrier(home, cfg, name, offline)
        out[c.type] = c
    return out


def carrier_for(home: Path, cfg: dict, etype: str, offline: bool = False) -> Carrier:
    """The carrier of endpoint type `etype` among those this node runs; ValueError if it runs none."""
    for name in cfg.get("carriers") or [cfg.get("carrier", "tor")]:
        c = _build_carrier(home, cfg, name, offline)
        if c.type == etype:
            return c
    raise ValueError(f"this node does not run the {etype} carrier (it runs: {', '.join(cfg.get('carriers') or [cfg.get('carrier', 'tor')])})")


def _reload_after_up(carrier) -> None:
    """A carrier just came up: one reload (tor re-reads its client-authorization files). A key a CLI process wrote while tor was in its first milliseconds was refused a SIGHUP there and the
    node cannot know it; this makes sure it is loaded (harmless when nothing changed)."""
    try:
        getattr(carrier, "reload", lambda: False)()
    except Exception:                                              # noqa: BLE001 - housekeeping
        pass


def _tick_locator_services(locsvcs: dict, usable=None) -> None:
    """One `tick` for the LocatorService of every carrier that is up (an announcement over a dead carrier would only fail and back off)."""
    for t, ls in locsvcs.items():
        if usable is None or usable(t):
            ls.tick()


def _credential_pairs(peers, etype: str) -> list:
    """[(agent id, address)] of every peer endpoint of carrier type `etype` (what `index_credentials` holds under the node id too)."""
    return [(a, ep["addr"]) for a, r in peers.all().items() for ep in endpoints_of(r) if ep["type"] == etype]


def _tcp_peer_ips(home: Path) -> list:
    """The IPs of our peers' tcp addresses (the route to one of them picks the address `bind: auto` listens on)."""
    from .tcplink import _split_addr
    out = []
    try:
        for rec in PeerBook(home / "peers.json").all().values():
            for ep in endpoints_of(rec):
                if ep.get("type") == "tcp":
                    out.append(_split_addr(ep["addr"])[0])
    except (ValueError, OSError):
        pass
    return out


def _instance_lock(home: Path, *, retry: float = 1.0, gap: float = 0.02):
    """An exclusive flock on home/node.lock held until the process exits (the kernel drops it on any death). None if another node holds it. The non-blocking try is repeated for
    about `retry` seconds: `status`/`stop`/`start` probe this very lock for microseconds and must never make a real start fail ("another node is already running")."""
    fd = os.open(home / "node.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    end = time.monotonic() + retry
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError:
            if time.monotonic() >= end:
                os.close(fd)
                return None
            time.sleep(gap)


def _clean_tail(text: str, cap: int = 300) -> str:
    """The carrier's own log text is not ours: no control or format characters (terminal escapes, bidi marks), one line, capped."""
    t = "".join(" " if unicodedata.category(c) in ("Cc", "Cf") else c for c in str(text))
    return " ".join(t.split())[:cap]


def _door_lines(tor: Carrier, out) -> None:
    for name, svc in sorted(tor.doors().items()):
        ep = tor.door_endpoint(name)
        out(f"  door for {name}: {ep['addr'] if ep else '(address not created yet)'}" + (f" (only agent {svc['agent'][:8]})" if svc["agent"] else ""))


def _recover_carrier(tor: Carrier, doors: Doors, out, history: list, end: float | None = None, *, clock=time.monotonic, sleep=time.sleep) -> bool:
    """The carrier died under a running node. Restart it (the SAME object: its socks port and the transports built on it stay valid) unless TOR_RESTARTS restarts
    already happened inside the rolling window; then say so and return False (the caller exits 1: a node with dead doors that keeps running is the silent failure).
    A restart counts from the moment of the exit, a successful one does not reset the budget. True = carry on (restarted, failed (the next pass will see it
    unhealthy and count again), or `end` reached). Runs in the loop's thread (TorNode.start needs the main thread). doors.sync() only AFTER the start (a reload
    with no tor running does nothing, and start() reads services.json itself)."""
    now = clock()
    tail = _clean_tail(getattr(tor, "_log_tail", lambda: "")())                  # BEFORE stop/start: start() truncates the log
    history[:] = [t for t in history if now - t < TOR_RESTART_WINDOW]
    if len(history) >= TOR_RESTARTS:
        out(f"error: carrier restart budget used ({TOR_RESTARTS} in {int(TOR_RESTART_WINDOW // 60)} min): giving up; last: {tail}")
        return False
    history.append(now)
    n, wait = len(history), TOR_BACKOFF[min(len(history), len(TOR_BACKOFF)) - 1]
    out(f"  carrier exited ({tail}); restart {n}/{TOR_RESTARTS} in {wait:g} s")
    until = now + wait
    while clock() < until:                                                        # slices: SIGTERM/Ctrl-C and --seconds are honoured during the backoff
        if end is not None and time.time() >= end:
            return True
        sleep(min(1.0, max(0.0, until - clock())))
    tor.stop()
    t0 = clock()
    try:
        if end is not None and isinstance(tor, TorNode):
            tor.start(wait=True, timeout=max(1.0, min(BOOTSTRAP_TIMEOUT, end - time.time())))
        else:
            tor.start(wait=True)
        doors.sync()
    except (CarrierError, OSError) as e:
        tor.stop()                                                                # a tor that did not bootstrap still runs: the next pass must see it as dead
        out(f"  carrier restart failed: {type(e).__name__}: {_clean_tail(e)}")
        return True
    out(f"  carrier restarted (took {clock() - t0:.0f} s)")
    _door_lines(tor, out)
    return True


def _say(*a) -> None:
    print(*a, flush=True)                                          # a node writing to a file or a pipe must show progress at once


REQUEST_TIMEOUT = 20.0     # one tor exchange once connected (request + response): a hung circuit must not hold a worker for a minute; the node retries with backoff
CONNECT_TIMEOUT = 45.0     # building the rendezvous circuit to a fresh onion service is slow (20-60 s the first time): connecting has its own, longer budget
CONNECT_TIMEOUTS = {"onion": CONNECT_TIMEOUT, "tcp": 10.0}      # per carrier (M1b): a dead private TCP address must not hold one of the 4 workers for Tor's 45 s


class _JoinWorker:
    """Every few seconds: the owner-side sweep (expiry, grace) on every carrier that is up, and (in a worker thread, it uses the network) one pass over the joins this agent is waiting on.
    M2: capsules have join doors on every carrier of the set, so both run over all of them; a carrier that is down is skipped (its doors are swept when it is back, and a join door that
    outlives its capsule answers nothing: JoinServer refuses after `exp`)."""
    SWEEP_EVERY, POLL_EVERY = 10.0, 20.0

    def __init__(self, home: Path, carriers: dict, me: Identity, book: PeerBook, out, codec=None, usable=None):
        self.home, self.carriers, self.me, self.book, self.out, self.codec = home, carriers, me, book, out, codec
        self.usable = usable                                       # callable(type) -> is that carrier up (M1c: while it is down nothing here runs on it, raises or holds a worker)
        self.last_sweep = self.last_poll = 0.0
        self.busy = threading.Event()

    def _up(self, etype: str) -> bool:
        return self.usable is None or self.usable(etype)

    def tick(self) -> None:
        if not any(self._up(t) for t in self.carriers):
            return
        now = time.time()
        if now - self.last_sweep >= self.SWEEP_EVERY:
            self.last_sweep = now
            try:
                capsule.sweep(self.home, list(self.carriers.values()), skip=[t for t in self.carriers if not self._up(t)])
            except Exception as e:                                 # noqa: BLE001 - a damaged capsule file must not stop the node
                self.out(f"  capsule sweep: {type(e).__name__}")
            try:
                knock.sweep(self.home, [c for t, c in self.carriers.items() if self._up(t)])
            except Exception as e:                                 # noqa: BLE001 - nor a damaged card file
                self.out(f"  card sweep: {type(e).__name__}")
        if now - self.last_poll >= self.POLL_EVERY and not self.busy.is_set() and (any(r.get("state") in ("door", "requested") for r in capsule.Joins(self.home).all().values())
                                                                                   or knock.waiting_joins(self.home)):
            self.last_poll = now
            self.busy.set()
            threading.Thread(target=self._poll, daemon=True).start()

    def _transport(self, ep: dict):
        if ep["type"] not in self.carriers or not self._up(ep["type"]):
            raise CarrierError(f"the {ep['type']} carrier is not up")           # (capsule.poll goes on to the next join door)
        return self.carriers[ep["type"]].dial(ep, timeout=REQUEST_TIMEOUT, connect_timeout=CONNECT_TIMEOUTS.get(ep["type"], CONNECT_TIMEOUT))

    def _poll(self) -> None:
        try:
            for cid, st in capsule.poll(self.home, self.carriers, self.me, self.book, self._transport, codec=self.codec).items():
                self.out(f"  join {cid}: {st}")
        except Exception as e:                                     # noqa: BLE001 - never kill the node for a join that cannot progress
            self.out(f"  join poll: {type(e).__name__}")
        try:
            for cid, st in knock.poll(self.home, self.carriers, self.me, self.book, self._transport, codec=self.codec).items():
                self.out(f"  card join {cid}: {st}")
        except Exception as e:                                     # noqa: BLE001
            self.out(f"  card join poll: {type(e).__name__}")
        finally:
            self.busy.clear()


def warm_blob_snapshot(m: Mirror, bsvc: BlobService) -> None:
    """Fill the blob service's member snapshot from every thread we hold: members are not "unvetted" after a restart (they would otherwise share the small
    global budget of strangers until their first request)."""
    with m._lock():
        for t in list(m.threads.values()):
            bsvc.note_thread(t)


def run(home: Path, me: Identity, *, seconds: float = 0, offline: bool = False, out=_say, allow_public_without_ip_hiding: bool = False, echo: bool = True) -> int:
    hist = History(home)
    emit = out

    def out(s):                                                    # every line of the node: to the caller's `out` (stdout unless echo is off) AND to history.log with a timestamp
        hist.log("node", s)
        if echo:
            emit(s)
    try:
        migrate_home(home)                                         # inbox/ -> guest/ (a no-op on a migrated home); refuses while another node holds the lock
        cfg = load_config(home)
        carriers = make_carriers(home, cfg, offline)               # {type: carrier}, the primary first
        tor = next(iter(carriers.values()))                        # (the primary: capsules, public doors; the name is from the days of one carrier)
    except ValueError as e:                                        # MigrationError is a ValueError
        out(f"error: {e}")
        return 1
    lock = _instance_lock(home)                                    # ONE node per home: a second one would take the first one's tor down
    if lock is None:
        out(f"error: another node is already running on {home} (lock {home / 'node.lock'}); stop it first")
        return 1
    started = time.time()
    multi = len(carriers) > 1                                      # M1c: several carriers = DEGRADE (keep serving on the ones that are up); one carrier = the old path, exits when it is gone
    cset = CarrierSet(carriers) if multi else None

    def status(**kw):                                              # node.pid / node.status.json: what `status` and `stop` read (DESIGN_node_daemon.md section 4)
        guards = {t: c.guard_stats() for t, c in carriers.items() if hasattr(c, "guard_stats")}
        if guards:
            kw["guard"] = guards                                   # accept-time guard counts (M3b): numbers only, never an address
        if cset is not None:                                       # ready = AT LEAST ONE carrier is up; `down` says why the others are not
            st = cset.status()
            kw["ready"] = bool(kw.get("ready")) and cset.any_up()
            kw["carriers_up"] = cset.up_types()
            kw["down"] = {t: f"{s['state']}: {s['reason']}" + (f", retry in {s['retry_in']} s" if s["retry_in"] is not None else "") for t, s in st.items() if s["state"] != "up"}
        daemon.write_status(home, started=started, carrier="+".join(carriers), **kw)
    daemon.write_self_pid(home)                                    # written AFTER the lock is held (the launcher never writes it)
    status(ready=False, doors_up=0, doors_total=0)
    m = open_mirror(home, me.id, poke=False)           # (the node's own appends must not poke itself: a 10k-event first sync would be a poke per event)
    for tid in list(m.threads):
        m.prune_dropped(tid)                                       # the replay block of the inbox door must not grow for ever
    peers = PeerBook(home / "peers.json")
    nlog = lambda *a: out("  " + " ".join(str(x) for x in a))     # noqa: E731
    books = {t: open_book(home, t) for t in carriers}                # (the carrier type is also the endpoint type: "tcp", "onion")
    pdialers = {t: PeerDialer(c, books[t], request_timeout=REQUEST_TIMEOUT, connect_timeout=CONNECT_TIMEOUTS.get(t, CONNECT_TIMEOUT)) for t, c in carriers.items()}     # one carrier: a peer's addresses in last-good-first order, fallback at once (locators.py)
    dialer = MultiDialer(pdialers, log=nlog, usable=cset.usable if cset else None)     # all carriers: ordered by the last good contact in either direction, per-(peer, carrier) skip; a DOWN carrier is left out (locators.py)
    for t, c in carriers.items():
        if hasattr(c, "index_credentials"):                         # a home from before the locator book: hold each credential under the peer's node id too (idempotent, never deletes)
            try:
                c.index_credentials(_credential_pairs(peers, t))
            except (CarrierError, OSError, ValueError) as e:        # a damaged held.json used to break dials only: it must not stop the NODE from starting
                out(f"  locator: held.json damaged, credentials not indexed by node id ({type(e).__name__})")
    node = Node(m, me, peers, home / "node.json", dialer, log=nlog, locators=dialer, retry_wait=max(getattr(c, "retry_wait", 30.0) for c in carriers.values()))
    node.pv = PeerVer(home / "peerver.json")
    node.rot = AutoRotator(m, me, peers, home / "rotation.json", log=nlog, auto_rotate=cfg["auto_rotate"], follow_rotation=cfg["follow_rotation"])      # (opt-in: DESIGN_autorotate.md; the verification of automatic follows runs whatever the switches say)
    node.rot.last_error = lambda peer, tid: (node.jobs.get(node._key(peer, tid, "pull")) or {}).get("err", "")      # (so an expiry can say WHY: the owner's gating text names the thread format)
    out(f"  rotation: auto_rotate {'on' if node.rot.auto_rotate else 'off'}, follow_rotation {'on' if node.rot.follow_rotation else 'off'}")        # (what the rotator was really given: the e2e tests read it)
    locsvcs = {t: LocatorService(me, peers, c, books[t], pdialers[t], log=nlog, on_adopt=node.address_changed) for t, c in carriers.items()}     # an address is announced and verified over ITS carrier only
    locsvc = locsvcs[tor.type]
    node.notify_to = NotifyDialer(pdialers, usable=cset.usable if cset else None, log=nlog)     # (M4b: the notify address a peer asked for is dialed first for our notifies to it; the pull addresses stay the fallback)
    nvia = carriers.get(NOTIFY_TYPES.get(cfg.get("notify_via") or "", ""))     # (the config says "tor"/"tcp", the carriers are keyed by carrier TYPE: "onion"/"tcp")                # M4b: where WE want notifies: our peer door for that peer on this carrier (None = no field is sent, as before)
    if nvia is not None:
        node.notify_field = lambda agent: ({"type": nvia.type, "addr": a} if (cset is None or cset.usable(nvia.type)) and (a := locsvcs[nvia.type]._our_address(agent)) else None)
    elif cfg.get("notify_via"):
        out(f"  notify_via {cfg['notify_via']} is not a carrier of this node ({'+'.join(carriers)}): no notify address is sent")
    blobs = BlobStore(home / "blobs")
    bindex = BlobIndex(m)
    bsvc = BlobService(blobs, bindex, log=out)
    warm_blob_snapshot(m, bsvc)
    syncsrv = None                                                  # (the routers below ask it which carrier the request being handled arrived over)
    syncsrv = SyncServer(m, identity=me, on_notify=node.on_notify, on_push=node.on_push, blobs=bsvc, pong=node.pong_for, ping_log=make_ping_log(out),
                         on_locator=route_locator(locsvcs, tor.type, lambda: syncsrv.via()), on_inbound=route_inbound(books), on_notify_at=route_notify_at(locsvcs), on_peer_ver=lambda agent, d: node.pv.note(agent, d), on_refuse=node.note_refusal)
    node.heard_from = syncsrv.heard.get                              # (M4a: an acknowledged notify the peer does not answer with a pull of its own makes us pull it, and a pull pushes)
    syncsrv.set_peers(peers.all())                                  # (who counts as a KNOWN sender for the server's budgets: refreshed every few seconds in the loop below)
    join_handler = capsule.JoinServer(home, list(carriers.values()), me, m).handle                # (M2: one JoinServer behind the join door of EVERY carrier)
    knock_handler = knock.KnockServer(home, list(carriers.values()), me, m, notify=lambda kid, tid: m.note_knock(tid)).handle      # (the open invitation: a public door, the primary carrier only)
    handlers = {"read": PublicRead(syncsrv, blobs=PublicBlob(syncsrv, bsvc)).handle, "inbox": Inbox(m, home).handle, "join": join_handler, "knock": knock_handler}
    doors_by = {t: Doors(c, syncsrv, out, handlers if c is tor else {"join": join_handler}, allow_public_without_ip_hiding=allow_public_without_ip_hiding) for t, c in carriers.items()}     # public doors: the primary carrier only
    pings = PingService(node, home, dialer)                         # (the dialer takes `left`: the CLI gives up at its deadline, so the dial must too)
    waker = Waker(home / "node.poke")
    waker.event = node.wake                                        # a notify or a finished pull wakes the loop; a CLI append pokes the file
    bworker = BlobWorker(node, blobs, bindex, Wants(home / "blobs"), me, lambda s: out(s))
    joiner = _JoinWorker(home, carriers, me, PeerBook(home / "peers.json"), out, m.codec, usable=cset.usable if cset else None)
    old_term = None
    if threading.current_thread() is threading.main_thread():
        def _term(signum, frame):
            raise KeyboardInterrupt                                # SIGTERM = Ctrl-C: the finally block below runs (also during a restart backoff)
        old_term = signal.signal(signal.SIGTERM, _term)
    try:
        capsule.sweep(home, list(carriers.values()))               # expired / rejected / abandoned join doors are deleted BEFORE tor starts, on every carrier (a kill -9 must not leave one)
        knock.sweep(home, list(carriers.values()))                 # ... and the knock doors of ended cards
        doors_up = lambda: sum(len(d.servers) for d in doors_by.values())           # noqa: E731
        doors_total = lambda: sum(len(c.doors()) for c in carriers.values())        # noqa: E731
        if multi:
            out("starting the carriers: " + ", ".join(sorted(carriers, key=lambda t: t == "onion")) + " (tor bootstraps in the background; the others serve at once)")
            for ev in cset.start_all(order=sorted(carriers, key=lambda t: t == "onion")):
                out(f"  {ev}")
            if not cset.any_alive():
                out("error: no carrier could start: " + cset.reasons())
                return 1
            for t in cset.up_types():
                doors_by[t].sync()
                _reload_after_up(carriers[t])
                _door_lines(carriers[t], out)
            pending = [t for t in carriers if not cset.usable(t)]
            out(f"serving sync on loopback behind {doors_up()} door(s) on {'+'.join(cset.up_types())}" + (f" ({', '.join(pending)} not up yet)" if pending else "") + f"; {len(peers.all())} peer(s) in the book. Ctrl-C to stop.")
        else:
            for c in sorted(carriers.values(), key=lambda c: c.type == "onion"):          # the carriers that start at once (tcp) before the one that bootstraps (tor): their doors serve while tor takes its minute
                out(f"starting the {c.type} carrier" + (" (bootstrap can take a minute; first descriptor publication a few more)..." if c.type == "onion" else "..."))
                c.start(wait=True)
                doors_by[c.type].sync()
                _door_lines(c, out)
            out(f"serving sync on loopback behind {doors_up()} door(s) on {'+'.join(carriers)}; {len(peers.all())} peer(s) in the book. Ctrl-C to stop.")
        status(ready=True, doors_up=doors_up(), doors_total=doors_total())
        end = time.time() + seconds if seconds else None
        restarts: dict = {t: [] for t in carriers}                 # (one-carrier path) monotonic times of each carrier's restarts inside the window
        shown: dict = {}                                           # carrier door problems already reported
        next_gc = 0.0
        next_peers = 0.0
        while end is None or time.time() < end:
            waker.round_started()                                  # BEFORE the round's work: a wake that arrives during it ends the next wait at once
            if time.time() >= next_gc:
                next_gc = time.time() + BLOB_GC_EVERY
                try:
                    with m._lock():                                # (the index reads the threads' event tables: same lock as the writers)
                        keep = bindex.referenced()
                    for c in blobs.gc(keep):
                        out(f"  blob {c[:19]}.. removed (no event references it any more)")
                except Exception as e:                             # noqa: BLE001 - housekeeping must never take the node down
                    out(f"  blob gc: {type(e).__name__}")
            if multi:                                              # one non-blocking step per carrier: a tor that is down or bootstrapping never stalls the pulls, notifies and pings on the others
                for ev in cset.tick():
                    out(f"  {ev}")
                for t, (was, now_) in cset.changed.items():
                    if now_ == "up":
                        doors_by[t].sync()
                        _reload_after_up(carriers[t])
                        _door_lines(carriers[t], out)
                    elif was == "up":
                        doors_by[t].stop()                         # the loopback listeners of a carrier that is gone: closed now, re-created (same ports) when it is up again
                if cset.none_up_too_long():
                    out("error: no carrier has been up for a while, nothing left to serve with: " + cset.reasons())
                    return 1
            else:
                dead = next((t for t, c in carriers.items() if not c.healthy()), None)
                if dead is not None:
                    if not _recover_carrier(carriers[dead], doors_by[dead], out, restarts[dead], end):
                        return 1
                    continue
            for t, c in carriers.items():
                if multi and not cset.usable(t):
                    continue
                doors_by[t].sync()
                for door, why in sorted(getattr(c, "last_errors", dict)().items()):     # a door the carrier could not open (said once per message; retried every tick)
                    if shown.get((t, door)) != why:
                        shown[(t, door)] = why
                        out(f"  carrier: door {door} is not being served: {why}")
            if time.time() >= next_peers:
                next_peers = time.time() + 2.0
                syncsrv.set_peers(peers.all())
            node.tick(parallel=True)
            node.refresh_snapshot()                                # (the pong snapshot: only when a ping asked since the last refresh, or every SNAPSHOT_MAX_AGE; the server answers from it without any lock)
            pings.tick()                                           # `sigilnet ping` requests from the CLI (home/ping/*.req)
            _tick_locator_services(locsvcs, cset.usable if multi else None)      # tell peers our new address / verify the addresses they told us (one worker thread per carrier, never waited for; none for a carrier that is down)
            joiner.tick()
            bworker.tick()
            status(ready=True, doors_up=doors_up(), doors_total=doors_total())
            waker.wait(TICK)
    except KeyboardInterrupt:
        pass
    except (CarrierError, ValueError, OSError) as e:
        out(f"error: {e}")
        return 1
    finally:
        if old_term is not None:
            signal.signal(signal.SIGTERM, old_term)
        for d in doors_by.values():
            d.stop()
        node.close()
        pings.close()
        for ls in locsvcs.values():
            ls.close()
        for c in carriers.values():
            c.stop()
        node._save()
        daemon.clear_files(home)
    return 0
