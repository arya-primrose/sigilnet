"""The listeners behind a carrier's doors (protocol layer; no Tor in here). One guarded loopback TcpServer per door (tcp.py: framing, MAX_REQ/MAX_RESP, deadlines,
connection cap), answering with the program that belongs to the door's kind. `noderun.py` is the composition root that picks the carrier."""
from __future__ import annotations

from .carrier import PUBLIC_KINDS, Carrier
from .sync import SyncServer
from .tcp import TcpServer

SHARED = "(shared)"


def door_handler(kind: str, agent, srv: SyncServer, handlers: dict, via=None):
    """The program that answers a door, by its kind. A kind without a handler answers NOTHING useful (the stranger's answer): never the sync server. `via` is the carrier type of the door."""
    if kind == "peer":
        return service_handler(srv, agent, via)
    h = handlers.get(kind)
    return h if h is not None else srv.refuse


def service_handler(srv: SyncServer, agent, via=None):
    """One per-peer onion service: if it is bound to an agent id, requests from anyone else get the stranger's answer (the peer's KEY, not just its
    descriptor key, is what this door is for). `via`: the carrier type of this door; the sync server is told (arrived_on) so an authenticated request refreshes that carrier's in_at."""
    arrived = getattr(srv, "arrived_on", None) if via is not None else None

    def handle(req):
        if agent is not None and not (isinstance(req, dict) and req.get("from") == agent):
            return srv.refuse(req)
        if arrived is None:
            return srv.handle(req)
        with arrived(via):
            return srv.handle(req)
    return handle


class Doors:
    """The loopback listeners behind the per-peer onion services: one per door, each with its own connection limits. `sync()` follows services.json:
    a door that is new, removed, moved to another port or BOUND TO ANOTHER AGENT gets a fresh listener; a door whose port cannot be bound is reported
    (once) and retried on the next call, without touching the others."""

    def __init__(self, tor: Carrier, syncsrv: SyncServer, out=print, handlers: dict | None = None, *, allow_public_without_ip_hiding: bool = False):
        self.tor, self.syncsrv, self.out = tor, syncsrv, out
        self.allow_public = allow_public_without_ip_hiding or "hides_ip" in tor.capabilities     # a public door announces an address: not on a carrier that does not hide ours, unless told
        self.handlers = handlers or {}                              # kind -> handler for the public / join doors (publicread, inbox, capsule)
        self.servers: dict = {}                                    # name -> TcpServer
        self.bound: dict = {}                                      # name -> (port, agent) the listener was built for
        self.failed: dict = {}                                     # name -> error text already reported

    def sync(self) -> None:
        self.tor.reconfigure()                                     # doors added/removed/re-keyed by the CLI: new torrc + SIGHUP
        want = self.tor.doors()
        if not self.allow_public:
            for k in [k for k, v in want.items() if v["kind"] in PUBLIC_KINDS]:
                self._report(k, OSError("a public door on a carrier that does not hide this host's address is refused (node run --allow-public-without-ip-hiding)"))
                want.pop(k)
        for name in [k for k in self.servers if k != SHARED and (k not in want or self.bound[k] != (want[k]["port"], want[k]["agent"], want[k]["kind"]))]:
            self.servers.pop(name).stop()
            self.bound.pop(name, None)
        self.failed = {k: v for k, v in self.failed.items() if k in want}
        if self.tor.shared_port() and SHARED not in self.servers:  # the legacy ONE shared service (only if the config asks for it)
            try:
                self.servers[SHARED] = TcpServer("127.0.0.1", self.tor.shared_port(), None, service_handler(self.syncsrv, None, self.tor.type)).start()
            except OSError as e:
                self._report(SHARED, e)
        for name, svc in want.items():
            if name in self.servers:
                continue
            try:
                self.servers[name] = TcpServer("127.0.0.1", svc["port"], None, door_handler(svc["kind"], svc["agent"], self.syncsrv, self.handlers, self.tor.type),
                                              **self.tor.server_limits(svc["kind"])).start()
                self.bound[name] = (svc["port"], svc["agent"], svc["kind"])
                self.failed.pop(name, None)
            except OSError as e:
                self._report(name, e)

    def _report(self, name: str, e: OSError) -> None:
        msg = f"{type(e).__name__}: {e.strerror or e}"
        if self.failed.get(name) != msg:
            self.failed[name] = msg
            self.out(f"  cannot open the door for {name}: {msg} (the other doors keep working; retrying)")

    def stop(self) -> None:
        for sv in self.servers.values():
            sv.stop()
        self.servers.clear()
        self.bound.clear()
