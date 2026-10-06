"""Helpers for the round-4 adversarial tests (step 3). Loopback only; no real tor network."""
import json
import random
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path

from sigilnet import node as N
from sigilnet import sync as S
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror

ONION = "a" * 56 + ".onion"
ONION2 = "b" * 56 + ".onion"


class Clock:
    def __init__(self, t=None):
        self.t = time.time() if t is None else t

    def __call__(self):
        return self.t


class Reply:
    """A transport from a function req -> response dict; adds the nonce echo and r=1 unless the function returns them itself."""

    def __init__(self, fn, echo=True):
        self.fn, self.echo, self.calls = fn, echo, []

    def request(self, req):
        self.calls.append(req)
        resp = self.fn(req)
        if self.echo and isinstance(resp, dict):
            resp = {"nonce": req["nonce"], "r": 1, **resp}
        return resp


class Signing:
    """Wraps a fake transport so its well-formed responses are signed by `ident`, as a real SyncServer does (the node requires this)."""

    def __init__(self, inner, ident):
        self.inner, self.ident = inner, ident

    def request(self, req):
        resp = self.inner.request(req)
        if isinstance(resp, dict) and isinstance(resp.get("nonce"), str) and type(resp.get("r")) is int and "by" not in resp and "rsig" not in resp:
            resp = {**resp, "by": self.ident.sign_pub}
            resp["rsig"] = self.ident.sign(S.RESP_CTX + S.canon.dumps(resp))
        return resp


def ep(onion, port=47200):
    """An onion endpoint {type, addr} (carrier.py)."""
    return {"type": "onion", "addr": f"{onion}:{port}"}


class Env:
    """Our node (me) with a mirror holding one thread in which `peer` is a member; a peer book naming `peer` at ONION."""

    def __init__(self, n_peers=1, rate_limit=False, pull_interval=300.0, transport=None, clock=None):
        self.home = Path(tempfile.mkdtemp())
        self.clock = clock or Clock()
        self.me = Identity.generate("me")
        self.peers = [Identity.generate(f"p{i}") for i in range(n_peers)]
        self.m = Mirror(self.home / "mirror", rate_limit=rate_limit, clock=self.clock)
        self.genesis = make_genesis(self.me, "thread", [(p, "member") for p in self.peers], k=1)
        self.tid = event_id(self.genesis)
        self.m.ingest(self.genesis)
        self.book = N.PeerBook(self.home / "peers.json")
        for i, p in enumerate(self.peers):
            self.book.add(p.id, f"p{i}", ep(chr(ord("a") + i) * 56 + ".onion"))
        self.transports = {}
        self.default = transport
        self.node = self.build(pull_interval)

    def build(self, pull_interval=300.0):
        return N.Node(self.m, self.me, self.book, self.home / "node.json", self.transport_for, clock=self.clock, rng=random.Random(7),
                      pull_interval=pull_interval)

    def transport_for(self, rec):
        for i, p in enumerate(self.peers):
            if rec["endpoint"]["addr"].split(":")[0] == chr(ord("a") + i) * 56 + ".onion":
                t = self.transports.get(p.id, self.default)
                return Signing(t, p) if hasattr(t, "request") else t
        raise AssertionError("unknown endpoint " + str(rec["endpoint"]))

    def state(self):
        return json.loads((self.home / "node.json").read_text())


def down_transport(exc=None):
    def fn(req):
        raise exc or ConnectionError("down")
    return Reply(fn)


def read_until_closed(sock, timeout=5.0, limit=1 << 20):
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < limit:
            c = sock.recv(65536)
            if not c:
                break
            buf += c
    except socket.timeout:
        buf += b"<TIMEOUT>"
    except OSError:
        pass                                   # reset by the peer: the connection is closed
    return buf


class FakeSocks:
    """A scripted SOCKS5 proxy on a loopback port. script(conn, greeting, request) runs in its own thread for every connection; `seen` keeps what the client sent."""

    def __init__(self, script, read_request=True):
        self.script, self.read_request = script, read_request
        self.seen, self.conns = [], 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self.stop_ev = threading.Event()
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    @property
    def socks(self):
        return ("127.0.0.1", self.port)

    def loop(self):
        while not self.stop_ev.is_set():
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.conns += 1
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        try:
            c.settimeout(5)
            greeting = c.recv(3)
            req = b""
            self.seen.append(greeting)
            if self.read_request and greeting == b"\x05\x01\x00":
                c.sendall(b"\x05\x00")
                req = self._read_req(c)
                self.seen.append(req)
            self.script(c, greeting, req)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    @staticmethod
    def _read_req(c):
        head = c.recv(5)
        if len(head) < 5:
            return head
        n = head[4]
        rest = b""
        while len(rest) < n + 2:
            ch = c.recv(n + 2 - len(rest))
            if not ch:
                break
            rest += ch
        return head + rest

    def close(self):
        self.stop_ev.set()
        self.sock.close()


OK_REPLY = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"


def frame(b):
    return struct.pack(">I", len(b)) + b


def collect_thread_errors():
    """Context helper: records unhandled exceptions in any thread (threading.excepthook)."""
    class C:
        def __enter__(s):
            s.errors = []
            s.old = threading.excepthook
            threading.excepthook = lambda a: s.errors.append(a)
            return s

        def __exit__(s, *a):
            threading.excepthook = s.old
    return C()
