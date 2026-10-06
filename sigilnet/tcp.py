"""Direct-link transport for sync: one request frame in, one response frame out, both Fernet-encrypted with a key the two agents share
(ttl 11 min: a little more than the request clock skew, so a peer whose clock is off by a few minutes still works). Private/loopback addresses only by default: this is the same-host / same-LAN link, not the internet.
Hard limits everywhere (frame sizes, deadlines, concurrent connections) because the server faces a peer that may be hostile or buggy.

PLAIN mode (key=None) is for Tor (step 3): the frames carry canonical JSON without the Fernet layer, because Tor already encrypts the circuit, the onion
service authorizes its clients, and every request is signed by the requester's agent key (sync.py). A plain server is therefore loopback-only (it
is reached through the local Tor daemon, never directly), and since every Tor connection arrives from 127.0.0.1 the per-address caps are replaced by
GLOBAL ones (concurrent connections, connections per minute)."""
from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

from . import canon

MAX_REQ = 64 * 1024
MAX_RESP = 1024 * 1024
TTL = 660                     # frames older than this are dropped; replay inside the window is stopped by the request nonce cache and the nonce echoed in responses (sync.py)
DEADLINE = 8.0                # a whole request/response exchange
HEADER_DEADLINE = 2.0         # the 4-byte length header: an idle connection is dropped quickly
PER_IP_CONNS = 2              # concurrent connections from one address (idle sockets cannot starve the peer)
PER_IP_PER_MIN = 600          # connections per minute from one address
PLAIN_CONNS = 8               # plain mode: concurrent connections in total (they all come from 127.0.0.1)
PLAIN_PER_MIN = 240           # plain mode: connections per minute in total


def _decrypt(f: Fernet, raw: bytes) -> bytes:
    """Fernet's own ttl check rejects tokens more than 60 s in the FUTURE whatever the ttl, which would drop a peer whose clock runs a little fast.
    We check the frame's timestamp ourselves against the same window as the requests (TTL either way); replay inside it is stopped by the nonce
    cache on the server and the echoed nonce in the response (sync.py)."""
    ts = f.extract_timestamp(raw)                 # verifies the frame's MAC (raises InvalidToken for a wrong key)
    if abs(time.time() - ts) > TTL:
        raise InvalidToken
    return f.decrypt(raw)


def new_key() -> str:
    return Fernet.generate_key().decode()


def local_ip() -> str:
    """This machine's outbound-facing IPv4 (no packet is sent); 127.0.0.1 if there is none."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _check_bind(host: str, allow_public: bool) -> None:
    ip = ipaddress.ip_address(host)
    if (ip.is_unspecified or ip.is_multicast or not (ip.is_private or ip.is_loopback)) and not allow_public:
        raise ValueError(f"refusing to bind {host}: not a specific private/loopback address (0.0.0.0 listens on EVERY interface; "
                         f"pass allow_public=True if you really mean it)")


def _read_exact(conn: socket.socket, n: int, deadline: float) -> bytes | None:
    buf = b""
    while len(buf) < n:
        left = deadline - time.time()
        if left <= 0:
            return None
        conn.settimeout(left)
        try:
            chunk = conn.recv(min(65536, n - len(buf)))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_frame(conn: socket.socket, cap: int, deadline: float) -> bytes | None:
    head = _read_exact(conn, 4, deadline)
    if head is None:
        return None
    (n,) = struct.unpack(">I", head)
    if n == 0 or n > cap:
        return None
    return _read_exact(conn, n, deadline)


def _frame(token: bytes) -> bytes:
    return struct.pack(">I", len(token)) + token


class TcpServer:
    def __init__(self, host: str, port: int, key: str | None, handler, *, max_conns: int = 16, allow_public: bool = False, allowed_ips=None, plain_per_min: int | None = None):
        if plain_per_min is not None and (isinstance(plain_per_min, bool) or not isinstance(plain_per_min, int) or plain_per_min < 1):
            raise ValueError("plain_per_min must be a positive integer")
        self.plain_per_min = plain_per_min or PLAIN_PER_MIN        # (plain mode only; a carrier that authenticated its visitors itself may raise it: carrier.server_limits)
        self.plain = key is None
        if self.plain:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("a plain (Tor) server binds loopback only: it is reached through the local Tor daemon, never directly")
            max_conns = min(max_conns, PLAIN_CONNS)
        else:
            _check_bind(host, allow_public)
        self.allowed_ips = set(allowed_ips) if allowed_ips else None       # optionally accept only the peer's address(es)
        self.per_ip: dict[str, int] = {}
        self.recent: dict[str, list] = {}
        self.mu = threading.Lock()
        self.host, self.port, self.f, self.handler = host, port, (None if self.plain else Fernet(key.encode())), handler
        self.sem = threading.BoundedSemaphore(max_conns)
        self.stop_ev = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(32)
        self.sock.settimeout(0.5)
        self.thread: threading.Thread | None = None

    def start(self) -> "TcpServer":
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()
        return self

    def serve_forever(self) -> None:
        while not self.stop_ev.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop_ev.is_set() or self.sock.fileno() == -1:
                    break                                          # we are being stopped
                time.sleep(0.05)                                   # a transient error (ECONNABORTED, EMFILE, ...): the listener must outlive it
                continue
            ip = addr[0]
            if self.allowed_ips is not None and ip not in self.allowed_ips:
                conn.close()
                continue
            if not self._admit(ip):                               # too many at once / too fast from one address: drop, do not queue
                conn.close()
                continue
            if not self.sem.acquire(blocking=False):
                self._release(ip)
                conn.close()
                continue
            threading.Thread(target=self._serve_one, args=(conn, ip), daemon=True).start()

    def _admit(self, ip: str) -> bool:
        now = time.time()
        if self.plain:
            ip = "*"                                              # every Tor connection looks the same: one global bucket
        with self.mu:
            hits = [t for t in self.recent.get(ip, []) if now - t < 60]
            if self.plain:
                if self.per_ip.get(ip, 0) >= PLAIN_CONNS or len(hits) >= self.plain_per_min:
                    self.recent[ip] = hits
                    return False
            elif self.per_ip.get(ip, 0) >= PER_IP_CONNS or len(hits) >= PER_IP_PER_MIN:
                self.recent[ip] = hits
                return False
            hits.append(now)
            self.recent[ip] = hits
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            if len(self.recent) > 1024:
                self.recent = {k: v for k, v in self.recent.items() if v and now - v[-1] < 60}
            return True

    def _release(self, ip: str) -> None:
        if self.plain:
            ip = "*"
        with self.mu:
            n = self.per_ip.get(ip, 0) - 1
            if n > 0:
                self.per_ip[ip] = n
            else:
                self.per_ip.pop(ip, None)

    def _serve_one(self, conn: socket.socket, ip: str = "") -> None:
        try:
            deadline = time.time() + DEADLINE
            head = _read_exact(conn, 4, min(deadline, time.time() + HEADER_DEADLINE))
            if head is None:
                return
            (n,) = struct.unpack(">I", head)
            raw = _read_exact(conn, n, deadline) if 0 < n <= MAX_REQ else None
            if raw is None:
                return
            try:
                req = canon.loads(raw if self.plain else _decrypt(self.f, raw))
            except (InvalidToken, canon.CanonError, ValueError):
                return                                              # wrong key, stale frame, or garbage: no answer at all
            resp = canon.dumps(self.handler(req))
            if len(resp) > MAX_RESP:
                resp = canon.dumps({"t": "error", "why": "response too large"})
            conn.settimeout(max(0.1, deadline - time.time()))
            conn.sendall(_frame(resp if self.plain else self.f.encrypt(resp)))
        except (OSError, canon.CanonError):
            pass
        finally:
            try:
                conn.close()
            finally:
                self._release(ip)
                self.sem.release()

    def stop(self) -> None:
        self.stop_ev.set()
        try:
            self.sock.close()
        except OSError:
            pass
        if self.thread:
            self.thread.join(2)


class TcpTransport:
    def __init__(self, host: str, port: int, key: str | None, timeout: float = 10.0, connect_timeout: float | None = None):
        self.host, self.port, self.timeout = host, port, timeout
        self.connect_timeout = connect_timeout                      # None: ONE budget for connecting and exchanging; else connecting has its own (a first rendezvous is slow)
        self.f = None if key is None else Fernet(key.encode())

    def _connect(self, end: float):
        return socket.create_connection((self.host, self.port), timeout=max(0.1, end - time.time()))

    def request(self, req: dict) -> dict:
        data = canon.dumps(req)
        if len(data) > MAX_REQ:
            raise ValueError("request too large")
        t0 = time.time()
        with self._connect(t0 + (self.connect_timeout or self.timeout)) as s:
            end = (time.time() if self.connect_timeout else t0) + self.timeout        # the exchange budget starts after connecting if connecting has its own
            s.settimeout(max(0.1, end - time.time()))
            s.sendall(_frame(data if self.f is None else self.f.encrypt(data)))
            raw = _read_frame(s, MAX_RESP + 4096, end)
        if raw is None:
            raise ConnectionError("no valid response")
        try:
            return canon.loads(raw if self.f is None else _decrypt(self.f, raw))
        except (InvalidToken, canon.CanonError) as e:
            raise ConnectionError("response could not be decrypted") from e
