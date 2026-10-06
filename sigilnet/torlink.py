"""Tor plumbing for step 3: an onion-only SOCKS5 client, the torrc we write, client-authorization files, and a manager for OUR OWN tor process.

What runs where:
  * we start `tor` ourselves with a private DataDirectory under the sigilnet home; its SocksPort is bound to 127.0.0.1 only and there is no ControlPort;
  * our sync server listens on 127.0.0.1 (plain frames, tcp.py) and tor forwards the onion service's virtual port to it: nothing listens on a public address;
  * the onion service uses v3 CLIENT AUTHORIZATION: only holders of a listed x25519 key can even read its descriptor. The DIALING peer generates its
    key pair and sends us only the PUBLIC half (`authorize`), so no private key ever travels; the dialing peer keeps the private half for
    ClientOnionAuthDir (`add_client_auth`);
  * we only ever dial v3 .onion names (the SOCKS5 name is resolved inside tor, never by us): a mistyped clearnet address cannot leave through tor.
Hard limits everywhere; nothing here trusts what a peer or the log says beyond the documented formats."""
from __future__ import annotations

import base64
import os
import ctypes
import fcntl
import hashlib
import json
import re
import shutil
import uuid
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import x25519

from . import onion as _onion
from .carrier import KINDS, PUBLIC_KINDS, Carrier, CarrierError, Secret, check_credential
from .keys import AGENT_ID_RE
from .onion import B32_KEY_RE, ONION_RE
from .tcp import TcpTransport

NAME_RE = re.compile(r"[a-z0-9_-]{1,32}")
BRIDGE_KEYWORDS = ("Bridge ", "ClientTransportPlugin ", "UseBridges ")
SERVICE_BASE = 47210                      # first local port handed to a per-peer onion service
MAX_SERVICES = 64
# door kinds (carrier.KINDS): peer: client-authorized door for one peer; read/inbox: PUBLIC doors (no client auth, step 4a); join: one-time capsule door (client-authorized with a throwaway key, step 4)
BOOTSTRAP_TIMEOUT = 180.0
CONNECT_TIMEOUT = 60.0                     # building a rendezvous circuit to an onion service can take a while

# tor's extended SOCKS5 reply codes (proposal 304) -> (name, worth retrying later)
SOCKS_ERRORS = {
    0x01: ("general failure", True), 0x02: ("not allowed", False), 0x03: ("network unreachable", True), 0x04: ("host unreachable", True),
    0x05: ("connection refused (nothing listens behind the onion service)", True), 0x06: ("TTL expired", True),
    0x07: ("command not supported", False), 0x08: ("address type not supported", False),
    0xF0: ("onion service descriptor cannot be found (offline or not published yet)", True),
    0xF1: ("onion service descriptor is invalid", True), 0xF2: ("onion service introduction failed", True),
    0xF3: ("onion service rendezvous failed", True), 0xF4: ("onion service needs authentication (no client key configured)", False),
    0xF5: ("onion service client authentication is wrong (we are not authorized)", False), 0xF6: ("invalid onion address", False),
    0xF7: ("onion service introduction timed out", True),
}


class TorError(CarrierError):
    """A tor-level failure; `retry` says whether trying again later can help (an unauthorized client cannot fix itself by waiting)."""

    def __init__(self, msg: str, retry: bool = True):
        super().__init__(msg)
        self.retry = retry


# ---------------------------------------------------------------- client authorization keys

def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=")


def make_client_key() -> tuple[str, str]:
    """(private, public) x25519 client-authorization key, both base32 (no padding) as tor wants them. The private half never leaves this host."""
    k = x25519.X25519PrivateKey.generate()
    priv = k.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())
    pub = k.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    return _b32(priv), _b32(pub)


def check_pub(pub: str) -> str:
    pub = (pub or "").strip()
    if not B32_KEY_RE.fullmatch(pub):
        raise ValueError("a client public key is 52 characters of base32 (A-Z, 2-7)")
    return pub


def check_onion(onion: str) -> str:
    onion = (onion or "").strip().lower()
    if not ONION_RE.fullmatch(onion):
        raise ValueError("expected a v3 onion address (56 base32 characters + .onion)")
    return onion


# ---------------------------------------------------------------- SOCKS5 to an onion service

def socks5_connect(socks: tuple, onion: str, port: int, timeout: float = CONNECT_TIMEOUT) -> socket.socket:
    """Open a stream to onion:port through the tor SocksPort `socks` = (host, port). The name goes to tor unresolved (ATYP 3)."""
    onion = check_onion(onion)
    if not 0 < int(port) < 65536:
        raise ValueError("bad port")
    end = time.time() + timeout
    try:
        s = socket.create_connection(socks, timeout=min(timeout, 10.0))
    except OSError as e:
        raise TorError(f"tor SocksPort {socks[0]}:{socks[1]} is not reachable ({e.strerror or type(e).__name__}): is tor running?") from e
    try:
        def need(n: int) -> bytes:
            buf = b""
            while len(buf) < n:
                left = end - time.time()
                if left <= 0:
                    raise TorError("tor did not answer in time")
                s.settimeout(left)
                try:
                    chunk = s.recv(n - len(buf))
                except OSError as e:
                    raise TorError(f"tor connection failed ({type(e).__name__})") from e
                if not chunk:
                    raise TorError("tor closed the connection")
                buf += chunk
            return buf

        s.settimeout(min(timeout, 10.0))
        s.sendall(b"\x05\x01\x00")                                   # version 5, one method: no authentication
        if need(2) != b"\x05\x00":
            raise TorError("tor SocksPort refused the handshake", retry=False)
        name = onion.encode("ascii")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", int(port)))
        ver, rep, _rsv, atyp = need(4)
        if ver != 5:
            raise TorError("not a SOCKS5 reply", retry=False)
        if rep != 0:
            what, retry = SOCKS_ERRORS.get(rep, (f"unknown SOCKS error 0x{rep:02x}", True))
            raise TorError(f"tor could not reach {onion[:8]}...: {what}", retry=retry)
        skip = {1: 4, 4: 16}.get(atyp)
        if skip is None and atyp == 3:
            skip = need(1)[0]
        if skip is None:
            raise TorError("bad SOCKS5 reply address type", retry=False)
        need(skip + 2)
        return s
    except BaseException:
        s.close()
        raise


class TorTransport(TcpTransport):
    """`request(dict) -> dict` to a peer's onion service (plain frames; signatures authenticate, tor and the onion authorization protect the wire)."""

    def __init__(self, onion: str, port: int, socks: tuple = ("127.0.0.1", 9050), timeout: float = 60.0, connect_timeout: float | None = None):
        super().__init__(check_onion(onion), int(port), None, timeout, connect_timeout)
        self.socks = (socks[0], int(socks[1]))

    def _connect(self, end: float):
        return socks5_connect(self.socks, self.host, self.port, max(0.1, end - time.time()))


# ---------------------------------------------------------------- our own tor process

def _q(path) -> str:
    """A torrc value in double quotes with backslash and quote escaped: spaces, '#', quotes and non-ASCII in a path are harmless (control characters are refused earlier)."""
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _port(p, what: str) -> int:
    if isinstance(p, bool) or not isinstance(p, (int, str)) or (isinstance(p, str) and not (p.isascii() and p.isdigit())):
        raise ValueError(f"{what} must be a port number")
    p = int(p)
    if not 0 < p < 65536:
        raise ValueError(f"{what} must be between 1 and 65535")
    return p


def _write_private(path: Path, text: str) -> None:
    """Create/replace a secret file that is 0600 from the very first byte (write_text + chmod leaves a window where it is world-readable)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(text)


try:
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)              # loaded BEFORE any fork: the child between fork and exec only calls prctl
except OSError:
    _LIBC = None
PR_SET_PDEATHSIG = 1


def _die_with_parent(parent_pid: int) -> None:
    """Runs in the child before exec: the kernel sends tor SIGTERM if the process that started it dies for ANY reason (kill -9 included), so no orphan
    tor survives. (On Linux the signal is tied to the THREAD that forked: TorNode.start() must run in the main thread; if the parent already died between
    fork and prctl we exit at once.)"""
    if _LIBC is not None:
        _LIBC.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
        if os.getppid() != parent_pid:
            os._exit(1)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TorNode(Carrier):
    """A private tor instance (the Tor implementation of carrier.Carrier): SocksPort for dialing out, optionally one client-authorized onion service forwarding `virtual_port` to 127.0.0.1:`local_port`."""

    def __init__(self, root, *, local_port: int | None = None, virtual_port: int = 47200, socks_port: int | None = None,
                 bridge_lines=(), tor_bin: str = "tor", offline: bool = False, service_port_base: int = SERVICE_BASE):
        if any(ord(c) < 32 or ord(c) == 127 for c in str(root)):
            raise ValueError("the tor directory path may not contain control characters")
        self.root = Path(root)
        self.data, self.hs, self.auth_in = self.root / "data", self.root / "hs", self.root / "client_auth"
        self.torrc, self.log, self.pidfile = self.root / "torrc", self.root / "tor.log", self.root / "tor.pid"
        self.local_port = _port(local_port, "local port") if local_port else None
        self.virtual_port = _port(virtual_port, "virtual port")
        self.socks_port = _port(socks_port, "socks port") if socks_port else _free_port()
        self.bridge_lines = [self._check_bridge_line(x) for x in bridge_lines]
        self.tor_bin, self.offline = tor_bin, offline
        self.service_base = _port(service_port_base, "service port base")
        self.svc_dir, self.svc_file = self.root / "services", self.root / "services.json"
        self.proc: subprocess.Popen | None = None
        for d in (self.root, self.data, self.auth_in, *([self.hs, self.hs / "authorized_clients"] if local_port else [])):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o700)
        self.services: dict = self._load_services()
        self._applied: dict | None = None                          # fingerprint of the doors (port, agent, client key) tor was last told about
        self._reload_due = False                                   # a door change was written but tor could not be told yet (still starting)
        self._term_at = None

    @staticmethod
    def _check_bridge_line(line: str) -> str:
        line = line.strip().rstrip("\\").rstrip()                  # a trailing backslash would continue the line in torrc syntax: dropped
        if any(ord(c) < 32 or ord(c) == 127 for c in line) or "\\" in line or not line.startswith(BRIDGE_KEYWORDS):
            raise ValueError("only Bridge / ClientTransportPlugin / UseBridges lines may be added to the tor configuration")
        return line

    def config(self) -> str:
        """The torrc. Loopback SocksPort, no ControlPort, no exit policy changes, nothing listens on a public address."""
        lines = [f"DataDirectory {_q(self.data)}", f"SocksPort 127.0.0.1:{self.socks_port}", "ControlPort 0", "Log notice stdout", f"PidFile {_q(self.pidfile)}",
                 "SafeLogging 1", "AvoidDiskWrites 1", f"ClientOnionAuthDir {_q(self.auth_in)}"]
        if self.offline:
            lines.append("DisableNetwork 1")                        # tests: create keys and files without touching the tor network
        limits = ["HiddenServiceMaxStreams 32", "HiddenServiceMaxStreamsCloseCircuit 1", "HiddenServiceEnableIntroDoSDefense 1", "HiddenServicePoWDefensesEnabled 1"]
        if self.local_port:
            lines += [f"HiddenServiceDir {_q(self.hs)}", "HiddenServiceVersion 3", f"HiddenServicePort {self.virtual_port} 127.0.0.1:{self.local_port}", *limits]
        for name, svc in sorted(self.services.items()):             # one onion service PER PEER: its own address, its own local port, its own limits
            lines += [f"HiddenServiceDir {_q(self.svc_dir / name)}", "HiddenServiceVersion 3", f"HiddenServicePort {self.virtual_port} 127.0.0.1:{svc['port']}", *limits]
        if self.bridge_lines:
            lines += ["UseBridges 1"] + [x for x in self.bridge_lines if not x.startswith("UseBridges ")]
        return "\n".join(lines) + "\n"

    # -- process
    def start(self, wait: bool = True, timeout: float = BOOTSTRAP_TIMEOUT, *, stale: bool = True) -> None:
        p = self.proc
        if p is not None and p.poll() is None:
            return
        if stale:
            self.stop_stale()                                      # a tor of ours left behind by a killed node would hold the data directory (a RESTART of a running node passes stale=False: it has none, and stopping one takes up to 16 s)
        self.services = self._load_services()
        _write_private(self.torrc, self.config())
        self._applied = self._fingerprint(self.services)
        _write_private(self.log, "")
        with open(self.log, "ab") as logf:                           # tor logs to stdout and we own the file: no path ever goes into the torrc's Log line
            if threading.current_thread() is not threading.main_thread():
                raise RuntimeError("TorNode.start() must run in the main thread (the kernel ties the child's death signal to the forking thread)")
            me = os.getpid()
            self.proc = subprocess.Popen([self.tor_bin, "-f", str(self.torrc)], stdin=subprocess.DEVNULL, stdout=logf,
                                         stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=lambda: _die_with_parent(me))
        self._term_at = None
        self._reload_due = False                                   # (start() read the files itself)
        if wait:
            self.wait_ready(timeout)

    def stop_stale(self, timeout: float = 15.0) -> bool:
        """Stop a tor that runs OUR torrc but is not our child (the node that started it was killed hard): it would keep the DataDirectory locked and the
        new tor would die with 'another Tor process is running'. Verified by pid file + /proc (never signals anything else). True if one was stopped."""
        pid = self._running_pid() if not self.running() else None
        if pid is None:
            return False
        os.kill(pid, signal.SIGTERM)
        end = time.time() + timeout
        while time.time() < end and self._running_pid() == pid:
            time.sleep(0.2)
        if self._running_pid() == pid:
            os.kill(pid, signal.SIGKILL)
            time.sleep(1.0)
        return True

    def _log_tail(self, n: int = 6) -> str:
        try:
            return " | ".join(self.log.read_text(errors="replace").splitlines()[-n:])
        except OSError:
            return ""

    def poll_ready(self) -> tuple:
        """One non-blocking look at the tor we started: ("ready", "") once it is usable (bootstrapped; offline: its onion addresses exist), ("starting", "") while it is coming up, ("failed", why)
        when the process is gone. The reason is read from the log NOW: a restart truncates it."""
        p = self.proc
        if p is None or p.poll() is not None:
            return ("failed", self._exit_text(p) + f": {self._log_tail()}")
        if self.offline:
            if (self.local_port and not self.hostname()) or any(not self.service_address(n) for n in self.services):
                return ("starting", "")
            return ("ready", "")
        return ("ready", "") if "Bootstrapped 100%" in self._log_text() else ("starting", "")

    def wait_ready(self, timeout: float = BOOTSTRAP_TIMEOUT) -> None:
        end = time.time() + timeout
        while time.time() < end:
            state, why = self.poll_ready()
            if state == "failed":
                raise TorError(why, retry=False)
            if state == "ready":
                return
            time.sleep(0.2 if self.offline else 0.5)
        raise TorError(f"tor did not bootstrap within {timeout:.0f} s: {self._log_tail()}")

    def _log_text(self) -> str:
        try:
            return self.log.read_text(errors="replace")
        except OSError:
            return ""

    def running(self) -> bool:
        p = self.proc                                              # (read ONCE: stop() sets it to None from the node's thread while workers and CLI paths ask)
        return p is not None and p.poll() is None

    def stop(self) -> None:
        p = self.proc
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(5)
        self.proc = None

    # -- stopping without blocking (the node loop): terminate now, reap on later ticks
    def stop_nowait(self) -> None:
        p = self.proc
        if p is not None and p.poll() is None:
            if getattr(self, "_term_at", None) is None:
                self._term_at = time.monotonic()
            try:
                p.terminate()
            except OSError:
                pass

    def reaped(self, kill_after: float = 10.0) -> bool:
        p = self.proc
        if p is None:
            return True
        if p.poll() is not None:
            self.proc = None
            self._term_at = None
            return True
        t = getattr(self, "_term_at", None)
        if t is not None and time.monotonic() - t >= kill_after:
            try:
                p.kill()
            except OSError:
                pass
        return False

    def begin_start(self, *, stale: bool = True) -> None:
        self.start(wait=False, stale=stale)

    @staticmethod
    def _exit_text(p) -> str:
        """How the tor process ended, for the reason a human reads in `status`: the exit status first (the log tail is mostly start-up notices, never the cause)."""
        rc = p.poll() if p is not None else None
        if rc is None:
            return "tor exited"
        if rc < 0:
            try:
                name = signal.Signals(-rc).name
            except ValueError:
                name = str(-rc)
            return f"tor exited (killed by signal {-rc} {name})"
        return f"tor exited (exit status {rc})"

    def down_reason(self) -> str:
        return self._exit_text(self.proc) + f": {self._log_tail()}"

    def _running_pid(self) -> int | None:
        """Our tor's pid: the child we started, or (from another process, e.g. the CLI) the one in the pid file IF it really is tor running our torrc."""
        p = self.proc
        if p is not None and p.poll() is None:
            return p.pid
        try:
            fd = os.open(self.pidfile, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)     # a FIFO or a symlink must not hang or redirect us
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return None
                pid = int(os.read(fd, 32).decode("ascii", "ignore").strip())
            finally:
                os.close(fd)
            if pid <= 1:
                return None
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except (OSError, ValueError):
            return None
        return pid if str(self.torrc).encode() in cmd and any(Path(c.decode(errors="ignore")).name == "tor" for c in cmd[:1]) else None

    @staticmethod
    def _handles_sighup(pid: int) -> bool:
        """Has the process INSTALLED a SIGHUP handler yet? (/proc/PID/status SigCgt: the mask of caught signals.) Until then the default action of SIGHUP is to terminate it. This is the exact
        condition, not a guess from the log or from files that appear early (the onion hostname file exists before tor's signal handlers do: measured, a reload racing the start killed tor)."""
        try:
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("SigCgt:"):
                    return bool(int(line.split()[1], 16) & (1 << (signal.SIGHUP - 1)))
        except (OSError, ValueError, IndexError):
            pass
        return False

    def _usable_now(self, pid: int) -> bool:
        return self._handles_sighup(pid)

    def reload(self) -> bool:
        """Re-read authorized_clients and ClientOnionAuthDir (SIGHUP). True if a tor of ours was signalled. A tor that has not installed its SIGHUP handler yet is NOT signalled (M1c: it would die, and a
        reload also comes from threads and processes that cannot see the node's state); `start()` reads the files itself and `reconfigure()` repeats the reload once tor is ready."""
        pid = self._running_pid()
        if pid is None:
            return False
        if not self._usable_now(pid):
            self._reload_due = True                                 # (the node's next reconfigure() delivers it once tor handles SIGHUP)
            return False
        os.kill(pid, signal.SIGHUP)
        return True

    @property
    def socks(self) -> tuple:
        return ("127.0.0.1", self.socks_port)

    def hostname(self) -> str | None:
        p = self.hs / "hostname"
        try:
            h = p.read_text().strip()
        except OSError:
            return None
        return h if ONION_RE.fullmatch(h) else None

    # -- who may read our descriptor / which onions we may read
    def authorize(self, name: str, pub: str) -> Path:
        """Allow the holder of x25519 key `pub` to reach our onion service. Re-authorizing a name replaces its key."""
        if not self.local_port:
            raise ValueError("this node has no onion service")
        if not NAME_RE.fullmatch(name or ""):
            raise ValueError("name: 1-32 characters of a-z 0-9 _ -")
        p = self.hs / "authorized_clients" / f"{name}.auth"
        _write_private(p, f"descriptor:x25519:{check_pub(pub)}\n")
        self.reload()
        return p

    def revoke(self, name: str) -> bool:
        if not NAME_RE.fullmatch(name or ""):
            raise ValueError("bad name")
        p = self.hs / "authorized_clients" / f"{name}.auth"
        gone = p.exists()
        if gone:
            p.unlink()
            self.reload()
        return gone

    def authorized(self) -> list:
        d = self.hs / "authorized_clients"
        return sorted(p.stem for p in d.glob("*.auth")) if d.exists() else []

    def add_client_auth(self, onion: str, priv: str) -> Path:
        """Keep the private half of OUR key for a peer's onion service, so our tor can read its descriptor."""
        onion = check_onion(onion)
        if not B32_KEY_RE.fullmatch((priv or "").strip()):
            raise ValueError("a client private key is 52 characters of base32")
        p = self.auth_in / f"{onion[:-6]}.auth_private"
        _write_private(p, f"{onion[:-6]}:descriptor:x25519:{priv.strip()}\n")
        self.reload()
        return p

    # -- one onion service per peer (spec 7.2; Sansa round 8): per-peer address, per-peer local port => per-peer connection limits, and revoking a peer
    #    means deleting ITS service (a revoked client with a cached descriptor reaches nothing)
    def _load_services(self) -> dict:
        try:
            raw = json.loads(self.svc_file.read_text())
        except (OSError, ValueError):
            return {}
        out = {}
        for name, v in (raw.items() if isinstance(raw, dict) else []):
            try:
                port = v.get("port")
                agent = v.get("agent")
                kind = v.get("kind", "peer")
                if NAME_RE.fullmatch(name) and isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536 and len(out) < MAX_SERVICES \
                        and kind in KINDS and (agent is None or (kind == "peer" and isinstance(agent, str) and AGENT_ID_RE.fullmatch(agent))):
                    out[name] = {"port": port, "agent": agent, "kind": kind}
            except (AttributeError, TypeError):
                continue
        return out

    def _save_services(self) -> None:
        tmp = self.svc_file.with_name(f"{self.svc_file.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        _write_private(tmp, json.dumps(self.services, sort_keys=True))
        os.replace(tmp, self.svc_file)

    def _locked(self):
        """An exclusive lock for read-modify-write of services.json (two CLI calls at once lose nothing)."""
        class L:
            def __init__(s, path):
                s.fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)

            def __enter__(s):
                fcntl.flock(s.fd, fcntl.LOCK_EX)
                return s

            def __exit__(s, *a):
                os.close(s.fd)
        return L(self.svc_file.with_name(self.svc_file.name + ".lock"))

    def _fingerprint(self, services: dict) -> dict:
        """What tor must know per door: local port, bound agent, and WHICH client key is authorized (a replaced key must reach a running tor too)."""
        out = {}
        for name, svc in services.items():
            try:
                key = hashlib.sha256((self.svc_dir / name / "authorized_clients" / "client.auth").read_bytes()).hexdigest()
            except OSError:
                key = None
            out[name] = [svc["port"], svc["agent"], key, svc.get("kind", "peer")]
        return out

    def add_service(self, name: str, pub: str, agent: str | None = None, kind: str = "peer") -> int:
        """Authorize the holder of client key `pub` on a service of their own (new, or the existing one of that name: same onion identity, new key).
        `agent`, if given, is the only agent id whose requests this service will answer. Returns the local port the service forwards to."""
        if not NAME_RE.fullmatch(name or ""):
            raise ValueError("name: 1-32 characters of a-z 0-9 _ -")
        pub = check_pub(pub)
        if kind not in ("peer", "join"):
            raise ValueError("a client-authorized door is a peer door or a join door")
        if agent is not None and (kind != "peer" or not AGENT_ID_RE.fullmatch(agent)):
            raise ValueError("bad agent id")
        with self._locked():
            self.services = self._load_services()
            svc = self.services.get(name)
            if svc is not None and svc.get("kind", "peer") != kind:
                raise ValueError(f"{name!r} is a {svc.get('kind', 'peer')} door; it cannot become a {kind} door (remove it first)")
            if svc is None:
                if len(self.services) >= MAX_SERVICES:
                    raise ValueError("too many peers")
                used = {s["port"] for s in self.services.values()}
                port = next((p for p in range(self.service_base, self.service_base + MAX_SERVICES) if p not in used), None)
                if port is None or port > 65535:
                    raise ValueError("no free local port for another service")
                svc = {"port": port, "agent": agent, "kind": kind}
            svc["agent"] = agent if agent is not None else svc.get("agent")
            d = self.svc_dir / name
            (d / "authorized_clients").mkdir(parents=True, exist_ok=True)
            for x in (self.svc_dir, d, d / "authorized_clients"):
                x.chmod(0o700)
            _write_private(d / "authorized_clients" / "client.auth", f"descriptor:x25519:{pub}\n")
            self.services[name] = svc
            self._save_services()
            return svc["port"]

    def add_public_service(self, name: str, kind: str) -> int:
        """A PUBLIC door (spec 5.1): an onion service with NO client authorization, so anyone who knows the address can connect. `kind` decides
        which program answers it ("read": unsigned read-only sync of public threads; "inbox": the write-only guest inbox). Returns its local port."""
        if not NAME_RE.fullmatch(name or ""):
            raise ValueError("name: 1-32 characters of a-z 0-9 _ -")
        if kind not in PUBLIC_KINDS:
            raise ValueError("a public door is a read door or an inbox door")
        with self._locked():
            self.services = self._load_services()
            svc = self.services.get(name)
            if svc is not None:
                if svc.get("kind", "peer") != kind:
                    raise ValueError(f"{name!r} is a {svc.get('kind', 'peer')} door; it cannot become a {kind} door (remove it first)")
                return svc["port"]
            if len(self.services) >= MAX_SERVICES:
                raise ValueError("too many doors")
            used = {s["port"] for s in self.services.values()}
            port = next((p for p in range(self.service_base, self.service_base + MAX_SERVICES) if p not in used), None)
            if port is None or port > 65535:
                raise ValueError("no free local port for another service")
            d = self.svc_dir / name
            d.mkdir(parents=True, exist_ok=True)
            for x in (self.svc_dir, d):
                x.chmod(0o700)
            self.services[name] = {"port": port, "agent": None, "kind": kind}
            self._save_services()
            return port

    def remove_service(self, name: str) -> bool:
        """Delete a peer's service for good (its onion identity too)."""
        if not NAME_RE.fullmatch(name or ""):
            raise ValueError("bad name")
        with self._locked():
            self.services = self._load_services()
            gone = self.services.pop(name, None) is not None
            if gone:
                self._save_services()
            d = self.svc_dir / name
            if d.is_dir() and not d.is_symlink():
                shutil.rmtree(d)
        return gone

    def service_address(self, name: str) -> str | None:
        try:
            h = (self.svc_dir / name / "hostname").read_text().strip()
        except OSError:
            return None
        return h if ONION_RE.fullmatch(h) else None

    def reconfigure(self) -> bool:
        """Re-read services.json; if anything tor must know changed (a door added or removed, its port, its agent, or its CLIENT KEY replaced), rewrite the
        torrc and tell a running tor (SIGHUP re-reads the torrc and the authorized_clients files). True if changed."""
        new = self._load_services()
        fp = self._fingerprint(new)
        if fp == self._applied and self.torrc.exists():
            if self._reload_due and self.reload():                  # a change was written while tor was still starting: it is ready now
                self._reload_due = False
            return False
        self.services = new
        _write_private(self.torrc, self.config())
        self._applied = fp
        self._reload_due = True
        self._reload_due = not self.reload() and self.running()      # (a tor that is still starting reads the files itself at the start; a tor that is not running has nothing to tell)
        return True

    def transport(self, onion: str, port: int | None = None, timeout: float = 60.0, connect_timeout: float | None = None) -> TorTransport:
        return TorTransport(onion, port or self.virtual_port, self.socks, timeout, connect_timeout)

    # ---------------------------------------------------------------- the Carrier contract (carrier.py): protocol modules use ONLY these
    type = "onion"
    capabilities = frozenset({"hides_ip"})
    retry_wait = 45.0                                              # one rendezvous circuit takes this long to give up: waiting less would only stack attempts

    def healthy(self) -> bool:
        return self.running()

    def dial(self, endpoint: dict, *, timeout: float, connect_timeout: float | None = None, agent: str | None = None):
        try:                                                           # (`agent`: the client key is held per onion here; see rebind_credential for a peer that moves)
            onion, port = _onion.parts(endpoint)
        except ValueError as e:
            raise TorError(str(e), retry=False) from None
        return self.transport(onion, port, timeout, connect_timeout)

    def new_credential(self) -> tuple:
        priv, pub = make_client_key()
        return Secret({"type": "onion", "key": priv}), {"type": "onion", "key": pub}

    def use_credential(self, endpoint: dict, secret, agent: str | None = None) -> None:
        onion, _ = _onion.parts(endpoint)
        self.add_client_auth(onion, check_credential(secret, secret=True)["key"])

    def _held_key(self, onion: str) -> str | None:
        """OUR private client key for `onion`, as stored in client_auth (None if there is none)."""
        try:
            line = (self.auth_in / f"{onion[:-6]}.auth_private").read_text().strip()
        except OSError:
            return None
        key = line.rsplit(":", 1)[-1]
        return key if B32_KEY_RE.fullmatch(key) else None

    def has_credential(self, endpoint: dict, agent: str | None = None) -> bool:
        try:
            onion, _ = _onion.parts(endpoint)
        except ValueError:
            return False
        return self._held_key(onion) is not None

    def rebind_credential(self, agent: str, held_endpoints, new_endpoint: dict) -> bool:
        """A peer announced a NEW onion address: it authorizes the same public client key there, so the private key we already hold for its old onion is the one to use at the new
        one (DESIGN_locator_book.md). Copies it; True if the new onion now has a key."""
        new_onion, _ = _onion.parts(new_endpoint)
        if self._held_key(new_onion):
            return True
        for ep in held_endpoints:
            try:
                old, _ = _onion.parts(ep)
            except ValueError:
                continue
            key = self._held_key(old)
            if key:
                self.add_client_auth(new_onion, key)
                return True
        return False

    def drop_credential(self, endpoint: dict, agent: str | None = None) -> bool:
        onion, _ = _onion.parts(endpoint)
        p = self.auth_in / f"{onion[:-6]}.auth_private"
        try:
            p.unlink()
        except FileNotFoundError:                                      # (the CLI and the node may race: whoever loses just reports "not there")
            return False
        self.reload()
        return True

    def open_door(self, name: str, kind: str, *, credential: dict | None = None, agent: str | None = None) -> int:
        if kind not in KINDS:
            raise ValueError("unknown door kind")
        if kind in PUBLIC_KINDS:
            if credential is not None or agent is not None:
                raise ValueError("a public door takes no credential and no agent")
            return self.add_public_service(name, kind)
        if credential is None:
            raise ValueError("a client-authorized door needs the public credential of its client")
        return self.add_service(name, check_credential(credential)["key"], agent, kind)

    def close_door(self, name: str) -> bool:
        return self.remove_service(name)

    def door_endpoint(self, name: str) -> dict | None:
        onion = self.service_address(name)
        return None if onion is None else _onion.endpoint(onion, self.virtual_port)

    def doors(self) -> dict:
        return {n: {"kind": s.get("kind", "peer"), "agent": s.get("agent"), "port": s["port"]} for n, s in self._load_services().items()}

    def door_gone(self, name: str) -> bool:
        return name not in self._load_services() and not (self.svc_dir / name).exists()

    def shared_port(self) -> int | None:
        return self.local_port

    def shared_endpoint(self) -> dict | None:
        h = self.hostname()
        return None if h is None else _onion.endpoint(h, self.virtual_port)
