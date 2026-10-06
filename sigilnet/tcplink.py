"""The TCP carrier (DESIGN_tcp_carrier.md rev 1, frozen interface): sigilnet over plain TCP between hosts that can reach each other (same host, LAN, VPN). It is a
Carrier like torlink.TorNode, so the protocol layer does not know the difference; what Tor gave for free is done here: TLS 1.3 to a PINNED door key (confidentiality
and door authentication, no CA), then client admission by an Ed25519 signature inside the TLS channel (a peer/join door admits exactly one credential), then a
byte pipe to the loopback port on which the PROTOCOL layer runs its own guarded server (framing, size caps, deadlines, per-request signatures are not carrier business).

Wire per connection: TLS1.3 (no tickets, no client cert, no SNI/ALPN) | door -> client 39 bytes `SNTCP1` + mode + nonce | (mode 1) client -> door 96 bytes
`pub(32)+sig(64)` over a length-prefixed message of [domain, nonce, door fp, sha256(pub)] | door -> client one byte 0x01 | then the protocol's own frames.
A failed admission closes the socket without a byte (the TLS handshake itself still shows that a TLS service exists: this carrier does not hide anything).

Keys are separated on purpose: the door's TLS key is ECDSA P-256 generated per door; the client admission key is an Ed25519 seed; neither is a sigilnet identity key."""
from __future__ import annotations

import array
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import select
import socket
import ssl
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from . import carrier as C
from . import tcp as T
from .acceptguard import AcceptGuard
from .carrier import Carrier, CarrierError, Secret, check_credential
from .keys import AGENT_ID_RE, verify_strict

HELLO_MAGIC = b"SNTCP1"
HELLO_LEN = 39
AUTH_LEN = 96
AUTH_DOMAIN = b"sigilnet-tcp-auth-1"
AGENT_KEY = "agent:"                                             # held.json: credentials held BY NODE ID live under "agent:<id>" (addresses are transient, DESIGN_locator_book.md)
PEER_PER_MIN = 3600                                            # connections/min the protocol guard behind a PEER door admits (must stay ABOVE blobserve's request budgets) (the one-connection-per-request carrier needs more than Tor's 240)
PIPE_UP = T.MAX_REQ + 64
PIPE_DOWN = T.MAX_RESP + 64
NAME_RE = re.compile(r"[a-z0-9_-]{1,32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
_OCTET = r"(?:0|[1-9][0-9]{0,2})"
_IP_RE = re.compile(rf"{_OCTET}(?:\.{_OCTET}){{3}}")
_PORT_RE = re.compile(r"[1-9][0-9]{0,4}")
_V6_TEXT_RE = re.compile(r"[0-9a-f:]{2,45}")                      # an IPv6 literal as we accept it: hex digits and colons only (no %zone, no dotted tail: those spellings are refused outright)
_BRACKET_RE = re.compile(r"\[([0-9a-f:]+)\]:([1-9][0-9]{0,4})")
_FORMAT_MSG = "a tcp endpoint is '<ipv4>:<port>#<64 hex door fingerprint>' or '[<ipv6>]:<port>#<64 hex door fingerprint>'"
# IPv6 addresses a peer may announce (DESIGN_ipv6.md rev 1 a): an ALLOW list, because a deny list for v6 rots. Global unicast minus the special blocks inside it, plus ULA.
_V6_GLOBAL = ipaddress.ip_network("2000::/3")
_V6_ULA = ipaddress.ip_network("fc00::/7")
_V6_SPECIAL = tuple(ipaddress.ip_network(n) for n in ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"))     # IETF protocol blocks (Teredo among them), documentation, 6to4 (it embeds an IPv4), documentation


# ---------------------------------------------------------------- formats (registered with carrier.py)
def _canon_v6(text: str) -> str:
    """An IPv6 literal (no brackets) -> its canonical compressed lowercase text. ValueError for any other spelling: a zone id, a dotted IPv4 tail, an IPv4-mapped address (a v6 door is V6ONLY: it
    could never be reached that way, and the spelling would let an IPv4 rule be dodged), a malformed one."""
    text = (text or "").strip().lower()
    if not _V6_TEXT_RE.fullmatch(text):
        raise ValueError(_FORMAT_MSG)
    try:
        a = ipaddress.IPv6Address(text)
    except ValueError:
        raise ValueError(_FORMAT_MSG) from None
    if a.ipv4_mapped is not None:
        raise ValueError(_FORMAT_MSG + " (an IPv4-mapped address is refused)")
    return str(a)


def fmt_hostport(host: str, port) -> str:
    """`host:port`, with an IPv6 host in brackets (what a person reads in a log or an error)."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def fmt_addr(host: str, port, fp: str) -> str:
    return f"{fmt_hostport(host, port)}#{fp}"


def _split_addr(a: str) -> tuple:
    """`'<ipv4>:<port>#<fp>'` or `'[<ipv6>]:<port>#<fp>'` -> (host text, port, fp). The host is the CANONICAL text without brackets (an IPv6 address in compressed lowercase form): every comparison of
    an address goes through this (DESIGN_ipv6.md rev 1 c)."""
    a = (a or "").strip().lower()
    hostport, sep, fp = a.partition("#")
    if hostport.startswith("["):
        m = _BRACKET_RE.fullmatch(hostport)
        if not sep or m is None or not HEX64.fullmatch(fp):
            raise ValueError(_FORMAT_MSG)
        ip, port = _canon_v6(m.group(1)), m.group(2)
    else:
        ip, sep2, port = hostport.rpartition(":")
        if not sep or not sep2 or not HEX64.fullmatch(fp) or not _IP_RE.fullmatch(ip) or not _PORT_RE.fullmatch(port):
            raise ValueError(_FORMAT_MSG)
        if any(int(o) > 255 for o in ip.split(".")):
            raise ValueError(_FORMAT_MSG + " (octets 0-255, port 1-65535)")
    if int(port) > 65535:
        raise ValueError(_FORMAT_MSG + " (octets 0-255, port 1-65535)")
    return ip, int(port), fp


def _check_addr(a: str) -> str:
    ip, port, fp = _split_addr(a)
    return fmt_addr(ip, port, fp)


def _check_key(k: str) -> str:
    k = (k or "").strip().lower()
    if not HEX64.fullmatch(k):
        raise ValueError("a tcp credential key is 64 hex characters")
    return k


C.register_type("tcp", check_addr=_check_addr, check_key=_check_key)


def endpoint(ip: str, port: int, fp: str) -> dict:
    return {"type": "tcp", "addr": _check_addr(fmt_addr(ip, port, fp))}


def _is_private(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return (a.is_private or a.is_loopback) and not a.is_unspecified and not a.is_multicast


def _v6_allowed(a: ipaddress.IPv6Address) -> bool:
    """The ALLOW list for an IPv6 address (rev 1 a): global unicast 2000::/3 minus the special blocks inside it, plus ULA fc00::/7. Everything else (::/8 with unspecified, loopback, mapped and
    compatible forms; 64:ff9b::/96 and 64:ff9b:1::/48 NAT64; 100::/64; fe80::/10; fec0::/10; ff00::/8) is refused. The loopback ::1 is decided by the caller (only when we are bound on it)."""
    return (a in _V6_GLOBAL and not any(a in n for n in _V6_SPECIAL)) or a in _V6_ULA


def _check_ip(ip, what: str, allow_public: bool = True, *, allow_any_interface: bool = False) -> str:
    """An IPv4 address (dotted quad) or an IPv6 address (a literal without brackets, no zone id) we may bind to or advertise; returned in canonical form (compressed lowercase for IPv6).
    An IPv4 address: Any address is allowed (M3: the human, 2026-10-04: "any ip address should be allowed, loopbacks, local, or public"; `allow_public`
    is kept in the signature and the config and is ignored). Never multicast; never 0.0.0.0, which would listen on EVERY interface, unless `allow_any_interface` (the listen address, with an explicit
    advertise address: 0.0.0.0 is not an address a peer can dial)."""
    if isinstance(ip, str) and ":" in ip:                                 # IPv6: allow list; "::" is the analogue of 0.0.0.0 (an explicit advertise address is required)
        try:
            a = ipaddress.IPv6Address(_canon_v6(ip))
        except ValueError:
            raise ValueError(f"{what} must be a dotted-quad IPv4 address or an IPv6 address (no brackets, no zone id)") from None
        if a.is_unspecified:
            if not allow_any_interface:
                raise ValueError(f"{what}: refusing {a} (:: would listen on EVERY interface)")
        elif not a.is_loopback and not _v6_allowed(a):
            raise ValueError(f"{what}: refusing {a} (not a global or unique-local IPv6 address)")
        return str(a)
    if not isinstance(ip, str) or not _IP_RE.fullmatch(ip) or any(int(o) > 255 for o in ip.split(".")):
        raise ValueError(f"{what} must be a dotted-quad IPv4 address or an IPv6 address")
    a = ipaddress.ip_address(ip)
    if a.is_multicast:
        raise ValueError(f"{what}: refusing {ip} (a multicast address)")
    if a.is_unspecified and not allow_any_interface:
        raise ValueError(f"{what}: refusing {ip} (0.0.0.0 would listen on EVERY interface)")
    if ip.startswith("0.") and not a.is_unspecified or a.is_reserved:
        raise ValueError(f"{what}: refusing {ip} (not a host address)")
    return ip


def _interfaces() -> list:
    """The IPv4 addresses of this machine's interfaces (Linux SIOCGIFCONF, standard library only), in the kernel's order. [] if the ioctl is not available."""
    try:
        size = 40 * 64
        buf = array.array("B", b"\0" * size)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            n = struct.unpack("iL", fcntl.ioctl(s.fileno(), 0x8912, struct.pack("iL", size, buf.buffer_info()[0])))[0]
        raw = buf.tobytes()
        return [socket.inet_ntoa(raw[i + 20:i + 24]) for i in range(0, n, 40)]
    except (OSError, ValueError, struct.error, OverflowError):
        return []


IF_INET6 = "/proc/net/if_inet6"
_IFA_BAD = 0x08 | 0x40                                           # DAD failed, tentative: not usable yet


def _interfaces6(path: str = IF_INET6) -> list:
    """The IPv6 addresses of this machine's interfaces (Linux /proc/net/if_inet6, standard library only), canonical text, usable ones only. [] if the file is not there (no IPv6)."""
    out = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5 or not re.fullmatch(r"[0-9a-f]{32}", parts[0]):
                    continue
                try:
                    flags = int(parts[4], 16)
                except ValueError:
                    continue
                if flags & _IFA_BAD:
                    continue
                a = ipaddress.IPv6Address(int(parts[0], 16))
                if str(a) not in out:
                    out.append(str(a))
    except (OSError, ValueError):
        return []
    return out


def _route_ip(dest: str) -> str | None:
    """The local address the kernel would use to reach `dest` (a UDP connect sends nothing)."""
    try:
        with socket.socket(socket.AF_INET6 if ":" in dest else socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((dest, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def resolve_bind(bind: str, allow_public: bool = False, hints=(), *, interfaces=None, route=None, interfaces6=None) -> str:
    """`bind` as configured: an address (returned as is), "auto6" = this machine's GLOBAL IPv6 address now (global unicast only: never a ULA or link-local by accident; none = a clear error), or
    "auto" = THIS machine's IPv4 address NOW (DESIGN_locator_book.md F1: a container that gets a new IP must still start).
    auto picks, among the machine's non-loopback, non-link-local addresses (private or public: M3), the one the route to a peer's address (`hints`) uses, else the first. The result still goes
    through the usual checks (TcpCarrier refuses what _check_ip refuses); `allow_public` is ignored."""
    if bind == "auto6":
        interfaces6, route = interfaces6 or _interfaces6, route or _route_ip
        cands = []
        for ip in interfaces6():
            try:
                a = ipaddress.IPv6Address(ip)
            except ValueError:
                continue
            if a in _V6_GLOBAL and _v6_allowed(a) and ip not in cands:
                cands.append(ip)
        if not cands:
            raise ValueError("bind \"auto6\": this machine has no global IPv6 address (give --bind ADDR)")
        for h in hints:
            if ":" in h:
                ip = route(h)
                if ip in cands:
                    return ip
        return cands[0]
    if bind != "auto":
        return bind
    interfaces, route = interfaces or _interfaces, route or _route_ip         # (looked up now, so a test or a caller can replace them)
    cands = []
    for ip in interfaces():
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast or a.is_reserved:
            continue                                                  # (M3: public addresses are candidates too; `allow_public` is ignored)
        if ip not in cands:
            cands.append(ip)
    if not cands:
        raise ValueError("bind \"auto\": this machine has no non-loopback IPv4 address (give --bind IP)")
    for h in hints:
        if ":" in h:
            continue                                                  # (an IPv6 peer address says nothing about the IPv4 route)
        ip = route(h)
        if ip in cands:
            return ip
    return cands[0]


def auth_message(nonce: bytes, door_fp: bytes, client_fp: bytes) -> bytes:
    """Length-prefixed (2 bytes, big endian) fields: no ambiguity between nonce, door and client."""
    return b"".join(len(p).to_bytes(2, "big") + p for p in (AUTH_DOMAIN, nonce, door_fp, client_fp))


def spki_fp(cert_der: bytes) -> str:
    cert = x509.load_der_x509_certificate(cert_der)
    return hashlib.sha256(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.parent / f".tmp.{os.getpid()}.{os.urandom(4).hex()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _new_door_pem() -> tuple:
    """-> (pem bytes: private key + self-signed certificate, spki fingerprint hex). The pin is the SPKI hash, so the certificate itself may be re-issued for the same key."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigilnet-tcp")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=36500)).sign(key, hashes.SHA256()))
    pem = (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
           + cert.public_bytes(serialization.Encoding.PEM))
    return pem, spki_fp(cert.public_bytes(serialization.Encoding.DER))


def _read_exact(s, n: int, deadline: float):
    buf = b""
    while len(buf) < n:
        left = deadline - time.time()
        if left <= 0:
            return None
        s.settimeout(left)
        try:
            chunk = s.recv(n - len(buf))
        except (socket.timeout, OSError):                          # ssl.SSLError is an OSError
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _kill(sock) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class TcpCarrier(Carrier):
    type = "tcp"
    capabilities = frozenset()
    retry_wait = 10.0                                               # a LAN peer that is down is tried again after this long (the first 3 retries, DESIGN_locator_book.md)

    def __init__(self, state_dir, *, bind: str, port_base: int, advertise: str | None = None, allow_public: bool = False,
                 max_streams_per_door: int = 8, max_unauth: int = 32, auth_deadline: float = 5.0, pipe_idle: float = 120.0, pipe_total: float = 600.0, resolver=None, max_unauth_per_door: int = 8):
        if not isinstance(allow_public, bool):
            raise ValueError("allow_public must be true or false")
        self.allow_public = allow_public
        self.bind = _check_ip(bind, "bind", allow_public, allow_any_interface=advertise is not None)
        self.advertise = _check_ip(advertise if advertise is not None else bind, "advertise", allow_public)
        self._advertise_given = advertise is not None
        self._resolver = resolver                                   # callable() -> the bind address NOW (`bind: auto`), or None: the address given is final. Asked again before a RESTART (M1c).
        if isinstance(port_base, bool) or not isinstance(port_base, int) or not 1024 <= port_base <= 64000:
            raise ValueError("port_base must be an integer between 1024 and 64000")
        self.port_base = port_base
        for name, v in (("max_streams_per_door", max_streams_per_door), ("max_unauth", max_unauth)):
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.max_streams, self.max_unauth = max_streams_per_door, max_unauth
        self.auth_deadline, self.pipe_idle, self.pipe_total = float(auth_deadline), float(pipe_idle), float(pipe_total)
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.doors_file, self.held_file, self.lock_file = self.dir / "doors.json", self.dir / "held.json", self.dir / "state.lock"
        self.started = False
        self._mu = threading.Lock()                                # counters and the listener table
        self._listeners: dict = {}                                 # door name -> {"sock","thread","index"}
        self.guard = AcceptGuard(per_door=max_unauth_per_door, global_cap=max_unauth, store=self.dir / "proven.json", writer=_write_private)     # the accept-time limits (M3b, acceptguard.py)
        self._streams: dict = {}                                   # door name -> admitted streams now
        self._conns: dict = {}                                     # live tls socket -> (door name, door index); closed by stop() and when the door is removed
        self._threads: set = set()
        self._stop = threading.Event()
        self._errors: dict = {}                                    # door name -> message, filled by reconfigure() (see last_errors)

    # ------------------------------------------------------------ state (shared with other processes: the CLI edits doors while a node runs)
    class _Lock:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX)

        def __exit__(self, *a):
            os.close(self.fd)

    def _locked(self):
        return self._Lock(self.lock_file)

    def _load(self) -> dict:
        try:
            raw = json.loads(self.doors_file.read_text())
        except FileNotFoundError:
            return {"version": 1, "next_index": 0, "doors": {}}
        except (OSError, ValueError):
            raise CarrierError("tcp state (doors.json) is damaged", retry=False) from None
        try:
            ok = isinstance(raw, dict) and raw.get("version") == 1 and isinstance(raw["next_index"], int) and isinstance(raw["doors"], dict)
            for n, d in (raw["doors"].items() if ok else []):
                ok = ok and NAME_RE.fullmatch(n) and d["kind"] in C.KINDS and isinstance(d["index"], int) and d["index"] >= 0 \
                    and isinstance(d["listen_port"], int) and isinstance(d["loopback_port"], int) and HEX64.fullmatch(d["fp"]) \
                    and (d["auth"] is None or HEX64.fullmatch(d["auth"])) and (d["agent"] is None or AGENT_ID_RE.fullmatch(d["agent"]))
        except (KeyError, TypeError):
            ok = False
        if not ok:
            raise CarrierError("tcp state (doors.json) is damaged", retry=False)
        return raw

    def _save(self, st: dict) -> None:
        _write_private(self.doors_file, json.dumps(st, sort_keys=True).encode())

    def _held(self) -> dict:
        try:
            raw = json.loads(self.held_file.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            raise CarrierError("tcp state (held.json) is damaged", retry=False) from None
        if not isinstance(raw, dict):
            raise CarrierError("tcp state (held.json) is damaged", retry=False)
        return raw

    def _pem(self, name: str) -> Path:
        return self.dir / f"door-{name}.pem"

    # ------------------------------------------------------------ lifecycle
    def start(self, wait: bool = True) -> None:
        if self.started:
            return
        self._stop.clear()
        try:
            self.started = True
            self.reconfigure(_force=True)
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        self._stop.set()
        with self._mu:
            listeners, self._listeners = list(self._listeners.values()), {}
            conns = list(self._conns)
            self.started = False
        for ls in listeners:
            try:
                ls["sock"].close()
            except OSError:
                pass
        for c in conns:
            _kill(c)
        for ls in listeners:
            ls["thread"].join(3)
        for t in list(self._threads):
            t.join(5)

    @property
    def _unauth(self) -> int:
        return self.guard._total

    def guard_stats(self) -> dict:
        """Counts only (no addresses): what the accept-time guard let in, refused and struck."""
        return self.guard.stats()

    def healthy(self) -> bool:
        with self._mu:
            return self.started and all(ls["thread"].is_alive() for ls in self._listeners.values())

    def refresh_bind(self) -> None:
        """Before a restart: a container that got a new IP must come back on it, not on the address resolved when the node started. ValueError if the new address is refused."""
        if self._resolver is None:
            return
        ip = _check_ip(self._resolver(), "bind", self.allow_public)
        self.bind = ip
        if not self._advertise_given:
            self.advertise = ip

    def down_reason(self) -> str:
        with self._mu:
            dead = [n for n, ls in self._listeners.items() if not ls["thread"].is_alive()]
        return ("listener of " + ", ".join(sorted(dead)) + " died") if dead else "stopped"

    def reconfigure(self, _force: bool = False) -> bool:
        """Apply the doors in doors.json to the running listeners. From start() (_force) any failure is fatal (fail loud at boot). From the node's tick it is not: ONE door that
        cannot be opened (its port is taken, its key file is damaged) must not take the other doors down or end the node; the problem is remembered in last_errors() and
        retried at the next call. A damaged doors.json is handled the same way (the existing listeners keep serving)."""
        if not self.started:
            return False
        try:
            st = self._load()
        except CarrierError as e:
            if _force:
                raise
            self._errors["(state)"] = str(e)
            return False
        self._errors.pop("(state)", None)
        changed = False
        with self._mu:
            have = dict(self._listeners)
        for name, ls in have.items():                              # a door removed, or re-created under the same name with another index: its listener goes
            d = st["doors"].get(name)
            if d is None or d["index"] != ls["index"]:
                with self._mu:
                    self._listeners.pop(name, None)
                    live = [c for c, key in self._conns.items() if key == (name, ls["index"])]
                try:
                    ls["sock"].close()
                except OSError:
                    pass
                for c in live:                                     # revocation is immediate: the live streams of a removed door end with its listener
                    _kill(c)
                ls["thread"].join(3)
                changed = True
        for name, d in st["doors"].items():
            with self._mu:
                known = name in self._listeners
            if known:
                self._errors.pop(name, None)
                continue
            try:
                self._listen(name, d)
            except CarrierError as e:
                if _force:
                    raise
                self._errors[name] = str(e)
                continue
            self._errors.pop(name, None)
            changed = True
        for gone in [n for n in self._errors if n != "(state)" and n not in st["doors"]]:
            del self._errors[gone]
        return changed

    def last_errors(self) -> dict:
        """door name (or "(state)") -> why it is not being served right now; empty when everything is up."""
        return dict(self._errors)

    def _listen(self, name: str, d: dict) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.options |= ssl.OP_NO_TICKET
        try:
            ctx.load_cert_chain(self._pem(name))
        except (OSError, ssl.SSLError):
            raise CarrierError(f"door {name!r}: its key file is missing or damaged", retry=False) from None
        v6 = ":" in self.bind
        try:
            sock = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM)
        except OSError as e:
            raise CarrierError(f"cannot listen on {fmt_hostport(self.bind, d['listen_port'])} ({e.strerror or e})", retry=False) from None
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            if v6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)        # a v6 door serves exactly IPv6: never an IPv4-mapped connection (those spellings are refused everywhere else)
            sock.bind((self.bind, d["listen_port"]))
            sock.listen(64)
        except OSError as e:
            sock.close()
            raise CarrierError(f"cannot listen on {fmt_hostport(self.bind, d['listen_port'])} ({e.strerror or e})", retry=False) from None
        sock.settimeout(0.5)
        th = threading.Thread(target=self._accept_loop, args=(name, d["index"], sock, ctx), daemon=True, name=f"tcp-door-{name}")
        with self._mu:
            self._listeners[name] = {"sock": sock, "thread": th, "index": d["index"]}
        th.start()

    # ------------------------------------------------------------ being reached
    def _accept_loop(self, name: str, index: int, sock, ctx) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return                                             # closed by stop()/reconfigure
            ip = addr[0] if isinstance(addr, tuple) and addr else ""
            if self._stop.is_set() or self.guard.admit(ip, name) is not None:
                conn.close()                                       # refused at once, before any handshake (the reason is only counted)
                continue
            th = threading.Thread(target=self._serve, args=(name, index, conn, ctx, ip), daemon=True, name=f"tcp-conn-{name}")
            with self._mu:
                self._threads.add(th)
            try:
                th.start()
            except RuntimeError:                                   # (a thread limit: this connection is refused, its slot is given back, the accept loop lives on)
                with self._mu:
                    self._threads.discard(th)
                self.guard.release(ip, name)
                conn.close()

    def _serve(self, name: str, index: int, conn, ctx, ip: str = "") -> None:
        tls = None
        unauth = True
        timer = None
        deadline = time.time() + self.auth_deadline
        stage, early_close = "handshake", False                  # early_close: no strike (closed before its first byte; or the door went away under it)
        try:
            conn.settimeout(self.auth_deadline)
            try:
                first = conn.recv(1, socket.MSG_PEEK)              # the first byte, left in the socket: ZERO bytes ever (closed or reset first) is a port scan or a health check, free; ANY byte is a commitment (the server side of TLS costs a signature)
            except socket.timeout:
                return                                              # silence until the deadline: a strike (the finally)
            except OSError:
                first = b""
            if first == b"":
                early_close = True
                return
            tls = ctx.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
            with self._mu:
                self._conns[tls] = (name, index)
            timer = threading.Timer(max(0.1, deadline - time.time()), _kill, args=(tls,))      # ONE total deadline from the accept for peek + handshake + admission (a trickle cannot drag it out)
            timer.daemon = True
            timer.start()
            tls.settimeout(max(0.1, deadline - time.time()))
            tls.do_handshake()                                      # (any failure from here on, EOF included, is a strike: the first byte was sent)
            stage = "hello"
            try:
                st = self._load()
            except CarrierError:
                early_close = True
                return
            d = st["doors"].get(name)
            if d is None or d["index"] != index:
                early_close = True
                return                                             # closed while connecting: nothing is answered
            nonce = os.urandom(32)
            mode = 1 if d["auth"] is not None else 0
            tls.settimeout(max(0.1, deadline - time.time()))
            tls.sendall(HELLO_MAGIC + bytes([mode]) + nonce)
            if mode == 1:
                stage = "admission"
                raw = _read_exact(tls, AUTH_LEN, deadline)
                if raw is None:
                    return                                         # (no frame in time, or closed: a strike in the finally below)
                try:
                    d = self._load()["doors"].get(name)           # re-read AT the moment that matters: a credential revoked during the admission window is refused
                except CarrierError:
                    early_close = True
                    return
                if d is None or d["index"] != index or d["auth"] is None:
                    early_close = True                             # (the door went away or was re-keyed: not the address's fault)
                    return
                pub, sig = raw[:32], raw[32:]
                client_fp = hashlib.sha256(pub).digest()
                same = hmac.compare_digest(client_fp, bytes.fromhex(d["auth"]))
                if not same:
                    return                                         # the key hash first: a stranger pays the handshake and nothing more (no signature verification); a strike below
                if not verify_strict(pub.hex(), sig.hex(), auth_message(nonce, bytes.fromhex(d["fp"]), client_fp)):
                    return                                         # no byte at all
                self.guard.proven(ip)                              # key in the table AND signature valid: this address is proven (strikes and ban cleared)
                stage = "admitted"
            else:
                stage = "admitted"                                 # (a public door has no admission: nothing proves anything, nothing is struck)
            self.guard.release(ip, name)                           # the connection becomes a stream (or ends here): the cap is checked BEFORE the admission byte
            unauth = False
            with self._mu:
                if self._streams.get(name, 0) >= self.max_streams:
                    return
                self._streams[name] = self._streams.get(name, 0) + 1
            try:
                if mode == 1:
                    tls.settimeout(max(0.1, deadline - time.time()))
                    tls.sendall(b"\x01")
                timer.cancel()
                self._pipe(tls, d["loopback_port"])
            finally:
                with self._mu:
                    self._streams[name] -= 1
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            if timer is not None:
                timer.cancel()
            if unauth:
                if stage != "admitted" and not early_close and not (stage == "hello" and self._stop.is_set()):
                    self.guard.strike(ip)                          # admission was not completed: a strike (not for a connection that closed before its first handshake bytes)
                self.guard.release(ip, name)
            with self._mu:
                self._conns.pop(tls, None)
                self._threads.discard(threading.current_thread())
            for s in (tls, conn):
                try:
                    if s is not None:
                        s.close()
                except OSError:
                    pass

    def _pipe(self, tls, port: int) -> None:
        try:
            backend = socket.create_connection(("127.0.0.1", port), timeout=2.0)
        except OSError:
            return
        start = last = time.time()
        up = down = 0
        client_eof = False
        try:
            tls.settimeout(self.pipe_idle)
            backend.settimeout(self.pipe_idle)
            while not self._stop.is_set():
                now = time.time()
                if now - start > self.pipe_total or now - last > self.pipe_idle:
                    return
                ready = []
                if not client_eof and tls.pending():
                    ready = [tls]
                else:
                    ready, _, _ = select.select([backend] + ([] if client_eof else [tls]), [], [], 1.0)
                for s in ready:
                    try:
                        data = s.recv(65536)
                    except (ssl.SSLZeroReturnError, ssl.SSLEOFError):     # a clean or ragged end of the TLS stream is an EOF
                        data = b""
                    if s is tls:
                        if not data:
                            client_eof = True
                            try:
                                backend.shutdown(socket.SHUT_WR)       # half-close forwarded: the backend may still answer
                            except OSError:
                                pass
                            continue
                        room = PIPE_UP - up
                        up += len(data)
                        if up > PIPE_UP:
                            backend.sendall(data[:room])           # exactly PIPE_UP bytes may pass; the byte after it ends the connection
                            return
                        backend.sendall(data)
                    else:
                        if not data:
                            return                                 # the backend is done: the exchange is complete
                        room = PIPE_DOWN - down
                        down += len(data)
                        if down > PIPE_DOWN:
                            tls.sendall(data[:room])
                            return
                        tls.sendall(data)
                    last = time.time()
        except (OSError, ssl.SSLError):
            return
        finally:
            try:
                backend.close()
            except OSError:
                pass

    # ------------------------------------------------------------ reaching others
    def new_credential(self) -> tuple:
        seed = os.urandom(32)
        pub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return Secret({"type": "tcp", "key": seed.hex()}), {"type": "tcp", "key": hashlib.sha256(pub).hexdigest()}

    def use_credential(self, endpoint: dict, secret, agent: str | None = None) -> None:
        ep = C.check_endpoint(endpoint)
        if ep["type"] != "tcp":
            raise ValueError("not a tcp endpoint")
        cred = check_credential(secret, secret=True)
        if cred["type"] != "tcp":
            raise ValueError("not a tcp credential")
        if agent is not None and not (isinstance(agent, str) and AGENT_ID_RE.fullmatch(agent)):
            raise ValueError("bad agent id")
        with self._locked():
            held = self._held()
            held[ep["addr"]] = {"type": "tcp", "key": cred["key"]}          # (also by address: what older code and older tools look up)
            if agent is not None:
                held[AGENT_KEY + agent] = {"type": "tcp", "key": cred["key"]}   # BY NODE ID: it stays valid when the peer's address changes
            _write_private(self.held_file, json.dumps(held, sort_keys=True).encode())

    def drop_credential(self, endpoint: dict, agent: str | None = None) -> bool:
        ep = C.check_endpoint(endpoint)
        with self._locked():
            held = self._held()
            gone = held.pop(ep["addr"], None) is not None
            if agent is not None and held.pop(AGENT_KEY + agent, None) is not None:
                gone = True
            if not gone:
                return False
            _write_private(self.held_file, json.dumps(held, sort_keys=True).encode())
            return True

    def has_credential(self, endpoint: dict, agent: str | None = None) -> bool:
        try:
            held = self._held()
            return (agent is not None and (AGENT_KEY + agent) in held) or C.check_endpoint(endpoint)["addr"] in held
        except (CarrierError, ValueError):
            return False

    def index_credentials(self, pairs) -> int:
        """Migration (idempotent): for each (agent id, tcp address) we hold a credential under the ADDRESS but not under the node id, hold it under the node id too.
        An entry that matches no peer stays as it is, and nothing is ever deleted. Returns how many were added."""
        added = 0
        with self._locked():
            held = self._held()
            for agent, addr in pairs:
                if not (isinstance(agent, str) and AGENT_ID_RE.fullmatch(agent)) or (AGENT_KEY + agent) in held:
                    continue
                try:
                    addr = _check_addr(addr)
                except ValueError:
                    continue
                if addr in held:
                    held[AGENT_KEY + agent] = dict(held[addr])
                    added += 1
            if added:
                _write_private(self.held_file, json.dumps(held, sort_keys=True).encode())
        return added

    def locator_problem(self, addr: str) -> str | None:
        """Why we would not dial this address a PEER announced (DESIGN_locator_book.md Q4, M3; DESIGN_ipv6.md rev 1 a). IPv4: any private or public address is allowed; refused are loopback unless we
        are on loopback ourselves, link-local (169.254/16, the cloud metadata address among it), multicast, unspecified, "this network" (0/8), reserved (240/4 and the broadcast address), one of OUR
        OWN doors, and a port below 1024. IPv6 (an ALLOW list): global unicast 2000::/3 minus Teredo and the other protocol blocks 2001::/23, documentation 2001:db8::/32 and 3fff::/20, and 6to4
        2002::/16, plus ULA fc00::/7; everything else is refused (unspecified, mapped, NAT64, link-local, site-local, multicast ...); ::1 only when we are bound on ::1. Literal addresses only
        (`_split_addr`): no hostnames, no octal/hex/short forms, no zone ids."""
        try:
            ip, port, fp = _split_addr(addr)
        except ValueError as e:
            return str(e)
        a = ipaddress.ip_address(ip)
        try:
            bound = ipaddress.ip_address(self.bind)
        except ValueError:
            bound = None
        if a.version == 6:
            if a.is_loopback:
                if bound is None or bound.version != 6 or not bound.is_loopback:
                    return "a loopback address (this node is not on loopback)"
            elif a.is_unspecified or a.is_multicast:
                return "an unspecified or multicast address"
            elif a.is_link_local:
                return "a link-local address"
            elif not _v6_allowed(a):
                return "an IPv6 address outside the allowed ranges (global unicast, unique local)"
        else:
            if a.is_unspecified or a.is_multicast:
                return "an unspecified or multicast address"
            if a.is_link_local:
                return "a link-local address"
            if a.is_reserved or ip.startswith("0."):                # 240.0.0.0/4 (the broadcast address among it) and "this network" are not hosts, whatever `is_private` says
                return "a reserved address"
            if a.is_loopback and (bound is None or bound.version != 4 or not bound.is_loopback):
                return "a loopback address (this node is not on loopback)"
        if port < 1024:
            return "a port below 1024"
        try:
            ours = {d["listen_port"] for d in self._load()["doors"].values()}
        except CarrierError:
            ours = set()
        if ip == self.advertise and port in ours:
            return "that is one of our own doors"
        return None

    def dial(self, endpoint: dict, *, timeout: float, connect_timeout: float | None = None, agent: str | None = None):
        try:
            ep = C.check_endpoint(endpoint)
            ip, port, fp = _split_addr(ep["addr"])
        except ValueError as e:
            raise CarrierError(str(e), retry=False) from None
        if ep["type"] != "tcp":
            raise CarrierError("this carrier only dials tcp endpoints", retry=False)
        return _Transport(self, ip, port, fp, ep["addr"], timeout, connect_timeout, agent)

    # ------------------------------------------------------------ doors
    def server_limits(self, kind: str) -> dict:
        """Only PEER doors get the raised limit (a measured need: a blob fetch makes one connection per chunk; their visitor was authenticated before the guard sees a byte).
        read/inbox keep tcp.py's defaults (strangers reach them) and so does JOIN: it is opened by the capsule's bearer key (whoever holds the block can reach it), the join
        flow needs ~30 requests/min, and a higher limit would only widen what a leaked capsule can do (Sansa's recommendation, 2026-10-02)."""
        return {"plain_per_min": PEER_PER_MIN} if kind == "peer" else {}

    def open_door(self, name: str, kind: str, *, credential: dict | None = None, agent: str | None = None) -> int:
        if not NAME_RE.fullmatch(name or ""):
            raise ValueError("name: 1-32 characters of a-z 0-9 _ -")
        if kind not in C.KINDS:
            raise ValueError("unknown door kind")
        if kind in C.PUBLIC_KINDS:
            if credential is not None or agent is not None:
                raise ValueError("a public door takes no credential and no agent")
            auth = None
        else:
            if credential is None:
                raise ValueError("a client-authorized door needs the public credential of its client")
            cred = check_credential(credential)
            if cred["type"] != "tcp":
                raise ValueError("not a tcp credential")
            auth = cred["key"]
            if agent is not None and (kind != "peer" or not AGENT_ID_RE.fullmatch(agent)):
                raise ValueError("bad agent id")
        with self._locked():
            st = self._load()
            d = st["doors"].get(name)
            if d is not None and d["kind"] != kind:
                raise ValueError(f"{name!r} is a {d['kind']} door; it cannot become a {kind} door (remove it first)")
            if d is None:
                i = st["next_index"]
                if self.port_base + 2 * i + 1 > 65535:
                    raise ValueError("too many doors for this port_base")
                pem, fp = _new_door_pem()
                _write_private(self._pem(name), pem)
                d = st["doors"][name] = {"kind": kind, "agent": None, "index": i, "listen_port": self.port_base + 2 * i,
                                         "loopback_port": self.port_base + 2 * i + 1, "auth": None, "fp": fp}
                st["next_index"] = i + 1
            d["auth"] = auth
            if agent is not None:
                d["agent"] = agent
            self._save(st)
            return d["loopback_port"]

    def close_door(self, name: str) -> bool:
        with self._locked():
            st = self._load()
            existed = st["doors"].pop(name, None) is not None
            if existed:
                self._save(st)
            try:
                self._pem(name).unlink()
            except FileNotFoundError:
                pass
            return existed

    def door_endpoint(self, name: str) -> dict | None:
        d = self._load()["doors"].get(name)
        return None if d is None else endpoint(self.advertise, d["listen_port"], d["fp"])

    def doors(self) -> dict:
        return {n: {"kind": d["kind"], "agent": d["agent"], "port": d["loopback_port"]} for n, d in self._load()["doors"].items()}

    def door_gone(self, name: str) -> bool:
        return name not in self._load()["doors"] and not self._pem(name).exists()


class _Transport(T.TcpTransport):
    """`request(dict) -> dict` to a tcp door: connect, TLS1.3 with the door's pinned key, admission, then the protocol's plain frames."""

    def __init__(self, carrier: TcpCarrier, ip: str, port: int, fp: str, addr: str, timeout: float, connect_timeout, agent: str | None = None):
        super().__init__(ip, port, None, timeout, connect_timeout)
        self.carrier, self.fp, self.addr, self.agent = carrier, fp, addr, agent

    def _connect(self, end: float):
        try:
            s = socket.create_connection((self.host, self.port), timeout=max(0.1, end - time.time()))
        except OSError as e:
            raise CarrierError(f"tcp connect to {fmt_hostport(self.host, self.port)} failed ({e.strerror or type(e).__name__})", retry=True) from None      # (a v6 address from a host without a v6 route fails at once and locally, ENETUNREACH/EAFNOSUPPORT: retryable, the node's ordinary backoff bounds it and an interface that comes up later is used)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE                            # no CA: the pin below is the authentication
        tls = None
        timer = None
        try:
            tls = ctx.wrap_socket(s, server_hostname=None, do_handshake_on_connect=False)
            timer = threading.Timer(max(0.1, end - time.time()), _kill, args=(tls,))
            timer.daemon = True
            timer.start()
            tls.settimeout(max(0.1, end - time.time()))
            tls.do_handshake()
            der = tls.getpeercert(binary_form=True)
            if not der or not hmac.compare_digest(spki_fp(der), self.fp):
                raise CarrierError("door key does not match the endpoint", retry=False)
            hello = _read_exact(tls, HELLO_LEN, end)
            if hello is None or hello[:6] != HELLO_MAGIC or hello[6] not in (0, 1):
                raise CarrierError("the door did not speak the tcp carrier protocol", retry=True)
            if hello[6] == 1:
                table = self.carrier._held()
                held = table.get(self.addr) or (table.get(AGENT_KEY + self.agent) if self.agent else None)      # THIS door's own entry first (a peer may have two doors, each with its own key); by node id only when this address has none: the peer's address may have changed since we stored it
                if held is None:
                    raise CarrierError("the door needs a credential and none is held", retry=False)
                seed = bytes.fromhex(check_credential(held, secret=True)["key"])
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                msg = auth_message(hello[7:], bytes.fromhex(self.fp), hashlib.sha256(pub).digest())
                tls.settimeout(max(0.1, end - time.time()))
                tls.sendall(pub + priv.sign(msg))
                ack = _read_exact(tls, 1, end)
                if ack != b"\x01":
                    raise CarrierError("not admitted (or the door went away)", retry=True)
            timer.cancel()
            return tls
        except CarrierError:
            self._drop(tls, s, timer)
            raise
        except ValueError:
            self._drop(tls, s, timer)
            raise CarrierError("the credential held for this door is damaged", retry=False) from None
        except (OSError, ssl.SSLError) as e:
            self._drop(tls, s, timer)
            raise CarrierError(f"tcp door {self.host}:{self.port}: {type(e).__name__}", retry=True) from None

    @staticmethod
    def _drop(tls, s, timer) -> None:
        if timer is not None:
            timer.cancel()
        for x in (tls, s):
            try:
                if x is not None:
                    x.close()
            except OSError:
                pass
