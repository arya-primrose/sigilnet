"""The accept-time guard of the TCP carrier (DESIGN_multicarrier.md M3, 3.4; numbers from Sansa's reviews). Pure logic with an injectable clock: no sockets in here.

What it limits is what FAILS admission, never what succeeds: a legitimate peer makes one connection per request and hundreds per blob fetch, so a cap on all connections per address would hurt real
peers. A connection is "unauthenticated" from accept until its admission frame (the 96-byte signed frame inside TLS) has been checked; the guard counts those, by door, by source address and in all.

    caps         per door `per_door` (8), in all `global_cap` (32); half of each is reserved for PROVEN addresses (an address that completed an admission in the last `proven_window`, 1 h): a stranger
                 may use `per_door - reserve_door` and `global_cap - reserve_global` of them, a proven address all of them.
    per address  at most `per_ip_stranger` (4) concurrent unauthenticated connections from a stranger address, `per_ip_proven` (16) from a proven one (a node that dials with 4 workers, a ping and a blob
                 worker at once, over a WAN where a handshake plus admission takes two round trips, needs more than 4).
    strikes      a connection that does not complete admission (handshake garbage, wrong key, deadline) is a STRIKE for its address; `strikes` (10) inside `strike_window` (60 s) ban the address for
                 `ban_base` (60 s), doubling at every repeat up to `ban_max` (1 h). A connection closed before it sent the first byte of the handshake is NOT a strike (a port scan is free for the scanner
                 anyway). A proven address is exempt from the ban table (a flooder behind the same NAT must not ban a peer); a successful admission clears the strikes and the ban.
    proven table separate from the strike/ban tables (a stranger churning the strike table must never evict a proven address), persisted (0600) so a restart does not make every peer a stranger,
                 written at most once per address per half window, strangers never persisted. Every table is bounded (`max_ips`, oldest dropped).

"Address" everywhere in this file means `guard_key(address)`: the IPv4 address, or the /64 of an IPv6 one (DESIGN_ipv6.md rev 1 b).

Counters (no addresses: a stranger controls how many lines a log gets) are in `stats()`."""
from __future__ import annotations

import ipaddress
import json
import threading
import time
from collections import OrderedDict, deque


def guard_key(addr) -> str:
    """THE key every table of the guard uses for a source address (per-address quotas, strikes, bans, the proven table): ONE function, no second keying path. IPv4: the address itself. IPv6: the /64
    prefix as text (`2001:db8:1:2::/64`), because whoever holds a /64 holds 2**64 source addresses (and v6 hosts rotate temporary addresses daily: an exact-address proven entry would go stale at
    once). A `%scope` (link-local sockets report one) is stripped; spellings are canonicalised; an IPv4-mapped form (it cannot arrive on a V6ONLY door) keys as the IPv4 address. Anything that is not an
    address (the empty string of a socket without a peer) stays as it is; a key of this function is its own fixed point (the proven table on disk holds keys)."""
    s = str(addr).partition("%")[0].strip().lower()
    if "/" in s:
        try:
            n = ipaddress.IPv6Network(s, strict=False)
        except ValueError:
            return s
        return f"{n.network_address}/64" if n.prefixlen == 64 else s
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return s
    if a.version == 6:
        if a.ipv4_mapped is not None:
            return str(a.ipv4_mapped)
        return f"{ipaddress.IPv6Network((a, 64), strict=False).network_address}/64"
    return str(a)


class AcceptGuard:
    def __init__(self, *, per_door: int = 8, global_cap: int = 32, per_ip_stranger: int = 4, per_ip_proven: int = 16, reserve_door: int | None = None, reserve_global: int | None = None,
                 strikes: int = 10, strike_window: float = 60.0, ban_base: float = 60.0, ban_max: float = 3600.0, proven_window: float = 3600.0, max_ips: int = 4096,
                 clock=time.time, store=None, writer=None):
        self.per_door, self.global_cap = per_door, global_cap
        self.per_ip_stranger, self.per_ip_proven = per_ip_stranger, per_ip_proven
        self.reserve_door = per_door // 2 if reserve_door is None else reserve_door
        self.reserve_global = global_cap // 2 if reserve_global is None else reserve_global
        self.strikes_n, self.strike_window = strikes, strike_window
        self.ban_base, self.ban_max, self.proven_window, self.max_ips = ban_base, ban_max, proven_window, max_ips
        self.clock = clock
        self._mu = threading.Lock()
        self._total = 0
        self._door: dict = {}
        self._ip: dict = {}
        self._strikes: OrderedDict = OrderedDict()                  # ip -> deque of strike times
        self._bans: OrderedDict = OrderedDict()                     # ip -> [until, level]
        self._proven: OrderedDict = OrderedDict()                   # ip -> time of its last admission (its OWN table)
        self._written: dict = {}                                    # ip -> when the proven table last wrote it down
        self.counts = {"admitted": 0, "refused_banned": 0, "refused_ip": 0, "refused_door": 0, "refused_global": 0, "strikes": 0, "bans": 0}
        self.store, self.writer = store, writer
        self._load()

    # ------------------------------------------------------------------ the proven table on disk
    def _load(self) -> None:
        if self.store is None:
            return
        try:
            raw = json.loads(self.store.read_text())
            now = self.clock()
            for ip, ts in sorted((raw.get("proven") or {}).items(), key=lambda kv: kv[1] if isinstance(kv[1], (int, float)) else 0):
                if isinstance(ip, str) and isinstance(ts, (int, float)) and not isinstance(ts, bool) and 0 <= now - ts <= self.proven_window and len(self._proven) < self.max_ips:
                    ip = guard_key(ip)
                    self._proven[ip] = max(float(ts), self._proven.get(ip, 0.0))
                    self._written[ip] = self._proven[ip]
        except (OSError, ValueError, AttributeError, TypeError):
            pass                                                    # (a missing or damaged file is an empty table, never an error)

    def _persist(self, payload: dict) -> None:
        if self.store is None or self.writer is None:
            return
        try:
            self.writer(self.store, json.dumps({"proven": payload}, sort_keys=True).encode())
        except OSError:
            pass                                                    # (the table is a cache: a failure to write it must never fail an admission)

    # ------------------------------------------------------------------ queries
    def _is_proven(self, ip: str, now: float) -> bool:
        ts = self._proven.get(ip)
        return ts is not None and 0 <= now - ts <= self.proven_window

    def is_proven(self, ip: str) -> bool:
        ip = guard_key(ip)
        with self._mu:
            return self._is_proven(ip, self.clock())

    def banned_until(self, ip: str):
        ip = guard_key(ip)
        with self._mu:
            b = self._bans.get(ip)
            return b[0] if b else None

    # ------------------------------------------------------------------ accept
    def admit(self, ip: str, door: str):
        """None: the connection is let in (counted as unauthenticated until `release`); else the reason it is refused at once, before any handshake."""
        ip = guard_key(ip)
        with self._mu:
            now = self.clock()
            proven = self._is_proven(ip, now)
            if not proven:
                b = self._bans.get(ip)
                if b is not None and now < b[0]:
                    self.counts["refused_banned"] += 1
                    return "banned"
            if self._ip.get(ip, 0) >= (self.per_ip_proven if proven else self.per_ip_stranger):
                self.counts["refused_ip"] += 1
                return "per-address cap"
            door_cap = self.per_door if proven else max(1, self.per_door - self.reserve_door)
            glob_cap = self.global_cap if proven else max(1, self.global_cap - self.reserve_global)
            if self._door.get(door, 0) >= door_cap:
                self.counts["refused_door"] += 1
                return "door cap"
            if self._total >= glob_cap:
                self.counts["refused_global"] += 1
                return "global cap"
            self._total += 1
            self._door[door] = self._door.get(door, 0) + 1
            self._ip[ip] = self._ip.get(ip, 0) + 1
            self.counts["admitted"] += 1
            return None

    def release(self, ip: str, door: str) -> None:
        """The connection stopped being unauthenticated (admitted, refused, failed, killed): called on EVERY exit path, once."""
        ip = guard_key(ip)
        with self._mu:
            self._total = max(0, self._total - 1)
            for table, key in ((self._door, door), (self._ip, ip)):
                n = table.get(key, 0) - 1
                if n > 0:
                    table[key] = n
                else:
                    table.pop(key, None)

    # ------------------------------------------------------------------ outcomes
    def strike(self, ip: str) -> bool:
        """A connection of `ip` did not complete admission. True if this strike banned the address."""
        ip = guard_key(ip)
        with self._mu:
            now = self.clock()
            if self._is_proven(ip, now):
                return False                                        # (exempt from the ban table)
            self.counts["strikes"] += 1
            q = self._strikes.pop(ip, None) or deque()
            q.append(now)
            while q and now - q[0] > self.strike_window:
                q.popleft()
            if len(q) < self.strikes_n:
                self._strikes[ip] = q
                self._bound(self._strikes)
                return False
            level = (self._bans[ip][1] + 1) if ip in self._bans else 0
            self._bans.pop(ip, None)
            self._bans[ip] = [now + min(self.ban_base * (2 ** level), self.ban_max), level]
            self._bound(self._bans)
            self.counts["bans"] += 1
            return True

    def proven(self, ip: str) -> None:
        """An admission of `ip` completed: its key was in the door's table AND its signature verified. It is proven for `proven_window`; its strikes and ban are cleared."""
        ip = guard_key(ip)
        with self._mu:
            now = self.clock()
            self._strikes.pop(ip, None)
            self._bans.pop(ip, None)
            self._proven.pop(ip, None)
            self._proven[ip] = now
            self._bound(self._proven)
            write = now - self._written.get(ip, -1e18) >= self.proven_window / 2
            payload = None
            if write:
                self._written[ip] = now
                if len(self._written) > self.max_ips:
                    self._written = {k: v for k, v in self._written.items() if k in self._proven}
                payload = dict(self._proven)
        if payload is not None:
            self._persist(payload)

    def _bound(self, table: OrderedDict) -> None:
        while len(table) > self.max_ips:
            table.popitem(last=False)

    def stats(self) -> dict:
        with self._mu:
            return dict(self.counts, unauthenticated=self._total, proven=len(self._proven), banned=sum(1 for b in self._bans.values() if self.clock() < b[0]))
