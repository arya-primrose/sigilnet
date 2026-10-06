"""The carriers of a node that runs SEVERAL (DESIGN_multicarrier.md M1c, "degrade").

A node with one carrier keeps the old path in noderun.run (start waits, a spent restart budget ends the node). A node with several keeps running while at least one carrier is UP: a carrier that
cannot start, died, or is being restarted is DOWN and the node serves and dials on the others. Nothing here blocks: `tick()` is called by the node loop (the main thread: a tor child must be forked
from it) and does one non-blocking step per carrier, with the backoff kept as timestamps compared to the clock, never as a sleep.

    up        serving
    starting  begin_start() done, poll_ready() says "starting" (a tor that is bootstrapping)
    stopping  stop_nowait() sent; reaped() on later ticks (a tor that does not leave is killed)
    down      waiting for `next_try`, then a restart: 5, 30, 120 s (BACKOFF), and once RESTARTS restarts happened inside WINDOW seconds one per SLOW seconds, for ever.

`usable(type)` is what the worker threads read (the MultiDialer, the LocatorService, the capsule worker): ONE immutable snapshot, swapped under a lock."""
from __future__ import annotations

import threading
import time

from .carrier import Carrier, CarrierError

BACKOFF = (5.0, 30.0, 120.0)        # seconds before restart 1, 2, 3 inside the window (the numbers of the one-carrier path, DESIGN_tor_restart.md)
RESTARTS = 3                        # restarts inside WINDOW after which the retries slow down (they never stop)
WINDOW = 1800.0
SLOW = 600.0
BOOTSTRAP_DEADLINE = 180.0          # a carrier "starting" for longer than this is stopped and counted as a failed start
NONE_UP_EXIT = 120.0                # no carrier up for this long: the node has nothing to serve with, it ends (exit 1, loud) instead of idling

_START_ERRORS = (Exception,)                                       # a carrier that raises ANYTHING is down with that reason, never a reason for the node to end (Sansa B2)


class CarrierRun:
    __slots__ = ("type", "carrier", "state", "reason", "since", "next_try", "restarts")

    def __init__(self, ctype: str, carrier: Carrier):
        self.type, self.carrier = ctype, carrier
        self.state, self.reason, self.since, self.next_try = "down", "not started", 0.0, 0.0
        self.restarts: list = []                                    # clock times of the restarts (begin_start calls after the first) inside WINDOW


class CarrierSet:
    def __init__(self, carriers: dict, *, clock=time.monotonic, bootstrap_deadline: float = BOOTSTRAP_DEADLINE):
        self.runs = {t: CarrierRun(t, c) for t, c in carriers.items()}
        self.clock, self.bootstrap_deadline = clock, bootstrap_deadline
        self._mu = threading.Lock()
        self._snap: dict = {}                                       # type -> state, replaced as a whole (never mutated): what the other threads read
        self._none_up_since = None
        self._publish()

    # -- what the other threads read
    def _publish(self) -> None:
        snap = {t: r.state for t, r in self.runs.items()}
        with self._mu:
            self._snap = snap

    def usable(self, ctype: str) -> bool:
        return self._snap.get(ctype) == "up"

    def up_types(self) -> list:
        return [t for t, s in self._snap.items() if s == "up"]

    def any_up(self) -> bool:
        return any(s == "up" for s in self._snap.values())

    def any_alive(self) -> bool:
        """Is some carrier up or on its way (starting)?"""
        return any(s in ("up", "starting") for s in self._snap.values())

    def status(self) -> dict:
        """{type: {"state", "reason", "retry_in"}} for the status file and `sigilnet status`."""
        now = self.clock()
        return {t: {"state": r.state, "reason": r.reason if r.state != "up" else "", "retry_in": max(0, round(r.next_try - now)) if r.state == "down" else None} for t, r in self.runs.items()}

    # -- the steps
    def _wait_for(self, r: CarrierRun, now: float) -> float:
        r.restarts = [t for t in r.restarts if now - t < WINDOW]
        n = len(r.restarts)
        return BACKOFF[min(n, len(BACKOFF) - 1)] if n < RESTARTS else SLOW

    def _go_down(self, r: CarrierRun, now: float, reason: str) -> str:
        """The carrier is gone (or never came): schedule the next try and say so (one line per change)."""
        wait = self._wait_for(r, now)
        r.state, r.reason, r.since, r.next_try = "down", str(reason)[:300], now, now + wait
        slow = len(r.restarts) >= RESTARTS
        return f"carrier {r.type}: down ({r.reason}); retry in {wait:g} s" + (" (restart budget spent: one try per %g s)" % SLOW if slow else "")

    def _launch(self, r: CarrierRun, now: float, stale: bool) -> str | None:
        """begin_start (never blocks). None = launched ("starting" or already "up"); else the reason it could not be."""
        try:
            if not stale:
                r.carrier.refresh_bind()
            r.carrier.begin_start(stale=stale)
        except _START_ERRORS as e:
            return f"cannot start: {type(e).__name__}: {e}"
        r.state, r.since, r.reason = "starting", now, ""
        return None

    def start_all(self, order=None) -> list:
        """First start, before the loop: the carriers in `order` (a list of types; tcp before tor so tcp serves while tor bootstraps). Blocking only where a carrier's own start is (tcp: no).
        Returns the event lines."""
        now = self.clock()
        events = []
        for t in order or list(self.runs):
            r = self.runs[t]
            stale = getattr(r.carrier, "stop_stale", None)
            if stale is not None:
                try:
                    stale()                                         # a tor of ours left by a killed node: once, here, never in the loop
                except Exception:                                   # noqa: BLE001 - best effort
                    pass
            try:
                why = self._launch(r, now, True)
                if why is not None:
                    events.append(self._go_down(r, now, why))
                else:
                    events += self._poll(r, now)
            except Exception as e:                                  # noqa: BLE001
                events.append(self._break(r, now, e))
        self._publish()
        return events

    def _poll(self, r: CarrierRun, now: float) -> list:
        state, why = r.carrier.poll_ready()
        if state == "ready":
            r.state, r.reason, r.since = "up", "", now
            return [f"carrier {r.type}: up"]
        if state == "failed":
            r.carrier.stop_nowait()
            r.state, r.reason, r.since = "stopping", why, now
            return [f"carrier {r.type}: start failed ({str(why)[:200]})"]
        if now - r.since > self.bootstrap_deadline:
            reason = f"did not become ready within {self.bootstrap_deadline:g} s: {r.carrier.down_reason()}"
            r.carrier.stop_nowait()
            r.state, r.reason, r.since = "stopping", reason, now
            return [f"carrier {r.type}: {reason[:200]}"]
        return []

    def _break(self, r: CarrierRun, now: float, e: BaseException) -> str:
        """A carrier call raised: that carrier is down with the exception as its reason (best effort to stop it), the others are untouched."""
        try:
            r.carrier.stop_nowait()
        except Exception:                                           # noqa: BLE001
            pass
        return self._go_down(r, now, f"{type(e).__name__}: {e}")

    def _step(self, r: CarrierRun, now: float) -> list:
        events = []
        if r.state == "up":
            if not r.carrier.healthy():
                reason = r.carrier.down_reason()
                r.carrier.stop_nowait()
                r.state, r.reason, r.since = "stopping", reason, now
                events.append(f"carrier {r.type}: lost ({str(reason)[:200]})")
        elif r.state == "starting":
            events += self._poll(r, now)
        if r.state == "stopping" and r.carrier.reaped():
            events.append(self._go_down(r, now, r.reason))
        elif r.state == "down" and now >= r.next_try:
            r.restarts.append(now)
            why = self._launch(r, now, False)
            if why is not None:
                events.append(self._go_down(r, now, why))
            else:
                events += self._poll(r, now) or [f"carrier {r.type}: restarting"]
        return events

    def tick(self) -> list:
        """One non-blocking step for every carrier; returns the event lines (a state change each: log them, and see `changed`)."""
        now = self.clock()
        events = []
        before = {t: r.state for t, r in self.runs.items()}
        for r in self.runs.values():
            try:
                events += self._step(r, now)
            except Exception as e:                                  # noqa: BLE001 - one broken carrier is a down carrier
                events.append(self._break(r, now, e))
        self._publish()
        self.changed = {t: (before[t], r.state) for t, r in self.runs.items() if before[t] != r.state}
        if self.any_up():
            self._none_up_since = None
        elif self._none_up_since is None:
            self._none_up_since = now
        return events

    changed: dict = {}

    def none_up_too_long(self) -> bool:
        """No carrier up for NONE_UP_EXIT seconds and none starting: the node ends (loudly) instead of idling with nothing to serve."""
        return self._none_up_since is not None and self.clock() - self._none_up_since >= NONE_UP_EXIT and not self.any_alive()

    def reasons(self) -> str:
        return "; ".join(f"{t}: {r.reason or r.state}" for t, r in self.runs.items())

    def stop_all(self) -> None:
        for r in self.runs.values():
            try:
                r.carrier.stop()
            except Exception:                                       # noqa: BLE001 - shutting down
                pass
        self._publish()
