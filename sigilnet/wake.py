"""Wake the node loop at once (DESIGN_node_wake.md rev 1).

The node loop used to `time.sleep(TICK)` between rounds, so a local post waited up to TICK for the node to notice it and a notify hint waited up to TICK for its pull to run.
Now the loop waits on a `Waker`: it returns early when the node's event is set (a notify made a pull due, a pull finished) or when the poke file changed (a CLI process
appended events to a mirror). Never longer than TICK: a missed wake costs at most the old behaviour. There is no inotify in the stdlib, so an idle node does one stat every POLL."""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

TICK = 2.0             # the backstop: the loop never waits longer than this
POLL = 0.05            # how often the wait looks at the event and the poke file
MIN_ROUND = 0.2        # two rounds are never closer than this (a burst of pokes cannot make the loop spin)
POKE_CAP = 4096        # the poke file is truncated by the next poke once it is this big


def poke(path) -> None:
    """Tell a running node that events were appended: one byte appended to `path` (so the size changes as well as the mtime). Best effort: never raises."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_size >= POKE_CAP:
                os.ftruncate(fd, 0)
            os.write(fd, b"x")
        finally:
            os.close(fd)
    except Exception:                                 # best effort by contract: a bad path (None, a NUL byte) is as harmless as an unwritable one
        pass


class Waker:
    def __init__(self, poke_path, *, clock=time.monotonic, sleep=time.sleep, poll=None, min_round=None, tick=None):
        self.poke_path = Path(poke_path)
        self.clock, self.sleep = clock, sleep
        self._poll, self._min_round, self._tick = poll, min_round, tick
        self.event = threading.Event()
        self._stamp = self._look()
        self._round_t0: float | None = None

    def _look(self):
        try:
            st = os.stat(self.poke_path)
        except OSError:
            return None                               # missing or unreadable = no change
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def round_started(self) -> None:
        """Called BEFORE the round's work: a wake that arrives during the round re-sets the event and the next wait returns at once."""
        self.event.clear()
        self._stamp = self._look()
        self._round_t0 = self.clock()

    def wait(self, timeout: float | None = None) -> str:
        """"wake" (the event was set), "poke" (the poke file changed since round_started) or "timeout". Not before `min_round` after round_started, not after `timeout`."""
        poll = POLL if self._poll is None else self._poll
        min_round = MIN_ROUND if self._min_round is None else self._min_round
        if timeout is None:
            timeout = TICK if self._tick is None else self._tick
        deadline = self.clock() + timeout
        earliest = deadline if self._round_t0 is None else min(self._round_t0 + min_round, deadline)
        if self._round_t0 is None:
            earliest = self.clock()
        reason = None
        while True:
            now = self.clock()
            if reason is None:
                if self.event.is_set():
                    reason = "wake"
                else:
                    cur = self._look()
                    if cur is not None and cur != self._stamp:
                        reason = "poke"
            if reason is not None and now >= earliest:
                return reason
            if now >= deadline:
                return reason or "timeout"
            self.sleep(max(0.0, min(poll, deadline - now)))
