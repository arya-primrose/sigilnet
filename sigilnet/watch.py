"""`sigilnet watch`: one long-lived process for the Claude Code Monitor tool (DESIGN_node_daemon.md section 7, P2). One flushed stdout line per new line of
`inbox.jsonl`; no filtering of its own (the daemon already decided what is wake-worthy), no text of any message.

  WATCH started: <N> unannounced
  INBOX <seq> <thread[:8]>: run sigilnet unread <thread[:8]>
  INBOX <seq> <thread[:8]> (guest request): run 'sigilnet requests list <thread[:8]>'
  INBOX <seq> <thread[:8]> (knock): a newcomer waits for your approval: run 'sigilnet knock list'
  INBOX x<K> (burst): run sigilnet list                          (more than burst_n lines inside burst_s seconds, by the lines' own times, in one step)
  REMINDER: <N> unread in <T> thread(s): run sigilnet list         (every `remind` seconds while something announced is still unread)

The cursor (`cursors/<consumer>.json`) is written AFTER the lines are printed: a kill in between re-announces, never loses. A consumer with no cursor file starts at the
head (the unread count is in the start line and the cursor is saved there, so a restart does not forget it); a damaged cursor or a different generation starts from 0."""
from __future__ import annotations

import time
from pathlib import Path

from . import cursors
from .home import open_mirror
from .inboxlog import InboxLog
from . import ping
from .keys import Identity


class Watcher:
    def __init__(self, home, consumer: str = "watch", *, out=print, clock=time.time, sleep=time.sleep, poll: float = 0.25, remind: float = 300.0,
                 burst_n: int = 20, burst_s: float = 10.0):
        cursors._path(home, consumer)                                    # validates the name
        self.home, self.consumer, self.out, self.clock, self.sleep = Path(home), consumer, out, clock, sleep
        self.poll, self.remind, self.burst_n, self.burst_s = poll, remind, burst_n, burst_s
        self.me = Identity.load(self.home / "identity.json")
        self.m = open_mirror(self.home, self.me.id)
        self.log = InboxLog(self.home)
        self.last_note = None                                            # when something was last announced (or reminded); None = nothing announced yet
        self._seen = None

    def unread(self) -> tuple:
        """(events, threads) still unread across the mirror."""
        self.m.refresh()
        per = [len(self.m.unread(tid, self.me.id)) for tid in list(self.m.threads)]
        return sum(per), sum(1 for n in per if n)

    def _reminder_due(self) -> bool:
        return self.last_note is not None and self.clock() - self.last_note >= self.remind

    def _lines(self, entries: list) -> list:
        if len(entries) > self.burst_n:
            ts = [e["t"] for e in entries]
            if any(ts[i + self.burst_n] - ts[i] <= self.burst_s for i in range(len(ts) - self.burst_n)):
                return [f"INBOX x{len(entries)} (burst): run sigilnet list"]
        out = []
        for e in entries:
            t8 = e["thread"][:8]
            out.append(f"INBOX {e['seq']} {t8} (guest request): run 'sigilnet requests list {t8}'" if e.get("guest") else
                       f"INBOX {e['seq']} {t8} (knock): a newcomer waits for your approval: run 'sigilnet knock list'" if e.get("knock") else f"INBOX {e['seq']} {t8}: run sigilnet unread {t8}")
        return out

    def step(self) -> list:
        """One iteration: the lines it prints now (already passed to `out`)."""
        key = self.log.stamp()                                           # (inode, size, mtime): an unchanged file is not read again (it may hold 8 MiB and this runs 4 times a second)
        if key is not None and key == self._seen and not self._reminder_due():
            return []
        cur = cursors.load(self.home, self.consumer)
        gen, seq = (cur or {}).get("gen"), (cur or {}).get("seq", 0)
        cgen, entries = self.log.read_from(gen, seq)
        lines = self._lines(entries) if entries else []
        now = self.clock()
        if not lines and self.last_note is not None and now - self.last_note >= self.remind:
            n, t = self.unread()
            from .knock import waiting_knocks
            k = waiting_knocks(self.home)                                # a newcomer's knock is waiting for the owner's decision: it is not an unread event, so it is counted apart
            if n or k:
                lines = [f"REMINDER: {n} unread in {t} thread(s)" + (f", {k} knock(s) waiting for your approval" if k else "") + ": run sigilnet list" + (" and sigilnet knock list" if k else "")]
            else:
                self.last_note = None                                    # everything announced has been handled: nothing to remind about
        for l in lines:
            self.out(l)
        if lines:
            self.last_note = now
        if entries and cgen:
            cursors.save(self.home, self.consumer, cgen, max(e["seq"] for e in entries))     # AFTER the print
        self._seen = key                                                 # only now: a print that raised must be retried by this same object, not skipped as "unchanged"
        return lines

    def run(self, seconds: float | None = None) -> int:
        cur = cursors.load(self.home, self.consumer)
        if cur is None:
            n, _ = self.unread()
            gen = self.log.gen
            cursors.save(self.home, self.consumer, gen, self.log.head())
        else:
            _, entries = self.log.read_from(cur.get("gen"), cur.get("seq", 0))
            n = len(entries)
            if n:
                self.last_note = self.clock()
        self.out(f"WATCH started: {n} unannounced")
        end = None if seconds is None else self.clock() + seconds
        next_beat = self.clock()                                         # the heartbeat a `ping` answers "watching" from (home/watch.beat)
        while end is None or self.clock() < end:
            if self.clock() >= next_beat:
                ping.beat(self.home)
                next_beat = self.clock() + ping.WATCH_BEAT_EVERY
            self.step()
            self.sleep(self.poll)
        return 0
