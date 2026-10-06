"""`wait`, `ask` bookkeeping and `status` (DESIGN_converse.md 3b). Everything here is local: it reads the mirror (`Mirror.refresh()` picks up what the node or the CLI appended: one stat per
thread) and the small state file (waitstate.py). It sends nothing and marks nothing read.

HIGH-WATER MARK per thread = a position in Thread.arrival (the order lines were resolved into events.jsonl) plus the id found at the position before it (the "tip"). Events after the mark
are new. If the tip no longer sits there (the file was rewritten, or lines that were skipped for a missing key arrived and shifted the order) but is still present, events after ITS new position
are new; if it is gone, everything now present counts as seen: ONE notice says so (an unreported event may be lost from `wait` in that rare case, but `unread` is the full record).
Only the very first look of a state (a new home, a rebuilt state file) is a baseline (one notice per thread); a thread first seen later starts at 0, so a pending [ASK] in a joined thread wakes.
Wake limit: at most WAKES_PER_HOUR returns per hour; beyond it ONE coalesced line, then the wake-worthy events are HELD (kept, counted, listed on the next normal return, never dropped from
`unread`) and a REMINDER line (output only, never an event) at most every REMIND seconds."""
from __future__ import annotations

import time

from . import convo as C
from .waitstate import MAX_HELD, WaitState

WAKES_PER_HOUR = 20
REMIND = 600
POLL_FAST, POLL_SLOW, SLOW_AFTER = 2.0, 5.0, 600.0
MAX_LINES_PER_THREAD = 10
MAX_THREADS_SHOWN = 20
EXIT_WOKE, EXIT_ERROR, EXIT_TIMEOUT = 0, 1, 3


def members(t) -> set:
    return {a for a, m in t.state()["members"].items() if m.get("role") != "guest"}


def _text(e) -> str:
    return e["body"].get("text", "") if e.get("kind") == "post" and isinstance(e.get("body"), dict) else ""


def my_tags(t, me: str) -> dict:
    """ALL my events of the thread: id -> tag (None when untagged). Never a bounded subset (an answer to my [ASK] would read as quiet)."""
    return {i: C.parse(_text(t.events[i]))[0] for i in t.arrival if i in t.events and t.events[i].get("author") == me and t.events[i].get("kind") == "post"}


def _view(t, i):
    e = t.events[i]
    return {"author": e.get("author"), "reply_to": e["body"].get("reply_to") if isinstance(e.get("body"), dict) else None}


def ask_state(t, ask: dict, upto: int, me: str, mem: set) -> bool:
    """Is my ask answered by the first `upto` events of arrival order? (position, not clocks; an ask whose event is gone is unanswered)."""
    try:
        pos = t.arrival.index(ask["id"])
    except ValueError:
        return False
    later = [_view(t, i) for i in t.arrival[pos + 1:upto] if i in t.events]
    return C.answered(ask, later, me, mem)


def new_slice(t, th, first_ever: bool) -> tuple:
    """(new event ids, notice or None, new mark entry). `th` is the stored {"mark", "tip"} or None for a thread this state has not marked yet.
    A thread first seen LATER (a capsule join, a thread someone added us to) starts at position 0: what its history already holds that needs attention IS reported. Only the very first
    look of this state (a new home, or a rebuilt state file) is a baseline."""
    arr = t.arrival
    entry = {"mark": len(arr), "tip": arr[-1] if arr else None}
    if th is None:
        if first_ever:
            return [], f"baseline set for {t.id[:8]}: {max(0, len(arr) - 1)} existing event(s) are not reported (see `unread`)", entry
        return list(arr), None, entry
    mark, tip = th["mark"], th["tip"]
    if mark <= len(arr) and (mark == 0 or (mark > 0 and arr[mark - 1] == tip)):
        return list(arr[mark:]), None, entry
    if tip is not None and tip in arr:                                  # the order shifted but the last reported event is still there: everything after IT is new
        return list(arr[arr.index(tip) + 1:]), f"{t.id[:8]}: the event order changed (late keys or a rewritten file); counting from the last event reported", entry
    return [], f"{t.id[:8]}: the event order changed (file rewritten or late keys): everything now present counts as seen, `unread` lists what is unread", entry


def scan(m, me: str, st: dict, tids, now: float) -> dict:
    """One pass over the watched threads; mutates `st` (marks, reported) and returns {"items": [(tid, id, text)], "overdue": [(tid, ask)], "notices": [...]}."""
    out = {"items": [], "overdue": [], "notices": []}
    first_ever = not st["seeded"]                                   # computed ONCE: every thread of a brand-new (or rebuilt, never-seeded) state is a baseline
    st["seeded"] = True                                             # set by the first completed scan even when there are NO threads yet (Sansa's F4)
    for tid in tids:
        t = m.threads.get(tid)
        if t is None:
            continue
        mem = members(t)
        mark_before = (st["threads"].get(tid) or {}).get("mark", 0)
        tags = my_tags(t, me)
        asks = [a for a in st["asks"] if a["thread"] == tid]
        view = [{"id": a["id"], "to": a["to"], "at": a["at"], "answered": ask_state(t, a, mark_before, me, mem)} for a in asks]   # as of what was ALREADY seen: a new answer must wake
        wait_on = C.awaited(view, mem, now)
        new, notice, entry = new_slice(t, st["threads"].get(tid), first_ever)
        if notice:
            out["notices"].append(notice)
        for i in new:
            e = t.events.get(i)
            if e is None or i in t.void_ids or e.get("kind") != "post":
                continue
            ev = {"author": e.get("author"), "text": _text(e), "reply_to": e["body"].get("reply_to")}
            if C.classify(ev, me, tags, wait_on) == "wake":
                out["items"].append((tid, i, ev["text"]))
        st["threads"][tid] = entry
        for a in asks:
            if a["id"] not in st["reported"] and C.overdue(a, ask_state(t, a, entry["mark"], me, mem), now):
                out["overdue"].append((tid, a))
    return out


def render(m, me: str, items, overdue, notes=()) -> list:
    """The output lines of one return. Peer text appears only through convo.line (12-char id + sanitised head)."""
    lines = list(notes)
    by: dict = {}
    for tid, i, text in items:
        by.setdefault(tid, []).append((i, text))
    for k, (tid, rows) in enumerate(by.items()):
        if k >= MAX_THREADS_SHOWN:
            lines.append(f"+{len(by) - k} more thread(s) with events: `sigilnet unread THREAD`")
            break
        t = m.threads.get(tid)
        un = len(m.unread(tid, me)) if t else 0
        lines.append(f"{tid[:8]} {C.sanitize(t.state()['title'], 40) if t else ''!r}: {len(rows)} to look at, {max(0, un - len(rows))} other unread (quiet or older); `sigilnet unread {tid[:8]}`")
        for i, text in rows[:MAX_LINES_PER_THREAD]:
            lines.append("  " + C.line(i, text))
        if len(rows) > MAX_LINES_PER_THREAD:
            lines.append(f"  +{len(rows) - MAX_LINES_PER_THREAD} more")
    for tid, a in overdue:
        lines.append(f"OVERDUE {tid[:8]}: no answer to your ask {a['id'][:12]} after {int((a['_now'] - a['at']) // 60)} min")
    return lines


def watch_list(m, names, include_public: bool) -> list:
    """Thread ids to watch: the named ones (prefix match, public allowed), else every non-public thread we hold (public ones with --all)."""
    if names:
        out = []
        for n in names:
            hit = [t for t in m.threads if t.startswith(n)]
            if len(hit) != 1:
                raise ValueError(f"thread '{n}': {'no match' if not hit else 'ambiguous'}")
            out.append(hit[0])
        return out
    return [tid for tid, t in m.threads.items() if include_public or t.state()["visibility"] != "public"]


def wait(m, me: str, state: WaitState, names, *, max_seconds: float, include_public: bool = False, clock=time.time, sleep=time.sleep, out=print) -> int:
    """Block until something needs attention. 0 = woke (lines printed), 3 = timeout, 1 = error (raised by the caller's wrapper)."""
    start = clock()
    deadline = start + max_seconds
    announced = set()
    while True:
        m.refresh()
        tids = watch_list(m, names, include_public)
        now = clock()
        result = {}
        notes = []

        def step(st):
            r = scan(m, me, st, tids, now)
            notes.extend(r["notices"])
            held_ids = {(h["thread"], h["id"]) for h in st["held"]}
            items = [(h["thread"], h["id"], _held_text(m, h)) for h in st["held"]] + [x for x in r["items"] if (x[0], x[1]) not in held_ids]
            overdue = [(tid, dict(a, _now=now)) for tid, a in r["overdue"]]
            if not items and not overdue:
                return
            recent = [w for w in st["wakes"] if now - w < 3600]
            if len(recent) < WAKES_PER_HOUR:
                st["wakes"] = recent + [now]
                st["held"] = []
                st["reported"] = (st["reported"] + [a["id"] for _, a in overdue])
                result["lines"] = render(m, me, items, overdue)
                return
            st["held"] = ([{"thread": tid, "id": i} for tid, i, _ in items] )[-MAX_HELD:]      # kept, counted, listed on the next normal return
            if now - st["coalesced_at"] >= 3600:
                st["coalesced_at"] = st["reminded_at"] = now
                result["lines"] = [f"COALESCED: more than {WAKES_PER_HOUR} wakes in the last hour; {len(st['held'])} event(s) are held back (listed on the next normal return); `sigilnet unread` shows everything"]
            elif st["held"] and now - st["reminded_at"] >= REMIND:
                st["reminded_at"] = now
                result["lines"] = [f"REMINDER: {len(st['held'])} held event(s) waiting (wake limit); `sigilnet unread`"]

        state.update(step)
        for n in notes:                                                # printed AFTER the lock is released (a stalled pipe must not hold it)
            if n not in announced:
                announced.add(n)
                out(n)
        if result.get("lines"):
            for ln in result["lines"]:
                out(ln)
            return EXIT_WOKE
        if clock() >= deadline:
            out("wait: nothing new before the timeout")
            return EXIT_TIMEOUT
        sleep(POLL_SLOW if clock() - start >= SLOW_AFTER else POLL_FAST)


def _held_text(m, h) -> str:
    t = m.threads.get(h["thread"])
    e = t.events.get(h["id"]) if t else None
    return _text(e) if e else ""


def status_lines(m, me: str, state: WaitState, home=None, clock=time.time) -> list:
    """`sigilnet status`: local numbers only, nothing from the network."""
    st = state.load()
    now = clock()
    lines = []
    for tid, t in m.threads.items():
        mem = members(t)
        mine = [a for a in st["asks"] if a["thread"] == tid]
        open_asks = [a for a in mine if not ask_state(t, a, len(t.arrival), me, mem)]
        lines.append(f"{tid[:8]} {C.sanitize(t.state()['title'], 40)!r}: {len(t.order)} events, {len(m.unread(tid, me))} unread, {len(open_asks)} open ask(s) of mine"
                     + (f" ({'public' if t.state()['visibility'] == 'public' else 'private'})"))
    recent = [w for w in st["wakes"] if now - w < 3600]
    lines.append(f"wait: {len(recent)}/{WAKES_PER_HOUR} wakes in the last hour, {len(st['held'])} held")
    if home is not None:
        try:
            from .blobstore import BlobStore
            lines.append(f"blobs: {BlobStore(home / 'blobs').usage()} bytes stored")
        except Exception:                                  # noqa: BLE001 - status never fails over a side detail
            pass
    return lines
