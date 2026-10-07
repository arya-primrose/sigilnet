"""`sigilnet live`: a human-readable, live view of one or more threads for a person watching (the observer seat). READ ONLY: it reads the mirror the node keeps
up to date and never writes an event, a cursor or a wake line of its own.

The layout (one block per event, replies named, long posts cut with a marker):

  ---- Wed 07 Oct 2026 (MDT) ----------------------------------------
  13:19:12  arya -> sansa                                    [ce750c7f]
            [SYNC-CHECK] arya=56 sansa=49
  13:19:40  sansa -> arya                                    [b5266486]
            in reply to arya [ce750c7f]: [SYNC-CHECK] arya=56 sansa=49
            [SYNC-CHECK] arya=57 sansa=49 (108 events replay clean ...)

Everything a peer wrote is DATA and printed as such: control, format (bidi, zero-width), private and separator characters are replaced by spaces before anything
reaches the terminal (an escape sequence in a post cannot move the cursor or recolour the screen); the colours here are the viewer's own. Tags like [ASK] are a
display convention (convo.py): the colour follows the text, nothing reads it as protocol. Times are the machine's local time zone."""
from __future__ import annotations

import hashlib
import re
import shutil
import time
import unicodedata

from . import convo
from .mirror import _STRIP, _attachments

DEFAULT_LINES = 30                         # wrapped lines of one post shown unless --full (an 8000-character review package would fill the screen)
MIN_WIDTH, MAX_WIDTH = 40, 140
GUTTER = 10                                # "13:19:12  " : the time column; the text hangs under the name
PALETTE = (36, 33, 35, 32, 34, 91, 96, 93)  # ANSI foreground codes handed out to authors by a hash of the agent id (same agent, same colour, in every run)
TAG_COLOUR = {"[ASK]": "1;33", "[DONE]": "1;32", "[STATUS?]": "1;35", "[STATUS]": "35", "[SYNC-CHECK]": "2", "[FYI]": "36", "[ROTATED-TO]": "1;36", "[ROTATED-FROM]": "1;36"}


def clean(text) -> str:
    """Peer text made safe to print, keeping its line breaks and indentation: every character of a category in mirror._STRIP (control, format, private, unassigned,
    line and paragraph separators) and every exotic space becomes a space; tabs become four spaces; `\\n` stays."""
    if not isinstance(text, str):
        return ""
    out = []
    for c in text.replace("\r\n", "\n").replace("\r", "\n"):
        if c == "\n":
            out.append(c)
        elif c == "\t":
            out.append("    ")
        else:
            cat = unicodedata.category(c)
            out.append(" " if cat in _STRIP or (cat == "Zs" and c != " ") else c)
    return "".join(out)


def cell(c: str) -> int:
    """Terminal columns one character takes: 0 for combining marks, 2 for East Asian wide/fullwidth (CJK, emoji), 1 otherwise."""
    if unicodedata.category(c) in ("Mn", "Me"):
        return 0
    return 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1


def cells(text: str) -> int:
    return sum(cell(c) for c in text)


def cut(text: str, width: int) -> str:
    """The longest prefix of `text` that fits `width` columns."""
    n = 0
    for i, c in enumerate(text):
        n += cell(c)
        if n > width:
            return text[:i]
    return text


def _wrap_line(line: str, width: int) -> list:
    """One source line wrapped to `width` COLUMNS: greedy by words, a word wider than the line is broken by characters, the indentation of the line is kept on every
    row, spaces at a break are dropped."""
    indent = line[:len(line) - len(line.lstrip(" "))][:width // 2]
    room = width - len(indent)
    rows, cur, used = [], "", 0
    for tok in re.findall(r"\s+|\S+", line.lstrip(" ")):
        if tok.isspace():
            if cur and used + len(tok) <= room:
                cur, used = cur + tok, used + len(tok)
            elif cur:
                rows.append(cur.rstrip())
                cur, used = "", 0
            continue
        w = cells(tok)
        if used + w <= room:
            cur, used = cur + tok, used + w
            continue
        if cur.strip():
            rows.append(cur.rstrip())
        cur, used = "", 0
        while cells(tok) > room:
            head = cut(tok, room) or tok[0]
            rows.append(head)
            tok = tok[len(head):]
        cur, used = tok, cells(tok)
    if cur.strip() or not rows:
        rows.append(cur.rstrip())
    return [indent + r for r in rows]


def wrap(text: str, width: int) -> list:
    """The lines of `text` wrapped to `width` terminal columns (wide characters count 2), each source line kept apart and its indentation kept on the continuation
    lines; an empty line stays one."""
    out = []
    for line in clean(text).split("\n"):
        line = line.rstrip()
        out += _wrap_line(line, width) if line else [""]
    while out and not out[-1].strip():
        out.pop()
    return out


class Style:
    def __init__(self, color: bool):
        self.color = color

    def __call__(self, code, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color and text else text


def author_colour(agent: str) -> int:
    return PALETTE[hashlib.sha256(agent.encode()).digest()[0] % len(PALETTE)]


def _members_everywhere(t) -> dict:
    """agent id -> member record, over the current state and every branch state (a member who left or sits on another branch still counts as a possible look-alike)."""
    out = {}
    for st in [t.state(), *t.states.values()]:
        for a, v in st["members"].items():
            out.setdefault(a, v)
    return out


def name_of(t, agent: str) -> str:
    """The member's display name as the thread knows it, or the id prefix. A display name is a claim: when another member of the thread (any branch) claims the same
    name, the id prefix is added (`alice (3f9a2c)`), exactly as `show`/`unread` print it, so two people can never look like one."""
    members = _members_everywhere(t)
    m = members.get(agent)
    name = clean(m.get("name", "")).strip() if m else ""
    if not name:
        return agent[:6]
    twin = any(a != agent and clean(v.get("name", "")).strip() == name for a, v in members.items())
    return f"{name} ({agent[:6]})" if twin else name


def _admin_line(t, e: dict) -> str:
    k, b = e["kind"], e["body"]
    who = lambda a: name_of(t, a) if isinstance(a, str) else "?"
    if k == "genesis":
        return f"thread created: {clean(b.get('title', '')).strip()[:100]!r}"
    if k == "member_add":
        a = b.get("agent")
        who_ = name_of(t, a) if isinstance(a, str) and a in _members_everywhere(t) else clean(str(b.get("name", "?")))[:40]
        return f"{who_} joined as {clean(str(b.get('role', '?')))[:20]}"
    if k == "member_remove":
        return f"{who(b.get('agent'))} was removed"
    if k == "revoke":
        return f"a key was revoked ({who(b.get('agent'))})"
    if k == "rules_update":
        return "the thread rules were updated"
    if k == "checkpoint":
        return "checkpoint"
    if k == "owner_transfer":
        return f"ownership moved to {who(b.get('new_owner') or b.get('to'))}"
    if k == "owner_takeover":
        return "ownership was taken over"
    if k == "close":
        return "thread CLOSED (nothing more can be posted here)"
    return f"({k})"


def _digest_line(e: dict) -> str:
    return f"({e['kind']}) " + clean(str(e["body"]))[:160].replace("\n", " ")


class Renderer:
    """Turns events into lines. Knows the width, the colours and the day of the last block (to print a date line when it changes)."""

    def __init__(self, *, width: int | None = None, color: bool = False, max_lines: int | None = DEFAULT_LINES, multi: bool = False):
        w = width or shutil.get_terminal_size((100, 24)).columns
        self.width = max(MIN_WIDTH, min(MAX_WIDTH, w))
        self.c, self.max_lines, self.multi, self.day = Style(color), max_lines, multi, None

    def day_line(self, ts: float) -> list:
        day = time.strftime("%a %d %b %Y", time.localtime(ts))
        if day == self.day:
            return []
        self.day = day
        head = f"---- {day} ({time.strftime('%Z', time.localtime(ts))}) "
        return ["", self.c("2", head + "-" * max(4, self.width - len(head)))]

    def banner(self, m, t) -> list:
        st = t.state()
        members = ", ".join(f"{name_of(t, a)} ({v['role']})" for a, v in st["members"].items())
        closed = " [CLOSED]" if st.get("closed") else ""
        return [self.c("1", f"== {t.id[:8]}  {clean(st['title'])}{closed}"), self.c("2", f"   members: {members}")]

    def event(self, m, t, i: str) -> list:
        e = t.events[i]
        when = time.strftime("%H:%M:%S", time.localtime(e["ts"]))
        out = self.day_line(e["ts"])
        pre = self.c("2", f"[{t.id[:8]}] ") if self.multi else ""
        tag = self.c("2", f"[{i[:8]}]")
        if e["kind"] in ("genesis", "member_add", "member_remove", "revoke", "rules_update", "checkpoint", "owner_transfer", "owner_takeover", "close"):
            out.append(f"{self.c('2', when)}  {pre}{self.c('2', '* ' + _admin_line(t, e))}")
            return out
        author = name_of(t, e["author"])
        who = self.c(f"1;{author_colour(e['author'])}", author)
        to = e["body"].get("to") if e["kind"] == "post" else None
        names = [name_of(t, a) for a in to[:8] if isinstance(a, str)] if isinstance(to, list) else []
        arrow = (" -> " + ", ".join(names) + (f" +{len(to) - 8}" if len(to) > 8 else "")) if names else ""
        head_plain = f"{when}  {'[' + t.id[:8] + '] ' if self.multi else ''}{author}{arrow}"
        pad = max(1, self.width - cells(head_plain) - 10)
        out.append(f"{self.c('2', when)}  {pre}{who}{self.c('2', arrow)}{' ' * pad}{tag}")
        pad_in = " " * GUTTER
        body_width = self.width - GUTTER
        if i in t.void_ids:
            out.append(pad_in + self.c("2", "[voided: beyond a cut; text withheld]"))
            return out
        if e["kind"] != "post":
            out.append(pad_in + self.c("2", _digest_line(e)))
            return out
        rt = e["body"].get("reply_to")
        if isinstance(rt, str):
            out.append(pad_in + self.c("2", self._reply_note(t, rt, body_width)))
        text = e["body"].get("text", "")
        lines = wrap(convo.annotate(text, t.state()["members"]) if isinstance(text, str) else "", body_width)
        skipped = 0
        if self.max_lines is not None and len(lines) > self.max_lines:
            skipped, lines = len(lines) - self.max_lines, lines[:self.max_lines]
        for n, l in enumerate(lines):
            out.append(pad_in + (self._tagged(l) if n == 0 else l))
        if skipped:
            out.append(pad_in + self.c("2", f"... (+{skipped} more lines; --full here, or `show {t.id[:8]} --full`)"))
        att = _attachments(e["body"].get("refs"))
        if att:
            out.append(pad_in + self.c("2", att.strip()))
        return out

    def _tagged(self, line: str) -> str:
        tag, _ = convo.parse(line)
        return self.c(TAG_COLOUR.get(tag, "36"), tag) + line[len(tag):] if tag else line

    def _reply_note(self, t, rt: str, width: int) -> str:
        p = t.events.get(rt)
        if p is None:
            return f"in reply to [{rt[:8]}]"
        if rt in t.void_ids:
            return f"in reply to [{rt[:8]}] (voided: text withheld)"
        quote = ""
        if p["kind"] == "post" and isinstance(p["body"].get("text"), str):
            quote = " ".join(clean(p["body"]["text"]).split())
        s = f"in reply to {name_of(t, p['author'])} [{rt[:8]}]" + (f": {quote}" if quote else "")
        return s if cells(s) <= width else cut(s, max(0, width - 3)) + "..."


class Live:
    """Follows threads of a mirror. `start()` prints the headers and the last `last` events of each thread; `step()` prints what arrived since (call it about once a
    second); a thread that appears later (a rotation followed by the node) is announced and shown from its start."""

    def __init__(self, m, wanted: list, out, *, last: int = 10, **style):
        self.m, self.wanted, self.out, self.last = m, wanted, out, last
        self.shown: dict = {}                                            # thread id -> set of event ids printed
        self.r = Renderer(**style)

    def _threads(self) -> list:
        ids = [tid for tid in self.m.threads if (any(tid.startswith(w) for w in self.wanted) if self.wanted else tid in self.shown or not self.m.threads[tid].state()["closed"])]
        return sorted(ids, key=lambda tid: (self.m.threads[tid].events[next(iter(self.m.threads[tid].order))]["ts"], tid))

    def _print(self, lines: list) -> None:
        for l in lines:
            self.out(l)

    def start(self) -> int:
        self.m.refresh()
        tids = self._threads()
        self.r.multi = len(tids) > 1
        for tid in tids:
            t = self.m.threads[tid]
            ids = t.topo(include_void=True)
            self._print(self.r.banner(self.m, t))
            if len(ids) > self.last:
                self._print([self.r.c("2", f"   ({len(ids) - self.last} earlier events not shown; --last N, or `show {tid[:8]}`)")])
            self.shown[tid] = set(ids)
            for i in ids[-self.last:] if self.last else []:
                self._print(self.r.event(self.m, t, i))
        return len(tids)

    def step(self) -> int:
        self.m.refresh()
        n = 0
        for tid in self._threads():
            t = self.m.threads[tid]
            seen = self.shown.get(tid)
            if seen is None:                                             # a thread that was not here at start
                self.r.multi = True
                self._print([""] + self.r.banner(self.m, t))
                seen = self.shown[tid] = set()
            new = [i for i in t.topo(include_void=True) if i not in seen]
            for i in new:
                seen.add(i)
                self._print(self.r.event(self.m, t, i))
            n += len(new)
        return n
