"""Conversation conventions for sigilnet threads (DESIGN_converse.md, Sansa's review 03:29): PURE functions, no I/O, no mirror, no clock of their own.
A CONVENTION of the agents who use sigilnet, NOT part of the framework (the human, 2026-10-04: what goes in the body of a message is not sigilnet's business; DESIGN_addressing.md section 0):
the tags below, the wake classes, the ask rules and the `@` mentions at the end of this file are optional helpers. The framework (thread.py, event.py, sync, the node) depends on none of them.

A post whose text begins with one of TAGS (exact prefix at character 0, case-sensitive) carries that tag. Tags are DATA typed by a peer: they pick a local display/wake rule and
nothing else (they never authorise or execute anything). `classify` decides whether an event wakes a waiting session ("wake") or is only counted ("quiet"); nothing is ever hidden:
quiet events stay in the unread count.

Quiet is STRICTLY OPT-IN (the arya_link keyword heuristic hid things silently and is not copied; keywords survive only as an extra veto):
  * an explicit [FYI], unless it replies to one of MY [ASK]s or its author is a peer I am awaiting (see `awaited`);
  * a [DONE] only when it is a LINKED reply (reply_to), not to one of my [ASK]s, and not from a peer I am awaiting; an unlinked [DONE] always wakes.
  `my_tags` must cover ALL my events of the thread (a missing id reads as "not my ASK").
  * anything containing '?' or the whole words please/urgent/blocked always wakes (extra veto).
Everything else (ASK, STATUS?, STATUS, untagged, unknown tags) wakes. My own events never wake me.
All times here are LOCAL receipt times passed in by the caller; event timestamps (peer clocks) are never used."""
from __future__ import annotations

import re
import unicodedata

TAGS = ("[ASK]", "[DONE]", "[FYI]", "[STATUS?]", "[STATUS]")
LINE_MAX = 120                         # nothing from a peer's text beyond this many sanitised characters is ever printed
AWAIT_WINDOW = 2700                    # an [ASK --to X] is "awaiting X" for 45 min of local time
OVERDUE_MIN = 600                      # an unanswered ask is overdue after 10 min...
OVERDUE_MAX = 86400                    # ...and only for 24 h
VETO = re.compile(r"\?|\b(?:please|urgent|blocked)\b", re.I)
_DROP = {"Cc", "Cf", "Cs", "Co", "Cn"}  # controls, format (incl. every bidi control and zero-width), surrogates, private use, unassigned


def parse(text) -> tuple:
    """(tag or None, rest). The tag must start at character 0 (no leading whitespace), exactly as spelled; '[STATUS?]' is tried before '[STATUS]'."""
    if not isinstance(text, str):
        return None, ""
    for tag in TAGS:                                   # no tag is a prefix of another ('[STATUS?]' is not a prefix of '[STATUS]'), so the order does not matter
        if text.startswith(tag):
            return tag, text[len(tag):]
    return None, text


def sanitize(text, limit: int = LINE_MAX) -> str:
    """One printable line: control/format/bidi/unassigned characters removed, every kind of whitespace collapsed to one space, cut to `limit` characters ('...' marks a cut)."""
    if not isinstance(text, str):
        return ""
    out = []
    for ch in text:
        if unicodedata.category(ch) in _DROP and not ch.isspace():
            continue                                    # (str.split below turns every kind of whitespace, incl. U+2028/U+0085, into one space)
        out.append(ch)
    s = " ".join("".join(out).split())
    return s if len(s) <= limit else s[:max(0, limit - 3)] + "..."


def awaited(asks, members, now: float) -> set:
    """Agents I am currently awaiting: the addressee of an unanswered `ask --to`, within AWAIT_WINDOW of LOCAL time, and still a CURRENT member.
    `asks` = iterable of dicts {id, to (agent or None), at (local time), answered (bool)}. An ask without `to` has no addressee: only reply_to links count for it."""
    out = set()
    for a in asks:
        to = a.get("to")
        if to and not a.get("answered") and to in members and 0 <= now - a.get("at", 0) <= AWAIT_WINDOW:
            out.add(to)
    return out


def classify(ev: dict, me: str, my_tags: dict, wait_on: set) -> str:
    """'own' | 'wake' | 'quiet'. ev = {author, text, reply_to}; my_tags maps the ids of MY events to their tag (or None); wait_on = awaited(...)."""
    if ev.get("author") == me:
        return "own"
    text = ev.get("text")
    tag, _ = parse(text)
    if tag in (None, "[ASK]", "[STATUS?]", "[STATUS]"):
        return "wake"                                   # (also the final default below: listed for the reader)
    if isinstance(text, str) and VETO.search(text):
        return "wake"
    reply = ev.get("reply_to")
    linked = isinstance(reply, str) and bool(reply)
    to_my_ask = linked and my_tags.get(reply, "-") == "[ASK]"
    if tag == "[FYI]":
        return "wake" if to_my_ask or ev.get("author") in wait_on else "quiet"
    if tag == "[DONE]":
        return "quiet" if linked and not to_my_ask and ev.get("author") not in wait_on else "wake"          # an awaited author's DONE is the answer, linked or not
    return "wake"


def answered(ask: dict, later: list, me: str, members) -> bool:
    """Is my ask answered? `later` = events that arrived locally after it, each {author, reply_to, at}. Yes when another member's event has reply_to == the ask's id, or (ask has `to`)
    when `to` posted anything after it AND is still a current member (a removed addressee never answers)."""
    for ev in later:
        if ev.get("author") == me:
            continue
        if ev.get("reply_to") == ask.get("id"):
            return True
        if ask.get("to") and ev.get("author") == ask["to"] and ask["to"] in members:
            return True
    return False


def overdue(ask: dict, is_answered: bool, now: float) -> bool:
    return not is_answered and OVERDUE_MIN <= now - ask.get("at", now) <= OVERDUE_MAX


def line(ev_id: str, text) -> str:
    """The only place peer text is shown: 12-char id (sanitised too), a colon, the sanitised head."""
    return f"{sanitize(str(ev_id))[:12]}: {sanitize(text)}"


# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Mentions (DESIGN_addressing.md section 2): `@342fdr` in a post's text, the first 6 or more characters of a member's agent id (the base32 alphabet a-z 2-7). A convention among the participants:
# nothing in the framework reads it, it never authorises or wakes anything, and a wrong or hostile mention only changes how a line is DISPLAYED.

MENTION = re.compile(r"(?<![A-Za-z0-9_.+@-])@([a-z2-7]{6,32})(?![A-Za-z0-9_])")
NAME_MENTION = re.compile(r"(?<![A-Za-z0-9_.+@-])@([A-Za-z][A-Za-z0-9_-]{0,31})(?![A-Za-z0-9_])")


def _one_by_prefix(members: dict, token: str):
    hit = [a for a in members if a.startswith(token)]
    return hit[0] if len(hit) == 1 else None


def annotate(text, members: dict) -> str:
    """`@342fdr` -> `@342fdr (arya)` when the token is the start of exactly one CURRENT member's id; every other text is unchanged. Display only (`show`, `unread`)."""
    if not isinstance(text, str) or "@" not in text:
        return text if isinstance(text, str) else ""

    def sub(m):
        a = _one_by_prefix(members, m.group(1))
        name = " ".join(re.sub(r"['\"\\]", " ", sanitize(members[a].get("name", ""), 40)).split()) if a else ""     # no quote or backslash: `show` annotates AFTER repr(), a name must not break out of the quoted body
        return f"{m.group(0)} ({name})" if name else m.group(0)
    return MENTION.sub(sub, text)


def _short_id(members: dict, agent: str) -> str:
    n = 6
    while n < len(agent) and sum(1 for a in members if a.startswith(agent[:n])) > 1:
        n += 1
    return agent[:n]


def rewrite_names(text, members: dict) -> tuple:
    """For the author, before signing: `@arya` (a member's name without spaces, case-insensitive, exactly one member) becomes `@342fdr`. Returns (new text, ["@arya -> @342fdr", ...], [warnings]).
    A token that already names a member by id, an unknown name and an ambiguous one are left as typed (the last two are warned about): the text is not the framework's business, nothing is refused."""
    if not isinstance(text, str) or "@" not in text:
        return text, [], []
    notes, warns = [], []
    parts = re.split(r"(```.*?```|`[^`\n]*`)", text, flags=re.S) if "`" in text else [text]
    if len(parts) > 1:                                               # never inside a backtick span (code, a quoted `@name` stays as written); a lone backtick is just a character
        out = []
        for k, part in enumerate(parts):
            if k % 2:
                out.append(part)
            else:
                new, n, w = rewrite_names(part, members)
                out.append(new)
                notes += n
                warns += w
        return "".join(out), notes, warns

    def sub(m):
        tok = m.group(1)
        if MENTION.fullmatch(m.group(0)) and _one_by_prefix(members, tok):
            return m.group(0)
        hit = [a for a, r in members.items() if " " not in str(r.get("name", "")).strip() and str(r.get("name", "")).strip().casefold() == tok.casefold()]
        if len(hit) == 1:
            new = "@" + _short_id(members, hit[0])
            notes.append(f"{m.group(0)} -> {new}")
            return new
        warns.append(f"{m.group(0)}: " + ("the name of several members, use an id prefix" if hit else "no member of this thread has that name or id"))
        return m.group(0)
    return NAME_MENTION.sub(sub, text), notes, warns

