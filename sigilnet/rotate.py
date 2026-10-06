"""Manual rotation: continue a thread that nears the MAX_STORED wall in a NEW thread (DESIGN_retention.md option A; the human, 2026-10-03: "Build manual").

`rotate_thread` is what `sigilnet rotate THREAD [--title T] [--close]` runs. It takes nothing from the old thread but its CURRENT state (members and their roles, rules, guest policy, threshold,
successors) and creates, in this order: (1) the new thread (same owner, and encrypted if the old one was), (2) its first post `[ROTATED-FROM] <old id> <old head> <old events>`, (3) in the old
thread the pointer post `[ROTATED-TO] <new id> ...`, and only if asked, (4) the `close` of the old thread. Nothing is deleted or moved: the old thread stays readable and synced.
It does NOT make the other nodes follow the new thread: a node pulls only threads it was told about (node.py `_plan`), so every other member runs `sigilnet peer invite OWNER --thread NEW`
(the pointer post says so, and the result carries the line). Only an owner may rotate, and only a private thread (a public thread has doors and guests: not covered)."""
import re

from . import event as E
from .build import Writer, make_genesis
from .thread import MAX_STORED

WARN_AT = 0.8                       # `list` and the sync check say "rotate soon" from this share of the wall (16000 of 20000 events)


class RotateError(ValueError):
    """Nothing was created (the message says why), or, if `partial` is set, only the first steps were done."""

    def __init__(self, msg, partial=None):
        super().__init__(msg)
        self.partial = partial


def near_wall(n_stored: int) -> bool:
    return n_stored >= WARN_AT * MAX_STORED


def next_title(title: str) -> str:
    """'arya+sansa coordination' -> '... (2)', '... (2)' -> '... (3)' (kept within the 200 characters a title may have)."""
    m = re.fullmatch(r"(.*) \((\d+)\)", title, re.S)
    base, n = (m.group(1), int(m.group(2)) + 1) if m else (title, 2)
    tail = f" ({n})"
    return base[:200 - len(tail)] + tail


class _Pub:
    """A member as `make_genesis` wants it (id, name, public keys): taken from the old thread's state, nothing secret."""

    def __init__(self, aid, rec):
        self.id, self.name, self.sign_pub, self.kex_pub = aid, rec.get("name", ""), rec["sign"], rec["kex"]


def already_rotated(t, me_id: str):
    """The id of the `[ROTATED-TO]` pointer this owner already posted in thread `t`, or None."""
    for i in t.order:
        e = t.events[i]
        if e["kind"] == "post" and e["author"] == me_id and str(e["body"].get("text", "")).startswith("[ROTATED-TO] "):
            return i
    return None


def rotate_thread(m, me, tid: str, *, title: str | None = None, close: bool = False) -> dict:
    """Returns {"old", "new", "title", "events", "invite": [(name, agent id)], "closed"}; raises RotateError."""
    t = m.threads.get(tid)
    if t is None:
        raise RotateError("no such thread")
    st = t.state()
    if st["owner"] != me.id:
        raise RotateError("only the owner of a thread may rotate it (the new thread is owned by whoever rotates)")
    if st["visibility"] != "private":
        raise RotateError("only a private thread can be rotated (a public thread has doors and guests; not covered)")
    if st["closed"]:
        raise RotateError("the thread is closed")
    done = already_rotated(t, me.id)
    if done:
        raise RotateError(f"this thread was already rotated (pointer post {done[:8]}); the new thread is named in it")
    if close and st["admin_threshold"] > 1:
        raise RotateError("--close needs co-signatures when the admin threshold is above 1: not supported here (rotate without --close)")
    others = [(_Pub(a, r), r["role"]) for a, r in st["members"].items() if a != me.id and r["role"] != "guest"]
    new_title = title if title is not None else next_title(st["title"])
    g = make_genesis(me, new_title, others, successors=[s for s in st["successors"] if s in st["members"]], rules=dict(st["rules"]),
                     guest_policy=dict(st["guest_policy"]), visibility="private", k=st["admin_threshold"])
    new_id, n_old, head_old = E.event_id(g), len(t.stored), t.head
    encrypted = m.codec.is_encrypted(tid)
    r = m.ingest(g)
    if not r.ok:
        raise RotateError(f"the new thread was refused: {r.reason or r.status}")
    partial = {"new": new_id}
    try:
        if encrypted:
            m.enable_encryption(new_id, me)
        nt = m.threads[new_id]
        r = m.ingest(Writer(me, nt).post(f"[ROTATED-FROM] {tid} {head_old} {n_old}"))
        if not r.ok:
            raise RotateError(f"the first post of the new thread was refused: {r.reason or r.status}")
        invite = [(rec.get("name") or a[:8], a) for a, rec in st["members"].items() if a != me.id]
        pointer = (f"[ROTATED-TO] {new_id} \"{new_title}\": this thread continues there (nothing was deleted). It nears the {MAX_STORED}-event wall. "
                   f"A node pulls only threads it was told about: on every other node run `sigilnet peer invite {me.id} --thread {new_id}` "
                   f"(the owner's id; your peer book may name the owner differently), then post in the new thread.")
        r = m.ingest(Writer(me, t).post(pointer))
        if not r.ok:
            raise RotateError(f"the pointer post in the old thread was refused: {r.reason or r.status}")
        closed = False
        if close:
            r = m.ingest(Writer(me, t).admin("close", {}))
            if not r.ok:
                raise RotateError(f"the old thread could not be closed: {r.reason or r.status}")
            closed = True
    except RotateError as e:
        raise RotateError(str(e) + f"  (the new thread {new_id} EXISTS; the steps after it were not all done)", partial) from None
    return {"old": tid, "new": new_id, "title": new_title, "events": n_old, "invite": invite, "closed": closed}
