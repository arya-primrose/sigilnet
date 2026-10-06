"""The stranger's side of the guest inbox (spec 5.1): read a public thread through its read door, then ask to be admitted through the inbox door."""
from __future__ import annotations

import os

from . import pow as P
from .build import Writer
from .event import encode
from .keys import Identity
from .mirror import Mirror

MAX_ACCEPTED_BITS = 28              # a challenge asking for more than this is refused by us (an owner cannot make a guest burn CPU without limit)


class GuestError(Exception):
    pass


def _printable(x, limit: int = 80) -> str:
    """Text from a hostile inbox that may reach a terminal: printable characters only."""
    return "".join(c if c.isprintable() else "?" for c in str(x))[:limit]


def _challenge(resp, tid) -> tuple[bytes, int]:
    if not isinstance(resp, dict) or resp.get("t") not in ("challenge", "stale") or resp.get("thread") != tid:
        raise GuestError("the inbox did not give a challenge" + (f" ({_printable(resp.get('why'))})" if isinstance(resp, dict) and isinstance(resp.get("why"), str) else ""))
    salt, bits = resp.get("salt"), resp.get("bits")
    if not isinstance(salt, str) or len(salt) != 32 or type(bits) is not int or not 0 <= bits <= P.MAX_BITS:
        raise GuestError("malformed challenge")
    try:
        return bytes.fromhex(salt), bits
    except ValueError:
        raise GuestError("malformed challenge") from None


def _send(transport, tid: str, me: Identity, ev: dict, attempts: int, solve) -> dict:
    """Challenge, proof of work, submit (retrying when the inbox moves its salt or bits). Returns the inbox's answer."""
    from .event import event_id
    eid = event_id(ev)
    resp = transport.request({"t": "challenge", "thread": tid})
    for _ in range(attempts):
        salt, bits = _challenge(resp, tid)
        if bits > MAX_ACCEPTED_BITS:
            raise GuestError(f"the inbox asks for {bits} bits of proof of work (more than the {MAX_ACCEPTED_BITS} this client will spend)")
        nonce = solve(salt, tid, me.sign_pub, eid, bits)
        resp = transport.request({"t": "submit", "thread": tid, "event": ev, "pow": {"salt": salt.hex(), "nonce": nonce}})
        if not isinstance(resp, dict) or resp.get("t") != "stale":
            return resp if isinstance(resp, dict) else {"t": "refused", "why": "malformed answer"}
    raise GuestError("the inbox kept changing its challenge; try again later")


def request_admission(transport, mirror: Mirror, me: Identity, tid: str, text: str, reply_to: str, *, attempts: int = 3, solve=P.solve) -> dict:
    """Build a fully signed guest request, solve the proof of work, submit it. Returns the inbox's answer ({"t": "ok", "id": ...} when queued).
    The thread (its genesis and the event we reply to) must already be in `mirror`: pull it through the read door first."""
    t = mirror.threads.get(tid)
    if t is None:
        raise GuestError("pull the thread through its read door first")
    if reply_to not in t.stored:
        raise GuestError("the event you reply to is not in the mirror (pull first)")
    ev = Writer(me, t).guest_request(text, reply_to)
    if len(encode(ev)) > t.state()["guest_policy"]["max_bytes"]:
        raise GuestError("the request is larger than this thread allows for guests")
    return _send(transport, tid, me, ev, attempts, solve)


def post_as_guest(transport, mirror: Mirror, me: Identity, tid: str, text: str, reply_to: str, *, attempts: int = 3, solve=P.solve) -> dict:
    """An ADMITTED guest's later post, through the inbox door (same proof of work, guest quota). We must already be a guest of the thread in `mirror`
    (pull after the owner accepted the request); the post is a normal signed post built against what we hold."""
    t = mirror.threads.get(tid)
    if t is None:
        raise GuestError("pull the thread through its read door first")
    m = t.state()["members"].get(me.id)
    if m is None or m["role"] != "guest":
        raise GuestError("you are not an admitted guest of this thread (yet): pull again after the owner accepted your request")
    if reply_to not in t.events:
        raise GuestError("the event you reply to is not in the mirror (pull first)")
    ev = Writer(me, t).post(text, reply_to)
    if len(encode(ev)) > t.state()["guest_policy"]["max_bytes"]:
        raise GuestError("the post is larger than this thread allows for guests")
    return _send(transport, tid, me, ev, attempts, solve)
