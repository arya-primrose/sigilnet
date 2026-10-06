"""Addressing, the FRAMEWORK side (DESIGN_addressing.md): who a post is for is the signed `to` of its body (a list of up to 16 agent ids; thread.py validates its shape), nothing else.
This module turns what a person types (`--to sansa,342fdr`) into those ids, fills the default `to` of a reply (option C: the parent's author), and prints the addressing of a stored post.
Nothing here reads the text of a post (mentions and tags are a CONVENTION of the participants: convo.py), and nothing is done or refused on receipt because of `to`."""
from __future__ import annotations

ACTORS = ("owner", "admin", "member")          # roles that can act: an observer cannot post, a guest only asks to join; neither can be addressed
MAX_TO = 16                                    # thread.py: a `to` holds at most this many ids
MIN_PREFIX = 6                                 # the shortest id prefix accepted (the six characters every listing shows)


class AddressError(ValueError):
    """What a person typed does not name the agents it should (nothing was posted)."""


def _fold(s: str) -> str:
    return " ".join(str(s).split()).casefold()


def resolve_one(members: dict, spec: str) -> str:
    """One member of the thread from a full agent id, a member name (exact, case-insensitive) or an id prefix of at least 6 characters, in that order; a leading `@` is ignored.
    Raises AddressError when nothing or several match (the message lists the candidates)."""
    s = str(spec).strip().lstrip("@").strip()
    if not s:
        raise AddressError("an empty addressee")
    if s in members:
        return s
    named = [a for a, r in members.items() if _fold(r.get("name", "")) == _fold(s)]
    if len(named) == 1:
        return named[0]
    if len(named) > 1:
        raise AddressError(f"'{spec}' is the name of {len(named)} members ({', '.join(a[:MIN_PREFIX] for a in named)}): use an id prefix")
    low = s.lower()
    pref = [a for a in members if len(low) >= MIN_PREFIX and a.startswith(low)]
    if len(pref) == 1:
        return pref[0]
    if len(pref) > 1:
        raise AddressError(f"'{spec}' starts the ids of {len(pref)} members: give more characters")
    raise AddressError(f"'{spec}' is no member of this thread (members: {', '.join(r.get('name') or a[:MIN_PREFIX] for a, r in members.items())})")


def resolve_many(members: dict, specs, me: str) -> list:
    """The ids for `--to a,b`: each resolved, de-duplicated (order kept), none ourselves, each a role that can act, at most 16."""
    out = []
    for spec in specs:
        if not str(spec).strip():
            continue
        a = resolve_one(members, spec)
        role = members[a].get("role")
        if a == me:
            raise AddressError("a post cannot be addressed to yourself")
        if role not in ACTORS:
            raise AddressError(f"'{spec}' is {'an' if role == 'observer' else 'a'} {role}: only an owner, admin or member can be addressed (a {role} cannot act in the thread)")
        if a not in out:
            out.append(a)
    if not out:
        raise AddressError("--to names nobody")
    if len(out) > MAX_TO:
        raise AddressError(f"at most {MAX_TO} addressees")
    return out


def reply_default(thread, parent_id: str, me: str) -> list:
    """Option C: a reply is addressed to the author of the post it answers. A parent that is not (yet) a resolved event has no trustworthy author: no `to`. A reply to OUR OWN post inherits
    that post's `to` (a follow-up to an ask keeps the asker's addressing), minus ourselves and whoever cannot act any more. An author who is an observer or a removed member: no `to`."""
    e = thread.events.get(parent_id)
    if e is None or parent_id in thread.void_ids:
        return []
    members = thread.state()["members"]
    a = e["author"]
    if a == me:
        old = e["body"].get("to") if e["kind"] == "post" else None
        return [x for x in old if isinstance(x, str) and x != me and members.get(x, {}).get("role") in ACTORS][:MAX_TO] if isinstance(old, list) else []
    return [a] if members.get(a, {}).get("role") in ACTORS else []
