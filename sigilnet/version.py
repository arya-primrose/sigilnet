"""Versions (DESIGN_versioning.md rev 3). Three different numbers with three lifetimes:
  * SW: the software version, a string for humans, NEVER used in a decision.
  * WIRE = (major, minor): how nodes talk NOW. A major increase is a breaking change, a minor increase is backwards compatible; a node speaks its own wire major and
    the PREVIOUS one (MAJORS), so 2.x falls back to 1.x and 3.x to 2.x, unless a major is deprecated. Major 0 = the 0.1.x shapes, which carry no declaration.
  * FORMATS: the thread formats this node reads and writes (the format of a thread is the `v` of its genesis).
A declaration is a self-declared hint (signed only as a claim of the node's own key); it rides as the extra field `ver` of summary/list/get/ping requests and, ONLY when
the asker declared itself, of their answers: a 0.1.x node ignores the extra field, so the 0.1.x wire bytes are unchanged."""
import re

SW = "0.4.2"
WIRE = (1, 0)
MAJORS = (1, 0)
FORMATS = (2, 1)
LEGACY = {"wire": "0.0", "majors": [0], "formats": [1], "sw": None}      # what a peer that declares nothing is taken to speak (0.1.x)

_WIRE_RE = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})")
_SW_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,39}")            # display only: printable, <= 40 characters, no spaces (the operator is often an LLM)
MAX_LIST = 8


def decl() -> dict:
    """This node's declaration (a fresh dict each call)."""
    return {"wire": f"{WIRE[0]}.{WIRE[1]}", "majors": list(MAJORS), "formats": list(FORMATS), "sw": SW}


def _ints(x, lo: int, hi: int):
    if not isinstance(x, list) or not 1 <= len(x) <= MAX_LIST:
        return None
    if any(type(i) is not int or not lo <= i <= hi for i in x) or len(set(x)) != len(x):
        return None
    return sorted(x, reverse=True)


def parse_decl(obj):
    """A peer's declaration, checked and normalised, or None (anything malformed is ignored as if the peer had declared nothing). Unknown extra keys are ignored: a later MINOR
    release may add some."""
    if not isinstance(obj, dict):
        return None
    wire, sw = obj.get("wire"), obj.get("sw")
    m = _WIRE_RE.fullmatch(wire) if isinstance(wire, str) else None
    majors, formats = _ints(obj.get("majors"), 0, 999), _ints(obj.get("formats"), 1, 999)
    if m is None or majors is None or formats is None or not (isinstance(sw, str) and _SW_RE.fullmatch(sw)):
        return None
    if int(m.group(1)) not in majors:
        return None                                                     # a node speaks at least its own wire major
    return {"wire": wire, "majors": majors, "formats": formats, "sw": sw}


def _minor(d: dict, major: int) -> int:
    """The minor level a node offers inside `major`: its own minor for its own major, 0 (the baseline) for an older major it can fall back to."""
    w = _WIRE_RE.fullmatch(d["wire"])
    return int(w.group(2)) if w and int(w.group(1)) == major else 0


def negotiate(local: dict, peer):
    """(major, minor) two nodes talk at, or None. The HIGHEST wire major in the intersection of both `majors`; inside it the LOWER minor's feature set (extras the other side does not
    know are ignored by design). `peer` None = a peer that declared nothing = the 0.1.x shapes (major 0)."""
    p = peer if peer is not None else LEGACY
    common = set(local["majors"]) & set(p["majors"])
    if not common:
        return None
    major = max(common)
    return major, min(_minor(local, major), _minor(p, major))


def serves_format(peer, fmt: int) -> bool:
    """May a thread of format `fmt` be served to this peer (undeclared = format 1 only)?"""
    return fmt in (peer if peer is not None else LEGACY)["formats"]


MAX_WHY = 190                       # a refusal travels as the `why` of an error answer; a 0.1.x asker keeps 200 printable characters of it


def thread_format(t) -> int:
    """The format of a thread = the `v` of its genesis (DESIGN_versioning.md rev 3, 5a). Constant for the thread's life: the thread id commits to it."""
    v = getattr(t, "format", None)
    return v if type(v) is int and v >= 1 else 1


def _or(nums) -> str:
    return " or ".join(str(n) for n in sorted(nums, reverse=True))


def refusal(local: dict, peer, fmt=None):
    """None when this node can serve the peer; otherwise the one plain sentence the peer's operator will read (the `why` of the error answer). FACTS FIRST, no URL (a peer-supplied
    why is shown to operators that are often LLMs; "upgrade at https://..." is the shape of a phishing line), at most MAX_WHY characters. `peer` is the declaration of THE REQUEST
    being answered (None = it declared nothing = 0.1.x): never the cache. `fmt`: the format of the thread asked for, when there is one."""
    if negotiate(local, peer) is None:
        who = f"peer speaks wire {peer['wire']} (sigilnet {peer['sw']})" if peer is not None else "peer declares no wire version (0.1.x)"
        text = f"{who}; this node (sigilnet {local['sw']}) speaks wire {_or(local['majors'])}: the peer must upgrade sigilnet"
    elif fmt is not None and not serves_format(peer, fmt):
        have = _or(peer["formats"]) if peer is not None else "1"
        text = f"thread uses format {fmt}, the peer reads format {have}: the peer must upgrade sigilnet (this node: sigilnet {local['sw']})"
    else:
        return None
    return text[:MAX_WHY]


def describe(d) -> str:
    """One short printable line for `peer list`/`ping`: 'wire 1.0 sw 0.2.0' or 'wire ? (0.1.x or older)'."""
    if d is None:
        return "wire ? (no declaration: 0.1.x or older)"
    return f"wire {d['wire']} sw {d['sw']}"
