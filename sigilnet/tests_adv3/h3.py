"""Helpers for round-3 sync tests."""
import tempfile

from sigilnet import sync as S
from sigilnet.event import event_id
from sigilnet.mirror import Mirror
from sigilnet.thread import default_rules

from sigilnet.tests.test_convergence import visible
from sigilnet.tests.util import World

BIG = {**default_rules(), "posts_per_author_per_hour": 10000}


def big_world(**kw):
    return World(rules=BIG, **kw)


def mirror_with(genesis, events, **kw):
    m = Mirror(tempfile.mkdtemp(), rate_limit=False, **kw)
    m.ingest(genesis)
    for _ in range(3):
        for ev in events:
            m.ingest(ev, live=False)
    return m


def vis(m, tid):
    return visible(m.thread(tid))


def all_events(w):
    return [w.t.events[i] for i in w.t.order[1:]]


class Fn:
    """A transport from a plain function."""
    def __init__(self, fn):
        self.fn, self.calls = fn, []

    def request(self, req):
        self.calls.append(req)
        resp = None
        try:
            resp = self.fn(req)
        except Exception:                                # noqa: BLE001 - a legacy test server that does not know `list`
            resp = None
        if req.get("t") == "list" and not (isinstance(resp, dict) and resp.get("t") in ("list", "error", "unknown")):
            # legacy test servers answer `summary` with leaves/pages: present that as the listing
            legacy = self.fn({**req, "t": "summary"})
            if isinstance(legacy, dict) and legacy.get("t") == "summary":
                resp = {"t": "list", "thread": legacy.get("thread"), "n": legacy.get("n"), "pages": legacy.get("pages", 1), "ids": legacy.get("leaves", [])}
            else:
                resp = legacy
        return dict(resp, nonce=req["nonce"], r=1) if isinstance(resp, dict) and "nonce" not in resp else resp
