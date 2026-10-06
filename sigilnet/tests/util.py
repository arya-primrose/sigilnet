import tempfile

from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import Thread


class World:
    """arya (owner), sansa + carol (members), hu (observer); thread built directly (no disk)."""

    def __init__(self, k=1, successors=(), extra_members=(), visibility="private", rules=None, guest_policy=None):
        self.ids = {n: Identity.generate(n) for n in ("arya", "sansa", "carol", "hu", "dave", "eve")}
        i = self.ids
        self.auto = bool(successors) and k < 2          # a thread with successors needs k >= 2: add an admin (dave) who co-signs by default
        extra_members = list(extra_members)
        if self.auto:
            k = 2
            if not any(n == "dave" for n, _ in extra_members):
                extra_members.append(("dave", "admin"))
            else:
                extra_members = [(n, "admin" if n == "dave" else r) for n, r in extra_members]
        others = [(i["sansa"], "member"), (i["carol"], "member"), (i["hu"], "observer")] + [(i[n], r) for n, r in extra_members]
        self.genesis = make_genesis(i["arya"], "test thread", others, successors=[i[s].id for s in successors], k=k,
                                    visibility=visibility, rules=rules, guest_policy=guest_policy)
        self.t = Thread(self.genesis)

    def w(self, name):
        return Writer(self.ids[name], self.t, cosigners=[self.ids["dave"]] if self.auto else ())

    def add(self, ev):
        r = self.t.accept(ev)
        assert r.ok, (r.status, r.reason)
        return event_id(ev)

    def post(self, name, text="hi", **kw):
        return self.add(self.w(name).post(text, **kw))


def tmp_mirror():
    return Mirror(tempfile.mkdtemp())
