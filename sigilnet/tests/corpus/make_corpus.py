"""Writes the FORMAT-1 CONFORMANCE CORPUS (DESIGN_versioning.md 5a.4): frozen format-1 threads plus the derived state the code that wrote them computed, and a must-reject list.

Run ONCE, with the package that defines format 1 (it was run with the genuine v0.1.1 package: `PYTHONPATH=<v0.1.1 tree> python make_corpus.py OUTDIR`). The files are then FROZEN: every
later release must replay events.jsonl to exactly expected.json (tests/test_corpus.py). Only throwaway identities, never ours. It uses only API that exists in every release.
Each scenario directory holds `events.jsonl` (canonical events, one per line, shuffled with a fixed seed: arrival order must not matter), `expected.json` and `reject.json` (events the
thread must refuse, with the status they got)."""
import json
import random
import sys
from pathlib import Path

from sigilnet import canon
from sigilnet import event as E
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.thread import Thread


def summary(t) -> dict:
    """The derived state a replay must reproduce (JSON-able, no times, no arrival data)."""
    st = t.state()
    keep = ("title", "owner", "owner_epoch", "epoch", "removed", "successors", "rules", "guest_policy", "admin_threshold", "visibility", "closed", "cp_count", "cut", "last_cp")
    out = {k: st[k] for k in keep}
    out["members"] = {a: m["role"] for a, m in sorted(st["members"].items())}
    out["id"], out["head"] = t.id, t.head
    out["order"] = list(t.order)
    out["void"] = sorted(t.void_ids)
    out["status"] = {s: sorted(i for i, x in t.status.items() if x == s) for s in sorted(set(t.status.values()))}
    out["stored"] = len(t.stored)
    return json.loads(json.dumps(out, sort_keys=True))


def resign(ident, ev, **changes):
    ev = {k: v for k, v in ev.items() if k not in ("sig", "cosigs")}
    ev.update(changes)
    ev["sig"] = ident.sign(E.sign_input(ev))
    return ev


class Scn:
    def __init__(self, name, k=1, successors=(), roles=None):
        names = ["owner", "sansa", "carol", "obs", "dave", "eve"]
        self.i = {n: Identity.generate(n) for n in names}
        i = self.i
        others = [(i["sansa"], "member"), (i["carol"], "member"), (i["obs"], "observer"), (i["dave"], "admin" if k > 1 else "member")]
        self.g = make_genesis(i["owner"], name, others, successors=[i[s].id for s in successors], k=k)
        self.t = Thread(self.g)
        self.k, self.name, self.rejects = k, name, []
        self.evs = [self.g]

    def w(self, who):
        return Writer(self.i[who], self.t, cosigners=[self.i["dave"]] if self.k > 1 else ())

    def add(self, ev, ok=("accepted", "voided")):
        r = self.t.accept(ev)
        assert r.status in ok, (self.name, ev["kind"], r.status, r.reason)
        self.evs.append(ev)
        return event_id(ev)

    def refuse(self, why, ev):
        r = self.t.accept(ev)
        assert r.status == "rejected", (self.name, why, r.status)
        self.rejects.append({"why": why, "event": ev, "status": r.status})

    def write(self, out: Path):
        d = out / self.name
        d.mkdir(parents=True, exist_ok=True)
        evs = list(self.evs)
        random.Random(self.name).shuffle(evs)
        (d / "events.jsonl").write_bytes(b"".join(canon.dumps(e) + b"\n" for e in evs))
        (d / "expected.json").write_text(json.dumps(summary(self.t), indent=1, sort_keys=True) + "\n")
        (d / "reject.json").write_text(json.dumps(self.rejects, indent=1, sort_keys=True) + "\n")


def rejects_for(s: Scn):
    """Events a format-1 thread must refuse, whatever release reads them."""
    o, sa = s.i["owner"], s.i["sansa"]
    base = s.w("sansa").post("base for the reject list")
    ok = s.add(base)
    p = s.w("sansa").post("probe")
    s.refuse("v 2 inside a v 1 thread", resign(sa, p, v=2))
    s.refuse("v 3", resign(sa, p, v=3))
    s.refuse("v is a boolean", resign(sa, p, v=True))
    s.refuse("unknown kind x-reaction.1 at v 1", resign(sa, p, kind="x-reaction.1"))
    s.refuse("unknown kind", resign(sa, p, kind="reaction"))
    s.refuse("extra body key x on a post", resign(sa, p, body={"text": "t", "x": {"a": 1}}))
    s.refuse("extra body key on a post", resign(sa, p, body={"text": "t", "extra": 1}))
    s.refuse("guest field from a member", resign(sa, p, body={"text": "t", "guest": {"name": "g", "sign": "00" * 32, "kex": "00" * 32}}))
    s.refuse("extra field of the event", {**p, "extra": 1})
    s.refuse("a signature of the wrong key", resign(s.i["carol"], p))
    s.refuse("a parent that is not 32 hex", resign(sa, p, parents=["zz"]))
    s.refuse("a negative seq", resign(sa, p, seq=-1))
    add = s.w("owner").add_member(s.i["eve"], "member")
    s.refuse("member_add with an extra body key", resign(o, add, body={**add["body"], "x": {}}))
    s.refuse("a second genesis", s.g if False else make_genesis(o, "second", []))
    return ok


def build(out: Path):
    # 1. basic traffic: posts, replies, a digest, refs, `to`
    s = Scn("basic")
    a = s.add(s.w("sansa").post("hello"))
    b = s.add(s.w("owner").post("hi back", reply_to=a))
    s.add(s.w("carol").post("third voice", reply_to=b))
    s.add(s.w("owner").post("to sansa", to=[s.i["sansa"].id]))
    s.add(s.w("sansa").post("a file", refs=[{"kind": "file", "cid": "sha256:" + "ab" * 32, "size": 12}]))
    s.add(s.w("owner").event("digest", {"text": "summary so far", "covers": [a, b], "pinned": True}))
    for n in range(6):
        s.add(s.w("sansa" if n % 2 else "owner").post(f"more {n}"))
    rejects_for(s)
    s.write(out)

    # 2. membership: add, remove with a cut, a late event of the removed member, self revoke
    s = Scn("membership")
    s.add(s.w("sansa").post("before"))
    s.add(s.w("owner").add_member(s.i["eve"], "member"))
    e1 = s.add(s.w("eve").post("eve speaks"))
    s.add(s.w("eve").post("eve again"))
    s.add(s.w("owner").admin("member_remove", {"agent": s.i["eve"].id}))
    s.add(s.w("carol").post("after the removal"))
    s.add(s.w("carol").admin("revoke", {"agent": s.i["carol"].id}))
    s.write(out)

    # 3. rules and checkpoints
    s = Scn("rules_checkpoints")
    s.add(s.w("sansa").post("one"))
    s.add(s.w("owner").admin("rules_update", {"rules": {"posts_per_author_per_hour": 30, "max_members": 8}}))
    s.add(s.w("owner").admin("checkpoint", {"count": 2, "heads": s.t.tips(), "epoch": 0}))
    s.add(s.w("sansa").post("two"))
    s.add(s.w("owner").admin("checkpoint", {"count": 3, "heads": s.t.tips(), "epoch": 0}))
    s.write(out)

    # 4. admin threshold 2: cosigned admin events and a close with a cut
    s = Scn("threshold2", k=2)
    s.add(s.w("owner").add_member(s.i["eve"], "member"))
    s.add(s.w("eve").post("x"))
    s.add(s.w("sansa").post("y"))
    s.add(s.w("owner").admin("rules_update", {"rules": {"posts_per_author_per_hour": 40}}))
    s.add(s.w("owner").admin("close", {}))
    s.write(out)

    # 5. forks: two competing admin events on one prev_admin, an equivocating author
    s = Scn("forks")
    s.add(s.w("sansa").post("start"))
    fa = s.w("owner").add_member(s.i["eve"], "member", ts=100)
    fb = s.w("owner").admin("rules_update", {"rules": {"posts_per_author_per_hour": 20}}, ts=101)
    s.add(fa)
    s.add(fb, ok=("accepted", "voided", "conflict"))      # (the losing branch of the fork is reported as a conflict; both are in the file)
    pa = s.w("carol").post("equivocation A", ts=200)
    pb = E.make_event(s.i["carol"], thread=s.t.id, kind="post", body={"text": "equivocation B"}, parents=pa["parents"], seq=pa["seq"], admin_ref=pa["admin_ref"], ts=201)
    s.add(pa)
    s.t.accept(pb)
    s.evs.append(pb)
    s.write(out)

    # 6. ownership: transfer, then a takeover on a second thread
    s = Scn("transfer")
    s.add(s.w("owner").admin("owner_transfer", {"new_owner": s.i["sansa"].id}, cosigners=[s.i["sansa"]], epoch_delta=1))
    s.add(s.w("sansa").post("now I own it"))
    s.write(out)
    s = Scn("takeover", k=2, successors=("sansa",))
    s.add(s.w("sansa").admin("owner_takeover", {"last_checkpoint": s.t.id}, cosigners=[s.i["carol"]], epoch_delta=1))
    s.add(s.w("carol").post("after the takeover"))
    s.write(out)


if __name__ == "__main__":
    build(Path(sys.argv[1]))
