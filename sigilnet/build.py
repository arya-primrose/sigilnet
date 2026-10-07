"""Convenience builders for signed events (used by the CLI and by tests). They only construct; Thread/Mirror decide validity."""
from __future__ import annotations

from . import event as E
from .keys import Identity
from .thread import Thread, default_guest_policy, default_rules


def make_genesis(owner: Identity, title: str, others=(), *, visibility="private", successors=(), rules=None, guest_policy=None,
                 k=1, ts=None, fmt: int = 1) -> dict:
    """others: iterable of (Identity, role). The owner is added with role "owner". `fmt` is the thread's format (the genesis `v`, constant for the thread's life)."""
    people = [(owner, "owner")] + [(i, r) for i, r in others]
    body = {"title": title, "owner": owner.id,
            "keys": {i.id: {"sign": i.sign_pub, "kex": i.kex_pub} for i, _ in people},
            "members": [{"id": i.id, "name": i.name or i.id[:8], "role": r} for i, r in people],
            "successors": list(successors), "rules": rules or default_rules(), "visibility": visibility,
            "guest_policy": guest_policy or default_guest_policy(), "admin_threshold": {"k": k}, "owner_epoch": 0, "epoch": 0}
    return E.make_event(owner, thread="", kind="genesis", body=body, parents=[], seq=0, admin_ref="", ts=ts, v=fmt)


class Writer:
    """Builds the next event for `identity` in `thread`: correct seq, admin_ref, parents and prev_admin filled in."""

    def __init__(self, identity: Identity, thread: Thread, cosigners=()):
        self.i, self.t, self.cosigners = identity, thread, list(cosigners)     # default co-signers for k-signature admin events

    def _seq(self) -> int:
        mine = [s for (a, s) in list(self.t.by_author_seq) + list(self.t._seq_all) if a == self.i.id]     # equivocated / waiting seqs are taken too
        return (max(mine) + 1) if mine else 0

    def post(self, text: str, reply_to: str | None = None, *, parents=None, ts=None, **extra) -> dict:
        body = {"text": text, **extra}
        if reply_to:
            body["reply_to"] = reply_to
            parents = list(parents or []) + [reply_to]
        return E.make_event(self.i, thread=self.t.id, kind="post", body=body, parents=parents or self.t.tips(), seq=self._seq(),
                            admin_ref=self.t.head, ts=ts, v=self.t.format)

    def event(self, kind: str, body: dict, *, parents=None, ts=None, admin_ref=None) -> dict:
        return E.make_event(self.i, thread=self.t.id, kind=kind, body=body, parents=parents or self.t.tips(), seq=self._seq(),
                            admin_ref=admin_ref or self.t.head, ts=ts, v=self.t.format)

    def ext(self, name: str, body: dict, *, parents=None, ts=None) -> dict:
        """An extension event (format 2 threads only): kind `x-<name>`; this release stores and relays it and never interprets it."""
        return self.event("x-" + name, body, parents=parents, ts=ts)

    def _last_seq(self, agent: str) -> int:
        seqs = [s for (a, s) in self.t.by_author_seq if a == agent]
        return max(seqs) if seqs else -1

    def admin(self, kind: str, body: dict, *, cosigners=(), ts=None, epoch_delta=0) -> dict:
        """Fills prev_admin/owner_epoch, and the cut a removal or a close must carry (the last seq seen per author) unless given."""
        st = self.t.state()
        body = dict(body)
        if kind in ("member_remove", "revoke") and "last_seq" not in body and "agent" in body:
            body["last_seq"] = self._last_seq(body["agent"])
            gaps = [g for g in self.t.missing_seqs(body["agent"]) if g < body["last_seq"]][:64]
            if gaps:
                body["missing"] = gaps
        if kind == "close" and "cut" not in body:
            body["cut"] = {a: self._last_seq(a) for a in {a for (a, _) in self.t.by_author_seq}}
            gaps = {a: [g for g in self.t.missing_seqs(a) if g < body["cut"][a]][:64] for a in body["cut"]}
            gaps = {a: g for a, g in gaps.items() if g}
            if gaps:
                body["cut_missing"] = gaps
        if not cosigners and self.cosigners and kind in ("member_add", "member_remove", "rules_update", "owner_transfer", "close") and st["admin_threshold"] > 1:
            cosigners = [c for c in self.cosigners if c.id != self.i.id]
        b = {"prev_admin": self.t.head, "owner_epoch": st["owner_epoch"] + epoch_delta, **body}
        ev = E.make_event(self.i, thread=self.t.id, kind=kind, body=b, parents=self.t.tips(), seq=self._seq(), admin_ref=self.t.head, ts=ts, v=self.t.format)
        for c in cosigners:
            ev = E.add_cosig(ev, c)
        return ev

    def add_member(self, who: Identity, role="member", *, admits=(), cosigners=(), ts=None) -> dict:
        body = {"agent": who.id, "name": who.name or who.id[:8], "role": role, "sign": who.sign_pub, "kex": who.kex_pub}
        if admits:
            body["admits"] = sorted(admits)
        return self.admin("member_add", body, cosigners=cosigners, ts=ts)

    def guest_request(self, text: str, reply_to: str, *, ts=None, seq: int | None = None) -> dict:
        """A stranger's fully signed post asking to be admitted (spec 5.1): carries the guest's own keys in the body."""
        guest = {"name": self.i.name or self.i.id[:8], "sign": self.i.sign_pub, "kex": self.i.kex_pub}
        return E.make_event(self.i, thread=self.t.id, kind="post", body={"text": text, "reply_to": reply_to, "guest": guest},
                            parents=[reply_to], seq=self._seq() if seq is None else seq, admin_ref=self.t.head, ts=ts, v=self.t.format)
