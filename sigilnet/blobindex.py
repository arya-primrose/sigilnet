"""Which blobs do the events of a mirror reference? (DESIGN_blobs.md rev 1, finding 4: no per-request event scan.)

An event's refs are immutable, so they are read once per event id and memoised per thread. A thread's cid -> events map is rebuilt only when the set of events
changed: Thread either reassigns `events` on re-derivation (the cache holds the old object, so the identity test cannot be fooled by address reuse) or adds to
it in place (the length test). Voiding is NOT part of that key: a lookup checks the CURRENT void set, so a voided referrer stops serving at once.

  live(tid, cid)     declared sizes from resolved, NON-voided events of that thread that reference cid ([] = not servable: unknown, unreferenced, voided only)
  referenced()       cids named by any live OR voided event of any thread (what GC must keep; a reorg can revive a voided event)
  servable_in(cid)   thread ids in which cid is live
Awaiting (not yet admitted) and parked events never count."""
from __future__ import annotations

import threading

from . import blob as B


def _refs_of(ev) -> tuple:
    body = ev.get("body") if isinstance(ev, dict) else None
    if not isinstance(body, dict) or ev.get("kind") != "post":
        return ()
    out = []
    for r in body.get("refs") or ():
        try:
            if r["kind"] == "file":
                out.append((B.check_cid(r["cid"]), r["size"]))
        except (B.BlobError, KeyError, TypeError):
            continue
    return tuple(out)


class BlobIndex:
    def __init__(self, mirror):
        self.mirror = mirror
        self._mu = threading.RLock()             # the node's loop (GC), the serve threads and the CLI worker share one index
        self._memo: dict = {}                    # tid -> {eid: refs tuple}
        self._cache: dict = {}                   # tid -> (events obj, void obj, {cid: [(eid, size)]}, len(events))

    def _by_cid(self, tid: str):
        t = self.mirror.threads.get(tid)
        if t is None:
            self._cache.pop(tid, None)
            self._memo.pop(tid, None)
            return None, None
        hit = self._cache.get(tid)
        if hit is not None and hit[0] is t.events and hit[3] == len(t.events):
            return t, hit[2]
        memo = self._memo.setdefault(tid, {})
        events, void = t.events, t.void_ids
        by: dict = {}
        for eid, ev in list(events.items()):
            r = memo.get(eid)
            if r is None:
                r = memo[eid] = _refs_of(ev)
            for cid, size in r:
                by.setdefault(cid, []).append((eid, size))
        for eid in [e for e in memo if e not in events]:
            del memo[eid]
        self._cache[tid] = (events, void, by, len(events))
        return t, by

    def live(self, tid: str, cid) -> list:
        with self._mu:
            return self._live_locked(tid, cid)

    def _live_locked(self, tid: str, cid) -> list:
        try:
            B.check_cid(cid)
        except B.BlobError:
            return []
        t, by = self._by_cid(tid)
        if t is None:
            return []
        return sorted({size for eid, size in by.get(cid, ()) if eid in t.events and eid not in t.void_ids})

    def refs(self, tid: str) -> dict:
        """{cid: sorted declared sizes} of the LIVE references of one thread (what `blob ls` offers)."""
        with self._mu:
            return self._refs_locked(tid)

    def _refs_locked(self, tid: str) -> dict:
        t, by = self._by_cid(tid)
        if t is None:
            return {}
        out = {}
        for cid, l in by.items():
            sizes = sorted({size for eid, size in l if eid in t.events and eid not in t.void_ids})
            if sizes:
                out[cid] = sizes
        return out

    def referenced(self) -> set:
        with self._mu:
            return self._referenced_locked()

    def _referenced_locked(self) -> set:
        out = set()
        for tid in list(self.mirror.threads):
            t, by = self._by_cid(tid)
            if t is not None:
                out.update(by)
        return out

    def servable_in(self, cid) -> list:
        with self._mu:
            return self._servable_in_locked(cid)

    def _servable_in_locked(self, cid) -> list:
        return [tid for tid in list(self.mirror.threads) if self.live(tid, cid)]
