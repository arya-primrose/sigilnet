"""The node's blob worker: serves the want queue (blobwant.py). Every few seconds, if requests are pending and no pass is running, one pass runs in a worker thread
(it uses the network): for each request, the peers that share the thread (the node's own plan) are tried in random order through blobfetch; the outcome goes to
the status file. A blob that is already held counts as done. Nothing here is ever triggered by an event: only by a `blob get` on this machine."""
from __future__ import annotations

import random
import threading
import time

from . import blobfetch as F
from .carrier import CarrierError
from .keys import is_hex


class BlobWorker:
    EVERY = 3.0

    def __init__(self, node, store, index, wants, me, out=lambda s: None, *, clock=time.time, rng=None, fetch=F.fetch):
        self.node, self.store, self.index, self.wants, self.me, self.out, self.clock = node, store, index, wants, me, out, clock
        self.rng = rng or random.Random()
        self.fetch = fetch
        self.bans: set = set()
        self.last = 0.0
        self.busy = threading.Event()

    def tick(self) -> None:
        now = self.clock()
        if now - self.last < self.EVERY or self.busy.is_set():
            return
        self.last = now
        if not self.wants.pending():
            return
        self.busy.set()
        threading.Thread(target=self.run_once, daemon=True).start()

    def run_once(self) -> None:
        try:
            for w in self.wants.pending():
                self._one(w["thread"], w["cid"])
        except Exception as e:                                     # noqa: BLE001 - a bad request must not stop the node
            self.out(f"  blob worker: {type(e).__name__}")
        finally:
            self.busy.clear()

    def _one(self, tid: str, cid: str) -> None:
        if self.store.has(cid):
            self.wants.finish(cid, True, "already held")
            return
        self.bans = {b for b in self.bans if b[1] != cid}          # a fresh want starts without the bans of an earlier one (they would otherwise last until restart)
        plan = self.node._plan()
        sources, skipped = [], []
        for aid, p in plan.items():
            if tid not in p["threads"]:
                continue
            try:
                sources.append(F.SignedSource(aid, self.node.transport_for(p["rec"]), self.me))
            except CarrierError as e:                              # a peer none of whose carriers is up (M1c) is skipped, not a reason to give the others up
                skipped.append((aid, str(e)))
        self.rng.shuffle(sources)
        if skipped:
            self.out(f"  blob {cid[:19]}..: {len(skipped)} peer(s) skipped ({skipped[0][1]})")
        if not sources:
            self.wants.finish(cid, False, f"no carrier up for any peer that shares this thread ({skipped[0][1]})" if skipped else "no peer shares this thread (add one with `peer add`)")
            return
        res = self.fetch(self.node.m, self.store, self.index, tid, cid, sources, self.me, referenced=self.index.referenced(), bans=self.bans)
        self.wants.finish(cid, res["ok"], res.get("why", ""))
        self.out(f"  blob {cid[:19]}.. {'fetched' if res['ok'] else 'FAILED: ' + str(res.get('why'))} ({res.get('requests', 0)} request(s), {res.get('bytes', 0)} byte(s), {res.get('halvings', 0)} halved, slowest answer {res.get('ask_max', 0.0):.1f}s, {res.get('ask_secs', 0.0):.1f}s waiting)")
