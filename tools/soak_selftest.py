#!/usr/bin/env python3
"""`tools/soak.py --selftest [--minutes M]`: the WHOLE soak driver pair in ONE process, in compressed time and with NO Tor and no network at all: two throwaway homes whose "nodes" are
in-process stand-ins that sync over the existing in-memory Loopback transport (the real SyncServer / pull / fetch_keys / BlobService / BlobWorker code), a real encrypted private thread
with a raised posts-per-hour rule (the compressed traffic would hit the real 60/h limit), the real sigilnet CLI as subprocesses, the real fault schedule (term, kill -9 as a stop, tor kill as a no-op).
It ends with the end-of-run compare. Everything is created under a temp dir and deleted afterwards. Use it to review the driver before the real run."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
TREE = HERE.parent
sys.path.insert(0, str(TREE))
sys.path.insert(0, str(HERE))

import soak  # noqa: E402
from sigilnet import sync as S  # noqa: E402
from sigilnet.blobindex import BlobIndex  # noqa: E402
from sigilnet.blobserve import BlobService  # noqa: E402
from sigilnet.blobstore import BlobStore  # noqa: E402
from sigilnet.blobwant import Wants  # noqa: E402
from sigilnet.blobworker import BlobWorker  # noqa: E402
from sigilnet.build import make_genesis  # noqa: E402
from sigilnet.envelope import EnvCodec  # noqa: E402
from sigilnet.event import event_id  # noqa: E402
from sigilnet.keys import Identity  # noqa: E402
from sigilnet.mirror import Mirror  # noqa: E402
from sigilnet.thread import default_rules  # noqa: E402


class FakeNode:
    """Stands in for `node run`: a loop that refreshes the mirror, pulls from the peer stand-in (and its keys) and ticks the blob worker. stop() makes it unreachable like a dead node."""

    def __init__(self, home: Path, ident, tid: str, log: Path):
        self.home, self.ident, self.tid, self.log = home, ident, tid, log
        Path(log).write_text("")
        self.m = Mirror(home / "mirror", codec=EnvCodec(home / "keys"), rate_limit=False)
        self.store = BlobStore(home / "blobs")
        self.index = BlobIndex(self.m)
        self.svc = BlobService(self.store, self.index)
        self.srv = S.SyncServer(self.m, identity=ident, blobs=self.svc)
        self.peer = None
        self.up, self.starts, self.proc = False, 0, None
        self._stop = threading.Event()
        self.thread = None
        node = self
        outer = types.SimpleNamespace(m=self.m)
        outer._plan = lambda: {node.peer.ident.id: {"rec": {}, "threads": {tid}}} if node.peer else {}
        outer.transport_for = lambda rec: node.peer_transport()
        self.worker = BlobWorker(outer, self.store, self.index, Wants(home / "blobs"), ident, lambda s: None)

    def peer_transport(self):
        peer = self.peer

        class Tr:
            def request(self, req):
                if not peer.up:
                    raise ConnectionError("peer node is down")
                return S.Loopback(peer.srv).request(req)
        return Tr()

    def start(self):
        self.up = True
        self.starts += 1
        if self.thread is None or not self.thread.is_alive():
            self._stop.clear()
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()

    def stop(self, sig=None, wait=0):
        self.up = False

    def alive(self):
        return self.up

    @property
    def pid(self):
        return os.getpid()

    def running_elsewhere(self):
        return False

    def kill_tor(self):
        return None

    def tor_pid(self):
        return None

    def close(self):
        self._stop.set()

    def pull_once(self):
        self.m.refresh()
        tr, kw = self.peer_transport(), {"peer_id": self.peer.ident.id}
        r = S.pull(self.m, self.tid, tr, self.ident, **kw)
        if r.get("need_keys"):
            S.fetch_keys(self.m, self.tid, tr, self.ident, need=r["need_keys"], unopened=r["unopened"], **kw)
            S.pull(self.m, self.tid, tr, self.ident, **kw)

    def _loop(self):
        while not self._stop.is_set():
            if self.up and self.peer is not None:
                try:
                    self.pull_once()
                    self.worker.tick()
                except Exception:          # noqa: BLE001 - a failed pull is normal while the peer is "down"
                    pass
            time.sleep(1.0)


def run(minutes: float = 10.0, seed="1", keep: bool = False) -> int:
    root = Path(tempfile.mkdtemp(prefix="soak_selftest_"))
    os.umask(0o077)
    try:
        k = minutes * 60.0 / (6 * 3600.0 + 600.0)
        cfg = soak.Cfg(k)
        ids = {s: Identity.generate(s) for s in ("arya", "sansa")}
        homes = {s: root / f"home_{s}" for s in ids}
        for s, h in homes.items():
            h.mkdir(mode=0o700)
            ids[s].save(h / "identity.json")
        rules = {**default_rules(), "posts_per_author_per_hour": 10000}
        g = make_genesis(ids["arya"], "soak-selftest", [(ids["sansa"], "member")], rules=rules)
        tid = event_id(g)
        for s, h in homes.items():
            Mirror(h / "mirror", codec=EnvCodec(h / "keys"), rate_limit=False).ingest(g)
        Mirror(homes["arya"] / "mirror", codec=EnvCodec(homes["arya"] / "keys"), rate_limit=False).enable_encryption(tid, ids["arya"])
        nodes = {s: FakeNode(homes[s], ids[s], tid, root / f"node_{s}.log") for s in ids}
        nodes["arya"].peer, nodes["sansa"].peer = nodes["sansa"], nodes["arya"]
        nodes["arya"].up = True
        assert soak.Cli(TREE, homes["arya"]).run("post", tid, "seed event so the joiner learns the thread is encrypted")[0] == 0
        nodes["sansa"].pull_once()          # the joiner holds the thread's keys BEFORE it posts (what the capsule join guarantees: the keys arrive with an envelope or in the signed join answer); without them its first posts would be stored as local PLAINTEXT events that sync never serves (found by this selftest, see README)
        drivers, results = {}, {}
        for s, other in (("arya", "sansa"), ("sansa", "arya")):
            a = types.SimpleNamespace(tree=str(TREE), home=str(homes[s]), side=s, peer_id=ids[other].id, thread=tid, out=str(root / f"out_{s}"), hours=6.0, seed=seed, preflight=True)
            drivers[s] = soak.Driver(a, soak.Cli(TREE, homes[s]), nodes[s], cfg, out=lambda text: None)
        t0 = time.time()
        threads = {s: threading.Thread(target=lambda s=s: results.__setitem__(s, drivers[s].run())) for s in drivers}
        for t in threads.values():
            t.start()
        for t in threads.values():
            t.join()
        for n in nodes.values():
            n.close()
        sm = {s: json.loads((root / f"out_{s}" / "summary.json").read_text()) for s in drivers}
        checks = [("both drivers exited 0", results == {"arya": 0, "sansa": 0}),
                  ("event sets identical", sm["arya"]["event_set_sha256"] == sm["sansa"]["event_set_sha256"] and sm["arya"]["events"] == sm["sansa"]["events"]),
                  ("verify clean on both", all(x["verify_rc"] == 0 for x in sm.values())),
                  ("every peer post seen (arya)", sm["arya"]["peer_posts_seen"] == sm["sansa"]["sent"]["post"]),
                  ("every peer post seen (sansa)", sm["sansa"]["peer_posts_seen"] == sm["arya"]["sent"]["post"]),
                  ("every blob fetched and verified", sm["arya"]["blobs_ok"] == sm["sansa"]["sent"]["blob"] and sm["sansa"]["blobs_ok"] == sm["arya"]["sent"]["blob"] and sm["arya"]["blobs_bad"] == sm["sansa"]["blobs_bad"] == 0),
                  ("asks answered (both sides)", sm["arya"]["asks_answered_wake"] >= 1 and sm["sansa"]["asks_answered_wake"] >= 1),
                  ("faults ran (sansa term + kill9, arya torkill + term)", sm["sansa"]["restarts"] >= 2 and sm["arya"]["restarts"] >= 1 and len(sm["sansa"]["faults"]) == 2 and len(sm["arya"]["faults"]) == 2),
                  ("no marker on disk, no duplicates, no gaps", all(x["markers_on_disk"] == 0 and not x["dups"] and not x["gaps"] for x in sm.values()))]
        print(f"selftest: {minutes:.1f} min budget, ran {time.time() - t0:.0f} s, k={k:.4f}; sent arya={sm['arya']['sent']} sansa={sm['sansa']['sent']}")
        for name, ok in checks:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not all(ok for _, ok in checks):
            for s, x in sm.items():
                print(s, json.dumps({k2: x[k2] for k2 in ("reason", "latency_s", "asks_answered_wake", "blobs_ok", "blobs_bad", "restarts", "faults", "cli_hangs")}))
        return 0 if all(ok for _, ok in checks) else 1
    finally:
        if keep:
            print("kept", root)
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run(float(sys.argv[1]) if len(sys.argv) > 1 else 10.0))
