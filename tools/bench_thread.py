"""Measure thread ingest cost at N events (DESIGN_retention.md section 2): python tools/bench_thread.py N [N ...]
For each N: cold load (add_many), the next ordinary post, an admin event (member_add), the Thread's memory, the size on disk.
Lifts MAX_STORED so N may exceed the wall. Set BENCH_PKG_ROOT to run against a copy of the package."""
import os, sys, time
sys.path.insert(0, os.environ.get("BENCH_PKG_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from sigilnet import event as E
from sigilnet import thread as T
from sigilnet.build import Writer
from sigilnet.event import event_id
from sigilnet.tests.util import World
from sigilnet.thread import Thread

T.MAX_STORED = 10 ** 7
RULES = {"max_event_bytes": 16384, "posts_per_author_per_hour": 10000, "max_members": 16, "checkpoint_every": 50,
         "owner_silence_hours": 72, "retention": "forever"}


def rss_mb():
    return int(open("/proc/self/statm").read().split()[1]) * 4096 / 1e6


def build(n):
    w = World(rules=RULES)
    names = ["arya", "sansa", "carol"]
    seq = {x: 0 for x in names}
    evs, prev = [], list(w.t.tips())
    for i in range(n):
        who = names[i % 3]
        ev = E.make_event(w.ids[who], thread=w.t.id, kind="post", body={"text": "m%d " % i + "x" * 200}, parents=prev, seq=seq[who],
                          admin_ref=w.t.head, ts=1_700_000_000 + i)
        seq[who] += 1
        evs.append(ev)
        prev = [event_id(ev)]
    return w, evs


for n in map(int, sys.argv[1:] or ["5000"]):
    w, evs = build(n)
    r0 = rss_mb()
    t = Thread(w.genesis)
    s = time.perf_counter(); t.add_many(evs); cold = time.perf_counter() - s
    nxt = E.make_event(w.ids["arya"], thread=t.id, kind="post", body={"text": "next"}, parents=[event_id(evs[-1])], seq=n, admin_ref=t.head,
                       ts=1_700_000_000 + n + 1)
    s = time.perf_counter(); t.accept(nxt); post = time.perf_counter() - s
    adm = Writer(w.ids["arya"], t).add_member(w.ids["eve"], "member")
    s = time.perf_counter(); r = t.accept(adm); admin = time.perf_counter() - s
    disk = sum(len(E.encode(e)) for e in evs[:1000]) / min(1000, n) * n / 1e6
    print(f"N={n}: cold load {cold:.2f}s, next post {post*1000:.2f} ms, member_add {admin:.2f}s ({r.status}), thread RSS +{rss_mb()-r0:.0f} MB, events.jsonl ~{disk:.0f} MB", flush=True)
