#!/usr/bin/env python3
"""tcp_bench.py: request round-trip numbers over the sigilnet TCP carrier (live test 4, phase P8). It dials the ONE peer endpoint stored in HOME's peers.json (the
credential is the one the join installed in HOME/tcp/held.json) and sends N signed `summary` requests (the cheapest valid sync request), timing each:
  conn  = TCP connect + TLS 1.3 + pin check + hello + admission   (everything the carrier adds before the first protocol byte)
  total = conn + request + response
It opens NO other socket: the endpoint must be an allowed container IP (default 127.0.0.1; pass --allow-ip for each other host) on a port in 47600-47799, else it refuses to start.
Optional --pid PID: reads that node's CPU time and RSS from /proc before and after. Output: one JSON line (and --csv FILE with every sample)."""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sigilnet import noderun                                   # noqa: E402
from sigilnet.cli import _identity                             # noqa: E402
from sigilnet.node import PeerBook                             # noqa: E402
from sigilnet.sync import sign_request                         # noqa: E402
from sigilnet import tcplink                                   # noqa: E402


def proc_stats(pid: int):
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        ticks = int(st[11]) + int(st[12])
        rss = next(int(x.split()[1]) for x in open(f"/proc/{pid}/status") if x.startswith("VmRSS:"))
        return {"cpu_s": ticks / os.sysconf("SC_CLK_TCK"), "rss_kb": rss}
    except (OSError, ValueError, StopIteration, IndexError):
        return None


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def summarize(xs):
    return {"n": len(xs), "min_ms": round(min(xs) * 1000, 2), "median_ms": round(statistics.median(xs) * 1000, 2), "p95_ms": round(pct(xs, 95) * 1000, 2),
            "p99_ms": round(pct(xs, 99) * 1000, 2), "max_ms": round(max(xs) * 1000, 2)} if xs else {"n": 0}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True)
    ap.add_argument("--thread", required=True, help="32 hex: the thread to ask `summary` about (we must be a member)")
    ap.add_argument("--peer", required=True, help="the peer's agent id (a key of peers.json)")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--allow-ip", action="append", default=["127.0.0.1"])
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--csv")
    a = ap.parse_args(argv)
    if not 1 <= a.n <= 2000:
        sys.exit("--n must be 1..2000")
    home = Path(a.home)
    cfg = noderun.load_config(home)
    if cfg.get("carrier") != "tcp":
        sys.exit("this home is not configured for the tcp carrier")
    peer = PeerBook(home / "peers.json").all().get(a.peer)
    if not peer or not peer["endpoint"] or peer["endpoint"]["type"] != "tcp":
        sys.exit("no tcp endpoint for that peer in peers.json")
    ep = peer["endpoint"]
    ip, port, _ = tcplink._split_addr(ep["addr"])
    if ip not in a.allow_ip or not 47600 <= port <= 47799:
        sys.exit(f"refusing to dial {ip}:{port}: not an allowed container IP on ports 47600-47799")
    me = _identity(home)
    carrier = noderun.make_carrier(home, cfg)                    # not started: it only dials
    tr = carrier.dial(ep, timeout=10)
    conn_t = []
    orig = tr._connect

    def timed(end):
        t = time.time()
        try:
            return orig(end)
        finally:
            conn_t.append(time.time() - t)
    tr._connect = timed
    before = proc_stats(a.pid) if a.pid else None
    totals, errors, rows = [], 0, []
    for i in range(a.n):
        req = sign_request(me, {"t": "summary", "thread": a.thread}, ts=int(time.time()), aud=a.peer)
        t0 = time.time()
        try:
            resp = tr.request(req)
            ok = isinstance(resp, dict) and resp.get("t") in ("summary", "unknown", "error")
        except Exception as e:                                   # noqa: BLE001 - count it, keep measuring
            ok, resp = False, {"err": type(e).__name__}
        dt = time.time() - t0
        if not ok:
            errors += 1
            continue
        totals.append(dt)
        rows.append((i, round(conn_t[-1] * 1000, 3), round(dt * 1000, 3), resp.get("t")))
    after = proc_stats(a.pid) if a.pid else None
    out = {"peer_endpoint": ep["addr"].split("#")[0], "requests": a.n, "errors": errors, "total": summarize(totals),
           "conn": summarize([r[1] / 1000 for r in rows]), "node_before": before, "node_after": after}
    print(json.dumps(out))
    if a.csv:
        Path(a.csv).write_text("i,conn_ms,total_ms,answer\n" + "\n".join(",".join(map(str, r)) for r in rows) + "\n")
    return 0 if errors == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
