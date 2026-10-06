#!/usr/bin/env python3
"""One side of the sigilnet SOAK TEST (DESIGN_soak.md, rev 1). Starts and owns the node of ONE home, posts on a seeded schedule, answers the peer's soak-asks, fetches the peer's blobs,
measures latency / resources, injects the faults, checks the stop conditions and writes CSV/JSON results. It runs only the sigilnet CLI of its own home (subprocess, list argv, never a
shell, every call under a timeout) and reads /proc: it opens NO sockets and writes only under --out (a 0700 directory OUTSIDE the home, files 0600, containing counts, ids and timings but
no event text and no key material). Peer text never reaches a command line, a shell or a file name: the driver acts only on 8-hex ids and integers it parsed with fixed regexes.

usage: tools/soak.py --tree DIR --home DIR --side arya|sansa --peer-id AGENT --thread THREAD_ID --out DIR [--hours 6] [--seed 1]    |    tools/soak.py --selftest [--minutes 10]
The home must already be initialised and joined to the thread (the capsule flow stays manual); stop any node of it first: this driver starts its own."""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import math
import os
import random
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

MARK = "SOAKMARK-"
TEXT_RE = re.compile(r"^soak (arya|sansa) #(\d+) ts=(\d+\.\d) (?:skip=(\d+(?:,\d+){0,19}) )?(?:sha=([0-9a-f]{64}) size=(\d+) )?(SOAKMARK-[0-9a-f]{16})")
ASK_RE = re.compile(r"^\[ASK\] soak-ask (arya|sansa) #(\d+) ts=(\d+\.\d) (SOAKMARK-[0-9a-f]{16})")
ANS_RE = re.compile(r"^\[DONE\] soak-answer (arya|sansa) re #(\d+) ts=(\d+\.\d) (SOAKMARK-[0-9a-f]{16})")
LINE_RE = re.compile(r"^\[([0-9a-f]{8})\] (.*?) \(([a-z_]+)\): (.*)$")
BLOB_N0 = 10 ** 6                       # blob posts are numbered from here so they never look like gaps in the plain post sequence
BLOB_MIN, BLOB_MAX = 64 * 1024, 2 * 1024 * 1024
RSS_LIMIT_KB, RSS_GROWTH_KB, HOME_LIMIT = 800 * 1024, 300 * 1024, 1 << 30
FAULTS = {"sansa": [(2.0, "term"), (5.0, "kill9")], "arya": [(3.0, "torkill"), (4.0, "term")]}     # (hours, kind): SIGTERM restart, SIGKILL crash, kill -9 of ONLY the tor child


@dataclass
class Cfg:
    """All the time constants; k < 1 compresses time (selftest only: k = 1/30 runs 6 h in 12 min)."""
    k: float = 1.0

    def s(self, seconds: float) -> float:
        return seconds * self.k

    @property
    def post_mean(self): return self.s(300.0)
    @property
    def post_min(self): return self.s(30.0)
    @property
    def ask_every(self): return self.s(1800.0)
    @property
    def blob_every(self): return self.s(3600.0)
    @property
    def sample_every(self): return self.s(600.0)
    @property
    def marker_every(self): return self.s(3600.0)
    @property
    def poll_every(self): return max(1.5, self.s(10.0))
    @property
    def fault_down(self): return self.s(180.0)
    @property
    def drain(self): return self.s(600.0)
    @property
    def gap_seconds(self): return self.s(1800.0)
    @property
    def silence_seconds(self): return self.s(2400.0)
    @property
    def bucket_per_hour(self): return 40.0 / self.k       # own posts/asks/answers/blobs: well under posts_per_author_per_hour = 60


# ------------------------------------------------------------------ pure helpers
def schedule(seed, side: str, hours: float, cfg: Cfg | None = None) -> list:
    """[(offset seconds, kind, arg)] sorted: post / ask / blob / sample / marker / fault. Deterministic for (seed, side, hours, cfg)."""
    cfg = cfg or Cfg()
    rng = random.Random(f"{seed}:{side}")
    end, ev = hours * 3600.0 * cfg.k, []
    t = rng.uniform(cfg.s(10), cfg.s(60))
    while t < end:
        ev.append((t, "post", None))
        t += max(cfg.post_min, rng.expovariate(1.0 / cfg.post_mean))
    t = cfg.s(900.0) + rng.uniform(0, cfg.s(120))
    while t < end:
        ev.append((t, "ask", None))
        t += cfg.ask_every + rng.uniform(-cfg.s(300), cfg.s(300))
    t = cfg.s(1800.0) + rng.uniform(0, cfg.s(120))
    while t < end:
        ev.append((t, "blob", int(math.exp(rng.uniform(math.log(BLOB_MIN), math.log(BLOB_MAX))))))
        t += cfg.blob_every + rng.uniform(-cfg.s(300), cfg.s(300))
    for t in _every(cfg.sample_every, end):
        ev.append((t, "sample", None))
    for t in _every(cfg.marker_every, end):
        ev.append((t, "marker", None))
    for h, kind in FAULTS.get(side, []):
        if cfg.s(h * 3600.0) < end - cfg.s(1800.0):
            ev.append((cfg.s(h * 3600.0), "fault", kind))
    return sorted(ev, key=lambda e: (e[0], e[1]))


def _every(step: float, end: float):
    t = step
    while t < end:
        yield t
        t += step


class TokenBucket:
    """At most `per_hour` takes per hour (burst `burst`): the driver's own posts must stay far below posts_per_author_per_hour."""

    def __init__(self, per_hour: float, burst: int = 5, clock=time.time):
        self.rate, self.burst, self.clock = per_hour / 3600.0, float(burst), clock
        self.tokens, self.t = float(burst), clock()

    def take(self) -> bool:
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


def make_text(side, n, ts, rng, sha=None, size=None, pad=2000, skips=()) -> str:
    """`skips` = numbers of my earlier posts whose delivery is unknown (the CLI call timed out): announced so the peer does not call them a gap."""
    sk = ("skip=" + ",".join(str(x) for x in list(skips)[-20:]) + " ") if skips else ""
    extra = f"sha={sha} size={size} " if sha else ""
    return f"soak {side} #{n} ts={ts:.1f} {sk}{extra}{MARK}{rng.getrandbits(64):016x} " + "x" * rng.randint(0, pad)


def make_ask(side, n, ts, rng) -> str:
    return f"[ASK] soak-ask {side} #{n} ts={ts:.1f} {MARK}{rng.getrandbits(64):016x}"


def make_answer(side, n, ts, rng) -> str:
    return f"[DONE] soak-answer {side} re #{n} ts={ts:.1f} {MARK}{rng.getrandbits(64):016x}"


def parse_unread(out: str) -> list:
    """[{id8, kind, text}] from `unread` output; a line that does not parse is ignored (never trusted, never executed)."""
    rows = []
    for ln in out.splitlines():
        m = LINE_RE.match(ln)
        if not m:
            continue
        try:
            text = ast.literal_eval(m.group(4))
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            continue
        if isinstance(text, str):
            rows.append({"id8": m.group(1), "kind": m.group(3), "text": text})
    return rows


def classify(text: str, me: str):
    """('post'|'ask'|'ans'|None, regex groups) for a message from the PEER (side != me)."""
    for kind, rx in (("post", TEXT_RE), ("ask", ASK_RE), ("ans", ANS_RE)):
        m = rx.match(text)
        if m and m.group(1) != me:
            return kind, m.groups()
    return None, None


def percentile(xs, p: float):
    if not xs:
        return None
    s = sorted(xs)
    return s[min(len(s) - 1, max(0, int(math.ceil(p / 100.0 * len(s))) - 1))]


def stored_size(plain: int) -> int:
    return 50 + plain + 16 * max(1, -(-plain // 65536))


def register_post(seen: dict, n: int, now: float) -> bool:
    """Record the first-seen time of peer post #n. False when it was already seen (a duplicate delivery)."""
    if n in seen:
        return False
    seen[n] = now
    return True


def find_gaps(seen: dict, now: float, gap_seconds: float, skipped=()) -> list:
    """Numbers below the highest seen one that never arrived although the highest one arrived more than gap_seconds ago (numbers the peer announced as skipped are not gaps)."""
    if not seen:
        return []
    hi = max(seen)
    if now - seen[hi] <= gap_seconds:
        return []
    return [n for n in range(1, hi) if n not in seen and n not in skipped]


def latency_stats(xs) -> dict:
    return {"n": len(xs), **{f"p{p}": percentile(xs, p) for p in (50, 95, 99)}, "max": max(xs) if xs else None}


def check_stop(rss: list, home_bytes: int, markers_found: list, dups: list, gaps: list, blob_bad: int = 0) -> str | None:
    """A reason to stop, or None. rss = node RSS samples in kB, oldest first."""
    if markers_found:
        return f"plaintext marker found on disk ({len(markers_found)} file(s))"
    if dups:
        return f"a peer post was delivered twice: {dups[:3]}"
    if gaps:
        return f"event gap: peer posts {gaps[:5]} never arrived although later ones did"
    if blob_bad:
        return "a fetched blob did not match its sha256/size"
    if home_bytes > HOME_LIMIT:
        return f"home is {home_bytes} bytes (limit {HOME_LIMIT})"
    xs = [r for r in rss if r]
    if xs and xs[-1] > RSS_LIMIT_KB:
        return f"node RSS {xs[-1]} kB over the limit {RSS_LIMIT_KB}"
    if len(xs) > 12:
        base = sorted(xs[:6])[3]
        if xs[-1] - base > RSS_GROWTH_KB:
            return f"node RSS grew by {xs[-1] - base} kB over the first hour's median"
    return None


def clean_err(s: str) -> str:
    """CLI stderr made safe for our logs: printable ASCII only, 160 chars."""
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in s)[-160:]


# ------------------------------------------------------------------ process helpers
def proc_stats(pid: int) -> dict:
    out = {}
    try:
        for ln in Path(f"/proc/{pid}/status").read_text().splitlines():
            if ln.startswith("VmRSS:"):
                out["rss_kb"] = int(ln.split()[1])
            elif ln.startswith("Threads:"):
                out["threads"] = int(ln.split()[1])
        out["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    except (OSError, ValueError):
        pass
    return out


def find_tor(home: Path):
    want = f"{home}/tor/torrc".encode()
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                c = Path(f"/proc/{p}/cmdline").read_bytes().split(b"\0")
            except OSError:
                continue
            if c and c[0].endswith(b"tor") and want in c:
                return int(p)
    return None


def dir_bytes(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def marker_scan(paths) -> list:
    """Files under `paths` that contain the marker (grep -rlaF: binary-safe; -r never follows symlinks met while walking)."""
    found = []
    for p in paths:
        r = subprocess.run(["grep", "-rlaF", "--", MARK, os.path.realpath(p)], capture_output=True, text=True, timeout=900)
        found += [x for x in r.stdout.splitlines() if x]
    return found


class Cli:
    def __init__(self, tree: Path, home: Path):
        self.tree, self.home, self.hangs = Path(tree), Path(home), 0

    def argv(self, *args):
        return [sys.executable, "-B", "-m", "sigilnet", "--home", str(self.home), *args]

    def run(self, *args, timeout=180):
        """(rc, stdout, stderr); a call that outlives its timeout is killed and counted (rc 124): the driver carries on."""
        try:
            p = subprocess.run(self.argv(*args), capture_output=True, text=True, cwd=str(self.tree), timeout=timeout, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            self.hangs += 1
            return 124, "", "timeout"

    def spawn(self, *args):
        return subprocess.Popen(self.argv(*args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(self.tree), start_new_session=True,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))


class Node:
    """The real node: `sigilnet node run` as a child process of the driver."""

    def __init__(self, cli: Cli, log: Path, seconds: int):
        self.cli, self.log, self.seconds, self.proc, self.starts = cli, Path(log), seconds, None, 0

    def start(self):
        with open(self.log, "ab") as f:
            self.proc = subprocess.Popen(self.cli.argv("node", "run", "--seconds", str(self.seconds)), stdout=f, stderr=subprocess.STDOUT, cwd=str(self.cli.tree),
                                         start_new_session=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.starts += 1

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def pid(self):
        return self.proc.pid if self.proc else None

    def stop(self, sig=signal.SIGTERM, wait: float = 45.0):
        if self.alive():
            self.proc.send_signal(sig)
            try:
                self.proc.wait(timeout=wait)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def running_elsewhere(self) -> bool:
        """A `node run` for this home (not our child) or a tor running its torrc."""
        if find_tor(self.cli.home):
            return True
        home = str(self.cli.home).encode()
        for p in os.listdir("/proc"):
            if p.isdigit() and int(p) != os.getpid():
                try:
                    c = Path(f"/proc/{p}/cmdline").read_bytes().split(b"\0")
                except OSError:
                    continue
                if b"node" in c and b"run" in c and home in c:
                    return True
        return False

    def kill_tor(self):
        tp = find_tor(self.cli.home)
        if tp:
            os.kill(tp, signal.SIGKILL)
        return tp

    def tor_pid(self):
        return find_tor(self.cli.home)


# ------------------------------------------------------------------ the driver
class Driver:
    def __init__(self, a, cli: Cli, node, cfg: Cfg | None = None, clock=time.time, sleep=time.sleep, out=print):
        os.umask(0o077)
        self.a, self.cli, self.node, self.cfg, self.clock, self.sleep, self.say = a, cli, node, cfg or Cfg(), clock, sleep, out
        self.rng = random.Random(f"{a.seed}:{a.side}:text")
        self.out = Path(a.out)
        self.out.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.bucket = TokenBucket(self.cfg.bucket_per_hour, 5, clock)
        self.sent = {"post": 0, "ask": 0, "blob": 0, "answer": 0}
        self.deferred = 0
        self.first_seen, self.latency, self.peer_ns, self.peer_blobs, self.dups = {}, [], {}, {}, []
        self.my_waits, self.blob_jobs, self.rss, self.last_sample, self.markers = [], [], [], {}, []
        self.pending_fault, self.watch = None, []
        self.pending_skips, self.post_unknown, self.post_failed, self.peer_skipped, self.followups = [], [], [], set(), []
        self.errors_total, self.step_fail = 0, {}
        self.stop_reason, self.cur_fault = None, None
        self.node_deaths = self.restarts = self.blob_ok = self.blob_bad = self.ask_ok = 0
        self.ask_secs, self.faults_done, self.fault_notes = [], [], []
        self.last_peer_seen = None
        self.t0 = None

    # ---- logging (no event text: ids, counts, timings only)
    def note(self, kind, **kw):
        rec = {"t": round(self.clock() - self.t0, 1) if self.t0 else 0, "kind": kind, **kw}
        with open(self.out / "events.log", "a") as f:
            f.write(json.dumps(rec) + "\n")
        return rec

    def csv(self, name, row, header):
        p = self.out / name
        new = not p.exists()
        with open(p, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(header)
            w.writerow(row)

    # ---- actions (each one honours the token bucket)
    def _allowed(self, what):
        if self.bucket.take():
            return True
        self.deferred += 1
        self.note("deferred_by_bucket", what=what)
        return False

    def do_post(self):
        if not self._allowed("post"):
            return
        self.sent["post"] += 1
        n = self.sent["post"]
        rc, o, e = self.cli.run("post", self.a.thread, make_text(self.a.side, n, self.clock(), self.rng, skips=self.pending_skips))
        if rc == 0:
            self.pending_skips = []                        # the accepted post announced them
        elif rc == 124:
            self.pending_skips.append(n)                   # a timed-out call may still have been ingested: keep the number, tell the peer it may be missing
            self.post_unknown.append(n)
            self.note("post_timeout", n=n)
        else:
            self.sent["post"] -= 1                         # nothing was posted: the number is given back (the peer must not see a hole)
            self.post_failed.append({"n": n, "rc": rc})
            self.note("post_failed", n=n, rc=rc, err=clean_err(e))

    def do_ask(self):
        if not self._allowed("ask"):
            return
        self.sent["ask"] += 1
        n = self.sent["ask"]
        ts = self.clock()
        rc, o, e = self.cli.run("ask", self.a.thread, make_ask(self.a.side, n, ts, self.rng)[len("[ASK] "):], "--to", self.a.peer_id)
        if rc != 0:
            self.note("ask_failed", n=n, rc=rc, err=clean_err(e))
            return
        self.my_waits.append({"n": n, "start": ts, "proc": self.cli.spawn("wait", "--max", str(int(max(30, self.cfg.s(900))))), "tries": 1})

    def do_blob(self, size):
        if not self._allowed("blob"):
            return
        self.sent["blob"] += 1
        n = self.sent["blob"]
        block = bytes(self.rng.getrandbits(8) for _ in range(4096))
        data = (block * (size // 4096 + 1))[:size]
        f = self.out / f"blob_{n}.bin"
        f.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        rc, o, e = self.cli.run("post", self.a.thread, make_text(self.a.side, BLOB_N0 + n, self.clock(), self.rng, sha=sha, size=size, pad=50), "--attach", str(f))
        f.unlink(missing_ok=True)
        self.note("blob_sent" if rc == 0 else "blob_send_failed", n=n, size=size, rc=rc, err=clean_err(e) if rc else "")

    def do_sample(self):
        row = {"t": round(self.clock() - self.t0)}
        st = proc_stats(self.node.pid) if self.node.alive() else {}
        tp = self.node.tor_pid()
        tst = proc_stats(tp) if tp else {}
        home = self.cli.home
        ev = next(iter((home / "mirror" / "threads").glob(f"{self.a.thread}/events.jsonl")), None) if (home / "mirror" / "threads").exists() else None
        try:
            log = Path(self.node.log).read_text(errors="replace")
        except OSError:
            log = ""
        try:
            torlog = (home / "tor" / "tor.log").read_text(errors="replace")
        except OSError:
            torlog = ""
        rc, o, e = self.cli.run("brief", self.a.thread, timeout=120)
        try:
            brief = json.loads(o) if rc == 0 else {}
        except ValueError:
            brief = {}
        try:
            sm = (home / "wait" / "state.json").stat().st_mtime
        except OSError:
            sm = None
        row.update({"rss_kb": st.get("rss_kb"), "threads": st.get("threads"), "fds": st.get("fds"), "tor_rss_kb": tst.get("rss_kb"), "tor_fds": tst.get("fds"),
                    "home_bytes": dir_bytes(home), "tor_dir_bytes": dir_bytes(home / "tor"), "events_bytes": ev.stat().st_size if ev else None,
                    "events_lines": sum(1 for _ in open(ev, "rb")) if ev else None, "events": brief.get("events"), "awaiting": brief.get("awaiting"), "missing": len(brief.get("missing") or []),
                    "conflicts": brief.get("conflicts"), "voided": brief.get("voided"), "log_pull_ok": log.count("pull ok"), "log_fail": log.count("FAIL"),
                    "log_error": len(re.findall(r"(?i)traceback|error:", log)), "tor_boots": torlog.count("Bootstrapped 100%"), "wait_state_mtime": sm})
        self.last_sample = row
        self.rss.append(row["rss_kb"])
        cols = list(row)
        self.csv("metrics.csv", [row[c] for c in cols], cols)

    def do_marker(self):
        paths = [self.cli.home] + ([Path(self.node.log)] if Path(self.node.log).exists() else [])
        self.markers = marker_scan(paths)
        self.note("marker_scan", found=len(self.markers))

    def do_fault(self, kind):
        rec = {"kind": kind, "at": round(self.clock() - self.t0, 1)}
        self.cur_fault = rec
        self.followups = []
        self.note("fault", fault=kind)
        if kind == "torkill":
            rec["tor_pid"] = self.node.kill_tor()
            self._deaths_at_torkill = self.node_deaths
            self.watch = [(self.clock() + self.cfg.s(d), d) for d in (120, 300, 600)]
        else:
            self.node.stop(signal.SIGKILL if kind == "kill9" else signal.SIGTERM)
            self.pending_fault = (self.clock() + self.cfg.fault_down, kind)
        self.fault_notes.append(rec)

    # ---- the poll: parse peer messages, answer asks, start blob fetches
    def poll(self):
        rc, o, e = self.cli.run("unread", self.a.thread, timeout=90)
        if rc != 0:
            self.note("unread_failed", rc=rc, err=clean_err(e))
            return
        now = self.clock()
        for row in parse_unread(o):
            key = (row["id8"], hashlib.sha1(row["text"].encode()).hexdigest()[:8])
            kind, g = classify(row["text"], self.a.side)
            if kind is None or key in self.first_seen:
                continue
            self.first_seen[key] = now
            self.last_peer_seen = now
            if kind == "post":
                n, ts = int(g[1]), float(g[2])
                for x in (g[3] or "").split(","):
                    if x:
                        self.peer_skipped.add(int(x))
                store = self.peer_blobs if n >= BLOB_N0 else self.peer_ns
                if not register_post(store, n, now):
                    self.dups.append(n)
                self.latency.append(now - ts)
                self.csv("latency.csv", [round(now - self.t0, 1), n, round(now - ts, 1), 1 if g[4] else 0], ["t", "peer_n", "latency_s", "blob"])
                if g[4]:
                    self.start_blob_fetch(int(g[5]), g[4])
            elif kind == "ask":                       # (first_seen above already makes this once per (id, text))
                if self._allowed("answer"):
                    self.sent["answer"] += 1
                    rc2, o2, e2 = self.cli.run("done", self.a.thread, make_answer(self.a.side, int(g[1]), self.clock(), self.rng)[len("[DONE] "):], "--re", row["id8"])
                    self.note("answered" if rc2 == 0 else "answer_failed", n=int(g[1]), rc=rc2, err=clean_err(e2) if rc2 else "")

    def start_blob_fetch(self, size, sha):
        rc, o, e = self.cli.run("blob", "ls", self.a.thread)
        want = stored_size(size)
        cids = [m.group(1) for m in re.finditer(r"(sha256:[0-9a-f]{64})\s+(\d+) bytes\s+not fetched", o) if int(m.group(2)) == want]
        if not cids:
            self.note("blob_not_listed", size=size)
            return
        dest = self.out / f"got_{cids[0][7:19]}.bin"
        self.blob_jobs.append({"sha": sha, "size": size, "dest": dest, "start": self.clock(),
                               "proc": self.cli.spawn("blob", "get", self.a.thread, cids[0], "--out", str(dest), "--wait", str(int(max(60, self.cfg.s(900)))))})

    def reap(self):
        for j in list(self.blob_jobs):
            if j["proc"].poll() is None:
                continue
            self.blob_jobs.remove(j)
            ok = j["dest"].exists() and j["dest"].stat().st_size == j["size"] and hashlib.sha256(j["dest"].read_bytes()).hexdigest() == j["sha"]
            self.blob_ok += bool(ok)
            self.blob_bad += (not ok)
            self.note("blob_ok" if ok else "BLOB_MISMATCH", size=j["size"], secs=round(self.clock() - j["start"], 1))
            j["dest"].unlink(missing_ok=True)
        for w in list(self.my_waits):
            if w["proc"].poll() is None:
                if self.clock() - w["start"] > self.cfg.s(1000) + 30:
                    w["proc"].kill()
                continue
            out = w["proc"].stdout.read() or ""
            answered_it = f"re #{w['n']} " in out
            if w["proc"].returncode == 0 and not answered_it and self.clock() - w["start"] < self.cfg.s(900):
                w["proc"] = self.cli.spawn("wait", "--max", str(int(max(30, self.cfg.s(900) - (self.clock() - w["start"])))))      # woken by something else: look again
                w["tries"] += 1
                continue
            self.my_waits.remove(w)
            secs = self.clock() - w["start"]
            self.ask_ok += bool(answered_it)
            if answered_it:
                self.ask_secs.append(secs)
            self.note("ask_answered_wake" if answered_it else "ask_no_answer_wake", n=w["n"], secs=round(secs, 1), rc=w["proc"].returncode, tries=w["tries"])

    # ---- supervision: node restarts, fault follow-up, watchdogs
    def supervise(self):
        now = self.clock()
        if self.pending_fault and now >= self.pending_fault[0]:
            kind = self.pending_fault[1]
            self.pending_fault = None
            self.node.start()
            self.restarts += 1
            rc, o, e = self.cli.run("verify", self.a.thread, timeout=120)
            self.note("fault_restart", fault=kind, verify_rc=rc, verify=" ".join(o.split())[:100])
            if self.cur_fault is not None:
                self.cur_fault.update(verify_rc=rc, verdict="restarted by the driver; verify clean" if rc == 0 else "FINDING: verify failed after the restart")
            return None
        if self.pending_fault:
            return None
        for w in list(self.watch):
            if now >= w[0]:
                self.watch.remove(w)
                rec = {"after_s": w[1], "node_alive": self.node.alive(), "tor_pid": self.node.tor_pid()}
                self.note("torkill_followup", **rec)
                self.followups.append(rec)
                if self.cur_fault is not None and not self.watch:
                    self.cur_fault["followups"] = list(self.followups)
                    died = self.node_deaths > getattr(self, "_deaths_at_torkill", self.node_deaths)
                    self.cur_fault["node_exited"] = died
                    self.cur_fault["verdict"] = ("node exited; the driver restarted it" if died else
                                                 "node restarted its tor" if rec["node_alive"] and rec["tor_pid"] else
                                                 "FINDING: node alive with NO tor (silently dead doors)" if rec["node_alive"] else "node is down")
        if not self.node.alive():
            self.node_deaths += 1
            self.note("node_died", deaths=self.node_deaths)
            if self.node_deaths >= 3:
                return "node died 3 times"
            self.node.start()
            self.restarts += 1
        if self.last_peer_seen is not None and now - self.last_peer_seen > self.cfg.silence_seconds and not getattr(self, "_silent", False):
            self._silent = True
            self.note("SILENCE_WARNING", seconds=round(now - self.last_peer_seen))
        elif self.last_peer_seen is not None and now - self.last_peer_seen <= self.cfg.silence_seconds:
            self._silent = False
        return None

    def request_stop(self, reason: str):
        if self.stop_reason is None:
            self.stop_reason = reason

    def guard(self, where, fn, *args):
        """Run one step; an exception is counted and logged (class + a short ASCII detail), never fatal by itself."""
        try:
            r = fn(*args)
            self.step_fail[where] = 0
            return r
        except Exception as e:                             # noqa: BLE001 - one failing step must not end a 6 h run
            self.errors_total += 1
            self.step_fail[where] = self.step_fail.get(where, 0) + 1
            self.note("driver_error", where=where, err=type(e).__name__, detail=clean_err(str(e)))
            if self.step_fail[where] >= 20:
                self.request_stop(f"step '{where}' raised 20 times in a row")
            return None

    def _action(self, kind, arg):
        if kind == "blob":
            self.do_blob(arg)
        elif kind == "fault":
            self.do_fault(arg)
        else:
            {"post": self.do_post, "ask": self.do_ask, "sample": self.do_sample, "marker": self.do_marker}[kind]()

    def _check(self):
        return check_stop(self.rss, self.last_sample.get("home_bytes") or 0, self.markers, self.dups,
                          find_gaps(self.peer_ns, self.clock(), self.cfg.gap_seconds, self.peer_skipped), self.blob_bad)

    def preflight(self) -> list:
        """Reasons NOT to start: the thread must be known with a VERIFIED key on every epoch (else a post would be a local plaintext event that sync never serves), no node/tor may already
        run for this home, and one `wait` is run now because the first `wait` of a home only baselines (a fast answer to the very first ask would be swallowed)."""
        problems = []
        rc, o, e = self.cli.run("list")
        if rc != 0 or self.a.thread[:8] not in o:
            problems.append("the thread is not in `list`")
        rc, o, e = self.cli.run("envelope", "status", self.a.thread)
        keys = [ln for ln in o.splitlines() if "key:" in ln]
        if rc != 0 or not keys or any("key: verified" not in ln for ln in keys):
            problems.append("no VERIFIED key on every epoch of the thread (a post now could be stored as local plaintext)")
        if self.node.running_elsewhere():
            problems.append("a node or tor is already running for this home")
        rc, o, e = self.cli.run("wait", "--max", "1")
        if rc not in (0, 3):
            problems.append(f"`wait` failed (rc {rc})")
        return problems

    def run(self):
        self.t0 = self.clock()
        try:
            stop = self._loop()
        except BaseException as e:                         # noqa: BLE001 - including KeyboardInterrupt: the node must be stopped and the summary written whatever happens
            stop = f"driver crashed: {type(e).__name__}"
            try:
                self.note("driver_crash", err=type(e).__name__, detail=clean_err(str(e)))
            except Exception:                              # noqa: BLE001
                pass
        return self.finish(stop)

    def _loop(self):
        ev = schedule(self.a.seed, self.a.side, self.a.hours, self.cfg)
        try:
            (self.out / "driver.pid").write_text(str(os.getpid()))
        except OSError:
            pass
        if getattr(self.a, "preflight", False):
            problems = self.preflight()
            if problems:
                self.note("preflight_failed", problems=problems)
                return "preflight failed: " + "; ".join(problems)
        self.node.start()
        self.note("start", clock=time.strftime("%Y-%m-%d %H:%M:%S %Z"), epoch=round(self.t0, 1), hours=self.a.hours, scale=self.cfg.k, events=len(ev))
        i, next_poll = 0, self.t0
        total = self.a.hours * 3600.0 * self.cfg.k + self.cfg.drain
        while self.stop_reason is None and self.clock() - self.t0 <= total:
            el = self.clock() - self.t0
            while i < len(ev) and ev[i][0] <= el:
                self.guard(ev[i][1], self._action, ev[i][1], ev[i][2])
                i += 1
            if self.clock() >= next_poll:
                self.guard("poll", self.poll)
                next_poll = self.clock() + self.cfg.poll_every
            self.guard("reap", self.reap)
            self.request_stop(self.guard("supervise", self.supervise) or self.guard("check_stop", self._check))
            self.sleep(1.0)
        return self.stop_reason

    def finish(self, stop):
        """Always: kill child waits/fetches, stop the node, write summary.json. Every part is guarded: a failure here must not leave the node running."""
        self.guard("finish_note", lambda: self.note("stop", reason=stop or "completed", clock=time.strftime("%Y-%m-%d %H:%M:%S %Z")))
        for j in self.blob_jobs:
            self.guard("kill_fetch", j["proc"].kill)
        for w in self.my_waits:
            self.guard("kill_wait", w["proc"].kill)
        vr = self.guard("verify", lambda: self.cli.run("verify", self.a.thread, timeout=300))
        er = self.guard("export", lambda: self.cli.run("export", self.a.thread, timeout=300))
        rc, o = (vr[0], vr[1]) if vr else (None, "")
        lines = sorted(x for x in (er[1] if er else "").splitlines() if x)
        self.guard("node_stop", self.node.stop)
        rss = [r for r in self.rss if r]
        gaps = find_gaps(self.peer_ns, self.clock(), self.cfg.gap_seconds, self.peer_skipped)
        findings = [f"fault {f.get('kind')} at {f.get('at')} s: {f['verdict']}" for f in self.fault_notes if "FINDING" in str(f.get("verdict", ""))]
        for cond, text in ((stop, f"stopped early: {stop}"), (rc != 0, f"verify rc {rc} at the end"), (self.dups, f"duplicate deliveries: {self.dups[:10]}"), (gaps, f"gaps in the peer's posts: {gaps[:10]}"),
                           (self.blob_bad, f"{self.blob_bad} blob(s) failed their sha256/size check"), (self.markers, f"{len(self.markers)} file(s) with the plaintext marker on disk"),
                           (self.post_failed, f"{len(self.post_failed)} post(s) refused by the CLI"), (self.errors_total, f"{self.errors_total} driver step error(s)"),
                           (self.cli.hangs, f"{self.cli.hangs} CLI call(s) hit their timeout")):
            if cond:
                findings.append(text)
        summary = {"side": self.a.side, "hours": self.a.hours, "scale": self.cfg.k, "stopped_early": bool(stop), "reason": stop or "completed", "verify_rc": rc, "verify": " ".join(o.split())[:120],
                   "events": len(lines), "event_set_sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest(), "sent": self.sent, "deferred_by_bucket": self.deferred,
                   "post_failed": self.post_failed, "post_timeouts_kept": self.post_unknown, "peer_skipped": sorted(self.peer_skipped), "driver_errors": self.errors_total,
                   "peer_posts_seen": len(self.peer_ns), "peer_blob_posts_seen": len(self.peer_blobs), "dups": self.dups,
                   "gaps": gaps,
                   "findings": findings, "latency_s": latency_stats(self.latency), "asks_answered_wake": self.ask_ok, "ask_wake_s": {p: percentile(self.ask_secs, p) for p in (50, 95)} | {"max": max(self.ask_secs, default=None)},
                   "blobs_ok": self.blob_ok, "blobs_bad": self.blob_bad, "node_starts": getattr(self.node, "starts", None), "restarts": self.restarts, "node_deaths": self.node_deaths,
                   "faults": self.fault_notes, "markers_on_disk": len(self.markers), "cli_hangs": self.cli.hangs,
                   "rss_kb_first_last_max": [rss[0], rss[-1], max(rss)] if rss else None, "last_sample": self.last_sample, "clock_end": time.strftime("%Y-%m-%d %H:%M:%S %Z")}
        (self.out / "summary.json").write_text(json.dumps(summary, indent=1))
        self.guard("say", self.say, json.dumps(summary, indent=1))
        return 0 if not stop and rc == 0 and not self.dups and not self.blob_bad else 1


def install_signal_handlers(driver):
    """SIGTERM / SIGINT end the run NORMALLY through finish() (node stopped, summary written). Returns the old handlers (tests restore them)."""
    def handler(signum, frame):
        driver.request_stop(f"signal {signal.Signals(signum).name}")
    return {s: signal.signal(s, handler) for s in (signal.SIGTERM, signal.SIGINT)}


def stop_running(out_dir) -> int:
    """`--stop --out DIR`: SIGTERM to the driver whose pid file is in DIR (after checking the pid really is a soak driver)."""
    try:
        pid = int((Path(out_dir) / "driver.pid").read_text().strip())
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except (OSError, ValueError):
        print("no running driver found for that --out", file=sys.stderr)
        return 1
    if not any(c.endswith(b"soak.py") for c in cmd):
        print("the pid in driver.pid is not a soak driver; not touching it", file=sys.stderr)
        return 1
    os.kill(pid, signal.SIGTERM)
    print(f"SIGTERM sent to driver {pid}; it stops its node and writes summary.json")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--stop", action="store_true", help="stop the driver whose driver.pid is in --out (SIGTERM)")
    ap.add_argument("--minutes", type=float, default=10.0)
    ap.add_argument("--tree")
    ap.add_argument("--home")
    ap.add_argument("--side", choices=["arya", "sansa"])
    ap.add_argument("--peer-id")
    ap.add_argument("--thread")
    ap.add_argument("--out")
    ap.add_argument("--hours", type=float, default=6.0)
    ap.add_argument("--seed", default="1")
    a = ap.parse_args(argv)
    if a.selftest:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import soak_selftest
        return soak_selftest.run(a.minutes, a.seed)
    if a.stop:
        if not a.out:
            sys.exit("--stop needs --out")
        return stop_running(a.out)
    for need in ("tree", "home", "side", "peer_id", "thread", "out"):
        if getattr(a, need) is None:
            sys.exit(f"--{need.replace('_', '-')} is required")
    if not re.fullmatch(r"[0-9a-f]{32}", a.thread) or not re.fullmatch(r"[a-z0-9]{32}", a.peer_id):
        sys.exit("bad --thread or --peer-id")
    os.umask(0o077)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    cli = Cli(Path(a.tree), Path(a.home))
    cfg = Cfg()
    a.preflight = True
    d = Driver(a, cli, Node(cli, out / "node.log", int(a.hours * 3600 + cfg.drain + 3600)), cfg)
    install_signal_handlers(d)
    return d.run()


if __name__ == "__main__":
    sys.exit(main())
