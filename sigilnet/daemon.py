"""`start` / `stop` / the status line (DESIGN_node_daemon.md section 4, P1): a node as a background process of a home.

The truth that a node runs is the flock on `home/node.lock` (the kernel drops it on any death). `node.pid` is for signalling only and is written BY THE NODE, after it
holds the lock, together with its start time (/proc/PID/stat field 22): `stop` signals a pid only if the start time still matches AND the command line is a sigilnet
node of this very home (a reused pid is never signalled). `node.status.json` is rewritten by the node every tick (ready, carrier, doors up/total). Zombies count as
dead (this container never reaps: `kill -0` sees them). Not a supervisor: nothing restarts a node that died."""
from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PID, STATUS, ERR, LOCK = "node.pid", "node.status.json", "node.err", "node.lock"
START_WAIT = 180.0                    # Tor's first bootstrap is slow
TERM_WAIT = 30.0


# ---------- /proc ----------
def proc_state(pid: int):
    """(state letter, start time in clock ticks) from /proc/PID/stat, or None if there is no such process."""
    try:
        data = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    rest = data[data.rfind(")") + 2:].split()                 # fields from 3 on: the command name may hold spaces and parentheses
    try:
        return rest[0], int(rest[19])
    except (IndexError, ValueError):
        return None


def proc_cmdline(pid: int) -> list:
    try:
        return [a.decode("utf-8", "replace") for a in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if a]
    except OSError:
        return []


def alive(pid: int) -> bool:
    s = proc_state(pid)
    return s is not None and s[0] not in ("Z", "X")


# ---------- the files ----------
def _write_json(path: Path, d: dict) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(d))
    os.replace(tmp, path)


def _read_json(path: Path):
    try:
        d = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def write_self_pid(home) -> None:
    home = Path(home)
    st = proc_state(os.getpid())
    _write_json(home / PID, {"pid": os.getpid(), "start_time": st[1] if st else None, "home": str(home)})


def write_status(home, **fields) -> None:
    fields.setdefault("pid", os.getpid())
    fields["at"] = time.time()
    try:
        _write_json(Path(home) / STATUS, fields)
    except OSError:
        pass                                                      # a status file that cannot be written must never take the node down


def carrier_label(st: dict) -> str:
    """The carriers a node is serving on NOW, from its status: `tcp+onion`, `tcp (onion down)` for a degraded node (M1c), else the configured carrier as before."""
    ups, down = st.get("carriers_up"), st.get("down")
    if isinstance(ups, list) and ups:
        return "+".join(ups) + (f" ({', '.join(sorted(down))} down)" if isinstance(down, dict) and down else "")
    return str(st.get("carrier"))


def clear_files(home) -> None:
    """The node's own exit: remove the pid and status files, only if they are ours."""
    home = Path(home)
    for name in (PID, STATUS):
        d = _read_json(home / name)
        if d is not None and d.get("pid") == os.getpid():
            try:
                (home / name).unlink()
            except OSError:
                pass


def read_pid(home) -> dict | None:
    d = _read_json(Path(home) / PID)
    if d is None or not isinstance(d.get("pid"), int) or isinstance(d.get("pid"), bool) or d["pid"] <= 1:
        return None
    return d


def is_our_node(home, rec: dict | None) -> bool:
    """The recorded pid is alive, is the same process (start time) and is a sigilnet node of THIS home."""
    if not rec:
        return False
    st = proc_state(rec["pid"])
    if st is None or st[0] in ("Z", "X") or st[1] != rec.get("start_time"):
        return False
    cmd = proc_cmdline(rec["pid"])
    return any("sigilnet" in a for a in cmd) and str(Path(home).absolute()) in cmd


def _probe(home) -> bool:
    """One non-blocking try on node.lock: True if somebody holds it."""
    try:
        fd = os.open(Path(home) / LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    finally:
        os.close(fd)
    return False


def lock_held(home, *, tries: int = 3, gap: float = 0.025, sleep=time.sleep) -> bool:
    """A node holds the lock for ever; a probe (another `status`, `stop`, `start`) holds it for microseconds. So True only when the lock is still held on `tries` tries `gap` apart,
    and a node that starts at that moment (it retries its own non-blocking flock for about a second) is never refused by a probe's momentary hold."""
    for i in range(tries):
        if not _probe(home):
            return False
        if i + 1 < tries:
            sleep(gap)
    return True


def _history_size(home) -> int:
    try:
        return (Path(home) / "history.log").stat().st_size
    except OSError:
        return 0


def _tail(home, n: int = 8, since: int = 0) -> str:
    """What a node that failed to start said: its history.log lines written after `since` (the node's own lines go there, `--history-only`) and what it printed to node.err (a traceback)."""
    lines = []
    try:
        with open(Path(home) / "history.log", "rb") as f:
            f.seek(since)
            lines += f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        pass
    try:
        lines += (Path(home) / ERR).read_text(errors="replace").splitlines()
    except OSError:
        pass
    return " | ".join("".join(" " if not c.isprintable() else c for c in l)[:300] for l in lines[-n:])


# ---------- start / stop / status ----------
def start(home, *, wait: float | None = None, no_wait: bool = False, out=print, clock=time.time, sleep=time.sleep) -> int:
    home = Path(home).absolute()
    wait = START_WAIT if wait is None else wait
    if not (home / "identity.json").is_file():
        out("error: no identity here: run `sigilnet init NAME` first")
        return 1
    if not (home / "node_config.json").is_file():
        out("error: no node configuration here: run `sigilnet init NAME` (or `node init`) first")
        return 1
    if lock_held(home):
        rec = read_pid(home)
        out(f"already running (pid {rec['pid'] if rec else '?'}); `sigilnet stop` first")
        return 1
    for name in (STATUS,):
        try:
            (home / name).unlink()
        except OSError:
            pass
    h0 = _history_size(home)
    env = dict(os.environ)
    root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    fd = os.open(home / ERR, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | (0 if lock_held(home) else os.O_TRUNC), 0o600)      # truncate only when no node holds the lock (two simultaneous starts must not wipe each other's output)
    try:
        proc = subprocess.Popen([sys.executable, "-m", "sigilnet", "--home", str(home), "node", "run", "--history-only"], stdin=subprocess.DEVNULL, stdout=fd, stderr=fd,
                                start_new_session=True, close_fds=True, env=env)
    finally:
        os.close(fd)
    out(f"starting (pid {proc.pid})...")
    if no_wait:
        return 0
    end = clock() + wait
    while clock() < end:
        rc = proc.poll()
        if rc is not None:
            rec = read_pid(home)
            if rc != 0 and lock_held(home) and is_our_node(home, rec):       # we lost a race against another start: that node is the winner, and its output is not ours
                out(f"already running (pid {rec['pid']}); `sigilnet stop` first")
            else:
                out(f"error: the node exited ({rc}) before it was ready: {_tail(home, since=h0)}")
            return 1
        st = _read_json(home / STATUS)
        if st and st.get("ready") and st.get("pid") == proc.pid:
            out(f"running (pid {proc.pid}, carrier {carrier_label(st)}, doors {st.get('doors_up')}/{st.get('doors_total')})")
            return 0
        sleep(0.5)
    out(f"not ready after {wait:g} s: the node keeps starting in the background (pid {proc.pid}); `sigilnet status` shows when it is up, {home / ERR} has its output")
    return 1


def _gone(pid: int) -> bool:
    return not alive(pid)


def stop(home, *, term_wait: float = TERM_WAIT, out=print, clock=time.time, sleep=time.sleep, cleanup=None) -> int:
    home = Path(home).absolute()
    rec = read_pid(home)
    ours = is_our_node(home, rec)
    held = lock_held(home)
    if not ours:
        if rec is not None:
            try:
                (home / PID).unlink()
            except OSError:
                pass
            out("removed a stale node.pid (that process is gone or is not this node)")
        if held:
            out("error: a node holds the lock but node.pid does not identify it: not signalling anything; stop it by hand")
            return 1
        out("not running")
        return 0
    pid = rec["pid"]
    out(f"stopping (pid {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    end = clock() + term_wait
    while clock() < end and not (_gone(pid) and not lock_held(home)):
        sleep(0.2)
    killed = False
    if not _gone(pid):
        out(f"no clean exit after {term_wait:g} s: SIGKILL")
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        killed = True
        end = clock() + 5.0
        while clock() < end and not _gone(pid):
            sleep(0.1)
        if not _gone(pid):
            out("error: the process is still there after SIGKILL")
            return 1
    if killed and cleanup is not None:
        cleanup(home, out)
    for name in (PID, STATUS):
        try:
            (home / name).unlink()
        except OSError:
            pass
    out("stopped")
    return 0


def carrier_cleanup(home, out=print) -> None:
    """After a SIGKILL only: a tor that runs OUR torrc but is no longer our child (TorNode.stop_stale verifies pid file + /proc). The tcp carrier has no child."""
    try:
        from . import noderun
        cfg = noderun.load_config(Path(home))
        if "tor" not in (cfg.get("carriers") or [cfg.get("carrier", "tor")]) or not (Path(home) / "tor" / "torrc").exists():
            return
        tn = noderun.carrier_for(Path(home), cfg, "onion", offline=True)
        if tn.stop_stale():
            out("stopped a leftover tor")
    except Exception as e:                                        # noqa: BLE001 - cleanup is best effort
        out(f"note: carrier cleanup skipped ({type(e).__name__})")


def status_lines(home) -> list:
    home = Path(home).absolute()
    rec = read_pid(home)
    held = lock_held(home)
    st = _read_json(home / STATUS) or {}
    if held and is_our_node(home, rec):
        up = max(0, int(time.time() - st.get("started", time.time()))) if st.get("started") else None
        bits = [f"pid {rec['pid']}"]
        if up is not None:
            bits.append(f"up {up // 3600}h{up % 3600 // 60:02d}m{up % 60:02d}s")
        if st.get("down") and isinstance(st["down"], dict):         # M1c: a node with several carriers keeps running while one is down
            up = "+".join(st.get("carriers_up") or []) or "none"
            bits.append(f"carrier {up} (" + "; ".join(f"{t}: {str(d)[:120]}" for t, d in sorted(st["down"].items())) + ")")
        elif st.get("carrier"):
            bits.append(f"carrier {st['carrier']}")
        if st.get("ready"):
            bits.append(f"doors {st.get('doors_up')}/{st.get('doors_total')}")
            g = st.get("guard")
            if isinstance(g, dict):
                refused = sum(int(v.get(k, 0) or 0) for v in g.values() if isinstance(v, dict) for k in ("refused_banned", "refused_ip", "refused_door", "refused_global"))
                bans = sum(int(v.get("bans", 0) or 0) for v in g.values() if isinstance(v, dict))
                if refused or bans:
                    bits.append(f"refused at accept {refused}, bans {bans}")
        else:
            bits.append("starting (not ready yet)")
        return [f"node: running ({', '.join(bits)}) on {home}"]
    if held:
        return [f"node: running, but node.pid does not identify it (not started by `start`? an old-code node?) on {home}"]
    return [f"node: stopped ({home})"]
