"""python -m sigilnet ... : a small local tool over the library (no network). State lives in --home (default ~/.sigilnet, 0600 files)."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from pathlib import Path

from . import event as E
from .build import Writer, make_genesis
from . import addressing as AD, convo
from .history import History
from .home import HomeError, open_mirror, resolve_home, shadowed
from .migrate import MigrationError, migrate_home
from .keys import Identity
from .mirror import BODY_CAP, Mirror, cap_text
from .rotate import near_wall
from .thread import MAX_STORED, Thread
from .carrier import CarrierError


def _home(a) -> Path:
    """The home (home.py: --home > $SIGILNET_HOME > walk up for .sigilnet/). An explicit path is created as before; a walked-to home must already exist: only `init` makes one."""
    try:
        h = resolve_home(a.home, os.environ, Path.cwd())
    except HomeError as e:
        sys.exit(f"error: {e}")
    if a.home or os.environ.get("SIGILNET_HOME"):
        h.mkdir(parents=True, exist_ok=True)
        h.chmod(0o700)
    try:
        migrate_home(h)                                    # inbox/ -> guest/ (DESIGN_node_daemon.md P0): before anything can open the guest door's state
    except MigrationError as e:
        sys.exit(f"error: {e}")
    return h


def _identity(home: Path) -> Identity:
    p = home / "identity.json"
    if not p.exists():
        sys.exit("no identity yet: run `id init <name>`")
    return Identity.load(p)


def _pub(i: Identity) -> dict:
    return {"name": i.name, "agent": i.id, "sign": i.sign_pub, "kex": i.kex_pub}


def _load_pub(path: str) -> Identity:
    """A public record (from `id show --json`) as a stand-in Identity for building member lists: only the public parts are used."""
    d = json.loads(Path(path).read_text())
    return type("Pub", (), {"id": d["agent"], "sign_pub": d["sign"], "kex_pub": d["kex"], "name": d.get("name", "")})()


def _mirror(home: Path, me_id: str) -> Mirror:
    return open_mirror(home, me_id)        # private threads are stored and served as envelopes (keys/ next to the data); every event that should wake the agent gets a line in inbox.jsonl


def _live_cmd(a, home: Path) -> int:
    import os
    import time as _time
    from .liveview import Live
    if not (home / "identity.json").exists():
        sys.exit("no identity yet: run `sigilnet init NAME`")
    me = _identity(home)
    m = _mirror(home, me.id)
    color = not a.no_color and (a.color or (sys.stdout.isatty() and not os.environ.get("NO_COLOR")))
    live = Live(m, a.thread, lambda s: print(s, flush=True), last=max(0, a.last), width=a.width, color=color, max_lines=None if a.full else 30)
    try:
        if not live.start() and a.once:
            print("no thread matches" if a.thread else "no threads in this mirror")
            return 1
        if not live.shown and not a.once:
            print("(no matching thread yet: waiting)" if a.thread else "(no threads yet: waiting)", flush=True)
        end = None if a.seconds is None else _time.monotonic() + a.seconds
        while not a.once and (end is None or _time.monotonic() < end):
            _time.sleep(max(0.05, a.poll))
            live.step()
    except KeyboardInterrupt:
        return 0
    except BrokenPipeError:                                          # `live | head`: leave quietly (stdout goes to /dev/null so the exit flush cannot complain)
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    return 0


def _thread(m: Mirror, prefix: str) -> Thread:
    hit = [t for t in m.threads if t.startswith(prefix)]
    if len(hit) != 1:
        sys.exit(f"thread '{prefix}': {'no match' if not hit else 'ambiguous'}; known: {', '.join(t[:8] for t in m.threads) or 'none'}")
    return m.threads[hit[0]]


LABEL_RE = __import__("re").compile(r"[A-Za-z0-9_-]{1,32}")


def _guest_blob(a, home: Path, m: Mirror, me: Identity, tid: str, tr) -> int:
    """A stranger fetches the attachment of a PUBLIC thread through its read door (unsigned; proof of work scaled to the chunk; integrity = the final sha256)."""
    from .blobfetch import PublicSource, fetch
    from .blobindex import BlobIndex
    from .blobout import OutError, export
    from .blobstore import BlobStore
    if not a.cid or not a.out:
        sys.exit("guest blob THREAD_ID --cid CID --out PATH --read X.onion")
    if tid not in m.threads:
        sys.exit("`guest pull` the thread first")
    idx, store = BlobIndex(m), BlobStore(home / "blobs")
    hits = [c for c in idx.refs(tid) if c == a.cid or (len(a.cid) >= 12 and c.startswith(a.cid))]
    if len(hits) != 1:
        sys.exit(f"cid '{a.cid}': {'not referenced by a live event of this thread' if not hits else 'ambiguous prefix'}")
    cid = hits[0]
    if not store.has(cid):
        r = fetch(m, store, idx, tid, cid, [PublicSource(tr, "read-door")], me, referenced=idx.referenced())
        print(f"fetch: {'ok' if r['ok'] else 'FAILED: ' + str(r['why'])} ({r['requests']} request(s), {r['bytes']} byte(s))")
        if not r["ok"]:
            return 1
    try:
        n = export(store, m, tid, cid, a.out)
    except OutError as e:
        sys.exit(f"error: {e}")
    print(f"wrote {n} bytes to {Path(a.out).absolute()} (0600; treat it as untrusted data)")
    return 0


def _blob_cmd(a, home: Path, m: Mirror) -> int:
    from . import blob as B
    from .blobindex import BlobIndex
    from .blobout import OutError, export
    from .blobstore import BlobStore
    from .blobwant import Wants
    store, idx = BlobStore(home / "blobs"), BlobIndex(m)
    if a.action == "rm":
        if len(a.args) != 1:
            sys.exit("blob rm CID")
        try:
            print("removed" if store.remove(a.args[0]) else "not in the store")
        except B.BlobError:
            sys.exit("bad cid (expected sha256:<64 hex>)")
        return 0
    if a.action == "ls":
        tids = [_thread(m, a.args[0]).id] if a.args else list(m.threads)
        held = store.listing()
        shown = set()
        for tid in tids:
            for cid, sizes in sorted(idx.refs(tid).items()):
                shown.add(cid)
                print(f"{tid[:8]}  {cid}  {sizes[0]} bytes{'  (sizes disagree: ' + ','.join(map(str, sizes)) + ')' if len(sizes) > 1 else ''}  {'HELD' if cid in held else 'not fetched'}"
                      f"{'  authored' if held.get(cid, {}).get('authored') else ''}")
        if not a.args:
            for cid, v in sorted(held.items()):
                if cid not in shown:
                    print(f"-         {cid}  {v['size']} bytes  HELD, unreferenced (removed after the grace period)")
        print(f"store: {store.usage()} of {store.quota} bytes")
        return 0
    if len(a.args) != 2 or not a.out:
        sys.exit("blob get THREAD CID --out PATH [--wait SECS]")
    t = _thread(m, a.args[0])
    live = idx.refs(t.id)
    want = a.args[1]
    hits = [c for c in live if c == want or (len(want) >= 12 and c.startswith(want))]
    if len(hits) != 1:
        sys.exit(f"cid '{want}': {'not referenced by a live event of this thread' if not hits else 'ambiguous prefix'} (`blob ls {t.id[:8]}` lists them)")
    cid = hits[0]
    wants = Wants(home / "blobs")
    if not store.has(cid):
        if max(live[cid]) > store.max_blob:
            sys.exit(f"the attachment is {live[cid][0]} bytes; the limit here is {store.max_blob} (max_blob_bytes)")
        if not wants.queued(cid) and not wants.add(t.id, cid):
            sys.exit("too many fetches queued")
        print(f"queued: the running node (`node run`) fetches {cid[:19]}.. from a peer" + ("" if a.wait else "; run this command again later, or pass --wait SECS"))
        end = time.time() + a.wait
        while not store.has(cid) and time.time() < end:
            st = wants.status(cid)
            if st is not None and not st["ok"]:
                sys.exit(f"fetch failed: {st['why']}")
            time.sleep(1.0)
        if not store.has(cid):
            return 0 if not a.wait else 1
    try:
        n = export(store, m, t.id, cid, a.out)
    except OutError as e:
        sys.exit(f"error: {e}")
    print(f"wrote {n} bytes to {Path(a.out).absolute()} (0600; treat it as untrusted data)")
    return 0


def _free_range(start: int, count: int, hosts) -> int:
    """The first base >= start (stepping by count) for which `count` consecutive ports can be bound on every host in `hosts`."""
    import socket
    hosts = list(dict.fromkeys(hosts))
    base = start
    while base + count < 65000:
        socks, ok = [], True
        try:
            for p in range(base, base + count):
                for h in hosts:
                    sk = socket.socket(socket.AF_INET6 if ":" in h else socket.AF_INET, socket.SOCK_STREAM)
                    socks.append(sk)
                    if ":" in h:
                        sk.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)         # (like the door: a v6 probe must not collide with the v4 probe of the same port)
                    sk.bind((h, p))
        except OSError:
            ok = False
        finally:
            for sk in socks:
                sk.close()
        if ok:
            return base
        base += count
    sys.exit("no free port range found")


def _git_tracks(d: Path) -> bool:
    import subprocess
    try:
        r = subprocess.run(["git", "-C", str(d), "ls-files", "--", ".sigilnet"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and bool(r.stdout.strip())


def _init_cmd(a) -> int:
    """`init NAME`: identity + node configuration in ./.sigilnet (or --home / $SIGILNET_HOME), one agent per project directory (DESIGN_node_daemon.md section 3)."""
    import argparse
    from . import noderun
    explicit = a.home or os.environ.get("SIGILNET_HOME")
    cwd = Path.cwd()
    target = Path(explicit) if explicit else cwd / ".sigilnet"
    if not explicit:
        try:
            tst = os.lstat(target)
        except OSError:
            tst = None
        if tst is not None and not stat.S_ISDIR(tst.st_mode):
            sys.exit(f"error: {target} is a symlink or a file, not a plain directory: not writing keys into whatever it points to (the same rule that makes `resolve_home` refuse it)")
    if (target / "identity.json").exists():
        sys.exit(f"error: {target} already holds an agent (one agent per project directory): remove it deliberately if you really mean to start over")
    if not explicit:
        if _git_tracks(cwd):
            sys.exit("error: git tracks files under .sigilnet (an already-tracked directory defeats its own .gitignore, and it holds private keys): `git rm -r --cached .sigilnet` first")
        parent = shadowed(os.environ, cwd)
        if parent is not None:
            print(f"note: this shadows the home {parent} of a parent directory (commands run under {cwd} will use the new one)", file=sys.stderr)
    ports = {"local_port": a.local_port, "virtual_port": a.virtual_port, "service_port_base": a.service_port_base, "tcp_port_base": a.tcp_port_base}
    if a.carrier == "tcp":
        if not a.bind:
            sys.exit("error: init --carrier tcp needs --bind IP (an address of this machine, or 'auto'; any IPv4 or IPv6 address is allowed, public too; 'auto6' = this machine's global IPv6 address)")
        if ports["tcp_port_base"] is None:
            from .tcplink import resolve_bind
            try:
                probe_ip = resolve_bind(a.bind)                                 # "auto" = this machine's address now (the config keeps "auto": DESIGN_locator_book.md F1)
            except ValueError as e:
                sys.exit(f"error: {e}")
            ports["tcp_port_base"] = _free_range(47600, 128, ["127.0.0.1", probe_ip])
    elif ports["service_port_base"] is None:
        ports["service_port_base"] = _free_range(noderun.DEFAULTS["service_port_base"], 64, ["127.0.0.1"])
    created = not target.exists()
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.chmod(0o700)
    me = Identity.generate(a.name)
    try:
        if not explicit:
            gi = target / ".gitignore"
            if not gi.exists():
                gi.write_text("*\n")
        me.save(target / "identity.json")
        ns = argparse.Namespace(cmd="node", action="init", args=[], bridge=a.bridge, carrier=a.carrier, bind=a.bind, advertise=a.advertise, **ports)
        rc = _node_cmd(ns, target, me, None)
    except BaseException:
        if created:
            import shutil
            shutil.rmtree(target, ignore_errors=True)                 # never leave an identity without a node configuration
        raise
    if rc:
        if created:
            import shutil
            shutil.rmtree(target, ignore_errors=True)
        return rc
    print(f"created {me.name}: agent {me.id} in {target}")
    print("note: the directory holds private keys. `.sigilnet/.gitignore` keeps them out of git only: a docker build context, rsync, tar or a backup copies them too.")
    return 0


def _ping_cmd(a, home: Path) -> int:
    from . import ping as P
    t0 = time.monotonic()
    try:
        res = P.ping_peer(home, a.peer, P.PING_DEFAULT_TIMEOUT if a.timeout is None else a.timeout)
    except P.PingError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e.strerror or e}", file=sys.stderr)
        return 1
    print(P.format_result(res, time.monotonic() - t0))
    return 0 if res.ok else 3


def _last_heard(home: Path) -> dict:
    """{agent: seconds since its last pong} from node.json (written by the node)."""
    try:
        raw = json.loads((home / "node.json").read_text()).get("pongs", {})
        return {k: max(0, int(time.time() - v["last_pong"])) for k, v in raw.items() if isinstance(v, dict) and isinstance(v.get("last_pong"), (int, float)) and not isinstance(v["last_pong"], bool)}
    except (OSError, ValueError, AttributeError, TypeError, KeyError):
        return {}


def _ago(secs: int) -> str:
    return f"{secs} s" if secs < 120 else (f"{secs // 60} min" if secs < 7200 else f"{secs // 3600} h")


def _notify_addrs(home: Path, agent: str) -> list:
    """[(carrier type, address, failures in a row)] of the notify addresses this peer announced and we verified (one per carrier type at most)."""
    from .locators import open_book
    d, out = home / "locators", []
    try:
        etypes = sorted(f.name[:-5] for f in d.iterdir() if f.name.endswith(".json")) if d.is_dir() else []
    except OSError:
        return out
    for etype in etypes:
        try:
            st = open_book(home, etype).notify_state(agent)
        except (OSError, ValueError):
            continue
        if st:
            out.append((etype, st["addr"], st["nfail"]))
    return out


def _locators(home: Path, agent: str, rec: dict) -> list:
    """[(carrier type, address, seconds since its last good contact or None, failed since)] for a peer: for each carrier type of its endpoints (the primary's first) the locator book's
    addresses in dial order, else the endpoint's own address; a peer whose record has no endpoint at all: whatever the locator books hold for it."""
    from .carrier import endpoints_of
    from .locators import open_book
    out = []
    for ep in endpoints_of(rec):
        try:
            detail = open_book(home, ep["type"]).detail(agent)
        except (OSError, ValueError):
            detail = []
        for addr, ago, failing in (detail or [(ep["addr"], None, False)]):
            out.append((ep["type"], addr, ago, failing))
    if not out:                                                        # a peer with no endpoint in its record but addresses in a carrier's locator book (an adopted announcement): list and rm see them as plan does
        d = home / "locators"
        try:
            etypes = sorted(f.name[:-5] for f in d.iterdir() if f.name.endswith(".json")) if d.is_dir() else []
        except OSError:                                                # (an unreadable locators/ directory: the book is a cache, never a reason to fail `peer list` or `peer rm`)
            etypes = []
        for etype in etypes:
            try:
                out += [(etype, addr, ago, failing) for addr, ago, failing in open_book(home, etype).detail(agent)]
            except (OSError, ValueError):
                continue
    return out


def _drop_peer_credentials(home: Path, book, agent: str) -> None:
    """`peer rm`: forget the credential we hold for this peer, under its node id AND under every address we know for it (best effort: a failure leaves the credential, never the peer)."""
    from . import noderun
    rec = book.all().get(agent)
    locs = _locators(home, agent, rec) if rec is not None else []
    if not locs:
        return
    try:
        cfg = noderun.load_config(home)
        for etype, addr, _, _ in locs:
            try:
                carrier = noderun.carrier_for(home, cfg, etype, offline=True)
            except ValueError:
                continue                                               # (a node holds credentials only for the carriers it runs)
            carrier.drop_credential({"type": etype, "addr": addr}, agent=agent)
    except Exception:                                                  # noqa: BLE001 - never block a removal on a carrier that is not there
        pass


def _revoke_peer_doors(home: Path, agent: str) -> list:
    """`peer rm`: close the door(s) WE gave this peer, on every carrier this node runs: the doors of kind peer bound to its agent id (M3c, DESIGN_multicarrier.md A5). A door bound to no agent is never
    touched (nothing says whose it is: `node doors` lists it); a failure on one carrier leaves its doors and never blocks the removal. -> [(carrier type, door name)] closed."""
    from . import noderun
    closed = []
    try:
        carriers = noderun.make_carriers(home, noderun.load_config(home), offline=True)
    except Exception:                                                  # noqa: BLE001 - a node with no carrier configured has no doors to close
        return closed
    for etype, carrier in carriers.items():
        try:
            doors = carrier.doors()
            names = sorted(n for n, d in doors.items() if d.get("kind") == "peer" and d.get("agent") == agent)
        except Exception:                                              # noqa: BLE001
            continue
        for name in names:
            try:
                if carrier.close_door(name):
                    closed.append((etype, name))
            except Exception:                                          # noqa: BLE001
                continue
    return closed


def _node_doors(home: Path, cfg: dict, book) -> int:
    """`node doors`: every door on every carrier this node runs, with the peer it is bound to; a door whose agent is not in the peer book (or is bound to none) is marked, so the owner can `node revoke` it."""
    from . import noderun
    peers = book.all()
    rows = 0
    for etype, carrier in noderun.make_carriers(home, cfg, offline=True).items():
        for name, d in sorted(carrier.doors().items()):
            agent = d.get("agent")
            if d.get("kind") != "peer":
                who = "(public or join door)"
            elif agent is None:
                who = "(bound to no agent: whose is it? `node revoke " + name + "` closes it)"
            elif agent in peers:
                who = f"peer {peers[agent].get('name') or agent[:8]}"
            else:
                who = f"NO PEER holds agent {agent[:8]}: `node revoke {name}` closes it"
            print(f"{etype:6} {name:34} {d.get('kind', 'peer'):6} {who}")
            rows += 1
    if not rows:
        print("no doors")
    return 0


def _peer_move(a, home: Path, me: Identity, book, noderun) -> int:
    """`peer move AGENT (--ip NEWIP | --endpoint TYPE:ADDR) [--no-verify]`: the peer lives somewhere else now. Both of our addresses may have changed, so neither side could announce
    (DESIGN_locator_book.md 3.6): a human relays the new address. --ip keeps the port and the door fingerprint of the address we hold. Unless --no-verify, a dial to the new address must be
    answered by a signed ping from that node id first; nothing is changed otherwise."""
    from . import ping as P
    from .carrier import check_endpoint
    peers = book.all()
    if len(a.args) != 1 or bool(a.ip) == bool(a.endpoint):
        sys.exit("peer move AGENT_ID (--ip NEWIP | --endpoint TYPE:ADDR) [--no-verify]")
    try:
        agent, _name = P._resolve(peers, a.args[0])
    except P.PingError as e:
        sys.exit(f"error: {e}")
    rec = peers[agent]
    cur = _locators(home, agent, rec)
    if a.ip:
        tcp_cur = [c for c in cur if c[0] == "tcp"]
        if not tcp_cur:
            sys.exit("error: --ip is for a tcp peer that already has an address (use --endpoint)")
        from .tcplink import _split_addr, fmt_addr
        try:
            _, port, fp = _split_addr(tcp_cur[0][1])
            new_ip = a.ip[1:-1] if a.ip.startswith("[") and a.ip.endswith("]") else a.ip          # (an IPv6 address may be given with or without brackets)
            endpoint = check_endpoint({"type": "tcp", "addr": fmt_addr(new_ip, port, fp)}, strict=True)
        except ValueError as e:
            sys.exit(f"error: {e}")
    else:
        etype, _, eaddr = a.endpoint.partition(":")
        try:
            endpoint = check_endpoint({"type": etype, "addr": eaddr}, strict=True)
        except ValueError as e:
            sys.exit(f"error: {e}")
    name = rec["name"] or agent[:8]
    if not a.no_verify:
        try:
            carrier = noderun.carrier_for(home, noderun.load_config(home), endpoint["type"], offline=True)
        except ValueError as e:
            sys.exit(f"error: {e}; {endpoint['type']} is not reachable from it")
        if carrier.type != "tcp":
            sys.exit("error: this command cannot verify a Tor address (the CLI has no Tor): the node verifies announced addresses itself; --no-verify sets it anyway")
        try:
            tr = carrier.dial(endpoint, timeout=10.0, connect_timeout=5.0, agent=agent)
            ok, why, _, _ = P.exchange(tr, me, agent, time.time, deadline=time.time() + 15.0)
        except CarrierError as e:
            ok, why = False, P._why_from(e)
        if not ok:
            sys.exit(f"error: no answer from {name} at the new address ({why}); nothing was changed (--no-verify sets it anyway)")
    book.add(agent, rec["name"], endpoint, rec["threads"])             # (also puts it first in the locator book)
    print(f"peer {name}: address moved" + ("" if not a.no_verify else " (not verified)") + (f" (verified: {name} answered)" if not a.no_verify else ""))
    return 0


def _node_cmd(a, home: Path, me: Identity, m: Mirror) -> int:
    from . import noderun
    from .node import PeerBook
    from . import onion as _onion
    from .carrier import check_credential, check_endpoint
    if a.cmd == "peer":
        book = PeerBook(home / "peers.json")
        if a.action == "list":
            heard = _last_heard(home)
            from . import peerver as _PV, version as _V
            pvs = _PV.PeerVer(home / "peerver.json")
            for aid, p in book.all().items():
                locs = _locators(home, aid, p)
                print(f"{p['name'] or '-':12} {aid}  {(locs[0][0] + ' ' + locs[0][1]) if locs else '(no endpoint: it dials us)'}  threads={','.join(t[:8] for t in p['threads']) or '(those we share)'}"
                      + (f"  last heard {_ago(heard[aid])} ago" if aid in heard else ""))
                e = pvs.get(aid)
                if e:                                                           # (a peer never heard from gets no line: the output stays what it was)
                    r = e.get("refused")
                    if r and time.time() - r["at"] < 7 * 86400:
                        print(f"{'':12} {'':32}  we refuse it ({_ago(max(0, int(time.time()) - r['at']))} ago): {r['why']}")
                    print(f"{'':12} {'':32}  " + (_V.describe({k: e[k] for k in ('wire', 'sw')}) if not e["legacy"] else "wire 0 (0.1.x or older: it declares nothing)") + f"  (recorded {_ago(max(0, int(time.time()) - e['seen']))} ago)")
                for etype, addr, ago, failing in locs[1:]:                  # the other addresses we hold for this peer, every carrier, in dial order (DESIGN_locator_book.md)
                    print(f"{'':12} {'':32}  also {etype} {addr}" + (f"  (last good {_ago(int(ago))} ago)" if ago is not None else "") + ("  (failed since)" if failing else ""))
                for etype, addr, nfail in _notify_addrs(home, aid):         # (M4b) where this peer asked us to tell it about news: apart from the pull addresses
                    print(f"{'':12} {'':32}  notify {etype} {addr} (adopted, verified)" + (f"  ({nfail} failure(s) in a row)" if nfail else ""))
            return 0
        if a.action == "rm":
            agent = a.args[0] if a.args else None
            if agent:
                _drop_peer_credentials(home, book, agent)
            closed = _revoke_peer_doors(home, agent) if agent and not a.keep_doors and agent in book.all() else []
            print("removed" if agent and book.remove(agent) else "no such peer")
            for etype, name in closed:
                print(f"closed the {etype} door {name} we gave this peer (a running node drops it within a few seconds)")
            return 0
        if a.action == "move":
            return _peer_move(a, home, me, book, noderun)
        if a.action == "invite":
            from . import ping as P
            if len(a.args) != 1 or not a.thread:
                sys.exit("peer invite AGENT --thread ID [--thread ID ...]   (AGENT: name, id or id prefix of a peer we hold; the thread id is the FULL 32-hex id)")
            try:
                agent, name = P._resolve(book.all(), a.args[0])
                added = book.invite(agent, a.thread)
            except (P.PingError, ValueError) as e:
                sys.exit(f"error: {e}")
            print(f"peer {name or agent[:8]}: " + ("invited to " + ", ".join(t[:8] for t in a.thread) + "; the node picks it up within a few seconds" if added else "nothing to add (already invited)"))
            return 0
        if len(a.args) != 2:
            sys.exit("peer add NAME AGENT_ID (--onion X.onion [--port P] | --endpoint TYPE:ADDR)")
        name, agent = a.args
        try:
            if a.onion and a.endpoint:
                sys.exit("give --onion or --endpoint, not both")
            if a.endpoint:
                etype, _, eaddr = a.endpoint.partition(":")
                endpoint = check_endpoint({"type": etype, "addr": eaddr})
            else:
                endpoint = _onion.endpoint(a.onion.strip(), a.port) if a.onion else None
            kf = None
            if a.key:
                if not LABEL_RE.fullmatch(a.key):
                    sys.exit("--key LABEL: 1-32 characters of a-z A-Z 0-9 _ -")
                if not endpoint:
                    sys.exit("--key needs --onion or --endpoint")
                kf = home / "peerkeys" / f"{a.key}.priv"
                if not kf.is_file():
                    sys.exit(f"no key '{a.key}': run `node auth {a.key}` first")
            book.add(agent, name, endpoint, a.thread)                   # (validates everything; nothing is added if it raises)
            if kf:
                noderun.carrier_for(home, noderun.load_config(home), endpoint["type"]).use_credential(endpoint, check_credential(json.loads(kf.read_text()), secret=True), agent=agent)
        except ValueError as e:
            sys.exit(str(e))
        print(f"peer {name} added")
        return 0
    cfg = noderun.load_config(home)
    if a.action == "notify-via":
        if len(a.args) > 1 or (a.args and a.args[0] not in ("tcp", "tor", "none")):
            sys.exit("node notify-via [tcp|tor|none]   (the carrier on which THIS node wants notifies; none = the addresses it already dials, as before)")
        if not a.args:
            print(f"notify_via: {cfg.get('notify_via') or 'none'}   (this node runs: {', '.join(cfg['carriers'])})")
            return 0
        want = None if a.args[0] == "none" else a.args[0]
        if want and want not in cfg["carriers"]:
            sys.exit(f"this node does not run {want} (it runs {', '.join(cfg['carriers'])}): add the carrier first")
        cfg["notify_via"] = want
        noderun.save_config(home, cfg)
        print(f"notify_via set to {want or 'none'}; a running node picks it up at its next start (`stop`, `start`).")
        if want == "tcp":
            print("NOTE: every peer of this node will learn the address of our tcp door for it, i.e. this machine's IP address, over WHATEVER carrier the pull uses (Tor included); a node that supports tcp is not hiding it.")
        return 0
    if a.action in ("auto-rotate", "follow-rotation"):
        key = a.action.replace("-", "_")
        if len(a.args) > 1 or (a.args and a.args[0] not in ("on", "off")):
            sys.exit(f"node {a.action} [on|off]   " + ("(this node, when it OWNS a private thread at 80% of the size wall, rotates it by itself: one attempt, never --close)" if key == "auto_rotate" else
                                                      "(this node follows the owner's [ROTATED-TO] pointer to the new thread by itself, for every peer that follows the old thread)"))
        if not a.args:
            print(f"{key}: {'on' if cfg.get(key) else 'off'}")
            return 0
        cfg[key] = a.args[0] == "on"
        noderun.save_config(home, cfg)
        print(f"{key} set to {a.args[0]}; a running node picks it up at its next start (`stop`, `start`).")
        return 0
    if a.action == "init":
        for k, v in (("local_port", a.local_port), ("virtual_port", a.virtual_port), ("service_port_base", a.service_port_base)):
            if v is not None:
                if not 0 < v < 65536:
                    sys.exit(f"{k.replace('_', '-')} must be between 1 and 65535")
                cfg[k] = v
        cfg["bridges"] = list(a.bridge) or cfg["bridges"]
        if a.carrier == "tcp":
            if not a.bind or a.tcp_port_base is None:
                sys.exit("node init --carrier tcp needs --bind IP and --tcp-port-base N")
            cfg["carrier"], cfg["carriers"] = "tcp", ["tcp"]
            cfg["tcp"] = {"bind": a.bind, "port_base": a.tcp_port_base, **({"advertise": a.advertise} if a.advertise else {})}
        elif a.carrier == "tor":
            cfg["carrier"], cfg["carriers"] = "tor", ["tor"]
            cfg.pop("tcp", None)
        try:
            noderun.make_carrier(home, cfg, offline=True)                  # validates the bridge lines / the tcp section and creates the directories
        except ValueError as e:
            sys.exit(str(e))
        noderun.save_config(home, cfg)
        if cfg.get("carrier") == "tcp":
            print(f"node configured: carrier tcp on {cfg['tcp']['bind']}" + (f" (now {noderun.resolve_bind('auto', cfg['tcp'].get('allow_public', False), noderun._tcp_peer_ips(home))})" if cfg["tcp"]["bind"] == "auto" else "") + f" from port {cfg['tcp']['port_base']} (one door per peer, two ports each). Next: `node authorize NAME PUBKEY --agent ID` for each peer, then `start` (or `node run` in the foreground).")
            return 0
        print(f"node configured: one onion service per peer (local ports from {cfg['service_port_base']}, onion port {cfg['virtual_port']}). Next: `node authorize NAME PUBKEY --agent ID` for each peer, then `start` (or `node run` in the foreground).")
        return 0
    if a.action == "address":
        tn = _door_carrier(home, cfg, a)
        rows = [(name, tn.door_endpoint(name), s["agent"]) for name, s in sorted(tn.doors().items()) if not a.args or name in a.args]
        if tn.shared_port() and not a.args:
            rows.insert(0, ("(shared)", tn.shared_endpoint(), None))
        for name, ep, agent in rows:
            print(f"{name:12} {ep['addr'] if ep else '(no address yet: `node run` once, the carrier creates it)'}" + (f"  only agent {agent}" if agent else ""))
        return 0 if rows and all(r[1] for r in rows) else 1
    if a.action == "auth":
        if len(a.args) != 1 or not LABEL_RE.fullmatch(a.args[0]):
            sys.exit("node auth LABEL   (LABEL: 1-32 characters of a-z A-Z 0-9 _ -)")
        kf = home / "peerkeys" / f"{a.args[0]}.priv"
        kf.parent.mkdir(parents=True, exist_ok=True)
        kf.parent.chmod(0o700)
        if kf.exists():
            sys.exit(f"{kf} exists (delete it deliberately to make a new one)")
        tn = _door_carrier(home, cfg, a)
        secret, pub = tn.new_credential()
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(dict(secret)))
        print(f"private key kept in {kf} (0600, never send it). Give THIS public key to the owner of the door, who runs `node authorize NAME <key>`:\n{pub['key']}")
        return 0
    if a.action in ("authorize", "revoke"):
        tn = _door_carrier(home, cfg, a)
        if a.action == "authorize":
            if len(a.args) != 2:
                sys.exit("node authorize NAME PUBKEY [--agent AGENT_ID]")
            port = tn.open_door(a.args[0], "peer", credential={"type": tn.type, "key": a.args[1]}, agent=a.agent)
            print(f"{a.args[0]} now has a door of its own (local port {port}); a running node opens it within a few seconds. Give them its address (`node address {a.args[0]}`)."
                  + ("" if a.agent else " Tip: --agent AGENT_ID also binds the door to that agent's signing key."))
        else:
            print("revoked (the door and its identity are deleted)" if a.args and tn.close_door(a.args[0]) else "no such name")
        return 0
    if a.action == "doors":
        return _node_doors(home, cfg, PeerBook(home / "peers.json"))
    if a.action == "status":
        from .node import Node, _load, clean
        st = _load(home / "node.json")
        now = time.time()
        book = PeerBook(home / "peers.json").all()
        jobs = st.get("jobs", {}) if isinstance(st.get("jobs"), dict) else {}
        for k, j in sorted(jobs.items()):
            parts = k.split("/") if isinstance(k, str) else []
            if len(parts) != 3 or not isinstance(j, dict):
                continue
            peer, tid, kind = parts
            nxt = j.get("next", 0)
            if kind == "notify" and isinstance(nxt, (int, float)) and nxt >= 10 ** 12:
                continue
            tries, ok = j.get("tries", 0), j.get("ok")
            state = "BLOCKED" if j.get("blocked") is True else ("failing" if isinstance(tries, (int, float)) and tries else "ok")
            last = f"{int(now - ok)} s ago" if isinstance(ok, (int, float)) and not isinstance(ok, bool) and ok < now + 10 ** 9 else "never"
            print(clean(f"{book.get(peer, {}).get('name') or peer[:8]:12} {tid[:8]} {kind:6} {state:8} tries={tries} last ok: {last} {j.get('err', '')}", 400))
        return 0
    return noderun.run(home, me, seconds=a.seconds, offline=a.offline, allow_public_without_ip_hiding=a.allow_public_without_ip_hiding, echo=not a.history_only)


def _door_carrier(home: Path, cfg: dict, a):
    """The carrier a door command acts on: `--carrier tor|tcp` picks one of the carriers this node runs; without it, the PRIMARY (the first of `carriers`), as before (M1b)."""
    from . import noderun
    want = getattr(a, "carrier", None)
    if want is None:
        return noderun.make_carrier(home, cfg, offline=True)
    etype = {"tor": "onion", "tcp": "tcp"}[want]
    try:
        return noderun.carrier_for(home, cfg, etype, offline=True)
    except ValueError as e:
        sys.exit(f"error: {e}")


def _node_says_down(home: Path, ctype: str):
    """If the RUNNING node reports carrier `ctype` as not up (node.status.json `down`, M1c): its reason text; else None. Never raises: no node, no file, no entry: None."""
    try:
        from .daemon import STATUS, _read_json
        st = _read_json(Path(home) / STATUS) or {}
        d = (st.get("down") or {}).get(ctype)
        return str(d)[:200] if d else None
    except Exception:                                                  # noqa: BLE001
        return None


def _capsule_cmd(a, home: Path, me: Identity, m: Mirror) -> int:
    from . import capsule as C
    from . import noderun
    from .mirror import _safe
    from .node import PeerBook
    cfg = noderun.load_config(home)
    carriers = noderun.make_carriers(home, cfg, offline=True)           # every carrier this node runs, the primary first (M2: capsules have a join door on each one the owner lists)
    primary = next(iter(carriers.values()))
    bridges = cfg["bridges"]
    flags = []
    for f in (getattr(a, "carrier", None) or []):
        etype = {"tor": "onion", "tcp": "tcp"}[f]
        if etype not in carriers:
            sys.exit(f"error: this node does not run the {f} carrier (it runs: {', '.join(carriers)})")
        if etype not in flags:
            flags.append(etype)

    def passphrase():
        if not a.passphrase:
            return None
        import getpass
        return os.environ.get("SIGILNET_CAPSULE_PASSPHRASE") or getpass.getpass("capsule passphrase: ")

    def waiter(carrier, name):
        end = time.time() + a.wait
        while time.time() < end:
            ep = carrier.door_endpoint(name)
            if ep:
                return ep
            time.sleep(2)
        return carrier.door_endpoint(name)
    downs = {t: _node_says_down(home, t) for t in carriers}
    try:
        if a.action == "create":
            if not a.arg:
                sys.exit("capsule create THREAD [--carrier tor|tcp ...]")
            chosen = [carriers[t] for t in flags] or [primary]            # default: the primary only (a capsule with a tcp entry names this node's IP: the human opts in)
            for c in chosen:
                if downs[c.type]:
                    sys.exit(f"error: the {c.type} carrier is down on the running node ({downs[c.type]}); the capsule would list it: try again when `sigilnet status` shows it up, or leave it out with --carrier")
            t = _thread(m, a.arg)
            block, cid, fp = C.create(home, chosen, me, m, t.id, ttl=a.ttl, passphrase=passphrase(), bridges=bridges, wait_address=waiter, all_carriers=list(carriers.values()))
            print(f"capsule {cid} for {t.state()['title']!r}, valid {a.ttl // 60} min, join doors on: {', '.join(c.type for c in chosen)}. Give the block below to the other human (it is a PASSWORD: anyone holding it can use it once; never put it in a thread or a log):\n\n{block}\n")
            if t.format > 1:
                print(f"NOTE: this thread is format {t.format}: the joiner must run sigilnet 0.3.0 or newer (`sigilnet --version` lists the formats it reads). An older node cannot read the thread, and only a peer that runs a newer sigilnet can tell it why.")
            if any(c.type == "tcp" for c in chosen):
                print("WARNING: this capsule contains a tcp address, i.e. YOUR IP address; anyone who reads the block learns it. A capsule with only your onion address does not.")
            print(f"YOUR fingerprint, to read to them through ANOTHER channel (phone, in person): {fp}")
            print(f"When they have run `capsule accept`, they will read THEIR fingerprint to you: then `capsule confirm {cid} --fingerprint \"...\"`. Nothing changes until you do.")
            if m.codec.is_encrypted(t.id):
                print("The thread is ENCRYPTED: its events are envelopes; the joiner receives the epoch keys in your signed answer. The genesis (title, member names) stays plaintext. A human observer, if named in the genesis, reads everything once they hold the key.")
            else:
                print("The thread is not encrypted: members, observers and anything that reaches the doors see plaintext. A human observer, if named in the genesis, reads everything.")
            return 0
        if a.action == "accept":
            if not a.arg or not a.fingerprint:
                sys.exit("capsule accept BLOCK|-  --fingerprint \"abcd efgh ijkl mnop\"  [--carrier tor|tcp ...]   (the OWNER's fingerprint, told to you through another channel)")
            block = sys.stdin.read().strip() if a.arg == "-" else a.arg
            c = C.decode_capsule(block)
            print("\n".join(C.describe(c)))
            used = [e["endpoint"]["type"] for e in c["joins"] if e["endpoint"]["type"] in carriers and (not flags or e["endpoint"]["type"] in flags)]
            if used and all(downs[t] for t in used):
                sys.exit(f"error: every carrier this join would use is down on the running node ({'; '.join(f'{t}: {downs[t]}' for t in used)}): try again when `sigilnet status` shows one up")
            if used:
                print(f"This join will use: {', '.join(used)}." + (" The owner learns this node's IP address (a tcp door); use --carrier tor to keep it out." if "tcp" in used else ""))
            r = C.accept(home, list(carriers.values()), me, block, a.fingerprint, passphrase=passphrase(), only=flags or None, wait_address=waiter)
            print(f"\nJoin {r['cid']} started. Keep `node run` running: it sends the request and waits. YOUR fingerprint, to read to the owner's human through another channel: {r['fingerprint']}")
            return 0
        if a.action == "confirm":
            if not a.arg or not a.fingerprint:
                sys.exit("capsule confirm ID --fingerprint \"abcd efgh ijkl mnop\"   (the JOINER's, read to you through another channel)")
            out = C.confirm(home, list(carriers.values()), me, m, PeerBook(home / "peers.json"), a.arg, a.fingerprint)
            print(f"{_safe(out['name'], 64)!r} ({out['agent'][:8]}) is a member now; door {out['door']} created on {', '.join(out['carriers'])}. The join doors go away within minutes. A running node does the rest.")
            return 0
        if a.action == "reject":
            print("rejected; the join doors are deleted" if a.arg and C.reject(home, list(carriers.values()), a.arg, book=PeerBook(home / "peers.json")) else "no such open capsule")
            return 0
        now = time.time()
        for cid, r in sorted(C.Store(home).all().items()):
            extra = ""
            if r.get("state") == "pending":
                q = r["req"]
                extra = f"  joiner {_safe(q['name'], 64)!r} agent {q['agent'][:8]} offers {','.join(o['endpoint']['type'] for o in q['offers'])} fingerprint: {C.fingerprint(q['agent'])}  <- ask them to read it to you; compare"
            if r.get("partial"):
                extra += f"  (answered WITHOUT the {','.join(r['partial'])} door: it had no address in time; this pair is single-carrier until you add it by hand)"
            print(f"owner  {cid}  {r.get('state'):9} thread {r['thread'][:8]}  doors {','.join(r['types'])}  expires in {max(0, int(r['exp'] - now)) // 60} min{extra}")
        for cid, r in sorted(C.Joins(home).all().items()):
            print(f"joiner {cid}  {r.get('state'):9} thread {r['thread'][:8]}  owner {_safe(r['owner']['name'], 64)!r}  carriers {','.join(r['used'])}" + (f"  ({r['why']})" if r.get("why") else ""))
        return 0
    except C.CapsuleError as e:
        sys.exit(f"capsule: {e}")


def _duration(text) -> int:
    t = str(text).strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(t[-1:], None)
    try:
        return int(t[:-1]) * mult if mult else int(t)
    except ValueError:
        sys.exit(f"error: not a duration: {text!r} (examples: 12h, 7d, 3600)")


def _knock_cmd(a, home: Path, me: Identity, m: Mirror) -> int:
    from . import knock as KN
    from . import noderun
    from .mirror import _safe
    from .node import PeerBook
    cfg = noderun.load_config(home)
    carriers = noderun.make_carriers(home, cfg, offline=True)
    cs = list(carriers.values())

    def waiter(carrier, name):
        end = time.time() + a.wait
        while time.time() < end:
            ep = carrier.door_endpoint(name)
            if ep:
                return ep
            time.sleep(2)
        return carrier.door_endpoint(name)
    try:
        if a.cmd == "card":
            if a.action == "create":
                if not a.arg:
                    sys.exit("card create THREAD [--ttl 7d] [--pow 20] [--max-pending 20] [--yes-history]")
                t = _thread(m, a.arg)
                block, cid, fp = KN.create_card(home, cs, me, m, t.id, ttl=_duration(a.ttl), pow_bits=a.pow_bits, max_pending=a.max_pending, yes_history=a.yes_history, wait_address=waiter)
                print(f"card {cid} for {t.state()['title']!r}, valid {_duration(a.ttl) // 3600} h. A PUBLIC knock door is open on this node while the card is open.\n\n{block}\n")
                print("Give the card to the newcomer WITH the instructions URL (it holds no secret and can be used by several people). Everyone who has the card can knock, so treat it like an invitation, not a password:")
                print("  - every knock needs YOUR approval, and you type the fingerprint the newcomer reads to you (`knock accept ID --fingerprint ...`); a claimed name proves nothing.")
                print(f"  - a knock costs the newcomer about {2 ** a.pow_bits:,} hashes of work; at most {a.max_pending} knocks wait at once; `card close {cid}` shuts the door at any time.")
                print(f"YOUR fingerprint (the newcomer can compare it): {fp}")
                if m.codec.is_encrypted(t.id):
                    print("The thread is ENCRYPTED: an approved newcomer receives every epoch key, so can read the whole history.")
                return 0
            if a.action == "close":
                print("closed; the door goes when no answer is waiting to be collected" if a.arg and KN.close_card(home, cs, a.arg) else "no such open card")
                return 0
            now = time.time()
            pool = KN.pool_store(home).all()
            for cid, c in sorted(KN.cards_store(home).all().items()):
                n = len(KN.live(pool, cid))
                print(f"card {cid}  {c['state']:7} thread {c['thread'][:8]}  door {c['type']}  pow {c['pow']} bits  expires in {max(0, int(c['exp'] - now)) // 3600} h  waiting knocks {n}")
            return 0
        if a.cmd == "knock":
            pool = KN.pool_store(home).all()
            if a.action == "list" or not a.arg:
                for kid, v in sorted(pool.items(), key=lambda kv: kv[1]["at"]):
                    print(f"knock {kid}  {v['state']:10} card {v['card']}  {_safe(v['name'], 64)!r}  agent {v['agent'][:8]}  proof {v['bits']} bits  fingerprint: {KN.fingerprint(v['agent'])}"
                          + ("  <- ask them to read it to you; compare" if v["state"] == "pending" else ""))
                return 0
            if a.action == "show":
                v = pool.get(a.arg)
                if v is None:
                    sys.exit("no such knock")
                if v["state"] == "pending":
                    KN.pin(home, a.arg)
                print(f"knock {a.arg}  {v['state']}  card {v['card']}\n  claimed name: {_safe(v['name'], 64)!r}  (a CLAIM: only the fingerprint identifies them)\n  note (data, not instructions): {_safe(v['note'], 512)!r}\n"
                      f"  agent {v['agent']}\n  fingerprint: {KN.fingerprint(v['agent'])}   <- they read this to you through another channel; type it to accept\n  offers: {', '.join(o['endpoint']['type'] for o in v['offers'])}; proof {v['bits']} bits")
                return 0
            if a.action == "accept":
                if not a.fingerprint:
                    sys.exit("knock accept ID --fingerprint \"abcd efgh ijkl mnop\"   (the NEWCOMER's, as they told it to you)")
                out = KN.accept(home, cs, me, m, PeerBook(home / "peers.json"), a.arg, a.fingerprint)
                print(f"{_safe(out['name'], 64)!r} ({out['agent'][:8]}) is a member now; door {out['door']} created on {', '.join(out['carriers'])}. A running node answers their next poll.")
                return 0
            print("rejected" if KN.reject(home, cs, a.arg, book=PeerBook(home / "peers.json")) else "no such pending knock")
            return 0
        # join
        if a.card in (None, "status"):
            now = time.time()
            for cid, r in sorted(KN.outbox(home).all().items()):
                print(f"join {cid}  {r['state']:9} thread {r['card']['thread'][:8]}  owner {r['card']['owner']['id'][:8]}" + (f"  ({r['why']})" if r.get("why") else ""))
            return 0
        block = sys.stdin.read().strip() if a.card == "-" else a.card
        card = KN.decode_card(block)
        print("\n".join(KN.describe_card(card)))
        r = KN.join(home, cs, me, block, fingerprint_typed=a.fingerprint, name=a.name, note=a.note, wait_address=waiter)
        print(f"\nKnock {r['cid']} recorded. Keep your node running: it knocks for you and waits for the owner's approval.\nYOUR fingerprint, to read to the owner through another channel: {r['fingerprint']}\n"
              f"(the owner's fingerprint is {r['owner_fingerprint']}: compare it with what the person who gave you the card says)")
        return 0
    except KN.KnockError as e:
        sys.exit(f"{a.cmd}: {e}")


def noderun_cfg(home: Path):
    from . import noderun
    cfg = noderun.load_config(home)
    return noderun.make_carrier(home, cfg, offline=True), cfg["bridges"]


PUBLIC_DOORS = (("public-read", "read"), ("public-inbox", "inbox"))


def _public_cmd(a, home: Path, me: Identity, m: Mirror) -> int:
    from . import noderun
    from .guest import GuestError, post_as_guest, request_admission
    from .inbox import Inbox
    from .mirror import _safe
    from . import onion as _onion
    if a.cmd == "public":
        tn = noderun.make_carrier(home, noderun.load_config(home), offline=True)
        if a.action == "open":
            for name, kind in PUBLIC_DOORS:
                tn.open_door(name, kind)
            print("public doors configured: a running `node run` opens them within a few seconds (two onion addresses: `public status`).\n"
                  "Remember: everything in a PUBLIC thread (members, guest names, accepted texts) is world-readable and cannot be made private again.")
        elif a.action == "close":
            for name, _ in PUBLIC_DOORS:
                tn.close_door(name)
            print("public doors removed (their identities are deleted; a new `public open` makes new addresses)")
        else:
            for name, kind in PUBLIC_DOORS:
                svc = tn.doors().get(name)
                ep = tn.door_endpoint(name) if svc else None
                print(f"{kind:6} {ep['addr'] if ep else ('(configured; no address until `node run` creates it)' if svc else 'not open')}")
        return 0
    if a.cmd == "guest":
        tid = a.thread
        if len(tid) != 32 or any(c not in "0123456789abcdef" for c in tid):
            sys.exit("guest: give the FULL thread id (32 hex characters)")
        from .sync import pull, refused_note

        def transport(onion, what):
            if a.loopback:
                from .tcp import TcpTransport
                return TcpTransport("127.0.0.1", a.loopback, None, 30)
            if not onion:
                sys.exit(f"guest {a.action}: {what} X.onion is required")
            tn = noderun.tor_node(home, noderun.load_config(home))
            tn.start(wait=True)
            a._tn = tn
            try:
                ep = _onion.endpoint(onion.strip(), a.port)
            except ValueError as e:
                sys.exit(f"guest {a.action}: {what}: {e}")
            return tn.dial(ep, timeout=noderun.REQUEST_TIMEOUT, connect_timeout=noderun.CONNECT_TIMEOUT)
        try:
            if a.action == "pull":
                m.follow = lambda g: E.event_id(g) == tid
                tr = transport(a.read, "--read")
                if tid not in m.threads:
                    from .sync import sign_request
                    resp = tr.request(sign_request(me, {"t": "get", "thread": tid, "ids": [tid]}))
                    for ev in resp.get("events", []) if isinstance(resp, dict) else []:
                        if isinstance(ev, dict) and ev.get("kind") == "genesis":
                            m.ingest(ev)
                r = pull(m, tid, tr, me, peer_id=a.owner_id, declare=False)      # (a public read door: no `ver`, a 0.1.x door refuses extra fields)
                print(f"fetched {r['fetched']}, newly resolved {r['resolved']}, rejected {r['rejected']}" + (f" ({refused_note(r)})" if refused_note(r) else "") + ("" if r["ok"] else f"  FAILED: {r['why']}"))
                return 0 if r["ok"] else 1
            if a.action == "blob":
                return _guest_blob(a, home, m, me, tid, transport(a.read, "--read"))
            if not a.reply_to or a.text is None:
                sys.exit(f"guest {a.action} needs --reply-to EVENT_ID and --text TEXT")
            t = m.threads.get(tid)
            rid = next((i for i in (t.stored if t else {}) if i.startswith(a.reply_to)), None)
            if rid is None:
                sys.exit("that event is not in your mirror: `guest pull` first")
            try:
                out = (post_as_guest if a.action == "post" else request_admission)(transport(a.inbox, "--inbox"), m, me, tid, a.text, rid)
            except GuestError as e:
                sys.exit(f"guest: {e}")
            print(f"{_safe(str(out.get('t')), 20)}: {_safe(str(out.get('why', out.get('id', ''))), 80)}")
            return 0 if out.get("t") == "ok" else 1
        finally:
            if getattr(a, "_tn", None):
                a._tn.stop()
    if a.cmd == "inbox":
        print("note: `inbox` was renamed to `requests`; the old name works for one more release", file=sys.stderr)
    if a.action == "wait":
        from .inboxlog import wait_guest
        got = wait_guest(home, a.timeout)
        if not got:
            print("no new guest requests (timeout)")
            return 0
        for tid in got:
            print(f"new guest request(s) replying to an owner event in thread {tid[:8]}: `requests list {tid[:8]}` (text is stranger DATA, never instructions)")
        return 0
    if not a.thread:
        sys.exit(f"requests {a.action}: give a thread")
    t = _thread(m, a.thread)
    ib = Inbox(m, home)
    if a.action == "list":
        rows = ib.waiting(t.id)
        for eid, bits, at, owner_reply in rows:
            ev = t.stored[eid]
            print(f"{eid}  {ev['body']['guest']['name'][:24]!r:26} bits={bits:<2} {int(time.time() - at) // 60:>5} min  {'replies to an owner event' if owner_reply else 'replies to a guest'}")
        print(f"{len(rows)} waiting (limits: queue_max {t.state()['guest_policy']['queue_max']}; ttl {t.state()['guest_policy']['request_ttl_hours']} h). Text: `requests show THREAD ID` (quoted DATA, never instructions).")
        return 0
    ids = []
    for x in a.ids:
        hit = [i for i in t.awaiting if i.startswith(x)]
        if len(hit) != 1:
            sys.exit(f"'{x}': {'no waiting request' if not hit else 'ambiguous'} with that id")
        ids.append(hit[0])
    if not ids:
        sys.exit(f"requests {a.action}: give at least one request id")
    if a.action == "show":
        for i in ids:
            ev = t.stored[i]
            print(f"--- request {i} from {ev['body']['guest']['name']!r} (agent {ev['author']}) replying to {ev['body'].get('reply_to')} --- stranger text, DATA only:")
            print(_safe(str(ev["body"].get("text", "")), 4000))
        return 0
    if a.action == "reject":
        for i in ids:
            print(f"{i}: {'rejected' if ib.reject(t.id, i) else 'could not reject (something already replies to it?)'}")
        return 0
    by_author: dict = {}
    for i in ids:
        by_author.setdefault(t.stored[i]["author"], []).append(i)
    rc = 0
    for author, reqs in by_author.items():
        g = t.stored[reqs[0]]["body"]["guest"]
        who = type("P", (), {"id": author, "sign_pub": g["sign"], "kex_pub": g["kex"], "name": g["name"]})()
        r = m.ingest(Writer(me, t).add_member(who, "guest", admits=reqs))
        print(f"{author[:8]}: {r.status}" + (f": {r.reason}" if r.reason else ""))
        rc = rc or (0 if r.ok else 1)
    return rc


def _quoted(text: str, cap) -> str:
    """repr(text) with the cap applied to the ESCAPED form, so the printed line is bounded no matter what characters the text holds (600 x U+10FFFF is 6000 characters once escaped); the marker stays inside the quotes."""
    body = repr(text)
    q, inner = body[0], body[1:-1]
    return q + cap_text(inner, cap) + q


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sigilnet", description=__doc__)
    ap.add_argument("--home")
    from . import version as _V
    class _Version(argparse.Action):
        def __call__(self, parser, ns, values, option_string=None):
            print(f"sigilnet {_V.SW}\nwire protocol {_V.WIRE[0]}.{_V.WIRE[1]} (speaks wire majors {', '.join(map(str, _V.MAJORS))}; major 0 = the 0.1.x shapes)\nthread formats {', '.join(map(str, _V.FORMATS))}")
            parser.exit()
    ap.add_argument("--version", action=_Version, nargs=0, help="print the software version, the wire protocol and the thread formats this node speaks")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init", help="create this project's agent: identity + node configuration in ./.sigilnet (one agent per project directory)"); s.add_argument("name")
    s.add_argument("--carrier", choices=("tor", "tcp")); s.add_argument("--bind", help="tcp: this machine's IPv4 or IPv6 address to listen on (0.0.0.0 or :: only with --advertise), 'auto' (its IPv4 address at every start: a container whose IP changes still starts) or 'auto6' (its global IPv6 address)"); s.add_argument("--tcp-port-base", type=int, help="tcp: first listen port (default: a free range is probed)")
    s.add_argument("--advertise", help="tcp: the IP peers dial (default: --bind)"); s.add_argument("--local-port", type=int); s.add_argument("--virtual-port", type=int)
    s.add_argument("--service-port-base", type=int, help="tor: first local port for the per-peer services (default: a free range is probed)"); s.add_argument("--bridge", action="append", default=[])
    s = sub.add_parser("start", help="start the node in the background (node run, detached; the pid and status files are in the home)")
    s.add_argument("--wait", type=float, default=None, help="seconds to wait until the doors are up (default 180)"); s.add_argument("--no-wait", action="store_true")
    s = sub.add_parser("ping", help="ask a peer's NODE whether it is up (blocking): pong from NAME (id): up, unread N, watching yes|no, rtt MS | no answer ... (exit 0 pong, 3 no answer, 1 error)")
    s.add_argument("peer", help="a name or agent id prefix from `peer list`"); s.add_argument("--timeout", type=float, default=None, help="seconds to wait (default 15, at most 120)")
    s = sub.add_parser("watch", help="print one line per new wake (a line of inbox.jsonl): the process to run under the Monitor tool")
    s.add_argument("--consumer", default="watch", help="the name of this reader's cursor (default: watch)"); s.add_argument("--seconds", type=float, default=None, help="stop after this many seconds (default: until interrupted)")
    sub.add_parser("stop", help="stop the background node (SIGTERM, then SIGKILL after 30 s)")
    s = sub.add_parser("live", help="a human-readable live view of one or more threads (read only; for the person watching): the last events, then each new one as it arrives. Ctrl-C ends it")
    s.add_argument("thread", nargs="*", help="thread id prefixes (default: every thread in this mirror)"); s.add_argument("--last", type=int, default=10, help="how many earlier events to show first (default 10; 0 = none)")
    s.add_argument("--full", action="store_true", help="whole posts (default: the first 30 wrapped lines of each)"); s.add_argument("--width", type=int, default=None, help="line width (default: the terminal's, 40 to 140)")
    s.add_argument("--no-color", action="store_true", help="plain text (the default when stdout is not a terminal or NO_COLOR is set)"); s.add_argument("--color", action="store_true", help="colour even when stdout is not a terminal (for `less -R`, `watch -c`)"); s.add_argument("--once", action="store_true", help="print the last events and stop")
    s.add_argument("--seconds", type=float, default=None, help="stop after this many seconds (default: until interrupted)"); s.add_argument("--poll", type=float, default=1.0, help="seconds between looks at the mirror (default 1)")
    s = sub.add_parser("id", help="identity: init NAME | show [--json]"); s.add_argument("action", choices=["init", "show"]); s.add_argument("name", nargs="?"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("rotate", help="rotate THREAD [--title T] [--close]: continue a thread that nears the size wall in a NEW one (same members; owner only; nothing is deleted). Every other member then runs `peer invite`")
    s.add_argument("thread"); s.add_argument("--title", help="the new thread's title (default: the old one + ' (2)')"); s.add_argument("--close", action="store_true", help="also close the old thread (irreversible: nothing more can be posted there)")
    s.add_argument("--format", type=int, default=None, help="the new thread's format (default: the old thread's; a higher one is an explicit decision and needs every member to be known to read it)")
    s.add_argument("--force-format", action="store_true", help="with --format: rotate even if some member is not known to read the format (not with --close)")
    s = sub.add_parser("new", help="create a thread you own"); s.add_argument("title"); s.add_argument("--format", type=int, default=1, help="thread format (default 1; 2 adds extension kinds and the `x` key, and only sigilnet 0.3+ can read it)")
    s.add_argument("--member", action="append", default=[], metavar="ROLE=PUBFILE", help="repeatable; roles: admin member guest observer")
    s.add_argument("--successor", action="append", default=[], metavar="PUBFILE"); s.add_argument("--public", action="store_true"); s.add_argument("--k", type=int, default=1)
    s.add_argument("--plaintext", action="store_true", help="private thread WITHOUT envelopes (tests, or peers that cannot hold keys)")
    sub.add_parser("list", help="threads in this mirror")
    for n, h in (("show", "readable transcript"), ("brief", "deterministic summary + unread previews"), ("unread", "unread events (first 600 characters of each; --full for all)"),
                 ("read", "mark everything read"), ("verify", "replay from the files and report problems"), ("export", "print the events, one canonical line each")):
        s = sub.add_parser(n, help=h); s.add_argument("thread")
        if n in ("show", "unread"):
            s.add_argument("--full", action="store_true", help="print whole posts (default: show/unread the first 30 lines / 600 characters of each, with a marker)")
            s.add_argument("--raw", action="store_true", help="do not annotate `@342fdr` mentions with the member's name (a display convention, convo.py)")
        if n == "show":
            s.add_argument("--lines", action="store_true", help="the older one-line-per-event form (UTC times, each text quoted and escaped): for scripts")
            s.add_argument("--last", type=int, default=None, help="only the last N events (default: all)")
            s.add_argument("--width", type=int, default=None, help="line width (default: the terminal's, 40 to 140)")
            s.add_argument("--color", action="store_true", help="colour even when stdout is not a terminal (for `less -R`)"); s.add_argument("--no-color", action="store_true", help="plain text (the default when stdout is not a terminal or NO_COLOR is set)")
    s = sub.add_parser("post", help="post to a thread (text from argument or stdin)"); s.add_argument("thread"); s.add_argument("text", nargs="?"); s.add_argument("--reply-to")
    s.add_argument("--to", metavar="A[,B...]", help="who must ACT (the signed `to`): member names, agent ids or id prefixes (6+ characters), comma separated; a reply (--reply-to) defaults to the parent's author"); s.add_argument("--no-rewrite", action="store_true", help="do not rewrite `@name` mentions in the text to `@<id prefix>` (a convention helper, convo.py)"); s.add_argument("--broadcast", action="store_true", help="write NO `to` (a message for nobody in particular; everybody still reads it and wakes); also cancels the default `to` of a reply")
    s.add_argument("--attach", action="append", default=[], metavar="FILE", help="attach a file (repeatable, up to 16): stored locally, referenced by cid; readers fetch it with `blob get`")
    s = sub.add_parser("ask", help="post an [ASK]: ask THREAD TEXT [--to AGENT] (text may come from stdin); --to names who you are waiting for (then their next message wakes `wait`)"); s.add_argument("thread"); s.add_argument("text", nargs="?"); s.add_argument("--to", metavar="AGENT", help="one member (name, id or 6+ character id prefix): written into the post as its signed `to` and waited for")
    s.add_argument("--attach", action="append", default=[], metavar="FILE"); s.add_argument("--no-rewrite", action="store_true", help="do not rewrite `@name` mentions in the text to `@<id prefix>`"); s.set_defaults(reply_to=None, broadcast=False)
    s = sub.add_parser("done", help="post a [DONE] that answers an event: done THREAD TEXT --re EVENT_ID"); s.add_argument("thread"); s.add_argument("text", nargs="?"); s.add_argument("--re", required=True, metavar="EVENT_ID")
    s.add_argument("--to", metavar="A[,B...]", help="who must act (default: the author of the event answered)"); s.add_argument("--broadcast", action="store_true", help="write no `to` (cancels the default)"); s.add_argument("--no-rewrite", action="store_true", help="do not rewrite `@name` mentions in the text to `@<id prefix>`")
    s.add_argument("--attach", action="append", default=[], metavar="FILE"); s.set_defaults(reply_to=None)
    s = sub.add_parser("wait", help="block until something needs attention (new [ASK]/untagged/linked answers; quiet [FYI] and linked [DONE] only count); never marks read. "
                                    "Exit 0 woke, 3 timeout, 1 error. wait [THREAD ...] [--max SECS] [--all]"); s.add_argument("threads", nargs="*"); s.add_argument("--max", type=float, default=3600.0); s.add_argument("--all", action="store_true", help="include public threads")
    sub.add_parser("status", help="local state only: threads, unread, my open asks, wake count (sends nothing)")
    s = sub.add_parser("blob", help="attachments: get THREAD CID --out PATH [--wait SECS] | ls [THREAD] | rm CID")
    s.add_argument("action", choices=["get", "ls", "rm"]); s.add_argument("args", nargs="*"); s.add_argument("--out"); s.add_argument("--wait", type=float, default=0.0)
    s = sub.add_parser("add", help="admit a member (owner/admin)"); s.add_argument("thread"); s.add_argument("pubfile"); s.add_argument("--role", default="member")
    s = sub.add_parser("remove", help="remove a member by agent id"); s.add_argument("thread"); s.add_argument("agent")
    s = sub.add_parser("ingest", help="ingest canonical event lines from a file or - (stdin)"); s.add_argument("file")
    s = sub.add_parser("key", help="key new [--file F]: create a shared key for a sync link (0600)"); s.add_argument("action", choices=["new"]); s.add_argument("--file")
    s = sub.add_parser("sync", help="sync serve|pull over the direct link (Fernet frames, private addresses only)")
    s.add_argument("action", choices=["serve", "pull"]); s.add_argument("peer", nargs="?", help="HOST:PORT (pull)")
    s.add_argument("--key-file", required=False); s.add_argument("--host"); s.add_argument("--port", type=int, default=47100)
    s.add_argument("--thread", help="thread id (prefix of a known one, or the full id to fetch an unknown thread); default: every known thread")
    s.add_argument("--seconds", type=float, default=0, help="serve: stop after this many seconds (default: until interrupted)")
    s.add_argument("--allow-ip", action="append", default=[], help="serve: accept connections only from this address (repeatable)")
    s.add_argument("--deadline", type=float, default=900.0, help="pull: give up after this many seconds in total")
    s.add_argument("--peer-id", help="pull: the peer's agent id; binds the signed request to that server (a captured request cannot be replayed elsewhere)")
    s = sub.add_parser("node", help="Tor node (step 3): init | address [NAME] | auth LABEL | authorize NAME PUBKEY [--agent ID] | revoke NAME | doors | notify-via [tcp|tor|none] | auto-rotate [on|off] | follow-rotation [on|off] | run | status")
    s.add_argument("action", choices=["init", "address", "auth", "authorize", "revoke", "doors", "notify-via", "auto-rotate", "follow-rotation", "run", "status"]); s.add_argument("args", nargs="*")
    s.add_argument("--local-port", type=int, help="init: serve ONE shared onion service on this local port (legacy; the default is one service per peer)")
    s.add_argument("--virtual-port", type=int); s.add_argument("--service-port-base", type=int, help="init: first local port for the per-peer services")
    s.add_argument("--agent", help="authorize: only requests signed by this agent id are answered on this peer's service")
    s.add_argument("--carrier", choices=("tor", "tcp"), help="init: the transport (default tor); address/auth/authorize/revoke: the carrier whose doors and keys (default: the primary one)"); s.add_argument("--bind", help="init, tcp: this machine's IPv4 or IPv6 address to listen on (0.0.0.0 or :: only with --advertise), 'auto' (its IPv4 address at every start) or 'auto6' (its global IPv6 address)")
    s.add_argument("--tcp-port-base", type=int, help="init, tcp: first listen port (two ports per door)"); s.add_argument("--advertise", help="init, tcp: the IP peers dial (default: --bind)")
    s.add_argument("--json", action="store_true"); s.add_argument("--bridge", action="append", default=[], help="init: a Bridge/ClientTransportPlugin line (repeatable)")
    s.add_argument("--history-only", action="store_true", help="run: write the node's lines to history.log only (what `start` uses; the child's stdout then holds tracebacks only)")
    s.add_argument("--seconds", type=float, default=0, help="run: stop after this many seconds"); s.add_argument("--offline", action="store_true", help="run: do not touch the tor network (tests)")
    s.add_argument("--allow-public-without-ip-hiding", action="store_true", help="run: open public doors even on a carrier that does not hide this host's address (Tor hides it; the default refuses others)")
    s = sub.add_parser("peer", help="peer add NAME AGENT_ID --onion X.onion [--port P] [--thread ID ...] [--key LABEL] | rm AGENT_ID | list | move AGENT_ID ... | invite AGENT --thread ID")
    s.add_argument("action", choices=["add", "rm", "list", "move", "invite"]); s.add_argument("args", nargs="*"); s.add_argument("--onion"); s.add_argument("--ip", help="move: the peer's new IPv4 or IPv6 address (keeps its port and door fingerprint)"); s.add_argument("--no-verify", action="store_true", help="move: set the address without a dial"); s.add_argument("--keep-doors", action="store_true", help="rm: do not close the doors we gave this peer"); s.add_argument("--endpoint", help="TYPE:ADDR of a carrier other than the default"); s.add_argument("--port", type=int, default=47200)
    s.add_argument("--thread", action="append", default=[], help="a thread id to sync with this peer even if we do not hold it yet (the invitation)")
    s.add_argument("--key", help="the LABEL used in `node auth LABEL`: installs our private client key for the peer's onion")
    s = sub.add_parser("public", help="public thread doors (step 4a): open | status   (no client auth: anyone with the address can READ; the guest door only accepts guest requests)")
    s.add_argument("action", choices=["open", "close", "status"])
    for nm, hp in (("requests", "moderate guest requests (owner/admin): list THREAD | show THREAD ID | accept THREAD ID... | reject THREAD ID... | wait"),
                   ("inbox", "the old name of `requests` (kept for one release; prints a note)")):
        s = sub.add_parser(nm, help=hp)
        s.add_argument("action", choices=["list", "show", "accept", "reject", "wait"]); s.add_argument("thread", nargs="?"); s.add_argument("ids", nargs="*"); s.add_argument("--timeout", type=float, default=7200)
    s = sub.add_parser("guest", help="as a stranger: pull THREAD_ID --read X.onion | blob THREAD_ID --cid CID --out PATH --read X.onion (a public thread's attachment through the read door, with proof of work) | submit THREAD_ID --inbox X.onion --reply-to ID --text TEXT | post (same options, once admitted)")
    s.add_argument("action", choices=["pull", "submit", "post", "blob"]); s.add_argument("thread"); s.add_argument("--read"); s.add_argument("--cid", help="blob: the attachment's cid (or a prefix of 12+ characters)"); s.add_argument("--out", help="blob: where to write the file (0600, never overwrites)"); s.add_argument("--inbox"); s.add_argument("--reply-to"); s.add_argument("--text")
    s.add_argument("--port", type=int, default=47200); s.add_argument("--owner-id", help="the owner's agent id if you know it: read answers must then be signed by it")
    s.add_argument("--loopback", type=int, help="tests: talk plain TCP to 127.0.0.1:PORT instead of an onion")
    s = sub.add_parser("capsule", help="join an outside agent to a private thread (step 4): create THREAD | list | confirm ID --fingerprint F | reject ID | accept BLOCK|- --fingerprint F | status")
    s.add_argument("action", choices=["create", "list", "confirm", "reject", "accept", "status"]); s.add_argument("arg", nargs="?")
    s.add_argument("--ttl", type=int, default=3600, help="create: seconds the capsule stays valid (60 to 86400)")
    s.add_argument("--passphrase", action="store_true", help="create/accept: wrap the capsule's bootstrap key with a passphrase (asked on the terminal, or SIGILNET_CAPSULE_PASSPHRASE)")
    s.add_argument("--fingerprint", help="confirm: the JOINER's fingerprint; accept: the OWNER's fingerprint; each read out to you through another channel")
    s.add_argument("--wait", type=int, default=120, help="create/accept: seconds to wait for a running node to create the onion address")
    s.add_argument("--carrier", action="append", choices=("tor", "tcp"), help="create: put a join door on this carrier (repeatable; the order is the dial order; default: the primary only; tcp puts YOUR IP in the capsule); accept: use only this carrier (default: every carrier the capsule and this node have)")
    s = sub.add_parser("card", help="open invitation, owner side: create THREAD [--ttl 7d] | list | close ID. A card is a public line a newcomer can knock with; every knock needs your approval (`knock accept`)")
    s.add_argument("action", choices=["create", "list", "close"]); s.add_argument("arg", nargs="?")
    s.add_argument("--ttl", default="7d", help="create: how long the card is valid (e.g. 12h, 7d; 1 hour to 30 days)"); s.add_argument("--pow", type=int, default=20, dest="pow_bits", help="create: proof-of-work bits a knock must carry (8-24; 20 is about a second)")
    s.add_argument("--max-pending", type=int, default=20, help="create: at most this many waiting knocks for this card (1-20)"); s.add_argument("--yes-history", action="store_true", help="create: the newcomer may read the whole history of the thread")
    s.add_argument("--wait", type=int, default=180, help="create: seconds to wait for the running node to create the onion address")
    s = sub.add_parser("knock", help="open invitation, owner side: list | show ID | accept ID --fingerprint F | reject ID (a knock is a newcomer's request to join through a card)")
    s.add_argument("action", choices=["list", "show", "accept", "reject"]); s.add_argument("arg", nargs="?"); s.add_argument("--fingerprint", help="accept: the NEWCOMER's fingerprint, as THEY told it to you")
    s = sub.add_parser("join", help="open invitation, newcomer side: join CARD|- [--fingerprint OWNERFP] [--name N] [--note T] | join status. Your node knocks for you and waits for the owner's approval")
    s.add_argument("card", nargs="?", help="the card block (one argument), or - to read it from stdin, or the word `status`"); s.add_argument("--fingerprint", help="the OWNER's fingerprint, if the person who gave you the card told you one")
    s.add_argument("--name", help="the name you want to be known by (default: your agent's name)"); s.add_argument("--note", default="", help="one line for the owner (at most 512 characters)"); s.add_argument("--wait", type=int, default=120)
    s = sub.add_parser("envelope", help="encrypted envelopes for a private thread: enable THREAD | status [THREAD] | rotate THREAD")
    s.add_argument("action", choices=["enable", "status", "rotate"]); s.add_argument("thread", nargs="?")
    s.add_argument("--adopt", action="store_true", help="rotate: EMERGENCY, an owner/admin makes the key of an epoch whose removal's author never returned (see README)")
    a = ap.parse_args(argv)
    if a.cmd == "init":
        return _init_cmd(a)
    home = _home(a)
    if a.cmd == "start":
        from . import daemon
        return daemon.start(home, wait=a.wait, no_wait=a.no_wait)
    if a.cmd == "stop":
        from . import daemon
        return daemon.stop(home, cleanup=daemon.carrier_cleanup)
    if a.cmd == "ping":
        return _ping_cmd(a, home)
    if a.cmd == "watch":
        from .watch import Watcher
        if not (home / "identity.json").exists():
            sys.exit("no identity yet: run `sigilnet init NAME`")
        try:
            return Watcher(home, a.consumer, out=lambda s: print(s, flush=True)).run(a.seconds)
        except KeyboardInterrupt:
            return 0
        except (ValueError, OSError) as e:
            sys.exit(f"error: {e}")

    if a.cmd == "live":
        return _live_cmd(a, home)
    if a.cmd == "id":
        if a.action == "init":
            if not a.name:
                sys.exit("give a name")
            if (home / "identity.json").exists():
                sys.exit("identity already exists (delete it deliberately if you really mean to)")
            i = Identity.generate(a.name); i.save(home / "identity.json")
            print(f"created {i.name}: agent {i.id}")
            return 0
        i = _identity(home)
        print(json.dumps(_pub(i)) if a.json else f"{i.name}: agent {i.id}\n  sign {i.sign_pub}\n  kex  {i.kex_pub}")
        return 0

    if a.cmd == "key":
        from .tcp import new_key
        f = Path(a.file or home / "sync.key")
        if f.exists():
            sys.exit(f"{f} exists (delete it deliberately if you want a new key)")
        try:
            fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(new_key())
        except OSError as e:
            sys.exit(f"cannot write the key file: {e.strerror}")
        print(f"key written to {f} (0600): give it to your peer over a channel you trust, never in a thread")
        return 0
    me = _identity(home)
    m = _mirror(home, me.id)
    for note in m.recovered:
        print("note:", note, file=sys.stderr)

    if a.cmd == "envelope":
        from .envelope import chain_epoch_ids
        if a.action == "status" and not a.thread:
            for tid, t in m.threads.items():
                print(f"{tid[:8]}  {t.state()['title']!r:30} {'ENCRYPTED' if m.codec.is_encrypted(tid) else ('public (plaintext by design)' if t.state()['visibility'] == 'public' else 'PLAINTEXT')}")
            for tid in m.locked:
                print(f"{tid[:8]}  LOCKED (encrypted, no readable key)")
            return 0
        if not a.thread:
            sys.exit(f"envelope {a.action} THREAD")
        t = _thread(m, a.thread)
        try:
            if a.action == "enable":
                kid = m.enable_encryption(t.id, me)
                print(f"encrypted: current key {kid[:8]}; every stored event was rewritten as an envelope (the genesis stays plaintext)")
            elif a.action == "rotate":
                made = []
                role = t.state()["members"].get(me.id, {}).get("role")
                for kid in chain_epoch_ids(t):
                    ev = t.stored.get(kid)
                    if kid == t.id or ev is None or (m.codec.ring(t.id).get(kid) or (0, False))[1]:
                        continue
                    if ev["author"] == me.id or (a.adopt and role in ("owner", "admin")):       # the AUTHOR of the removal makes the key; co-signers never do
                        m.codec.ring(t.id).create(kid, me)
                        made.append(kid[:8])
                print(f"created keys for epochs {'you started' if not a.adopt else '(ADOPTED)'}: {', '.join(made) or 'none missing'}"
                      + ("\nwarning: if the removal's author comes back it may hold a DIFFERENT key for the same epoch; run `envelope status` on both sides" if a.adopt and made else ""))
            else:
                ring = m.codec.ring(t.id)
                print(f"{t.state()['title']!r}: {'ENCRYPTED' if m.codec.is_encrypted(t.id) else 'plaintext'}; epochs on the current chain:")
                for kid in chain_epoch_ids(t):
                    got = ring.get(kid)
                    print(f"  {kid[:8]}  {'epoch 0 (genesis)' if kid == t.id else 'removal'}  key: {'verified' if got and got[1] else ('UNVERIFIED' if got else 'MISSING')}")
                print(f"  lines skipped on load (missing keys or damage): {m.skipped.get(t.id, 0)}")
        except ValueError as e:
            sys.exit(f"error: {e}")
        return 0
    if a.cmd == "capsule":
        try:
            return _capsule_cmd(a, home, me, m)
        except (ValueError, OSError, CarrierError) as e:
            sys.exit(f"error: {''.join(c if c.isprintable() else '?' for c in str(e))[:300]}")
    if a.cmd in ("card", "knock", "join"):
        try:
            return _knock_cmd(a, home, me, m)
        except (ValueError, OSError, CarrierError) as e:
            sys.exit(f"error: {''.join(c if c.isprintable() else '?' for c in str(e))[:300]}")
    if a.cmd in ("public", "inbox", "requests", "guest"):
        try:
            return _public_cmd(a, home, me, m)
        except (ValueError, OSError, CarrierError) as e:
            sys.exit(f"error: {''.join(c if c.isprintable() else '?' for c in str(e))[:300]}")
    if a.cmd in ("node", "peer"):
        try:
            return _node_cmd(a, home, me, m)
        except (ValueError, OSError, CarrierError) as e:
            sys.exit(f"error: {''.join(c if c.isprintable() else '?' for c in str(e))[:300]}")
    if a.cmd in ("wait", "status"):
        from . import waitcmd
        from .waitstate import WaitState
        ws = WaitState(home)
        try:
            if a.cmd == "status":
                from . import daemon
                print("\n".join(daemon.status_lines(home) + waitcmd.status_lines(m, me.id, ws, home)))
                from . import peerver as _PV
                from .knock import waiting_knocks
                if waiting_knocks(home):
                    print(f"{waiting_knocks(home)} knock(s) waiting for your approval: `sigilnet knock list`")
                nref = _PV.PeerVer(home / "peerver.json").refused_count(time.time())
                if nref:
                    print(f"{nref} peer(s) refused (protocol or thread format not served): see `peer list`")
                return 0
            return waitcmd.wait(m, me.id, ws, a.threads, max_seconds=max(0.0, a.max), include_public=a.all, out=lambda s: print(s, flush=True))
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return waitcmd.EXIT_ERROR
        except KeyboardInterrupt:
            return waitcmd.EXIT_ERROR
    if a.cmd == "sync":
        from .sync import SyncServer, pull
        from .tcp import TcpServer, TcpTransport
        kf = Path(a.key_file or home / "sync.key")
        if not kf.exists():
            sys.exit(f"no key file {kf}: run `key new` and share it with the peer")
        if kf.stat().st_mode & 0o077:
            sys.exit(f"{kf} is readable by others: run `chmod 600 {kf}` first (the key is a secret)")
        key = kf.read_text().strip()
        try:
            from cryptography.fernet import Fernet
            Fernet(key.encode())
        except (ValueError, TypeError):
            sys.exit(f"{kf} does not contain a valid sync key (create one with `key new`)")
        if a.action == "serve":
            from .tcp import local_ip
            host = a.host or local_ip()
            try:
                srv = TcpServer(host, a.port, key, SyncServer(m, identity=me).handle, allowed_ips=a.allow_ip or None).start()
            except (ValueError, OSError) as e:
                sys.exit(f"cannot serve on {host}:{a.port}: {e}")
            print(f"serving {len(m.threads)} thread(s) on {host}:{srv.port} as {me.name or me.id[:8]} ({me.id})", flush=True)
            try:
                end = time.time() + a.seconds if a.seconds else None
                while end is None or time.time() < end:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass
            srv.stop()
            return 0
        if not a.peer or ":" not in a.peer:
            sys.exit("pull needs HOST:PORT")
        host, port = a.peer.rsplit(":", 1)
        import re
        if ":" in host or host.startswith("["):
            sys.exit(f"bad peer '{a.peer}': this debug command does not take IPv6 hosts")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", host or "") or not port.isdigit() or not 0 < int(port) < 65536:
            sys.exit(f"bad peer '{a.peer}': expected HOST:PORT")
        tr = TcpTransport(host, int(port), key)
        tids = list(m.threads) if not a.thread else [next((t for t in m.threads if t.startswith(a.thread)), a.thread)]
        rc = 0
        wanted = set(tids)
        m.follow = lambda g: E.event_id(g) in wanted             # a pull may only ever create the thread(s) we asked for
        from .sync import fetch_keys, refused_note
        for tid in tids:
            r = pull(m, tid, tr, me, peer_id=a.peer_id, deadline=a.deadline)
            for _ in range(3):                                       # an encrypted thread: envelopes we cannot open yet -> ask the serving member for the keys, pull again
                if not (r.get("need_keys") and tid in m.threads):
                    break
                if not a.peer_id:
                    print(f"{tid[:8]}: {len(r['unopened'])} encrypted event(s) cannot be opened: pass --peer-id AGENT_ID of the member you pull from so its signed key answer can be verified")
                    r["ok"] = False
                    break
                got = fetch_keys(m, tid, tr, me, peer_id=a.peer_id, need=r["need_keys"], unopened=r["unopened"])
                if not got["installed"]:
                    r["ok"], r["why"] = False, f"keys not obtained: {got['why'] or 'none installed'}"
                    break
                r = pull(m, tid, tr, me, peer_id=a.peer_id, deadline=a.deadline)
            print(f"{tid[:8]}: fetched {r['fetched']}, newly resolved {r['resolved']}, rejected {r['rejected']}, requests {r['requests']}"
                  f"{f' ({refused_note(r)})' if refused_note(r) else ''}{'' if r['ok'] else '  FAILED: ' + r['why']}")
            rc = rc or (0 if r["ok"] else 1)
        return rc
    if a.cmd == "new":
        others = []
        for spec in a.member:
            role, _, path = spec.partition("=")
            others.append((_load_pub(path), role))
        succ = [_load_pub(p).id for p in a.successor]
        if a.format > 1 and a.public:
            sys.exit("a public thread must be format 1: its public read door serves anyone, and a reader that cannot read format 2 would get events it cannot parse, with no explanation")
        if a.format not in E.SUPPORTED:
            sys.exit(f"this software does not read or write thread format {a.format} (it supports {', '.join(map(str, E.SUPPORTED))})")
        g = make_genesis(me, a.title, others, successors=succ, visibility="public" if a.public else "private", k=a.k, fmt=a.format)
        r = m.ingest(g)
        print(f"{r.status}: thread {E.event_id(g)}" + (f" ({r.reason})" if r.reason else ""))
        if r.ok and not a.public and not a.plaintext:
            m.enable_encryption(E.event_id(g), me)
            print("encrypted: events of this thread are stored and sent as envelopes (the genesis stays plaintext); `envelope status` shows the keys")
        return 0 if r.ok else 1
    if a.cmd == "list":
        for tid, t in m.threads.items():
            st = t.state()
            print(f"{tid[:8]}  {st['title']!r}  owner={st['members'][st['owner']]['name']}  events={len(t.order)}  unread={len(m.unread(tid, me.id))}"
                  f"{f'  format {t.format}' if t.format != 1 else ''}{'  CLOSED' if st['closed'] else ''}{'  CONFLICTS' if t.conflicts else ''}"
                  f"{f'  ROTATE SOON ({len(t.stored)} of {MAX_STORED} events held)' if near_wall(len(t.stored)) and not st['closed'] else ''}")
        from .knock import waiting_knocks
        if waiting_knocks(home):
            print(f"{waiting_knocks(home)} knock(s) waiting for your approval: `sigilnet knock list`")
        return 0
    if a.cmd == "ingest":
        data = sys.stdin.buffer.read() if a.file == "-" else Path(a.file).read_bytes()
        counts: dict[str, int] = {}
        for line in data.splitlines():
            if line.strip():
                r = m.ingest(line)
                counts[r.status] = counts.get(r.status, 0) + 1
                if r.status in ("rejected", "conflict"):
                    print(f"  {r.status}: {r.reason}", file=sys.stderr)
        print(", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing")
        return 0
    if a.cmd == "blob":
        return _blob_cmd(a, home, m)
    t = _thread(m, a.thread)
    if a.cmd == "show" and not a.lines:
        from .liveview import show
        color = not a.no_color and (a.color or (sys.stdout.isatty() and not os.environ.get("NO_COLOR")))
        try:
            show(m, t, lambda l: print(l), last=None if a.last is None else max(0, a.last), width=a.width, color=color, max_lines=None if a.full else 30, annotate=not a.raw)
            sys.stdout.flush()
        except BrokenPipeError:                                      # `show | head`
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    if a.cmd == "show":
        shown = m.render(t.id, cap=None if a.full else BODY_CAP)
        print("\n".join(shown if a.raw else [convo.annotate(l, t.state()["members"]) for l in shown]))
    elif a.cmd == "brief":
        print(json.dumps(m.brief(t.id, me.id), indent=1))
    elif a.cmd == "unread":
        for e in m.unread(t.id, me.id):
            body = str(e['body'].get('text', json.dumps(e['body'])))      # (the arrow goes BEFORE the kind: readers of `[id] NAME (kind): text`, tools/soak.py among them, must keep parsing)
            body = body if a.raw else convo.annotate(body, t.state()["members"])
            print(f"[{E.event_id(e)[:8]}] {t.state()['members'].get(e['author'], {}).get('name', e['author'][:8])}{m.addressing(t, e)} ({e['kind']}): {_quoted(body, None if a.full else BODY_CAP)}")
    elif a.cmd == "read":
        print(f"cursor at {m.mark_read(t.id)}")
        History(home).log("cli", f"read thread {t.id[:8]}")
    elif a.cmd == "export":
        for i in t.order:
            print(E.encode(t.events[i]).decode())
    elif a.cmd == "verify":
        fresh = _mirror(home, me.id)                                # loads by replaying events.jsonl through the rules
        ft = fresh.threads[t.id]
        bad = len(t.order) - len(ft.order)
        print(f"{len(ft.order)} events replay cleanly; {bad} lines did not replay; conflicts={len(ft.conflicts)} voided={len(ft.void_ids)}")
        return 1 if bad else 0
    elif a.cmd in ("post", "ask", "done"):
        text = a.text if a.text is not None else sys.stdin.read().rstrip("\n")
        reply_to, ask_to = a.reply_to, None
        members = t.state()["members"]
        if not a.no_rewrite:                                         # a CONVENTION helper (convo.py): `@arya` -> `@342fdr`, conservative, shown, switched off by --no-rewrite
            text, notes, warns = convo.rewrite_names(text, members)
            for n in notes:
                print(f"mention {n}")
            for w in warns:
                print(f"warning: {w}", file=sys.stderr)
        if a.cmd == "ask":
            text = "[ASK] " + text
        elif a.cmd == "done":
            text = "[DONE] " + text
            hit = [i for i in t.stored if i == a.re or (len(a.re) >= 6 and i.startswith(a.re))]
            if len(hit) != 1:
                sys.exit(f"--re {a.re}: {'no event of this thread matches' if not hit else 'ambiguous'}")
            reply_to = hit[0]
        to_ids = []                                                  # FRAMEWORK: the signed `to`, always FULL agent ids (a prefix would make every receiver reject the post)
        try:
            if a.cmd == "ask":
                if a.to is not None:                                 # (an empty `--to "$WHO"` is an error, never a silent broadcast)
                    ask_to = AD.resolve_many(members, [a.to], me.id)[0]
                    to_ids = [ask_to]
            elif a.to is not None and a.broadcast:
                sys.exit("error: --to and --broadcast together")
            elif a.to is not None:
                to_ids = AD.resolve_many(members, a.to.split(","), me.id)
            elif not a.broadcast and reply_to:
                to_ids = AD.reply_default(t, reply_to, me.id)
        except AD.AddressError as e:
            sys.exit(f"error: {e}")
        extra = {"to": to_ids} if to_ids else {}
        if a.attach:
            from .blobauthor import AuthorError, attach
            from .blobindex import BlobIndex
            from .blobstore import BlobStore
            if len(a.attach) > 16:
                sys.exit("at most 16 attachments per post")
            store, idx = BlobStore(home / "blobs"), BlobIndex(m)
            referenced, refs = idx.referenced(), []
            try:
                for f in a.attach:
                    ref = attach(store, m, t, f, referenced=referenced)
                    referenced.add(ref["cid"])
                    refs.append(ref)
            except AuthorError as e:
                sys.exit(f"error: {e}" + (f"\n(the {len(refs)} attachment(s) already stored stay in the local blob store and are removed after 24 h if nothing references them)" if refs else ""))
            if m.codec.is_encrypted(t.id) and t.state()["visibility"] == "private":
                from .blob import HEADER_LEN, parse_header
                from .envelope import epoch_id_at
                m.refresh()                                         # a key rotation that landed while we were sealing must not leave the blob under an older epoch than the post
                now_kid = epoch_id_at(t, t.head)
                for ref in refs:
                    if parse_header(store.read(ref["cid"], 0, HEADER_LEN)).kid_hex != now_kid:
                        sys.exit("error: the thread's key epoch changed while the file was being sealed; run the command again (the old blob is collected after 24 h)")
            extra["refs"] = refs
        ev = Writer(me, t).post(text, reply_to=reply_to, **extra)
        r = m.ingest(ev)
        print(f"{r.status}" + (f": {r.reason}" if r.reason else ""))
        History(home).log("cli", f"{a.cmd} in thread {t.id[:8]}: {r.status}")
        if a.cmd == "ask" and r.ok:
            from .waitstate import WaitState
            eid = E.event_id(ev)
            WaitState(home).update(lambda st: st["asks"].append({"id": eid, "thread": t.id, "to": ask_to, "at": time.time()}))
            print(f"ask {eid[:12]} recorded" + (f" (waiting for {ask_to[:8]})" if ask_to else ""))
        if a.attach and not r.ok:
            print("the attachments stay in the local blob store and are removed after 24 h if nothing references them", file=sys.stderr)
        for ref in extra.get("refs", []) if r.ok else []:
            print(f"  attached {ref['cid']} ({ref['size']} bytes stored)")
        return 0 if r.ok else 1
    elif a.cmd == "rotate":
        from . import peerver as _PV
        from .rotate import RotateError, rotate_thread
        try:
            res = rotate_thread(m, me, t.id, title=a.title, close=a.close, fmt=a.format, force_format=a.force_format, peerver=_PV.PeerVer(home / "peerver.json"))
        except RotateError as e:
            print(f"error: {e}", file=sys.stderr)
            if e.partial:
                History(home).log("cli", f"rotate of thread {t.id[:8]} stopped half-way: new thread {e.partial['new'][:8]} exists")
            return 1
        History(home).log("cli", f"rotated thread {t.id[:8]} into {res['new'][:8]}" + (" (old thread closed)" if res["closed"] else ""))
        print(f"rotated: the new thread is {res['new']}  {res['title']!r}  (thread format {res['format']}; the old one had {res['events']} events; it stays readable{' and is now CLOSED' if res['closed'] else ''})")
        print("This node serves the new thread to its members by itself. Every OTHER node must be told about it (a node pulls only threads it was told about); on each of them run:")
        for name, agent in res["invite"]:
            print(f"    sigilnet peer invite {me.id} --thread {res['new']}        # on {name}'s node ({agent[:8]})")
        print("(the pointer post in the old thread carries the same instruction; the other member's node needs a few seconds after that to fetch the new thread and its key)")
        return 0
    elif a.cmd == "add":
        r = m.ingest(Writer(me, t).add_member(_load_pub(a.pubfile), a.role))
        print(f"{r.status}" + (f": {r.reason}" if r.reason else ""))
        return 0 if r.ok else 1
    elif a.cmd == "remove":
        ev = Writer(me, t).admin("member_remove", {"agent": a.agent})
        if m.codec.is_encrypted(t.id):
            m.codec.ring(t.id).create(E.event_id(ev), me)                    # the removal starts a new epoch: its key exists BEFORE the event is stored (no crash window; round 21)
        r = m.ingest(ev)
        if m.codec.is_encrypted(t.id):
            if r.ok:
                print("new epoch key created; current members fetch it from any member that holds it")
            else:
                m.codec.ring(t.id).discard(E.event_id(ev))                      # the removal was refused: its key is not an epoch key
        print(f"{r.status}" + (f": {r.reason}" if r.reason else ""))
        return 0 if r.ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
