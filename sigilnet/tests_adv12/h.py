"""Helpers for tests_adv12 (Sansa): P2 of DESIGN_node_daemon rev 3 (inbox.jsonl, history.log, watch, Mirror hook) tested against the FROZEN INTERFACE (section 14)
only. Nothing here imports an implementation detail beyond that section: InboxLog, History, Watcher, Mirror(me=, inbox=), Mirror.note_guest/rebuild_inbox."""
import json
import multiprocessing as mp
import os
import tempfile
import time
import unittest
from pathlib import Path

from sigilnet import inboxlog
from sigilnet.envelope import EnvCodec
from sigilnet.event import event_id
from sigilnet.inboxlog import InboxLog
from sigilnet.mirror import Mirror, UNREAD_KINDS
from sigilnet.tests.util import World

ENTRY_KEYS = {"seq", "t", "thread", "guest"}


class Clock:
    """A settable clock; `sleep` advances it, so a Watcher loop never really waits."""

    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, d):
        self.t += d


def entries(home) -> list:
    """The inbox.jsonl entries (not the {"gen"} line), parsed straight from the bytes, ignoring any torn line."""
    p = Path(home) / "inbox.jsonl"
    out = []
    for raw in (p.read_bytes().split(b"\n") if p.exists() else []):
        try:
            d = json.loads(raw)
        except ValueError:
            continue
        if isinstance(d, dict) and "seq" in d:
            out.append(d)
    return out


def raw_gen(home):
    first = (Path(home) / "inbox.jsonl").read_bytes().split(b"\n")[0]
    return json.loads(first)["gen"]


class Env:
    """A home directory (identity.json = 'hu', the observer, so every peer event is wake-worthy), a Mirror with me=/inbox=, and a World to build events with."""

    def __init__(self, visibility="public", extra_members=(), me="hu", inbox_clock=None, rate_limit=False, encrypt=True):
        self.home = Path(tempfile.mkdtemp(prefix="adv12_"))
        self.world = World(visibility=visibility, extra_members=list(extra_members))
        self.me = me
        self.ids = self.world.ids
        self.ids[me].save(self.home / "identity.json")
        self.rate_limit = rate_limit
        self.inbox_clock = inbox_clock
        self.codec = EnvCodec(self.home / "keys")
        self.m = self.open()
        assert self.m.ingest(self.world.genesis).ok
        self.tid = event_id(self.world.genesis)
        self.private = visibility == "private"
        if self.private and encrypt:
            self.m.enable_encryption(self.tid)

    def open(self, with_inbox=True) -> Mirror:
        kw = {"me": self.ids[self.me].id, "inbox": InboxLog(self.home, **({"clock": self.inbox_clock} if self.inbox_clock else {}))} if with_inbox else {}
        return Mirror(self.home / "mirror", codec=EnvCodec(self.home / "keys"), rate_limit=self.rate_limit, **kw)

    def post(self, name, text="hi", m=None, **kw):
        ev = self.world.w(name).post(text, **kw)
        eid = self.world.add(ev)
        res = (m or self.m).ingest(ev)
        return eid, res

    def admin(self, name, kind, body):
        ev = self.world.w(name).admin(kind, body)
        eid = self.world.add(ev)
        return eid, self.m.ingest(ev)

    def lines(self) -> list:
        return entries(self.home)

    def unread(self, m=None) -> list:
        m = m or self.m
        m.refresh()
        return m.unread(self.tid, self.ids[self.me].id)

    def events_file(self) -> Path:
        return self.home / "mirror" / "threads" / self.tid / "events.jsonl"


def _author_proc(home, me_id, ident_path, tid, n, tag):
    from sigilnet.build import Writer
    from sigilnet.keys import Identity
    m = Mirror(Path(home) / "mirror", codec=EnvCodec(Path(home) / "keys"), rate_limit=False, me=me_id, inbox=InboxLog(home))
    ident = Identity.load(ident_path)
    for k in range(n):
        m.refresh()
        ev = Writer(ident, m.threads[tid]).post(f"{tag}-{k}")
        r = m.ingest(ev)
        if not r.ok:
            os._exit(3)


def run_authors(env: Env, names, n):
    """One process per author, each ingesting n posts of its own into the SAME home concurrently."""
    ctx = mp.get_context("fork")
    ps = []
    for nm in names:
        p = env.home / f"ident-{nm}.json"
        env.ids[nm].save(p)
        ps.append(ctx.Process(target=_author_proc, args=(str(env.home), env.ids[env.me].id, str(p), env.tid, n, nm)))
    for p in ps:
        p.start()
    for p in ps:
        p.join(120)
    return [p.exitcode for p in ps]
