"""Where a node's home is (DESIGN_node_daemon.md section 3, P1).

First match wins: `--home DIR` > `$SIGILNET_HOME` > walk UP from the working directory for the nearest directory that holds `.sigilnet/` (like git).
There is no `~/.sigilnet` default: the walk never looks at `$HOME/.sigilnet`, and under `$HOME` it stops there (never above). A found `.sigilnet` is accepted only if it is
a real directory (no symlink) owned by us with mode 0700 and an `identity.json` that is a regular file owned by us; anything else is an error that names the
path, and the walk does NOT go on to a further ancestor (a planted or stray ancestor home would decide the carrier, the bind address and who we post as).
Nothing in this module creates a directory."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Mapping

DIRNAME = ".sigilnet"


class HomeError(ValueError):
    pass


def _check(d: Path) -> None:
    """d is a `.sigilnet` candidate found by the walk."""
    try:
        st = os.lstat(d)
    except OSError as e:
        raise HomeError(f"cannot look at {d}: {e.strerror}") from None
    if not stat.S_ISDIR(st.st_mode):
        raise HomeError(f"{d} is not a plain directory (a symlink or a file): not using it, and not looking further up")
    if st.st_uid != os.geteuid():
        raise HomeError(f"{d} is owned by another user: not using it, and not looking further up")
    if stat.S_IMODE(st.st_mode) != 0o700:
        raise HomeError(f"{d} has mode {stat.S_IMODE(st.st_mode):04o}, it must be 0700 (it holds private keys): fix it with chmod 700, it is not used until then")
    try:
        ist = os.lstat(d / "identity.json")
    except OSError:
        raise HomeError(f"{d} has no identity.json (an unfinished init?): run `sigilnet init NAME` in the project directory, or remove it") from None
    if not stat.S_ISREG(ist.st_mode) or ist.st_uid != os.geteuid():
        raise HomeError(f"{d}/identity.json is not a regular file owned by you: not using it")


def _walk(start: Path, home_dir: Path | None) -> Path | None:
    """The nearest `.sigilnet` at or above `start` (existing, not yet checked), or None. Under `home_dir` the walk stops AT it: `$HOME/.sigilnet` is never looked at."""
    d = Path(os.path.realpath(start))                              # BOTH sides resolved: a $HOME that is a symlink (or has "./", "//", a bind alias) must not let the walk slip past it
    under = home_dir is not None and (d == home_dir or home_dir in d.parents)
    while True:
        if under and d == home_dir:
            return None
        cand = d / DIRNAME
        if os.path.lexists(cand):
            return cand
        if d.parent == d:
            return None
        d = d.parent


def _home_dir(env: Mapping[str, str]) -> Path | None:
    h = env.get("HOME")
    return Path(os.path.realpath(h)) if h else None


def resolve_home(args_home, env: Mapping[str, str], cwd) -> Path:
    if args_home:
        return Path(args_home)
    if env.get("SIGILNET_HOME"):
        return Path(env["SIGILNET_HOME"])
    found = _walk(Path(cwd), _home_dir(env))
    if found is None:
        raise HomeError(f"no {DIRNAME} found from {Path(cwd)} upward; run `sigilnet init NAME` in the project directory")
    _check(found)
    return found


def shadowed(env: Mapping[str, str], cwd) -> Path | None:
    """A usable home in an ANCESTOR of `cwd` (what a new `init` here would hide), or None. Never raises: this only feeds a note."""
    real = Path(os.path.realpath(cwd))
    parent = real.parent
    if parent == real:
        return None
    found = _walk(parent, _home_dir(env))
    if found is None:
        return None
    try:
        _check(found)
    except HomeError:
        return None
    return found


def open_mirror(home, me: str, *, poke: bool = True):
    """The ONLY production way to build a Mirror (cli, `node run`, watch): it knows whose events are not wake-worthy (`me` = the agent id of the home's identity.json) and
    writes `inbox.jsonl`. `poke=True` (the CLI) also pokes `node.poke` after every append so a running node wakes at once; the node's own mirror passes False. A Mirror built any other way writes no wake lines at all, so a test greps the sources for any other construction site."""
    from .envelope import EnvCodec
    from .inboxlog import InboxLog
    from .mirror import Mirror
    home = Path(home)
    return Mirror(home / "mirror", codec=EnvCodec(home / "keys"), me=me, inbox=InboxLog(home), poke=(home / "node.poke") if poke else None)
