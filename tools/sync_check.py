"""Print the [SYNC-CHECK] line for a thread from THIS home's mirror (design: DESIGN_persistent_thread.md rev 3, Sansa's change (a)):
    python tools/sync_check.py HOME THREAD_PREFIX
prints   [SYNC-CHECK] <name>=<last seq> <name>=<last seq> ...   one entry per author that has posts (own posts: the truth; the others: what this mirror holds).
Each side posts the line once a day and after a restart/outage and compares the OTHER author's number with what it holds: per-author seq is monotone, so
concurrent posting cannot cause a false mismatch; a lost middle event shows as a pending gap, a tail loss is caught by the next check. Read-only (opens the mirror, writes nothing)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sigilnet.home import open_mirror
from sigilnet.keys import Identity

home, prefix = Path(sys.argv[1]).expanduser(), sys.argv[2]
home = home / ".sigilnet" if (home / ".sigilnet").is_dir() else home
me = Identity.load(home / "identity.json")
m = open_mirror(home, me.id, poke=False)
tids = [t for t in m.threads if t.startswith(prefix)]
if len(tids) != 1:
    sys.exit(f"thread prefix {prefix!r} matches {len(tids)} threads")
t = m.threads[tids[0]]
st = t.state()
names = {a: (r.get("name") or a[:8]) for a, r in st["members"].items()}
last = {}
for (a, s) in t.by_author_seq:
    last[a] = max(last.get(a, -1), s)
from sigilnet.rotate import near_wall
from sigilnet.thread import MAX_STORED
if near_wall(len(t.stored)) and not st["closed"]:
    print(f"note: ROTATE SOON: {len(t.stored)} of {MAX_STORED} events held; `sigilnet rotate` (DESIGN_retention.md)", file=sys.stderr)
print("[SYNC-CHECK] " + " ".join(f"{names.get(a, a[:8])}={s}" for a, s in sorted(last.items(), key=lambda kv: names.get(kv[0], kv[0])) if a in names and st["members"][a]["role"] != "observer"))
