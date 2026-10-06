"""An independent random-history generator (round 2): admin k-of-n, admins, guests admitted mid-history, several removals (also of an admin),
owner_transfer, takeovers, close, checkpoints, stale-view writers, replies to voided events, forks of admin events. Every event is built from a
random recent snapshot of the reference thread (a stale view), so concurrency is real."""
import copy
import random

from sigilnet import event as E
from sigilnet.event import event_id
from sigilnet.thread import Thread

from .util2 import Net

WRITERS = ("owner", "admin", "member", "guest")


def build(seed, steps=None, allow_close=True, guests_on=True):
    rnd = random.Random(seed)
    k = rnd.choice([1, 1, 2])
    roles = {"sansa": "admin", "carol": "member", "dave": "member"}
    net = Net(roles=roles, successors=rnd.choice([("carol", "dave"), ("dave", "carol"), ("carol",), ("carol", "dave")]), k=k,
              visibility="public")
    ref = net.ref
    seq = {n: 0 for n in net.ids}
    seq["arya"] = 1
    snaps = [copy.deepcopy(ref)]
    fresh_agents = ["erin", "hu"]
    guests = ["g1", "g2", "g3"] if guests_on else []
    open_reqs = []                       # (name, request id)
    closed = False

    def keep(ev, who):
        r = ref.accept(ev)
        if r.status in ("accepted", "voided", "awaiting"):
            net.events.append(ev)
            seq[who] += 1
            snaps.append(copy.deepcopy(ref))
            snaps[:] = snaps[-6:]
            return True
        return False

    def parents_of(view, extra=()):
        tips = view.tips()
        ps = set(extra)
        if tips:
            ps |= set(rnd.sample(tips, min(len(tips), rnd.choice([1, 1, 2]))))
        if not ps or rnd.random() < 0.15:
            ps.add(rnd.choice(list(view.events)))            # also voided / old events (replies to tombstones)
        return sorted(ps)

    def admin_ev(view, who, kind, body, cos=()):
        st = view.state()
        b = {"prev_admin": view.head, "owner_epoch": st["owner_epoch"], **body}
        ev = E.make_event(net.ids[who], thread=net.tid, kind=kind, body=b, parents=parents_of(view), seq=seq[who], admin_ref=view.head,
                          ts=rnd.randint(1, 50))
        for c in cos:
            ev = E.add_cosig(ev, net.ids[c])
        return ev

    def admins_in(view):
        return [net.name(a) for a in Thread.admin_set(view.state())]

    def cosigners(view, author):
        pool = [n for n in admins_in(view) if n != author]
        rnd.shuffle(pool)
        return pool[:max(0, view.state()["admin_threshold"] - 1)]

    for step in range(steps or rnd.randint(14, 26)):
        view = rnd.choice(snaps[-4:])
        st = view.state()
        mem = {net.name(a): m["role"] for a, m in st["members"].items()}
        r = rnd.random()
        if r < 0.45:
            cands = [n for n, ro in mem.items() if ro in WRITERS]
            if not cands:
                continue
            who = rnd.choice(cands)
            ps = parents_of(view)
            body = {"text": f"{who}{step}"}
            if rnd.random() < .4:
                body["reply_to"] = rnd.choice(ps)
            keep(E.make_event(net.ids[who], thread=net.tid, kind="post", body=body, parents=ps, seq=seq[who], admin_ref=view.head,
                              ts=rnd.randint(1, 50)), who)
        elif r < 0.52 and guests:
            g = guests.pop(0)
            owner_ev = [i for i in view.events if view.events[i]["author"] == st["owner"] and i not in view.void_ids]
            rt = rnd.choice(owner_ev or [net.tid])
            G = E.make_event(net.ids[g], thread=net.tid, kind="post", body={"text": "req " + g, "reply_to": rt, "guest": {
                "name": g, "sign": net.ids[g].sign_pub, "kex": net.ids[g].kex_pub}}, parents=[rt], seq=0, admin_ref=view.head, ts=rnd.randint(1, 50))
            if keep(G, g):
                open_reqs.append((g, event_id(G)))
        elif r < 0.60 and open_reqs and not st["closed"]:
            g, gid = open_reqs.pop(0)
            au = [n for n in admins_in(view)]
            if not au or g in mem:
                continue
            who = rnd.choice(au)
            cos = cosigners(view, who)
            ident = net.ids[g]
            ev = admin_ev(view, who, "member_add", {"agent": ident.id, "name": g, "role": rnd.choice(["guest", "guest", "member"]),
                                                     "sign": ident.sign_pub, "kex": ident.kex_pub, "admits": [gid]}, cos)
            keep(ev, who)
        elif r < 0.65 and fresh_agents and not st["closed"]:
            au = admins_in(view)
            a = fresh_agents.pop(0)
            if not au or a in mem:
                continue
            who = rnd.choice(au)
            ident = net.ids[a]
            keep(admin_ev(view, who, "member_add", {"agent": ident.id, "name": a, "role": "observer" if a == "hu" else "member",
                                                     "sign": ident.sign_pub, "kex": ident.kex_pub}, cosigners(view, who)), who)
        elif r < 0.73 and not st["closed"]:
            targets = [n for n, ro in mem.items() if ro != "owner"]
            au = admins_in(view)
            if not targets or not au:
                continue
            t = rnd.choice(targets)
            who = rnd.choice(au)
            seen = [s for (a, s) in view.by_author_seq if a == net.ids[t].id]
            last = max(seen or [-1]) + rnd.choice([0, 0, -1, 1])
            keep(admin_ev(view, who, "member_remove", {"agent": net.ids[t].id, "last_seq": max(-1, last)}, cosigners(view, who)), who)
        elif r < 0.78 and not st["closed"]:
            cands = [n for n, ro in mem.items() if ro != "owner"]
            if cands:
                who = rnd.choice(cands)
                seen = [s for (a, s) in view.by_author_seq if a == net.ids[who].id]
                keep(admin_ev(view, who, "revoke", {"agent": net.ids[who].id, "last_seq": max(seen or [-1])}), who)
        elif r < 0.85 and not st["closed"]:
            own = net.name(st["owner"])
            keep(admin_ev(view, own, "checkpoint", {"count": rnd.randint(0, 3) + st["cp_count"], "heads": sorted(rnd.sample(view.tips() or [net.tid], 1)),
                                                     "epoch": st["epoch"]}), own)
        elif r < 0.89 and not st["closed"]:
            own = net.name(st["owner"])
            cands = [n for n, ro in mem.items() if ro in ("admin", "member")]
            if cands:
                no = rnd.choice(cands)
                ev = admin_ev(view, own, "owner_transfer", {"new_owner": net.ids[no].id, "owner_epoch": st["owner_epoch"] + 1},
                              cosigners(view, own) + [no])
                ev = E.add_cosig(ev, net.ids[no]) if False else ev
                keep(ev, own)
        elif r < 0.95 and not st["closed"]:
            cands = [net.name(s) for s in st["successors"] if s in st["members"]]
            if cands:
                who = rnd.choice(cands)
                voters = [n for n, ro in mem.items() if ro in ("admin", "member") and n != net.name(st["owner"]) and n != who]
                keep(admin_ev(view, who, "owner_takeover", {"owner_epoch": st["owner_epoch"] + 1, "last_checkpoint": st["last_cp"]},
                              voters), who)
        elif r < 0.97 and allow_close and not st["closed"]:
            own = net.name(st["owner"])
            cut = {a: max(s for (b, s) in view.by_author_seq if b == a) for a in {a for (a, _) in view.by_author_seq}}
            keep(admin_ev(view, own, "close", {"cut": cut}, cosigners(view, own)), own)
        else:
            cands = [n for n, ro in mem.items() if ro in ("admin", "member", "owner")]
            if cands and not st["closed"]:
                who = rnd.choice(cands)
                keep(admin_ev(view, who, "rules_update", {"rules": {"checkpoint_every": rnd.randint(1, 90)}}, cosigners(view, who)), who)
    return net


def check_invariants(t: Thread, k_note=""):
    """Structural invariants that must hold in every reachable state."""
    problems = []
    st = t.state()
    owners = [a for a, m in st["members"].items() if m["role"] == "owner"]
    if owners != [st["owner"]]:
        problems.append(f"owner {st['owner']} vs role owners {owners}")
    for s in st["successors"]:
        if s not in st["members"] or st["members"][s]["role"] not in ("admin", "member"):
            problems.append(f"successor {s} is not an admin/member")
    if len(Thread.admin_set(st)) < st["admin_threshold"]:
        problems.append("admin set below k")
    if not (t.void_ids <= set(t.events)):
        problems.append("void id not in events")
    if set(t.lost_admin) & set(t.events):
        problems.append("an event is both lost and live")
    if t.head not in t.states:
        problems.append("head has no state")
    x, n = t.head, 0
    while x != t.id and n < 10000:
        x = t.events[x]["body"]["prev_admin"]; n += 1
    if x != t.id:
        problems.append("admin chain does not reach genesis")
    for i, e in t.events.items():
        for p in e["parents"]:
            if not (p in t.stored or p in t.lost_admin):
                problems.append(f"{i[:6]} has an unknown parent")
                break
    return problems
