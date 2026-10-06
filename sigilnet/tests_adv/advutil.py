import copy

from sigilnet import event as E
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.keys import Identity
from sigilnet.thread import Thread
from sigilnet.tests.util import World, tmp_mirror  # noqa: F401


def resign(ev, ident, **changes):
    """Copy of ev with top-level fields changed and re-signed by ident."""
    out = copy.deepcopy(ev)
    out.update(changes)
    out.pop("cosigs", None)
    out["sig"] = ident.sign(E.sign_input(out))
    return out


def st(world, ev):
    return world.t.accept(ev)
