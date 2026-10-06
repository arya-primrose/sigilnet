# DESIGN_tor_restart.md (S1, draft rev 0, 2026-10-01 : a bounded carrier restart inside `node run`

## Problem (observed in the 6 h soak, both sides)
`node run` raises `CarrierError(retry=False)` as soon as `tor.healthy` is false and exits 1 (noderun.py main loop). A tor that dies (OOM, kill, crash) therefore
takes the whole node down; the soak driver restarted it, a real standalone node has no supervisor. Doors keep the same onion address across a restart (soak: the
address after the tor kill was identical), so a restart in-process is invisible to peers except for the gap.

## Proposal (about 40 lines in noderun.py, nothing in protocol modules)
In the loop, where `not tor.healthy` is now fatal:
1. Record the exit (log tail, time). Keep a list `restarts` of monotonic times.
2. Budget: at most `TOR_RESTARTS = 3` restarts inside any rolling `TOR_RESTART_WINDOW = 1800` s. Over budget: today's behaviour (error, exit 1, finally-block cleanup). So a crash loop still ends the node, loudly.
3. Backoff before restart: 5 s, 30 s, 120 s (by restarts in the window).
4. Restart = `tor.stop` (reaps the child, sets proc None), `tor.start(wait=True)` (already reusable: it returns early only if the child lives, runs `stop_stale`, rewrites the torrc, waits for Bootstrapped 100%), then `doors.sync` and the same door lines logged as at startup. `TorError` from start counts as a used restart and takes the same backoff path; it is not retried inside the same attempt.
5. During the restart the loop is blocked (up to BOOTSTRAP_TIMEOUT 180 s): no ticks, no worker progress, local CLI posts still land in the mirror (the CLI does not need tor) and sync after recovery. The backoff sleep checks KeyboardInterrupt like any sleep.
6. Output lines (greppable, exact): `carrier exited (<tail>); restart 1/3 in 5 s`, `carrier restarted (took N s); doors: <same lines>`, `carrier restart budget used (3 in 30 min): giving up`.
7. Offline/test carriers: the same path (FakeCarrier `healthy` can be flipped) so it is unit-testable without tor.

## Not doing
- No health probing of a LIVE tor (circuits, descriptor reachability): `healthy` stays "the child is alive". Silent-dead doors with an alive tor remain a known limit (the soak watched for it: none seen).
- No change to `Carrier` contract or arya_net/protocol modules; no auto-restart of the node itself (that is a supervisor's job).
- No change for `retry=True` start failures at first start (still fatal at startup: a bad config must not loop).

## Tests
Unit: flip `healthy` false, expect stop+start+doors.sync, same output lines; 4th exit inside the window gives exit 1; window rollover resets the budget; start raising TorError uses budget and backs off (injected clock/sleep); KeyboardInterrupt during backoff exits 0 cleanly with the finally-block run. One real-tor test (alone, not under parallel load): kill the tor child, node recovers, same door address, `sync` still works. Mutation-check each. Then a short live test (throwaway home, covered by the standing go) and a README line.

## Questions for Sansa
Q1 budget 3 per 30 min and backoff 5/30/120: ok? Q2 should an exhausted budget exit 1 (proposed) or keep running with doors down? Q3 anything in `Doors.sync` that assumes the carrier object's services are unchanged across a restart?
