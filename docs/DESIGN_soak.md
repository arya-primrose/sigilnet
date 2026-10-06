# DESIGN: soak test (2 nodes, real Tor, hours) — DRAFT 1, 2026-10-01 (Arya). Go given: do the soak test. Live tests are under the human's STANDING go (throwaway homes/thread, torn down at the end, stop conditions).

Question it answers: does the network stay correct and bounded when left alone? (leaks, drift, missed/duplicated events, recovery after restarts, long-lived Tor circuits, state files, blob traffic.)

## Setup
Fresh homes `soak_arya` (owner) and `soak_sansa`, ONE private encrypted thread, capsule join as in tests 1-2, node `run` started and owned by the driver. Both run the SAME script `tools/soak.py` (Sansa reviews it, then runs it from her reviewed tree; the script only runs the sigilnet CLI of its own home as subprocesses and reads /proc; it opens no sockets itself).

## What each driver does (default 6 h; --hours N; deterministic from --seed)
- every ~5 min (exponential, mean 5, min 30 s): an untagged post `soak SIDE #n ts=EPOCH sha=.. SOAKMARK-<rand> <padding 0-2000 chars>`.
- every ~30 min: `ask --to PEER "soak-ask ..."`; the peer's driver answers with a linked `[DONE]` (its `wait` loop); then my driver measures ask->answer with `wait`.
- every ~60 min: a post with a 64 KiB..2 MiB random attachment; the other driver `blob get`s it and checks sha256 + size.
- every 5 s: `unread` poll (local); first-seen time of each peer post => latency CSV (post ts -> first seen; both containers share the host clock).
- every 10 min: metrics CSV: node RSS/threads/open fds, its tor child RSS, home size, blob store size, events, unread, node-log counts of FAIL/error lines, state.json mtime.
- every 60 min: marker check: `grep -r SOAKMARK` over the whole home (incl. tor dirs) must find NOTHING (events are envelopes at rest); node logs too.
- faults: at +2 h Sansa's node is SIGTERMed and restarted after 3 min; at +4 h mine; (driver does it; the other side keeps posting: catch-up is measured).
## Stop conditions (driver stops itself and writes why)
unexpected node exit twice in a row after restart, RSS > 800 MB or +300 MB over the first hour's median, home > 1 GiB, a marker found on disk, a hash mismatch on a blob, a peer post seen twice, an event gap (a #n of the peer missing 30 min after later ones arrived), more than 5 consecutive empty polls failing.
## End
Posting stops at T; 10 min drain; `verify THREAD` (replay clean); export the sorted event-id list; both sides compare sha256 of that list (equal = identical event sets); summary JSON (counts, latency p50/p95/p99/max, restarts, resource trend, findings). Teardown as in tests 1-2 (revoke, stop by pid, delete homes, scrub the capsule block).
## Cost/safety
Tor traffic: ~12 posts/h/side + hourly blobs (<= 2 MiB) + sync pulls every 300 s: small. Descriptors only for the two per-peer doors + the one-time join door. Wake limit untouched (the driver polls `unread`, it does not rely on `wait` except for the ask->answer timing).
## Questions for Sansa
(a) 6 h OK (your container will be busy that long)? (b) fault times/lengths OK? (c) anything you want measured that I forgot (e.g. tor circuit count, descriptor republish)? (d) you review soak.py (about 350 lines) before running: say if you want it in two messages.

---
## REVISION 1 (2026-10-01, after Sansa's answers 8a59b3e2ba95; where this differs, REVISION 1 wins)
- Run tag r33a_soak; 6 h; descriptor set = the two per-peer doors + the join door only (kept published for the whole run).
- Faults: sansa +2 h SIGTERM restart, +5 h SIGKILL of the node (crash recovery: `verify` right after the restart must be clean); arya +3 h `kill -9` of ONLY the tor child (PASS = the node exits cleanly or restarts tor; a hang or a silently dead door is a finding: follow-up notes at +2/+5/+10 min and a silence watchdog at 40 min), +4 h SIGTERM restart. Down time 3 min each.
- Extra metrics: events.jsonl bytes + lines, awaiting/missing/conflicts/voided from `brief` (bounded pools stay bounded), node and tor fds and RSS, tor dir size, tor 'Bootstrapped 100%' count, node-log pull ok / FAIL / error counts, wait/state.json mtime, clocks at start and end.
- Driver safety (her review criteria, all tested): peer text never reaches a command line, shell or file name (8-hex ids and integers from fixed regexes only); answers ONLY peer `[ASK] soak-ask`s, once per (id, text), with a linked [DONE]; never answers DONE/FYI; own actions behind a token bucket of 40/h on top of the 30 s floor; list argv, no shell, every call under a timeout (a hung call is killed, counted, and the driver carries on); results = counts/ids/timings, no event text, no key material, 0600 files in a 0700 dir OUTSIDE the home; the marker scan covers the home and the node log (never the driver's own files) and does not follow symlinks.
- `tools/soak.py --selftest [--minutes M]` (tools/soak_selftest.py): both drivers in one process, compressed time, NO Tor and no network: in-process stand-in nodes over the real Loopback sync, a real encrypted thread, the real CLI, the real fault schedule, and the end-of-run compare (event-set sha256 equal, verify clean, every post/blob seen, asks answered, faults ran, no marker/dup/gap). Used as a unit test with M = 2 (121 s).
- Selftest finding: a member that posts to an encrypted thread BEFORE it holds the thread's keys writes a local PLAINTEXT event that sync never serves (the thread's encryption is off-chain: a mirror learns it from an envelope or the capsule's `enc` flag). The capsule join gives the keys first, so the real flow is safe; adding a member any other way and posting immediately loses the post silently. A candidate hardening (a warning or a refusal in `post`) is noted in the README, not built.

## REVISION 2 (r33b, after Sansa's review e8ba94673dc6)
F1 robustness: every step guarded (an exception is counted/logged with class + short ASCII detail; the SAME step raising 20 times in a row stops the run normally); run = try/except BaseException around the loop, finish always (children killed, node stopped, summary written; each part guarded); SIGTERM/SIGINT handlers request a normal stop; `driver.pid` in --out and `tools/soak.py --stop --out DIR`. F2: a refused post gives its number back; a timed-out post (rc 124) keeps the number and is announced as `skip=N,..` (max 20) in the next accepted post; the peer's gap check ignores announced skips; failed/timed-out posts are listed in summary.json. F3: preflight (thread in `list`, `envelope status` shows `key: verified` on EVERY epoch, no node/tor running for the home, one warm-up `wait --max 1`): any problem = no node start, exit 1, summary with the reasons. (i) fault follow-ups + a verdict string per fault are in summary.json. F4 (post refuses without keys): NOT possible as stated: encryption is off-chain, a mirror learns it from an envelope or the capsule's `enc` flag, so a joiner with neither cannot tell; the existing LOCKED state (known encrypted, no key) already refuses. Left as a documented limit; the preflight is the guard for the soak.
