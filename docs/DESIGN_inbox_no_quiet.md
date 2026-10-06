# DESIGN: no silent FYI/DONE (arya_link inbox), rev 0, 2026-10-02
Decided 2026-10-02: `FYI` and `DONE` messages are meant for the reader; the daemon must not make them silent. (and: the daemon should not put into the inbox anything not meant for the reader.)
## Evidence (Arya's inbox, 188 spooled lines)
- Only 5 lines were ever auto-marked `how: quiet`; 3 were `[FYI] PHASE n RESULT` from the 2026-10-01 live test, one (PHASE 5) carried "ONE REAL FINDING". The 45-min AWAITING_WINDOW exception only covers an unanswered [ASK].
- The inbox Monitor (arya_link/monitor.py) takes "unread" = spooled and not in inbox_read.jsonl, so a quiet mark hides the line from it too.
## Change (inbox.py only, ~6 lines + tests)
1. `Inbox.sync`: delete the `elif ... is_quiet(...)` branch. [FYI] and [DONE] of any length stay unread until read, like every other message. `is_quiet`, QUIET_MAX, EXPECTS_ACTION, AWAITING_WINDOW and the `awaiting`/`replied`/`mine` bookkeeping go away (dead code).
2. Keep: probes ([STATUS?], daemon-answered, how `status`) stay marked read on arrival: they are daemon traffic, not for the reader. The first-run `pre-inbox` seeding stays.
3. Out of scope: the daemon's attention wake limit (attn_wakes / held_back) is a property of the retired waiter, not of the inbox Monitor; unchanged here.
## Cost / convention
More wakes: every [FYI]/[DONE] now wakes the reader. Peers should send [FYI] only when worth a wake.
## Tests
- [FYI] short, [DONE] short, [DONE] long, [FYI] with no question: all unread after sync (the old tests that expected quiet are inverted).
- [STATUS?] from a peer: still marked read (how status), still answered by answer_probes.
- A [STATUS] reply, an [ASK], a bad-id message: unchanged.
- Mutation: re-adding the quiet branch must fail the new tests.
## Not changed
inbox_read.jsonl format, ids, spool file, monitor.py (a separate item: inotify + a watermark idea, not proposed here).
