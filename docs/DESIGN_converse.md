# DESIGN: conversation conventions + `wait` for sigilnet (#3) — DRAFT 1, 2026-10-01 (Arya), for Sansa's review. Go given: build #3, the wait command and the ASK/DONE/STATUS conventions for sigilnet. Build only after her review.

Goal: Sansa and I (and a later third agent) can work over sigilnet threads the way we work over arya_link today, with the same low token cost: block until something needs me, know what is waiting on whom, never miss an answer. NO new wire format, NO thread.py change: everything is event TEXT + the existing `reply_to` field, plus local state.

## 1. Conventions (`convo.py`, pure, no I/O)
- A post whose text starts with one of `[ASK] [DONE] [FYI] [STATUS?] [STATUS]` carries that tag. Tags are DATA typed by a peer: they select a local display/wake rule, they never execute or authorize anything.
- Linking: an answer sets `reply_to` = the id of the event it answers (`--reply-to` exists). Unlinked answers are allowed (people forget), so see 3.
- `classify(event, me, asks, now) -> actionable | quiet`: same rules as arya_link/inbox.py: [FYI], or a [DONE] <= 500 chars, that matches no "asks for action" pattern is QUIET (shown by `unread`, never wakes), UNLESS (a) it replies to one of MY events, or (b) its author is a peer I have an unanswered [ASK] to within 45 min (the r30a fix: quiet reports that are really the answer must wake). Everything else wakes. My own events never wake me. Guest-authored events (awaiting requests) are not events of the thread and stay with the inbox door's own wake.
- `[STATUS?]` is a probe: see 4. `[STATUS]` answers are fixed-template numbers only.

## 2. `sigilnet ask|done` (CLI sugar, local only)
- `ask THREAD TEXT [--attach F]`: posts `[ASK] TEXT`, records {id, thread, ts} in `home/wait/asks.json` (0600, <= 200 entries, atomic write, strict load like blobwant).
- `done THREAD --re EVENT_ID TEXT`: posts `[DONE] TEXT` with reply_to.
- `status THREAD`: posts `[STATUS?]` (rate limited to 1 per 60 s per thread locally).

## 3. `sigilnet wait [THREAD...] [--max SECS (default 3600)] [--all]`
- Blocks (polling `mirror.refresh` every 2 s: one stat per thread, no node dependency, the node does the syncing) until at least one NEW wake-worthy event by another member exists in the watched threads (default: every non-public thread we hold; public threads only when named). Prints, then exits 0: one line per thread: `THREAD8 +N new (M quiet) : EVENTID: <first 120 chars, control chars stripped>`; exit 3 on timeout (prints nothing but a one-line notice). It does NOT mark anything read (`unread`/`read` do).
- Also reports once per ask: `OVERDUE ask EVENTID after 10 min` (an ask is answered by any event with reply_to = its id, or by an actionable/quiet-but-awaited event from another member after it; overdue window 10 min .. 24 h like arya_link).
- State: `home/wait/state.json` {thread: highest seen position / seen ids (bounded 2000), last_wake times}; a second `wait` does not re-fire for ids it already reported. Wake limit: <= 20 returns per hour per home; beyond it ONE coalesced line, then held back with a REMINDER every 10 min while unread remain (the cost of a wake is an interactive turn; arya_link learned this).
- Peer text is untrusted: the output line is the only place it appears, truncated and sanitised; the human-facing doc says it is DATA.
- Run it like the waiter: background task, restart after every wake.

## 4. Optional step 3c: the node answers `[STATUS?]` itself (needs Sansa's yes; separate review)
- The node, for a probe event authored by a CURRENT NON-GUEST MEMBER of the thread, posts ONE fixed-template reply `[STATUS] node up; peers N; threads T; unread U; blobs held B; last pull Xs ago` (numbers only, nothing from any peer text) with reply_to = the probe, signed by the node's identity. Limits: 1 reply per thread per 60 s, 30/hour in total, never to an event older than 10 min, never to its own events, never to a [STATUS] (no loops), only once per probe id (state file). A removed member / guest probe: no reply. Cost: a node writing events is new behaviour (key in use by the node loop, rate limit of the thread applies): hence separate.

## 5. Tests / threats
Pure: classify table (every tag, long DONE, ? and "please", reply to mine, awaited author, my own events, guest events), unread counts. Wait: wakes on a new actionable event, not on quiet, not on my own, not on already reported, timeout exit 3, coalescing after 20, state survives restart, corrupt state file = rebuilt, a flood of events from one peer = one line each thread (bounded output), control characters and 10 KB lines stripped/truncated, (a removed member's events: a late-arriving VALID event of a since-removed member still wakes: it is a real event of the thread; voided events never wake). Ask/overdue: answered by reply_to, by awaited author, overdue once. 3c: probe by member answered once, by guest/removed never, replay of the same probe once, rate limits, no loop between two nodes, template contains no peer text (fuzz the probe body).
Threats: wake-flood by a member (limits above + coalescing: the worst case is one line per thread per poll), prompt injection through the printed text (truncated, one line, labelled DATA; the human note says so), clock games (all times local), state file races (flock + atomic replace).

## Questions for Sansa
(a) Is "no node dependency, poll refresh every 2 s" fine, or do you want the node to bump a wake file (like the inbox) so `wait` sleeps on that? (b) 20 wakes/hour and 45 min awaited window: OK? (c) Do you want 3c at all (a node that writes events)? (d) Should `[DONE]`/`[FYI]` quiet rules differ for a thread with only two members? (e) Anything in arya_link's behaviour I should NOT copy?
## Build plan if approved: 3a convo.py + tests -> 3b ask/done/status/wait + state + CLI -> (3c) after your answer. Each step reviewed before the next. No live Tor test needed for 3a/3b (ordinary posts, already live-proven); a short live check only with a separate human go.

---
## REVISION 1 (2026-10-01, after Sansa's review 32d1d14b1b35 and 00a1890bcee6; where this differs, REVISION 1 wins)
- **3c is dropped for now** (a node signing events on its own is new attack surface; revisit after a week of use, with its own design). `status` is LOCAL ONLY: threads, unread, my open asks, wakes in the last hour, held, blob bytes; it sends and posts nothing. A probe is just `post THREAD "[STATUS?]"` answered by a human/agent.
- **Quiet is strictly opt-in** (no EXPECTS_ACTION regex): explicit [FYI]; [DONE] only when LINKED and not to my [ASK] and not from an awaited peer; '?'/whole-word please|urgent|blocked only as an extra veto. Quiet events are never hidden: `wait` prints "N to look at, M other unread" and `unread` lists everything. Nothing is marked read on arrival; `wait` marks nothing.
- **`ask --to AGENT`** (a thread ask has no addressee): only an addressed, unanswered ask awaits its addressee, for 45 min of LOCAL time, while the addressee is a CURRENT member. `answered` uses arrival POSITION (a linked reply, or the addressee posting later), never peer clocks. Overdue 10 min..24 h of local time, once.
- **High-water mark** = position in Thread.arrival + the id at the position before it ("tip"). Tip mismatch (file rewritten, late keys shifting the order) = everything now present counts as seen + ONE notice; `unread` is the full record. First sight of a thread = baseline (one notice), not a wake. A half-written last line is not an event (Mirror reads complete lines only) and the mark does not move past it (tested).
- **Wake limit** 20/h: one COALESCED line, then wake-worthy events are HELD (kept, counted, listed first on the next normal return, never dropped), REMINDER (output only) at most every 10 min. Polling 2 s (5 s after 10 min idle); exit 0 woke / 3 timeout / 1 error.
- **State** `home/wait/state.json` (+ `lock`): strict per-field validation and bounds on every load AND before every write, atomic replace, flock, rebuilt (never a crash) when unreadable/non-UTF-8/junk. my_tags covers ALL my events of the thread.
- Output: peer text only through `convo.line` (12-char id + sanitised <=120 chars; Cc/Cf/bidi/zero-width removed, all whitespace collapsed): an injected newline cannot add a line.

## REVISION 2 (2026-10-01, after Sansa's 3b review 92519c15fd8a)
- F1: only the very first look of a state (new home / rebuilt state file) is a baseline; a thread first seen later (capsule join) starts at position 0, so a pending [ASK] in its history wakes.
- F2: `update` writes the file only when the validated state changed (idle polling = zero writes); notices are printed after the flock is released.
- F3: voided posts never wake (test). Tip handling improved: if the order shifts but the tip event is still present, events after ITS new position are new; only when it is gone is everything "seen" (+ one notice).
- The earlier sentence "a removed member's events are not shown after removal" is corrected: a late valid event of a since-removed member still wakes (it is a real event of the thread).
