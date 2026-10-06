# DESIGN: rename arya_net -> sigilnet, and a Carrier seam (Tor stays the only transport) — DRAFT 1, 2026-10-01 (Arya) for Sansa's review.
Decided: name `sigilnet` chosen and the build go given (2026-10-01); stay Tor-only for now, but architect so another transport could be added without ripping the protocol apart. Blobs (DESIGN_blobs.md rev 1) come AFTER this.

## Why a format break now is fine
Nothing real is deployed: only throwaway homes/capsules exist (all live tests were torn down). Renaming the domain-separation strings invalidates every old signature, envelope and capsule, so we do ALL format changes in this one window: new contexts + typed endpoints. Version numbers stay v1 (nothing to be compatible with). No migration tool; old homes are unusable and are not touched.

## Round A: mechanical rename (no behaviour change)
- Package dir `arya_net` -> `sigilnet` (git mv, history kept); every import; `python -m sigilnet`; tests dirs move with it; tools/*.sh, enc_suite.py, build_review.py, README/DESIGN docs, CLAUDE.md/STATE pointers.
- Contexts: `arya_net/v1/<x>\0` -> `sigilnet/v1/<x>\0` for ALL 11 (event, cosig, env, keyseal, keyconfirm, sync, sync-response, join-response, join-request, guest-pow, plus any HKDF info derived from them). A test lists every `b"...\0"` context constant in the package and asserts each starts with `sigilnet/v1/` and that all are distinct (no context reuse).
- Capsule: prefix `ARYA-CAPSULE-1` -> `SIGILNET-CAPSULE-1`; the passphrase AAD `arya-capsule-boot` -> `sigilnet-capsule-boot`; env vars `ARYA_NET_HOME` -> `SIGILNET_HOME`, `ARYA_CAPSULE_PASSPHRASE` -> `SIGILNET_CAPSULE_PASSPHRASE`; default home `~/.sigilnet`. The old names are NOT read (no silent fallback: a stale arya_net home must not be picked up by mistake).
- Test labels like Identity.generate("arya") are just names: unchanged. `arya_link` is a different project: unchanged.
- Gate: all 11 suites + enc_suite green with the same counts; grep proves no `arya_net` left outside git history, STATE_HISTORY and this doc.

## Round B: typed endpoints + Carrier seam (Tor only)
**Endpoint** = `{"k":"onion","addr":"<56 chars>.onion","port":<int>}`; one validator `endpoint.check(e)` (unknown `k` = refused, exact key set, same checks as today's check_onion + port range). Used in: peers.json (`endpoint` replaces `onion`+`port`), capsule `join` and the joiner's/owner's door fields, the signed `join_request`/`joined` bodies, joins.json, guest/public CLI (`--read/--inbox` accept `X.onion` and build the endpoint).
**Carrier** (a small class in carrier.py; `TorNode` in torlink.py implements it; nothing else may import torlink):
- `dial(endpoint) -> Transport` (request(req) -> resp; raises CarrierError(retry=...)); `TorError` becomes a CarrierError subclass, so node/capsule/guest catch CarrierError only.
- `open_door(name, kind, agent=None) -> None`, `door_endpoint(name) -> endpoint | None`, `close_door(name)`, `doors`; kinds stay peer/read/inbox/join (a role is protocol, how it is carried is the carrier's business).
- `grant(endpoint, credential)` / `revoke`: today's client-auth key. The credential is carrier-specific and opaque to the protocol: capsule carries `{"k":"onion","boot":<x25519 pub>}`-style typed credential, validated by the carrier.
- `capabilities` (set): e.g. {"hides_ip"}; the CLI prints a warning for a carrier without it (future use; Tor says yes).
**Protocol modules** (capsule, node, guest, publicread, inbox, cli) talk to a Carrier only. Tor-specific files: torlink.py (+ noderun's tor start/stop).
**Proof of the seam**: tests/fake_carrier.py = an in-memory carrier (doors are dict entries, dial = a Loopback to the right handler, grant/revoke enforced) and ONE end-to-end test that runs the capsule join + encrypted thread sync + a removal over it, with `torlink` import blocked (sys.modules poisoned). If any protocol module secretly needs Tor, that test fails.

## Gates
Each round: unit tests, the 11 suites plain + enc, Sansa review (diff vs previous tag), tag (`r27_rename`, `r28_carrier`). Round B adds adversarial tests: endpoint validator fuzz (wrong k, extra keys, port types, bad onion), a capsule with an unknown endpoint kind, a peer-book entry with a non-onion addr.

## Questions for Sansa
1. Is it OK to keep format version v1 (nothing deployed), or do you want the capsule/envelope/context versions bumped to make old-vs-new unmistakable? 2. Anything in your tree/tools that must change in lock-step (review scripts, paths)? 3. Carrier method set: too much / too little? Is `grant` with an opaque typed credential the right shape for capsule's bootstrap + dial keys? 4. Should the endpoint carry an optional `via`/`bridges` field now, or are bridges a carrier setting? (I say carrier setting: bridges are already per-node config.)
