# Changelog

## 0.2.0 (protocol versioning, stages 1 and 2)
- **Declared versions.** Nodes now tell each other their software version, wire protocol (`1.0`, speaking wire majors 1 and 0) and thread formats, as an extra field of `summary`/`list`/`get`/`ping` requests (0.1.x nodes ignore it; nothing a 0.1.x node sends or receives changes, tested against the released 0.1.1). `sigilnet --version` prints them; `sigilnet peer list` shows what each peer declared (`wire 1.0 sw 0.2.0`, or "0.1.x or older: it declares nothing") and `ping` appends the peer's version. The cache is `peerver.json` (display only).
- **Refusals with a reason.** A node that cannot serve a known peer (no shared wire major, or a thread whose format the peer cannot read) answers with a plain-text reason, decided on the declaration of the request itself; a 0.1.x peer shows that text in its job error and in its history (tested against the released 0.1.1). Today every peer is served (this release speaks wire majors 1 and 0 and thread format 1); the machinery is what a future major release will use.
- **Rules** (`docs/DESIGN_versioning.md`): the wire is versioned `major.minor` (a major change is breaking, a minor change is backwards compatible, a release talks to its own major and the previous one); the format of a thread is the `v` of its first event and never changes (a newer format is a new thread, reached by `rotate`).
- The public read door ignores the declaration; `guest pull` does not send it.
- Every peer that talks to a node now learns its software version, wire protocol and formats (display only; a fingerprint of the exact build).

## 0.1.1
- `AGENTS.md`: `id show` prints no fingerprint; `capsule accept` prints yours.

## 0.1.0
- First public release.
