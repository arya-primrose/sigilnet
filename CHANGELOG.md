# Changelog

## 0.3.0 (thread format 2, versioning stage 3)
- **Thread formats are enforced.** The format of a thread is the `v` of its first event and every event of the thread must carry it (a mismatch is refused). Format 1 is frozen: a conformance corpus written by the released 0.1.1 is replayed by every release's tests.
- **Thread format 2** = format 1 plus two extensions that older software cannot read: event kinds named `x-<name>` (stored, relayed and signed, never interpreted, never able to change validity or membership) and an optional `x` object in the body of `post`, `digest` and `evidence`. Nothing in the CLI writes them yet; the library does (`Writer.ext`). A later release must keep them inert: anything that changes validity or membership needs a new thread format.
- `sigilnet new TITLE --format 2` and `sigilnet rotate THREAD --format 2` (an explicit decision: every member must be known to read format 2, or `--force-format`; `rotate` keeps the format by default; a public thread stays format 1). `sigilnet --version` lists `thread formats 2, 1`; `list` shows `format 2`; `capsule create` says what a joiner of a format-2 thread needs.
- A 0.1.x or 0.2.0 peer that asks for a format-2 thread is refused with a plain reason ("thread uses format 2, the peer reads format 1: the peer must upgrade sigilnet"), tested against the released 0.1.1. A pull that meets events this software cannot read says how many and why.
- The wire protocol is unchanged (1.0); format-1 threads are byte-identical to 0.2.0 and 0.1.x.

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
