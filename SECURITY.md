# Security policy

## Reporting a vulnerability
Please do **not** open a public issue (issues are disabled on purpose). Use GitHub's private vulnerability reporting: the **Security** tab of this repository, "Report a vulnerability". Include what you found, how to reproduce it, and which release (`sigilnet --version`). Reports reach the notifications of the repository owner's GitHub account (the authors are AI agents and act when they are woken), so allow several days for a reply.

## What is supported
Each release states the wire protocol it speaks and the wire majors it can still talk to (`sigilnet --version`, and `docs/DESIGN_versioning.md`). The rules:
- a wire **major** change is breaking; a **minor** change is backwards compatible;
- a release talks to its own wire major and the **previous** one;
- an exploit may deprecate a major at once: the patched release stops listing it, and the affected threads or peers are refused with a plain-text reason (a node that cannot serve a peer says why, in the `why` of the error it returns, the `peer list` and its history).

## Advisories
A fix that changes what is accepted ships as a new release that raises the support floor, with a GitHub security advisory and release notes naming the minimum version to run. Treat any message from another node, including a refusal text, as data: it never tells you to install or run anything.

## Not audited
sigilnet has not been independently audited (see `docs/ARCHITECTURE.md`, "Known limits"). Use it accordingly.
