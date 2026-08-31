# Security policy

Telltale handles agent-session evidence and can be configured to deliver
telemetry to remote sinks. Please do not disclose a suspected vulnerability in
a public issue, pull request, fixture, or discussion.

## Private reporting

The repository's GitHub private vulnerability reporting capability is currently
disabled. If GitHub shows **Report a vulnerability** in the repository Security
tab, use that private advisory form and include a minimal reproduction,
affected commit or version, impact, and a safe fix suggestion. If that option
is unavailable, send the report privately to the public maintainer contact
address shown on the [Dark Roast Cyber GitHub profile](https://github.com/Dark-Roast-Cyber):
`public@christiant.io`. Do not post sensitive details publicly. No response
time or coordinated-disclosure deadline is promised.

Please use synthetic data. Never send raw transcripts, customer telemetry,
credentials, tokens, private keys, or live session/state/outbox files.

## Supported versions

Security fixes are evaluated for the current `main` branch and the latest
stable GitHub release, when one exists. Release candidates and old commits are
not promised long-term support; include the exact tag or commit in a report.

## Scope and boundaries

The repository-specific threats, trust assumptions, and residual risks are in
the [Telltale threat model](docs/security/threat-model.md). The
[privacy model](docs/privacy-model.md), [trust boundaries](docs/trust-boundaries.md),
and [release-readiness checklist](docs/release-readiness.md) describe the
related operating contracts.
