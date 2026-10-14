# Working on Telltale

## Start with the relevant authority

- `docs/development-principles.md` governs architecture and engineering tradeoffs.
- `ROADMAP.md` defines milestone direction; accepted GitHub Issues define bounded
  work. Neither future direction nor a cleanup request authorizes every redesign.
- `openspec/specs/` holds durable formal requirements. Detailed active planning
  belongs in local ignored state, not another public task tracker.
- For semantic changes, follow the relevant contracts in
  `docs/semantic-foundation.md`, `docs/canonical-observation-v2.md`,
  `docs/detection-v2.md`, and `docs/telemetry-output-architecture.md`.

Read only the material needed for the touched boundary. Follow links to the
canonical owner rather than copying its rules into new instruction documents.

## Changes and cleanup

Preserve intentional consumer, privacy, source-atomicity, and durable-delivery
contracts. The current production path is Canonical Observation v2 to Detection
v2 with Event 3.0 output. Do not reactivate retired sources, shadow paths, or
Event4 runtime behavior as an incidental refactor.

Prefer deletion, consolidation, and clear semantic ownership over more crates,
wrappers, configuration, or speculative extension points. A smaller diff or line
count alone is not success. For an explicit simplification/refactoring task, use
the project `telltale-simplify` skill. A normal bug fix does not need a broad
architecture audit or mandatory agent chain.

## Validation and evidence

Use `Makefile`, the affected package's tests, and scripts as executable authority.
Start with focused checks; `make check-fast` is the local engineering slice and
`make ci-local` is the canonical locked Linux pre-push gate. Run the relevant
Event 3.0, provenance, local-event-feed, embedding, installation, or platform gates
when that contract changes. Required CI/release checks still apply.

Use synthetic fixtures and temporary state, not personal agent databases,
credentials, or a live scanner/service. Preserve unrelated working changes.
A local pass does not qualify Windows, packaged artifacts, remote CI, or release
identity. Report the actual tested revision, checks, and missing gates.
