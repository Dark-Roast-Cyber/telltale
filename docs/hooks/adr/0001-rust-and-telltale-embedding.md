# ADR 0001: Rust, and Telltale through the supported embedding facade

Status: Accepted (2026-11-04)

## Context

Telltale owns acquisition, Canonical Observation v2, Detection v2, Rule v1
content, action findings, redaction and versioned wire forms. Its embedding
contract (`docs/embedding.md` at Telltale `0249eaf`) classifies
`scan_sources_detailed`, `SourceScan`, `ActionFinding` / `ActionRecordV1`,
`semantic_provenance` and the rule catalog as *Supported*;
`canonical_runtime` and lower crates are *Not an API*. The removed
`detect_records` / `evaluate_session` record APIs are gone on purpose.

## Decision

Implement Telltale Hooks in Rust as an ordinary Cargo consumer of
`telltale-core`, pinned by Git revision, and use only Supported surfaces.
Host-only detection knowledge (hook self-protection) ships as Rule v1
documents added through `Pipeline::builder().rules_document()`.

## Evidence

- An exploratory latency experiment (not part of this repository): the facade evaluates a synthesized Claude Code
  window and anchors correlations (score 115 download-then-execute plus cloud
  credential harvest) at the pending call.
- Telltale's own `tests/embedding-consumer/tests/record_contract.rs` uses the
  same "write native JSONL, scan it" pattern.

## Rejected alternatives

- **Shell out to the `telltale` CLI**: scans session roots and emits
  session-scoped Event 3, not per-action records; adds process and parsing
  cost on top of the same build cost.
- **`telltale-rules` regex evaluation inline**: documented for gateways, but
  bypasses Detection v2 native predicates, chains, download links and
  process-chain detections; we would be re-deriving action semantics.
- **Lower-level `telltale-detect` / canonical runtime**: explicitly not an API.
- **TypeScript/Python hook with Telltale over IPC**: a second language for no
  security benefit; the hook itself must stay small and fast.

## Consequences

- Superseded by [ADR 0007](0007-hooks-inside-telltale.md): hooks are now part of
  Telltale and no pin exists. (Formerly, pin bumps were deliberate and
  `build.rs` published the revision in telemetry.) Rule changes change `semantic_identity`.
- We inherit Telltale's redaction and evidence bounds unchanged.
- Generic detection gaps are reported upstream, not patched here.
