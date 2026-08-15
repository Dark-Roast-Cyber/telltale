# Telltale Roadmap

Telltale is an open-source detection layer for AI coding agents — visibility,
detection, and investigation for autonomous coding agents and other tool-using
AI systems. It is the foundation for the Agent Detection and Response (ADR)
category.

This roadmap is a stable public summary of project direction. Detailed
execution planning is maintained internally.

## Current Focus: 0.5.0 Telltale Maturation

The approved 0.5.0 milestone folds in the unpublished 0.4.0 API and parser work
and completes the breaking native Event 3.0 and SIEM identity migration from the
former product identity.
The objective is a reliable, testable path from installation through source
discovery, parsing, deterministic detection, state handling, and SIEM delivery.
Priorities, in order:

1. **Establish a measured baseline** — prove known-positive synthetic detection
   and canonical JSONL/HEC event parity before changing contracts.
2. **Make runtime provenance explainable** — expose the exact build,
   configuration, rule origins, source selection, normalized record counts,
   matches, emitted detections, and suppression reasons without transcript
   inspection.
3. **Complete the native identity cut** — native events use Event 3.0,
   `telltale-*` IDs, package-only `telltale_version`, and canonical Telltale SIEM
   identities. ADR remains the category term. Historical events retain explicit
   read/import handling and their original legacy fields.
4. **Keep embedded review out of the scanner** — deterministic detection,
   response metadata, and timeline anchors remain the core contract; any future
   AI enrichment is a separately designed capability.
5. **Harden detection and state reliability** — positive and benign fixture
   coverage, exact risk contribution accounting, cursor boundaries, and
   replay-safe deduplication.
6. **Prove canonical install and lifecycle behavior** — functional post-install
   checks, explicit Telltale state/event migration, rollback, and no duplicate
   canonical schedules.
7. **Pass host, SIEM, and cross-platform release gates** — native Linux, macOS,
   and Windows archives must execute a positive fixture and validate emitted
   schema before release.

For future tagged releases: installer integrity checks, CI preflight, archive
verification, and cross-platform smoke tests.

## Near-Term Themes

- **Test dataset and visibility requirements** — a labeled dataset of AI
  sessions (benign, uneventful, eventful) with sysmon/EDR-style event capture:
  packages installed, sites called via curl/wget/cli/python, download-to-disk,
  and additional researched visibility requirements. Events are tied to
  session IDs that reference collected session storage (planned S3 buckets or
  file drives). Designed to work out of the box while remaining highly
  configurable.
- **Agentic development framework** — research and adopt a structured framework
  (e.g., spec-driven development) for how Telltale is built by AI agents.

## Beyond 0.5.0

The following remain outside the approved 0.5.0 reliability and migration
milestone and require separate scope, compatibility review, and release
planning:

- New agent sources and third-party parser/plugin APIs
- Sequence/data-flow detection syntax and new rule-language features
- Policy modes, intent guard, active response, confirmation, and blocking
- Remote rule feeds, manifests, signatures, and polling
- Tamper-evident signing and forensic snapshots
- Native persistent delivery outbox
- Long-lived semver promises and a feature-flag matrix

## Principles

- **Visibility first, detection second, response later.** First produce
  trustworthy local telemetry from agent logs. Then make detections
  understandable. Only consider active blocking after the data model is stable.
- **Batch first, real-time later.** Log review before live hooks.
- **Deterministic detection is authoritative.** AI enrichment is optional future
  work outside the embedded 0.5.0 runtime.
- **Detection separate from action.** Telltale emits visibility and alerts;
  blocking is a future policy layer.
- **Privacy by default.** No raw secrets, API keys, full transcript bodies, or
  unnecessary command output in emitted telemetry.
- **Agent-agnostic by design.** Each supported agent is a source adapter behind
  a stable interface: discover, parse, normalize, detect, score, emit.

## License

Telltale Core is open source under Apache-2.0.
