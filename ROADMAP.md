# Telltale Roadmap

Telltale is an open-source detection layer for AI coding agents — visibility,
detection, and investigation for autonomous coding agents and other tool-using
AI systems. It is the foundation for the Agent Detection and Response (ADR)
category.

This roadmap is a stable public summary of project direction. Detailed
execution planning is maintained internally.

## Current Focus: 0.2.0 Maturity

The 0.2.0 release makes Telltale safe, understandable, and practical to run.
Priorities, in order:

1. **Ordered rule packs** — bundled < organization < deployment < local/UI
   precedence, with provenance and conflict diagnostics. *(shipped)*
2. **Rename internal `adr` references to `telltale`** — the product is
   Telltale; "ADR" remains the category name. Cross-repo refactor (CLI, crates,
   config, docs) sequenced before the remaining release work so everything
   ships on the new product identity.
3. **Configuration consolidation** — one shared scan/watch configuration path
   to remove a high-risk duplication seam.
4. **Explicit delivery semantics** — honest local JSONL + best-effort remote
   sinks, with documented retry, loss, and replay behavior.
5. **Maintainability cleanup** — split large test files, remove unused
   placeholders, deduplicate documentation.
6. **Claims and evidence** — public support claims match measured evidence;
   unknowns are labeled preview rather than converted into broad claims.

Before a tagged release: installer integrity checks, CI preflight, archive
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

## Post-0.2.0 Direction

Explicitly deferred until the 0.2.0 release is stable:

- New agent sources and third-party parser/plugin APIs
- Sequence/data-flow detection syntax and new rule-language features
- Policy modes, intent guard, active response, confirmation, and blocking
- Remote rule feeds, manifests, signatures, and polling
- Tamper-evident signing and forensic snapshots
- Native persistent delivery outbox
- Crates.io publication and broad semver promises

## Principles

- **Visibility first, detection second, response later.** First produce
  trustworthy local telemetry from agent logs. Then make detections
  understandable. Only consider active blocking after the data model is stable.
- **Batch first, real-time later.** Log review before live hooks.
- **Regex/static scoring first, LLM triage only after thresholds.**
- **Detection separate from action.** Telltale emits visibility and alerts;
  blocking is a future policy layer.
- **Privacy by default.** No raw secrets, API keys, full transcript bodies, or
  unnecessary command output in emitted telemetry.
- **Agent-agnostic by design.** Each supported agent is a source adapter behind
  a stable interface: discover, parse, normalize, detect, score, triage, emit.

## License

Telltale Core is open source under Apache-2.0.
