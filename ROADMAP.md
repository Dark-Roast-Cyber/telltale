# Telltale Roadmap

Telltale is an open-source detection layer for AI coding agents — visibility,
detection, and investigation for autonomous coding agents and other tool-using
AI systems. It is the foundation for the Agent Detection and Response (ADR)
category.

This roadmap is a stable public summary of project direction. Detailed
execution planning is maintained internally. The authoritative architecture
philosophy lives in [development
principles](docs/development-principles.md); where that document and the
summaries below differ on future architecture, the principles govern.

## Current Focus: 0.6.0 Trust, Privacy, and Durable Collection

Telltale 0.5.0 established the canonical Event 3.0 identity, explicit source-parser
architecture, cross-platform release gates, and a deterministic local detection
pipeline. The 0.6.0 milestone focuses on the evidence and operational guarantees
needed for controlled client adoption.

Priorities, in order:

1. **Measure detection behavior** — maintain a versioned labeled synthetic corpus
   that separates deterministic conformance from synthetic efficacy and produces
   reproducible rule/session metrics. Do not present synthetic results as
   production false-positive or detection rates.
2. **Harden the privacy boundary** — make evidence sanitization a centralized
   contract and prove controlled credential/path markers do not survive emitted
   events, diagnostics, or durable delivery storage.
3. **Add persistent remote-delivery replay** — preserve local JSONL as the
   recommended durable first write while adding restart-safe at-least-once remote
   delivery for that deployment mode.
4. **Formalize project security** — publish vulnerability-reporting and
   threat-model documentation, gate dependency advisories/licenses/sources,
   generate an SBOM, and harden release-workflow dependencies.
5. **Prove install and platform reliability** — close remaining installer
   correctness gaps and decide the Windows clean-host runtime policy if Windows
   remains an advertised target.
6. **Prove an adoption profile** — document and validate the supported
   embedding/sidecar model for another endpoint client without making Telltale
   itself a hosted multi-tenant control plane.

### 0.6.0 principles

- Event 3.0 remains the native event contract unless a separately reviewed
  compatibility need requires otherwise.
- Deterministic detection remains authoritative.
- Synthetic efficacy results are not presented as production false-positive or
  detection rates.
- Durable remote delivery is explicitly at-least-once; receivers must
  deduplicate.
- Privacy tests use synthetic controlled markers, never real secrets or customer
  transcripts.
- Telltale remains tenant-agnostic; multi-tenant identity and re-keying belong
  to downstream collectors.

## Near-Term Themes

- **Architecture & quality framework** — evolve the engineering standards and
  architecture principles Telltale is built against, with one accepted Issue at
  a time and bounded, reviewable changes.

## Beyond 0.6.0

The Event4 and future telemetry/output architectures are accepted and
documented as intended future work, not implemented capability. Detection v2
has an experimental, non-production foundation: only `observation_match`, the
`DetectorResult` -> `Signal` -> atomic `Finding` path, and the Rule v1 compiler
are implemented. Shadow/activation paths, advanced detector runtimes, and a
Detection Content v2 loader do not exist.
Canonical Observation v2 core types/scaffolding are implemented, and the Claude
Code (`claude.projects`) v2 reference projection plus the Codex v2 reference
adapter family are implemented as non-production projections. The OpenCode
(`opencode.sqlite`) v2 reference projection is also implemented as a
non-production projection. `opencode.legacy_json` remains supported and its v2
migration has not started; `opencode.project_json` remains Candidate and its v2
migration has not started. Production normalization/detection still uses
`NormalizedRecordV1`. Canonical Observation v2 production cutover, production
Detection v2, Event4, and telemetry/output v2 have not started. Event 3.0
remains the current frozen compatibility and output contract; migration
requires explicit gates. Broader selector visibility and efficacy measurement,
including the `compat.v1.url` gap, is deferred to P13.

The following remain outside the approved 0.6.0 trust, privacy, and durable
collection milestone and require separate scope, compatibility review, and
release planning:

- New agent sources and third-party parser/plugin APIs
- Sequence/data-flow detection syntax and new rule-language features
- Policy modes, intent guard, active response, confirmation, and blocking
- Remote rule feeds, manifests, signatures, and polling
- Tamper-evident signing and forensic snapshots
- Hook-based process interception
- Embedded or agentic runtime review
- Long-lived semver promises and a feature-flag matrix

### Priority reference clients

- **Claude Code** (`claude.projects`): first implemented Canonical Observation
  v2 reference adapter; production remains `NormalizedRecordV1`.
- **Codex**: implemented v2 reference adapter family (`codex.sessions`,
  `codex.archived_sessions`, and `codex.headless_sessions` supported;
  `codex.project_sessions` candidate); production remains `NormalizedRecordV1`.
- **OpenCode**: `opencode.sqlite` has an implemented non-production Canonical
  Observation v2 reference projection. `opencode.legacy_json` remains
  supported, while its v2 migration has not started; `opencode.project_json`
  remains Candidate, and its v2 migration has not started. Production remains
  `NormalizedRecordV1`.
- **Claude Desktop**: priority discovery and modeling are required before
  migration; it is not assumed equivalent to Claude Code.
- **ChatGPT Desktop**: priority discovery and modeling are required before
  migration; it is not assumed equivalent to Codex.
- **Gemini CLI** / `gemini.tmp`: legacy compatibility only; no new Canonical
  Observation v2 migration is planned. It is not renamed to Antigravity.

## Principles

- **Visibility first, detection second, response later.** First produce
  trustworthy local telemetry from agent logs. Then make detections
  understandable. Only consider active blocking after the data model is stable.
- **Batch first, real-time later.** Log review before live hooks.
- **Deterministic detection is authoritative.** AI enrichment is optional future
  work outside the embedded runtime.
- **Detection separate from action.** Telltale emits visibility and alerts;
  blocking is a future policy layer.
- **Privacy by default.** No raw secrets, API keys, full transcript bodies, or
  unnecessary command output in emitted telemetry.
- **Agent-agnostic by design.** Each supported agent is a source adapter behind
  a stable interface: discover, parse, normalize, detect, score, emit.

## License

Telltale Core is open source under Apache-2.0.
