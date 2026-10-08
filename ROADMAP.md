# Telltale Roadmap

Telltale is an open-source detection layer for AI coding agents and the foundation
for the Agent Detection and Response (ADR) category.

This file is the public milestone-level roadmap. It intentionally does not carry
detailed task state. Durable architecture and behavior are documented under
`docs/`; durable formal requirements live under `openspec/specs/`; accepted
bounded work belongs in GitHub Issues; detailed active implementation planning is
kept in local OpenSpec changes and other host-only planning state.

The authoritative architecture philosophy lives in
[development principles](docs/development-principles.md). Where a roadmap summary
and an accepted architecture document differ in technical detail, the architecture
document governs.

## 0.6.x Architecture Convergence

The earlier dependency-maintenance and repository-cleanup phases are no longer
active roadmap sections. Completed implementation history belongs in Git history
and `CHANGELOG.md`. The 0.6.x architecture-convergence sequence is complete
through step 7.

The migration should reduce parallel machinery as it progresses. New compatibility
layers are acceptable only when they have a specific migration purpose and a
clear deletion gate.

### 0.7 target agent set

The required session/store adapter families for the 0.7 baseline are:

- **Claude Code**: `claude.projects`
- **Codex**: `codex.sessions`, `codex.archived_sessions`, and
  `codex.headless_sessions`
- **OpenCode**: `opencode.sqlite`
- **OpenClaw**: `openclaw.agents`
- **Qwen**: `qwen.projects`
- **GitHub Copilot**: `copilot.process_log`

Claude and Codex desktop-app-specific acquisition is deferred when it requires
separate source contracts. The core Claude Code and Codex session sources above
are the 0.7 convergence requirement.

The following former source identities were retired during 0.6.x convergence
and are not built-in discovery or parser paths:

- `gemini.tmp`
- `opencode.legacy_json`
- `roocode.tasks`
- `kilocode.tasks`
- `opencode.project_json`
- `codex.project_sessions`

Git history preserves their former implementations and fixtures. They must not
return as compatibility registrations or receive Canonical Observation v2 work
without a separately accepted source contract. OpenCode support for 0.7 is the
current `opencode.sqlite` database only; prior OpenCode source layouts and
source-backed record/export compatibility are not protected contracts.

### Completed 0.6.x convergence sequence

Completed milestones, in order:

1. Contracted the supported-source denominator; non-target sources were retired
   or reclassified, not ported to the new semantic architecture.
2. Kept Rule v1 as supported content on Detection v2, including modifier,
   contribution, and scoring semantics.
3. Moved process-chain matching, suppression, correlation, and risk to Detection
   v2 without fabricating observed Process facts from command text.
4. Made public `telltale-sources` the single cross-source COv2 acquisition API
   for all eight identities: source-owned mapping, caller-owned observed time,
   separate progress, and no legacy bridge.
5. Cut scan, watch, and the supported embedding facade over together to the normal
   COv2 -> Detection v2 runtime path with shared source-atomic behavior: canonical
   activity, baseline replacement, cursor eligibility, and no OpenCode cursor
   advance on downstream operational failure ([activation, Issue #51](https://github.com/Dark-Roast-Cyber/telltale/issues/51)).
6. Retired transitional compatibility and shadow machinery; OpenCode now uses only
   the bounded native/canonical `opencode.sqlite` path ([Issue #54 closeout](https://github.com/Dark-Roast-Cyber/telltale/issues/54#issuecomment-5819387704)).
7. Kept Event 3.0 the sole output for 0.7; Event4 remains inactive ([Issue #55](https://github.com/Dark-Roast-Cyber/telltale/issues/55),
   [completion](https://github.com/Dark-Roast-Cyber/telltale/commit/d3bfbd8aafebda2adc6c9433b1e2937069053526),
   [CI](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/36067578187),
   [CodeQL](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/36067577883)).

These remain the active constraints: caller-supplied direct-record evaluation
is removed rather than kept as a second evaluation path. Event 3.0's schema, wire contract,
constructors, privacy behavior, and persisted bytes remain unchanged, though newly
emitted canonical evidence, hashes, or severity need not match legacy output.
Future Event4 remains an independent projection from accepted semantic truth.
The current runtime has no dual emission, Event4 opt-in, or telemetry-profile
runtime. Generalized `CanonicalPayload` remains deferred.

The accepted semantic direction is documented in:

- [Semantic foundation](docs/semantic-foundation.md)
- [Canonical Observation v2](docs/canonical-observation-v2.md)
- [Detection v2](docs/detection-v2.md)
- [Event4](docs/event4.md)
- [Telemetry/output architecture](docs/telemetry-output-architecture.md)

Those documents define architecture. They are not task trackers.

## Current Focus: 0.7.0 Near-Production Baseline

0.7.0 is the first milestone intended to be close to a production-ready,
long-lived architectural baseline.

Before final 0.7.0, the normal production tree should satisfy these principles:

- one authoritative Canonical Observation v2 production path for the target
  source set;
- one authoritative Detection v2 production path;
- Rule v1 retained as content compatibility rather than a second detector engine;
- shipped process-chain behavior converged on the same detector result model;
- Event 3.0 is the deliberate production/compatibility output for 0.7, with
  Event4 production activation deferred behind explicit future gates;
- no normal production feature described as shadow, fixture-only, experimental,
  or a planned replacement for another normal production path;
- no legacy implementation retained without an explicit continuing compatibility
  purpose;
- supported sources have truthful capability and validation status;
- migration-only shadow/equivalence machinery removed after its activation gate
  has been satisfied;
- public documentation and OpenSpec requirements describe the product that
  actually ships;
- privacy, durability, release, installation, and platform guarantees continue to
  have explicit validation;
- the supported embedding surface is deliberate enough for downstream adoption.

After 0.7.0, the bias should shift toward stability. Foundational rewrites should
become exceptional rather than routine, and new capabilities should build on the
0.7 semantic core instead of introducing competing foundations.

Crates.io publication is intentionally deferred while these boundaries are still
moving. Revisit registry publication after the 0.7 architecture and embedding
surface have stabilized enough to support external Rust consumers deliberately.

## Beyond 0.7.0

The longer-term direction remains broader than session-store detection, but new
capabilities should reuse the same semantic core rather than becoming separate
products inside the repository.

Likely later areas include:

- a [resource-bounded continuous observer](docs/continuous-observer-plan.md),
  with explicit start/stop/service-status commands and opt-in reboot persistence,
  while preserving one-shot scanning and external lifecycle ownership;
- direct harness integrations and lower-latency observation;
- inference-gateway observation and policy boundaries;
- Claude and Codex desktop-app-specific acquisition when separate source work is
  justified;
- runtime observation such as OpenShell integration;
- policy, decisions, approvals, and capability-driven enforcement;
- additional rule-package and managed-content mechanisms;
- richer correlation and investigation workflows;
- optional agent-relevant operating-system context;
- mature external embedding and integration surfaces.
- an out-of-process analyzer extension protocol (`analyzer.v1`) whose results
  return through Telltale's Finding semantics; see
  [analyzer extensions](docs/development-principles.md#analyzer-extensions-direction-not-implemented).

These are direction, not automatically approved implementation scope. Accepted
work should be bounded independently before implementation.

## Planning and Sources of Truth

Telltale deliberately separates durable product truth from temporary execution
state.

| Artifact | Responsibility |
| --- | --- |
| `README.md` | Current product overview, supported user-facing behavior, and entry points |
| `ROADMAP.md` | Public milestone-level direction and sequencing |
| `docs/` | Durable architecture, contracts, operating guidance, and contributor documentation |
| `openspec/specs/` | Durable formal behavioral requirements |
| GitHub Issues | Accepted, bounded backlog and work items |
| Local `openspec/changes/` | Detailed active implementation packages and task state |
| Local idea/planning files | Raw intake or a small now/next index only; not durable product truth |
| `CHANGELOG.md` and Git history | Shipped and completed history |

The public repository should remain sufficient to understand what Telltale is,
how it behaves, and where it is going without publishing local session state,
private evidence, scratch plans, or agent handoff material.

Completed work should leave active planning context once its durable requirements,
documentation, and release history are in the proper locations.

## Principles

- **Visibility first, detection second, response later.** First produce trustworthy
  telemetry from agent activity. Then make detections understandable. Add active
  response only where the data and capability model can support it truthfully.
- **Normalize before analytics.** Source-specific activity should become canonical
  observations before detection, policy, and telemetry semantics depend on it.
- **Deterministic detection is authoritative.** AI enrichment may complement the
  system but should not replace deterministic security behavior.
- **Detection remains separate from action.** A signal describes observed
  behavior; policy and deployment capability determine what can be done about it.
- **Privacy by default.** Do not emit raw secrets, unnecessary transcript bodies,
  or avoidable sensitive evidence.
- **Agent-agnostic by design.** Source-specific implementations belong at adapter
  boundaries behind common semantics.
- **Fail explicitly.** Unsupported observation or enforcement capabilities must
  degrade truthfully rather than pretending the requested behavior occurred.
- **Prefer one current architecture over permanent transition layers.** Migration
  compatibility is useful only while it has a defined purpose.

## License

Telltale Core is open source under Apache-2.0.
