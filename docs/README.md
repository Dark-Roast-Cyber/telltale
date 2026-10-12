# Documentation map

Use this index to find the owning document, not as a second specification.
[AgentArchaeology.ai](https://agentarchaeology.ai/) owns practitioner explanations;
this repository owns versioned product contracts. Read only the relevant pages.

## Start a task

1. **Purpose and scope:** read the [product overview](../README.md),
   [roadmap](../ROADMAP.md), and [development principles](development-principles.md).
   Principles constrain current engineering; future capabilities still need
   separately accepted scope.
2. **Decisions:** read the task's GitHub Issue, later scope updates, linked PRs,
   and the relevant [formal specification](../openspec/specs/). An issue's opening
   description may have been superseded. Use the merged change and current
   contract to distinguish completed work from remaining scope.
3. **Implementation:** follow [architecture and code entry points](architecture.md#module-boundaries),
   then inspect callers and nearby tests. Code presence alone does not establish
   a supported API; [embedding](embedding.md) classifies the Rust surfaces.
4. **Evidence:** separate implementation, publication, and qualification. Check
   the exact source SHA, artifact, platform, and test scope. A passing synthetic
   test or native runner is not clean-host or live-use qualification.

For rationale not explained in a contract, use `git log -- <path>` and
`git blame <path>`, then read the linked PR/Issue discussion. Cite the decision
and identify superseded guidance. If code and an accepted contract conflict,
report the discrepancy rather than silently treating either as a new decision.
When changing behavior, update the owning contract and acceptance evidence;
avoid another status file, duplicate plan, or decision catalog.

## Current product and engineering guidance

| Question | Owner |
| --- | --- |
| Install, configure, schedule, or verify? | [Install](install.md) |
| Upgrade or roll back? | [Controlled deployment](controlled-deployment.md), [installer matrix](installer-migration-matrix.md), [migration contract](migration-contract.md), [0.7 migration](migrations/0.7.0.md) |
| Source identities and validation depth? | [Source validation matrix](source-validation-matrix.md) |
| Discovery paths and per-source visibility? | [Session sources](session-sources.md), [agent capability profiles](agent-capability-profiles.md) |
| OpenCode admission, cursor behavior, or recovery limits? | [OpenCode live ingestion](opencode-live-ingestion.md) |
| Pipeline, dependency boundaries, and code ownership? | [Architecture](architecture.md), [development principles](development-principles.md) |
| Source-evidence model and semantic flow? | [Canonical Observation v2](canonical-observation-v2.md), [semantic foundation](semantic-foundation.md) |
| Runtime evaluator, scoring, and process chains? | [Detection v2](detection-v2.md), [detection model](detection-model.md), [process-chain detections](process-chain-detections.md) |
| Rule quality, categories, and examples? | [Detection content standard](detection-content-standard.md), [threat taxonomy](threat-taxonomy.md), [ATLAS coverage](../MITRE_ATLAS_COVERAGE.md), [use cases](use-cases.md) |
| Policy configuration versus enforcement? | [Policy modes](policy-modes.md), [policy authoring](agent-policy-authoring.md) |
| Event 3.0 schema, local output, and sinks? | [Telemetry output](telemetry-output.md) |
| Rust embedding, action findings, and investigation? | [Embedding](embedding.md), [core package](../crates/telltale/README.md) |
| Optional viewer or static MCP inventory? | [Console](telltale-console.md), [MCP inventory](mcp-tool-inventory.md) |
| Privacy and untrusted evidence? | [Privacy model](privacy-model.md), [trust boundaries](trust-boundaries.md), [threat model](security/threat-model.md) |
| Add a source or measure detection behavior? | [Adding an agent source](adding-agent-source.md), [evaluation corpus](../tests/evaluation/README.md) |
| Release procedure, integrity, and reporting? | [Release readiness](release-readiness.md), [security operations](security/operations.md), [SECURITY.md](../SECURITY.md) |
| Version, license, and packaging policy? | [Versioning](versioning.md), [license and packaging](license-and-packaging.md) |

### Release evidence and open decisions

[GitHub Releases](https://github.com/Dark-Roast-Cyber/telltale/releases) owns
published artifact identity; [CHANGELOG](../CHANGELOG.md) records release history;
[release readiness](release-readiness.md) and the qualification Issue own gate
results and limitations. Check those records instead of copying a “latest RC”
or checklist into this index.

- [#87](https://github.com/Dark-Roast-Cyber/telltale/issues/87): RC2 freeze,
  publication, exact-source/artifact evidence, and remaining qualification gates.
  Read subsequent gate reports as well as the original checklist.
- [#91](https://github.com/Dark-Roast-Cyber/telltale/issues/91): OpenCode cursor
  recovery decisions. Its post-#90 scope update separates completed regression
  detection from the remaining explicit reset/rebaseline operation.

Qualification results do not authorize a live canary, stable promotion, another
tag, or downstream adoption. Those remain separately scoped decisions.

## Experimental and future boundaries

These pages explicitly distinguish implemented foundations from proposed
production behavior. They are not blanket implementation authorization.

| Area | Owner |
| --- | --- |
| Non-production Event4 contract foundation | [Event4](event4.md) |
| Future output boundary, not active Event3 delivery | [Telemetry/output architecture](telemetry-output-architecture.md) |
| Experimental inference normalizer and deferred integrations | [Inference crate](../crates/telltale-inference/README.md), [acquisition design](inference-runtime-acquisition.md) |
| Proposed continuous service, distinct from current scan/watch | [Continuous observer](continuous-observer-plan.md) |

## Requirements, history, and publication

[OpenSpec specifications](../openspec/specs/) own formal behavioral requirements.
For source admission and accounting, start at
[source-support-denominator](../openspec/specs/source-support-denominator/spec.md)
and [canonical-accounting-coverage](../openspec/specs/canonical-accounting-coverage/spec.md).
The same directory holds adapter, detection, privacy, persistence, delivery,
investigation, and release requirements; it is not a task tracker.

[0.4 migration](migrations/0.4.0.md) is historical, not current upgrade guidance.
[Historical schemas](../schemas/historical/README.md) retain immutable wire
contracts. Git history preserves removed docs and rationale; an old plan does
not override the current contract.

Keep public contracts and synthetic examples tracked. Keep raw sessions,
credentials, deployment-specific settings, host evidence, local agent workflow,
and OpenSpec change/task state private. Public docs must not depend on ignored
files. Publish reviewed, sanitized evidence summaries, not private archives.
