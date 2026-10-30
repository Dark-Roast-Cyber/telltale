# Documentation map

Use this index to find the owning document, not as a second specification.
[AgentArchaeology.ai](https://agentarchaeology.ai/) owns practitioner explanations;
this repository owns versioned product contracts.

| Question | Owner |
| --- | --- |
| Install, configure, schedule, or verify? | [Install](install.md) |
| Upgrade or roll back? | [Controlled deployment](controlled-deployment.md), [migration contract](migration-contract.md), [0.7 migration](migrations/0.7.0.md) |
| Source identities and validation depth? | [Source validation matrix](source-validation-matrix.md) |
| Discovery paths and per-source visibility? | [Session sources](session-sources.md), [agent capability profiles](agent-capability-profiles.md) |
| Exact source identities, roots, paths, and patterns as data? | [Source catalog](catalog/sources.json), generated from the registry; see the [catalog notes](catalog/README.md) |
| What current harness releases write, and what Telltale reads of it? | [Upstream format cases](../tests/upstream_formats/README.md) and their pinned [harness manifest](../tests/upstream_formats/harnesses.json) |
| OpenCode admission, cursor behavior, or recovery limits? | [OpenCode live ingestion](opencode-live-ingestion.md) |
| Scoring and process chains? | [Detection model](detection-model.md), [process-chain detections](process-chain-detections.md) |
| Rule quality and categories? | [Detection content standard](detection-content-standard.md), [threat taxonomy](threat-taxonomy.md) |
| Rule v1 field names, targets, and accepted values as data? | [Rule vocabulary](catalog/rule-vocabulary.json), generated from the validator |
| Community rules, rule packages, or opting out? | [Install: community rules and rule packages](install.md#community-rules-and-rule-packages) |
| Policy configuration versus enforcement? | [Policy modes](policy-modes.md), [policy authoring](agent-policy-authoring.md) |
| Event 3.0 schema, local output, and sinks? | [Telemetry output](telemetry-output.md) |
| Rust embedding, action findings, and investigation? | [Embedding](embedding.md), [core package](../crates/telltale/README.md) |
| Optional viewer or static MCP inventory? | [Console](telltale-console.md), [MCP inventory](mcp-tool-inventory.md) |
| Privacy and untrusted evidence? | [Privacy model](privacy-model.md), [threat model](security/threat-model.md) |
| Measure detection behavior? | [Evaluation corpus](../tests/evaluation/README.md) |
| Release integrity and reporting? | [Security operations](security/operations.md), [SECURITY.md](../SECURITY.md) |
| Version, license, and packaging policy? | [Versioning](versioning.md), [license and packaging](license-and-packaging.md) |

[GitHub Releases](https://github.com/Dark-Roast-Cyber/telltale/releases) own
published artifact identity, and the [CHANGELOG](../CHANGELOG.md) records release
history. [Historical schemas](../schemas/historical/README.md) retain immutable
wire contracts. The experimental
[inference crate](../crates/telltale-inference/README.md) documents its own
supported subsets.
