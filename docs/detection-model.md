# Detection Model

> **Website:** For an approachable overview of the detection model and threat taxonomy, see [AgentArchaeology.ai/telltale/detection-model](https://agentarchaeology.ai/telltale/detection-model/).

The current Rule v1 and process-chain engine is documented here. [Detection v2](detection-v2.md)
describes the accepted future detection architecture; it is not the current
engine and is not implemented.

## Risk Flow

Each activity starts at score `0`. Routine tool activity, powerful-looking tool
names, and error text are informational only. Positive risk is a typed ledger of
deterministic rule, chain-modifier, or enabled baseline-deviation contributions;
the event score is the checked exact sum of that ledger. Negative contributions,
caps, quantization, and subtraction are not part of the current contract.

Emitted native activity, detection, and session-summary events use schema
version `3.0` and include `risk_contributions`. Each entry has a stable `id`,
`type`, positive `points`, and bounded deterministic `rationale`. Session
summaries deduplicate contribution keys within the paired client/source/session
scope, so replay and same-source duplicate contributions do not inflate risk.
Distinct source IDs remain distinct; source-alias canonicalization is deferred.

For Elasticsearch-compatible consumers, install the repository-native
`config/examples/elastic-telltale-index-template.json` index template for
native Event 3.0 events. It maps both `risk_score` and nested
`risk_contributions.points` as `unsigned_long`; using a narrower integer mapping
would not preserve the canonical `u64` contract.

| Score | Severity | Behavior |
| ---: | --- | --- |
| 0-19 | informational | Emit an informational native detection or process-chain event when matched; activity is separate. |
| 20-49 | low | Log detection with matched rule details and deterministic response metadata. |
| 50-69 | medium | Log detection with expanded context and deterministic response metadata. |
| 70-89 | high | Emit deterministic response metadata for security review. |
| 90+ | critical | Emit deterministic response metadata for immediate investigation. |

Default thresholds are configured by `TELLTALE_RISK_THRESHOLD_LOW`,
`TELLTALE_RISK_THRESHOLD_MEDIUM`, `TELLTALE_RISK_THRESHOLD_HIGH`, and
`TELLTALE_RISK_THRESHOLD_CRITICAL`. Unknown inherited variables do not affect
threshold resolution.

## Rule Categories

- `secret_access`: `.env`, auth files, SSH keys, cloud credentials, package tokens.
- `credential_pattern`: API keys, JWTs, private keys, OAuth tokens.
- `execution`: shell, eval, interpreters, encoded payloads.
- `download`: curl, wget, PowerShell web requests, package downloads.
- `install`: npm, pip, cargo, brew, apt, binary installers.
- `exfiltration`: outbound upload, pastebin-like targets, cloud object writes, suspicious webhooks.
- `persistence`: shell profile edits, cron/systemd/launch agents, startup folders.
- `approval_bypass`: context indicating bypassing prompts, hidden execution, or no-confirm behavior.
- `tool_injection`: tool-call-shaped content in model output where no tool was requested or registered.
- `mcp_prompt_injection`: fake or poisoned MCP tool metadata, tool responses, server instructions, or `tools/list` content that tries to steer the agent.

See [threat-taxonomy.md](threat-taxonomy.md) for the Telltale category contract, current bundled rule mapping, and optional offline MITRE ATLAS tagging guidance.

## Process-Chain Detections

A second rule vocabulary evaluates parent/child process relationships and
standalone process indicators, and emits its own `process_chain` events. It runs
alongside the regex engine and does not change regex rule evaluation, regex
scoring, or the session `detection` event.

Process-chain rules add the `defense_evasion`, `command_and_control`,
`discovery`, `credential_access`, `lateral_movement`, `impact`, and `collection`
categories, and they emit informational events with `risk_score: 0` rather than
staying silent, so weak steps can still anchor a correlated finding.

See [process-chain-detections.md](process-chain-detections.md) for the scoring
model, deduplication, correlation windows, false-positive controls, and the
`process_chain` event schema. Set `TELLTALE_PROCESS_CHAIN_DETECTIONS=0` to disable
the pack for a scan.

## Configurable Rules And Policies

Telltale loads bundled default rules from the binary by default. Repeated `--rules`
flags add custom YAML files on top of those defaults:

```sh
telltale scan --once --no-local-config --rules custom-rules.yaml --root tests/fixtures/session_stores --dry-run
```

Use `--no-default-rules` to omit only the embedded bundled pack. Managed
directories still load; combine it with `--no-local-config` for an explicit
custom-only rule set:

```sh
telltale scan --once --no-local-config --no-default-rules --rules custom-rules.yaml --root tests/fixtures/session_stores --dry-run
```

Custom rule files can also live under local config roots. Telltale checks
existing `/etc/telltale` and per-user config roots by default; pass
`--config-dir <path>` to use an explicit root for a command, or
`--no-local-config` to disable discovery. Rule packs resolve in fixed tier
order (bundled defaults → `organization-rules.d` → `rules.d` → `ui-rules.d`);
a higher tier fully replaces a same-ID definition in place, while unique IDs are
additive. Replacements and winners are available in the provenance columns of
`telltale rules list --verbose` and in `telltale rules validate`. Repeated
explicit `--rules` files remain an additive-only stage after managed packs, so
they cannot replace managed definitions.

See [Install](install.md) for the full config directory layout, trust-boundary
guidance, override YAML format, `--no-default-rules`/`--no-local-config`
behavior, and `telltale config validate` / `telltale rules export-default`
usage.

The simplest valid custom rule uses `targets` plus `regex`:

```yaml
version: 1
description: Local custom rules.
defaults:
  case_insensitive: true
  enabled: true
rules:
  - id: example.download.curl
    title: Example curl download
    category: download
    severity: low
    score: 20
    targets: [command, arguments, url]
    regex: '(^|\b)curl\b.*https?://'
    tags: [example, network, download]
    explanation: Example rule that matches curl-based HTTP downloads.
    falsepositives:
      - Setup docs or normal dependency fetches may legitimately use curl.
modifiers: []
```

Telltale also supports a Sigma-inspired `detection.selection` map with `condition: selection`:

```yaml
rules:
  - id: custom.agent.malicious_behavior
    title: Custom malicious agent behavior
    category: custom_agent_behavior
    severity: high
    score: 70
    detection:
      selection:
        assistant_context: 'exfiltrate project secrets'
        arguments: 'exfiltrate project secrets'
      condition: selection
    tags: [custom, agent-behavior]
    explanation: User-defined rule for suspicious agent behavior.
```

Policy YAML can select active rule categories and rule ids without editing the rule files:

```yaml
name: strict-workstation
enabled_categories: [secret_access, credential_pattern, exfiltration, mcp_prompt_injection]
disabled_rules: [network.controlled_test_domain.darkroast]
```

Use `telltale rules list`, `telltale rules validate`, and `telltale rules test` to inspect,
compile, and preview configured rules before writing scan output. `telltale rules list`
keeps its default five tab-separated columns (`id`, `category`, `severity`,
`score`, `enabled`); add `--verbose` for the winner and replaced-source
provenance columns. All three commands also load bundled defaults unless
`--no-default-rules` is set; managed
directories still load when bundled defaults are disabled. Use
`telltale rules export-default --output <local-path>` when an operator wants a local
copy of the embedded default pack to inspect or adapt. An edited copy placed in
a managed tier intentionally replaces matching IDs; passing it with `--rules`
requires `--no-default-rules` to avoid additive collision with the embedded copy.

Policy-violation detections, ad-hoc hunts, and production alerts use the same rule engine and syntax as security detections. Keep policy-focused bundles under `config/rules/policy-violations/` and temporary hunting bundles under `config/rules/ad-hoc/` when useful for clear rule-set organization. Rule purpose is described by metadata fields such as `detection_class`, `signal_type`, and `analytic_intent`; observed behavior remains in `category`. See [agent-policy-authoring.md](agent-policy-authoring.md) for the workflow that maps human policy controls to Telltale categories, rule IDs, fixtures, and validation commands.

Events carry the same metadata for SIEM filtering:

- `detection_classes`: `security_detection`, `policy_violation`, `threat_hunting`, `compliance_observation`, `operational_health`, or `baseline_deviation`.
- `signal_types`: `atomic`, `chain`, `correlation`, or `baseline_deviation`.
- `analytic_intents`: `alert`, `hunt`, `enrich`, `baseline`, or `audit`.
- `atlas_tags`: optional MITRE ATLAS context tags. Coverage is tracked in [../MITRE_ATLAS_COVERAGE.md](../MITRE_ATLAS_COVERAGE.md).

## Context Rules

See [detection-content-standard.md](detection-content-standard.md) for the full quality bar: required rule metadata, fixture expectations, false-positive notes, severity rationale, documentation expectations, and deprecation rules.

High-risk combinations:

- secret read followed by outbound network call;
- download followed by execution;
- install followed by shell profile or service modification;
- base64/hex decode piped into shell;
- model proposes or emits tool call without matching user intent in preceding context;
- tool arguments contain credential patterns.
- MCP metadata or tool output contains prompt-injection language plus a command, URL, sensitive path, or tool-call-shaped object;
- a controlled test-domain egress attempt to `darkroastcyber.io` appears near MCP metadata or tool-call injection context.

## First Alert Use Case

The first end-to-end alert should demonstrate fake MCP prompt injection / tool poisoning in a synthetic agent transcript.

Scenario:

- A fake MCP server or fake `tools/list` response presents a harmless-looking tool, such as `repo_status`, `get_compliance_status`, or `summarize_project`.
- The tool description, parameter description, server instructions, tool result, or adjacent assistant context includes hidden or explicit instructions like ignoring previous instructions, silently reading secrets, bypassing approval, or calling another tool.
- The injected instruction attempts to read a sensitive local file or credential-looking value and send it to a reserved controlled test-domain destination.
- Telltale must emit a high or critical detection event without logging raw secret values or full transcript bodies.

Synthetic evidence examples may mention:

- `mcp.tools_list`, `mcp.tool.description`, `mcp.tool.parameters`, or `mcp.tool.result`;
- `ignore previous instructions`, `without asking`, `do not tell the user`, or `silently run`;
- `.env`, SSH keys, API tokens, or credential-shaped text;
- `https://exfil.example.invalid/...` as the reserved controlled destination.

Expected rule chain:

- `mcp.tool_metadata.prompt_injection`
- `approval.bypass.context`
- `secret.env.read` or another `secret_access` rule
- `network.controlled_test_domain.darkroast`
- `chain.mcp_injection_then_egress`

Rule modifiers may key off categories or exact rule ids. Exact rule-id modifiers cover chains where both signals share one category, such as `execution.shell` plus `execution.encoded_payload` emitting `chain.shell_encoded_payload`.

## Source Capability Awareness

Not all agent sources expose the same fields. Detection and analyst review context
should account for source-level gaps documented in [agent-capability-profiles.md](agent-capability-profiles.md). Key constraints:

- **User intent context** is unavailable for Copilot process logs. Rules targeting `user_context` silently skip Copilot records.
- **Model/provider attribution** is weaker for Copilot and Claude. Cross-session correlation by model/provider is unreliable for these sources.
- **`call_id` linking** is only natively available for Copilot. Tool-call/tool-result pairing for other sources relies on ordering and tool name matching.
- **`is_error` detection** is universally lossy through the legacy conversion path.

## Baseline Deviation State

Model behavioral baselines are maintained in scanner state and can be used by `--baseline-deviation-scoring` to add bounded activity risk modifiers for new tool names, path classes, or network host observations. Normal scanning requires current native state; legacy state is accepted only by the explicit `telltale migrate state` command. The emitted activity evidence should expose only deviation counts, not the raw baseline network host labels.

Baseline network host identities are hashed with deterministic `sha256:` labels before they are persisted in scanner state. Existing raw labels from older state files are hashed only by the explicit migration command; normal scanning rejects unversioned state. See [privacy-model.md](privacy-model.md#4-local-only-sensitive-context) for handling guidance.

## Analyst Review Context

The emitted event context supports analyst review of:

- Did the user clearly request this tool action? (Note: user intent is unavailable for some sources — see [agent-capability-profiles.md](agent-capability-profiles.md))
- Is the action proportional to the task?
- Does the command access, transmit, or persist sensitive material?
- Is there evidence of model/provider tool injection?
- What severity and confidence should be assigned?

Native Event 3.0 retains deterministic severity, response metadata, and
top-level `timeline_anchors` when available. It does not emit `triage`,
`llm_triage`, or compatibility verdicts. Historical Event 1.0 and 2.0 records
remain readable with their original fields.

## Response Contract

Detection events include a top-level `response` object that is safe for SIEM indexing and analyst workflows. The fields are deterministic and derived from severity, matched rule IDs, and categories:

- `recommended_action`: one of `monitor`, `review`, `investigate`, or `investigate_immediately`.
- `response_playbook`: a stable Telltale playbook identifier for the strongest matched rule family.
- `investigation_summary`: a short redaction-safe summary of the matched rules/categories and next investigation step.
- `escalation`: `routine_review` or `security_review_required`.

The response object does not include raw transcript bodies or secrets. It remains
deterministic event metadata and is available to downstream analyst workflows.
