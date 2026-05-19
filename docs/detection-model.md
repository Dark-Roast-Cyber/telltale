# Detection Model

## Risk Flow

Each tool call starts at score `0`. Rules add points. Context modifiers add or subtract points. Severity is derived from the final score unless triage overrides it.

| Score | Severity | Behavior |
| ---: | --- | --- |
| 0-19 | informational | Log notable activity only. |
| 20-49 | low | Log detection with matched rule details. |
| 50-69 | medium | Log detection and include expanded context fields. |
| 70-89 | high | Run Llama Guard and triage model, emit triage result. |
| 90+ | critical | Run triage and emit alert-ready event. |

Default thresholds are configured by `ADR_RISK_THRESHOLD_LOW`, `ADR_RISK_THRESHOLD_MEDIUM`,
`ADR_RISK_THRESHOLD_TRIAGE`, and `ADR_RISK_THRESHOLD_ALERT`.

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

See [threat-taxonomy.md](threat-taxonomy.md) for the ADR category contract, current bundled rule mapping, and optional offline MITRE ATLAS tagging guidance.

## Configurable Rules And Policies

ADR loads the bundled rules by default from `config/rules/tool-call-regex.yaml`. You can replace that set at scan time with one or more custom YAML files:

```sh
adr scan --once --rules custom-rules.yaml --root tests/fixtures/session_stores --dry-run
```

The simplest valid custom rule uses `targets` plus `regex`:

```yaml
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
```

ADR also supports a Sigma-inspired `detection.selection` map with `condition: selection`:

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

Use `adr rules list`, `adr rules validate`, and `adr rules test` to inspect, compile, and preview configured rules before writing scan output.

Policy-violation detections, ad-hoc hunts, and production alerts use the same rule engine and syntax as security detections. Keep policy-focused bundles under `config/rules/policy-violations/` and temporary hunting bundles under `config/rules/ad-hoc/` when useful for clear rule-set organization. Rule purpose is described by metadata fields such as `detection_class`, `signal_type`, and `analytic_intent`; observed behavior remains in `category`. See [agent-policy-authoring.md](agent-policy-authoring.md) for the workflow that maps human policy controls to ADR categories, rule IDs, fixtures, and validation commands.

Events carry the same metadata for SIEM filtering:

- `detection_classes`: `security_detection`, `policy_violation`, `threat_hunting`, `compliance_observation`, `operational_health`, or `baseline_deviation`.
- `signal_types`: `atomic`, `chain`, `correlation`, `baseline_deviation`, or `llm_triage`.
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
- The injected instruction attempts to read a sensitive local file or credential-looking value and send it to the controlled tester domain `darkroastcyber.io`.
- ADR must emit a high or critical detection event without logging raw secret values or full transcript bodies.

Synthetic evidence examples may mention:

- `mcp.tools_list`, `mcp.tool.description`, `mcp.tool.parameters`, or `mcp.tool.result`;
- `ignore previous instructions`, `without asking`, `do not tell the user`, or `silently run`;
- `.env`, SSH keys, API tokens, or credential-shaped text;
- `https://darkroastcyber.io/...` as the controlled destination.

Expected rule chain:

- `mcp.tool_metadata.prompt_injection`
- `approval.bypass.context`
- `secret.env.read` or another `secret_access` rule
- `network.controlled_test_domain.darkroast`
- `chain.mcp_injection_then_egress`

Rule modifiers may key off categories or exact rule ids. Exact rule-id modifiers cover chains where both signals share one category, such as `execution.shell` plus `execution.encoded_payload` emitting `chain.shell_encoded_payload`.

## Source Capability Awareness

Not all agent sources expose the same fields. Detection rules and triage prompts should account for source-level gaps documented in [agent-capability-profiles.md](agent-capability-profiles.md). Key constraints:

- **User intent context** is unavailable for Copilot process logs. Rules targeting `user_context` silently skip Copilot records.
- **Model/provider attribution** is weaker for Copilot and Claude. Cross-session correlation by model/provider is unreliable for these sources.
- **`call_id` linking** is only natively available for Copilot. Tool-call/tool-result pairing for other sources relies on ordering and tool name matching.
- **`is_error` detection** is universally lossy through the legacy conversion path.

## Baseline Deviation State

Model behavioral baselines are maintained in scanner state and can be used by `--baseline-deviation-scoring` to add bounded activity risk modifiers for new tool names, path classes, or network host observations. The emitted activity evidence should expose only deviation counts, not the raw baseline network host labels.

Baseline network host identities are hashed with deterministic `sha256:` labels before they are persisted in scanner state. Existing raw labels from older state files are hashed on load and written back hashed on the next state save. See [privacy-model.md](privacy-model.md#4-local-only-sensitive-context) for handling guidance.

## Triage Prompt Contract

The triage prompt should answer:

- Did the user clearly request this tool action? (Note: user intent is unavailable for some sources — see [agent-capability-profiles.md](agent-capability-profiles.md))
- Is the action proportional to the task?
- Does the command access, transmit, or persist sensitive material?
- Is there evidence of model/provider tool injection?
- What severity and confidence should be assigned?

Triage output must be structured JSON with `verdict`, `severity`, `confidence`, `reason`, `matched_risks`, and `recommended_action`. Valid verdicts are `malicious`, `suspicious`, `benign`, or `unknown`; emitted ADR telemetry also uses scanner-state verdicts such as `pending`, `not_required`, and `config_missing`.

Triage HTTP calls default to a 10 second connect/read/write timeout and 2 retries with exponential backoff. Set `ADR_TRIAGE_TIMEOUT_MS` and `ADR_TRIAGE_MAX_RETRIES` in `.env` to tune those limits for a local LiteLLM or OpenAI-compatible endpoint.

## Response Contract

Detection events include a top-level `response` object that is safe for SIEM indexing and analyst workflows. The fields are deterministic and derived from severity, matched rule IDs, and categories:

- `recommended_action`: one of `monitor`, `review`, `investigate`, or `investigate_immediately`.
- `response_playbook`: a stable ADR playbook identifier for the strongest matched rule family.
- `investigation_summary`: a short redaction-safe summary of the matched rules/categories and next investigation step.
- `escalation`: `routine_review` or `security_review_required`.

The response object does not include raw transcript bodies or secrets. Optional LLM triage may update `triage`, but the response object remains stable event metadata.
