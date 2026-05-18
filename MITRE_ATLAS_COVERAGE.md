# MITRE ATLAS Coverage

This file tracks Telltale rule coverage against MITRE ATLAS for agentic coding detections. ATLAS is documentation and analyst context only. Runtime scans, validation, and tests must not fetch ATLAS data.

Use this file with `atlas_tags` in rule YAML:

```yaml
atlas_tags:
  - atlas:AML.T0051
```

The rule engine validates tag shape (`atlas:<id>`) but does not verify the ID against the internet or a runtime feed. When precise ATLAS context matters, use the optional local helper documented in `docs/threat-taxonomy.md`:

```sh
scripts/atlas-lookup "prompt injection"
```

## Metadata Contract

All ADR rules use the same rule structure, regardless of purpose:

- `category`: concrete behavior observed by ADR, such as `exfiltration`, `approval_bypass`, or `mcp_prompt_injection`.
- `detection_class`: why the rule exists, such as `security_detection`, `threat_hunting`, or `policy_violation`.
- `signal_type`: analytic shape, such as `atomic`, `chain`, or `correlation`.
- `analytic_intent`: how analysts should treat the event, such as `alert`, `hunt`, `audit`, `enrich`, or `baseline`.
- `atlas_tags`: optional ATLAS context tags.

Policy violations, bleeding-edge ad-hoc hunts, and production alerts are all normal ADR rules. They may live in separate bundles for operator clarity, but they use the same syntax, validation, fixture expectations, scoring, redaction, and event schema.

## Coverage Table

| ADR Rule Or Family | ADR Category | Detection Class | Signal Type | Analytic Intent | ATLAS Tags | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `mcp.tool_metadata.prompt_injection` | `mcp_prompt_injection` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0051` | Prompt/tool metadata attempts to steer the agent. |
| `approval.bypass.context` | `approval_bypass` | `policy_violation` | `atomic` | `alert` | `atlas:AML.T0051` | Approval bypass often appears as direct or indirect prompt injection language. |
| `chain.mcp_injection_then_egress` | derived chain | `security_detection` | `chain` | `alert` | `atlas:AML.T0051`, `atlas:AML.T0086` | Prompt injection plus agent-tool egress. |
| `exfil.outbound_upload` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Traditional cyber egress through command or tool execution. |
| `exfil.encoded_http` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Encoded outbound HTTP transfer. |
| `adhoc.agent_tool_exfil_phrase` | `exfiltration` | `threat_hunting` | `atomic` | `hunt` | `atlas:AML.T0086`, `atlas:AML.T0025` | Example ad-hoc hunt for agent-tool exfiltration language. |
| `credential.api_key.pattern` | `credential_pattern` | `threat_hunting` | `atomic` | `hunt` | `atlas:AML.T0057` | Credential-like material in context; can be benign or exposed data leakage. |
| `policy.agent_guardrail_modification` | `persistence` | `policy_violation` | `atomic` | `audit` | none | Local policy-control mapping; no precise ATLAS tag assigned yet. |

## Open Mapping Work

Rules without `atlas_tags` are not automatically deficient. Prefer no ATLAS tag over a weak mapping. Add tags when the relationship is specific and defensible, then update this file in the same change as the rule YAML.
