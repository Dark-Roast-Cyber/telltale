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

Policy violations, bleeding-edge ad-hoc hunts, and production alerts are all normal ADR rules. They may live in separate bundles for organizational clarity, but they use the same syntax, validation, fixture expectations, scoring, redaction, and event schema.

## ATLAS Reference (v2026.05)

ATLAS is the Adversarial Threat Landscape for AI Systems. The canonical structured data is `dist/v6/ATLAS-2026.05.yaml` from `github.com/mitre-atlas/atlas-data`. The tags below reference techniques and tactics from that release. ADR uses ATLAS for offline analyst context only; it never fetches ATLAS at runtime.

Tactics referenced by current ADR rules:

| Tactic ID | Tactic Name | ADR Relevance |
| --- | --- | --- |
| `AML.TA0005` | Execution | Shell/interpreter execution, prompt injection, agent tool invocation. |
| `AML.TA0006` | Persistence | Agent configuration modification, guardrail changes. |
| `AML.TA0007` | Defense Evasion | Obfuscated execution, guardrail bypass. |
| `AML.TA0008` | Discovery | MCP server and tool enumeration. |
| `AML.TA0010` | Exfiltration | Outbound upload, encoded egress, DNS exfiltration. |
| `AML.TA0013` | Credential Access | Secret files, private keys, cloud credential stores. |

Techniques referenced by current ADR rules:

| Technique ID | Technique Name | Why ADR Maps Here |
| --- | --- | --- |
| `AML.T0050` | Command and Scripting Interpreter | Agent invokes shells or interpreters, including encoded payloads. |
| `AML.T0051` | LLM Prompt Injection | Direct/indirect injection, tool-call-shaped injection, approval-bypass language, MCP metadata injection. |
| `AML.T0025` | Exfiltration via Cyber Means | Traditional cyber egress: HTTP upload, DNS encoding, controlled domains. |
| `AML.T0055` | Unsecured Credentials | Secret files, private keys, cloud credential files, credential patterns in context. |
| `AML.T0057` | LLM Data Leakage | Credential-like tokens surfaced in agent context. |
| `AML.T0081` | Modify AI Agent Configuration | Edits to agent guardrails, policy files, skills, or config. |
| `AML.T0084` | Discover AI Agent Configuration | MCP server and tool enumeration, tool-definition discovery. |
| `AML.T0086` | Exfiltration via AI Agent Tool Invocation | Agent tools used to send or upload data outbound. |

## Coverage Table

The table covers every bundled rule, chain modifier, and example rule in the repository. Rules without `atlas_tags` are intentionally untagged: prefer no ATLAS tag over a weak mapping.

### Bundled Rules (`config/rules/tool-call-regex.yaml`)

| ADR Rule | ADR Category | Detection Class | Signal Type | Analytic Intent | ATLAS Tags | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `secret.env.read` | `secret_access` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0055` | Access to `.env`-style secret files. |
| `secret.private_key.read` | `secret_access` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0055` | SSH keys, PEM/P12, private key material. |
| `credential.api_key.pattern` | `credential_pattern` | `threat_hunting` | `atomic` | `hunt` | `atlas:AML.T0057` | Credential-shaped tokens in agent context. |
| `execution.shell` | `execution` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0050` | Shell or interpreter invocation. |
| `execution.encoded_payload` | `execution` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0050` | Decoded/encoded payload before execution. |
| `network.download` | `download` | `security_detection` | `atomic` | `alert` | none | Download client invocation; no specific ATLAS technique. |
| `install.package_manager` | `install` | `security_detection` | `atomic` | `alert` | none | Package manager install; no specific ATLAS technique. |
| `exfil.outbound_upload` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Outbound upload or object-store copy. |
| `persistence.shell_profile` | `persistence` | `security_detection` | `atomic` | `alert` | none | Shell profile/service persistence; traditional, not AI-specific. |
| `approval.bypass.context` | `approval_bypass` | `policy_violation` | `atomic` | `alert` | `atlas:AML.T0051` | Bypass-approval language often overlaps prompt injection. |
| `tool.injection.shape` | `tool_injection` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0051` | Tool-call-shaped content may spoof or steer tool use. |
| `mcp.tool_metadata.prompt_injection` | `mcp_prompt_injection` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0051` | MCP metadata/tool result contains injection instructions. |
| `network.controlled_test_domain.darkroast` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Controlled tester domain contact. |
| `exfil.dns_encoding` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Base64-encoded DNS exfiltration. |
| `exfil.encoded_http` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Encoded data sent to external HTTP endpoint. |
| `credential.cloud_harvest` | `credential_harvesting` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0055` | Cloud provider credential files. |
| `supply_chain.publish` | `supply_chain` | `security_detection` | `atomic` | `alert` | none | Package publishing command; the act itself is not an ATLAS technique. |
| `mcp.server_enumeration` | `mcp_enumeration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0084` | MCP server/tool enumeration and probing. |

### Bundled Chain Modifiers (`config/rules/tool-call-regex.yaml`)

| ADR Modifier | Trigger | Detection Class | Signal Type | Analytic Intent | ATLAS Tags | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `chain.secret_then_network` | `secret_access` + `download` | `security_detection` | `chain` | `alert` | none | ADR-specific correlation; no single ATLAS technique. |
| `chain.download_then_execute` | `download` + `execution` | `security_detection` | `chain` | `alert` | none | Traditional download-execute pattern. |
| `chain.shell_encoded_payload` | `execution.shell` + `execution.encoded_payload` | `security_detection` | `chain` | `alert` | none | Obfuscated shell execution; ADR-specific scoring. |
| `chain.install_then_persistence` | `install` + `persistence` | `security_detection` | `chain` | `alert` | none | Install near persistence surfaces. |
| `chain.mcp_injection_then_egress` | `mcp_prompt_injection` + `exfiltration` | `security_detection` | `chain` | `alert` | `atlas:AML.T0051`, `atlas:AML.T0086` | Prompt injection plus agent-tool egress. |
| `chain.credential_then_publish` | `credential_harvesting` + `supply_chain` | `security_detection` | `chain` | `alert` | none | Credential harvesting near package publishing. |
| `chain.harvest_then_exfil` | `credential_harvesting` + `exfiltration` | `security_detection` | `chain` | `alert` | `atlas:AML.T0055`, `atlas:AML.T0025` | Credential theft followed by exfiltration. |
| `chain.mcp_enumeration_then_injection` | `mcp_enumeration` + `mcp_prompt_injection` | `security_detection` | `chain` | `alert` | `atlas:AML.T0084`, `atlas:AML.T0051` | MCP discovery followed by prompt injection. |

### Example Rules

| ADR Rule | ADR Category | Detection Class | Signal Type | Analytic Intent | ATLAS Tags | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `adhoc.agent_tool_exfil_phrase` | `exfiltration` | `threat_hunting` | `atomic` | `hunt` | `atlas:AML.T0086`, `atlas:AML.T0025` | Ad-hoc hunt for agent-tool exfiltration language. |
| `policy.agent_guardrail_modification` | `persistence` | `policy_violation` | `atomic` | `audit` | `atlas:AML.T0081` | Edits to agent guardrails, policy, skills, or config files. |

## Coverage Summary

- Bundled rules: 18 (13 with ATLAS tags, 5 intentionally untagged)
- Bundled chain modifiers: 8 (3 with ATLAS tags, 5 intentionally untagged)
- Example rules: 2 (2 with ATLAS tags)
- Distinct ATLAS techniques referenced: 8 (`AML.T0050`, `AML.T0051`, `AML.T0025`, `AML.T0055`, `AML.T0057`, `AML.T0081`, `AML.T0084`, `AML.T0086`)
- Distinct ATLAS tactics referenced: 6 (`AML.TA0005`, `AML.TA0006`, `AML.TA0007`, `AML.TA0008`, `AML.TA0010`, `AML.TA0013`)

## Open Mapping Work

Rules without `atlas_tags` are not automatically deficient. Prefer no ATLAS tag over a weak mapping. Add tags only when the relationship is specific and defensible, and keep this reference aligned with the published rule set.

Candidate techniques for future mapping as detection content grows:

| ADR Area | Candidate ATLAS Technique | Why It May Fit Later |
| --- | --- | --- |
| Agent tool invocation / command execution | `AML.T0053` | When ADR detects unauthorized tool invocation distinct from shell execution. |
| Supply chain compromise | `AML.T0010`, `AML.T0104`, `AML.T0109` | When ADR adds poisoned-package or rug-pull detections. |
| Agent context poisoning / memory | `AML.T0080` | When ADR detects memory or thread manipulation. |
| Jailbreak / guardrail bypass | `AML.T0054` | When ADR adds explicit jailbreak detection beyond approval bypass. |
| Prompt obfuscation | `AML.T0068` | When ADR detects obfuscated injection payloads. |
| Credential harvesting from agent config | `AML.T0083` | When ADR distinguishes agent-config credentials from cloud credentials. |
| Data destruction via agent tools | `AML.T0101` | When ADR adds destructive tool-use detections. |
| Agentic resource consumption | `AML.T0034.002` | When ADR adds cost/resource-abuse detections. |