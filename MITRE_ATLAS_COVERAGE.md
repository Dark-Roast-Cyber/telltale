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

All Telltale rules use the same rule structure, regardless of purpose:

- `category`: concrete behavior observed by Telltale, such as `exfiltration`, `approval_bypass`, or `mcp_prompt_injection`.
- `detection_class`: why the rule exists, such as `security_detection`, `threat_hunting`, or `policy_violation`.
- `signal_type`: analytic shape, such as `atomic`, `chain`, or `correlation`.
- `analytic_intent`: how analysts should treat the event, such as `alert`, `hunt`, `audit`, `enrich`, or `baseline`.
- `atlas_tags`: optional ATLAS context tags.

Policy violations, bleeding-edge ad-hoc hunts, and production alerts are all normal Telltale rules. They may live in separate bundles for organizational clarity, but they use the same syntax, validation, fixture expectations, scoring, redaction, and event schema.

## ATLAS Reference (v2026.09)

ATLAS is the Adversarial Threat Landscape for AI Systems. This document is aligned to ATLAS content release `2026.09`, published September 14, 2026. The canonical structured data is `dist/v6/ATLAS-2026.09.yaml` from `github.com/mitre-atlas/atlas-data`.

ATLAS v2026.09 contains 1 matrix, 16 tactics, 120 techniques, 88 sub-techniques, 40 mitigations, and 73 case studies. The September release added agent-focused techniques including `AML.T0133` Discover AI Agent Runtime Capabilities. The July and August releases also added or refined techniques that matter to Telltale, including AI Agent Tool Poisoning, Publish Poisoned AI Artifacts, and Obfuscated Files or Information.

Telltale uses ATLAS for offline analyst context only. It never fetches ATLAS at runtime.

### Tactics represented by current Telltale tags

| Tactic ID | Tactic Name | Telltale Relevance |
| --- | --- | --- |
| `AML.TA0005` | Execution | Shell/interpreter execution and prompt injection. |
| `AML.TA0006` | Persistence | Agent configuration modification and tool poisoning context. |
| `AML.TA0007` | Defense Evasion | Guardrail modification and obfuscation-related future mappings. |
| `AML.TA0008` | Discovery | Agent configuration and runtime capability discovery. |
| `AML.TA0010` | Exfiltration | Outbound upload, encoded egress, DNS exfiltration, and agent-tool exfiltration. |
| `AML.TA0013` | Credential Access | Secret files, private keys, cloud credential stores, and agent configuration credentials. |

### Techniques currently emitted by Telltale rule content

The entries below are the ATLAS IDs currently present in bundled or example rule YAML. This is an inventory of emitted metadata, not a claim that every match proves the complete adversary behavior described by ATLAS.

| Technique ID | Technique Name | Current Telltale Use | v2026.09 Review |
| --- | --- | --- | --- |
| `AML.T0050` | Command and Scripting Interpreter | Shell/interpreter activity and encoded-payload commands. | Strong for `execution.shell`; `AML.T0123` is more precise for pure encoding/obfuscation behavior. |
| `AML.T0051` | LLM Prompt Injection | Approval-bypass context, tool-call-shaped content, MCP metadata/tool-result injection, and injection chains. | Strong when untrusted instructions are established; broad when only suspicious language or tool-call shape is observed. |
| `AML.T0025` | Exfiltration via Cyber Means | HTTP/object-store upload, encoded HTTP, DNS exfiltration, controlled test-domain matches, and exfiltration chains. | Strong for observed egress; a domain string alone does not establish exfiltration. |
| `AML.T0055` | Unsecured Credentials | Secret files, private keys, cloud credential files, and credential-harvest chains. | Strong for credential access/search behavior. |
| `AML.T0057` | LLM Data Leakage | Credential-shaped tokens present in agent-visible fields. | Broader than the ATLAS technique. Token presence does not prove that an LLM leaked the value. |
| `AML.T0081` | Modify AI Agent Configuration | Example policy rule for guardrail, policy, skill, and agent-config paths. | Conceptually strong, but the example rule can match a path reference without proving a write or modification. |
| `AML.T0084` | Discover AI Agent Configuration | MCP server/tool enumeration and its correlation chain. | `AML.T0133` is now more precise for runtime tool/capability enumeration. Retain `T0084` for actual configuration discovery. |
| `AML.T0086` | Exfiltration via AI Agent Tool Invocation | MCP-injection-plus-egress chain and an ad-hoc agent-tool exfiltration phrase hunt. | Use only when structured evidence establishes agent tool invocation. Generic egress or descriptive text alone is insufficient. |

### More precise ATLAS 2026.09 techniques now relevant to Telltale

These techniques are not automatically emitted by current bundled rules. They identify where current rules can be narrowed or future Detection v2 content can use stronger harness semantics.

| Technique ID | Technique Name | Telltale Relevance |
| --- | --- | --- |
| `AML.T0133` | Discover AI Agent Runtime Capabilities | Runtime enumeration of registered tools, parameters, reachable resources, identity, or permission scope. More precise than `T0084` for `mcp.server_enumeration`. |
| `AML.T0110.000` | AI Agent Tool Poisoning: Definition and Instructions | Malicious model-visible tool descriptions, schemas, manifests, skill instructions, parameter descriptions, or other static tool metadata. |
| `AML.T0110.002` | AI Agent Tool Poisoning: Runtime Response | Malicious instructions or deceptive content returned by a tool and incorporated into subsequent model context. |
| `AML.T0123` | Obfuscated Files or Information | Encoded or otherwise obfuscated commands, payloads, credentials, or communications. |
| `AML.T0098` | AI Agent Tool Credential Harvesting | Agent-mediated retrieval of credentials from connected tools such as code repositories, document stores, email, or collaboration systems. |
| `AML.T0083` | Credentials from AI Agent Configuration | Credentials obtained from agent configuration, including tool/service tokens and connection material. |
| `AML.T0115.002` | Publish Poisoned AI Artifacts: AI Agent Tools | Publishing poisoned agent tools through registries, repositories, tool hubs, or hosted services. This supersedes the former `AML.T0104` identifier. |

## Coverage Table

The table covers every bundled rule, chain modifier, and example rule in the repository. The ATLAS Tags column reflects the rule YAML as shipped today. Rules without `atlas_tags` are intentionally untagged. Prefer no ATLAS tag over a weak mapping.

### Bundled Rules (`config/rules/tool-call-regex.yaml`)

| Rule | ADR Category | Detection Class | Signal Type | Analytic Intent | ATLAS Tags | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `secret.env.read` | `secret_access` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0055` | Access to `.env`-style secret files. |
| `secret.private_key.read` | `secret_access` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0055` | SSH keys, PEM/P12, private key material. |
| `credential.api_key.pattern` | `credential_pattern` | `threat_hunting` | `atomic` | `hunt` | `atlas:AML.T0057` | Credential-shaped token presence. Current tag is broader than ATLAS leakage semantics because the rule does not establish disclosure or transfer. |
| `execution.shell` | `execution` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0050` | Shell or interpreter invocation. |
| `execution.encoded_payload` | `execution` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0050` | Encoded/decoded payload behavior. Consider `AML.T0123` when the detection is specifically about obfuscation rather than execution. |
| `network.download` | `download` | `security_detection` | `atomic` | `alert` | none | HTTP/FTP retrieval by a download client; outbound POST/`--data` is not a download. |
| `install.package_manager` | `install` | `security_detection` | `atomic` | `alert` | none | Package manager install; no specific ATLAS technique is asserted. |
| `exfil.outbound_upload` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Outbound upload or object-store copy. |
| `persistence.shell_profile` | `persistence` | `security_detection` | `atomic` | `alert` | none | Shell profile/service persistence; traditional, not AI-specific. |
| `approval.bypass.context` | `approval_bypass` | `policy_violation` | `atomic` | `alert` | `atlas:AML.T0051` | Suspicious approval-bypass language. Current tag is strongest only when the instruction originated from an untrusted prompt or tool context. |
| `tool.injection.shape` | `tool_injection` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0051` | Tool-call-shaped content may spoof or steer tool use; shape alone does not prove prompt injection. |
| `mcp.tool_metadata.prompt_injection` | `mcp_prompt_injection` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0051` | Strong prompt-injection mapping. ATLAS 2026.09 also provides `AML.T0110.000` for poisoned tool definitions and `AML.T0110.002` for poisoned runtime responses. |
| `network.controlled_test_domain.darkroast` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Controlled-domain string match. Current tag is only semantically complete when the observation establishes actual egress. |
| `exfil.dns_encoding` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Base64-encoded DNS exfiltration. |
| `exfil.encoded_http` | `exfiltration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0025` | Encoded hostname or base64 request material sent through an HTTP client. |
| `credential.cloud_harvest` | `credential_harvesting` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0055` | Cloud provider credential files. |
| `supply_chain.publish` | `supply_chain` | `security_detection` | `atomic` | `alert` | none | Package publishing command; the act itself does not prove publication of a poisoned AI artifact. |
| `mcp.server_enumeration` | `mcp_enumeration` | `security_detection` | `atomic` | `alert` | `atlas:AML.T0084` | Current emitted tag. `AML.T0133` is more precise for runtime MCP/tool capability enumeration in ATLAS 2026.09. |

### Bundled Chain Modifiers (`config/rules/tool-call-regex.yaml`)

| Modifier | Trigger | Detection Class | Signal Type | Analytic Intent | ATLAS Tags | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `chain.secret_then_network` | `secret_access` + `download` | `security_detection` | `chain` | `alert` | none | Telltale-specific correlation; no single ATLAS technique. |
| `chain.download_then_execute` | `download` + `execution` | `security_detection` | `chain` | `alert` | none | Traditional download-execute pattern. |
| `chain.shell_encoded_payload` | `execution.shell` + `execution.encoded_payload` | `security_detection` | `chain` | `alert` | none | Obfuscated shell execution. `AML.T0050` plus `AML.T0123` is a candidate mapping if rule metadata is revised. |
| `chain.install_then_persistence` | `install` + `persistence` | `security_detection` | `chain` | `alert` | none | Install near persistence surfaces. |
| `chain.mcp_injection_then_egress` | `mcp_prompt_injection` + `exfiltration` | `security_detection` | `chain` | `alert` | `atlas:AML.T0051`, `atlas:AML.T0086` | `T0051` is strong. `T0086` should be retained only if the correlated egress is known to be an agent tool invocation rather than generic command/network egress. |
| `chain.credential_then_publish` | `credential_harvesting` + `supply_chain` | `security_detection` | `chain` | `alert` | none | Credential harvesting near package publishing. |
| `chain.harvest_then_exfil` | `credential_harvesting` + `exfiltration` | `security_detection` | `chain` | `alert` | `atlas:AML.T0055`, `atlas:AML.T0025` | Credential access followed by cyber exfiltration. |
| `chain.mcp_enumeration_then_injection` | `mcp_enumeration` + `mcp_prompt_injection` | `security_detection` | `chain` | `alert` | `atlas:AML.T0084`, `atlas:AML.T0051` | Current emitted tags. `AML.T0133` is more precise for the runtime enumeration half of the chain. |

### Example Rules

| Rule | ADR Category | Detection Class | Signal Type | Analytic Intent | ATLAS Tags | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `adhoc.agent_tool_exfil_phrase` | `exfiltration` | `threat_hunting` | `atomic` | `hunt` | `atlas:AML.T0086`, `atlas:AML.T0025` | Phrase hunt for agent-tool exfiltration language. It does not by itself prove tool invocation or exfiltration, so these tags are hypothesis context rather than confirmed behavior. |
| `policy.agent_guardrail_modification` | `persistence` | `policy_violation` | `atomic` | `audit` | `atlas:AML.T0081` | Agent guardrail/policy/config path detection. A future operation-aware rule should distinguish reads/references from actual modifications. |

## Coverage Summary

Current shipped/example rule metadata remains:

- Bundled rules: 18 (13 with ATLAS tags, 5 intentionally untagged)
- Bundled chain modifiers: 8 (3 with ATLAS tags, 5 intentionally untagged)
- Example rules: 2 (2 with ATLAS tags)
- Distinct ATLAS technique IDs currently emitted: 8 (`AML.T0050`, `AML.T0051`, `AML.T0025`, `AML.T0055`, `AML.T0057`, `AML.T0081`, `AML.T0084`, `AML.T0086`)
- Distinct ATLAS tactics represented by those technique relationships: 6 (`AML.TA0005`, `AML.TA0006`, `AML.TA0007`, `AML.TA0008`, `AML.TA0010`, `AML.TA0013`)

The ATLAS 2026.09 review does not silently change rule metadata. Updating `atlas_tags` is a detection-content change and should move with the relevant rule semantics and fixtures.

## Open Mapping Work

Rules without `atlas_tags` are not automatically deficient. Prefer no ATLAS tag over a weak mapping. Add tags only when the relationship is specific and defensible, and keep this reference aligned with the published rule set.

Highest-value mapping/convergence work:

| Telltale Area | Candidate ATLAS Technique | Why It Fits |
| --- | --- | --- |
| MCP/tool runtime enumeration | `AML.T0133` | Direct match for runtime discovery of agent tools, parameters, capabilities, reachable resources, identity, and permissions. Candidate replacement for `AML.T0084` on `mcp.server_enumeration`. |
| MCP/tool definition poisoning | `AML.T0110.000` | Direct match for malicious tool descriptions, parameter descriptions, schemas, manifests, and skill instructions. |
| MCP/tool response poisoning | `AML.T0110.002` | Direct match for malicious runtime tool responses that influence subsequent model behavior. |
| Encoded/obfuscated payloads | `AML.T0123` | More precise than command execution when the observed behavior is encoding, decoding, chunking, or obfuscation itself. |
| Agent tool invocation | `AML.T0053` | Use when Telltale establishes that the agent invoked a tool, distinct from generic process execution. |
| Agent-tool credential harvesting | `AML.T0098` | Use when credentials are retrieved through connected agent tools rather than local credential files alone. |
| Credentials from agent configuration | `AML.T0083` | Use when Telltale can establish that credentials came specifically from agent/tool configuration. |
| Agent configuration discovery | `AML.T0084` | Retain for reads of actual agent configuration, dashboards, config files, or equivalent configuration sources. |
| Agent context poisoning / memory | `AML.T0080` | Use when Telltale detects persistent manipulation of memory or conversation/thread context. |
| Jailbreak / guardrail bypass | `AML.T0054` | Use when an explicit jailbreak is detected rather than generic approval-bypass language. |
| Prompt obfuscation | `AML.T0068` | Use when an injection payload is deliberately hidden or encoded to evade review or defenses. |
| Agent-tool exfiltration | `AML.T0086` | Use when structured tool invocation evidence shows sensitive data transmitted through an agent tool. |
| Poisoned agent-tool publication | `AML.T0115.002` | Current ATLAS replacement for the former `AML.T0104` Publish Poisoned AI Agent Tool technique. |
| AI supply chain compromise / rug pull | `AML.T0010`, `AML.T0109` | Use when Telltale adds evidence for compromised AI components or trusted components that later become malicious. |
| Data destruction via agent tools | `AML.T0101` | Use when destructive agent tool invocation is observed. |
| Agentic resource consumption | `AML.T0034.002` | Use when Telltale adds cost, recursive delegation, or excessive tool-use abuse detections. |

### Rule-content changes that should accompany future retagging

1. Split `mcp.tool_metadata.prompt_injection` by evidence source so static definition/instruction poisoning can map to `AML.T0110.000` and malicious runtime responses can map to `AML.T0110.002`.
2. Move `mcp.server_enumeration` toward `AML.T0133` when the detector is specifically observing runtime capability enumeration. Keep `AML.T0084` for actual configuration discovery.
3. Replace `credential.api_key.pattern -> AML.T0057` with a leakage rule that establishes sensitive material moving into model output or an outbound tool/action.
4. Retag `execution.encoded_payload` or a narrower successor with `AML.T0123` when obfuscation is the observed behavior.
5. Require actual egress before treating controlled-domain presence as `AML.T0025`.
6. Require untrusted instruction provenance before treating approval-bypass language as `AML.T0051`.
7. Require structured agent-tool invocation before emitting `AML.T0086`.
8. Make the guardrail/config rule operation-aware before treating a path reference as `AML.T0081`.

These are detection-content changes, not documentation-only corrections, and should be implemented with the corresponding fixtures and rule tests.
