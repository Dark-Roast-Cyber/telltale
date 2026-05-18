# Threat Taxonomy

## Purpose

ADR uses its own operational categories for deterministic detection, scoring, policy filters, and SIEM output. MITRE ATLAS is an offline reference for naming, tagging, and documentation only.

ATLAS must not be fetched or parsed during `adr scan`, `adr rules validate`, tests, or normal runtime execution. Use it while authoring detection content, then commit the resulting ADR rule tags, explanations, fixtures, and docs.

## Offline ATLAS Reference

The optional local ATLAS copy should live at:

```text
references/atlas-data/dist/ATLAS.yaml
```

Create it with a local sparse clone:

```sh
mkdir -p references
git clone --filter=blob:none --sparse https://github.com/mitre-atlas/atlas-data references/atlas-data
git -C references/atlas-data sparse-checkout set dist
```

The helper reads only the local file:

```sh
scripts/atlas-lookup "prompt injection"
scripts/atlas-lookup AML.T0051 --description
ADR_ATLAS_PATH=/path/to/ATLAS.yaml scripts/atlas-lookup exfiltration --json
```

If the local file is absent, the helper prints setup instructions and exits without network access.

## Tagging Contract

Every bundled detection rule must have exactly one ADR `category`. The category is the operational classification used by the rule engine and policy filters.

ATLAS tags are optional. Add them only when the mapping is specific and defensible:

- `atlas:AML.T0051`
- `atlas:AML.T0051.001`
- `atlas:AML.TA0005`

Do not add an ATLAS tag just because a keyword matches. Prefer no ATLAS tag over a weak mapping. Keep ADR categories stable even when ATLAS terminology changes.

## AI Coder Workflow

When creating or changing detection content:

1. Read this file before editing `config/rules/tool-call-regex.yaml`.
2. Assign exactly one ADR category to each rule.
3. Use `scripts/atlas-lookup <term>` only against a local `ATLAS.yaml` file when ATLAS context is relevant.
4. Add ATLAS tags only when a concrete tactic or technique explains the rule.
5. Keep the rule explanation in ADR terms: what the agent did, why it matters, and what evidence is safe for SIEM.
6. Add or update synthetic fixtures.
7. Validate the rule file and run the narrowest relevant tests.

## ADR Categories

| Category | Meaning | Typical Evidence | Current Bundled Rules |
| --- | --- | --- | --- |
| `secret_access` | The agent accessed local secret-bearing files or private key material. | `.env`, SSH keys, PEM/P12 files. | `secret.env.read`, `secret.private_key.read` |
| `credential_pattern` | Credential-like material appeared in agent context or tool data. | API keys, JWTs, bearer tokens, cloud access key patterns. | `credential.api_key.pattern` |
| `execution` | The agent used shell or interpreter execution, especially obfuscated execution. | `bash`, `python -c`, `node -e`, base64 decode, `certutil -decode`. | `execution.shell`, `execution.encoded_payload` |
| `download` | The agent fetched remote content or invoked a download-capable client. | `curl`, `wget`, PowerShell web requests, `fetch`. | `network.download` |
| `install` | The agent invoked package managers or installers. | `npm install`, `pip install`, `cargo install`, `apt install`. | `install.package_manager` |
| `exfiltration` | The agent sent, staged, or encoded data for outbound transfer. | HTTP POST/upload, object-store copy, encoded HTTP, DNS encoding, controlled tester domains. | `exfil.outbound_upload`, `network.controlled_test_domain.darkroast`, `exfil.dns_encoding`, `exfil.encoded_http` |
| `persistence` | The agent touched startup, profile, scheduled task, or service persistence surfaces. | `.bashrc`, `.zshrc`, `crontab`, `systemctl enable`, `launchctl load`. | `persistence.shell_profile` |
| `approval_bypass` | Context asks the agent to avoid user approval, hide behavior, or run silently. | "without asking", "do not tell", "bypass approval", "no confirm". | `approval.bypass.context` |
| `tool_injection` | Tool-call-shaped content appears where it may spoof or steer tool use. | `<tool_call>`, `tool_calls`, `function_call`, `recipient_name`, `arguments`. | `tool.injection.shape` |
| `mcp_prompt_injection` | MCP metadata, server instructions, tool descriptions, parameters, or tool results try to steer the agent. | `tools/list`, tool description, parameter description, server instructions, tool result plus hidden instructions. | `mcp.tool_metadata.prompt_injection` |
| `credential_harvesting` | The agent targeted local, cloud, container, or orchestration credential stores. | `.aws/credentials`, `.kube/config`, Docker config, service-account files. | `credential.cloud_harvest` |
| `supply_chain` | The agent attempted package publishing or release actions. | `npm publish`, `cargo publish`, `twine upload`, `gem push`. | `supply_chain.publish` |
| `mcp_enumeration` | The agent probed MCP servers, tools, or capabilities. | Repeated `tools/list`, MCP server probing, enumeration language. | `mcp.server_enumeration` |

## Derived Chain Modifiers

Chain modifiers add score and derived rule IDs when multiple categories or rules appear together. They do not replace the single category assigned to each base rule.

| Modifier | Trigger | Meaning |
| --- | --- | --- |
| `chain.secret_then_network` | `secret_access` + `download` | Secret access occurred near network-capable behavior. |
| `chain.download_then_execute` | `download` + `execution` | Remote content was fetched near executable behavior. |
| `chain.shell_encoded_payload` | `execution.shell` + `execution.encoded_payload` | Shell execution and decoded payload behavior appeared together. |
| `chain.install_then_persistence` | `install` + `persistence` | Installation occurred near startup or service modification. |
| `chain.mcp_injection_then_egress` | `mcp_prompt_injection` + `exfiltration` | Prompt/tool poisoning appeared near outbound transfer. |
| `chain.credential_then_publish` | `credential_harvesting` + `supply_chain` | Credential harvesting appeared near package publishing. |
| `chain.harvest_then_exfil` | `credential_harvesting` + `exfiltration` | Credential harvesting appeared near data theft behavior. |
| `chain.mcp_enumeration_then_injection` | `mcp_enumeration` + `mcp_prompt_injection` | MCP probing appeared near prompt-injection behavior. |

## ATLAS Alignment Guidance

Use ATLAS to improve analyst vocabulary, not to force complete coverage. Some ADR categories align naturally with ATLAS tactics or techniques; others are ADR-specific operational signals.

Useful starting searches:

| ADR Area | Suggested Lookup |
| --- | --- |
| MCP or web/tool prompt injection | `scripts/atlas-lookup "prompt injection"` |
| Tool metadata or tool result poisoning | `scripts/atlas-lookup "tool poisoning"` |
| Outbound transfer or encoded egress | `scripts/atlas-lookup exfiltration` |
| Persistence through prompt or configuration changes | `scripts/atlas-lookup persistence` |
| Agent command and control patterns | `scripts/atlas-lookup "command and control"` |

Record the final mapping in rule tags only when the lookup result clearly describes the ADR behavior.
