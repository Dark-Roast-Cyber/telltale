# Threat Taxonomy

> **Website:** For an approachable overview of detection categories and threat taxonomy, see [AgentArchaeology.ai/telltale/detection-model](https://agentarchaeology.ai/telltale/detection-model/).

## Purpose

ADR uses its own operational categories for deterministic detection, scoring, policy filters, and SIEM output. MITRE ATLAS is an offline reference for naming, tagging, and documentation only.

ATLAS must not be fetched or parsed during `telltale scan`, `telltale rules validate`, tests, or normal runtime execution. Use it while authoring detection content, then commit the resulting ADR rule tags, explanations, fixtures, and docs.

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
TELLTALE_ATLAS_PATH=/path/to/ATLAS.yaml scripts/atlas-lookup exfiltration --json
```

If the local file is absent, the helper prints setup instructions and exits without network access.

## Tagging Contract

Every bundled detection rule must have exactly one ADR `category`. The category is the operational classification used by the rule engine and policy filters.

ATLAS tags are optional. Add them only when the mapping is specific and defensible:

- `atlas:AML.T0051`
- `atlas:AML.T0051.001`
- `atlas:AML.TA0005`

Do not add an ATLAS tag just because a keyword matches. Prefer no ATLAS tag over a weak mapping. Keep ADR categories stable even when ATLAS terminology changes.

## Detection Content Guidance

When authoring or reviewing detection content:

1. Assign exactly one ADR category to each rule.
2. Use `scripts/atlas-lookup <term>` only against a local `ATLAS.yaml` file when ATLAS context is relevant.
3. Add ATLAS tags only when a concrete tactic or technique explains the rule.
4. Keep rule explanations in ADR terms: what happened, why it matters, and what evidence is safe for SIEM.
5. Keep fixtures synthetic and validation offline.

## ADR Categories

| Category | Meaning | Typical Evidence | Current Bundled Rules |
| --- | --- | --- | --- |
| `secret_access` | The agent accessed local secret-bearing files or private key material. | `.env`, SSH keys, PEM/P12 files. | `secret.env.read`, `secret.private_key.read` |
| `credential_pattern` | Credential-like material appeared in agent context or tool data. | API keys, JWTs, bearer tokens, cloud access key patterns. | `credential.api_key.pattern` |
| `execution` | The agent used shell or interpreter execution, especially obfuscated execution. | `bash`, `python -c`, `node -e`, base64 decode, `certutil -decode`. | `execution.shell`, `execution.encoded_payload` |
| `download` | The agent fetched remote content or invoked a download-capable client. | `wget`, `curl` GET/retrieval, PowerShell web requests, `fetch`. Outbound POST/`--data` is not a download. | `network.download` |
| `install` | The agent invoked package managers or installers. | `npm install`, `pip install`, `cargo install`, `apt install`. | `install.package_manager` |
| `exfiltration` | The agent sent, staged, or encoded data for outbound transfer. | HTTP POST/upload, object-store copy, encoded HTTP hostnames or base64 bodies, encoded data piped or substituted into a DNS lookup, controlled tester domains. | `exfil.outbound_upload`, `network.controlled_test_domain.darkroast`, `exfil.dns_encoding`, `exfil.encoded_http` |
| `persistence` | The agent wrote or enabled startup, profile, scheduled task, or service persistence. | Redirects, `tee`, in-place edits or copies onto `.bashrc`/`.zshrc` and other startup files, patches to them, `crontab` installs, `systemctl enable`, `launchctl load`. Shell reads such as `grep … ~/.bashrc` and native file-tool reads do not match. | `persistence.shell_profile` |
| `destructive` | The agent ran a command that can delete or discard data. Each rule scores 55, so with shell credit one destructive command reaches security review; the rules cannot tell a requested reset from an unrequested one. | `rm -rf ~/`, `mkfs`, `dd of=/dev/…`; `git reset --hard`, `git push --force`, `git clean -f`; `DROP TABLE`, `dropdb`; `terraform destroy`, `kubectl delete namespace`, `podman system reset`, `docker system prune --volumes`. | `destructive.filesystem_wipe`, `destructive.git_discard`, `destructive.database_drop`, `destructive.infrastructure_teardown` |
| `approval_bypass` | Context asks the agent to avoid user approval, hide behavior, or run silently. | "without asking", "do not tell", "bypass approval", "no confirm". | `approval.bypass.context` |
| `instruction_override` | Assistant output repeats a generic instruction to ignore or disregard prior instructions. It is a zero-point corroborating signal. | "ignore previous instructions", "disregard all prior instructions". | `prompt_injection.instruction_override` |
| `tool_injection` | Tool-call-shaped content appears where it may spoof or steer tool use. | `<tool_call>`, `tool_calls`, `function_call`, `recipient_name`, `arguments`. | `tool.injection.shape` |
| `mcp_prompt_injection` | MCP metadata, server instructions, tool descriptions, parameters, or tool results try to steer the agent. | `tools/list`, tool description, parameter description, server instructions, tool result plus hidden instructions. | `mcp.tool_metadata.prompt_injection` |
| `credential_harvesting` | The agent read, copied, encoded, archived or sent a cloud, container, or orchestration credential file, or opened one with a native file tool. | `cat ~/.aws/credentials`, `tar … ~/.kube/config`, `curl -T ~/.aws/credentials`, Docker config, service-account files. A CLI given the path it authenticates with (`kubectl --kubeconfig ~/.kube/config`, `KUBECONFIG=`, `--key-file`) does not match. | `credential.cloud_harvest` |
| `supply_chain` | The agent attempted package publishing or release actions. | `npm publish`, `cargo publish`, `twine upload`, `gem push`. | `supply_chain.publish` |
| `mcp_enumeration` | The agent probed MCP servers, tools, or capabilities. | Repeated `tools/list`, MCP server probing, enumeration language. | `mcp.server_enumeration` |
| `defense_evasion` | LOLBin proxy execution, log or recovery tampering, or interference with security tooling. | `rundll32`, `mshta`, `regsvr32`, `wevtutil cl`, `fltmc unload`. | `procchain.evasion.*` |
| `command_and_control` | Download cradles, remote-management abuse, or tunnelling. | `certutil -urlcache`, RMM agents spawning shells, `ngrok`, `chisel`. | `procchain.c2.*` |
| `discovery` | Host, account, network, service, or directory enumeration. | `whoami`, `net user`, `nltest`, `adfind`, `sharphound`. | `procchain.discovery.*` |
| `credential_access` | Access to credential stores, LSASS memory, registry hives, or the AD database. | `mimikatz`, `procdump lsass`, `reg save hklm\\sam`, `ntdsutil ifm`. | `procchain.credaccess.*` |
| `lateral_movement` | Remote execution against other hosts. | PsExec, WinRM, DCOM, `sshd`, GPO deployment. | `procchain.lateral.*` |
| `impact` | Destruction of recovery data or availability. | `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit recoveryenabled no`. | `procchain.impact.*` |
| `collection` | Local data staged for transfer. | `rar`/`7z` archive creation, especially password-protected. | `procchain.collection.*` |

## Derived Chain Modifiers

Chain modifiers add score and derived rule IDs when the steps they name are linked. Each bundled chain declares its link: the steps fall within a number of tool calls of each other, counted so that a call and its result count once and messages add no distance, in declared order unless the link allows any order. One call that matches every step always links. `chain.download_then_execute` has its own link, below. A modifier without a link, such as one in a rule pack written before links, keeps co-occurrence anywhere in the session. Modifiers do not replace the single category assigned to each base rule.

| Modifier | Trigger | Meaning |
| --- | --- | --- |
| `chain.secret_then_network` | `secret_access` + `exfiltration` | Secret access, then an outbound transfer within three tool calls. A secret read and a download do not chain. |
| `chain.download_then_execute` | `download` + `execution`, linked | Downloaded content ran: a download piped to an interpreter, or a downloaded file executed within 15 minutes. A download and an unrelated shell call do not chain. |
| `chain.shell_encoded_payload` | `execution.shell` + `execution.encoded_payload` | Shell execution and decoded payload behavior in the same call. |
| `chain.mcp_injection_then_egress` | `mcp_prompt_injection` + `exfiltration` | Prompt/tool poisoning, then outbound transfer within three tool calls. |
| `chain.credential_then_publish` | `credential_harvesting` + `supply_chain` | Credential harvesting, then package publishing within three tool calls. |
| `chain.harvest_then_exfil` | `credential_harvesting` + `exfiltration` | Credential harvesting, then data theft behavior within three tool calls. |
| `chain.mcp_enumeration_then_injection` | `mcp_enumeration` + `mcp_prompt_injection` | MCP probing, then prompt-injection behavior within three tool calls. |
| `chain.instruction_override_with_approval_bypass` | `instruction_override` + `approval_bypass` | An assistant instruction override and an approval-bypass directive within three tool calls of each other, in either order. |

Process-chain correlations are separate from these modifiers: they require an
ordered sequence within a time window and an entity boundary. See
[process-chain-detections.md](process-chain-detections.md).

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
