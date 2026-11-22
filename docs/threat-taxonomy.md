# Threat Taxonomy

> **Website:** For an approachable overview of detection categories and threat taxonomy, see [AgentArchaeology.ai/telltale/detection-model](https://agentarchaeology.ai/telltale/detection-model/).

## Purpose

ADR uses its own operational categories for deterministic detection, scoring, policy filters, and SIEM output. MITRE ATLAS is an offline reference for naming, tagging, and documentation only.

ATLAS must not be fetched or parsed during `telltale scan`, `telltale rules validate`, tests, or normal runtime execution. Use it while authoring detection content, then commit the resulting ADR rule tags, explanations, fixtures, and docs. Rule-to-ATLAS coverage is tracked in [telltale-detections](https://github.com/Dark-Roast-Cyber/telltale-detections/blob/main/docs/atlas-coverage.md).

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
2. Add ATLAS tags only when a concrete tactic or technique explains the rule.
3. Keep rule explanations in ADR terms: what happened, why it matters, and what evidence is safe for SIEM.
4. Keep fixtures synthetic and validation offline.

## ADR Categories

| Category | Meaning | Typical Evidence | Current Bundled Rules |
| --- | --- | --- | --- |
| `secret_access` | The agent accessed local secret-bearing files or private key material. | `.env`, SSH keys, PEM/P12 files. | `secret.env.read`, `secret.private_key.read` |
| `credential_pattern` | Credential-like material appeared in agent context or tool data. | API keys, JWTs, bearer tokens, cloud access key patterns. | `credential.api_key.pattern` |
| `execution` | The agent used shell or interpreter execution, especially obfuscated execution. Decoded content scores as executed when the same command runs it directly (a pipe to a shell or to an interpreter reading standard input, substitution into `eval`, `source`, a shell or an interpreter, a variable that `eval` runs, or `Invoke-Expression`, a script block or an assembly load), decodes with `certutil`, or decodes to an executable-looking file followed by a run step. | `bash`, `python -c`, `node -e`, `base64 -d \| sh`, `eval "$(… \| base64 -d)"`, `certutil -decode`. | `execution.shell`, `execution.encoded_payload` |
| `download` | The agent fetched remote content or invoked a download-capable client. | `wget`, `curl` GET/retrieval, PowerShell web requests (`iwr`, `irm`), `fetch`. Outbound POST/`--data` is not a download. | `network.download` |
| `install` | The agent invoked package managers or installers. | `npm install`, `pip install`, `cargo install`, `apt install`. | `install.package_manager` |
| `exfiltration` | The agent sent, staged, or encoded data for outbound transfer. A bodyless IMDSv2 token request is not an upload. | HTTP POST/upload, object-store copy of a local source to a remote destination (downloads that name the remote source first, and storage inventory, do not match), GitHub CLI publication of a cloud credential file, encoded HTTP hostnames or base64 bodies, encoded data piped or substituted into a DNS lookup, a tool call that names a controlled tester domain. | `exfil.outbound_upload`, `network.controlled_test_domain.darkroast`, `exfil.dns_encoding`, `exfil.encoded_http` |
| `network_reference` | A message or tool result names a destination without any tool call to it. A zero-point hunt signal: a reference alone does not show that anything was sent, so it supplies no `exfiltration` chain step. | Assistant text or a tool result that names a controlled tester domain. | `network.controlled_test_domain.mention` |
| `persistence` | The agent wrote or enabled startup, profile, scheduled task, service, or agent-instruction persistence. | Shell profile edits, `crontab` installs, service enables, or native file-tool writes to `AGENTS.md`, `CLAUDE.md`, and skill entrypoints. Reads and path references do not match the agent-instruction write rule. | `persistence.shell_profile`, `persistence.agent_instruction_write` |
| `destructive` | The agent ran a command that can delete or discard data. Each rule scores 55, so with shell credit one destructive command reaches security review; the rules cannot tell a requested reset from an unrequested one. | `rm -rf ~/`, `mkfs`, `dd of=/dev/…`; `git reset --hard`, `git push --force`, `git clean -f`; `DROP TABLE`, `dropdb`; `terraform destroy`, `kubectl delete namespace`, `podman system reset`, `docker system prune --volumes`. | `destructive.filesystem_wipe`, `destructive.git_discard`, `destructive.database_drop`, `destructive.infrastructure_teardown` |
| `approval_bypass` | Context asks the agent to avoid user approval, hide behavior, or run silently. | "without asking", "do not tell", "bypass approval", "no confirm". | `approval.bypass.context` |
| `instruction_override` | Assistant output or a tool result contains a bounded instruction-override pattern. Both rules are zero-point corroborating signals; the tool-result rule also requires a secret-transfer directive. | "ignore previous instructions", followed in a tool result by a direction to upload secrets. | `prompt_injection.instruction_override`, `prompt_injection.tool_result_egress_directive` |
| `tool_injection` | Tool-call-shaped content appears where it may spoof or steer tool use. | `<tool_call>`, `tool_calls`, `function_call`, `recipient_name`, `arguments`. | `tool.injection.shape` |
| `mcp_prompt_injection` | MCP metadata, server instructions, tool descriptions, parameters, or tool results try to steer the agent. | `tools/list`, tool description, parameter description, server instructions, tool result plus hidden instructions. | `mcp.tool_metadata.prompt_injection` |
| `credential_harvesting` | The agent read, copied, encoded, archived or sent a cloud, container, or orchestration credential file, or opened one with a native file tool. | `cat ~/.aws/credentials`, `tar … ~/.kube/config`, `curl -T ~/.aws/credentials`, `gh gist create` or `gh issue`/`pr comment --body-file` of such a file, Docker config, service-account files. A CLI given the path it authenticates with (`kubectl --kubeconfig ~/.kube/config`, `KUBECONFIG=`, `--key-file`) does not match. | `credential.cloud_harvest` |
| `supply_chain` | The agent attempted package publishing or release actions. | `npm publish`, `cargo publish`, `twine upload`, `gem push`. | `supply_chain.publish` |
| `mcp_enumeration` | The agent probed MCP servers, tools, or capabilities. | Repeated `tools/list`, MCP server probing, enumeration language. | `mcp.server_enumeration` |
| `defense_evasion` | LOLBin proxy execution, log or recovery tampering, interference with security tooling, or decoding. The decode rule is a zero-point hunt signal that marks every decode on the timeline, whether or not the command runs the result. | `rundll32`, `mshta`, `regsvr32`, `wevtutil cl`, `fltmc unload`, `base64 -d file`, `certutil -decode`. | `obfuscation.decode`, `procchain.evasion.*` |
| `command_and_control` | Download cradles, remote-management abuse, or tunnelling. | `certutil -urlcache`, RMM agents spawning shells, `ngrok`, `chisel`. | `procchain.c2.*` |
| `discovery` | Host, account, network, service, or directory enumeration. | `whoami`, `net user`, `nltest`, `adfind`, `sharphound`. | `procchain.discovery.*` |
| `credential_access` | Access to credential stores, LSASS memory, registry hives, or the AD database. | `mimikatz`, `procdump lsass`, `reg save hklm\\sam`, `ntdsutil ifm`. | `procchain.credaccess.*` |
| `lateral_movement` | Remote execution against other hosts. | PsExec, WinRM, DCOM, `sshd`, GPO deployment. | `procchain.lateral.*` |
| `impact` | Destruction of recovery data or availability. | `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit recoveryenabled no`. | `procchain.impact.*` |
| `collection` | Local data staged for transfer. | `rar`/`7z` archive creation, especially password-protected. | `procchain.collection.*` |

### Destructive Git requests

`destructive.git_discard` is one behaviour-family rule, not a rule for every
command spelling. It reads `tool.command`, keeps its existing UUID and 55-point
contribution, and includes explicit file restores, forced checkouts and branch
switches, forced worktree removal, local discard, and remote-history changes.
`--force-with-lease` remains observable: a safer force push still rewrites
history. Plain `git checkout <branch>` and `git restore --staged <path>`
requests are not selected.

Plain clean/push dry runs and help requests have a conservative
`recorded_exclusion` filter. It accepts only whole literal invocations and
valueless options listed in the rule. An option value, pathspec, quoted text,
or an unresolved shell construct cannot by itself establish a safe preview.
Other benign spellings and compound calls can still match. A preview in one
command does not veto a destructive match in another. The selection retains
Telltale's existing quote-removed command reading; the filter reads only the
recorded text.

A match describes a request, not authorization, successful execution or actual
data loss. Authorized restores and history maintenance are expected false
positives. Telltale does not inspect the current filesystem to decide whether
historical work was disposable. Indirect operations and shell or Git state
not present in the recorded command remain coverage limits; this is not a
complete Git interpreter.

The command distinctions were informed by
[CC Safety Net's Git analyzer at revision ab95df5](https://github.com/kenryu42/cc-safety-net/blob/ab95df55d26cca52f49326980be0ef9f81e1406c/src/gate/analyzer/git/rules.ts)
and Git's [clean](https://git-scm.com/docs/git-clean) and
[restore](https://git-scm.com/docs/git-restore) references. Telltale implements
its own bounded Rule v2 patterns; it does not import CC Safety Net's runtime,
blocking policy, filesystem inspection or safety presets. The upstream MIT
notice is retained in the bundled rule source.

## Derived Chain Modifiers

Chain modifiers add score and derived rule IDs when the steps they name are linked. Each bundled chain declares its link: the steps fall within a number of tool calls of each other, counted so that a call and its result count once and messages add no distance, in declared order unless the link allows any order. One call that matches every step always links. `chain.download_then_execute` has its own link, below. A modifier without a link, such as one in a rule pack written before links, keeps co-occurrence anywhere in the session. Modifiers do not replace the single category assigned to each base rule.

| Modifier | Trigger | Meaning |
| --- | --- | --- |
| `chain.secret_then_network` | `secret_access` + `exfiltration` | Secret access, then an outbound transfer within three tool calls. A secret read and a download do not chain. |
| `chain.download_then_execute` | `download` + `execution`, linked | Downloaded content ran: a download piped to an interpreter, a download whose output the same command runs as code (a shell's or `source`'s process-substitution script, `eval` or `sh -c` of a command substitution, PowerShell `iex` of a web request, a Python one-liner that runs a fetched response (experimental)), or a downloaded file executed within 15 minutes. A download and an unrelated shell call do not chain. |
| `chain.shell_encoded_payload` | `execution.shell` + `execution.encoded_payload` | Shell execution and decoded payload behavior in the same call. |
| `chain.mcp_injection_then_egress` | `mcp_prompt_injection` + `exfiltration` | Prompt/tool poisoning, then outbound transfer within three tool calls. |
| `chain.credential_then_publish` | `credential_harvesting` + `supply_chain` | Credential harvesting, then package publishing within three tool calls. |
| `chain.harvest_then_exfil` | `credential_harvesting` + `exfiltration` | Credential harvesting, then data theft behavior within three tool calls. |
| `chain.mcp_enumeration_then_injection` | `mcp_enumeration` + `mcp_prompt_injection` | MCP probing, then prompt-injection behavior within three tool calls. |
| `chain.instruction_override_with_approval_bypass` | `instruction_override` + `approval_bypass` | An assistant instruction override and an approval-bypass directive within three tool calls of each other, in either order. |
| `chain.tool_result_egress_directive_then_upload` | `prompt_injection.tool_result_egress_directive` + `exfil.outbound_upload` | A lower-trust tool result directs secret transfer before an outbound upload command within two tool calls. The observed command is an attempt, not proof of completed transfer. |

Process-chain correlations are separate from these modifiers: they require an
ordered sequence within a time window and an entity boundary. See
[process-chain-detections.md](process-chain-detections.md).

## ATLAS Alignment Guidance

Use ATLAS to improve analyst vocabulary, not to force complete coverage. Some ADR categories align naturally with ATLAS tactics or techniques; others are ADR-specific operational signals. Record a mapping in rule tags only when the ATLAS entry clearly describes the ADR behavior.
