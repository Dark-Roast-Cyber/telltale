# Changelog

> **Release status:** [GitHub Releases](https://github.com/Dark-Roast-Cyber/telltale/releases) is authoritative for published artifacts. `v0.7.0-rc.3` is prepared source only. `v0.7.0-rc.2` is published as prerelease ID `409281155` from `c3132f22f0758912fbcbc7451f5fefee514c5bdb`; five-platform native verification passed in run `38098389234` using verifier tooling `8bc745fac485ffede1c4b06dbbc4ae6862ec5349`. RC2 clean Windows without a Redistributable passed (Issue #87); clean Linux, canary and stable promotion remain pending. `v0.7.0-rc.1` (prerelease ID `397543935`) is superseded. `v0.6.0` remains the official stable release and `v0.5.0` the previous stable. Historical `v0.6.0-rc.3` qualification does not qualify the new candidate. Retained weekly development notes are historical snapshots, not current release status.

---

## 0.7.0-rc.3 — prepared source (not tagged or published)

- Retain content-free processing failure reasons in local scan diagnostics
  instead of reporting only the failed stage; Event 3.0 error codes and source
  failure behavior are unchanged.
- Make four bundled detections depend on what a command does, not on words
  that appear near it:
  - `chain.download_then_execute` now needs downloaded content to run in session
    scoring: a download piped to an interpreter, or a downloaded file executed
    within 15 minutes. These are the links action findings already required.
    Before, any download plus any shell call in a session added 35 points, so an
    ordinary API `curl` through a shell tool scored 70/high, the same as
    `curl … | sh`. Sessions that never run what they fetch lose the chain.
    Field-level `CompiledRuleSet::evaluate()` keeps co-occurrence within one
    record. `wget -qO-` and other wget flag clusters ending in `-O` are now read
    as output to standard output.
  - `exfil.dns_encoding` no longer matches every `base64 --encode`, which scored
    70/high for encoding a word. It requires encoded data piped or substituted
    into a DNS lookup, or the existing long-label forms.
  - `persistence.shell_profile` shell matches now require a write or an enable:
    redirects, `tee`, in-place `sed`/`perl`, copies onto a startup file, patch
    headers, `crontab` installs, `systemctl enable`, `launchctl load|bootstrap`.
    Reading `~/.bashrc` from a shell no longer scores 45. Startup files now
    include `.zprofile`, `.zshenv`, `.zlogin` and `.bash_login`. Native file
    tools match only startup files they write, through `written_path`; reading
    one with a file tool no longer matches either.
- `credential.cloud_harvest` now requires a cloud credential file to be read,
  copied, encoded, archived or sent (`cat`, `grep`, `base64`, `cp`, `scp`, `tar`,
  `curl`, input redirection, inline interpreter code and similar), or opened by
  a native file tool. A CLI given the path it authenticates with
  (`kubectl --kubeconfig ~/.kube/config`, `KUBECONFIG=`, `--key-file`) no longer
  scores 50; listing pods with an explicit kubeconfig dropped from 65 to 15.
  Action findings no longer treat such a CLI parameter as a credential read.
- Chain modifiers can declare how their steps link with `link: {calls, order,
  minutes}`: within `calls` tool calls of each other (0 means one call; a call
  and its result count once, and messages add no distance), in declared order
  unless `order: any`, and optionally within `minutes` of the completing step.
  Session scoring and action findings apply the same link. Every bundled chain
  except `chain.download_then_execute` declares one: the `_then_` chains link
  within three calls in order, `chain.instruction_override_with_approval_bypass`
  within three calls in either order, and `chain.shell_encoded_payload` within
  one call. Before, session scoring counted co-occurrence anywhere in the
  session, so a credential read early in a long session and an unrelated publish
  much later chained. Calls without a source time now link by distance, and
  action findings now link steps in one call. A modifier without a link keeps
  session-wide co-occurrence and its earlier action semantics, so existing rule
  packs are unchanged; releases before links ignore the field.
  `ModifierDefinition` and `RuleV1CompatibilityModifier` gain a public `link`
  field and `ActionModifierSemantics` gains `within_calls`, so code that builds
  them with struct literals must set the new fields; the rule catalog reports a
  declared link as `action_link: within_calls:N`.
- `chain.secret_then_network` now pairs secret access with exfiltration, not
  with any download: reading a secrets file and then fetching a document no
  longer adds 35. Remove `chain.install_then_persistence`, which matched the
  ordinary "install a tool, add it to PATH in `.bashrc`" setup; both atomic
  rules still score.
- Add four alert rules in the new `destructive` category for commands that can
  delete or discard data. Each scores 55, so one destructive shell command
  reaches 70/high and security review. The rules cannot tell a requested reset
  from an unrequested one:
  - `destructive.filesystem_wipe`: home, root or disk deletion;
  - `destructive.git_discard`: hard reset, clean, force push, branch or stash
    deletion;
  - `destructive.database_drop`;
  - `destructive.infrastructure_teardown`: cloud, Kubernetes and stored-data
    teardown, `podman system reset`, `podman machine reset`, and Docker or
    Podman volume pruning (`system prune` only with `--volumes`).
- Add the Rule v1 target `written_path` (`compat.v1.written_path`), the ninth
  compatibility view. It holds the file-keyed top-level arguments of a call that
  writes them: a native file-write tool (`Write`, `Edit`, `write_file`,
  `replace` and similar) or any call whose arguments carry the written content
  (`content`, `new_string`, `newString`, `new_str`, `file_text`, `edits` and
  similar). `file_path` keeps reads and writes alike. Rules that use the new
  target do not load in earlier releases. Action findings read the same field,
  so detailed scans also stop matching persistence on shell or native reads of
  a startup file. The native action profile version is now 4, which also covers
  the wget output-cluster parsing and the cloud credential scoping above;
  semantic identities change and replay identities do not.
- Evaluation corpus: add twelve command-effect cases. Security-review confusion
  moves from TP 13 / FP 0 / TN 25 / FN 2 to TP 18 / FP 2 / TN 30 / FN 2. The two
  false positives are a requested `git reset --hard` and a requested
  test-database reset, which the destructive rules escalate like unrequested
  ones.

- Restore `execution.shell` session-scoring parity for shell-tool calls whose
  recorded command omits a shell wrapper, including Codex `exec_command` and
  OpenCode v2. Exact shell-tool names now contribute the existing 15 points;
  command/argument shell and interpreter patterns still apply, without counting
  a rule twice. Recorded requests and denied attempts are not proof of execution.
  User-approved shell activity can still combine with other rules to alert;
  no user-context suppression is added.
  Retain one representative shell-credit observation per session while evaluating
  and counting every call, so long harmless shell histories do not exhaust the
  unchanged evidence-retention bounds. Other rules and native actions are unchanged.

- Add versioned wire forms for embedding hosts. `SourceScan::action_records()`
  returns one `ActionRecordV1` (`telltale.action.v1`) per action finding: the
  accessor values plus client, source ID, source path hash, semantic identity
  and the `event_id` of the linked session Event 3 object. `rule_catalog_document`
  returns the bundled catalog as `RuleCatalogV1` (`telltale.rule_catalog.v1`).
  Both have strict consumers in `telltale-schema` that reject other versions,
  unknown fields and inconsistent values, and JSON Schemas in `schemas/`.
  Hosts wrap them in their own delivery envelope instead of designing an
  action or catalog format. `telltale_core::inventory` re-exports structured MCP
  server discovery. Event 3.0, CLI output and existing APIs are unchanged; the
  migration guide adds an embedding-host checklist of changes since RC2.

- Give embedding hosts the record checks they were re-deriving.
  `ActionRecordV1::delivery_key()` returns a pinned key over the semantic
  identity and the replay identity, or else the source path hash, coordinate
  and finding IDs. The documented coordinate-only key merged the several
  process-chain actions that one tool call can carry. `check_session_event`
  checks that an Event 3 detection or process-chain event can travel with a
  record and, for a linked record, that it is the linked event. The record
  consumer now also rejects text that redaction would still change. The
  record schema and Event 3.0 are unchanged.

- Add generated contributor catalogs: `docs/catalog/sources.json` lists every
  registered source's exact client, source ID, root, relative path, pattern and
  discovery special cases, and `docs/catalog/rule-vocabulary.json` lists the
  Rule v1 fields, targets and accepted values the validator takes. A test fails
  when either file is stale or when the source tables in the docs name an
  identity the registry does not have; `make catalog-update` regenerates them.
  `tests/upstream_formats` checks synthetic cases shaped from pinned harness
  releases, asserting a floor for supported shapes and the exact current outcome
  for known gaps. `make harness-drift-check` and a weekly workflow verify the
  pins and list newer harness releases. No runtime behavior changes.

- Reject YAML-escaped control and hidden formatting characters in rule packages,
  including nested rule text, without rejecting ordinary multiline content or
  literal regex escapes. U+2028 and U+2029 are rejected too: YAML breaks lines
  at them, so they could add package keys that a reviewer's viewer never shows.

- Reject a carriage return in a rule package unless it ends a CRLF line. YAML
  breaks lines there, so a lone one could add a key, such as `enabled: false`,
  that a terminal draws over; CRLF packages still load. A `"\r"` escape in a
  quoted string is rejected like other escaped controls. Two installed copies of
  one package ID now fail with each copy's version and content SHA-256 prefix
  instead of only the ID, since diagnostics never show their paths.
  `TELLTALE_COMMUNITY_RULES` accepts `0`, `false`, `off`, and `no` in any case;
  `FALSE` used to leave community rules on.

- Fix three detection gaps that synthetic lab scenarios found. `approval.bypass.context`
  no longer fires on a documentation review that quotes any of its phrases as
  disallowed, including inside Codex exec output with its exit metadata; only
  "bypass approval" in plain text was excused before. Review framing placed after
  an instruction still does not excuse it. `persistence.shell_profile` now matches
  options before the verb, such as `systemctl --user enable`. The cmd and PowerShell
  `schtasks` process-chain rules no longer score a read-only `schtasks /Query` as
  task creation, while a `/Create` whose action merely contains a query still scores.

- Embed the published `telltale.community` 0.1.0 release
  (`Dark-Roast-Cyber/telltale-detections` tag `v0.1.0`, source `d895523`). The
  rules are unchanged from the earlier snapshot; the package now records its
  release `revision`, so its content SHA-256 is
  `09be5cf10bca843561725784f4d28c41f817ae24484d146471584a4e2ff45cd5`, matching
  the release `SHA256SUMS` and its build-provenance attestation.

- Add state-only `cursor list` / `cursor reset` for one exact stored OpenCode
  source/schema cursor, with a matching inspection digest, explicit history-gap
  acceptance and separate unfinished-drain abandonment acknowledgement. Baselines,
  deduplication and other cursors remain unchanged. Subsequent bootstrap is bounded,
  not history recovery, whole-store evaluation or safe downgrade. Operators must
  pause scanning throughout inspection, reset and retries; installation or output
  failure can leave the reset committed without acknowledgement. Inspect state
  before retrying; see the [operator procedure](docs/opencode-live-ingestion.md#explicit-operator-cursor-reset).
- `approval.bypass.context` exclusions now accept any whitespace between
  `bypass` and `approval`, matching the selection. A documentation quote split
  across ordered message parts (joined with newlines) is excluded instead of
  scoring 45.
- Add the zero-point assistant-context rule
  `prompt_injection.instruction_override` ("ignore/disregard previous/prior
  instructions", with the same documentation exclusions as approval bypass) and
  the 30-point modifier `chain.instruction_override_with_approval_bypass`. An
  override quote alone emits a zero-risk detection; beside approval bypass the
  session scores 75 and requires security review. The chain is session-scoped.
  Matching sessions that already scored now include both IDs and gain 30 points.
- The evaluation corpus now also runs the default rule profile (core plus the
  embedded community package) and writes it to
  `target/evaluation/default-profile-report.v1.json`. A test fails on any
  per-case difference from the core-only golden that is not listed. Counts stay
  separate per profile. The CLI canonical-efficacy test pins both profiles with
  a cleared environment. No runtime behavior changes.
- Codex completed `CommandExecution` results now carry a Derived `command.text`
  facet: a POSIX shell-quoted rendering of argv that a shell parses back into
  exactly argv. Argv stays structured in `tool.arguments`, and no execution,
  Process, File, or Network fact is added. Command and argument rules in every
  rule profile now see completed commands. A request and its completed result
  still count each rule once per session, though both can appear as evidence
  anchors. A rendering that does not fit the canonical bounds is omitted rather
  than rejecting the result.
- Add rule packages and enable community rules by default. Telltale now embeds
  the `telltale.community` package (rule IDs `tdx.*`, Apache-2.0) from the
  community detections repository: Git hook path changes, MCP server
  registration commands, and Windows persistence commands. `--no-community-rules`
  or `TELLTALE_COMMUNITY_RULES=0` keeps only the core rules; `--no-default-rules`
  now omits both core rules and the embedded community snapshot. Operators can
  install versioned, namespaced `telltale-rule-package/v1` files in
  `rule-packages.d` to run a newer community release or their own packages.
  Packages only add definitions and cannot reuse a core namespace. `rules
  validate`, `config validate`, and scan effective configuration report each
  active package's ID, version, content SHA-256, and origin. The embedding
  facade adds `PipelineBuilder::rule_package`, `without_community_rules`, and
  `Pipeline::rule_packages`; the bundled rule catalog includes community entries
  with a `package_id`.

- Add `scripts/build-windows-development.ps1`, a development-only Windows build
  helper for PowerShell 5.1 and 7. It builds `telltale` with `--locked`, adds
  the static-CRT flag to the rustflags source Cargo reads for the default MSVC
  target, rejects a conflicting CRT flag, never falls back to another target,
  and reports the path, version,
  source revision and SHA-256. It does not install anything.
- Build provenance watches the real Git metadata paths (`HEAD`, the active loose
  ref and `packed-refs`), so linked worktrees and new commits on the same branch
  refresh the reported revision, and a changed `PATH` reruns the build script.
  `GIT_DIR`, `GIT_WORK_TREE` and `GIT_COMMON_DIR` cannot select another
  repository, and path lookup works with Git 2.5 and later. Failures keep
  `unknown` with bounded warning categories only.
- Add `scripts/verify-live-host.ps1`, a read-only verifier that runs one dry-run
  scan per selected client with temporary log and state paths. It classifies each
  client as `passed`, `passed_with_limits`, `failed` or `not_available` from the
  scanner output, failing a scan that exceeds `-TimeoutSeconds` (default 600) or
  whose record-kind counts do not add up. Its report omits session IDs, source
  paths and transcript content. It does not install, schedule or change source stores.
- Keep process findings for executable names containing spaces by encoding
  generated standalone deduplication keys within existing identifier bounds.
  Existing valid keys and authored chain-key validation are unchanged.
- Fix Claude Code ingestion for current 2.1.x transcripts, including the Claude
  desktop app's Code tab on Windows. Bookkeeping records are skipped, and
  `thinking`/media blocks are dropped. Tool arguments and results live once on
  the Tool observation, with the authored-text budget for Claude command, file
  body, edit and prompt fields. Previously each of these failed the whole
  transcript. An unknown record or block, or an oversized record, is now
  quarantined by itself and reported without content, like OpenCode v2 rows.
- Fix Codex ingestion for current rollouts. Previously every Codex source on a
  Windows 11 host failed as a whole. Forked threads whose ordinals continue
  from a parent `history_base` are now read. Bookkeeping records
  (`token_usage_record`, `compacted`, `thread_settings_applied`,
  `turn_aborted`, compaction and review-mode items) are skipped. Code-mode
  `exec` scripts, text-array tool output and completed-command output get the
  direct-text budget, and a command's exit code is its own fact. An unknown or
  unmapped record or item, a parent's copy of a subagent item, or an oversized
  record is now quarantined by itself and reported without content.
- Claude install inventory recognizes the Claude desktop app's bundled Claude
  Code (`%APPDATA%\Claude\claude-code\<version>\<hash>\claude.exe` and its MSIX
  mirror) as metadata-only `executable` evidence. On Windows these signals
  change the inventory hash once; the next scheduled `install_inventory` event
  carries it.
- `claude.projects` discovery adds `$CLAUDE_CONFIG_DIR/projects` beside
  `~/.claude/projects` when the variable is set in the scanner's environment.
- A full scan in which every selected source of one client fails processing
  emits one `warning` `operational_alert` per client
  (`alert_type=source_parse_outage`, `check_name=operational_alert`).
  Per-source `scanner_error` stays `informational`, as the Event 3.0 contract
  requires. Outside `--backfill`, which re-emits every scan's events, an
  unchanged outage alerts once; after a full scan in which a source of the client
  processes successfully, a recurrence alerts again.
- The current-user Windows installer verifies exact Release identity,
  checksums, canonical ZIP contents, binary version and source-bound attestation.
  Binary files are separate from existing per-user Logs/State defaults.
- The uninstaller verifies receipt ownership, executable digest and exact task identity.
- Optional least-privilege `TelltaleScan` and reversible installer-owned PATH
  changes; development-local installation is explicitly unpublished.
- Digest-bound receipts, staged replacement and transaction recovery. Default
  uninstall retains data; confirmed purge removes owned generated data, with
  configuration requiring separate explicit selection. Legacy installs are retained.
- Synthetic Windows lifecycle regressions and disposable-runner scheduling
  validation. ZIP inventory and Event 3.0 are unchanged. OpenCode persisted
  cursor/token compatibility is covered by the current
  [migration guide](docs/migrations/0.7.0.md#opencode-v2-changes-after-rc2).
  RC3 tagging/publication and qualification remain separate gates.
- Bound untrusted rule-server requests, source admission, MCP inventory,
  historical export and durable sink delivery. Failed MCP reads restore their
  byte reservation; one unreadable configuration cannot starve later inputs.
- Require HTTPS for remote HTTP sinks unless explicitly configured otherwise;
  reject URL credentials/fragments and stop redirects for operator review.
  The obsolete rule-save endpoint is removed.
- Reject the Linux checksum-bypass option and replace the retired YAML parser
  with `yaml_serde` / `libyaml-rs`, preserving the Serde YAML import surface.
- Assemble rules-server HTTP responses before Windows socket writes and make
  accepted-socket mode explicit in the macOS/Linux backlog regression.
- Coordinate all workspace versions, internal requirements and both lockfiles;
  add exact-source prospective preflight and embedding/Git-consumer CI evidence.

---

## 0.7.0-rc.2 — published prerelease (five-platform native verified)

- Typed, wire-neutral Rust embedding contract: `PipelineError` and
  `AcquisitionError` are typed and `#[non_exhaustive]`; `scan_sources`,
  detailed action findings with replay identity, semantic provenance and
  `SourceScan::failure()` / `coverage()`. Record evaluation APIs are removed.
  See the [migration guide](docs/migrations/0.7.0.md).
- OpenCode resume tokens for embedding hosts, bound to the exact source path.
  A store regressed below the saved position now fails as `resume_regressed`
  for both embedded and CLI scans instead of reporting an empty success; the
  CLI keeps its cursor.
- `build()` rejects a rule set with no enabled rules.
- Encoded tool arguments are decoded member by member, so one oversized member
  cannot hide URL facts or put replaced text into command text.
- Event 3.0 and persisted state formats are unchanged. Five-platform native
  verification passed in run `38098389234`; clean-host gates are pending.
  Crates.io publication remains deferred.

---

## 0.7.0-rc.1 — published prerelease (five-platform native qualified)

- Eight exact built-in source identities across six agent families replace the
  broader legacy denominator. Retired identities are removed, not registered as
  compatibility aliases; see the [migration guide](docs/migrations/0.7.0.md).
- Source-native Canonical Observation v2 acquisition and Detection v2 evaluation
  are authoritative for CLI scan/watch and `telltale-core::Pipeline::scan_root`.
  Rule v1 remains the content format; process-chain evaluation runs within
  Detection v2. Caller-supplied `NormalizedRecord` APIs remain separate
  record-level compatibility surfaces.
- Event3 (`3.0`) remains the sole production output contract. Rust adopters have
  documented `telltale-core::Pipeline`, typed `Event3Record`, bounded read-only
  `LocalEventFeed`, and producer-provenance contracts. Event4 is not activated.
- Update the locked rustls dependency for RUSTSEC-2026-0285; established
  installer provenance, security, and release-package gates remain in place.
  Five-platform native qualification passed in run `36305581215`; crates.io
  publication remains deferred.

---

## 0.6.0 — published stable (2026-09-12)

- Promoted the accepted `v0.6.0-rc.3` release line to stable package metadata.
  At stable promotion, runtime and release archive construction remained
  materially equivalent to the live-qualified candidate.
- Exact rc.3 passed manual and timer-triggered scans on the authorized live
  Linux host, with valid Event3 local output and successful configured HEC
  delivery. Stable `v0.6.0` subsequently passed the same live checks.
- Crates.io publication remains a separate, intentionally deferred distribution
  action.

---

## 0.5.0 — published stable (2026-08-19)

- Promoted the accepted immutable `v0.5.0-rc.7` candidate to the stable
  package version `0.5.0` without changing runtime, Event 3.0, detection,
  installer, or service behavior.
- The immutable [v0.5.0 tag and GitHub Release](https://github.com/Dark-Roast-Cyber/telltale/releases/tag/v0.5.0) are published. Crates.io publication remains a separate distribution action.

---

## 0.5.0-rc.7 — published candidate

- Repair canonical Linux installer validation for the documented implicit
  systemd user-manager working-directory default, accepting only the exact
  missing-OK canonical home form after declaration proof.
- Reject base, unit-specific, and inherited `WorkingDirectory=` contributions
  while retaining optional environment-file, transaction, recovery, and
  activation ordering safeguards.
- Publication and provenance passed. G-SERVICE passed. GitHub-hosted native
  Windows/macOS execution of the published Release artifacts passed. Live
  HEC/Splunk remain `SKIPPED_EXTERNAL`.

---

## 0.5.0-rc.6 — published candidate

- Repair canonical Linux installer validation for an absent optional
  `EnvironmentFile`, while rejecting alternate, extra, reset, ambiguous, and
  inherited environment sources.
- Publication and provenance passed. Live G-SERVICE confirmed the optional-file
  repair, then failed before binary replacement on the separate systemd
  user-manager `WorkingDirectory` normalization defect.

---

## 0.6.0-rc.3 — published candidate

- Configure the official `x86_64-pc-windows-msvc` release build to statically
  link the applicable MSVC CRT without changing the Windows target or bundling
  Microsoft DLLs.
- Add a fail-closed `dumpbin /DEPENDENTS` gate for the exact staged Windows
  binary and reject redistributable MSVC runtime imports before packaging,
  attestation, or upload.
- Exercise the same static-CRT build, PE import check, and `--version` smoke in
  Windows CI while retaining the normal Rust suite and release ZIP tests.
- The prerelease is published as Release ID `386482697` from source SHA
  `db9cf63434a6e1fdf1373e82d96d709f6fbabc58`. Publication/provenance,
  static-CRT publication, five-platform native verification, and Issue #23
  clean-Windows static-CRT and functional acceptance passed. Official stable
  remains `v0.5.0`; Issue #23 is closed and Issue #37 remains open. This does
  not change or make a static-linkage claim for immutable `v0.6.0-rc.2`.

---

## 0.6.0-rc.2 — published candidate

- Repair the current-user systemd `EnvironmentFile=` declaration so the
  optional prefix and absolute path are parsed as one valid path value, including
  supported paths containing whitespace. The real parser consumes the complete
  directive value without shell-unquoting it, so the canonical form is
  `EnvironmentFile=-/absolute/path`, not either quoted variant.
- Preserve exact generated-unit and effective-policy validation. The known valid
  v0.5.0 current-user declaration upgrades transactionally; alternate paths,
  resets, multiple directives, the rc.1 quoted form, and unit-specific drop-ins
  still fail closed.
- Add a real `systemd-analyze verify` regression that distinguishes the valid
  generated form from the rc.1 failure, plus a bounded live-user-manager test for
  present and absent optional environment files.
- The immutable `v0.6.0-rc.2` prerelease is published as Release ID `385903701`
  from source SHA `158b18ce78c6f503c38619e816790035f88b09db`.
  Publication/provenance, G-SERVICE, and five-platform native verification
  passed; official stable remains `v0.5.0`, and Issues #23 and #37 remain open.

---

## 0.6.0-rc.1 — published immutable failed candidate

- Publication and provenance: **PASS**.
- G-SERVICE: **FAIL**. Current-user generated `EnvironmentFile` quoting placed
  quote characters around the absolute path while leaving the optional `-`
  outside. Fedora/systemd treated the resulting path as non-absolute and ignored
  the optional environment file.
- A separate synthetic qualification invocation used the wrong override
  mechanism and scanned the ordinary user root rather than the intended
  synthetic-only root. No raw event content was retained as release evidence,
  state/log consistency was preserved, and this is a qualification-tooling
  finding rather than an additional candidate-behavior finding.

**Detection quality**
- Add a deterministic labeled evaluation contract. The current corpus contains
  44 cases, with 30 scored results: 11 true positives, 0 false positives,
  19 true negatives, and 0 false negatives. This is a bounded corpus result,
  not a claim of perfect detection.
- Preserve retained Rule v1 metadata and risk accounting, and repair the encoded
  HTTP upload/download overlap that produced a known false positive.

**Event3 and privacy**
- Event3 remains the frozen production telemetry contract. A typed public Event3
  consumer and terminal privacy hardening were added without changing the wire
  schema (`9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754`).

**Durable delivery**
- Canonical JSONL remains the first durable write. Operators can opt into a
  durable remote-delivery outbox with restart/replay and at-least-once semantics.
  Delivery may duplicate an event after uncertain remote acceptance; receivers
  should deduplicate by `event_id`. Durable storage fails closed on Windows.

**Producer provenance**
- Add a deterministic producer/detector manifest for effective detector content
  and configuration. It does not prove artifact authenticity, bind a manifest to
  each event, or establish scan, host, or attestation identity.

**Sources and local consumers**
- Improve production source discovery and parser correctness while retaining the
  existing `NormalizedRecordV1` production path and exact parser ownership.
- Add `LocalEventFeed`, a bounded, read-only Rust consumer of local Event3 JSONL.
  It does not own a watcher, runtime, or database.
- Add Telltale Console as an optional local Event3 viewer and separate
  repository/source-run package. It remains `publish = false` and is not in the
  canonical CLI GitHub release archives.
- Add native OpenCode session export as an optional investigation primitive.
  Production scanning has not migrated to this export path.

**Operational and release hardening**
- Strengthen installer validation, exact development artifact identity, rollback,
  systemd compatibility, explicit HEC/Universal Forwarder routing, package and
  release-version gates, dependency policy, SBOM checks, and pinned release
  workflows.
- Final qualification remains pending for Windows clean-host runtime policy,
  controlled deployment validation, and candidate-native artifacts.

**Future foundations**
- Canonical Observation v2 is non-production projection foundation work.
  Detection v2 is foundation and fixture-only shadow work. Event4 is future
  architecture and is not the production event contract. Managed adoption is
  future work.

---

## Week — 2026-07-13 to 2026-07-20

21 commits across 8 days, grouped by theme.

**Ordered Rule Packs (Phase 0 closure)**
- `5687ef8` (07-20) — Add ordered rule-pack precedence with provenance and trust boundary. Bundled < organization < deployment < local/UI tiers; higher tiers fully replace same-ID definitions; equal-tier/cross-kind/explicit collisions fail with both source identities. `adr rules list` keeps five-column default and gains `--verbose` provenance. Shared resolver across scan/watch/coverage/rules serve. Trust-boundary docs added.
- `4e146e1` (07-20) — Add public ROADMAP.md with stable project direction summary.

**Windows CI & Test Portability**
- `35696bd` (07-18) — Add Windows CI quality gate.
- `172da44` (07-18) — Fix Windows CLI test portability.
- `f9ba8fe` (07-18) — Scope OpenCode cursor test to Linux.
- `f267ddd` (07-18) — Gate Linux-only SQLite test import.
- `8867968` (07-18) — Make project config test platform neutral.
- `2149e7c` (07-18) — Document experimental Windows P54 coverage.

**Release Bundles & Installer**
- `738c0d5` (07-18) — Package signed Telltale release bundles.
- `e20cea8` (07-18) — Validate curated release bundles and align release context on main.
- `ebb36cb` (07-17) — Verify release checksums in installer and make timer setup opt-in (`--with-timer` instead of on-by-default; `--skip-checksum` opt-out).

**Workspace Extraction**
- `bc1f1b0` (07-17) — Add telltale embedding facade crate (`Pipeline::builder()`, `scan_root()`, `detect_records()`, `evaluate_session()`).
- `57014cb` (07-17) — Extract `telltale-detect` workspace crate (detection, timeline, correlation, baseline, allowlist, MCP analysis).
- `abc7b35` (07-17) — Extract `telltale-sources` workspace crate (discovery, OS path roots, the static per-agent source-definition/install registry, parser entry points, and install inventory; parser dispatch remained centralized with selected source-specific helpers).
- `6661c43` (07-17) — Convert repo to Cargo workspace with `telltale-schema` and `telltale-rules` crates.
- `bcf15bc` (07-17) — Move install inventory definitions into per-agent source modules and collect them through the static registry (Phase 5 of source-module refactor).
- `a98615f` (07-17) — Apply rustfmt to sink and CLI modules (formatting-only).

**Event Sinks & Delivery**
- `6f11494` (07-16) — Add policy-configurable event sinks with Elastic and Splunk HEC emitters. SinkSet with explicit failure policy, `outputs.d/*.yaml` config, shared ureq/rustls HTTP transport, Elasticsearch Bulk API sink, upgraded Splunk HEC with batched envelopes, `adr config validate` sink reporting.
- `1138b78` (07-16) — Move OpenCode SQLite parser and source defs behind `src/sources/opencode/`.

**Logging & Sink Testing**
- `331892c` (07-13) — Test detection delivery across sinks.
- `8f834ca` (07-13) — Harden production event logging.

> **Notable:** Workspace modularization (07-17) — four commits splitting the monolithic crate into `telltale-schema`, `telltale-rules`, `telltale-sources`, `telltale-detect`, plus an embedding facade — all preserving binary-parity fixture scans. Cross-platform CI (07-18) — Windows joined the quality gate; six commits fixed platform-specific test assumptions. Rule-pack precedence (07-20) — the largest single change (22 files, +1546/−200), closing Phase 0 of the 0.2.0 maturity plan.

---

## Week — 2026-07-06 to 2026-07-12

18 commits across 6 days, grouped by theme.

**Source Module Organization (selected parser moves)**
- `6c47f7d` (07-08) — Move Copilot parser and source defs behind `src/sources/copilot/`.
- `5fce36c` (07-08) — Move Codex source defs and tests behind `src/sources/codex/`.
- `5d4b6f8` (07-08) — Move RooCode and KiloCode source defs and tests behind `src/sources/`.
- `df3e151` (07-08) — Move Qwen and OpenClaw source defs and tests behind `src/sources/`.
- `370a85a` (07-08) — Move Claude source definitions and tests behind `src/sources/claude/`.
- `1138b78` (07-16) — Move OpenCode SQLite parser and source defs behind `src/sources/opencode/` (carried forward from prior week).
- `4b9948b` (07-07) — Move Gemini source definition and source-specific JSON parser behind `src/sources/gemini/`.

**Watch Mode & Health Events**
- `56e1f7d` (07-07) — Refactor watch mode into a resource-efficient monitor (targeted re-scans, event coalescing, `--min-scan-interval-ms`, WAL sidecar filtering, clean shutdown).
- `b20eb06` (07-07) — Track `install_inventory` in StateChangeProbe and add watch-mode tests.
- `305acf4` (07-07) — Enrich health events with build version and scan counts.
- `a13a2ee` (07-07) — Harden SQLite source parsing against lock contention (5-second `busy_timeout`).

**Bug Fixes**
- `137054d` (07-08) — Fix OpenCode SQLite parser: qualify `time_updated` as `part.time_updated` in JOIN query.
- `7dc2835` (07-08) — Fix `scanner_error` dedup mismatch: bypass `should_emit` for scanner_error events.
- `cd8031b` (07-12) — Deduplicate `source_discovery` health events after source removal.

**Rule Management**
- `9ee1a7a` (07-07) — Add local rule overrides (`overrides.d/*.yaml`).
- `c77f06a` (07-07) — Add bundled default rule export (`adr rules export-default`).
- `bfbfe9e` (07-07) — Add local rule configuration workflow (`adr config validate`, local `rules.d/` discovery).

**Scaffolding**
- `4726d7a` (07-07) — Add source adapter scaffolding (`src/sources/registry.rs`, `SourceAdapter` trait placeholder).
- `d2eeff8` (07-07) — Gitignore `PLAN-watch-followups.md` as internal planning doc.

> **Notable:** Source module work moved per-agent source definitions and tests into `src/sources/<agent>/`; selected source-specific parser implementations moved for Copilot, Gemini, and OpenCode, while generic extraction and `SourceKind` dispatch remained centralized. The unused `SourceAdapter` trait is scaffolding, not a runtime parser contract. Watch mode was rebuilt for resource efficiency with targeted re-scans and clean shutdown.

---

## Week — 2026-06-29 to 2026-07-05

1 commit.

- `b6bb4b2` (07-03) — Document source adapter links in README.

---

## Week — 2026-06-22 to 2026-06-28

2 commits.

- `233c7b3` (06-22) — Document source adapter refactor plan.
- `867b324` (06-22) — Add install inventory telemetry.

---

## Week — 2026-06-15 to 2026-06-21

12 commits across 6 days, grouped by theme.

**Installer & Deployment**
- `fad54fe` (06-21) — Add user-first Linux installer (sudo-free, no SIEM config).
- `995241a` (06-21) — Validate Linux installer on host; add macOS/Windows install directions to README.
- `5b56f44` (06-21) — Align Splunk UF helper with system path profile.
- `3745ac3` (06-21) — Add OS path profiles for telemetry logs.
- `922797f` (06-21) — Document OS telemetry path profiles.
- `043e85b` (06-21) — Add OS-native telemetry rotation guidance.
- `b6ddf4d` (06-21) — Document active telemetry file monitoring paths.

**Log Rotation**
- `db20f29` (06-21) — Add built-in cross-platform size-based log rotation (100 MB max, keep 5, same behavior on Linux/macOS/Windows).
- `5eb9261` (06-21) — Fix review issues: strict cleanup matching, same-day ordering, best-effort cleanup.

**OpenCode SQLite Ingestion**
- `a318b99` (06-16) — Add cursor-aware OpenCode SQLite ingestion.
- `d71d0ce` (06-16) — Parse OpenCode SQLite `part` rows.

**Housekeeping**
- `d823657` (06-21) — Untrack internal OpenCode SQLite ingestion plan.

> **Notable:** The user-first Linux installer shipped — a single curl|bash command that installs to `~/.local/bin` with no sudo. Built-in cross-platform log rotation went live, removing the need for OS-specific logrotate on basic deployments.

---

## Week — 2026-06-08 to 2026-06-14

13 commits across 2 days, grouped by theme.

**Performance & Cleanup**
- `220b473` (06-09) — Replace O(n*m) session grouping with HashMap-based O(n) approach.
- `2769d21` (06-09) — Hoist regex compilation to `LazyLock` statics in redaction paths.
- `ccdcd59` (06-09) — Decompose `cli.rs` and `event.rs` into focused submodules.
- `22df237` (06-09) — Remove `http` from Cargo.lock (dependency removed earlier).
- `77cbcfc` (06-09) — Remove unused `http` dependency.

**Project Discovery & MCP**
- `ee4a06d` (06-10) — Add default project-local discovery roots (`~/github`, `~/projects`).
- `6417394` (06-10) — Add runtime MCP usage events.
- `ba0f998` (06-10) — Fix `approval.bypass.context` false positives from system prompts.
- `943836d` (06-10) — Remove `source_silence_threshold` operational alert.

**Release & Docs**
- `ace93c0` (06-09) — Consolidate release preflight targets and public-docs tests.
- `575e249` (06-09) — Add badges and rename Documentation to Related resources.
- `1618b19` (06-09) — Gitignore website planning artifacts that belong in agentarchaeology repo.
- `64d9a1a` (06-09) — Add AgentArchaeology.ai cross-references to README and docs.

> **Notable:** Performance improvements to session grouping (O(n) instead of O(n*m)) and regex compilation (LazyLock statics). Project-local discovery gained sensible defaults. MCP runtime usage events shipped.

---

## Week — 2026-05-25 to 2026-05-31

68 commits across 6 days, grouped by theme.

**Release Boundary Guards (bulk of the week)**
- 30+ commits establishing the public-release boundary guard framework: host-only path classification, public docs inventory, release workflow internal-only path lists, split-checkout wording removal, `.gitignore` alignment, and bidirectional consistency checks between the release checklist and documentation inventory.
- Key structural commits: `ec4d250` (05-28) — Add public release preflight target. `5dcc769` (05-27) — Add public release readiness checklist. `1f2fb0d` (05-27) — Add public telemetry output guide. `e03f987` (05-27) — Consolidate public boundary guard tests.

**Release Artifact Pipeline**
- `f89ab0a` (05-30) — Publish release archive checksums.
- `21dcf9d` (05-30) — Validate release checksum manifests.
- `a3835a6` (05-30) — Add release artifact manifest check.
- `5f1444c` (05-30) — Cover release zip artifact manifest.
- `8b77b34` (05-30) — Review Cargo package release contents.
- `f38a19b` (05-30) — Expand release fixture smoke coverage.
- `8dd1e24` (05-30) — Wire public boundary checks into release preflight.
- `ff5a922` (05-30) — Check public branch alignment before release.
- `343a17e` (05-30) — Add public push review helper.
- `0902457` (05-30) — Check release tag version in preflight.

**Scanner Error Suppression**
- `68f5b7f` (05-30) — Suppress `scanner_error` events for empty sources.

> **Notable:** The single largest week by commit count. The entire public-release boundary framework was built — preflight checks, documentation inventory, boundary guards, and release artifact validation. This established the single-local-repo/public-remote release model that all subsequent releases follow.

---

## Week — 2026-05-18 to 2026-05-24

50 commits across 6 days, grouped by theme.

**Health & Telemetry**
- `7e8d0dc` (05-20) — Expose health dimensions in status.
- `aa09314` (05-20) — Suppress unchanged health heartbeats.
- `6970eff` (05-20) — Add health source inventory change markers.
- `209ca57` (05-20) — Add health telemetry check dimensions.
- `a73a017` (05-20) — Compact health event source inventory evidence.
- `3eecef0` (05-20) — Add static MCP inventory activity events.
- `89ce54c` (05-20) — Cover unsupported MCP inventory events.
- `8489b7c` (05-20) — Validate MCP inventory activity schema.
- `4602f8c` (05-19) — Add session risk summary events.
- `286974a` (05-19) — Validate session risk summary schema.
- `63fd27e` (05-19) — Cover session risk summary dry-run output.

**Watch & Export**
- `7974e3c` (05-23) — Add watch client filtering (`--client`).
- `f092e0c` (05-23) — docs: document watch client filters.
- `eb9b7c1` (05-23) — Stabilize detection fingerprints.
- `7e671a7` (05-23) — Reject malformed JSONL in status.
- `054d62c` (05-23) — Add export malformed JSONL regression.
- `3f4711d` (05-19) — Harden export timeline validation.
- `a230938` (05-19) — Aggregate duplicate correlation windows.
- `9deeac2` (05-19) — Normalize offset event timestamps.
- `f793d5a` (05-19) — Harden Splunk HEC endpoint parsing.
- `7b5b799` (05-19) — Test timeline elastic bulk rejection.

**Documentation & Public Surface**
- `c84d132` (05-19) — Trim public documentation surface.
- `9f89ee3` (05-19) — Trim policy authoring examples.
- `2a1a2c0` (05-19) — Add simple detection rule example.
- `9479657` (05-19) — Tighten public documentation wording.
- `4bf41f9` (05-23) — Expand README public docs index.
- `5747e39` (05-23) — Test public docs local links.
- `f9734e5` (05-23) — Add README local link regression test.
- `1122d75` (05-23) — Clarify public packaging boundary.
- `f7a4e11` (05-23) — Update systemd scan example cadence.
- `a9c1baf` (05-19) — Refactor CLI scan and parser helpers.
- `f8721c6` (05-19) — Cap redacted evidence excerpts.
- `f65ead9` (05-19) — Improve chain modifier coverage guidance.
- `1722c72` (05-19) — Update Copilot timestamp capability docs.
- `4fefff5` (05-19) — Cover export timeline text validation.
- `31e5e0b` (05-19) — Validate source timeline client filters.
- `51dcc21` (05-19) — Keep Ralph diary local only.

**CI & Config**
- `b8ad6ad` (05-18) — Simplify CI workflow.
- `203cbf8` (05-18) — Fix Rust CI formatting and discovery checks.
- `d2919e8` (05-18) — Restore README Splunk telemetry dashboard.
- `3544316` (05-18) — Trim public documentation bloat.
- `3d0314e` (05-18) — Clarify install scan root.
- `594e601` (05-18) — Align install verification with README.
- `9c5f913` (05-18) — Add README links for public reference docs.
- `c59b162` (05-18) — Ignore local SIEM development files.
- `a6135ef` (05-18) — Ignore local-only development files.

> **Notable:** Health telemetry matured significantly — health dimensions, inventory change markers, MCP inventory activity, and session risk summaries all shipped. Watch mode gained client filtering. The public documentation surface was trimmed and tightened. Detection fingerprints were stabilized.

---

## Week — 2026-05-11 to 2026-05-17

5 commits — the initial public release preparation.

- `655ebc9` (05-17) — Prepare starter public Telltale release.
- `34462b6` (05-17) — Refresh public logo image.
- `ff2a1a3` (05-17) — Remove Docker packaging from public starter.
- `ecb92ce` (05-17) — Polish public starter documentation.
- `e2d17e1` (05-17) — Add README telemetry dashboard image.

> **Notable:** The first public-facing commits captured in this changelog. The repository has substantial development history prior to this week that is not represented here — this changelog begins with the initial public release preparation (logo, documentation, and packaging trimmed for public consumption).

---

*This changelog covers 200 commits from 2026-05-17 to 2026-07-20. Weekly summaries are grouped by theme within each week. For detailed per-commit descriptions, see the [GitHub commit log](https://github.com/Dark-Roast-Cyber/telltale/commits/main).*
