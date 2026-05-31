# Privacy and Evidence Model

ADR monitors agent session stores that contain sensitive material: API keys, credentials, private keys, file paths, conversation bodies, and tool-call arguments. The privacy model defines how ADR classifies, transforms, and emits evidence so SIEM events remain useful without becoming a new secret-leak surface.

## Evidence Classes

ADR uses five evidence classes, ordered from safest to most sensitive:

### 1. Safe Metadata

**Definition**: Structured fields that describe the detection without revealing session content.

**Examples**:
- `client` (codex, opencode, copilot, claude, ...)
- `source_kind` (jsonl, sqlite, copilot_process_log, ...)
- `rule_ids` (secret.env.read, mcp.tool_metadata.prompt_injection, ...)
- `categories` (secret_access, mcp_prompt_injection, ...)
- `severity` (informational, low, medium, high, critical)
- `risk_score` (0–100)
- `event_type` (detection, activity, health, ...)
- `session_id` (opaque identifier, not raw transcript path)
- `tool_name` (bash, write, curl, ...)
- `timestamp` (RFC3339)
- `adr_version`, `scan_duration_ms`, `rule_count`

**Current behavior**: These fields appear as top-level event fields. No redaction needed because they are identifiers, not content.

**SIEM use**: Correlation, filtering, dashboarding, alerting.

### 2. Redacted Excerpt

**Definition**: Bounded text from session content with sensitive spans replaced by class markers.

**Current implementation**: `redact_sensitive_text()` in `src/event.rs`.

**Redaction rules applied** (in order):
1. Controlled domain: `darkroastcyber.io` → `[controlled-domain]`
2. Sensitive paths: `.env` → `[sensitive-path]`
3. Secret markers: `id_rsa`, `id_ed25519`, `.pem` → `[redacted-secret]`
4. Generic secret labels: `api key`, `api token`, `credential` → `[redacted-secret]`
5. Private key headers: `-----BEGIN ... PRIVATE KEY-----` → `[redacted-secret]`
6. Package manager commands: `pip install ...`, `npm install ...` → `[package-manager-command]`
7. Startup targets: `~/.bashrc`, `~/.zshrc`, `crontab` → `[startup-target]`
8. Encoded decoders: `base64 --decode` → `[encoded-decoder]`
9. Credential tokens: `ghp_*`, `sk-*`, `AKIA*`, `xox*-*`, `eyJ*` (JWT), `Bearer *` → `[redacted-secret]`
10. Encoded blobs: base64-like strings ≥20 chars → `[encoded-blob]`

**Bounded length**: Redacted excerpts are truncated to 80 whitespace-delimited tokens.

**Current behavior**: Applied to `evidence[].redacted_value` fields in detection and activity events.

**SIEM use**: Analyst triage, pattern recognition, timeline reconstruction.

### 3. Hashed Value

**Definition**: SHA-256 digest of the original value, enabling correlation without disclosure.

**Current implementation**: `path_hash()` and `evidence_hash()` in `src/event.rs`.

**Current behavior**:
- `evidence[].hash` is populated for all evidence items in detection events (tests assert `hash.is_some()`).
- `source_path_hash` on events is a SHA-256 of the source file path.
- Correlation events hash `event_id` for cross-reference.

**SIEM use**: Deduplication, correlation across sessions, lookup against known-bad hashes.

### 4. Local-Only Sensitive Context

**Definition**: Evidence that is useful for local review but should not be emitted to SIEM by default.

**Current event behavior**: ADR does not currently emit a separate local-only context field. The bounded excerpt approach (80 tokens + redaction) serves as the default compromise for SIEM events.

**Baseline state behavior**: Model behavioral baselines are persisted in local scanner state so deviation scoring can compare new observations with prior local activity. Baseline summaries track network host labels observed in parsed tool arguments or results, but persisted scanner state stores those labels as deterministic `sha256:` hashes. Host labels can reveal internal services, customer domains, repository infrastructure, or other environment-specific destinations, so raw labels remain local-only sensitive context and must not be copied into public reports, committed, or exported as telemetry by default.

When `--baseline-deviation-scoring` is enabled, emitted activity evidence reports deviation counts such as `new_network_hosts`; it does not emit raw baseline host labels. Existing state files from earlier builds are migrated on load by hashing raw baseline host labels in memory; the next successful state save writes only hashed labels.

**Future work**:
- Add an optional `local_context` field to events that is populated only when `--emit-local-context` is set.
- Local context could include longer excerpts, unredacted tool names, or full argument shapes.
- The SIEM JSONL writer would strip `local_context` unless explicitly opted in.
- A local review tool (`adr inspect <event_id>`) could read the local context from the JSONL file.

### 5. Never Emit

**Definition**: Data that must never appear in ADR events, regardless of configuration.

**Examples**:
- Raw API keys, tokens, passwords, secrets
- Full auth files (`.aws/credentials`, `.npmrc`, `.netrc`)
- Private key bodies (PEM, OpenSSH, Ed25519)
- Full session transcript bodies
- Raw `.env` file contents
- Raw command output containing secrets
- Session store file contents (only hashes and excerpts)

**Current behavior**: The redaction pipeline in `redact_sensitive_text()` and `redact_error_message()` prevents these from reaching `evidence[].redacted_value`. Tests assert that specific secret patterns do not appear in redacted output.

## Evidence Minimalism

ADR should emit the least evidence needed to prove a detection.

Guidance:
- Prefer safe metadata first. If a rule can be explained by `client`, `session_id`, `rule_id`, `category`, `tool_name`, `severity`, or `risk_score`, do not add content evidence just to make the event look richer.
- Use a redacted excerpt only when an analyst needs the matched text or short surrounding context to understand why the rule fired.
- Use hashes when exact-value correlation matters but the raw value does not need to leave the host.
- Use local-only sensitive context only for local review workflows, never as a default SIEM payload.
- Do not emit raw transcript bodies, raw secrets, or full command output when a smaller class proves the same behavior.

Examples:
- A suspicious file-read rule can emit the path field and its hash without including the full surrounding command line when the path itself proves the match.
- A prompt-injection rule should emit a short redacted excerpt of the injected text, not the entire conversation turn.
- A secret-harvesting chain can emit redacted excerpts and hashes for the sensitive read plus the follow-on action, while omitting unrelated nearby transcript text.

## Evidence in the Event Schema

The `Event` struct in `src/event.rs` maps evidence classes to fields:

| Field | Evidence Class | Notes |
| --- | --- | --- |
| `client`, `session_id`, `severity`, `risk_score`, `rule_ids`, `categories`, `tags`, `tool_name`, `timestamp`, `event_type` | Safe metadata | Top-level structured fields |
| `evidence[].redacted_value` | Redacted excerpt | Bounded, redacted text from session content |
| `evidence[].hash` | Hashed value | SHA-256 of the original value |
| `evidence[].field` | Safe metadata | Identifies which source field the evidence came from |
| `evidence[].rule_id` | Safe metadata | Links evidence to the rule that matched it |
| `source_path_hash` | Hashed value | SHA-256 of the source file path |
| `triage.*` | Safe metadata + redacted excerpt | Triage verdict, confidence, reason, timeline anchors |
| `response.*` | Safe metadata | Recommended action, playbook, summary, escalation |

Baseline snapshots and per-source baseline contributions live in scanner state, not the event schema. Their network host labels are stored as deterministic `sha256:` hashes so deviation scoring can compare identities without persisting raw destinations.

## Error and Scanner Event Privacy

Scanner error events (`event_type: scanner_error`) apply additional privacy:

- `redact_error_message()` strips absolute paths (`/home/*`, `/Users/*`, `/tmp/*`, `/var/*`) → `<path>`
- `redact_error_message()` strips secret-like key-value pairs (`token: ...`, `key: ...`, `secret: ...`) → `[redacted-secret]`
- Error messages are truncated to 200 characters

## Hashing Policy

| Value Type | Hash Function | When to Hash |
| --- | --- | --- |
| Source file path | SHA-256 (`path_hash()`) | Always, for `source_path_hash` and evidence |
| Evidence original value | SHA-256 (`evidence_hash()`) | Always, for `evidence[].hash` |
| Baseline network host label | SHA-256 with `sha256:` prefix | Persisted scanner state stores hashed host identities; legacy raw labels are hashed on state load and written hashed on the next save |
| Session ID | None | Session IDs are opaque identifiers, not secrets |
| Event ID | SHA-256 | In correlation events for cross-reference |

Hashes are deterministic: the same input always produces the same hash, enabling correlation across scans without storing raw values.

## Fixture Privacy

Test fixtures must be synthetic and should not contain real transcripts,
credentials, hostnames, private paths, or production session data.

Fixture files under `tests/fixtures/` contain:
- Synthetic session IDs (e.g., `uc001-positive`, `api-key-pattern`)
- Synthetic credentials (e.g., `ghp_1234567890abcdef1234`, `AKIA1234567890ABCDEF`)
- Synthetic domains (e.g., `darkroastcyber.io`)
- Synthetic paths (e.g., `.env`, `id_rsa`)

Detection tests verify that these synthetic values do not appear in redacted output.

## Public Documentation and Release Boundary

Public examples, screenshots, release notes, and support claims should use
synthetic fixtures or already-redacted event output. Do not copy live session
stores, raw transcripts, local telemetry logs, scanner state, workstation paths,
hostnames, SIEM endpoint details, or credential-like values into public
documentation or release artifacts.

When live host validation is needed, keep the exact source paths and raw
observations in local-only notes. Public validation summaries should describe
the supported client, fixture coverage, deterministic test command, and any
known lossy fields without exposing host-specific evidence. If a public issue
or release note needs an example, recreate the behavior with a synthetic fixture
and cite the fixture-safe command that reproduces it.

## Future Privacy Work

### Dedicated Redaction Stage

A future redaction stage should:
1. Classify sensitive spans by type (credential, path, domain, encoded blob, private key)
2. Preserve useful evidence shape (length, structure, class markers)
3. Make redaction decisions testable and auditable
4. Support privacy-focused models or services when available

### Privacy-Focused Model Integration

When a privacy/redaction model is available (e.g., OpenAI-compatible):
1. Send bounded context to the model
2. Receive structured redaction annotations
3. Apply redactions deterministically
4. Log redaction decisions for audit

### Local Context Opt-In

Future CLI flags:
- `--emit-local-context`: include longer excerpts in events
- `--local-context-max-tokens`: bound local context size (default: 0, disabled)
- `--redaction-level`: `strict` (default), `relaxed`, `audit`

## References

- [detection-content-standard.md](detection-content-standard.md) — Rule metadata and fixture expectations
- [normalization-schema.md](normalization-schema.md) — Canonical transcript schema
- [telemetry-output.md](telemetry-output.md) — Public JSONL telemetry and fixture-backed release evidence guidance
- [trust-boundaries.md](trust-boundaries.md) — Untrusted session content and publication boundary guidance
- [release-readiness.md](release-readiness.md) — Release artifact and public evidence checklist
