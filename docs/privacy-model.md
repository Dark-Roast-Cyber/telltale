# Privacy and Evidence Model

> **Website:** For an approachable guide to provenance and evidence handling, see [AgentArchaeology.ai/field-guide/provenance](https://agentarchaeology.ai/field-guide/provenance/).

Telltale monitors agent session stores that contain sensitive material: API keys, credentials, private keys, file paths, conversation bodies, and tool-call arguments. The privacy model defines how Telltale classifies, transforms, and emits evidence so SIEM events remain useful without becoming a new secret-leak surface.

## Tested v0.6 Boundary

`Event`, `Event::emittable()`, and `serialize_event_for_emission()` are equivalent, authoritative, deterministic, local-only privacy boundaries. Serialization terminal-sanitizes a clone without changing the raw in-memory `Event`; production JSONL, HEC, and Elastic serializers use that canonical representation. Native Event 3.0 emission always uses the trusted compile-time Telltale package version; arbitrary public version mutations, including credential-bearing SemVer metadata, are replaced before emission. Canonical Event 3.0 emission preserves only established 64-character lowercase-hex `source_path_hash`/evidence hashes; arbitrary post-construction source-hash values become deterministic SHA-256 values. MITRE ATT&CK technique IDs preserve the current `T1234`/`T1234.001` forms, while other values become deterministic `mitre:<sha256>` fallbacks. Known `source_counts` keys remain `<client>.<source-kind>` identifiers; noncanonical keys become deterministic `source_count:<sha256>` keys with collision suffixes. `workspace` is not a native Event 3.0 field; source workspace metadata remains part of the local normalized-input model and, when selected as evidence, is emitted only through the evidence path sanitizer. `telltale-schema` exposes `PrivacySanitizer` and `SanitizationContext`; the legacy `redact_sensitive_text()` helper delegates to that authority. There is no external redaction model or service, and sanitization happens after parsing and deterministic detection/scoring, not on detector inputs.

### Historical Opaque Markers

Historical Event 3.0 JSON is untrusted. For repeated export and derived timeline/correlation linkage, Telltale preserves an opaque marker only when the complete string exactly matches a registered marker type and the emitted form `[type:64-lowercase-hex-digest]`. This is syntax recognition, not provenance: an attacker can supply an exact marker, and it remains an unauthenticated pseudonymous label. Malformed, near-miss, unknown-type, upper-case, prefixed, or suffixed marker-looking values are processed by the normal native identifier policy instead. The same rule applies to arbitrary historical extension values and keys.

Native/source-controlled values do not gain this preservation behavior merely by resembling a marker; their source context applies the ordinary emitted identifier policy. Historical timeline and correlation serializers use the same exact recognizer and explicit historical-context helpers, so legitimate labels stay stable across re-export without changing detection, scoring, or trust decisions. A future authenticated provenance design would require a separately specified signed or otherwise verifiable export envelope; no marker syntax currently supplies authentication, authorization, or trust.

The tested contexts are evidence, command/result, diagnostic/error, URL, path, bounded summary, and controlled metadata. Raw evidence and source fields remain available for local matching, state, timeline, and correlation. At terminal serialization, content uses its context-specific sanitizer. Recognized product metadata such as `codex`, `gpt-5`, and `openai`, plus controlled identifiers such as `secret.env.read` and reviewed playbook names, remain readable only when they contain no credential material. Other source-provided agent/model/provider values become deterministic opaque markers. Session IDs must be both structurally safe and credential-free; all other session IDs become deterministic session-specific, domain-separated hashes, and session risk-entity values use the identical policy. Invalid source `event_time` remains opaque. All response strings and risk-contribution rationales receive useful bounded summary sanitization rather than blanket hashing. Process host/user, source-event, dedup, and non-session risk entities remain opaque. A host risk entity and its process host use the same marker.

### URL Decoding Boundary

For a percent-encoded URL candidate, the sanitizer decodes the whole candidate only until the first recognizable `scheme://` representation. It freezes the authority, path, query, and fragment boundaries at that representation. Any subsequent percent decoding is component-local: decoded authority `/`, `\\`, `?`, `#`, or `@` bytes invalidate and replace the complete candidate, while decoded path/query/fragment delimiters are classified or redacted within their original component and cannot create or redefine an outer boundary. The bounded `%252F`, `%255C`, `%253F`, `%2523`, `%2540`, mixed-case `%252f`, fully double-encoded scheme, safe fully encoded URL, literal userinfo, and encoded sensitive-path cases are covered by focused sanitizer and emission tests; repeated sanitization is idempotent.

The synthetic controlled-marker corpus serializes detection, activity (including install inventory), health, scanner error, operational alert, session risk summary, correlation, and process-chain Event 3.0 families. It also covers MCP inventory/config errors, delivery diagnostics, and canonical JSONL persistence. The serialized marker checker compares exact decoded JSON keys and string values; it does not normalize arbitrary encodings. Encoding-specific assurance comes from separate adversarial sanitizer cases for the supported escaped and bounded percent-encoded representations. The corpus proves those specific cases and markers are absent; it does not claim perfect classification of every possible secret or host identifier.

## Privacy Surface Matrix

The matrix records every Event 3.0 and diagnostic text surface. "Controlled" means a generated enum, fixed schema value, or validated rule/configuration identifier rather than session content. It remains readable because preserving these values is necessary for filtering and compatibility; arbitrary values in the same field class are sanitized or made opaque at the terminal owner.

| Surface | Provenance | Context | Earlier handling | Terminal handling and owner |
| --- | --- | --- | --- | --- |
| `timestamp`, `observed_at`, `ingested_at`, `schema_version`, `event_id`, `event_type`, `severity`, `time_source`, `time_confidence`, `client`, `component`, `check_name`, `status` | Generated or fixed schema/constructor values | Controlled metadata | Serialized as constructed | Preserved by `Event`'s terminal wire view; no source text is accepted here. |
| `telltale_version` | Compile-time package metadata | Trusted controlled constant | Serialized as constructed | Native terminal serialization replaces public mutations with the trusted compile-time package version; historical JSONL/Elastic export preserves safe historical version metadata. |
| `event_time` | Source timestamp or constructor timestamp | Timestamp | Serialized as constructed | Valid RFC3339 is preserved; invalid source text becomes an opaque `invalid-event-time` marker in `terminal_emittable_event`. |
| `time_override_reason` | Local override/error text | Diagnostic | Serialized as constructed | Diagnostic sanitizer in `terminal_emittable_event`. |
| `agent`, `model`, `provider` | Parsed source metadata | Controlled product metadata | Serialized as constructed | `terminal_product_metadata` preserves recognized bounded product identifiers only when they are credential-free, and makes all other source values opaque; raw values remain available in memory. |
| `session_id`, `source_path_hash` | Parser identity and precomputed hash | Structured identifier/hash | Serialized as constructed | `terminal_session_id` preserves a bounded credential-free identifier; unsafe source values use a session-specific domain-separated hash. `terminal_evidence_hash` preserves canonical lowercase-hex source hashes and deterministically hashes arbitrary values. The path never appears because only its hash is emitted. |
| `tool_name`, `tags` | Parsed tool label; rule/allowlist annotation | Identifier | Serialized as constructed | `terminal_identifier`; `allowlist:*` annotations become opaque suppression markers. |
| `rule_ids`, `categories`, `detection_classes`, `signal_types`, `analytic_intents`, `atlas_tags`, `timeline_anchors.*`, `risk_contributions[].id` | Bundled or local rule content | Controlled metadata | Serialized as constructed | Preserved as reviewed rule identifiers/classes; they are not source excerpts and retain detection and schema compatibility. |
| `mitre_attack_techniques` | Bundled or local ATT&CK mapping | Controlled identifier | Serialized as constructed | Canonical `T1234` and `T1234.001` values remain readable; arbitrary values use deterministic `mitre:<sha256>` fallbacks that remain schema-compatible and idempotent. |
| `evidence[].field`, `evidence[].rule_id`, `evidence[].hash` | Constructor mapping, rule identifier, precomputed hash | Controlled metadata/hash | Serialized as constructed | Preserved by the terminal wire view. The field names select the sanitizer without exposing source content. |
| `evidence[].redacted_value` | Source excerpt, path, URL, command/result, or diagnostic | Evidence, Path, URL, CommandResult, or Diagnostic | Constructor-specific redaction could be bypassed by later mutation/direct serde | `terminal_evidence` selects the context from `field` and calls `PrivacySanitizer`. |
| `risk_contributions[].rationale`, `detection_reason` | Rule/config prose and derived detection explanation | Summary | Serialized as constructed | Bounded summary sanitizer through `RiskContribution::for_emission` and `terminal_emittable_event`; safe rationale remains readable. |
| `response.recommended_action`, `response.response_playbook`, `response.investigation_summary`, `response.escalation` | Derived response policy text | Summary | Serialized as constructed | Native terminal serialization preserves the reviewed static action, five playbook, and escalation values, rejects unreviewed response-playbook mutations with a generic error, and summary-sanitizes investigation text. |
| `source_counts` keys, `active_policy_name` | Source registry key; operator policy configuration | Controlled metadata; identifier | Serialized as constructed | Known `<client>.<source-kind>` registry keys remain readable. Noncanonical source-count keys become deterministic `source_count:<sha256>` keys; collision suffixes preserve each count without merging. Policy name becomes an opaque marker because it is arbitrary operator text. |
| `risk_entity_type`, `risk_entity_value` | Derived entity type and source actor/session identity | Identifier or Summary | Serialized as constructed | Type is controlled; session values use the same safe-or-domain-separated-hash policy as `session_id`, host/user values become opaque, and other values use Summary sanitization. |
| `process.host`, `process.user`, `process.source_event_id`, `process.dedup_key` | Source process/event identity and derived dedup key | Identifier | Serialized as constructed | Deterministic opaque markers in `terminal_process_context`; a host risk entity uses the same host marker. |
| `process.source_process_name`, `process.target_process_name`, `process.parent_process_name` | Source process labels | Identifier | Serialized as constructed | `terminal_identifier` preserves recognized safe labels and makes arbitrary values opaque. |
| `process.source_process_path`, `process.target_process_path`, `process.parent_process_path` | Source paths | Path | Serialized as constructed | Path sanitizer in `terminal_process_context`. |
| `process.source_process_command_line`, `process.target_process_command_line` | Source command lines | CommandResult | Serialized as constructed | Command/result sanitizer in `terminal_process_context`. |
| `process.rule_name`, `process.investigation_fields[]`, `process.falsepositives[]`, `process.risk_adjustment` | Local process-rule/config prose | Identifier | Serialized as constructed | Deterministic opaque config markers in `terminal_process_context`; `secondary_rule_ids` and `rule_severity` remain controlled rule metadata. |
| `scanner_error.evidence[error]`, `scanner_error.evidence[source_path]` | Parser error and source path | Diagnostic; Path | Error was diagnostic-redacted before state fingerprinting; path was added as evidence | Constructor retains the pre-fingerprint diagnostic behavior; terminal evidence sanitization applies again to every Event serialization. |
| `operational_alert.evidence[alert_type]`, `[threshold]`, `[actual_value]` | Local alert config, counters, and sink error text | Evidence | Serialized as constructed | `terminal_evidence` sanitizes all three; fixed alert labels/counters remain useful while embedded delivery errors cannot leak. |
| MCP inventory/config errors, scanner progress/fatal errors, historical timeline/export labels | Parser/import error text and imported historical JSON | Diagnostic; Summary; Path | Per-call rendering/redaction | `PrivacySanitizer` at the final rendered diagnostic. Historical JSONL/Elastic export recursively sanitizes string values and unsafe object keys while preserving arrays, objects, and unknown extension structure; unknown historical strings default to Summary, not metadata. Rules test, preview, coverage, and server save path output use the same session, metadata, path, and diagnostic policies. |
| Sink failure alerts and stderr/log delivery/rotation errors | HTTP/error display text and host paths | Evidence or Diagnostic | Could retain transport error text until the sink/console path | Operational-alert evidence crosses `Event` serialization; final console rendering uses the Diagnostic sanitizer. JSONL, HEC, and Elastic receive only canonical Event bytes. |

## Evidence Classes

Telltale uses five evidence classes, ordered from safest to most sensitive:

### 1. Safe Metadata

**Definition**: Structured fields that describe the detection without revealing session content.

**Examples**:
- `client` (codex, opencode, copilot, claude, ...)
- `source_kind` (jsonl, sqlite, copilot_process_log, ...)
- `rule_ids` (secret.env.read, mcp.tool_metadata.prompt_injection, ...)
- `categories` (secret_access, mcp_prompt_injection, ...)
- `severity` (informational, low, medium, high, critical)
- `risk_score` (non-negative cumulative risk points; not capped at 100)
- `event_type` (detection, activity, health, ...)
- `session_id` (a readable bounded identifier only when the source value passes the emitted-session safety policy; otherwise a deterministic session-specific opaque marker)
- `tool_name` (bash, write, curl, ...)
- `timestamp` (RFC3339)
- `telltale_version`, `scan_duration_ms`, `rule_count`

**Current behavior**: These fields retain raw values in memory for deterministic processing. The emitted Event 3.0 representation keeps its field shape, preserves reviewed safe metadata, and uses stable opaque markers for unsafe source-derived identifiers and tags.

**SIEM use**: Correlation, filtering, dashboarding, alerting.

### 2. Redacted Excerpt

**Definition**: Bounded text from session content with sensitive spans replaced by class markers.

**Current implementation**: `PrivacySanitizer` in `crates/telltale-schema/src/event/redaction.rs`; `redact_sensitive_text()` is its evidence-context compatibility wrapper.

**Redaction rules applied** (in order):
1. Generic case-insensitive structured assignments in JSON, YAML, `.env`, shell `export`, PowerShell `$env:`, and space-separated secret flags preserve the key/operator while replacing quoted, escaped, unquoted, and supported multiline values. Bounded `\u`, `\x`, and escaped-quote classification covers escaped JSON/key syntax without emitting decoded source syntax; Unicode assignment whitespace includes NBSP and EM SPACE. Quoted keys recognize camel/suffix forms such as `refreshToken`, `databasePassword`, and `secretKey`. Multiline redaction removes the YAML block-style marker so every context is idempotent without absorbing the following assignment.
2. URL userinfo is removed structurally for recognized URL schemes and scheme-relative authorities. Fully encoded candidates receive bounded whole-candidate decoding only until the first recognizable `scheme://`; boundaries then remain fixed and later decoding is component-local. Mixed-case or percent-encoded credential-like query values are replaced while safe host, ordinary web/DSN paths, parameter names, safe values, and fragments remain useful where parsing permits. URL paths receive bounded decoded classification: local filesystem/profile and credential-file shapes are replaced without emitting decoded source material, while ordinary paths such as API, documentation, repository, and database names remain intact. Query values and fragments receive at most two percent-decode passes; if decoded inspection finds credential material, the component is redacted rather than returning its original encoded bytes, without redefining an outer boundary. Nested URLs beyond the bounded inspection depth fail closed. Malformed authorities, including authorities whose bounded decoded classification contains structural delimiters, replace the complete URL-like candidate with `[redacted-url]`.
3. Windows profiles, temporary/state locations, and UNC paths; Linux home/root/temporary/private state; macOS home/private temporary; SSH; and credential-file paths become path markers, including platform paths with spaces before a sensitive segment and POSIX paths after arbitrary punctuation. URL authority and safe URL path shape are preserved by segmenting punctuation-delimited absolute paths outside URLs. Diagnostic paths use `<path>`; emitted evidence uses `[sensitive-path]`.
4. Complete PEM private-key blocks, known GitHub/OpenAI/AWS/Slack-style tokens, JWTs, Bearer/Basic values, and base64-like encoded blobs are replaced.
5. Existing controlled-domain, package-manager, startup-target, and encoded-decoder markers remain bounded contextual signals.

**Bounds**: input is bounded to 4096 UTF-8-safe bytes before pattern processing. When that bound cuts through a non-whitespace lexical fragment, only the retained terminal fragment is replaced with the stable `[truncated-tail]` marker before classification and whitespace compaction; the useful safe prefix remains available. A cut at a whitespace boundary does not discard preceding evidence. Evidence, URL, command/result, and summary output are bounded to 512 UTF-8-safe bytes; diagnostics are bounded to 200 bytes; path output is bounded to 256 bytes. Evidence normalization retains at most 80 whitespace-delimited tokens. The marker is deterministic and idempotent; these are bounded inspection guarantees, not arbitrary scanning or perfect classification claims.

**Current behavior**: Applied centrally by `Event`, `Event::emittable()`, and `serialize_event_for_emission()` to every Event 3.0 serialization, rather than by individual constructors or sinks. `telltale export` recursively applies the same schema-owned policy to imported historical JSON objects, arrays, string values, and unsafe extension keys before it writes JSONL or Elastic bulk output. The traversal preserves JSON structure, canonical `source_path_hash` and evidence-hash fields, and exact recognized opaque labels in historical Event 3.0 input only; those labels are unauthenticated and therefore do not establish provenance or trust. Unknown historical strings default to Summary, and metadata treatment is reserved for explicit top-level and response fields. It does not alter raw internal parser or detector values.

**SIEM use**: Analyst triage, pattern recognition, timeline reconstruction.

### 3. Hashed Value

**Definition**: SHA-256 digest of the original value, enabling correlation without disclosure.

**Current implementation**: `path_hash()` and `evidence_hash()` in `crates/telltale-schema/src/event/inventory.rs`.

**Current behavior**:
- `evidence[].hash` is populated for all evidence items in detection events (tests assert `hash.is_some()`).
- `source_path_hash` on events is a SHA-256 of the source file path. The terminal boundary also protects manually mutated public Event values by preserving canonical lowercase-hex hashes and hashing any other non-empty value.
- Correlation events hash `event_id` for cross-reference.

**SIEM use**: Deduplication, correlation across sessions, lookup against known-bad hashes.

### 4. Local-Only Sensitive Context

**Definition**: Evidence that is useful for local review but should not be emitted to SIEM by default.

**Current event behavior**: Telltale does not emit a separate local-only context field. Raw parser records and detector inputs remain local process memory only; emitted canonical Events carry bounded sanitized excerpts and approved metadata.

**Baseline state behavior**: Model behavioral baselines are persisted in local scanner state so deviation scoring can compare new observations with prior local activity. Baseline summaries track network host labels observed in parsed tool arguments or results, but persisted scanner state stores those labels as deterministic `sha256:` hashes. Host labels can reveal internal services, customer domains, repository infrastructure, or other environment-specific destinations, so raw labels remain local-only sensitive context and must not be copied into public reports, committed, or exported as telemetry by default. Native state also requires an explicit `state_schema_version` and rejects raw host labels; legacy state is accepted only by the explicit state migration command.

When `--baseline-deviation-scoring` is enabled, emitted activity evidence reports deviation counts such as `new_network_hosts`; it does not emit raw baseline host labels. Existing unversioned state files from earlier builds must be explicitly migrated; migration hashes raw baseline host labels and the next native state save contains only hashed labels.

**Future work**:
- Add an optional `local_context` field to events that is populated only when `--emit-local-context` is set.
- Local context could include longer excerpts, unredacted tool names, or full argument shapes.
- The SIEM JSONL writer would strip `local_context` unless explicitly opted in.
- A local review tool (`telltale inspect <event_id>`) could read the local context from the JSONL file.

### 5. Never Emit

**Definition**: Data that must never appear in Telltale events, regardless of configuration.

**Examples**:
- Raw API keys, tokens, passwords, secrets
- Full auth files (`.aws/credentials`, `.npmrc`, `.netrc`)
- Private key bodies (PEM, OpenSSH, Ed25519)
- Full session transcript bodies
- Raw `.env` file contents
- Raw command output containing secrets
- Session store file contents (only hashes and excerpts)

**Current behavior**: The terminal Event serialization wrapper and final rendered diagnostic context prevent these from reaching canonical Event text or stderr/log diagnostics. Synthetic controlled-marker tests assert specific marker values do not survive serialized output.

## Evidence Minimalism

Telltale should emit the least evidence needed to prove a detection.

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

The `Event` struct in `crates/telltale-schema/src/event/mod.rs` maps evidence classes to fields:

| Field | Evidence Class | Notes |
| --- | --- | --- |
| `client`, `session_id`, `severity`, `risk_score`, `rule_ids`, `categories`, `tags`, `tool_name`, `timestamp`, `event_type` | Safe metadata | Top-level structured fields |
| `evidence[].redacted_value` | Redacted excerpt | Bounded, redacted text from session content, including workspace observations when a source exposes them |
| `evidence[].hash` | Hashed value | SHA-256 of the original value |
| `evidence[].field` | Safe metadata | Identifies which source field the evidence came from |
| `evidence[].rule_id` | Safe metadata | Links evidence to the rule that matched it |
| `source_path_hash` | Hashed value | SHA-256 of the source file path |
| `timeline_anchors` | Safe metadata | Deterministic entry indexes, rule IDs, categories, and evidence fields |
| `response.*` | Safe metadata | Recommended action, playbook, summary, escalation |

Baseline snapshots and per-source baseline contributions live in scanner state, not the event schema. Their network host labels are stored as deterministic `sha256:` hashes so deviation scoring can compare identities without persisting raw destinations.

## Error and Scanner Event Privacy

Scanner error events (`event_type: scanner_error`) retain the established diagnostic-redacted text before state fingerprinting. MCP summaries retain their established safe command representation before hashing. MCP config errors and sink failures receive terminal sanitization before emission, and fatal local diagnostics sanitize the final rendered stderr message. The diagnostic context removes sensitive paths, structured secret values, URL userinfo, credential query values, known credential forms, and private-key material, then applies the 200-byte UTF-8-safe bound.

## Durable JSONL and Future Delivery

Canonical local JSONL is the durable first write. It serializes canonical `Event` bytes; the JSONL sink is not a repair layer. The privacy test writes a synthetic adversarial event through the production append path, compares persisted bytes to canonical serialization, and runs the reusable serialized-byte controlled-marker checker on those bytes.

Issue #26 must reuse `check_serialized_event_markers()` for every durable outbox, retry, permanent-failure, and dead-letter payload. The checker rejects inputs larger than 1 MiB and over-nested JSON with safe error text, and stops at the first marker without rendering input bytes or marker values. Those stores must contain only canonical Event 3.0 bytes after this boundary, never raw transcript or parser records.

## Hashing Policy

| Value Type | Hash Function | When to Hash |
| --- | --- | --- |
| Source file path | SHA-256 (`path_hash()`) | Always, for `source_path_hash` and evidence |
| Evidence original value | SHA-256 (`evidence_hash()`) | Always, for `evidence[].hash` |
| Baseline network host label | SHA-256 with `sha256:` prefix | Persisted native scanner state stores hashed host identities; legacy raw labels are accepted only by the explicit state migration command and are hashed in its canonical output |
| Unsafe session ID | SHA-256 of the `session-id:v1` domain-separated input | `terminal_session_id()` preserves only bounded credential-free IDs and hashes all other source-provided IDs |
| Event ID | SHA-256 | In correlation events for cross-reference |
| Non-canonical MITRE technique value | SHA-256 with `mitre:` prefix | Terminal Event serialization |
| Non-canonical source-count key | SHA-256 with `source_count:` prefix | Terminal Event serialization |

Hashes are deterministic: the same input always produces the same hash, enabling correlation across scans without storing raw values.

The path hashing used for `source_path_hash` and `evidence_hash()` retain their existing SHA-256 input semantics in this boundary change. Deterministic hashes can still be susceptible to dictionary comparison for low-entropy inputs; they are correlation aids, not encryption or a tenant-keyed privacy mechanism. MITRE and source-count fallback hashes are opaque identifiers, not validated ATT&CK mappings or source names.

Canonical constructor output and event identity/delivery mechanisms remain
unchanged. Public native version mutations and noncanonical source hashes,
MITRE values, and source-count keys intentionally produce different emitted and
newly persisted bytes after terminal correction. Corrections happen before the
JSONL first write; persisted historical bytes are never replay-time
reserialized. Historical JSONL/Elastic export retains safe historical version
metadata rather than applying the native version replacement.

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

### Encoded URL Recognition Limit

Encoded URL recognition makes at most two whole-candidate percent-decode passes and stops at the first syntactically supported `scheme://`. Tested literal, fully encoded, mixed literal/encoded, and double-encoded forms are recognized only when they reach that representation within the bound. Authority, path, query, and fragment ownership is then immutable; ambiguous recognized URL intent is replaced atomically, and later decoding is component-local. Percent-encoded text that remains without a supported `scheme://` after two passes is ordinary text and is not claimed as supported URL recognition.

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

The dedicated deterministic redaction stage is current v0.6 behavior, not future work. External or LLM-based privacy classification is not part of the v0.6 architecture: raw source text is not sent to a hosted redaction service, and no downstream sink is trusted to repair unsafe event content. Future privacy changes require a separately reviewed threat model and must preserve this fail-closed local boundary unless explicitly superseded.

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
