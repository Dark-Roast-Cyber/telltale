# privacy-boundary Specification

## Purpose
Defines privacy invariants for textual data emitted from Telltale through canonical events and operational diagnostics.
## Requirements
### Requirement: Emitted textual evidence crosses the privacy boundary

The system SHALL expose one deterministic emitted-text sanitization boundary and SHALL route sensitive or content-derived Event 3.0 text through that boundary before serialization. Compatibility helpers MAY remain only as wrappers over the same implementation authority.

#### Scenario: Structured secret assignment

- **WHEN** source-derived evidence contains a controlled synthetic secret in JSON, YAML, shell, or key/value assignment form
- **THEN** the serialized Event 3.0 does not contain the controlled secret value

#### Scenario: Assignment syntax varies

- **WHEN** a case-insensitive secret-bearing key appears in key/value, JSON, YAML, `.env`, shell export, or PowerShell environment assignment syntax with whitespace, quotes, escaping, or supported multiline structure
- **THEN** the value is replaced while useful key or structural context remains and unrelated surrounding evidence is not greedily consumed

### Requirement: Sanitization is context aware

The system SHALL apply sanitization appropriate to the output context so that evidence, commands, URLs, paths, scanner errors, and delivery errors can preserve only the structure needed by their contracts.

#### Scenario: Command summary contains a secret-bearing argument

- **WHEN** a command summary contains a controlled secret value in an argument
- **THEN** the command remains recognizable at a bounded useful level while the secret value is absent

### Requirement: URL credentials are not emitted

The system SHALL remove URL userinfo and SHALL redact credential-like query values before emitting URL-derived text. For a percent-encoded URL candidate, it SHALL make no more than two whole-candidate percent-decode passes and SHALL stop at the first syntactically supported `scheme://` representation (including mixed literal/encoded scheme forms). Once that representation is found, its authority, path, query, and fragment boundaries are immutable. Any later percent decoding SHALL be component-local for classification/redaction and SHALL NOT create or redefine an outer URL component. Percent-encoded text that does not expose a supported `scheme://` within that bound SHALL not be claimed as recognized URL input.

#### Scenario: URL contains userinfo

- **WHEN** source text contains `https://user:CONTROLLED_SECRET@example.invalid/path`
- **THEN** emitted text contains neither the userinfo secret nor the `user:...@` authority component

#### Scenario: URL query contains credentials

- **WHEN** a URL has mixed-case or percent-encoded credential-like query names among safe parameters
- **THEN** userinfo is absent, sensitive parameter values are redacted, and safe scheme, host, path, query key names, parameters, and fragment remain useful where parsing permits

#### Scenario: Bounded URL decoding preserves component ownership

- **WHEN** a bounded encoded URL contains `%252F`, `%255C`, `%253F`, `%2523`, `%2540`, or mixed-case `%252f` in its authority, or contains encoded `?`/`#` material in its path, query, or fragment after the first recognizable `scheme://`
- **THEN** decoded authority delimiters fail closed atomically by replacing the complete recognized URL-like candidate, while path/query/fragment delimiters remain local to their original component and cannot create or redefine the outer boundaries; safe fully encoded URLs remain useful and repeated sanitization is idempotent

#### Scenario: URL recognition is bounded and mixed-form aware

- **WHEN** URL syntax is literal, fully encoded, mixed literal/encoded, or double encoded and a supported `scheme://` becomes recognizable within two whole-candidate decode passes
- **THEN** sanitization starts at that first representation and applies the immutable component policy; ordinary percent-encoded non-URL text and URL-looking text beyond the two-pass recognition bound remain ordinary text and are not claimed as supported URL recognition

### Requirement: Sensitive paths are not emitted

The system SHALL consistently replace privacy-sensitive Windows drive/profile, UNC, Linux home, macOS home, temporary/private-state, SSH/private-key, and credential-file paths while preserving a safe path-class marker where useful. It SHALL NOT change `source_path_hash` semantics.

#### Scenario: Diagnostic includes a private host path

- **WHEN** source-derived text includes a controlled username in a host path
- **THEN** the serialized or displayed output contains neither the username nor identifying UNC authority/share and includes a safe path marker

#### Scenario: URL path contains a sensitive filesystem shape

- **WHEN** native or historical text contains a URL whose path is a local user profile, private state location, or credential-file path, including bounded percent-encoded forms
- **THEN** the scheme and safe authority/query structure remain useful while the sensitive path and controlled username are replaced before Event serialization or durable JSONL/Elastic output

### Requirement: Known credentials and private keys are fail-closed

The system SHALL redact known GitHub, `sk-*`, AWS AKIA, Slack, JWT, Bearer, encoded/high-entropy credential shapes and the complete sensitive body and boundaries of a private-key block.

#### Scenario: Multiline private key

- **WHEN** emitted text contains a synthetic private-key boundary, body, and end boundary
- **THEN** no boundary or body marker survives and bounded safe surrounding text may remain

### Requirement: Diagnostics remain bounded and privacy safe

Scanner and delivery diagnostics SHALL remove controlled secret values and sensitive host-path content and SHALL enforce their documented output bound.

#### Scenario: Parser error includes path and token

- **WHEN** an underlying error includes an absolute host path and controlled token value
- **THEN** the emitted scanner diagnostic contains neither raw value and remains within the configured diagnostic bound

#### Scenario: Delivery failure is displayed and emitted

- **WHEN** a sink error contains URL userinfo, a credential query value, or a sensitive path
- **THEN** neither operational Event JSON nor stderr/log diagnostic output contains the controlled values

### Requirement: Controlled marker validation covers every textual event family

The privacy test system SHALL serialize representative events for every Event 3.0 family capable of carrying source-derived text or errors and SHALL fail if a controlled marker survives serialization.

#### Scenario: New textual event family lacks privacy coverage

- **WHEN** a textual event builder is added without a representative controlled-marker serialization test
- **THEN** the privacy coverage gate fails or otherwise identifies the uncovered event family before release

Covered families SHALL include detection, activity, health, scanner error, operational alert, session risk summary, correlation, process-chain, and any additional current Event 3.0 family capable of carrying content-derived or diagnostic text.

### Requirement: Sanitized evidence remains bounded and useful

The system SHALL use Unicode-safe bounds and SHALL preserve safe analytic structure such as rule/category/action identifiers, safe tool names, URL host/path shape, query key names, and explicit redaction class markers. It SHALL NOT emit unbounded transcript excerpts.

#### Scenario: Truncation does not promote a partial lexical tail

- **WHEN** raw text exceeds the 4096-byte inspection bound and the bound cuts through a credential-shaped, assignment-like, URL-like, encoded, opaque, or otherwise lexical token
- **THEN** the UTF-8-safe retained prefix is classified only after the ambiguous terminal fragment is replaced with a stable truncation-tail marker, whitespace compaction does not promote any retained token prefix, and the result remains within its context output bound

#### Scenario: Truncation preserves a useful safe prefix

- **WHEN** raw text exceeds the input bound but contains safe text before the cut, or the cut falls at a whitespace boundary
- **THEN** the safe leading evidence remains useful, the ambiguous retained tail is the only content neutralized, and repeated sanitization produces identical output without reinterpreting the truncation marker

#### Scenario: Benign near-miss text

- **WHEN** ordinary text resembles but does not satisfy a secret or sensitive-path pattern
- **THEN** the ordinary text remains recognizable and output stays within its context bound

### Requirement: Durable storage may persist only privacy-safe canonical events

Any future durable delivery outbox or dead-letter payload SHALL persist only canonical Event 3.0 bytes after this privacy boundary.

#### Scenario: Outbox implementation consumes a serialized event

- **WHEN** durable delivery stores Event 3.0 payload bytes
- **THEN** the same controlled-marker validator can be applied to those bytes and no unsanitized transcript/source record is required by the queue contract

#### Scenario: Current durable JSONL first write

- **WHEN** an Event 3.0 carrying synthetic adversarial inputs is emitted to the canonical JSONL sink
- **THEN** reusable serialized-byte marker validation proves the persisted bytes contain no controlled marker

### Requirement: Event and processing contracts remain stable

The change SHALL preserve Event 3.0 shape, parser/source identity, explicit parser failures, detector inputs, rule matches, scoring, efficacy labels, and durable-first-write behavior. All adversarial data SHALL be synthetic, and sanitization SHALL use no external model or service.

#### Scenario: Evaluation baseline is rerun

- **WHEN** the Issue #24 evaluation contract runs after privacy hardening
- **THEN** efficacy outcomes and detector semantics are unchanged; any characterization-byte change is limited to reviewed sanitized output

### Requirement: Historical opaque labels remain stable without gaining trust

For historical Event 3.0 export and derived timeline/correlation output, the system SHALL preserve an opaque identifier only when one authoritative full-string recognizer accepts a registered expected type and the exact form `[type:64-lowercase-hex-digest]`. The preserved value SHALL be treated only as an unauthenticated pseudonymous label. Marker recognition SHALL NOT authenticate provenance, authorize behavior, suppress detections, or alter detector/scoring semantics. Native/source-controlled values SHALL continue through their ordinary emitted identifier policy.

#### Scenario: Exact historical marker survives re-export and derived linkage

- **WHEN** a historical Event 3.0 record contains exact recognized session, product, or derived-reference markers
- **THEN** repeated JSONL/Elastic export and derived timeline/correlation output preserve those exact labels for linkage

#### Scenario: Marker-looking source value is malformed or native

- **WHEN** a marker-looking value has an unknown type, wrong length, invalid character, upper-case digest, prefix, suffix, or originates from a native/source-controlled field
- **THEN** it is not preserved as a historical marker and the ordinary emitted identifier policy applies

#### Scenario: Attacker supplies an exact historical marker

- **WHEN** an untrusted historical Event 3.0 record contains an exact recognized marker
- **THEN** the label may be preserved for idempotence and correlation linkage but is not authenticated or trusted provenance

