# http-transfer-direction Specification

## Purpose
Define directional and encoding-evidence semantics for bundled HTTP transfer
rules so download, outbound upload, and encoded HTTP remain independently
meaningful.

## Requirements
### Requirement: Download matching requires retrieval, not outbound upload

`network.download` SHALL match download-capable retrieval of remote HTTP/FTP
content and SHALL NOT match curl invocations whose evidence is outbound upload
(`--data`, `--data-binary`, `--upload-file`, `-X POST`/`PUT`, or `-F`).

#### Scenario: Documented package fetch

- **WHEN** a tool call runs `curl https://packages.example.invalid/tool.tar.gz`
- **THEN** `network.download` matches
- **AND** `exfil.outbound_upload` does not match

#### Scenario: Outbound encoded API POST

- **WHEN** a tool call runs `curl --data` with a request body to an `https://` URL
- **THEN** `network.download` does not match

#### Scenario: Short-flag retrieval

- **WHEN** a tool call runs `curl -fsSL https://example.com/payload.sh -o /tmp/payload.sh`
- **THEN** `network.download` matches

### Requirement: Encoded HTTP requires encoding evidence

`exfil.encoded_http` SHALL match HTTP client use with encoded hostname labels or
request-body material that includes base64 special characters (`+`, `/`, or `=`).
It SHALL NOT treat a long alphanumeric token alone as encoded HTTP.

#### Scenario: Benign long token POST

- **WHEN** a tool call posts sixty `A` characters with `curl --data` to an HTTPS URL
- **THEN** `exfil.encoded_http` does not match
- **AND** `exfil.outbound_upload` may still match

#### Scenario: Encoded hostname GET

- **WHEN** a tool call GETs `https://` plus a 20+ alphanumeric label and a
  lowercase DNS suffix
- **THEN** `exfil.encoded_http` matches
- **AND** the session remains at or above the security-review boundary when the
  existing malicious encoded-egress fixture is evaluated

#### Scenario: Encoding without an HTTP client

- **WHEN** encoded-looking material appears without `curl`/`wget`/`fetch` HTTP use
- **THEN** `exfil.encoded_http` does not match
- **AND** `network.download` and `exfil.outbound_upload` do not match from that
  encoding alone

### Requirement: Independent encoding and outbound transfer remain additive

When a single invocation independently satisfies outbound upload and encoded-HTTP
evidence, both rules SHALL match and both contributions SHALL be counted. The
engine SHALL NOT subtract overlapping interpretations after scoring.

#### Scenario: Encoded outbound POST

- **WHEN** a tool call uses `curl --data` with a base64 body containing `=` or
  `+/` and an HTTPS destination
- **THEN** `exfil.encoded_http` and `exfil.outbound_upload` both match
- **AND** `network.download` does not match
- **AND** the checked contribution total equals the sum of retained contributions
