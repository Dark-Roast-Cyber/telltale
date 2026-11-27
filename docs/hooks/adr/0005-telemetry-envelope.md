# ADR 0005: Host envelope around unmodified ActionRecordV1

Status: Accepted (2026-11-04)

## Context

Telltale: "Hosts forward these; they do not design their own action format"
(`docs/embedding.md`, host wire). Telltale models detections, not hook
decisions, harness lifecycle, or whether enforcement held; Event 4.0 alert
records are planned but inactive.

## Decision

One JSONL record per hook observation, schema `telltale_hooks.record.v1`
(`schemas/telltale-hooks-record-v1.schema.json`), kinds `decision`,
`outcome`, `result_finding`, `lifecycle`, `error`. Detection content travels
only as `telltale: [{delivery_key, record: ActionRecordV1}]`, unmodified and
strictly re-validatable with `ActionRecordV1::from_json`. Host fields cover
what Telltale does not: harness and hook identity, permission mode, session,
subagent and prompt IDs, verdict, basis, scores, enforcement outcome, and
evaluation status (coverage, visibility limits, failure codes, timings).

Privacy: no prompts, tool inputs, outputs, or paths. Inputs and cwd appear
only as SHA-256; prompt length and hash only. Telltale's redacted evidence is
the only content.

## Consequences

- SIEM mapping (Elastic, Splunk HEC) happens at the transport boundary,
  per Telltale guidance; a later issue covers shipping.
- When Telltale ships Event 4.0, re-evaluate whether decision/outcome
  records should move into it; keep `delivery_key` stable across that move.

## Addendum (2026-11-26): upload destination facts

Status: Accepted. Amends "Decision" for 0.8.0; the record version stays
`telltale_hooks.record.v1` because the field is optional and additive.

An entry of `telltale` whose action carries `exfil.outbound_upload` may also
hold `destinations`: the upload's destination facts
(`DestinationFacts`: `destinations`, `complete`, `local_only`), beside the
unmodified record. Evidence is redacted, so without them a host cannot tell
an upload to its own artifact host from one to an unknown host.

This adds one content source to the privacy statement above. Besides
Telltale's redacted evidence, a record may now carry destination entries:
hosts and at most two path segments or an object-storage bucket and prefix,
built from parsed URL parts in a closed alphabet, never a port, userinfo,
query or fragment, and kept only when the evidence sanitizer leaves them
unchanged. A strict reader checks them with `DestinationFacts::is_valid`.
