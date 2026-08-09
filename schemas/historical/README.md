# Historical event schemas

These schemas are immutable evidence for the event contracts shipped by the
tagged releases. `event-1.0.schema.json` is copied from `v0.1.0` (and matches
the `v0.2.0` artifact); `event-2.0.schema.json` is copied from `v0.3.0` (the
Event 2.0 contract). `event-3.0.schema.json` pins the native Event 3.0
contract activated by the 0.5.0 identity migration.
The strict validator dispatches only after an input declares the exact version
it is being validated against.

The historical files are separate from `schemas/event.schema.json`, which is
the native current-event schema. They are validation references, not migration
targets. Historical records retain their original event ID, version, fields,
and unknown JSON values. A later migration must preserve the untouched source
record and must not rewrite historical records as Event 3.0.

The copied schema byte hashes are `396065acda07468b0d30cd0759fa55b60280b070aa24ccabe89bd6a868509f03`
for the 1.0 artifact (the v0.1.0/v0.2.0 blob) and
`4b41c09e2663ead7049ccdc90737f5536942da6b6247af74f43215f29cfa00a5` for the
2.0 artifact (the v0.3.0 blob). Fixtures use synthetic UUIDs, timestamps,
hashes, source labels, and redacted evidence only; they contain no real
transcripts or credentials.

The Event 3.0 artifact hash is
`9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754`.
