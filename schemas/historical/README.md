# Historical event schema

`event-3.0.schema.json` is the immutable Event 3.0 wire contract. It is
byte-identical to `schemas/event.schema.json`. The artifact hash is
`9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754`.

It is a validation reference for the current journal reader, not a conversion
target. Event 1.0 and 2.0 schemas are not packaged. Current `export` and
`status` reject those records with `unsupported_schema_version` and do not
rewrite them as Event 3.0. Read or export an old journal with the older binary
that wrote it, and keep a new scan journal separate from that file.

## Historical rule catalog schema

`rule-catalog-v1.schema.json` is the rule catalog v1 contract
(`telltale.rule_catalog.v1`) that Telltale 0.7 emits. Its artifact hash is
`347479fb462aa8169184d5d706384374dcd1080d8b47e8f68e6a772b1a5ad584`. Current
releases emit rule catalog v2 (`schemas/rule-catalog-v2.schema.json`) and do
not read v1 documents.
