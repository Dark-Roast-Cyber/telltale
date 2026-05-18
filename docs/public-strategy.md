# Public Strategy Summary

Telltale is the open-source core of a local-first agent detection and response
tooling stack. It exists to make agent behavior visible, reviewable, and
exportable without requiring vendor lock-in or live hooks inside the agent
runtime.

The public strategy emphasizes:

- agent-agnostic source adapters behind stable discovery and parse interfaces;
- deterministic detection and scoring before any model-assisted triage;
- privacy-conscious evidence handling with redaction and hashing by default;
- append-only JSONL telemetry that downstream SIEM tools can consume.

Detailed planning is intentionally omitted from the public summary until each
capability is ready to document as an operator-facing workflow.

For the related public roadmap and release notes summaries, see
`docs/public-roadmap.md` and `docs/public-release-notes.md`.
