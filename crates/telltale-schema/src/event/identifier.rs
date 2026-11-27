//! Terminal policy for native and historical Event 3.0 identifiers.

use super::inventory::evidence_hash;
use super::redaction::contains_credential_material;
use crate::clients::ClientId;
use crate::scoring::is_canonical_contribution_id;

pub(super) fn terminal_tag(tag: &str) -> String {
    if let Some(name) = tag.strip_prefix("allowlist:") {
        return format!("allowlist:{}", opaque_identifier("suppression", name));
    }
    terminal_identifier("tag", tag)
}

pub(super) fn terminal_imported_session_id(canonical_event: bool, value: &str) -> String {
    if canonical_event {
        terminal_historical_session_id(value)
    } else {
        terminal_session_id(value)
    }
}

pub(super) fn terminal_imported_product_metadata(
    canonical_event: bool,
    kind: &str,
    value: &str,
) -> String {
    if canonical_event {
        terminal_historical_product_metadata(kind, value)
    } else {
        terminal_product_metadata(kind, value)
    }
}

pub(super) fn terminal_imported_opaque_identifier(
    canonical_event: bool,
    kind: &str,
    value: &str,
) -> String {
    if canonical_event {
        terminal_historical_opaque_identifier(kind, value)
    } else {
        opaque_identifier(kind, value)
    }
}

pub(super) fn terminal_imported_tag(canonical_event: bool, tag: &str) -> String {
    if canonical_event {
        if is_canonical_opaque_identifier_for_kind("tag", tag) {
            return tag.to_string();
        }
        if tag
            .strip_prefix("allowlist:")
            .is_some_and(|value| is_canonical_opaque_identifier_for_kind("suppression", value))
        {
            return tag.to_string();
        }
        terminal_tag(tag)
    } else {
        terminal_tag(tag)
    }
}

/// Produce an opaque marker for a raw source-derived identifier that must
/// remain correlatable without leaving the terminal privacy boundary.
pub fn opaque_identifier(kind: &str, value: &str) -> String {
    opaque_identifier_for_hash_input(kind, value, value)
}

fn opaque_identifier_for_hash_input(kind: &str, _value: &str, hash_input: &str) -> String {
    let prefix = format!("[{kind}:");
    format!("{prefix}{}]", evidence_hash(hash_input))
}

const CANONICAL_OPAQUE_IDENTIFIER_KINDS: &[&str] = &[
    "agent",
    "analytic-intent",
    "atlas-tag",
    "call",
    "category",
    "client",
    "dedup",
    "detection-class",
    "event",
    "event-type",
    "evidence-field",
    "host",
    "invalid-event-time",
    "invalid-timestamp",
    "metadata-key",
    "metadata-value",
    "model",
    "policy",
    "process",
    "process-adjustment",
    "process-config",
    "process-rule",
    "provider",
    "provenance-kind",
    "risk-summary",
    "rule",
    "rule-source",
    "session",
    "severity",
    "sink",
    "signal-type",
    "source-event",
    "suppression",
    "tag",
    "time-confidence",
    "time-source",
    "tool",
    "user",
];

/// A full-string canonical opaque marker parsed without assigning provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalOpaqueIdentifier<'a> {
    kind: &'a str,
    digest: &'a str,
}

impl CanonicalOpaqueIdentifier<'_> {
    pub fn kind(&self) -> &str {
        self.kind
    }

    pub fn digest(&self) -> &str {
        self.digest
    }
}

/// Recognize the exact marker form emitted by Telltale.
///
/// This validates only marker syntax and a registered marker kind. It does not
/// authenticate the source that supplied the value.
pub fn parse_canonical_opaque_identifier(value: &str) -> Option<CanonicalOpaqueIdentifier<'_>> {
    let body = value.strip_prefix('[')?.strip_suffix(']')?;
    let (kind, digest) = body.split_once(':')?;
    if !CANONICAL_OPAQUE_IDENTIFIER_KINDS.contains(&kind)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    Some(CanonicalOpaqueIdentifier { kind, digest })
}

/// Match an exact canonical opaque marker for its expected identity kind.
pub fn is_canonical_opaque_identifier_for_kind(kind: &str, value: &str) -> bool {
    parse_canonical_opaque_identifier(value).is_some_and(|marker| marker.kind == kind)
}

/// Preserve only an exact historical canonical session marker; source values
/// that merely resemble markers are processed through the native policy.
pub fn terminal_historical_session_id(value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind("session", value) {
        value.to_string()
    } else {
        terminal_session_id(value)
    }
}

/// Preserve only an exact historical canonical product marker.
pub fn terminal_historical_product_metadata(kind: &str, value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind(kind, value) {
        value.to_string()
    } else {
        terminal_product_metadata(kind, value)
    }
}

pub(super) fn terminal_historical_client_id(value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind("client", value) {
        value.to_string()
    } else {
        terminal_client_id(value)
    }
}

/// Preserve only an exact historical canonical marker for an identifier kind.
pub fn terminal_historical_identifier(kind: &str, value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind(kind, value) {
        value.to_string()
    } else {
        terminal_identifier(kind, value)
    }
}

pub(crate) fn is_native_rule_identifier(value: &str) -> bool {
    is_canonical_contribution_id(value) && !contains_credential_material(value)
}

pub(crate) fn is_terminal_rule_identifier(value: &str) -> bool {
    value
        .strip_prefix("redacted.")
        .is_some_and(super::is_canonical_sha256_hex)
        || is_native_rule_identifier(value)
}

/// Preserve safe native rule identifiers and hash every other value, including
/// source text shaped like a historical replacement.
pub fn terminal_rule_identifier(value: &str) -> String {
    if is_native_rule_identifier(value) {
        value.to_string()
    } else {
        format!("redacted.{}", evidence_hash(value))
    }
}

/// Recognize terminal rule-ID syntax only at historical Event 3 readback.
/// A matching replacement is not authenticated provenance.
pub fn terminal_historical_rule_identifier(value: &str) -> String {
    if is_terminal_rule_identifier(value) {
        value.to_string()
    } else {
        terminal_rule_identifier(value)
    }
}

fn terminal_historical_opaque_identifier(kind: &str, value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind(kind, value) {
        value.to_string()
    } else {
        opaque_identifier(kind, value)
    }
}

pub(super) fn terminal_imported_identifier(
    canonical_event: bool,
    kind: &str,
    value: &str,
) -> String {
    if canonical_event {
        terminal_historical_identifier(kind, value)
    } else {
        terminal_identifier(kind, value)
    }
}

/// Preserve structurally safe source session identifiers. Other source values
/// remain correlatable through a session-specific domain-separated hash.
pub fn terminal_session_id(value: &str) -> String {
    if is_safe_structured_identifier(value) && !contains_credential_material(value) {
        return value.to_string();
    }
    opaque_identifier_for_hash_input("session", value, &format!("session-id:v1\0{value}"))
}

pub(super) fn terminal_client_id(value: &str) -> String {
    if matches!(value, "scanner" | "none" | "install_inventory")
        || value.split(',').all(is_supported_client_identifier)
    {
        return value.to_string();
    }
    opaque_identifier("client", value)
}

pub(super) fn terminal_imported_client_id(canonical_event: bool, value: &str) -> String {
    if canonical_event {
        terminal_historical_client_id(value)
    } else {
        terminal_client_id(value)
    }
}

/// Clients whose sources were retired (decision S2). They are no longer
/// `ClientId`s, but records written while they were supported keep their
/// readable name.
const RETIRED_CLIENT_NAMES: &[&str] = &["gemini", "roocode", "kilocode"];

/// Whether `value` is a client name that output keeps readable: every
/// `ClientId`, so a new client cannot ship with its name hashed, plus the
/// retired names.
pub(super) fn is_supported_client_identifier(value: &str) -> bool {
    ClientId::from_name(value).is_some() || RETIRED_CLIENT_NAMES.contains(&value)
}

/// Agent, model, and provider are controlled product metadata contexts, not
/// arbitrary evidence. Preserve bounded structured identifiers and hash all
/// other source-provided values under their provenance label.
pub fn terminal_product_metadata(kind: &str, value: &str) -> String {
    if is_safe_product_metadata(kind, value) {
        return value.to_string();
    }
    opaque_identifier(kind, value)
}

fn is_safe_product_metadata(kind: &str, value: &str) -> bool {
    if !is_safe_structured_identifier(value) || contains_credential_material(value) {
        return false;
    }
    match kind {
        "agent" => is_supported_client_identifier(value),
        "provider" => matches!(
            value,
            "openai"
                | "anthropic"
                | "google"
                | "github"
                | "microsoft"
                | "azure"
                | "ollama"
                | "openrouter"
        ),
        "model" => [
            "gpt-",
            "o1",
            "o3",
            "o4",
            "claude-",
            "gemini-",
            "qwen",
            "llama",
            "mistral",
            "deepseek-",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix)),
        _ => false,
    }
}

pub(super) fn is_safe_structured_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b':')
        })
}

/// Sanitize an identifier while retaining canonical static labels where safe.
pub fn terminal_identifier(kind: &str, value: &str) -> String {
    if value.len() <= 128
        && !contains_credential_material(value)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b':' | b'>' | b'+')
        })
    {
        return value.to_string();
    }
    opaque_identifier(kind, value)
}

/// Built-in harness tool names of supported clients that terminal identifiers
/// would otherwise hash because of their casing. A closed vocabulary cannot carry
/// secrets or paths; MCP and other host-defined names are not listed.
const KNOWN_HARNESS_TOOL_NAMES: &[&str] = &[
    "Agent",
    "Bash",
    "BashOutput",
    "Edit",
    "ExitPlanMode",
    "Glob",
    "Grep",
    "KillShell",
    "LS",
    "MultiEdit",
    "NotebookEdit",
    "NotebookRead",
    "Read",
    "SlashCommand",
    "Skill",
    "Task",
    "TodoRead",
    "TodoWrite",
    "WebFetch",
    "WebSearch",
    "Write",
];

/// Action-facing tool label: known built-in tool names verbatim, everything else
/// through [`terminal_identifier`]. Event 3 keeps `terminal_identifier` unchanged.
pub fn terminal_tool_label(value: &str) -> String {
    if KNOWN_HARNESS_TOOL_NAMES.contains(&value) {
        return value.to_string();
    }
    terminal_identifier("tool", value)
}

/// Preserve an action tool label exactly as [`terminal_tool_label`] produced it
/// (a known built-in name, a safe lowercase name, or a canonical opaque `tool`
/// marker); normalize anything else. Use this, not
/// [`terminal_historical_identifier`], to validate stored or received action
/// tool labels: the generic form re-hashes readable built-in names.
pub fn terminal_historical_tool_label(value: &str) -> String {
    if is_canonical_opaque_identifier_for_kind("tool", value) {
        value.to_string()
    } else {
        terminal_tool_label(value)
    }
}

pub(super) fn is_safe_atlas_tag(value: &str) -> bool {
    value.len() <= 128
        && value.starts_with("atlas:")
        && !contains_credential_material(value)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_uppercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b':')
        })
}

pub(super) fn terminal_atlas_tag(value: &str) -> String {
    if is_safe_atlas_tag(value) {
        return value.to_string();
    }
    format!("atlas:{}", evidence_hash(value))
}

#[cfg(test)]
mod tests;
