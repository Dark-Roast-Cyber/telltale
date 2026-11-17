//! OpenCode: the tool shapes captured ahead of its adapter.
//!
//! There is no OpenCode adapter in the registry yet. The normalization below
//! comes from payloads captured from OpenCode 1.19.5 and 2.2.5
//! (tests/hooks/fixtures/opencode) and is pinned by the parity tests, so the
//! adapter starts from evaluated shapes.

use crate::hooks::normalize::Rules;

/// The `Context::harness` name the adapter will use.
pub const NAME: &str = "opencode";

/// OpenCode 1.19.5 `apply_patch` and 2.2.5 `patch` (`{"patchText": patch}`),
/// `edit` and `multiedit` (`edits[]`) with camelCase keys.
pub const NORMALIZATION: Rules = Rules {
    patch_tools: &[
        ("apply_patch", false, Some("patchText")),
        ("patch", false, Some("patchText")),
    ],
    key_tools: &["edit", "multiedit"],
    keys: &[("newString", "new_string"), ("oldString", "old_string")],
    tool_names: &[],
};
