//! Shared process-chain configuration and command extraction.
//!
//! Detection v2 adapts canonical Tool evidence through this extractor to private
//! matcher inputs. Session suppression/correlation belongs to
//! `process_chain_session`; Event3 projection belongs to `v2::event3`.

#[cfg(test)]
mod tests;

use time::Duration;

use telltale_rules::process_chain::{
    ProcessChainContext, ProcessObservation, ProcessRef, normalize_process_name,
};

use crate::process_chain_session::{
    DEFAULT_MAX_CORRELATION_RISK_PER_ENTITY, DEFAULT_MAX_CORRELATIONS_PER_RULE_ENTITY,
    DEFAULT_SUPPRESSION_WINDOW,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessChainConfig {
    /// Environment-specific false-positive controls.
    pub context: ProcessChainContext,
    /// Repeats of the same rule for the same entity inside this window are
    /// collapsed into the first event, which records `repeat_count`.
    pub suppression_window: Duration,
    /// Maximum correlation events emitted per rule per entity per scan.
    pub max_correlations_per_rule_entity: usize,
    /// Ceiling on total correlation risk attributed to one entity per scan.
    /// Correlations past the cap still emit, but as informational events.
    pub max_correlation_risk_per_entity: u64,
}

impl Default for ProcessChainConfig {
    fn default() -> Self {
        Self {
            context: ProcessChainContext::default(),
            suppression_window: DEFAULT_SUPPRESSION_WINDOW,
            max_correlations_per_rule_entity: DEFAULT_MAX_CORRELATIONS_PER_RULE_ENTITY,
            max_correlation_risk_per_entity: DEFAULT_MAX_CORRELATION_RISK_PER_ENTITY,
        }
    }
}

// ---------------------------------------------------------------------------
// Observation extraction
// ---------------------------------------------------------------------------

/// Interpreters whose command line embeds another command line, with the flags
/// that introduce the nested payload.
const NESTED_INTERPRETERS: &[(&str, &[&str])] = &[
    ("cmd", &["/c", "/k", "/r"]),
    (
        "powershell",
        &["-c", "-command", "-comman", "-comm", "-com"],
    ),
    ("pwsh", &["-c", "-command"]),
    ("bash", &["-c"]),
    ("sh", &["-c"]),
    ("zsh", &["-c"]),
    ("wsl", &["-e", "--exec", "--"]),
];

/// Wrappers that prefix a real command without being the meaningful parent.
const TRANSPARENT_WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "time", "timeout", "start", "call", "exec", "nice", "stdbuf",
];

/// Binaries that only exist on Windows. Seeing one lets the extractor infer a
/// Windows shell as the parent when the source did not report a process tree.
const WINDOWS_ONLY_BINARIES: &[&str] = &[
    "arp",
    "atbroker",
    "bcdedit",
    "bitsadmin",
    "certutil",
    "cipher",
    "cmd",
    "cmstp",
    "copy",
    "cscript",
    "csc",
    "csvde",
    "diskshadow",
    "displayswitch",
    "dsget",
    "dsquery",
    "esentutl",
    "fltmc",
    "forfiles",
    "fsutil",
    "gpupdate",
    "hostname",
    "icacls",
    "installutil",
    "ipconfig",
    "klist",
    "ldifde",
    "magnify",
    "makecab",
    "mmc",
    "mpcmdrun",
    "msbuild",
    "msdt",
    "mshta",
    "msiexec",
    "narrator",
    "nbtstat",
    "net",
    "net1",
    "netsh",
    "netstat",
    "nltest",
    "ntdsutil",
    "osk",
    "pathping",
    "pcalua",
    "powershell",
    "procdump",
    "psexec",
    "qprocess",
    "reg",
    "regsvr32",
    "route",
    "rundll32",
    "sc",
    "schtasks",
    "sethc",
    "systeminfo",
    "tasklist",
    "taskkill",
    "tracert",
    "utilman",
    "vssadmin",
    "wbadmin",
    "wevtutil",
    "whoami",
    "wmic",
    "wscript",
    "xcopy",
    "xwizard",
];

/// Recovers the parent/child relationships a single command line describes.
///
/// Explicit relationships (`cmd /c whoami`) are reported with
/// `parent_inferred: false`. A statement with no visible interpreter gets an
/// inferred Windows shell only when the invoked binary is Windows-only or the
/// statement is unambiguously Windows-shaped; otherwise the parent is left
/// empty and only standalone indicators can match.
pub(crate) fn observations_from_command_line(command_line: &str) -> Vec<ProcessObservation> {
    let mut observations = Vec::new();
    collect_observations(command_line, None, 0, &mut observations);
    observations
}

fn collect_observations(
    command_line: &str,
    explicit_parent: Option<&str>,
    depth: usize,
    out: &mut Vec<ProcessObservation>,
) {
    if depth > 3 {
        return;
    }
    for statement in split_statements(command_line) {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        let tokens = tokenize(statement);
        let Some(binary_token) = first_meaningful_token(&tokens) else {
            continue;
        };
        let child = normalize_process_name(binary_token);
        if child.is_empty() {
            continue;
        }

        let (parent_name, inferred) = match explicit_parent {
            Some(parent) => (parent.to_string(), false),
            None => match infer_parent_shell(&child, statement) {
                Some(shell) => (shell.to_string(), true),
                None => (String::new(), true),
            },
        };

        let nested = nested_payload(&child, &tokens);

        // An interpreter that carries a payload is only a wrapper: the payload's
        // own statements describe the real children, and they repeat the same
        // text, so emitting the wrapper too would duplicate every command-line
        // indicator. An interpreter with no recoverable payload (an encoded
        // PowerShell command, for instance) still has to be reported.
        if nested.is_none() {
            out.push(ProcessObservation {
                parent: ProcessRef::named(parent_name),
                child: ProcessRef {
                    name: binary_token.to_string(),
                    path: binary_token
                        .contains(['\\', '/'])
                        .then(|| binary_token.to_string()),
                    pid: None,
                    command_line: Some(statement.to_string()),
                },
                parent_inferred: inferred,
                ..ProcessObservation::default()
            });
        }

        if let Some(nested) = nested {
            collect_observations(&nested, Some(&child), depth + 1, out);
        }
    }
}

fn first_meaningful_token(tokens: &[String]) -> Option<&str> {
    let mut index = 0;
    while index < tokens.len() {
        let candidate = tokens[index].as_str();
        // Skip `VAR=value` prefixes and transparent wrappers such as `sudo`.
        let normalized = normalize_process_name(candidate);
        if candidate.contains('=') && !candidate.contains(['\\', '/']) {
            index += 1;
            continue;
        }
        if TRANSPARENT_WRAPPERS.contains(&normalized.as_str()) {
            index += 1;
            continue;
        }
        // A leading `-flag` or a short `/c`-style switch is never the binary.
        if candidate.starts_with('-') || (candidate.starts_with('/') && candidate.len() <= 3) {
            index += 1;
            continue;
        }
        return Some(candidate);
    }
    None
}

fn nested_payload(binary: &str, tokens: &[String]) -> Option<String> {
    let flags = NESTED_INTERPRETERS
        .iter()
        .find(|(name, _)| *name == binary)
        .map(|(_, flags)| *flags)?;
    let position = tokens.iter().position(|token| {
        let lowered = token.to_ascii_lowercase();
        flags.contains(&lowered.as_str())
    })?;
    let payload = tokens
        .get(position + 1..)
        .map(|rest| rest.join(" "))
        .unwrap_or_default();
    (!payload.trim().is_empty()).then_some(payload)
}

fn infer_parent_shell(child: &str, statement: &str) -> Option<&'static str> {
    // A shell invoking itself is an artefact of inference, not an observation.
    if matches!(
        child,
        "cmd" | "powershell" | "pwsh" | "bash" | "sh" | "zsh" | "wsl"
    ) {
        return None;
    }
    if WINDOWS_ONLY_BINARIES.contains(&child) {
        return Some("cmd");
    }
    if statement_is_windows_shaped(statement) {
        return Some("cmd");
    }
    None
}

fn statement_is_windows_shaped(statement: &str) -> bool {
    let lowered = statement.to_ascii_lowercase();
    let has_env_var_reference = lowered.matches('%').count() >= 2 && !lowered.contains("http");
    lowered.contains(".exe") || lowered.contains(r":\") || has_env_var_reference
}

/// Splits a command line on statement and pipeline separators, ignoring
/// separators inside quotes.
fn split_statements(command_line: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = command_line.chars().peekable();

    while let Some(character) = chars.next() {
        match quote {
            Some(open) => {
                if character == open {
                    quote = None;
                } else {
                    current.push(character);
                    continue;
                }
                current.push(character);
            }
            None => match character {
                '"' | '\'' => {
                    quote = Some(character);
                    current.push(character);
                }
                '\n' | '\r' | ';' | '|' => {
                    // `&&`, `||`, and single `|` all end a statement.
                    if character == '|' && chars.peek() == Some(&'|') {
                        chars.next();
                    }
                    statements.push(std::mem::take(&mut current));
                }
                '&' => {
                    if chars.peek() == Some(&'&') {
                        chars.next();
                    }
                    statements.push(std::mem::take(&mut current));
                }
                _ => current.push(character),
            },
        }
    }
    statements.push(current);
    statements
        .into_iter()
        .filter(|statement| !statement.trim().is_empty())
        .collect()
}

/// Quote-aware whitespace tokenizer. Quotes are stripped from the token so that
/// `"C:\Program Files\7z.exe"` normalizes to `7z`.
fn tokenize(statement: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for character in statement.chars() {
        match quote {
            Some(open) if character == open => quote = None,
            Some(_) => current.push(character),
            None => match character {
                '"' | '\'' => quote = Some(character),
                character if character.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(character),
            },
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}
