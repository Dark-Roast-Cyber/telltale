//! The privacy sanitizer. Each `SanitizationContext` (evidence, summary,
//! diagnostic, URL, path and others) has its own rules; URLs, including
//! encoded and nested ones, are redacted with bounded decoding. Also owns the
//! controlled-marker checks that privacy tests use as their oracle.

use std::fmt;
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};

const MAX_INPUT_BYTES: usize = 4096;
const MAX_REDACTED_EVIDENCE_BYTES: usize = 512;
const MAX_DIAGNOSTIC_BYTES: usize = 200;
const MAX_PATH_BYTES: usize = 256;
const MAX_EVIDENCE_TOKENS: usize = 80;
/// Upper bound for the reusable serialized-event marker checker. Event payloads
/// are already bounded before persistence, so larger input is not safe to scan.
pub const MAX_SERIALIZED_EVENT_BYTES: usize = 1_048_576;
const TRUNCATED_SUFFIX: &str = "[truncated]";
const TRUNCATED_TAIL_MARKER: &str = "[truncated-tail]";
const REDACTED_SECRET: &str = "[redacted-secret]";
const REDACTED_URL: &str = "[redacted-url]";
const SENSITIVE_PATH: &str = "[sensitive-path]";
const DIAGNOSTIC_PATH: &str = "<path>";

static PRIVATE_KEY_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)-{5}\s*BEGIN\s+(?:(?:[A-Z0-9 ]+\s+)?PRIVATE\s+KEY|PGP\s+PRIVATE\s+KEY\s+BLOCK)\s*-{5}.*?(?:-{5}\s*END\s+(?:(?:[A-Z0-9 ]+\s+)?PRIVATE\s+KEY|PGP\s+PRIVATE\s+KEY\s+BLOCK)\s*-{5}|$)",
    )
    .expect("private key block regex")
});

static PRIVATE_KEY_END_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)-{5}\s*END\s+(?:(?:[A-Z0-9 ]+\s+)?PRIVATE\s+KEY|PGP\s+PRIVATE\s+KEY\s+BLOCK)\s*-{5}",
    )
    .expect("private key end regex")
});

static PRIVATE_KEY_PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b((RSA|OPENSSH|EC|DSA)\s+)?PRIVATE\s+KEY\b")
        .expect("private key phrase regex")
});

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b[a-z][a-z0-9+.-]*:)?//[^\s<>\"']+"#).expect("URL regex")
});

/// Windows device-namespace (`\\?\`, `\\.\`), NT object-namespace (`\Device\`,
/// `\??\`, `\GLOBAL??\`, `\DosDevices\`), UNC (`\\server\share`), drive
/// (`C:\`, `C:/`), and backslash home (`~\`) paths in plain, JSON-escaped, and
/// mixed-width separator forms.
///
/// Device and NT object branches precede UNC so shared starts with drive
/// colons or `{guid}` volume names match whole. NT object and UNC starts
/// require a token boundary (not a word character, closing bracket, or stray
/// backslash) so escaped registry keys such as `HKCU\\Software\\...` or COM
/// CLSID paths stay intact. Drive letters disallow a preceding letter so
/// PowerShell provider drives such as `HKLM:\` stay readable, while allowing
/// escaped `\n`, `\r`, or `\t` prefixes.
static WINDOWS_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    const PART_CHAR: &str = r#"[^\s\\/<>"'`,;()\[\]{}:&|]"#;
    const DEVICE_NAME_CHAR: &str = r#"[^\s\\/<>"'`,;()\[\]:&|]"#;
    const SEP: &str = r"(?:\\+|/)";
    const TOKEN_LEAD: &str = r"(?:^|[^\w.\-)}\]\\]|\\[nrt])";
    // Directories may hold spaces; the last component may not.
    let tail = format!(r"(?:{PART_CHAR}+(?:\s+{PART_CHAR}+)*{SEP})*{PART_CHAR}+");
    // Match the same preceding text as UNC before choosing this alternative;
    // otherwise UNC can win earlier and stop at the device drive's colon.
    let win32_device = format!(
        r"(?P<win32_lead>\\[nrt]|[^\\])?\\{{2,}}[?.]{SEP}(?:[A-Z]:{PART_CHAR}*|{DEVICE_NAME_CHAR}+)(?:{SEP}{tail})?"
    );
    // NT redirector paths can carry logon-ID prefix segments (`\;Z:0001\server\share`).
    let nt_object = format!(
        r"(?P<nt_lead>{TOKEN_LEAD})\\+(?:Device|GLOBAL\?\?|\?\?|DosDevices){SEP}(?:[A-Z]:{PART_CHAR}*|{DEVICE_NAME_CHAR}+)(?:{SEP};[A-Za-z0-9._:-]+)*(?:{SEP}{tail})?"
    );
    let unc = format!(
        r"(?P<unc_lead>{TOKEN_LEAD})(?P<unc_start>\\{{2,}})(?P<unc_server>{PART_CHAR}+)(?P<unc_sep>\\+){tail}"
    );
    let drive = format!(r"(?P<drive_lead>^|[^A-Z]|\\[nrt])[A-Z]:{SEP}{tail}");
    let home = format!(r"(?P<home_lead>^|[^A-Za-z0-9_~\\]|\\[nrt])~\\+{tail}");
    Regex::new(&format!(
        r"(?i){win32_device}|{nt_object}|{unc}|{drive}|{home}"
    ))
    .expect("Windows path regex")
});

static POSIX_PRIVATE_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?P<prefix>^|[^A-Z0-9_~/])(?:/|~[/\\])(?:[^\s/<>\"'`,;()\[\]{}:&|]+(?:\s+[^\s/<>\"'`,;()\[\]{}:&|]+)*/)*[^\s/<>\"'`,;()\[\]{}:&|]+"#,
    )
        .expect("POSIX private path regex")
});

static CREDENTIAL_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:(?:[A-Z]:\\|\\\\|/|~[/\\])[^\s<>\"'`,;()\[\]{}:&|]*[/\\])?(?:\.npmrc|\.netrc|credentials|id_(?:rsa|dsa|ecdsa|ed25519)|\.(?:pem|p12|pfx|key)|[^\s<>\"'`,;()\[\]{}:&|]+\.(?:pem|p12|pfx|key))"#,
    )
    .expect("credential path regex")
});

static DOT_ENV_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?P<path>(?:(?:[A-Z]:\\|\\\\|/|~[/\\])[^\s<>\"'`,;()\[\]{}:&|]*[/\\])?\.env(?:\.(?:local|development|production|test|staging))?)(?P<boundary>$|[^A-Z0-9_.-])"#,
    )
    .expect(".env path regex")
});

static SENSITIVE_LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:api\s+(?:key|token)|credentials?)\b").expect("sensitive label regex")
});

static PACKAGE_MANAGER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(npm|pnpm|yarn|bun|pip|pipx|uv|cargo|go|brew|apt|apt-get|dnf|yum)\b\s+(install|add|i|get|run|create|x)(\s+\S+)?",
    )
    .expect("package manager regex")
});

static STARTUP_TARGET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(~/)?\.(bashrc|zshrc|profile|bash_profile)\b|config/fish/config\.fish|crontab")
        .expect("startup target regex")
});

static ENCODED_DECODER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bbase64\s+(-d|--decode)\b").expect("encoded decoder regex"));

static CREDENTIAL_GH_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bgh[pousr]_[A-Za-z0-9_-]{16,}\b").expect("credential regex")
});

static CREDENTIAL_SK_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bsk-[A-Za-z0-9_-]{16,}\b").expect("credential regex"));

static CREDENTIAL_AKIA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bAKIA[0-9A-Z]{16}\b").expect("credential regex"));

static CREDENTIAL_XOX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bxox[abcdeprs]-[A-Za-z0-9-]{20,}\b").expect("credential regex")
});

/// Vendor tokens the encoded-blob rule cannot reach: a `_` before the body
/// leaves no word boundary to start at, and a `-` or `_` inside the body ends
/// the run early. Each alternative is a documented vendor prefix followed by
/// a body too long to be an identifier that merely starts the same way
/// (`npm_config_registry`, `hf_hub_download`, `github_pat_rotation_policy`).
static CREDENTIAL_VENDOR_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:",
        // GitLab: every documented token prefix.
        r"gl(?:pat|oas|dt|rtr?|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{20,}",
        // GitHub fine-grained personal access token.
        r"|github_pat_[A-Za-z0-9]{20,}[A-Za-z0-9_]*",
        // Hugging Face and npm access tokens.
        r"|(?:hf|npm)_[A-Za-z0-9]{30,}",
        r")\b",
    ))
    .expect("credential regex")
});

static CREDENTIAL_JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
        .expect("credential regex")
});

static CREDENTIAL_BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=:-]{8,}(?:=+|\b)")
        .expect("credential regex")
});

static ENCODED_BLOB_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b").expect("encoded blob regex"));

static HIGH_CONFIDENCE_GH_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)ghp_[A-Za-z0-9]{8,}").expect("credential marker regex"));

static HIGH_CONFIDENCE_SK_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)sk-[A-Za-z0-9]{8,}").expect("credential marker regex"));

static HIGH_CONFIDENCE_AKIA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)AKIA[A-Z0-9]{12,}").expect("credential marker regex"));

static HIGH_CONFIDENCE_XOX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)xox[baprs]-[A-Za-z0-9-]{8,}").expect("credential marker regex")
});

static HIGH_CONFIDENCE_JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
        .expect("credential marker regex")
});

static HIGH_CONFIDENCE_PRIVATE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)-{5}BEGIN [A-Z0-9 ]+ PRIVATE KEY-{5}").expect("credential marker regex")
});

/// The contract for text leaving an Event 3.0 construction or diagnostic path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizationContext {
    Evidence,
    Diagnostic,
    Url,
    Path,
    CommandResult,
    Summary,
    Metadata,
}

/// Deterministic, local-only sanitization for emitted text.
pub struct PrivacySanitizer;

impl PrivacySanitizer {
    pub fn sanitize(context: SanitizationContext, text: &str) -> String {
        Self::try_sanitize(
            context,
            text,
            &mut |_| Ok::<_, std::convert::Infallible>(()),
        )
        .expect("infallible privacy charge")
    }

    /// Budget-aware evidence sanitization. Composite scanners reserve conservative
    /// byte visits before entering their bounded decode/assignment passes; simple
    /// replacement passes charge their current input independently.
    pub fn try_sanitize<E>(
        context: SanitizationContext,
        text: &str,
        charge: &mut impl FnMut(usize) -> Result<(), E>,
    ) -> Result<String, E> {
        charge(text.len().min(MAX_INPUT_BYTES))?;
        let bounded = bounded_input(text);
        charge(bounded.text.len())?;
        let redacted = if bounded.was_truncated {
            neutralize_truncated_tail(&bounded.text)
        } else {
            bounded.text
        };
        let redacted = redact_bounded(context, redacted, charge)?;

        charge(redacted.len())?;
        let normalized = if context == SanitizationContext::CommandResult {
            redacted
        } else {
            redacted
                .split_whitespace()
                .take(MAX_EVIDENCE_TOKENS)
                .collect::<Vec<_>>()
                .join(" ")
        };
        charge(normalized.len())?;
        Ok(truncate_utf8_bytes(
            &normalized,
            max_output_bytes(context),
            TRUNCATED_SUFFIX,
        ))
    }
}

/// Every pattern pass, in order, over text already within the input bound.
fn redact_bounded<E>(
    context: SanitizationContext,
    mut redacted: String,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    charge(redacted.len())?;
    let encoded_reservation = if has_percent_escape(&redacted) {
        redacted
            .len()
            .saturating_mul(redacted.len().max(1))
            .saturating_mul(4)
    } else {
        redacted.len().saturating_mul(4)
    };
    charge(encoded_reservation)?;
    redacted = redact_encoded_url_candidates(&redacted, charge)?;
    redacted = redact_urls_at_depth(&redacted, 0, charge)?;
    charge(redacted.len())?;
    redacted = PRIVATE_KEY_BLOCK_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    redacted = redact_assignments(&redacted, true, charge)?;
    charge(redacted.len())?;
    redacted = redacted.replace(
        "https://darkroastcyber.io/mcp-lab",
        "https://darkroastcyber.io/[redacted]",
    );
    charge(redacted.len())?;
    redacted = redacted.replace("darkroastcyber.io", "[controlled-domain]");
    charge(redacted.len().saturating_mul(4))?;
    redacted = redact_sensitive_labels(&redacted);
    charge(redacted.len())?;
    redacted = PACKAGE_MANAGER_RE
        .replace_all(&redacted, "[package-manager-command]")
        .into_owned();
    charge(redacted.len())?;
    redacted = STARTUP_TARGET_RE
        .replace_all(&redacted, "[startup-target]")
        .into_owned();
    charge(redacted.len())?;
    redacted = ENCODED_DECODER_RE
        .replace_all(&redacted, "[encoded-decoder]")
        .into_owned();
    charge(redacted.len().saturating_mul(16))?;
    redacted = redact_paths(&redacted, path_marker(context));
    if context == SanitizationContext::Diagnostic {
        charge(redacted.len())?;
        redacted = redacted.replace(SENSITIVE_PATH, DIAGNOSTIC_PATH);
    }
    charge(redacted.len())?;
    redacted = PRIVATE_KEY_PHRASE_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = CREDENTIAL_GH_TOKEN_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = CREDENTIAL_SK_KEY_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = CREDENTIAL_AKIA_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = CREDENTIAL_XOX_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = CREDENTIAL_VENDOR_TOKEN_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = CREDENTIAL_JWT_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = CREDENTIAL_BEARER_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = HIGH_CONFIDENCE_GH_TOKEN_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = HIGH_CONFIDENCE_SK_KEY_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = HIGH_CONFIDENCE_AKIA_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = HIGH_CONFIDENCE_XOX_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = HIGH_CONFIDENCE_JWT_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len())?;
    redacted = HIGH_CONFIDENCE_PRIVATE_KEY_RE
        .replace_all(&redacted, REDACTED_SECRET)
        .into_owned();
    charge(redacted.len().saturating_mul(4))?;
    redacted = redact_encoded_blobs_outside_urls(&redacted);
    Ok(redacted)
}

/// Compatibility wrapper for existing evidence callers.
pub fn redact_sensitive_text(text: &str) -> String {
    PrivacySanitizer::sanitize(SanitizationContext::Evidence, text)
}

/// Input processed by [`redact_multiline_bounded`]; longer text is cut with
/// the fail-closed rule and reported as truncated.
const MAX_MULTILINE_INPUT_BYTES: usize = 256 * 1024;
/// Newline cuts tried per chunk before the chunk fails closed.
const MAX_CUT_PROBES: usize = 64;
/// Bytes the path guard may scan past a cut before treating it as unsafe.
const MAX_CUT_PATH_SCAN_BYTES: usize = 4096;
/// Re-redaction rounds allowed to reach a fixed point.
const MAX_MULTILINE_FIXED_POINT_ROUNDS: usize = 4;

/// Words whose presence at the end of a line lets a later pass continue
/// across the following newline: secret keys and flags (the assignment
/// scanner skips newlines between key, separator and value), the label,
/// bearer, private-key-phrase and decoder patterns (`\s+` between words), and
/// package-manager names (`\s+` before the subcommand).
const CUT_GUARD_WORDS: [&str; 22] = [
    "basic", "private", "rsa", "openssh", "ec", "dsa", "api", "base64", "npm", "pnpm", "yarn",
    "bun", "pip", "pipx", "uv", "cargo", "go", "brew", "apt", "aptget", "dnf", "yum",
];
const PACKAGE_MANAGER_WORDS: [&str; 14] = [
    "npm", "pnpm", "yarn", "bun", "pip", "pipx", "uv", "cargo", "go", "brew", "apt", "aptget",
    "dnf", "yum",
];
const PACKAGE_MANAGER_SUBCOMMANDS: [&str; 7] = ["install", "add", "i", "get", "run", "create", "x"];
/// Attempts to back a fitted cut off to an earlier word boundary.
const MAX_FIT_ATTEMPTS: usize = 64;

/// The guard word lists as case-insensitive suffix patterns. The passes they
/// mirror match their words with the same engine and `(?i)` (Unicode simple
/// case folding, so `ſ` is `s` and `K` (Kelvin) is `k`), so a guard built from
/// the same list accepts every spelling its pass accepts.
static CUT_GUARD_WORD_RE: LazyLock<Regex> = LazyLock::new(|| word_suffix_regex(&CUT_GUARD_WORDS));
static SECRET_KEY_WORD_RE: LazyLock<Regex> = LazyLock::new(|| word_suffix_regex(&SECRET_KEY_WORDS));
static PACKAGE_MANAGER_WORD_RE: LazyLock<Regex> =
    LazyLock::new(|| word_suffix_regex(&PACKAGE_MANAGER_WORDS));
static PACKAGE_MANAGER_SUBCOMMAND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)\A(?:{})\z",
        PACKAGE_MANAGER_SUBCOMMANDS.join("|")
    ))
    .expect("package manager subcommand regex")
});

fn word_suffix_regex(words: &[&str]) -> Regex {
    Regex::new(&format!(r"(?i)(?:{})\z", words.join("|"))).expect("guard word regex")
}

/// Multi-line redaction for transcript records, which may exceed the
/// single-call input bound. Line breaks are kept, other whitespace runs in a
/// line collapse to one space, and the result is cut to `max_output_bytes`
/// (at most [`MAX_INPUT_BYTES`]). Returns the text and whether anything was
/// withheld.
///
/// Text that fits one sanitizer call is redacted by that one call, so it
/// hides everything the single call hides. Longer text is redacted in chunks.
/// Soundness argument for the chunking:
///
/// 1. The URL passes run on each line first, then private key blocks are
///    removed from the whole bounded, URL-passed input, so no armor or body is
///    left to straddle a cut. This is the order of one sanitizer call (URL
///    passes, then the block pass), so the block pass replaces what it would
///    in that call (plus blocks that span a cut) and never hides URL text
///    from the URL passes.
/// 2. Chunks end only at a newline, which is dropped and re-joined. The
///    URL passes never cross a newline, so the text every later pass reads
///    (`U`) is the line-wise join of each line's URL-pass output, and a chunk
///    redacts to its part of the whole when no later pattern match spans the
///    newline. Every anchor (`^`, `$`, `\b`, the path lead and boundary
///    classes, the encoded-candidate boundary) treats start or end of text
///    like a newline.
/// 3. A newline is cut only when, read on `U`, nothing can span it. Every
///    construct that can is listed here with the condition that rules it
///    out:
///    - Assignment keys, separators and values joined by whitespace
///      (`skip_assignment_whitespace` crosses newlines), flags, quoted and
///      escape-decoded keys: the text before the newline must not end in a
///      possible secret key (a key-character run ending in a secret word, a
///      quote, or a token holding `\`), nor in `=`/`:` after one.
///    - Block scalar continuation (indented or empty lines, including
///      escape-decoded indentation): the next line must start with a
///      character that is neither whitespace nor `\`.
///    - The label, bearer, private-key-phrase, decoder and package-manager
///      patterns (`\s+` between fixed words, and `(\s+\S+)?` after a
///      subcommand): the line must not end in one of [`CUT_GUARD_WORDS`] or
///      in a package-manager subcommand after a package-manager word.
///      Words are compared by regexes built from the same lists with the
///      passes' `(?i)` folding, over runs of Unicode letters and digits.
///    - Private key blocks decoded from encoded URLs (`\s` in the armor,
///      `.*?` to the end): no block may be open at the cut and no partial
///      armor may end the line.
///    - Windows and POSIX directory components joined by whitespace: one
///      side of the newline is a character no component holds, or no `/`
///      or `\` lies between the chunk start and the cut without such a
///      character in between, or none follows the cut before one.
///
///    Token, URL, path-file and blob patterns hold no whitespace.
/// 4. Later passes cannot create a join: replacements end in `]` or keep
///    their last character, and markers hold no path separator.
/// 5. With no safe newline within the chunk bound, and at the input bound,
///    the text fails closed: the cut fragment (quote aware) is dropped, then
///    everything from the first `/`, `\` or `%` in the trailing run without
///    a path-stopping character (with a drive letter and colon before it),
///    so no visible text depends on what was cut.
///
/// The joined text is kept to one sanitizer call by dropping trailing chunks
/// at their joins, re-redacted until it is a fixed point, and only then cut
/// to `max_output_bytes`: a cut backs off to an earlier word
/// boundary until the result is itself a fixed point. A prefix of fully
/// redacted text shows nothing the full text hides. Below 11 bytes a cut
/// record is empty; below 13 it shows only `[truncated]`.
#[doc(hidden)]
pub fn redact_multiline_bounded(text: &str, max_output_bytes: usize) -> (String, bool) {
    redact_multiline_with_limits(
        text,
        max_output_bytes,
        MAX_INPUT_BYTES,
        MAX_MULTILINE_INPUT_BYTES,
    )
}

fn redact_multiline_with_limits(
    text: &str,
    max_output_bytes: usize,
    chunk_limit: usize,
    input_limit: usize,
) -> (String, bool) {
    let max_output_bytes = max_output_bytes.min(MAX_INPUT_BYTES);
    if max_output_bytes == 0 {
        return (String::new(), !text.is_empty());
    }
    let (normalized, over) = normalize_newlines_bounded(text, input_limit);
    let mut truncated = over;
    let bounded = if over {
        fail_closed_prefix(&normalized[..floor_char_boundary(&normalized, input_limit)])
    } else {
        normalized.as_str()
    };

    let mut body = String::new();
    // Offsets in `body` of the newlines that join chunks: verified safe cuts.
    let mut joins = Vec::new();
    if bounded.len() <= chunk_limit {
        // One sanitizer call: exactly what the single call hides.
        body = redact_multiline_chunk(bounded);
    } else {
        let url_passed = bounded
            .split('\n')
            .map(url_pass_line)
            .collect::<Vec<_>>()
            .join("\n");
        let source = PRIVATE_KEY_BLOCK_RE.replace_all(&url_passed, REDACTED_SECRET);
        let mut lines = MultilineSource::new(&source, chunk_limit);
        let mut first = 0;
        while first < lines.len() {
            if first > 0 {
                joins.push(body.len());
                body.push('\n');
            }
            match lines.next_chunk(first) {
                MultilineChunk::Rest => {
                    body.push_str(&redact_multiline_chunk(lines.raw(first, lines.len() - 1)));
                    break;
                }
                MultilineChunk::Cut(last) => {
                    body.push_str(&redact_multiline_chunk(lines.raw(first, last)));
                    first = last + 1;
                    if body.len() > max_output_bytes {
                        truncated = true;
                        break;
                    }
                }
                MultilineChunk::FailClosed(window) => {
                    body.push_str(&redact_multiline_chunk(fail_closed_prefix(window)));
                    truncated = true;
                    break;
                }
            }
        }
    }

    // Keep at most one sanitizer call of joined text: drop trailing chunks at
    // their joins, which are safe cuts. A single chunk that redaction grew
    // past the bound is cut at a word boundary: a prefix of a complete
    // redaction shows only what it shows.
    let mut text = body;
    while text.len() > MAX_INPUT_BYTES
        && let Some(join) = joins.pop()
    {
        text.truncate(join);
        truncated = true;
    }
    if text.len() > MAX_INPUT_BYTES {
        let end = word_boundary_at_or_before(&text, MAX_INPUT_BYTES);
        text.truncate(end);
        truncated = true;
    }
    redact_then_fit(text, truncated, max_output_bytes)
}

/// Redact joined text to a fixed point before anything is cut to fit, so a
/// cut never falls inside a match that only the whole text completes.
fn redact_then_fit(mut text: String, truncated: bool, maximum: usize) -> (String, bool) {
    for _ in 0..MAX_MULTILINE_FIXED_POINT_ROUNDS {
        let again = redact_multiline_chunk(&text);
        if again == text {
            return fit_multiline(&text, truncated, maximum);
        }
        text = again;
    }
    // No fixed point within the bound: withhold the text.
    (withheld(maximum), true)
}

/// Newlines normalized to `\n`, stopping once the output passes `limit`
/// bytes, so the work is bounded by the input cap. A `\r\n` that straddles
/// the cap is read whole. Returns whether text was left out.
fn normalize_newlines_bounded(text: &str, limit: usize) -> (String, bool) {
    let mut out = String::with_capacity(text.len().min(limit.saturating_add(4)));
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if out.len() > limit {
            return (out, true);
        }
        if character == '\r' {
            characters.next_if_eq(&'\n');
            out.push('\n');
        } else {
            out.push(character);
        }
    }
    let over = out.len() > limit;
    (out, over)
}

/// One sanitizer call over a chunk within the input bound, then the
/// transcript whitespace rule.
fn redact_multiline_chunk(chunk: &str) -> String {
    let redacted = redact_bounded(SanitizationContext::Evidence, chunk.to_owned(), &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .unwrap_or_else(|never| match never {});
    collapse_intraline_whitespace(&redacted)
}

/// The URL passes of [`redact_bounded`], which every later pass reads.
fn url_pass_line(line: &str) -> String {
    let mut charge = |_: usize| Ok::<_, std::convert::Infallible>(());
    let decoded =
        redact_encoded_url_candidates(line, &mut charge).unwrap_or_else(|never| match never {});
    redact_urls_at_depth(&decoded, 0, &mut charge).unwrap_or_else(|never| match never {})
}

fn collapse_intraline_whitespace(text: &str) -> String {
    text.split('\n')
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Cut fully redacted text to `maximum`, never through a marker, and mark a
/// cut or earlier truncation with the truncation suffix. A cut that is not a
/// fixed point of the sanitizer (the suffix completes a pattern) backs off to
/// the previous word boundary; with nothing left, only the suffix remains.
fn fit_multiline(text: &str, truncated: bool, maximum: usize) -> (String, bool) {
    if !truncated && text.len() <= maximum {
        return (text.to_owned(), false);
    }
    let suffix_room = TRUNCATED_SUFFIX.len() + 1;
    let mut end = if text.len() + suffix_room <= maximum {
        text.len()
    } else if maximum > suffix_room {
        floor_char_boundary(text, maximum - suffix_room)
    } else {
        0
    };
    for _ in 0..MAX_FIT_ATTEMPTS {
        end = before_open_marker(text, end);
        let kept = text[..end].trim_end();
        if kept.is_empty() {
            break;
        }
        let fitted = format!("{kept} {TRUNCATED_SUFFIX}");
        if redact_multiline_chunk(&fitted) == fitted {
            return (fitted, true);
        }
        end = previous_word_boundary(text, end);
    }
    (withheld(maximum), true)
}

/// The truncation suffix alone, or nothing when even that does not fit.
fn withheld(maximum: usize) -> String {
    if maximum >= TRUNCATED_SUFFIX.len() {
        TRUNCATED_SUFFIX.to_owned()
    } else {
        String::new()
    }
}

/// The largest offset below `end` that is not inside a run of letters and
/// digits.
fn previous_word_boundary(text: &str, end: usize) -> usize {
    let mut characters = text[..end].char_indices().rev().peekable();
    let Some((mut at, mut current)) = characters.next() else {
        return 0;
    };
    for (offset, previous) in characters {
        if !(previous.is_alphanumeric() && current.is_alphanumeric()) {
            break;
        }
        at = offset;
        current = previous;
    }
    at
}

/// `end`, or the start of the replacement marker (`[...]`) it falls inside.
fn before_open_marker(text: &str, end: usize) -> usize {
    match text[..end].rfind('[') {
        Some(open) if !text[open..end].contains(']') && text[open..].contains(']') => open,
        _ => end,
    }
}

/// The largest word boundary at or before `limit`, outside a marker.
fn word_boundary_at_or_before(text: &str, limit: usize) -> usize {
    let end = floor_char_boundary(text, limit);
    if end >= text.len() {
        return text.len();
    }
    let end = before_open_marker(text, end);
    let inside = text[..end]
        .chars()
        .next_back()
        .is_some_and(char::is_alphanumeric)
        && text[end..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric);
    if inside {
        previous_word_boundary(text, end)
    } else {
        end
    }
}

/// Keep only text whose redaction cannot depend on what follows `window`:
/// drop the fragment the cut falls in (quote aware), then everything from
/// the first `/`, `\` or `%` in the trailing run that holds no character a
/// path component excludes. A path or encoded URL that could continue past
/// the cut therefore never shows a component.
fn fail_closed_prefix(window: &str) -> &str {
    let mut end = truncated_fragment_start(window).unwrap_or(window.len());
    let run_start = window[..end]
        .char_indices()
        .rev()
        .find(|(_, character)| is_path_stop(*character))
        .map_or(0, |(offset, character)| offset + character.len_utf8());
    if let Some(offset) = window[run_start..end].find(['/', '\\', '%']) {
        end = run_start + offset;
        // A drive (`C:`) before the separator belongs to the path.
        let mut tail = window[..end].chars().rev();
        if tail.next() == Some(':') && tail.next().is_some_and(char::is_alphabetic) {
            end = window[..end - 1]
                .char_indices()
                .next_back()
                .map_or(0, |(offset, _)| offset);
        }
    }
    &window[..end]
}

/// A character excluded from every Windows and POSIX path component, other
/// than whitespace and separators.
fn is_path_stop(character: char) -> bool {
    matches!(
        character,
        '<' | '>'
            | '"'
            | '\''
            | '`'
            | ','
            | ';'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | ':'
            | '&'
            | '|'
    )
}

enum MultilineChunk<'a> {
    /// The rest of the text fits one chunk.
    Rest,
    /// Cut after this line.
    Cut(usize),
    /// No safe cut within the bound: fail closed on this window.
    FailClosed(&'a str),
}

struct MultilineSource<'a> {
    text: &'a str,
    /// Byte ranges of the lines, without their newlines.
    lines: Vec<(usize, usize)>,
    /// URL-pass output per line, computed on demand; `None` for a line
    /// longer than a chunk, which is never read.
    url_passed: Vec<Option<Option<String>>>,
    chunk_limit: usize,
}

impl<'a> MultilineSource<'a> {
    fn new(text: &'a str, chunk_limit: usize) -> Self {
        let mut lines = Vec::new();
        let mut start = 0;
        for (offset, _) in text.match_indices('\n') {
            lines.push((start, offset));
            start = offset + 1;
        }
        lines.push((start, text.len()));
        let url_passed = vec![None; lines.len()];
        Self {
            text,
            lines,
            url_passed,
            chunk_limit: chunk_limit.max(1),
        }
    }

    fn len(&self) -> usize {
        self.lines.len()
    }

    fn raw(&self, first: usize, last: usize) -> &'a str {
        &self.text[self.lines[first].0..self.lines[last].1]
    }

    fn url_passed(&mut self, line: usize) -> Option<&str> {
        if self.url_passed[line].is_none() {
            let (start, end) = self.lines[line];
            let passed =
                (end - start <= self.chunk_limit).then(|| url_pass_line(&self.text[start..end]));
            self.url_passed[line] = Some(passed);
        }
        self.url_passed[line]
            .as_ref()
            .and_then(|passed| passed.as_deref())
    }

    fn next_chunk(&mut self, first: usize) -> MultilineChunk<'a> {
        let base = self.lines[first].0;
        if self.text.len() - base <= self.chunk_limit {
            return MultilineChunk::Rest;
        }
        let window = &self.text[base..floor_char_boundary(self.text, base + self.chunk_limit)];
        let last_fitting = (first..self.lines.len() - 1)
            .take_while(|line| self.lines[*line].1 - base <= self.chunk_limit)
            .last();
        let Some(last_fitting) = last_fitting else {
            return MultilineChunk::FailClosed(window);
        };
        let mut left = String::new();
        let mut left_ends = Vec::with_capacity(last_fitting + 1 - first);
        for line in first..=last_fitting {
            if line > first {
                left.push('\n');
            }
            let passed = self
                .url_passed(line)
                .expect("a line inside a chunk is URL-passed");
            left.push_str(passed);
            left_ends.push(left.len());
        }
        for line in (first..=last_fitting).rev().take(MAX_CUT_PROBES) {
            if self.cut_is_safe(&left[..left_ends[line - first]], line + 1) {
                return MultilineChunk::Cut(line);
            }
        }
        MultilineChunk::FailClosed(window)
    }

    /// Whether no later pass can match across the newline before `next`,
    /// given `left`, the URL-pass output from the chunk start to it.
    fn cut_is_safe(&mut self, left: &str, next: usize) -> bool {
        let Some(first_next) = self.url_passed(next).and_then(|line| line.chars().next()) else {
            return false;
        };
        // Block scalars continue over indented and empty lines; `\` may
        // decode to indentation.
        if first_next.is_whitespace() || first_next == '\\' {
            return false;
        }
        let trimmed = left.trim_end();
        let Some(last) = trimmed.chars().next_back() else {
            return true;
        };
        if may_end_secret_key(trimmed) {
            return false;
        }
        if matches!(last, '=' | ':') && may_end_secret_key(&trimmed[..trimmed.len() - 1]) {
            return false;
        }
        let mut tokens = trimmed.split_whitespace().rev();
        if let (Some(subcommand), Some(manager)) = (tokens.next(), tokens.next())
            && PACKAGE_MANAGER_SUBCOMMAND_RE.is_match(subcommand)
            && ends_with_guard_word(manager, &PACKAGE_MANAGER_WORD_RE)
        {
            return false;
        }
        if left.contains("-----") {
            if PRIVATE_KEY_BLOCK_RE
                .find_iter(left)
                .any(|block| block.end() == left.len())
            {
                return false;
            }
            // Every letter and digit, as the armor's `(?i)[A-Z0-9 ]` folds.
            let before_armor_words = trimmed.trim_end_matches(|character: char| {
                character.is_alphanumeric() || character.is_whitespace()
            });
            if before_armor_words.ends_with("-----") {
                return false;
            }
        }
        self.path_cannot_span(left, last, first_next, next)
    }

    /// A directory component joined over whitespace needs component
    /// characters on both sides of the newline, a separator between the
    /// chunk start and the newline, and one after it, with no character in
    /// between that a component excludes.
    fn path_cannot_span(&mut self, left: &str, last: char, first_next: char, next: usize) -> bool {
        if is_path_stop(last) || last == '/' || is_path_stop(first_next) || first_next == '/' {
            return true;
        }
        let separator_before = left
            .chars()
            .rev()
            .find(|character| is_path_stop(*character) || matches!(character, '/' | '\\'))
            .is_some_and(|character| matches!(character, '/' | '\\'));
        if !separator_before {
            return true;
        }
        let mut scanned = 0;
        for line in next..self.lines.len() {
            let Some(passed) = self.url_passed(line) else {
                return false;
            };
            for character in passed.chars() {
                if matches!(character, '/' | '\\') {
                    return false;
                }
                if is_path_stop(character) {
                    return true;
                }
            }
            scanned += passed.len() + 1;
            if scanned > MAX_CUT_PATH_SCAN_BYTES {
                return false;
            }
        }
        true
    }
}

/// Whether `text` may end in a key the assignment scanner treats as secret,
/// or a word the cross-line patterns continue from: a quote (a quoted key),
/// a final token holding `\` (escape-decoded syntax), or a key-character run
/// whose letters and digits end in a secret or guard word. Keys may start
/// anywhere in the run, so a suffix match is enough.
fn may_end_secret_key(text: &str) -> bool {
    let text = text.trim_end();
    let Some(last) = text.chars().next_back() else {
        return false;
    };
    if matches!(last, '"' | '\'') {
        return true;
    }
    // Split at ASCII whitespace only: a token at least as long as the one
    // any pass reads.
    let token_start = text
        .char_indices()
        .rev()
        .find(|(_, character)| character.is_ascii_whitespace())
        .map_or(0, |(offset, character)| offset + character.len_utf8());
    if text[token_start..].contains('\\') {
        return true;
    }
    ends_with_guard_word(text, &SECRET_KEY_WORD_RE)
        || ends_with_guard_word(text, &CUT_GUARD_WORD_RE)
}

/// Whether the letters and digits (any script) of the trailing key-character
/// run of `text` end in a word of `words`, a suffix pattern built by
/// [`word_suffix_regex`] that folds case as the passes do.
fn ends_with_guard_word(text: &str, words: &Regex) -> bool {
    let mut run = text
        .chars()
        .rev()
        .take_while(|character| character.is_alphanumeric() || matches!(character, '_' | '.' | '-'))
        .filter(|character| character.is_alphanumeric())
        .collect::<Vec<_>>();
    run.reverse();
    words.is_match(&run.into_iter().collect::<String>())
}

/// Evidence bytes shown before and after a hit when a field does not fit.
const EXCERPT_BEFORE_BYTES: usize = 160;
const EXCERPT_AFTER_BYTES: usize = 240;
/// Raw bytes kept before the hit when a field exceeds the input bound. The
/// rest of the bound follows the hit, so both raw cuts stay far outside the
/// displayed excerpt.
const EXCERPT_REGION_BEFORE_BYTES: usize = 1536;
/// Text after a leading cut that is redacted but never shown: at least this
/// many bytes, in whole fragments, and at least `LEADING_GUARD_FRAGMENTS`.
/// A label the sanitizer reads across whitespace (`--password value`,
/// `key = value`, `Bearer token`, a path with spaces) may sit before the cut
/// while its value follows it.
const LEADING_GUARD_BYTES: usize = 256;
const LEADING_GUARD_FRAGMENTS: usize = 3;
/// Raw text before a leading cut, on the cut's line, read for labels whose
/// value runs past the cut.
const LEADING_LINE_SCAN_BYTES: usize = 16 * 1024;
/// What could open such a value in a line's unscanned start: an escape, or an
/// authorization word.
static UNSCANNED_LINE_VALUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\\|auth|bearer").expect("unscanned line value regex"));

/// Redacted evidence that locates one hit in its field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceExcerpt {
    /// The field whole when its redaction fits the evidence bounds, otherwise
    /// a window around the hit. Always a fixed point of
    /// [`redact_sensitive_text`].
    pub text: String,
    /// Byte range of the hit in `text`, set only when that position is exact.
    pub highlight: Option<Range<usize>>,
    /// Field text was cut before the excerpt.
    pub elided_before: bool,
    /// Field text was cut after the excerpt.
    pub elided_after: bool,
}

impl PrivacySanitizer {
    /// Evidence for the hit at byte range `hit` of `text`, in the evidence
    /// context and bounds.
    ///
    /// A field longer than the input bound is sanitized as a raw region
    /// around the hit. Both raw cuts are neutralized with the fragment rule
    /// the input bound uses: the fragment holding a cut, including a quoted
    /// value that spans it, is dropped, so a secret that straddles a cut is
    /// never partly shown. A leading cut inside a private key block moves past
    /// the block's end, and past an authorization or quoted value whose label
    /// is earlier on the cut's line. The text just after a leading cut is
    /// redacted but not shown, since the label that would mask it may lie
    /// before the cut. The excerpt is then cut from the region's redaction.
    /// The highlight is set only when redacting the text before, at and after
    /// the hit separately reproduces the region's redaction, so it never
    /// points at a guessed position; a hit that redaction merges with its
    /// neighbors, or that a dropped fragment holds, gets `None`.
    pub fn try_sanitize_excerpt<E>(
        text: &str,
        hit: Option<Range<usize>>,
        charge: &mut impl FnMut(usize) -> Result<(), E>,
    ) -> Result<EvidenceExcerpt, E> {
        let hit = hit.filter(|hit| {
            hit.start < hit.end
                && hit.end <= text.len()
                && text.is_char_boundary(hit.start)
                && text.is_char_boundary(hit.end)
        });
        let (mut start, mut end) = (0, text.len());
        if text.len() > MAX_INPUT_BYTES {
            let anchor = hit.as_ref().map_or(0, |hit| hit.start);
            start = floor_char_boundary(text, anchor.saturating_sub(EXCERPT_REGION_BEFORE_BYTES));
            end = floor_char_boundary(text, start + MAX_INPUT_BYTES);
            if start > 0 {
                start = neutralize_leading_cut(text, start, end, charge)?;
                start = skip_open_private_key_block(text, start, end, charge)?;
                start = skip_open_line_value(text, start, end, charge)?;
            }
            if end < text.len() {
                end = neutralize_trailing_cut(text, start, end, charge)?;
            }
        }
        let region = &text[start..end];
        charge(region.len())?;
        let redacted = redact_region(region, charge)?;

        // The hit in the region's redaction: exact, or an anchor for placement.
        let (highlight, anchor) = match &hit {
            Some(hit) if hit.start >= start && hit.end <= end => exact_highlight(
                region,
                hit.start - start..hit.end - start,
                &redacted,
                charge,
            )?,
            Some(hit) if hit.start < start => (None, 0..0),
            Some(_) => (None, redacted.len()..redacted.len()),
            None => (None, 0..0),
        };
        // Only text past the leading guard may be shown.
        let floor = if start > 0 {
            let guard = leading_guard(region, charge)?;
            shown_from(region, guard, &redacted, charge)?
        } else {
            0
        };
        let whole = &redacted[floor..];
        let highlight = highlight
            .filter(|range| range.start >= floor)
            .map(|range| range.start - floor..range.end - floor);
        let anchor = if anchor.start >= floor {
            anchor.start - floor..anchor.end - floor
        } else {
            0..0
        };
        let tokens = token_spans(whole);
        let (window, highlight) =
            if whole.len() <= MAX_REDACTED_EVIDENCE_BYTES && tokens.len() <= MAX_EVIDENCE_TOKENS {
                (0..whole.len(), highlight)
            } else {
                let (before, after) = if hit.is_some() {
                    (EXCERPT_BEFORE_BYTES, EXCERPT_AFTER_BYTES)
                } else {
                    (0, MAX_REDACTED_EVIDENCE_BYTES)
                };
                excerpt_window(whole, &tokens, anchor, highlight, before, after)
            };
        let mut excerpt = whole[window.clone()].to_owned();
        let mut highlight =
            highlight.map(|range| range.start - window.start..range.end - window.start);
        // Cutting whole tokens out of redacted text normally keeps it a fixed
        // point; where a cut changes how the rest reads, redact again and
        // drop the now unreliable position. Uncut, the excerpt is exactly
        // `try_sanitize` output, which is already a fixed point.
        let cut = start > 0 || end < text.len() || floor > 0 || window != (0..whole.len());
        if cut {
            let again = Self::try_sanitize(SanitizationContext::Evidence, &excerpt, charge)?;
            if again != excerpt {
                excerpt = again;
                highlight = None;
            }
        }
        charge(text.len())?;
        Ok(EvidenceExcerpt {
            text: excerpt,
            highlight,
            elided_before: floor + window.start > 0
                || text[..start].chars().any(|c| !c.is_whitespace()),
            elided_after: window.end < whole.len()
                || text[end..].chars().any(|c| !c.is_whitespace()),
        })
    }
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Move a raw start cut past the fragment that holds it. The quote state at
/// the cut comes from the text before it, so a quoted value that opened
/// before the cut is dropped through its closing quote.
fn neutralize_leading_cut<E>(
    text: &str,
    start: usize,
    end: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<usize, E> {
    charge(start)?;
    let mut scanner = FragmentScanner::default();
    let mut at_boundary = false;
    for character in text[..start].chars() {
        at_boundary = scanner.step(character);
    }
    if at_boundary {
        return Ok(start);
    }
    charge(end - start)?;
    for (offset, character) in text[start..end].char_indices() {
        if scanner.step(character) {
            return Ok(start + offset);
        }
    }
    Ok(end)
}

/// Move a leading cut that falls inside a private key block, one whose
/// `BEGIN` line starts before the cut, past the block's `END` line.
fn skip_open_private_key_block<E>(
    text: &str,
    start: usize,
    end: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<usize, E> {
    // Include a `BEGIN` line that the cut itself splits.
    let scanned = floor_char_boundary(text, start.saturating_add(64).min(end));
    charge(scanned)?;
    let open = PRIVATE_KEY_BLOCK_RE
        .find_iter(&text[..scanned])
        .filter(|block| block.start() < start)
        .last()
        .is_some_and(|block| block.end() > start && !PRIVATE_KEY_END_RE.is_match(block.as_str()));
    if !open {
        return Ok(start);
    }
    charge(end - start)?;
    match PRIVATE_KEY_END_RE.find(&text[start..end]) {
        Some(found) => neutralize_leading_cut(text, start + found.end(), end, charge),
        None => Ok(end),
    }
}

/// Move a leading cut past the end of an assignment value that a label before
/// it opened on the cut's line. Such a value can outlast the leading guard: an
/// authorization value runs to the line end or `;`, and a quoted value to its
/// closing quote, which may be escaped or encoded (`\u0022`), as the
/// assignment pass decodes it. Any key run that holds a secret key word
/// counts, wherever the assignment pass would resume, so the scan stays linear
/// and errs toward dropping text. Only the last `LEADING_LINE_SCAN_BYTES`
/// before the cut are scanned; a longer line whose unscanned start holds a
/// backslash or an authorization word is dropped to its end. Plain values end
/// at the fragment the cut drops. YAML block values are not covered.
fn skip_open_line_value<E>(
    text: &str,
    start: usize,
    end: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<usize, E> {
    if start >= end {
        return Ok(start);
    }
    charge(start)?;
    let line_start = text[..start].rfind(['\r', '\n']).map_or(0, |at| at + 1);
    let mut window_start = line_start;
    if start - line_start > LEADING_LINE_SCAN_BYTES {
        // Begin at whitespace, which no unquoted key or escape spans.
        let from = floor_char_boundary(text, start - LEADING_LINE_SCAN_BYTES);
        window_start = text[from..start]
            .find(char::is_whitespace)
            .map_or(start, |at| from + at);
        if UNSCANNED_LINE_VALUE_RE.is_match(&text[line_start..window_start]) {
            let skipped = line_end(text, start).min(end);
            return neutralize_leading_cut(text, skipped, end, charge);
        }
    }
    let window = &text[window_start..end];
    charge(window.len().saturating_mul(8))?;
    let decoded = decode_assignment_syntax(window);
    let scan = decoded
        .as_ref()
        .map_or(window, |decoded| decoded.text.as_str());
    let source = |offset: usize| {
        window_start
            + decoded.as_ref().map_or(offset, |decoded| {
                decoded
                    .source_boundaries
                    .binary_search_by_key(&offset, |boundary| boundary.0)
                    .map_or(window.len(), |at| decoded.source_boundaries[at].1)
            })
    };
    let bytes = scan.as_bytes();
    let key_byte = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-');
    let mut shown = start;
    // The first `\r`, `\n` or `;` at or after an authorization value's start.
    let mut stop: Option<usize> = None;
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !key_byte(bytes[cursor]) {
            cursor += 1;
            continue;
        }
        let key_start = cursor;
        while cursor < bytes.len() && key_byte(bytes[cursor]) {
            cursor += 1;
        }
        if source(key_start) >= shown {
            break;
        }
        let key = &scan[key_start..cursor];
        let compact = key
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        if !SECRET_KEY_WORDS.iter().any(|word| compact.contains(word)) {
            continue;
        }
        let mut value_start = cursor;
        skip_assignment_whitespace(scan, &mut value_start);
        let spaced = value_start > cursor;
        if matches!(bytes.get(value_start), Some(b'"' | b'\'')) {
            let mut after_quote = value_start + 1;
            skip_assignment_whitespace(scan, &mut after_quote);
            if matches!(bytes.get(after_quote), Some(b'=' | b':')) {
                value_start = after_quote;
            }
        }
        if matches!(bytes.get(value_start), Some(b'=' | b':')) {
            value_start += 1;
            skip_assignment_whitespace(scan, &mut value_start);
        } else if !(spaced && key.contains("--")) {
            continue;
        }
        let value_end = if ["auth", "authorization", "bearer"]
            .iter()
            .any(|word| compact.ends_with(word))
        {
            if stop.is_none_or(|stop| stop < value_start) {
                stop = Some(
                    scan[value_start..]
                        .find(['\r', '\n', ';'])
                        .map_or(scan.len(), |at| value_start + at),
                );
            }
            stop
        } else if bytes.get(value_start) == Some(&b'\\')
            && matches!(bytes.get(value_start + 1), Some(b'"' | b'\''))
        {
            let quote = bytes[value_start + 1];
            Some(
                find_escaped_quote(scan, value_start + 2, quote)
                    .map_or_else(|| line_end(scan, value_start), |at| at + 2),
            )
        } else if let Some(quote @ (b'"' | b'\'')) = bytes.get(value_start).copied() {
            Some(
                find_quote(scan, value_start + 1, quote)
                    .map_or_else(|| line_end(scan, value_start), |at| at + 1),
            )
        } else {
            None
        };
        if let Some(value_end) = value_end {
            shown = shown.max(source(value_end));
        }
    }
    if shown == start {
        return Ok(start);
    }
    neutralize_leading_cut(text, shown, end, charge)
}

/// The offset in `region`, which starts at a leading cut, of the first
/// fragment boundary past the leading guard.
fn leading_guard<E>(
    region: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<usize, E> {
    charge(region.len())?;
    let mut scanner = FragmentScanner::default();
    let mut fragments = 0;
    let mut previous_boundary = true;
    for (offset, character) in region.char_indices() {
        let boundary = scanner.step(character);
        if boundary && !previous_boundary {
            fragments += 1;
            if fragments >= LEADING_GUARD_FRAGMENTS && offset >= LEADING_GUARD_BYTES {
                return Ok(offset);
            }
        }
        previous_boundary = boundary;
    }
    Ok(region.len())
}

/// The offset in `redacted`, the redaction of `region`, from which no text
/// derived from `region[..guard]` remains: past the guarded text's own
/// redaction when `redacted` starts with it, otherwise past as many tokens as
/// that redaction has, since redaction in context joins text rather than
/// splitting it.
fn shown_from<E>(
    region: &str,
    guard: usize,
    redacted: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<usize, E> {
    let guarded = redact_region(&region[..guard], charge)?;
    if guarded.is_empty() {
        return Ok(0);
    }
    if redacted.starts_with(&guarded)
        && matches!(redacted.as_bytes().get(guarded.len()), None | Some(b' '))
    {
        return Ok((guarded.len() + 1).min(redacted.len()));
    }
    let skip = token_spans(&guarded).len();
    Ok(token_spans(redacted)
        .get(skip)
        .map_or(redacted.len(), |token| token.start))
}

/// Move a raw end cut back to the start of the fragment that holds it,
/// unless the cut already ends a fragment.
fn neutralize_trailing_cut<E>(
    text: &str,
    start: usize,
    end: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<usize, E> {
    charge(end - start)?;
    let mut scanner = FragmentScanner::default();
    let mut fragment_start = start;
    let mut at_boundary = false;
    for (offset, character) in text[start..end].char_indices() {
        at_boundary = scanner.step(character);
        if at_boundary {
            fragment_start = start + offset;
        }
    }
    let next_ends_fragment =
        scanner.quote.is_none() && text[end..].chars().next().is_some_and(char::is_whitespace);
    Ok(if at_boundary || next_ends_fragment {
        end
    } else {
        fragment_start
    })
}

/// Evidence redaction of a region within the input bound, without the
/// output byte and token bounds.
fn redact_region<E>(
    region: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    let redacted = redact_bounded(SanitizationContext::Evidence, region.to_owned(), charge)?;
    charge(redacted.len())?;
    Ok(redacted.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The hit's range in `whole` when `whole` starts with the separate
/// redactions of the text before the hit and of the hit, joined as the region
/// joins them, plus an anchor for placing the excerpt either way. The text
/// through the hit must redact to that same join, so a value opened before
/// the hit that masks it never leaves a later copy of the hit located. Only
/// text up to the hit is redacted: the text after the hit is the larger part
/// of a region, and redaction can reserve work quadratic in its input.
fn exact_highlight<E>(
    region: &str,
    hit: Range<usize>,
    whole: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<(Option<Range<usize>>, Range<usize>), E> {
    let (before, at) = (&region[..hit.start], &region[hit.clone()]);
    let prefix = redact_region(before, charge)?;
    let piece = redact_region(at, charge)?;
    let space = !prefix.is_empty()
        && (before.ends_with(char::is_whitespace) || at.starts_with(char::is_whitespace));
    let start = prefix.len() + usize::from(space);
    let located = start..start + piece.len();
    let through = redact_region(&region[..hit.end], charge)?;
    let exact = !piece.is_empty()
        && through.len() == located.end
        && through.starts_with(&prefix)
        && (!space || through.as_bytes().get(prefix.len()) == Some(&b' '))
        && through.get(located.clone()) == Some(piece.as_str())
        && whole.starts_with(&through);
    let anchor = located.start.min(whole.len())..located.end.min(whole.len());
    Ok((exact.then_some(located), anchor))
}

/// Byte ranges of the space-separated tokens of normalized text.
fn token_spans(text: &str) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut start = 0;
    for token in text.split(' ') {
        if !token.is_empty() {
            spans.push(start..start + token.len());
        }
        start += token.len() + 1;
    }
    spans
}

/// Whole tokens around `anchor`, about `before` and `after` bytes on each
/// side, within the evidence byte and token bounds. A highlight that cannot
/// fit is dropped.
fn excerpt_window(
    whole: &str,
    tokens: &[Range<usize>],
    anchor: Range<usize>,
    highlight: Option<Range<usize>>,
    before: usize,
    after: usize,
) -> (Range<usize>, Option<Range<usize>>) {
    if tokens.is_empty() {
        return (0..0, None);
    }
    let first = tokens
        .iter()
        .position(|token| token.end > anchor.start)
        .unwrap_or(tokens.len() - 1);
    let last = tokens
        .iter()
        .rposition(|token| token.start < anchor.end)
        .unwrap_or(first)
        .max(first);
    let fits = |low: usize, high: usize| {
        high - low <= MAX_EVIDENCE_TOKENS
            && tokens[high - 1].end - tokens[low].start <= MAX_REDACTED_EVIDENCE_BYTES
    };
    if !fits(first, last + 1) {
        // The hit alone exceeds the bounds: show as much of it as fits.
        let mut high = first + 1;
        while high < tokens.len() && fits(first, high + 1) {
            high += 1;
        }
        let start = tokens[first].start;
        let end = floor_char_boundary(
            whole,
            tokens[high - 1]
                .end
                .min(start + MAX_REDACTED_EVIDENCE_BYTES),
        );
        return (start..end, None);
    }
    let (mut low, mut high) = (first, last + 1);
    loop {
        let mut grew = false;
        if low > 0 && anchor.start - tokens[low - 1].start <= before && fits(low - 1, high) {
            low -= 1;
            grew = true;
        }
        if high < tokens.len() && tokens[high].end - anchor.end <= after && fits(low, high + 1) {
            high += 1;
            grew = true;
        }
        if !grew {
            break;
        }
    }
    (tokens[low].start..tokens[high - 1].end, highlight)
}

pub(crate) fn redact_error_message(text: &str) -> String {
    PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text)
}

/// A synthetic value that must not appear in serialized event bytes.
#[derive(Debug, Clone, Copy)]
pub struct ControlledMarker<'a> {
    pub id: &'a str,
    pub value: &'a str,
}

/// Safe result from a serialized-byte controlled-marker check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializedMarkerCheckError {
    InputTooLarge {
        case_id: String,
    },
    MaximumDepthExceeded {
        case_id: String,
    },
    InvalidSerializedEvent {
        case_id: String,
    },
    MarkerFound {
        case_id: String,
        field: String,
        marker_id: String,
    },
}

impl fmt::Display for SerializedMarkerCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { case_id } => write!(
                formatter,
                "privacy marker check failed for case {case_id}: serialized input exceeds the safe limit"
            ),
            Self::MaximumDepthExceeded { case_id } => write!(
                formatter,
                "privacy marker check failed for case {case_id}: serialized input exceeds the safe nesting limit"
            ),
            Self::InvalidSerializedEvent { case_id } => {
                write!(
                    formatter,
                    "privacy marker check failed for case {case_id}: invalid serialized event"
                )
            }
            Self::MarkerFound {
                case_id,
                field,
                marker_id,
            } => write!(
                formatter,
                "privacy marker check failed for case {case_id}, field {field}, marker {marker_id}"
            ),
        }
    }
}

impl std::error::Error for SerializedMarkerCheckError {}

/// Checks serialized Event 3.0 JSON without returning controlled marker values.
pub fn check_serialized_event_markers(
    bytes: &[u8],
    case_id: &str,
    markers: &[ControlledMarker<'_>],
) -> Result<(), SerializedMarkerCheckError> {
    let safe_case_id = safe_report_label(case_id);
    if bytes.len() > MAX_SERIALIZED_EVENT_BYTES {
        return Err(SerializedMarkerCheckError::InputTooLarge {
            case_id: safe_case_id,
        });
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut state = MarkerCheckState::default();
    let mut count = 0;
    loop {
        let field = if count == 0 {
            "$".to_string()
        } else {
            format!("$[{count}]")
        };
        let seed = MarkerSeed {
            markers,
            state: &mut state,
            field,
            depth: 0,
        };
        match seed.deserialize(&mut deserializer) {
            Ok(()) => {}
            Err(_) if state.match_info.is_some() => {
                let (field, marker_id) = state
                    .match_info
                    .expect("marker match is present when parsing stops early");
                return Err(SerializedMarkerCheckError::MarkerFound {
                    case_id: safe_case_id,
                    field,
                    marker_id,
                });
            }
            Err(_) if state.maximum_depth_exceeded => {
                return Err(SerializedMarkerCheckError::MaximumDepthExceeded {
                    case_id: safe_case_id,
                });
            }
            Err(error) if error.is_eof() && count > 0 => break,
            Err(_) => {
                return Err(SerializedMarkerCheckError::InvalidSerializedEvent {
                    case_id: safe_case_id,
                });
            }
        }
        count += 1;
    }
    if count == 0 {
        return Err(SerializedMarkerCheckError::InvalidSerializedEvent {
            case_id: safe_case_id,
        });
    }
    if let Some((field, marker_id)) = state.match_info {
        return Err(SerializedMarkerCheckError::MarkerFound {
            case_id: safe_case_id,
            field,
            marker_id,
        });
    }
    Ok(())
}

const MAX_MARKER_REPORT_LABEL_BYTES: usize = 64;
const MAX_MARKER_DEPTH: usize = 32;

#[derive(Default)]
struct MarkerCheckState {
    match_info: Option<(String, String)>,
    maximum_depth_exceeded: bool,
}

impl MarkerCheckState {
    fn check(&mut self, text: &str, field: &str, markers: &[ControlledMarker<'_>]) -> bool {
        if self.match_info.is_none()
            && let Some(marker) = markers
                .iter()
                .find(|marker| !marker.value.is_empty() && text.contains(marker.value))
        {
            self.match_info = Some((field.to_string(), safe_report_label(marker.id)));
        }
        self.match_info.is_some()
    }
}

fn safe_report_label(value: &str) -> String {
    let mut label = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(MAX_MARKER_REPORT_LABEL_BYTES)
        .collect::<String>();
    if label.is_empty() {
        label = "invalid-id".to_string();
    }
    label
}

struct MarkerSeed<'a, 'b> {
    markers: &'a [ControlledMarker<'a>],
    state: &'b mut MarkerCheckState,
    field: String,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for MarkerSeed<'_, '_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(MarkerVisitor {
            markers: self.markers,
            state: self.state,
            field: self.field,
            depth: self.depth,
        })
    }
}

struct MarkerVisitor<'a, 'b> {
    markers: &'a [ControlledMarker<'a>],
    state: &'b mut MarkerCheckState,
    field: String,
    depth: usize,
}

impl<'de> Visitor<'de> for MarkerVisitor<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, text: &str) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        if self.state.check(text, &self.field, self.markers) {
            return Err(E::custom("privacy marker check stopped"));
        }
        Ok(())
    }

    fn visit_string<E>(self, text: String) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&text)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= MAX_MARKER_DEPTH {
            self.state.maximum_depth_exceeded = true;
            return Err(A::Error::custom("privacy marker check stopped"));
        }
        let mut index = 0;
        while sequence
            .next_element_seed(MarkerSeed {
                markers: self.markers,
                state: self.state,
                field: format!("{}[{index}]", self.field),
                depth: self.depth + 1,
            })?
            .is_some()
        {
            index += 1;
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= MAX_MARKER_DEPTH {
            self.state.maximum_depth_exceeded = true;
            return Err(A::Error::custom("privacy marker check stopped"));
        }
        while let Some(key) = map.next_key::<String>()? {
            if self.state.check(&key, &self.field, self.markers) {
                return Err(A::Error::custom("privacy marker check stopped"));
            }
            map.next_value_seed(MarkerSeed {
                markers: self.markers,
                state: self.state,
                // Never put a source-controlled key in an error/report path.
                field: format!("{}.<key>", self.field),
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

pub(crate) fn contains_high_confidence_credential_marker(text: &str) -> bool {
    HIGH_CONFIDENCE_GH_TOKEN_RE.is_match(text)
        || HIGH_CONFIDENCE_SK_KEY_RE.is_match(text)
        || HIGH_CONFIDENCE_AKIA_RE.is_match(text)
        || HIGH_CONFIDENCE_XOX_RE.is_match(text)
        || HIGH_CONFIDENCE_JWT_RE.is_match(text)
        || HIGH_CONFIDENCE_PRIVATE_KEY_RE.is_match(text)
}

/// Classifies source-controlled credential material before values are admitted
/// to structured metadata or retained after URL component decoding.
pub(crate) fn contains_credential_material(text: &str) -> bool {
    contains_high_confidence_credential_marker(text)
        || CREDENTIAL_GH_TOKEN_RE.is_match(text)
        || CREDENTIAL_SK_KEY_RE.is_match(text)
        || CREDENTIAL_AKIA_RE.is_match(text)
        || CREDENTIAL_XOX_RE.is_match(text)
        || CREDENTIAL_VENDOR_TOKEN_RE.is_match(text)
        || CREDENTIAL_JWT_RE.is_match(text)
        || CREDENTIAL_BEARER_RE.is_match(text)
        || ENCODED_BLOB_RE.is_match(text)
        || contains_secret_assignment(text)
        || contains_url_userinfo(text)
}

fn contains_secret_assignment(text: &str) -> bool {
    let mut offset = 0;
    while offset < text.len() {
        if scan_secret_assignment(&text[offset..], true).is_some() {
            return true;
        }
        let character = text[offset..]
            .chars()
            .next()
            .expect("offset remains on a character boundary");
        offset += character.len_utf8();
    }
    false
}

fn contains_url_userinfo(text: &str) -> bool {
    URL_RE.find_iter(text).any(|capture| {
        let url = capture.as_str();
        let Some((_, rest)) = url_prefix_and_authority(url) else {
            return false;
        };
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        rest[..authority_end]
            .rsplit_once('@')
            .is_some_and(|(userinfo, _)| !userinfo.is_empty())
    })
}

fn redact_assignments<E>(
    text: &str,
    allow_flags: bool,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    charge(text.len())?;
    // Reserve decoding, URL partitioning and output copies linearly. Assignment
    // scans reserve their reached key/value spans below, before executing them;
    // one quote must not charge the square of the entire evidence preview.
    charge(text.len().saturating_mul(16))?;
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;
    for url in URL_RE.find_iter(text) {
        redacted.push_str(&redact_assignments_outside_urls(
            &text[offset..url.start()],
            allow_flags,
            charge,
        )?);
        // URL credentials and query values have their own structural pass.
        redacted.push_str(url.as_str());
        offset = url.end();
    }
    redacted.push_str(&redact_assignments_outside_urls(
        &text[offset..],
        allow_flags,
        charge,
    )?);
    Ok(redacted)
}

fn redact_sensitive_labels(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;
    for url in URL_RE.find_iter(text) {
        redacted.push_str(&redact_sensitive_labels_outside_urls(
            &text[offset..url.start()],
        ));
        redacted.push_str(url.as_str());
        offset = url.end();
    }
    redacted.push_str(&redact_sensitive_labels_outside_urls(&text[offset..]));
    redacted
}

fn redact_sensitive_labels_outside_urls(text: &str) -> String {
    SENSITIVE_LABEL_RE
        .replace_all(text, |captures: &regex::Captures<'_>| {
            let label = captures.get(0).expect("sensitive label match");
            if label_is_assignment_key(&text[label.end()..]) {
                label.as_str().to_string()
            } else {
                REDACTED_SECRET.to_string()
            }
        })
        .into_owned()
}

fn label_is_assignment_key(suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches(char::is_whitespace);
    let suffix = suffix
        .strip_prefix('"')
        .or_else(|| suffix.strip_prefix('\''))
        .unwrap_or(suffix);
    let suffix = suffix.trim_start_matches(char::is_whitespace);
    matches!(suffix.as_bytes().first(), Some(b'=' | b':'))
}

fn redact_assignments_outside_urls<E>(
    text: &str,
    allow_flags: bool,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    let Some(classified) = decode_assignment_syntax(text) else {
        return redact_literal_assignments(text, allow_flags, charge);
    };
    let mut redacted = String::with_capacity(text.len());
    let mut classified_offset = 0;
    let mut source_offset = 0;

    while classified_offset < classified.text.len() {
        reserve_assignment_scan(&classified.text[classified_offset..], charge)?;
        if let Some(assignment) =
            scan_secret_assignment(&classified.text[classified_offset..], allow_flags)
        {
            let assignment_start = classified.source_offset(classified_offset);
            let assignment_end = classified.source_offset(classified_offset + assignment.end);
            redacted.push_str(&text[source_offset..assignment_start]);
            redacted.push_str(&redact_classified_assignment(
                text,
                &classified,
                classified_offset,
                assignment,
            ));
            classified_offset += assignment.end;
            source_offset = assignment_end;
        } else {
            let character = classified.text[classified_offset..]
                .chars()
                .next()
                .expect("classified offset remains on a character boundary");
            classified_offset += character.len_utf8();
        }
    }
    redacted.push_str(&text[source_offset..]);

    Ok(redacted)
}

fn redact_literal_assignments<E>(
    text: &str,
    allow_flags: bool,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;

    while offset < text.len() {
        reserve_assignment_scan(&text[offset..], charge)?;
        if let Some(assignment) = scan_secret_assignment(&text[offset..], allow_flags) {
            let (_, replacement) = redact_assignment_value(
                &text[offset..],
                assignment.value_start,
                assignment.authorization,
            );
            redacted.push_str(&replacement);
            offset += assignment.end;
        } else {
            let character = text[offset..]
                .chars()
                .next()
                .expect("offset remains on a character boundary");
            redacted.push(character);
            offset += character.len_utf8();
        }
    }

    Ok(redacted)
}

fn reserve_assignment_scan<E>(
    text: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<(), E> {
    if text.starts_with(['"', '\'']) {
        let quote = text.as_bytes()[0];
        for (index, byte) in text.bytes().enumerate().skip(1) {
            charge(1)?;
            // Match find_quote's existing lexical rules exactly, including its
            // immediate preceding-backslash check and newline termination.
            if matches!(byte, b'\n' | b'\r') {
                return charge(index.saturating_mul(16));
            }
            if byte == quote && (index == 1 || text.as_bytes()[index - 1] != b'\\') {
                charge(index.saturating_mul(16))?;
                if is_secret_key(&text[1..index]) {
                    charge(text.len().saturating_mul(16))?;
                }
                return Ok(());
            }
        }
        // A missing closing delimiter still visits the complete suffix.
        return charge(text.len().saturating_mul(16));
    }
    let mut end: usize = 0;
    for byte in text.bytes() {
        charge(1)?;
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')) {
            break;
        }
        end += 1;
    }
    // Covers rescanning the key, component classification/normalization and
    // temporary key material. Malicious long tokens still incur quadratic work
    // over successive suffix attempts and exhaust the same source budget.
    charge(end.saturating_mul(16))?;
    if end != 0 && is_secret_key(&text[..end]) {
        charge(text.len().saturating_mul(16))?;
    }
    Ok(())
}

fn redact_classified_assignment(
    source: &str,
    classified: &DecodedAssignmentSyntax,
    assignment_start: usize,
    assignment: SecretAssignment,
) -> String {
    let value_start = assignment_start + assignment.value_start;
    let value_end = assignment_start + assignment.end;
    let source_start = classified.source_offset(assignment_start);
    let source_value_start = classified.source_offset(value_start);
    let source_end = classified.source_offset(value_end);
    let value = &classified.text[value_start..value_end];

    if value.starts_with(REDACTED_SECRET) {
        return source[source_start..source_end].to_string();
    }
    if assignment.authorization || value.starts_with(['|', '>']) {
        return format!(
            "{}{}",
            &source[source_start..source_value_start],
            REDACTED_SECRET
        );
    }
    let quoted = value.len() >= 2
        && matches!(value.as_bytes().first(), Some(b'"' | b'\''))
        && value.as_bytes().first() == value.as_bytes().last();
    if quoted {
        let opening_end = classified.source_offset(value_start + 1);
        let closing_start = classified.source_offset(value_end - 1);
        return format!(
            "{}{}{}{}",
            &source[source_start..source_value_start],
            &source[source_value_start..opening_end],
            REDACTED_SECRET,
            &source[closing_start..source_end]
        );
    }
    format!(
        "{}{}",
        &source[source_start..source_value_start],
        REDACTED_SECRET
    )
}

/// Decode only bounded assignment syntax so escaped JSON and shell renderings
/// are classified by the same scanner as their literal equivalents. The source
/// spans let the caller replace only secret values without emitting decoded text.
fn decode_assignment_syntax(text: &str) -> Option<DecodedAssignmentSyntax> {
    const MAX_ESCAPED_SYNTAX_DEPTH: usize = 2;
    let mut characters = text
        .char_indices()
        .map(|(start, character)| SyntaxCharacter {
            character,
            source_start: start,
            source_end: start + character.len_utf8(),
        })
        .collect::<Vec<_>>();
    let mut changed = false;

    for _ in 0..MAX_ESCAPED_SYNTAX_DEPTH {
        let (decoded, decoded_changed) = decode_assignment_syntax_once(&characters);
        characters = decoded;
        changed |= decoded_changed;
        if !decoded_changed {
            break;
        }
    }

    changed.then(|| DecodedAssignmentSyntax::from_characters(characters))
}

#[derive(Clone)]
struct SyntaxCharacter {
    character: char,
    source_start: usize,
    source_end: usize,
}

struct DecodedAssignmentSyntax {
    text: String,
    source_boundaries: Vec<(usize, usize)>,
}

impl DecodedAssignmentSyntax {
    fn from_characters(characters: Vec<SyntaxCharacter>) -> Self {
        let mut text = String::with_capacity(characters.len());
        let mut source_boundaries = Vec::with_capacity(characters.len() + 1);
        source_boundaries.push((0, 0));
        for character in characters {
            let offset = text.len();
            debug_assert_eq!(source_boundaries.last().map(|entry| entry.0), Some(offset));
            debug_assert_eq!(
                source_boundaries.last().map(|entry| entry.1),
                Some(character.source_start)
            );
            text.push(character.character);
            source_boundaries.push((text.len(), character.source_end));
        }
        Self {
            text,
            source_boundaries,
        }
    }

    fn source_offset(&self, decoded_offset: usize) -> usize {
        self.source_boundaries
            .iter()
            .find_map(|(offset, source_offset)| {
                (*offset == decoded_offset).then_some(*source_offset)
            })
            .expect("decoded offset remains on a source character boundary")
    }
}

fn decode_assignment_syntax_once(characters: &[SyntaxCharacter]) -> (Vec<SyntaxCharacter>, bool) {
    let mut decoded = Vec::with_capacity(characters.len());
    let mut offset = 0;
    let mut changed = false;

    while offset < characters.len() {
        if let Some((character, consumed)) = decode_escaped_syntax_character(&characters[offset..])
        {
            decoded.push(SyntaxCharacter {
                character,
                source_start: characters[offset].source_start,
                source_end: characters[offset + consumed - 1].source_end,
            });
            offset += consumed;
            changed = true;
        } else {
            decoded.push(characters[offset].clone());
            offset += 1;
        }
    }

    (decoded, changed)
}

fn decode_escaped_syntax_character(characters: &[SyntaxCharacter]) -> Option<(char, usize)> {
    if characters.first()?.character != '\\' {
        return None;
    }
    match characters.get(1)?.character {
        '"' | '\'' | '\\' => Some((characters[1].character, 2)),
        'x' => {
            let high = characters.get(2)?.character.to_digit(16)?;
            let low = characters.get(3)?.character.to_digit(16)?;
            Some((char::from_u32(high * 16 + low)?, 4))
        }
        'u' => {
            let mut value = 0;
            for character in characters.get(2..6)? {
                value = value * 16 + character.character.to_digit(16)?;
            }
            Some((char::from_u32(value)?, 6))
        }
        _ => None,
    }
}

/// Scan a bounded, ASCII-shaped assignment without relying on an unbounded
/// regex backtrack. The caller has already capped the input to `MAX_INPUT_BYTES`.
#[derive(Clone, Copy)]
struct SecretAssignment {
    end: usize,
    value_start: usize,
    authorization: bool,
}

fn scan_secret_assignment(text: &str, allow_flags: bool) -> Option<SecretAssignment> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let mut cursor = 0;
    let (key_start, key_end, flag) = if let Some(quote @ (b'\"' | b'\'')) = bytes.first().copied() {
        let key_start = 1;
        let key_end = find_quote(text, key_start, quote)?;
        cursor = key_end + 1;
        (key_start, key_end, false)
    } else {
        let flag = text.starts_with("--");
        if flag {
            cursor += 2;
        }
        let key_start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-'))
        {
            cursor += 1;
        }
        (key_start, cursor, flag)
    };
    let key = &text[key_start..key_end];
    if key.is_empty() || !is_secret_key(key) {
        return None;
    }

    let whitespace_start = cursor;
    skip_assignment_whitespace(text, &mut cursor);
    let authorization = is_authorization_key(key);
    let has_separator = matches!(bytes.get(cursor), Some(b'=' | b':'));
    if has_separator {
        cursor += 1;
        skip_assignment_whitespace(text, &mut cursor);
    } else if !flag || !allow_flags || cursor == whitespace_start {
        return None;
    }

    let prefix_end = cursor;
    let (end, _) = redact_assignment_value(text, prefix_end, authorization);
    Some(SecretAssignment {
        end,
        value_start: prefix_end,
        authorization,
    })
}

fn skip_assignment_whitespace(text: &str, cursor: &mut usize) {
    while let Some(character) = text[*cursor..].chars().next() {
        if !character.is_whitespace() {
            break;
        }
        *cursor += character.len_utf8();
    }
}

const SECRET_KEY_WORDS: [&str; 15] = [
    "apikey",
    "accesstoken",
    "accesskey",
    "authorization",
    "auth",
    "bearer",
    "clientsecret",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "token",
    "privatekey",
    "key",
];

fn is_secret_key(key: &str) -> bool {
    let parts = secret_key_parts(key);
    let compact = parts.join("");
    SECRET_KEY_WORDS.contains(&compact.as_str())
        || parts
            .last()
            .is_some_and(|part| SECRET_KEY_WORDS.contains(&part.as_str()))
}

fn secret_key_parts(key: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut previous_was_lowercase = false;

    for character in key.chars() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                parts.push(std::mem::take(&mut current));
            }
            previous_was_lowercase = false;
            continue;
        }
        if character.is_ascii_uppercase() && previous_was_lowercase && !current.is_empty() {
            parts.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_lowercase());
        previous_was_lowercase = character.is_ascii_lowercase();
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn is_authorization_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(normalized.as_str(), "authorization" | "auth" | "bearer")
}

fn redact_assignment_value(text: &str, value_start: usize, authorization: bool) -> (usize, String) {
    let bytes = text.as_bytes();
    if text[value_start..].starts_with(REDACTED_SECRET) {
        let end = value_start + REDACTED_SECRET.len();
        return (end, text[..end].to_string());
    }
    if authorization {
        let end = authorization_value_end(text, value_start);
        return (end, format!("{}{}", &text[..value_start], REDACTED_SECRET));
    }

    if matches!(bytes.get(value_start), Some(b'|' | b'>')) {
        return redact_block_assignment_value(text, value_start);
    }

    if matches!(
        (bytes.get(value_start), bytes.get(value_start + 1)),
        (Some(b'\\'), Some(b'\"' | b'\''))
    ) {
        let quote = bytes[value_start + 1];
        let closing = find_escaped_quote(text, value_start + 2, quote);
        let end = closing.map_or_else(|| line_end(text, value_start), |index| index + 2);
        let closing_text = closing.map_or("", |index| &text[index..index + 2]);
        return (
            end,
            format!(
                "{}{}{}{}",
                &text[..value_start],
                &text[value_start..value_start + 2],
                REDACTED_SECRET,
                closing_text
            ),
        );
    }

    if let Some(quote @ (b'\"' | b'\'')) = bytes.get(value_start).copied() {
        let closing = find_quote(text, value_start + 1, quote);
        let end = closing.map_or_else(|| line_end(text, value_start), |index| index + 1);
        let closing_text = closing.map_or("", |index| &text[index..index + 1]);
        return (
            end,
            format!(
                "{}{}{}{}",
                &text[..value_start],
                &text[value_start..value_start + 1],
                REDACTED_SECRET,
                closing_text
            ),
        );
    }

    let mut end = value_start;
    while let Some(character) = text[end..].chars().next() {
        if character.is_whitespace()
            || matches!(
                character,
                ',' | ';' | '}' | ']' | ')' | '"' | '\'' | '&' | '#'
            )
        {
            break;
        }
        end += character.len_utf8();
    }
    (end, format!("{}{}", &text[..value_start], REDACTED_SECRET))
}

fn line_end(text: &str, start: usize) -> usize {
    text[start..]
        .find(['\r', '\n'])
        .map_or(text.len(), |offset| start + offset)
}

fn authorization_value_end(text: &str, start: usize) -> usize {
    text[start..]
        .find(['\r', '\n', ';'])
        .map_or(text.len(), |offset| start + offset)
}

fn redact_block_assignment_value(text: &str, value_start: usize) -> (usize, String) {
    let style_line_end = line_end(text, value_start);
    if style_line_end == text.len() {
        return (
            style_line_end,
            format!("{}{}", &text[..value_start], REDACTED_SECRET),
        );
    }

    let bytes = text.as_bytes();
    let block_line_break = if bytes.get(style_line_end) == Some(&b'\r')
        && bytes.get(style_line_end + 1) == Some(&b'\n')
    {
        "\r\n"
    } else {
        "\n"
    };
    let mut cursor = style_line_end + block_line_break.len();
    loop {
        let line_start = cursor;
        let line_end = line_end(text, line_start);
        let line_is_indented = matches!(bytes.get(line_start), Some(b' ' | b'\t'));
        let line_is_empty = line_start == line_end;
        if !line_is_indented && !line_is_empty {
            // Removing the style marker ensures a second pass sees an ordinary
            // redacted assignment rather than a block that absorbs `next=value`.
            return (
                line_start,
                format!(
                    "{}{}{}",
                    &text[..value_start],
                    REDACTED_SECRET,
                    block_line_break
                ),
            );
        }
        if line_end == text.len() {
            return (
                text.len(),
                format!("{}{}", &text[..value_start], REDACTED_SECRET),
            );
        }
        cursor = if bytes.get(line_end) == Some(&b'\r') && bytes.get(line_end + 1) == Some(&b'\n') {
            line_end + 2
        } else {
            line_end + 1
        };
    }
}

fn find_quote(text: &str, start: usize, quote: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    while let Some(byte) = bytes.get(cursor) {
        if *byte == b'\n' || *byte == b'\r' {
            return None;
        }
        if *byte == quote && (cursor == start || bytes[cursor - 1] != b'\\') {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn find_escaped_quote(text: &str, start: usize, quote: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] == b'\\' && bytes[cursor + 1] == quote {
            return Some(cursor);
        }
        if matches!(bytes[cursor], b'\n' | b'\r') {
            return None;
        }
        cursor += 1;
    }
    None
}

const MAX_PERCENT_DECODE_DEPTH: usize = 2;
const MAX_NESTED_URL_DEPTH: usize = 2;

// Without a complete %HH escape, decoding cannot change a candidate's scheme.
// Keep this linear guard aligned with the reservation and both scanner entries.
fn has_percent_escape(text: &str) -> bool {
    text.as_bytes().windows(3).any(|bytes| {
        bytes[0] == b'%' && bytes[1].is_ascii_hexdigit() && bytes[2].is_ascii_hexdigit()
    })
}

fn redact_encoded_url_candidates<E>(
    text: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    if !has_percent_escape(text) {
        return Ok(text.to_owned());
    }
    let literal_urls = URL_RE
        .find_iter(text)
        .map(|capture| (capture.start(), capture.end()))
        .collect::<Vec<_>>();
    let mut redacted = String::with_capacity(text.len());
    let mut source_offset = 0;
    let mut scan_offset = 0;

    while let Some((start, end, decoded)) =
        find_encoded_url_candidate(text, scan_offset, &literal_urls)
    {
        redacted.push_str(&text[source_offset..start]);
        let (url, trailing) = split_url_trailing_punctuation(&decoded);
        redacted.push_str(&sanitize_url_at_depth(url, 0, charge)?);
        redacted.push_str(trailing);
        source_offset = end;
        scan_offset = end;
    }

    redacted.push_str(&text[source_offset..]);
    Ok(redacted)
}

fn find_encoded_url_candidate(
    text: &str,
    offset: usize,
    literal_urls: &[(usize, usize)],
) -> Option<(usize, usize, String)> {
    // Shared by top-level candidates and URL component inspection. Without
    // complete percent escapes, no candidate can decode into a different URL scheme.
    if !has_percent_escape(&text[offset..]) {
        return None;
    }
    for (relative_start, _) in text[offset..].char_indices() {
        let start = offset + relative_start;
        if literal_urls
            .iter()
            .any(|(url_start, url_end)| *url_start <= start && start < *url_end)
            || !encoded_url_candidate_boundary(text, start)
        {
            continue;
        }

        let end = encoded_url_candidate_end(text, start);
        let candidate = &text[start..end];
        if candidate.contains('%')
            && url_prefix_and_authority(candidate).is_none()
            && let Some(decoded) = decode_url_candidate_until_scheme(candidate)
        {
            return Some((start, end, decoded));
        }
    }
    None
}

fn encoded_url_candidate_boundary(text: &str, start: usize) -> bool {
    let Some(previous) = text[..start].chars().next_back() else {
        return true;
    };
    !previous.is_ascii_alphanumeric() && previous != '_' && previous != '%'
}

fn encoded_url_candidate_end(text: &str, start: usize) -> usize {
    text[start..]
        .char_indices()
        .find_map(|(offset, character)| {
            (character.is_whitespace() || matches!(character, '<' | '>' | '"' | '\''))
                .then_some(start + offset)
        })
        .unwrap_or(text.len())
}

/// Decode only enough of an encoded URL candidate to expose its first
/// recognizable scheme-relative structure. Component delimiters that remain
/// encoded at that point belong to their original component and are never
/// allowed to create a new one during classification.
fn decode_url_candidate_until_scheme(candidate: &str) -> Option<String> {
    let mut representation = candidate.to_string();
    for pass in 0..=MAX_PERCENT_DECODE_DEPTH {
        if has_supported_absolute_url_prefix(&representation) {
            return Some(representation);
        }
        if pass == MAX_PERCENT_DECODE_DEPTH {
            break;
        }
        let decoded = percent_decode_once(&representation);
        if decoded == representation {
            break;
        }
        representation = decoded;
    }
    None
}

/// Decode a URL component for inspection without decoding through an encoded
/// nested URL's first recognized scheme. Text outside an encoded candidate
/// keeps the component-local bounded decoding used by the ordinary URL path.
fn decode_url_component_for_inspection<E>(
    value: &str,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    charge(value.len())?;
    charge(if has_percent_escape(value) {
        value
            .len()
            .saturating_mul(value.len().max(1))
            .saturating_mul(4)
    } else {
        value.len().saturating_mul(4)
    })?;
    let literal_urls = URL_RE
        .find_iter(value)
        .map(|capture| (capture.start(), capture.end()))
        .collect::<Vec<_>>();
    let mut decoded = String::with_capacity(value.len());
    let mut source_offset = 0;
    let mut scan_offset = 0;

    while let Some((start, end, candidate)) =
        find_encoded_url_candidate(value, scan_offset, &literal_urls)
    {
        decoded.push_str(&percent_decode_bounded(&value[source_offset..start]));
        decoded.push_str(&candidate);
        source_offset = end;
        scan_offset = end;
    }

    decoded.push_str(&percent_decode_bounded(&value[source_offset..]));
    Ok(decoded)
}

fn redact_urls_at_depth<E>(
    text: &str,
    depth: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    charge(text.len())?;
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;
    for capture in URL_RE.find_iter(text) {
        redacted.push_str(&text[offset..capture.start()]);
        let (url, trailing) = split_url_trailing_punctuation(capture.as_str());
        redacted.push_str(&sanitize_url_at_depth(url, depth, charge)?);
        redacted.push_str(trailing);
        offset = capture.end();
    }
    redacted.push_str(&text[offset..]);
    Ok(redacted)
}

fn sanitize_url_at_depth<E>(
    url: &str,
    depth: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    charge(url.len().saturating_mul(64))?;
    let Some((prefix, rest)) = url_prefix_and_authority(url) else {
        return Ok(url.to_string());
    };
    let file_url = prefix.eq_ignore_ascii_case("file://");
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let suffix = &rest[authority_end..];
    // Only raw userinfo delimiters are trusted for preserving the raw host.
    // Decoded structural delimiters make the complete candidate ambiguous.
    let authority = authority
        .rsplit_once('@')
        .map(|(_, authority)| authority)
        .unwrap_or(authority);
    let decoded_authority = percent_decode_bounded(authority);
    if decoded_authority_has_structural_delimiter(&decoded_authority)
        || !(valid_url_authority(&decoded_authority) || file_url && authority.is_empty())
    {
        return Ok(REDACTED_URL.to_string());
    }
    let authority = if contains_credential_material(&decoded_authority) {
        REDACTED_SECRET
    } else {
        authority
    };

    let (before_fragment, fragment) = suffix
        .split_once('#')
        .map_or((suffix, None), |parts| (parts.0, Some(parts.1)));
    let (path, query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(path, query)| (path, Some(query)));
    let sensitive_path = is_sensitive_url_path(path, file_url, charge)?;
    let mut sanitized_suffix = redact_url_path(path, depth, sensitive_path, charge)?;
    if let Some(query) = query {
        sanitized_suffix.push('?');
        sanitized_suffix.push_str(&redact_query_values(query, depth, charge)?);
    }
    if let Some(fragment) = fragment {
        sanitized_suffix.push('#');
        sanitized_suffix.push_str(&redact_url_component(fragment, depth, charge)?);
    }
    let authority = if file_url && sensitive_path {
        ""
    } else {
        authority
    };
    Ok(format!("{prefix}{authority}{sanitized_suffix}"))
}

fn decoded_authority_has_structural_delimiter(authority: &str) -> bool {
    authority.contains(['/', '\\', '?', '#', '@'])
        || authority
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn url_prefix_and_authority(url: &str) -> Option<(&str, &str)> {
    if let Some((scheme, rest)) = url
        .split_once("://")
        .filter(|(scheme, _)| is_supported_url_scheme(scheme))
    {
        let prefix_length = scheme.len() + 3;
        return Some((&url[..prefix_length], rest));
    }
    url.strip_prefix("//").map(|rest| ("//", rest))
}

fn has_supported_absolute_url_prefix(url: &str) -> bool {
    url_prefix_and_authority(url).is_some_and(|(prefix, _)| prefix != "//")
}

fn is_supported_url_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
}

fn split_url_trailing_punctuation(url: &str) -> (&str, &str) {
    let mut end = url.len();
    while !url[..end].ends_with(REDACTED_SECRET)
        && end > 0
        && matches!(
            url.as_bytes()[end - 1],
            b'.' | b',' | b';' | b'!' | b')' | b']' | b'}'
        )
    {
        end -= 1;
    }
    (&url[..end], &url[end..])
}

fn valid_url_authority(authority: &str) -> bool {
    if authority.is_empty() || authority.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return false;
    }
    if authority.starts_with('[') {
        let Some(closing) = authority.find(']') else {
            return false;
        };
        let suffix = &authority[closing + 1..];
        return closing > 1
            && (suffix.is_empty()
                || suffix.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
                }));
    }
    if authority.contains(['[', ']']) {
        return false;
    }
    match authority.split_once(':') {
        None => true,
        Some((host, port)) => {
            !host.is_empty()
                && !port.is_empty()
                && !port.contains(':')
                && port.bytes().all(|byte| byte.is_ascii_digit())
        }
    }
}

fn redact_query_values<E>(
    query: &str,
    depth: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    charge(query.len().saturating_mul(8))?;
    query
        .split_inclusive(['&', ';'])
        .map(|segment| {
            let (body, separator) = segment.strip_suffix('&').map_or_else(
                || {
                    segment
                        .strip_suffix(';')
                        .map_or((segment, ""), |body| (body, ";"))
                },
                |body| (body, "&"),
            );
            let Some((name, value)) = body.split_once('=') else {
                return Ok(segment.to_string());
            };
            if sensitive_query_name(name) {
                Ok(format!("{name}={REDACTED_SECRET}{separator}"))
            } else {
                // A safe query key does not make its value safe: values can
                // contain assignments or host paths copied from diagnostics,
                // including URL-encoded forms.
                let value = redact_url_component(value, depth, charge)?;
                Ok(format!("{name}={value}{separator}"))
            }
        })
        .collect()
}

fn sensitive_query_name(name: &str) -> bool {
    let decoded = percent_decode_bounded(name);
    let normalized = decoded
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "apikey"
            | "accesstoken"
            | "accesskey"
            | "authorization"
            | "auth"
            | "bearer"
            | "clientsecret"
            | "credential"
            | "credentials"
            | "key"
            | "password"
            | "passwd"
            | "privatekey"
            | "refreshtoken"
            | "secret"
            | "sig"
            | "signature"
            | "token"
            | "xamzsignature"
    ) || [
        "apikey",
        "accesstoken",
        "accesskey",
        "clientsecret",
        "credential",
        "password",
        "secret",
        "token",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix))
}

fn redact_url_component<E>(
    value: &str,
    depth: usize,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    let decoded = decode_url_component_for_inspection(value, charge)?;
    charge(decoded.len().saturating_mul(16))?;
    if contains_credential_material(&decoded) {
        return Ok(REDACTED_SECRET.to_string());
    }
    if depth >= MAX_NESTED_URL_DEPTH && URL_RE.is_match(&decoded) {
        return Ok("[nested-url]".to_string());
    }
    let inspected = redact_urls_at_depth(&decoded, depth + 1, charge)?;
    let inspected = redact_assignments(&inspected, true, charge)?;
    charge(inspected.len().saturating_mul(16))?;
    let inspected = redact_paths_outside_urls(&inspected, SENSITIVE_PATH);
    Ok(if inspected == decoded {
        value.to_string()
    } else if inspected.contains(['&', ';', '?', '#']) {
        // A decoded component must not introduce a new outer URL boundary.
        REDACTED_SECRET.to_string()
    } else {
        inspected
    })
}

fn redact_url_path<E>(
    value: &str,
    depth: usize,
    sensitive_path: bool,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<String, E> {
    charge(value.len())?;
    if sensitive_path {
        return Ok(if value.starts_with('/') {
            format!("/{SENSITIVE_PATH}")
        } else {
            SENSITIVE_PATH.to_string()
        });
    }
    let decoded = decode_url_component_for_inspection(value, charge)?;
    charge(decoded.len().saturating_mul(16))?;
    if contains_credential_material(&decoded) {
        return Ok(path_component_replacement(value, REDACTED_SECRET));
    }
    if depth >= MAX_NESTED_URL_DEPTH && URL_RE.is_match(&decoded) {
        return Ok(path_component_replacement(value, "[nested-url]"));
    }
    let inspected = redact_urls_at_depth(&decoded, depth + 1, charge)?;
    let inspected = redact_assignments(&inspected, true, charge)?;
    charge(inspected.len())?;
    Ok(if inspected == decoded {
        value.to_string()
    } else if inspected.contains(['?', '#']) {
        // Keep path-local decoding from creating a query or fragment.
        path_component_replacement(value, REDACTED_SECRET)
    } else {
        inspected
    })
}

fn path_component_replacement(value: &str, replacement: &str) -> String {
    if value.starts_with('/') {
        format!("/{replacement}")
    } else {
        replacement.to_string()
    }
}

fn is_sensitive_url_path<E>(
    value: &str,
    file_url: bool,
    charge: &mut impl FnMut(usize) -> Result<(), E>,
) -> Result<bool, E> {
    charge(value.len().saturating_mul(4))?;
    if value.is_empty() {
        return Ok(false);
    }
    if file_url {
        return Ok(true);
    }

    let decoded = decode_url_component_for_inspection(value, charge)?;
    charge(decoded.len().saturating_mul(8))?;
    if CREDENTIAL_PATH_RE.is_match(&decoded) || DOT_ENV_PATH_RE.is_match(&decoded) {
        return Ok(true);
    }

    let normalized = decoded.replace('\\', "/").to_ascii_lowercase();
    let normalized = normalized.as_str();
    Ok(normalized.starts_with("/home/")
        || normalized.starts_with("/root/")
        || normalized.starts_with("/users/")
        || normalized.starts_with("/private/")
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/var/lib/")
        || normalized.starts_with("/var/log/")
        || normalized.starts_with("/var/run/")
        || normalized.as_bytes().get(..10).is_some_and(|prefix| {
            prefix.len() >= 10
                && prefix[0] == b'/'
                && prefix[1].is_ascii_alphabetic()
                && &prefix[2..10] == b":/users/"
        })
        || (normalized.starts_with("//") && normalized.contains("/users/"))
        || normalized.contains("/.ssh/")
        || normalized.contains("/.aws/"))
}

fn percent_decode_bounded(value: &str) -> String {
    let mut decoded = value.to_string();
    for _ in 0..MAX_PERCENT_DECODE_DEPTH {
        let next = percent_decode_once(&decoded);
        if next == decoded {
            break;
        }
        decoded = next;
    }
    decoded
}

fn percent_decode_once(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push(high * 16 + low);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn redact_paths(text: &str, marker: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;
    for url in URL_RE.find_iter(text) {
        redacted.push_str(&redact_paths_outside_urls(
            &text[offset..url.start()],
            marker,
        ));
        // URLs have already been structurally sanitized. Do not mistake their
        // hierarchy for host paths on this later pass. A punctuation-delimited
        // absolute path is outside the URL even when source text omits spaces.
        let (url_text, path_text) = split_url_before_absolute_path(url.as_str());
        redacted.push_str(url_text);
        redacted.push_str(&redact_paths_outside_urls(path_text, marker));
        offset = url.end();
    }
    redacted.push_str(&redact_paths_outside_urls(&text[offset..], marker));
    redacted
}

fn redact_encoded_blobs_outside_urls(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;
    for url in URL_RE.find_iter(text) {
        redacted.push_str(&mask_encoded_blobs(&text[offset..url.start()]));
        redacted.push_str(url.as_str());
        offset = url.end();
    }
    redacted.push_str(&mask_encoded_blobs(&text[offset..]));
    redacted
}

/// Mask a run of twenty or more blob characters only when it looks encoded.
/// Base64 and hex carry digits or padding; a long mixed-case identifier (a
/// registry value name or a Pascal-case cmdlet noun) carries neither and tells
/// a reviewer what the action did. This is a heuristic, not a decoder:
/// encoded data that is mixed case, has fewer than two digits and no `+`, `/`
/// or `=` is kept.
fn mask_encoded_blobs(text: &str) -> std::borrow::Cow<'_, str> {
    ENCODED_BLOB_RE.replace_all(text, |captures: &regex::Captures<'_>| {
        let token = &captures[0];
        if looks_encoded(token) {
            "[encoded-blob]".to_string()
        } else {
            token.to_string()
        }
    })
}

fn looks_encoded(token: &str) -> bool {
    let digits = token.chars().filter(char::is_ascii_digit).count();
    if digits >= 2 || token.contains(['+', '/', '=']) {
        return true;
    }
    // No digits and no padding: an identifier is mixed case (camel or Pascal
    // case). A single-case run of letters is still treated as a blob (hex
    // spelled from a-f alone, a padding run).
    let upper = token.chars().any(|c| c.is_ascii_uppercase());
    let lower = token.chars().any(|c| c.is_ascii_lowercase());
    !(upper && lower)
}

/// A bare `/word` is far more often a command flag (`cmd.exe /c`, `reg add
/// /v`, `schtasks /create`) than a path. One segment of 1-16 characters from
/// `[A-Za-z0-9_-]` is kept, including a bare top-level directory such as
/// `/etc`. Anything with more shape (`/home/u`, `/tmp/x.sh`, `~/notes`) is
/// still a path.
fn is_flag_like(path: &str) -> bool {
    let Some(word) = path.strip_prefix('/') else {
        return false;
    };
    !word.is_empty()
        && word.len() <= 16
        && word
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn split_url_before_absolute_path(url: &str) -> (&str, &str) {
    for (offset, character) in url.char_indices() {
        if matches!(character, ';' | ',' | '|' | '`' | '(' | '[' | '{') {
            let path_start = offset + character.len_utf8();
            if url[path_start..].starts_with('/') {
                return url.split_at(path_start);
            }
        }
    }
    (url, "")
}

fn redact_paths_outside_urls(text: &str, marker: &str) -> String {
    let redacted = redact_windows_paths(text, marker);
    let redacted = POSIX_PRIVATE_PATH_RE
        .replace_all(&redacted, |captures: &regex::Captures<'_>| {
            let whole = &captures[0];
            let path = &whole[captures["prefix"].len()..];
            if is_flag_like(path) {
                return whole.to_string();
            }
            format!("{}{}", &captures["prefix"], marker)
        })
        .into_owned();
    let redacted = DOT_ENV_PATH_RE
        .replace_all(&redacted, |captures: &regex::Captures<'_>| {
            format!("{marker}{}", &captures["boundary"])
        })
        .into_owned();
    CREDENTIAL_PATH_RE
        .replace_all(&redacted, marker)
        .into_owned()
}

/// Redact Windows device, NT object-namespace, UNC, drive, and backslash home
/// paths in one pass. A leading boundary capture is preserved; doubled
/// backslash escape runs such as `\\r\\n` or `\\u0061\\u0062` are skipped
/// without skipping any path that follows them.
fn redact_windows_paths(text: &str, marker: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(captures) = WINDOWS_PATH_RE.captures_at(text, search) {
        let whole = captures.get(0).expect("whole match");
        if let (Some(start), Some(server), Some(sep)) = (
            captures.name("unc_start"),
            captures.name("unc_server"),
            captures.name("unc_sep"),
        ) && is_escaped_sequence_not_unc(
            start.as_str(),
            server.as_str(),
            sep.as_str(),
            &text[sep.end()..whole.end()],
        ) {
            search = start.end();
            continue;
        }
        let lead = path_lead(&captures);
        let span_start = whole.start() + lead;
        let split_end = split_before_chained_path_after_escape(text, span_start, whole.end());
        let trimmed_end = trim_trailing_escaped_whitespace(text, span_start, split_end);
        let span_end = extend_spaced_filename(text, span_start, trimmed_end);
        redacted.push_str(&text[copied..span_start]);
        redacted.push_str(marker);
        copied = span_end;
        search = span_end;
    }
    redacted.push_str(&text[copied..]);
    redacted
}

/// What a path start needs beyond its prefix: the colon, a first separator
/// and one component character, with room for an escaped separator.
const PATH_START_TAIL_BYTES: usize = 32;

/// A match that stops right before `:` may have run from one path through an
/// escaped line break into the drive letter of the next
/// (`C:\Temp\a.txt\nC:\Users\secret.txt`, or the same with a `\\?\` or
/// `\??\` prefix, however often escaped). The end of the first path, so that
/// the second is matched whole on the next pass instead of leaving its tail
/// after the marker.
///
/// The second path's start is read back from the match's end: its drive
/// letter, then the backslashes, `?` and `.` of a device prefix, then the
/// escape. One path-start test follows, over text no longer than twice that
/// prefix, so the work is bounded by the match.
fn split_before_chained_path_after_escape(text: &str, span_start: usize, span_end: usize) -> usize {
    if !text[span_end..].starts_with(':') {
        return span_end;
    }
    let bytes = text.as_bytes();
    let mut after_escape = span_end - 1;
    if after_escape <= span_start || !bytes[after_escape].is_ascii_alphabetic() {
        return span_end;
    }
    while after_escape > span_start && matches!(bytes[after_escape - 1], b'\\' | b'?' | b'.') {
        after_escape -= 1;
    }
    // A device prefix's backslashes follow the escape's letter directly, so
    // the walk stops on that letter with the escape's one backslash before it.
    let Some(escape_start) = after_escape.checked_sub(2).filter(|at| *at > span_start) else {
        return span_end;
    };
    if !matches!(bytes[after_escape - 1], b'n' | b'r' | b't')
        || bytes[escape_start] != b'\\'
        || bytes[escape_start - 1] == b'\\'
    {
        return span_end;
    }
    let mut window_end =
        (span_end + (span_end - after_escape) + PATH_START_TAIL_BYTES).min(text.len());
    while !text.is_char_boundary(window_end) {
        window_end -= 1;
    }
    if !starts_windows_path(&text[after_escape..window_end]) {
        return span_end;
    }
    // A drive letter cannot follow a component, so this escape is one
    // whatever precedes it; earlier ones are trimmed by the usual rule.
    let first_end = trim_trailing_escaped_whitespace(text, span_start, escape_start);
    if is_complete_windows_path(&text[span_start..first_end]) {
        first_end
    } else {
        span_end
    }
}

/// The length of the boundary a Windows path match captured before the path.
fn path_lead(captures: &regex::Captures<'_>) -> usize {
    [
        "win32_lead",
        "nt_lead",
        "unc_lead",
        "drive_lead",
        "home_lead",
    ]
    .iter()
    .find_map(|name| captures.name(name))
    .map_or(0, |lead| lead.len())
}

/// Whether a Windows path match begins at the first byte of `candidate`.
fn starts_windows_path(candidate: &str) -> bool {
    WINDOWS_PATH_RE.captures(candidate).is_some_and(|captures| {
        let lead = path_lead(&captures);
        captures.get(0).expect("whole match").start() + lead == 0
    })
}

/// Keeps a trailing single-backslash escape (`\n`, `\r`, `\t`) outside a
/// complete Windows path, so an escaped line break after a path is not taken
/// into the marker.
///
/// In text such as `C:\Users\Alice\n Notes.txt` the same bytes can be a
/// component named `n Notes.txt`, and trimming would leave that name
/// readable. The escape is trimmed only where it cannot be a component: the
/// path's separators are doubled, so a single backslash separates nothing, or
/// the component before it is a file name with an extension, which has no
/// children. Anything else stays in the marker.
///
/// The trailing run is peeled in one pass and the result validated at most
/// twice, so the work is linear in the match.
fn trim_trailing_escaped_whitespace(text: &str, span_start: usize, span_end: usize) -> usize {
    let mut trimmed = span_end;
    while trimmed >= span_start + 2 {
        let bytes = &text.as_bytes()[span_start..trimmed];
        let last = bytes[bytes.len() - 1];
        if !matches!(last, b'n' | b'r' | b't') {
            break;
        }
        let backslashes = bytes[..bytes.len() - 1]
            .iter()
            .rev()
            .take_while(|&&byte| byte == b'\\')
            .count();
        if backslashes != 1 {
            break;
        }
        trimmed -= 2;
    }
    if trimmed == span_end {
        return span_end;
    }
    [trimmed, trimmed + 2]
        .into_iter()
        .filter(|end| *end < span_end)
        .find(|end| {
            let path = &text[span_start..*end];
            escape_cannot_be_component(path) && is_complete_windows_path(path)
        })
        .unwrap_or(span_end)
}

/// Whether a single-backslash escape after `path` cannot be read as a
/// separator and the start of another component.
fn escape_cannot_be_component(path: &str) -> bool {
    let (before, last) = match path.rfind(['\\', '/']) {
        Some(separator) => (&path[..separator], &path[separator + 1..]),
        None => return false,
    };
    before.ends_with('\\') || has_filename_extension(last)
}

fn is_complete_windows_path(candidate: &str) -> bool {
    WINDOWS_PATH_RE.captures(candidate).is_some_and(|captures| {
        let whole = captures.get(0).expect("whole match");
        if let (Some(start), Some(server), Some(sep)) = (
            captures.name("unc_start"),
            captures.name("unc_server"),
            captures.name("unc_sep"),
        ) && is_escaped_sequence_not_unc(
            start.as_str(),
            server.as_str(),
            sep.as_str(),
            &candidate[sep.end()..whole.end()],
        ) {
            return false;
        }
        let lead = path_lead(&captures);
        whole.start() + lead == 0
            && extend_spaced_filename(candidate, 0, whole.end()) == candidate.len()
    })
}

/// Extend a Windows path match across spaces in its final component when the
/// continuation clearly belongs to the filename rather than following command
/// arguments:
/// - When the matched final segment already carries a file extension, stop so
///   following arguments (`file.txt now`, `"a.exe arg2"`) are not swallowed.
/// - Otherwise, inside matching quotes opened immediately before the path,
///   extend across plain words up to the closing quote (or the first
///   extension-bearing word if a flag follows).
/// - Outside quotes, extend across plain words through the first
///   extension-bearing word (e.g. `C:\Users\Alice\Private Notes.txt`),
///   stopping before flags (`-...`), assignments (`=`), newlines, or
///   delimiters.
fn extend_spaced_filename(text: &str, span_start: usize, match_end: usize) -> usize {
    let last_segment = text[span_start..match_end]
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("");
    if has_filename_extension(last_segment) {
        return match_end;
    }
    let opening_quote = opening_path_quote(text, span_start);
    let mut cursor = match_end;
    let mut best_end = match_end;
    while text[cursor..].starts_with(' ') {
        let rest = text[cursor..].trim_start_matches(' ');
        let word_start = text.len() - rest.len();
        let word_end = word_start
            + rest
                .find(|c: char| {
                    c.is_whitespace()
                        || matches!(
                            c,
                            '\\' | '/'
                                | '<'
                                | '>'
                                | '"'
                                | '\''
                                | '`'
                                | ','
                                | ';'
                                | '('
                                | ')'
                                | '['
                                | ']'
                                | '{'
                                | '}'
                                | ':'
                                | '&'
                                | '|'
                                | '='
                        )
                })
                .unwrap_or(rest.len());
        let word = &text[word_start..word_end];
        if word.is_empty() || word.starts_with('-') {
            break;
        }
        let (candidate, candidate_end) = match word.strip_suffix('.') {
            Some(trimmed) if has_filename_extension(trimmed) => (trimmed, word_end - 1),
            _ => (word, word_end),
        };
        if let Some((quote, escaped)) = opening_quote {
            let after = &text[word_end..];
            let closes_quote = if escaped {
                after.starts_with(&format!("\\{quote}"))
            } else {
                after.starts_with(quote)
            };
            if closes_quote {
                return word_end;
            }
            if has_filename_extension(candidate) {
                return candidate_end;
            }
            if after.starts_with(' ') {
                cursor = word_end;
                continue;
            }
            break;
        }
        if has_filename_extension(candidate) {
            best_end = candidate_end;
            break;
        }
        cursor = word_end;
    }
    best_end
}

fn opening_path_quote(text: &str, span_start: usize) -> Option<(char, bool)> {
    let prefix = &text[..span_start];
    let quote = prefix.chars().next_back()?;
    if !matches!(quote, '"' | '\'' | '`') {
        return None;
    }
    let escaped = prefix[..prefix.len() - quote.len_utf8()].ends_with('\\');
    Some((quote, escaped))
}

fn has_filename_extension(segment: &str) -> bool {
    let Some((stem, ext)) = segment.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty()
        && (1..=8).contains(&ext.len())
        && ext.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// Distinguish doubled-backslash escape sequences (`\\r\\n`, `\\n\\t`,
/// `\\u0061\\u0062`, `\\x0d\\x0a`) from mixed-width UNC paths whose server
/// separator is doubled (`\\fileserver\\share`).
fn is_escaped_sequence_not_unc(start: &str, server: &str, sep: &str, following: &str) -> bool {
    if start.len() != 2 || sep.len() < 2 {
        return false;
    }
    server.len() == 1
        || is_unicode_or_hex_escape(server)
        || (is_regex_class_component(server)
            && following
                .split(['\\', '/'])
                .next()
                .is_some_and(is_regex_class_component))
}

fn is_regex_class_component(component: &str) -> bool {
    matches!(
        component.as_bytes(),
        [b'd' | b'D' | b's' | b'S' | b'w' | b'W']
            | [b'd' | b'D' | b's' | b'S' | b'w' | b'W', b'+' | b'*' | b'?']
    )
}

fn is_unicode_or_hex_escape(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    (bytes.len() == 5
        && bytes[0].eq_ignore_ascii_case(&b'u')
        && bytes[1..].iter().all(u8::is_ascii_hexdigit))
        || (bytes.len() == 3
            && bytes[0].eq_ignore_ascii_case(&b'x')
            && bytes[1..].iter().all(u8::is_ascii_hexdigit))
}

fn path_marker(context: SanitizationContext) -> &'static str {
    if context == SanitizationContext::Diagnostic {
        DIAGNOSTIC_PATH
    } else {
        SENSITIVE_PATH
    }
}

fn max_output_bytes(context: SanitizationContext) -> usize {
    match context {
        SanitizationContext::Diagnostic => MAX_DIAGNOSTIC_BYTES,
        SanitizationContext::Path => MAX_PATH_BYTES,
        SanitizationContext::Evidence
        | SanitizationContext::Url
        | SanitizationContext::CommandResult
        | SanitizationContext::Summary
        | SanitizationContext::Metadata => MAX_REDACTED_EVIDENCE_BYTES,
    }
}

fn truncate_utf8_bytes(text: &str, maximum: usize, suffix: &str) -> String {
    if text.len() <= maximum {
        return text.to_string();
    }
    if suffix.len() >= maximum {
        return String::new();
    }
    let mut end = maximum - suffix.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{suffix}", &text[..end])
}

struct BoundedInput {
    text: String,
    was_truncated: bool,
}

/// Bound input before any pattern processing. The truncation state is kept
/// separately so a terminal fragment is quarantined before classification.
fn bounded_input(text: &str) -> BoundedInput {
    BoundedInput {
        text: truncate_utf8_bytes(text, MAX_INPUT_BYTES, ""),
        was_truncated: text.len() > MAX_INPUT_BYTES,
    }
}

/// If the bound cuts through a lexical fragment, discard that fragment rather
/// than letting compaction promote an unclassified prefix into emitted text.
fn neutralize_truncated_tail(bounded: &str) -> String {
    let Some(fragment_start) = truncated_fragment_start(bounded) else {
        return bounded.to_string();
    };

    let prefix_limit = MAX_INPUT_BYTES.saturating_sub(TRUNCATED_TAIL_MARKER.len());
    let prefix = truncate_utf8_bytes(&bounded[..fragment_start], prefix_limit, "");
    format!("{prefix}{TRUNCATED_TAIL_MARKER}")
}

/// Return the beginning of the final fragment when the cut falls inside one.
/// Whitespace inside a quoted value is kept part of that fragment, so a
/// truncated assignment cannot expose a suffix after its last internal space.
fn truncated_fragment_start(text: &str) -> Option<usize> {
    let mut fragment_start = 0;
    let mut scanner = FragmentScanner::default();
    for (offset, character) in text.char_indices() {
        if scanner.step(character) {
            fragment_start = offset + character.len_utf8();
        }
    }

    if text.is_empty() || text.chars().next_back().is_some_and(char::is_whitespace) {
        None
    } else {
        Some(fragment_start)
    }
}

/// The fragment rule shared by every cut: whitespace ends a fragment only
/// outside a quoted value, and a backslash escapes inside one.
#[derive(Clone, Copy, Default)]
struct FragmentScanner {
    quote: Option<char>,
    escaped: bool,
}

impl FragmentScanner {
    /// Advance by one character; true when it is a fragment boundary.
    fn step(&mut self, character: char) -> bool {
        if let Some(active_quote) = self.quote {
            if self.escaped {
                self.escaped = false;
            } else if character == '\\' {
                self.escaped = true;
            } else if character == active_quote {
                self.quote = None;
            }
            return false;
        }
        if character == '"' || character == '\'' {
            self.quote = Some(character);
            false
        } else {
            character.is_whitespace()
        }
    }
}

#[cfg(test)]
mod tests;
