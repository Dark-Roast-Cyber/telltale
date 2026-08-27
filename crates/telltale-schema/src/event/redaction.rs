use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};

const MAX_INPUT_BYTES: usize = 4096;
const MAX_REDACTED_EVIDENCE_BYTES: usize = 512;
const MAX_DIAGNOSTIC_BYTES: usize = 200;
const MAX_PATH_BYTES: usize = 256;
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

static PRIVATE_KEY_PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b((RSA|OPENSSH|EC|DSA)\s+)?PRIVATE\s+KEY\b")
        .expect("private key phrase regex")
});

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b[a-z][a-z0-9+.-]*:)?//[^\s<>\"']+"#).expect("URL regex")
});

static WINDOWS_OR_UNC_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:\b[A-Z]:\\(?:[^\s\\<>\"'`,;()\[\]{}:&|]+(?:\s+[^\s\\<>\"'`,;()\[\]{}:&|]+)*\\)*[^\s\\<>\"'`,;()\[\]{}:&|]+|\\\\[^\s\\<>\"'`,;()\[\]{}:&|]+\\(?:[^\s\\<>\"'`,;()\[\]{}:&|]+(?:\s+[^\s\\<>\"'`,;()\[\]{}:&|]+)*\\)*[^\s\\<>\"'`,;()\[\]{}:&|]+)"#,
    )
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
    Regex::new(r"(?i)\bxox[baprs]-[A-Za-z0-9-]{20,}\b").expect("credential regex")
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
        let bounded = bounded_input(text);
        let mut redacted = if bounded.was_truncated {
            neutralize_truncated_tail(&bounded.text)
        } else {
            bounded.text
        };
        redacted = redact_encoded_url_candidates(&redacted);
        redacted = redact_urls(&redacted);
        redacted = PRIVATE_KEY_BLOCK_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = redact_assignments(&redacted, true);
        redacted = redacted.replace(
            "https://darkroastcyber.io/mcp-lab",
            "https://darkroastcyber.io/[redacted]",
        );
        redacted = redacted.replace("darkroastcyber.io", "[controlled-domain]");
        redacted = redact_sensitive_labels(&redacted);
        redacted = PACKAGE_MANAGER_RE
            .replace_all(&redacted, "[package-manager-command]")
            .into_owned();
        redacted = STARTUP_TARGET_RE
            .replace_all(&redacted, "[startup-target]")
            .into_owned();
        redacted = ENCODED_DECODER_RE
            .replace_all(&redacted, "[encoded-decoder]")
            .into_owned();
        redacted = redact_paths(&redacted, path_marker(context));
        if context == SanitizationContext::Diagnostic {
            redacted = redacted.replace(SENSITIVE_PATH, DIAGNOSTIC_PATH);
        }
        redacted = PRIVATE_KEY_PHRASE_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = CREDENTIAL_GH_TOKEN_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = CREDENTIAL_SK_KEY_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = CREDENTIAL_AKIA_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = CREDENTIAL_XOX_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = CREDENTIAL_JWT_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = CREDENTIAL_BEARER_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = HIGH_CONFIDENCE_GH_TOKEN_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = HIGH_CONFIDENCE_SK_KEY_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = HIGH_CONFIDENCE_AKIA_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = HIGH_CONFIDENCE_XOX_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = HIGH_CONFIDENCE_JWT_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = HIGH_CONFIDENCE_PRIVATE_KEY_RE
            .replace_all(&redacted, REDACTED_SECRET)
            .into_owned();
        redacted = redact_encoded_blobs_outside_urls(&redacted);

        let normalized = if context == SanitizationContext::CommandResult {
            redacted
        } else {
            redacted
                .split_whitespace()
                .take(80)
                .collect::<Vec<_>>()
                .join(" ")
        };
        truncate_utf8_bytes(&normalized, max_output_bytes(context), TRUNCATED_SUFFIX)
    }
}

/// Compatibility wrapper for existing evidence callers.
pub fn redact_sensitive_text(text: &str) -> String {
    PrivacySanitizer::sanitize(SanitizationContext::Evidence, text)
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

fn redact_assignments(text: &str, allow_flags: bool) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;
    for url in URL_RE.find_iter(text) {
        redacted.push_str(&redact_assignments_outside_urls(
            &text[offset..url.start()],
            allow_flags,
        ));
        // URL credentials and query values have their own structural pass.
        redacted.push_str(url.as_str());
        offset = url.end();
    }
    redacted.push_str(&redact_assignments_outside_urls(
        &text[offset..],
        allow_flags,
    ));
    redacted
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

fn redact_assignments_outside_urls(text: &str, allow_flags: bool) -> String {
    let Some(classified) = decode_assignment_syntax(text) else {
        return redact_literal_assignments(text, allow_flags);
    };
    let mut redacted = String::with_capacity(text.len());
    let mut classified_offset = 0;
    let mut source_offset = 0;

    while classified_offset < classified.text.len() {
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

    redacted
}

fn redact_literal_assignments(text: &str, allow_flags: bool) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;

    while offset < text.len() {
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

    redacted
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
    if let Some(quote @ (b'"' | b'\'')) = value.as_bytes().first().copied()
        && value.as_bytes().last() == Some(&quote)
        && value.len() >= 2
    {
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

fn is_secret_key(key: &str) -> bool {
    let parts = secret_key_parts(key);
    let compact = parts.join("");
    let known = [
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
    known.contains(&compact.as_str())
        || parts
            .last()
            .is_some_and(|part| known.contains(&part.as_str()))
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

fn redact_urls(text: &str) -> String {
    redact_urls_at_depth(text, 0)
}

fn redact_encoded_url_candidates(text: &str) -> String {
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
        redacted.push_str(&sanitize_url_at_depth(url, 0));
        redacted.push_str(trailing);
        source_offset = end;
        scan_offset = end;
    }

    redacted.push_str(&text[source_offset..]);
    redacted
}

fn find_encoded_url_candidate(
    text: &str,
    offset: usize,
    literal_urls: &[(usize, usize)],
) -> Option<(usize, usize, String)> {
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
fn decode_url_component_for_inspection(value: &str) -> String {
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
    decoded
}

fn redact_urls_at_depth(text: &str, depth: usize) -> String {
    URL_RE
        .replace_all(text, |captures: &regex::Captures<'_>| {
            let url = captures.get(0).map_or("", |capture| capture.as_str());
            let (url, trailing) = split_url_trailing_punctuation(url);
            format!("{}{}", sanitize_url_at_depth(url, depth), trailing)
        })
        .into_owned()
}

fn sanitize_url_at_depth(url: &str, depth: usize) -> String {
    let Some((prefix, rest)) = url_prefix_and_authority(url) else {
        return url.to_string();
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
        return REDACTED_URL.to_string();
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
    let sensitive_path = is_sensitive_url_path(path, file_url);
    let mut sanitized_suffix = redact_url_path(path, depth, sensitive_path);
    if let Some(query) = query {
        sanitized_suffix.push('?');
        sanitized_suffix.push_str(&redact_query_values(query, depth));
    }
    if let Some(fragment) = fragment {
        sanitized_suffix.push('#');
        sanitized_suffix.push_str(&redact_url_component(fragment, depth));
    }
    let authority = if file_url && sensitive_path {
        ""
    } else {
        authority
    };
    format!("{prefix}{authority}{sanitized_suffix}")
}

fn decoded_authority_has_structural_delimiter(authority: &str) -> bool {
    authority.contains(['/', '\\', '?', '#', '@'])
        || authority
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn url_prefix_and_authority(url: &str) -> Option<(&str, &str)> {
    if let Some((scheme, rest)) = url.split_once("://")
        && is_supported_url_scheme(scheme)
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

fn redact_query_values(query: &str, depth: usize) -> String {
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
                return segment.to_string();
            };
            if sensitive_query_name(name) {
                format!("{name}={REDACTED_SECRET}{separator}")
            } else {
                // A safe query key does not make its value safe: values can
                // contain assignments or host paths copied from diagnostics,
                // including URL-encoded forms.
                let value = redact_url_component(value, depth);
                format!("{name}={value}{separator}")
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

fn redact_url_component(value: &str, depth: usize) -> String {
    let decoded = decode_url_component_for_inspection(value);
    if contains_credential_material(&decoded) {
        return REDACTED_SECRET.to_string();
    }
    if depth >= MAX_NESTED_URL_DEPTH && URL_RE.is_match(&decoded) {
        return "[nested-url]".to_string();
    }
    let inspected = redact_urls_at_depth(&decoded, depth + 1);
    let inspected = redact_assignments(&inspected, true);
    let inspected = redact_paths_outside_urls(&inspected, SENSITIVE_PATH);
    if inspected == decoded {
        value.to_string()
    } else if inspected.contains(['&', ';', '?', '#']) {
        // A decoded component must not introduce a new outer URL boundary.
        REDACTED_SECRET.to_string()
    } else {
        inspected
    }
}

fn redact_url_path(value: &str, depth: usize, sensitive_path: bool) -> String {
    if sensitive_path {
        return if value.starts_with('/') {
            format!("/{SENSITIVE_PATH}")
        } else {
            SENSITIVE_PATH.to_string()
        };
    }
    let decoded = decode_url_component_for_inspection(value);
    if contains_credential_material(&decoded) {
        return path_component_replacement(value, REDACTED_SECRET);
    }
    if depth >= MAX_NESTED_URL_DEPTH && URL_RE.is_match(&decoded) {
        return path_component_replacement(value, "[nested-url]");
    }
    let inspected = redact_urls_at_depth(&decoded, depth + 1);
    let inspected = redact_assignments(&inspected, true);
    if inspected == decoded {
        value.to_string()
    } else if inspected.contains(['?', '#']) {
        // Keep path-local decoding from creating a query or fragment.
        path_component_replacement(value, REDACTED_SECRET)
    } else {
        inspected
    }
}

fn path_component_replacement(value: &str, replacement: &str) -> String {
    if value.starts_with('/') {
        format!("/{replacement}")
    } else {
        replacement.to_string()
    }
}

fn is_sensitive_url_path(value: &str, file_url: bool) -> bool {
    if value.is_empty() {
        return false;
    }
    if file_url {
        return true;
    }

    let decoded = decode_url_component_for_inspection(value);
    if CREDENTIAL_PATH_RE.is_match(&decoded) || DOT_ENV_PATH_RE.is_match(&decoded) {
        return true;
    }

    let normalized = decoded.replace('\\', "/").to_ascii_lowercase();
    let normalized = normalized.as_str();
    normalized.starts_with("/home/")
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
        || normalized.contains("/.aws/")
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
        redacted
            .push_str(&ENCODED_BLOB_RE.replace_all(&text[offset..url.start()], "[encoded-blob]"));
        redacted.push_str(url.as_str());
        offset = url.end();
    }
    redacted.push_str(&ENCODED_BLOB_RE.replace_all(&text[offset..], "[encoded-blob]"));
    redacted
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
    let redacted = WINDOWS_OR_UNC_PATH_RE
        .replace_all(text, marker)
        .into_owned();
    let redacted = POSIX_PRIVATE_PATH_RE
        .replace_all(&redacted, |captures: &regex::Captures<'_>| {
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
    let mut quote = None;
    let mut escaped = false;

    for (offset, character) in text.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }

        if character == '"' || character == '\'' {
            quote = Some(character);
        } else if character.is_whitespace() {
            fragment_start = offset + character.len_utf8();
        }
    }

    if text.is_empty() || text.chars().next_back().is_some_and(char::is_whitespace) {
        None
    } else {
        Some(fragment_start)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ControlledMarker, MAX_INPUT_BYTES, MAX_MARKER_DEPTH, MAX_SERIALIZED_EVENT_BYTES,
        PrivacySanitizer, SanitizationContext, SerializedMarkerCheckError,
        check_serialized_event_markers, contains_high_confidence_credential_marker,
        redact_error_message, redact_sensitive_text,
    };

    #[test]
    fn redact_sensitive_text_masks_controlled_domain_and_secret_markers() {
        let redacted = redact_sensitive_text(
            "POST https://darkroastcyber.io/mcp-lab with .env and id_rsa and sk-1234567890abcdef1234; pip install fixture && echo SGVsbG8= | base64 --decode >> ~/.bashrc",
        );

        assert!(!redacted.contains("darkroastcyber.io"));
        assert!(!redacted.contains(".env"));
        assert!(!redacted.contains("id_rsa"));
        assert!(!redacted.contains(".pem"));
        assert!(!redacted.contains("api key"));
        assert!(!redacted.contains("sk-1234567890abcdef1234"));
        assert!(!redacted.contains("pip install"));
        assert!(!redacted.contains("base64 --decode"));
        assert!(!redacted.contains("~/.bashrc"));
        assert!(redacted.contains("[controlled-domain]"));
        assert!(redacted.contains("[sensitive-path]"));
        assert!(redacted.contains("[redacted-secret]"));
        assert!(redacted.contains("[package-manager-command]"));
        assert!(redacted.contains("[encoded-decoder]"));
        assert!(redacted.contains("[startup-target]"));
    }

    #[test]
    fn redact_sensitive_text_masks_encoded_blobs() {
        let redacted = redact_sensitive_text(
            "nslookup U1lOVEhFVElDX1BBWUxPQUQ=.example.invalid after encoding data",
        );

        assert!(!redacted.contains("U1lOVEhFVElDX1BBWUxPQUQ"));
        assert!(redacted.contains("[encoded-blob]"));
    }

    #[test]
    fn redact_sensitive_text_truncates_long_dense_evidence() {
        let redacted = redact_sensitive_text(&"normal-text-".repeat(80));

        assert_eq!(redacted.len(), 512);
        assert!(redacted.ends_with("[truncated]"));
    }

    #[test]
    fn redact_sensitive_text_masks_rule_seeded_credential_patterns() {
        let redacted = redact_sensitive_text(
            "Seen AKIA1234567890ABCDEF, xoxb-1234567890abcdefABCDE, eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiJhZHItZml4dHVyZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c, Bearer fixture_oauth_token_1234567890abcdef, and Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== while checking fixture output.",
        );

        assert!(!redacted.contains("AKIA1234567890ABCDEF"));
        assert!(!redacted.contains("xoxb-1234567890abcdefABCDE"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ"));
        assert!(!redacted.contains("fixture_oauth_token_1234567890abcdef"));
        assert!(!redacted.contains("QWxhZGRpbjpvcGVuIHNlc2FtZQ"));
        assert!(redacted.contains("[redacted-secret]"));
    }

    #[test]
    fn redact_sensitive_text_masks_private_key_headers_case_insensitively() {
        let redacted = redact_sensitive_text(
            "Command output: -----BEGIN OpenSSH PRIVATE KEY----- synthetic-fixture-body -----END OpenSSH PRIVATE KEY-----",
        );

        assert!(!redacted.contains("BEGIN"));
        assert!(!redacted.contains("END"));
        assert!(!redacted.contains("PRIVATE KEY"));
        assert!(!redacted.contains("OpenSSH"));
        assert!(redacted.contains("[redacted-secret]"));
    }

    #[test]
    fn privacy_corpus_masks_structured_url_key_and_path_markers() {
        let redacted = redact_sensitive_text(
            "API_KEY=\"TT_PRIVACY_ASSIGNMENT_25\"; https://user:TT_PRIVACY_URL_25@example.invalid/run?%74%6f%6b%65%6e=TT_PRIVACY_QUERY_25&safe=value#section; -----BEGIN PRIVATE KEY-----\nTT_PRIVACY_PEM_25\n-----END PRIVATE KEY-----; C:\\Users\\TT_PRIVACY_USER_25\\.ssh\\id_ed25519",
        );

        for marker in [
            "TT_PRIVACY_ASSIGNMENT_25",
            "TT_PRIVACY_URL_25",
            "TT_PRIVACY_QUERY_25",
            "TT_PRIVACY_PEM_25",
            "TT_PRIVACY_USER_25",
        ] {
            assert!(!redacted.contains(marker));
        }
        assert!(redacted.contains("API_KEY=\"[redacted-secret]\""));
        assert!(redacted.contains("safe=value#section"));
        assert!(redacted.contains("[sensitive-path]"));
    }

    #[test]
    fn privacy_corpus_handles_assignment_variants_without_greedy_consumption() {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::CommandResult,
            r#"{"Api_Key":"TT_PRIVACY_JSON_25","safe":"ok"}; export GitHub_Token = 'TT_PRIVACY_SHELL_25'; $env:SECRET = "TT_PRIVACY_POWERSHELL_25"; .env API_TOKEN="TT_PRIVACY_ENV_25\"escaped"; Authorization: Bearer TT_PRIVACY_HEADER_25; token: |
  TT_PRIVACY_MULTILINE_25
next=value; tokenizer=ordinary"#,
        );

        for (index, marker) in [
            "TT_PRIVACY_JSON_25",
            "TT_PRIVACY_SHELL_25",
            "TT_PRIVACY_POWERSHELL_25",
            "TT_PRIVACY_ENV_25",
            "TT_PRIVACY_HEADER_25",
            "TT_PRIVACY_MULTILINE_25",
        ]
        .into_iter()
        .enumerate()
        {
            assert!(!redacted.contains(marker), "assignment case {index}");
        }
        assert!(redacted.contains("\"Api_Key\":\"[redacted-secret]\""));
        assert!(redacted.contains("GitHub_Token = '[redacted-secret]'"));
        assert!(redacted.contains("next=value"));
        assert!(redacted.contains("tokenizer=ordinary"));
    }

    #[test]
    fn assignment_scanner_handles_quoted_json_and_yaml_keys_with_spaces() {
        let markers = ["tt_privacy_quoted_json_25", "tt_privacy_quoted_yaml_25"];
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::CommandResult,
            r#"{"api key":"tt_privacy_quoted_json_25"}
'api token': tt_privacy_quoted_yaml_25
safe=value"#,
        );

        for marker in markers {
            assert!(!redacted.contains(marker));
        }
        assert!(redacted.contains(r#""api key":"[redacted-secret]""#));
        assert!(redacted.contains("'api token': [redacted-secret]"));
        assert!(redacted.contains("safe=value"));
    }

    #[test]
    fn assignment_scanner_handles_camel_case_secret_keys_and_diagnostic_flags() {
        let markers = [
            "tt_privacy_refresh_token_25",
            "tt_privacy_database_password_25",
            "tt_privacy_secret_key_25",
            "tt_privacy_diagnostic_flag_25",
        ];
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Diagnostic,
            r#""refreshToken": "tt_privacy_refresh_token_25"; "databasePassword": "tt_privacy_database_password_25"; "secretKey": "tt_privacy_secret_key_25"; --secret-key tt_privacy_diagnostic_flag_25"#,
        );

        for marker in markers {
            assert!(!redacted.contains(marker));
        }
        assert!(redacted.contains(r#""refreshToken": "[redacted-secret]""#));
        assert!(redacted.contains(r#""databasePassword": "[redacted-secret]""#));
        assert!(redacted.contains(r#""secretKey": "[redacted-secret]""#));
        assert!(redacted.contains("--secret-key [redacted-secret]"));
    }

    #[test]
    fn path_sanitization_covers_posix_delimiter_boundaries() {
        for input in [
            "error:/opt/tt_privacy_colon_path_25/config",
            "command `/opt/tt_privacy_backtick_path_25/config`",
            "path=[/opt/tt_privacy_bracket_path_25/config]",
            "error;/opt/tt_privacy_semicolon_path_25/config",
            "error,/opt/tt_privacy_comma_path_25/config",
            "error|/opt/tt_privacy_pipe_path_25/config",
        ] {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, input);
            assert!(!redacted.contains("tt_privacy_"), "{input}: {redacted}");
            assert!(redacted.contains("<path>"));
        }
    }

    #[test]
    fn path_sanitization_preserves_url_shape_while_redacting_punctuated_paths() {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Diagnostic,
            "https://example.invalid/safe/path;/opt/tt_privacy_after_url_25/config",
        );

        assert!(
            !redacted.contains("tt_privacy_after_url_25"),
            "redacted output: {redacted}"
        );
        assert!(redacted.contains("https://example.invalid/safe/path;<path>"));
    }

    #[test]
    fn assignment_scanner_fails_closed_for_shell_flags_auth_and_unclosed_quotes() {
        let cases = [
            "TOKEN=?TT_PRIVACY_ASSIGNMENT_QUERY_25",
            r#"API_KEY=\"TT_PRIVACY_ESCAPED_QUOTE_25\""#,
            "--api-key TT_PRIVACY_FLAG_25",
            "Authorization: Negotiate TT_PRIVACY_AUTH_25 additional-value",
            "TOKEN=\"TT_PRIVACY_UNCLOSED_25",
        ];

        for case in cases {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::CommandResult, case);
            assert!(
                !redacted.contains("TT_PRIVACY_"),
                "controlled marker remained in assignment case"
            );
            assert_eq!(
                PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &redacted),
                redacted,
                "assignment sanitization must be idempotent"
            );
        }
    }

    #[test]
    fn sanitization_is_idempotent_for_every_emission_context() {
        let input = "TOKEN=TT_PRIVACY_IDEMPOTENT_25 https://user:TT_PRIVACY_URL_25@example.invalid/path?sig=TT_PRIVACY_SIG_25 /opt/TT_PRIVACY_PATH_25";
        for context in [
            SanitizationContext::Evidence,
            SanitizationContext::Diagnostic,
            SanitizationContext::Url,
            SanitizationContext::Path,
            SanitizationContext::CommandResult,
            SanitizationContext::Summary,
            SanitizationContext::Metadata,
        ] {
            let once = PrivacySanitizer::sanitize(context, input);
            assert_eq!(PrivacySanitizer::sanitize(context, &once), once);
        }
    }

    #[test]
    fn multiline_assignment_sanitization_is_exactly_idempotent_in_every_context() {
        let input = "token: |\n  tt_privacy_multiline_exact_25\nnext=value";
        for context in [
            SanitizationContext::Evidence,
            SanitizationContext::Diagnostic,
            SanitizationContext::Url,
            SanitizationContext::Path,
            SanitizationContext::CommandResult,
            SanitizationContext::Summary,
            SanitizationContext::Metadata,
        ] {
            let once = PrivacySanitizer::sanitize(context, input);
            assert!(!once.contains("tt_privacy_multiline_exact_25"));
            assert!(!once.contains("token: |"));
            assert!(once.contains("next=value"));
            assert_eq!(PrivacySanitizer::sanitize(context, &once), once);
        }
    }

    #[test]
    fn ordinary_bare_text_is_not_classified_as_a_secret() {
        let value = "ordinary-marker";
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Summary, value),
            value
        );
    }

    #[test]
    fn privacy_corpus_preserves_safe_unicode_url_structure() {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            "https://例え.テスト/経路;token=TT_PRIVACY_PARAM_25?SAFE=値&SeCrEt=TT_PRIVACY_QUERY_25#token=TT_PRIVACY_FRAGMENT_25",
        );

        for marker in [
            "TT_PRIVACY_PARAM_25",
            "TT_PRIVACY_QUERY_25",
            "TT_PRIVACY_FRAGMENT_25",
        ] {
            assert!(!redacted.contains(marker));
        }
        assert!(redacted.contains("例え.テスト"));
        assert!(redacted.contains("SAFE=値"));
    }

    #[test]
    fn url_sanitization_covers_signature_key_and_refresh_query_names() {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            "https://example.invalid/object?key=TT_PRIVACY_KEY_25&Refresh_Token=TT_PRIVACY_REFRESH_25&sig=TT_PRIVACY_SIG_25&X-Amz-Signature=TT_PRIVACY_AMZ_25&safe=value",
        );

        for marker in [
            "TT_PRIVACY_KEY_25",
            "TT_PRIVACY_REFRESH_25",
            "TT_PRIVACY_SIG_25",
            "TT_PRIVACY_AMZ_25",
        ] {
            assert!(!redacted.contains(marker));
        }
        assert!(redacted.contains("safe=value"));
        assert!(redacted.contains("X-Amz-Signature=[redacted-secret]"));
    }

    #[test]
    fn url_sanitization_sanitizes_content_inside_safe_query_values() {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            "https://example.invalid/run?message=token:TT_PRIVACY_NESTED_25&encoded=token%3DTT_PRIVACY_ENCODED_NESTED_25&next=%2Fhome%2FTT_PRIVACY_QUERY_PATH_25%2F.ssh%2Fid_rsa&safe=value",
        );

        assert!(!redacted.contains("TT_PRIVACY_NESTED_25"));
        assert!(!redacted.contains("TT_PRIVACY_ENCODED_NESTED_25"));
        assert!(!redacted.contains("TT_PRIVACY_QUERY_PATH_25"));
        assert!(redacted.contains("message="));
        assert!(redacted.contains("next=[sensitive-path]"));
        assert!(redacted.contains("safe=value"));
    }

    #[test]
    fn url_sanitization_handles_websocket_userinfo_ipv6_and_trailing_punctuation() {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            "wss://user:TT_PRIVACY_WS_USERINFO_25@[2001:db8::1]:9443/mcp?sig=TT_PRIVACY_WS_SIG_25). ws://user:TT_PRIVACY_WS_MALFORMED_25@",
        );

        assert!(!redacted.contains("TT_PRIVACY_WS_"));
        assert!(redacted.contains("wss://[2001:db8::1]:9443/mcp?sig=[redacted-secret])."));
        assert!(redacted.contains("[redacted-url]"));
    }

    #[test]
    fn malformed_websocket_userinfo_fails_closed_and_normal_hosts_remain_structured() {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            "wss://user:tt_privacy_ws_malformed_25 ws://example.invalid:9443/socket",
        );

        assert!(!redacted.contains("tt_privacy_ws_malformed_25"));
        assert!(redacted.contains("[redacted-url]"));
        assert!(redacted.contains("ws://example.invalid:9443/socket"));
    }

    #[test]
    fn privacy_corpus_handles_malformed_urls_and_path_classes() {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Diagnostic,
            "https://user:TT_PRIVACY_MALFORMED_25@ /Users/TT_PRIVACY_MAC_25/Library/state /tmp/TT_PRIVACY_TEMP_25 \\\\TT_PRIVACY_UNC_25\\share\\credentials",
        );

        for marker in [
            "TT_PRIVACY_MALFORMED_25",
            "TT_PRIVACY_MAC_25",
            "TT_PRIVACY_TEMP_25",
            "TT_PRIVACY_UNC_25",
        ] {
            assert!(!redacted.contains(marker));
        }
        assert!(redacted.contains("<path>"));
    }

    #[test]
    fn diagnostic_paths_cover_all_absolute_platform_forms_and_spaces() {
        for path in [
            r#"D:\Projects\TT_PRIVACY_DRIVE_25\Project Space\config.json"#,
            "/opt/TT_PRIVACY_OPT_25/project",
            "/var/log/TT_PRIVACY_VAR_25/app.log",
            "/private/tmp/TT_PRIVACY_PRIVATE_25",
            r#"\\server\TT_PRIVACY_UNC_25\Project Space\config.json"#,
        ] {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, path);
            assert!(!redacted.contains("TT_PRIVACY_"));
            assert_eq!(redacted, "<path>");
        }
    }

    #[test]
    fn private_key_blocks_cover_pgp_crlf_escaped_newlines_and_missing_end() {
        for block in [
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nTT_PRIVACY_PGP_25\r\n-----END PGP PRIVATE KEY BLOCK-----",
            r#"-----BEGIN PRIVATE KEY-----\nTT_PRIVACY_ESCAPED_PEM_25\n-----END PRIVATE KEY-----"#,
            "-----BEGIN RSA PRIVATE KEY-----\nTT_PRIVACY_MISSING_END_25",
            "-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----",
        ] {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, block);
            assert!(!redacted.contains("TT_PRIVACY_"));
            assert!(!redacted.contains("BEGIN"));
            assert!(!redacted.contains("END"));
            assert!(redacted.contains("[redacted-secret]"));
        }
    }

    #[test]
    fn assignment_scanner_handles_escaped_json_keys_and_unicode_separators() {
        let markers = [
            "TT_PRIVACY_ESCAPED_JSON_KEY_25",
            "TT_PRIVACY_ESCAPED_ASSIGNMENT_25",
            "TT_PRIVACY_NBSP_ASSIGNMENT_25",
            "TT_PRIVACY_EM_SPACE_ASSIGNMENT_25",
        ];
        let input = [
            r#"{"api\u005fkey":"TT_PRIVACY_ESCAPED_JSON_KEY_25"}; \"token\"\u0020=\u0020\"TT_PRIVACY_ESCAPED_ASSIGNMENT_25\"; secret"#,
            "\u{00a0}",
            "=\u{00a0}TT_PRIVACY_NBSP_ASSIGNMENT_25; password\u{2003}=\u{2003}TT_PRIVACY_EM_SPACE_ASSIGNMENT_25",
        ]
        .concat();
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &input);

        for marker in markers {
            assert!(
                !redacted.contains(marker),
                "controlled marker remained in escaped or Unicode assignment"
            );
        }
    }

    #[test]
    fn escaped_assignments_preserve_original_syntax_and_safe_surrounding_text() {
        let marker = "TT_PRIVACY_ESCAPED_ASSIGNMENT_EXACT_25";
        let cases = [
            (
                format!(r#"before {{"token":"{marker}"}} after=safe"#),
                r#"before {"token":"[redacted-secret]"} after=safe"#,
            ),
            (
                format!(r#"before {{"to\u006ben":"{marker}"}} after=safe"#),
                r#"before {"to\u006ben":"[redacted-secret]"} after=safe"#,
            ),
            (
                format!(r#"before \"token\"=\"{marker}\" after=safe"#),
                r#"before \"token\"=\"[redacted-secret]\" after=safe"#,
            ),
            (
                format!(r#"before {{\"token\":\"{marker}\"}} after=safe"#),
                r#"before {\"token\":\"[redacted-secret]\"} after=safe"#,
            ),
            (
                format!(r#"before {{\\\"to\\u006ben\\\":\\\"{marker}\\\"}} after=safe"#),
                r#"before {\\\"to\\u006ben\\\":\\\"[redacted-secret]\\\"} after=safe"#,
            ),
        ];

        for (input, expected) in cases {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &input);
            assert!(
                !redacted.contains(marker),
                "escaped assignment retained a controlled marker"
            );
            assert_eq!(redacted, expected);
            assert_eq!(
                PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &redacted),
                redacted
            );
        }
    }

    #[test]
    fn escaped_assignment_corpus_covers_required_source_renderings() {
        let marker = "TT_PRIVACY_ESCAPED_REQUIRED_25";
        let cases = [
            format!(r#"before {{\"api_key\":\"{marker}\"}} after=safe"#),
            format!(r#"before {{\"token\": \"{marker}\"}} after=safe"#),
            format!(r#"before {{\\\"password\\\":\\\"{marker}\\\"}} after=safe"#),
            format!(r#"before token="{marker}" after=safe"#),
            format!(r#"before token=\\\"{marker}\\\" after=safe"#),
        ];

        for input in cases {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &input);
            assert!(!redacted.contains(marker));
            assert!(redacted.starts_with("before "));
            assert!(redacted.ends_with(" after=safe"));
            assert!(redacted.contains("[redacted-secret]"));
            assert_eq!(
                PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &redacted),
                redacted
            );
        }
    }

    #[test]
    fn assignment_scanner_handles_nbsp_and_em_space_separately() {
        let nbsp_marker = "TT_PRIVACY_NBSP_EXACT_25";
        let em_space_marker = "TT_PRIVACY_EM_SPACE_EXACT_25";
        let nbsp = PrivacySanitizer::sanitize(
            SanitizationContext::CommandResult,
            &format!("before token\u{00a0}=\u{00a0}{nbsp_marker} after=safe"),
        );
        let em_space = PrivacySanitizer::sanitize(
            SanitizationContext::CommandResult,
            &format!("before Api_Key\u{2003}:\u{2003}\"{em_space_marker}\" after=safe"),
        );

        assert!(!nbsp.contains(nbsp_marker));
        assert!(nbsp.contains("before token\u{00a0}=\u{00a0}[redacted-secret] after=safe"));
        assert!(!em_space.contains(em_space_marker));
        assert!(
            em_space.contains("before Api_Key\u{2003}:\u{2003}\"[redacted-secret]\" after=safe")
        );
    }

    #[test]
    fn url_sanitization_handles_bounded_nested_encoding_and_fragments() {
        let marker = "TT_PRIVACY_ENCODED_URL_25";
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            &format!(
                "https://outer.example.invalid/run?safe=value&next=https%253A%252F%252Finner.example.invalid%252Fcallback%253Ftoken%253D{marker}#token={marker}&encoded=token%253D{marker}"
            ),
        );

        assert!(
            !redacted.contains(marker),
            "controlled marker remained in bounded URL encoding or fragment"
        );
        assert!(redacted.contains("safe=value"));
    }

    #[test]
    fn url_sanitization_handles_each_required_encoded_query_value_and_depth_two() {
        let ghp_marker = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12";
        let encoded_ghp_marker = "%67%68%70%5F%41%62%43%64%45%66%47%68%49%6A%4B%6C%4D%6E%4F%70%51%72%53%74%55%76%57%78%59%7A%31%32";
        let assignment_marker = "TT_PRIVACY_ENCODED_ASSIGNMENT_25";
        let json_marker = "TT_PRIVACY_ENCODED_JSON_25";
        let redirect_marker = "TT_PRIVACY_ENCODED_REDIRECT_25";
        let depth_two_marker = "TT_PRIVACY_ENCODED_DEPTH_TWO_25";
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            &format!(
                "https://outer.example.invalid/path?safe=ok&gh={encoded_ghp_marker}&assignment=token%3D{assignment_marker}&json=%7B%22api_key%22%3A%22{json_marker}%22%7D&redirect=https%3A%2F%2Fuser%3A{redirect_marker}%40redirect.example.invalid%2Fnext&depth2=token%253D{depth_two_marker}"
            ),
        );

        for (index, marker) in [
            ghp_marker,
            assignment_marker,
            json_marker,
            redirect_marker,
            depth_two_marker,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                !redacted.contains(marker),
                "encoded query value case {index} retained a controlled marker"
            );
        }
        assert!(redacted.contains("https://outer.example.invalid/path?"));
        assert!(redacted.contains("safe=ok"));
        assert!(redacted.contains("gh="));
        assert!(redacted.contains("assignment="));
        assert!(redacted.contains("json="));
        assert!(redacted.contains("redirect="));
        assert!(redacted.contains("depth2="));
        assert!(!redacted.contains(encoded_ghp_marker));
        assert!(redacted.matches("[redacted-secret]").count() >= 5);
    }

    #[test]
    fn url_sanitization_handles_plain_and_encoded_fragment_forms() {
        let plain_marker = "TT_PRIVACY_PLAIN_FRAGMENT_25";
        let encoded_assignment_marker = "TT_PRIVACY_ENCODED_FRAGMENT_ASSIGNMENT_25";
        let encoded_json_marker = "TT_PRIVACY_ENCODED_FRAGMENT_JSON_25";
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            &format!(
                "https://fragment.example.invalid/path?safe=ok#token={plain_marker}&token%3D{encoded_assignment_marker}&%7B%22token%22%3A%22{encoded_json_marker}%22%7D"
            ),
        );

        for marker in [plain_marker, encoded_assignment_marker, encoded_json_marker] {
            assert!(
                !redacted.contains(marker),
                "fragment form retained a controlled marker"
            );
        }
        assert!(redacted.contains("https://fragment.example.invalid/path?safe=ok#"));
    }

    #[test]
    fn url_sanitization_removes_userinfo_for_supported_and_relative_schemes() {
        let marker = "TT_PRIVACY_URL_USERINFO_25";
        for scheme in [
            "http",
            "https",
            "ws",
            "wss",
            "ftp",
            "ssh",
            "postgres",
            "postgresql",
            "mysql",
            "mariadb",
            "redis",
            "mongodb",
            "amqp",
            "smtp",
            "git+https",
        ] {
            let redacted = PrivacySanitizer::sanitize(
                SanitizationContext::Url,
                &format!("{scheme}://user:{marker}@example.invalid:8443/mcp?safe=value"),
            );
            assert!(
                !redacted.contains(marker),
                "controlled marker remained in scheme userinfo"
            );
            assert!(redacted.contains(&format!("{scheme}://example.invalid:8443/mcp?safe=value")));
        }

        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            &format!("//user:{marker}@example.invalid/mcp?safe=value"),
        );
        assert!(
            !redacted.contains(marker),
            "controlled marker remained in scheme-relative userinfo"
        );
        assert!(redacted.contains("//example.invalid/mcp?safe=value"));
    }

    #[test]
    fn path_sanitization_covers_spaces_before_sensitive_markers() {
        let marker = "TT_PRIVACY_SPACED_PATH_25";
        for path in [
            format!("/opt/Project Space/{marker}/config.json"),
            format!("/Users/Project Space/{marker}/Library/state"),
            format!(r#"C:\Users\Project Space\{marker}\config.json"#),
            format!(r#"\\server\Project Space\{marker}\config.json"#),
        ] {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &path);
            assert!(
                !redacted.contains(marker),
                "controlled marker remained in a spaced platform path"
            );
            assert_eq!(redacted, "<path>");
        }
    }

    #[test]
    fn path_sanitization_handles_required_spaced_platform_paths_without_eating_quoted_text() {
        let marker = "TT_PRIVACY_REQUIRED_SPACED_PATH_25";
        for path in [
            format!("/Users/alice/Library/Application Support/{marker}"),
            format!("/home/alice/My Project/{marker}"),
            format!(r#"C:\Users\alice\Application Data\{marker}"#),
            format!(r#"\\server\Shared Space\{marker}\config.json"#),
        ] {
            let redacted = PrivacySanitizer::sanitize(
                SanitizationContext::Diagnostic,
                &format!("before \"{path}\" after=safe sentence"),
            );
            assert!(
                !redacted.contains(marker),
                "spaced platform path retained a controlled marker"
            );
            assert_eq!(redacted, "before \"<path>\" after=safe sentence");
        }

        let dsn = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            &format!("postgresql://user:{marker}@db.example.invalid:5432/app?sslmode=require"),
        );
        assert!(!dsn.contains(marker));
        assert_eq!(
            dsn,
            "postgresql://db.example.invalid:5432/app?sslmode=require"
        );
    }

    #[test]
    fn privacy_corpus_bounds_pathological_assignment_input() {
        let marker = "TT_PRIVACY_BOUNDED_25";
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Evidence,
            &format!("TOKEN={marker}{}", "x".repeat(100_000)),
        );

        assert!(!redacted.contains(marker));
        assert!(redacted.len() <= 512);
    }

    #[test]
    fn redact_error_message_strips_absolute_paths() {
        let redacted = redact_error_message(
            "io error: No such file or directory (os error 2) at /home/user/.local/share/opencode/opencode.db",
        );
        assert!(!redacted.contains("/home/user"));
        assert!(redacted.contains("<path>"));
    }

    #[test]
    fn redact_error_message_truncates_long_messages() {
        let long_msg = "x".repeat(300);
        let redacted = redact_error_message(&long_msg);
        assert!(redacted.len() <= 200);
        assert_eq!(redacted, "[encoded-blob]");
    }

    #[test]
    fn redact_error_message_truncates_long_multibyte_messages_safely() {
        let long_msg = "界".repeat(100);
        let redacted = redact_error_message(&long_msg);

        assert!(redacted.len() <= 200);
        assert!(redacted.ends_with("[truncated]"));
    }

    #[test]
    fn redact_error_message_masks_encoded_blobs() {
        let redacted = redact_error_message("connection failed with U1lOVEhFVElDX1BBWUxPQUQ=");

        assert!(!redacted.contains("U1lOVEhFVElDX1BBWUxPQUQ"));
        assert!(redacted.contains("[encoded-blob]"));
    }

    #[test]
    fn redact_error_message_masks_secrets() {
        let redacted = redact_error_message("connection failed: token: abc123secret");
        assert!(!redacted.contains("abc123secret"));
        assert!(redacted.contains("[redacted-secret]"));
    }

    #[test]
    fn redact_error_message_strips_windows_paths() {
        let redacted = redact_error_message(
            r#"sqlite open failed at C:\Users\tester\AppData\Local\opencode\opencode.db"#,
        );
        assert!(!redacted.contains(r#"C:\Users\tester"#));
        assert!(redacted.contains("<path>"));
    }

    #[test]
    fn marker_checker_reports_only_case_field_and_marker_id() {
        let marker = ControlledMarker {
            id: "assignment",
            value: "TT_PRIVACY_CHECKER_25",
        };
        let error = check_serialized_event_markers(
            br#"{"evidence":[{"redacted_value":"TT_PRIVACY_CHECKER_25"}]}"#,
            "checker-case",
            &[marker],
        )
        .expect_err("controlled marker must be found");

        assert_eq!(
            error.to_string(),
            "privacy marker check failed for case checker-case, field $.<key>[0].<key>, marker assignment"
        );
    }

    #[test]
    fn marker_checker_catches_keys_and_duplicate_key_values() {
        let marker = ControlledMarker {
            id: "marker",
            value: "TT_PRIVACY_DUPLICATE_25",
        };

        assert!(
            check_serialized_event_markers(
                br#"{"TT_PRIVACY_DUPLICATE_25":"safe"}"#,
                "key-case",
                &[marker],
            )
            .is_err()
        );
        assert!(
            check_serialized_event_markers(
                br#"{"evidence":"TT_PRIVACY_DUPLICATE_25","evidence":"safe"}"#,
                "duplicate-case",
                &[marker],
            )
            .is_err()
        );
    }

    #[test]
    fn marker_checker_has_safe_input_and_depth_limits_and_stops_after_a_match() {
        let marker = ControlledMarker {
            id: "limit-marker",
            value: "tt_privacy_marker_checker_25",
        };
        let oversized = vec![b' '; MAX_SERIALIZED_EVENT_BYTES + 1];
        let size_error = check_serialized_event_markers(&oversized, "size-case", &[marker])
            .expect_err("oversized serialized input must be rejected");
        assert_eq!(
            size_error.to_string(),
            "privacy marker check failed for case size-case: serialized input exceeds the safe limit"
        );

        let too_deep = format!(
            "{}null{}",
            "[".repeat(MAX_MARKER_DEPTH + 1),
            "]".repeat(MAX_MARKER_DEPTH + 1)
        );
        let depth_error =
            check_serialized_event_markers(too_deep.as_bytes(), "depth-case", &[marker])
                .expect_err("over-nested serialized input must be rejected");
        assert_eq!(
            depth_error.to_string(),
            "privacy marker check failed for case depth-case: serialized input exceeds the safe nesting limit"
        );

        let early_error = check_serialized_event_markers(
            br#"{"evidence":"tt_privacy_marker_checker_25",invalid"#,
            "early-case",
            &[marker],
        )
        .expect_err("marker must be reported before a later malformed suffix");
        assert!(matches!(
            early_error,
            SerializedMarkerCheckError::MarkerFound { .. }
        ));
    }

    #[test]
    fn high_confidence_markers_match_session_one_patterns_and_near_misses_do_not() {
        for marker in [
            "ghp_12345678",
            "SK-abcdefgh",
            "akia1234567890AB",
            "XOXB-12345678",
            "eYj_12345678.segment_5678.segment_9012",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ] {
            assert!(contains_high_confidence_credential_marker(marker));
        }
        for near_miss in [
            "ghp_1234567",
            "sk-1234567",
            "AKIA1234567890A",
            "xoxb-1234567",
            "segment_1234.segment_5678.segment_9012",
            "-----BEGIN OPENSSH PUBLIC KEY-----",
        ] {
            assert!(!contains_high_confidence_credential_marker(near_miss));
        }
    }

    #[test]
    fn encoded_authority_and_path_assignments_do_not_survive_url_sanitization() {
        let marker = "TT_PRIVACY_ENCODED_URL_AUTHORITY_25";
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            &format!(
                "https://user%3A{marker}%40example.invalid/path%2Ftoken%3D{marker}?next=https%3A%2F%2Fuser%3A{marker}%40next.example.invalid%2Fpath%3Ftoken%3D{marker}"
            ),
        );

        assert!(
            !redacted.contains(marker),
            "encoded URL authority or assignment retained a controlled marker"
        );
        assert_eq!(redacted, "[redacted-url]");
    }

    #[test]
    fn malformed_and_percent_encoded_url_authorities_are_replaced_as_whole_candidates() {
        let path_marker = "TT_PRIVACY_PATH_25";
        let query_marker = "TT_PRIVACY_QUERY_25";
        let cases = [
            (
                "literal-empty-host-userinfo",
                format!("https://@/home/{path_marker}/.ssh/id_rsa?token={query_marker}"),
            ),
            (
                "encoded-slash",
                format!("https://example.invalid%2fhome%2f{path_marker}%2f.ssh%2fid_rsa"),
            ),
            (
                "encoded-backslash",
                format!("https://example.invalid%5CUsers%5C{path_marker}%5C.ssh%5Cid_rsa"),
            ),
            (
                "encoded-query",
                format!("https://example.invalid%3ftoken%3d{query_marker}"),
            ),
            (
                "encoded-fragment",
                format!("https://example.invalid%23token%3d{query_marker}"),
            ),
            (
                "encoded-userinfo-delimiter",
                format!("https://{query_marker}%40example.invalid/private"),
            ),
            (
                "encoded-whitespace",
                format!("https://example.invalid%20{path_marker}"),
            ),
            (
                "encoded-control",
                format!("https://example.invalid%0a{path_marker}"),
            ),
            (
                "double-encoded-slash",
                format!("https://example.invalid%252Fhome%252F{path_marker}%252F.ssh%252Fid_rsa"),
            ),
        ];

        for (case_id, input) in cases {
            for context in [
                SanitizationContext::Evidence,
                SanitizationContext::Diagnostic,
                SanitizationContext::Url,
                SanitizationContext::Path,
                SanitizationContext::CommandResult,
                SanitizationContext::Summary,
                SanitizationContext::Metadata,
            ] {
                let redacted = PrivacySanitizer::sanitize(context, &input);
                assert!(
                    !redacted.contains(path_marker) && !redacted.contains(query_marker),
                    "authority case {case_id} retained a controlled marker"
                );
                assert_eq!(
                    redacted, "[redacted-url]",
                    "authority case {case_id} must replace the complete URL-like candidate"
                );
                assert_eq!(
                    PrivacySanitizer::sanitize(context, &redacted),
                    redacted,
                    "authority case {case_id} must be idempotent"
                );
            }
        }
    }

    #[test]
    fn fully_encoded_url_authority_delimiters_fail_closed_at_first_scheme_representation() {
        let marker = "TT_PRIVACY_ENCODED_AUTHORITY_COMPONENT_25";
        let cases = [
            (
                "encoded-slash",
                format!("https%3A%2F%2Fexample.invalid%252F{marker}%2Fsafe"),
            ),
            (
                "encoded-backslash",
                format!("https%3A%2F%2Fexample.invalid%255C{marker}%2Fsafe"),
            ),
            (
                "encoded-query",
                format!("https%3A%2F%2Fexample.invalid%253Fnext%253D{marker}%2Fsafe"),
            ),
            (
                "encoded-fragment",
                format!("https%3A%2F%2Fexample.invalid%2523safe%253D{marker}%2Fsafe"),
            ),
            (
                "encoded-userinfo-delimiter",
                format!("https%3A%2F%2Fexample.invalid%2540{marker}%2Fsafe"),
            ),
            (
                "encoded-mixed-case-slash",
                format!("https%3A%2F%2Fexample.invalid%252f{marker}%2Fsafe"),
            ),
            (
                "fully-double-encoded-scheme",
                format!("https%253A%252F%252Fexample.invalid%25252F{marker}%252Fsafe"),
            ),
        ];

        for (case_id, input) in cases {
            for context in [
                SanitizationContext::Evidence,
                SanitizationContext::Diagnostic,
                SanitizationContext::Url,
                SanitizationContext::Path,
                SanitizationContext::CommandResult,
                SanitizationContext::Summary,
                SanitizationContext::Metadata,
            ] {
                let redacted = PrivacySanitizer::sanitize(context, &input);
                assert!(
                    !redacted.contains(marker),
                    "encoded URL authority case {case_id} retained a controlled marker"
                );
                assert_eq!(
                    redacted, "[redacted-url]",
                    "encoded URL authority case {case_id} must replace the complete candidate"
                );
                assert_eq!(
                    PrivacySanitizer::sanitize(context, &redacted),
                    redacted,
                    "encoded URL authority case {case_id} must be idempotent"
                );
            }
        }
    }

    #[test]
    fn encoded_url_candidate_prefix_forms_are_atomic_and_bounded() {
        let marker = "TT_PRIVACY_ENCODED_CANDIDATE_PATH_25";
        let valid_cases = [
            (
                "fully-encoded-scheme",
                format!(
                    "%68%74%74%70%73%3A%2F%2Fexample.invalid%2Fhome%2F{marker}%2F.ssh%2Fid_rsa"
                ),
            ),
            (
                "literal-scheme-encoded-separators",
                format!("https:%2F%2Fexample.invalid%2Fhome%2F{marker}%2F.ssh%2Fid_rsa"),
            ),
            (
                "encoded-scheme-literal-separators",
                format!("https%3A//example.invalid%2Fhome%2F{marker}%2F.ssh%2Fid_rsa"),
            ),
            (
                "double-encoded-full-scheme",
                format!(
                    "%2568%2574%2574%2570%2573%253A%252F%252Fexample.invalid%252Fhome%252F{marker}%252F.ssh%252Fid_rsa"
                ),
            ),
        ];
        for (case_id, input) in valid_cases {
            let redacted = PrivacySanitizer::sanitize(
                SanitizationContext::Url,
                &format!("prefix {input} suffix"),
            );
            assert!(
                !redacted.contains(marker),
                "valid URL case {case_id} retained marker"
            );
            assert!(
                redacted == "prefix https://example.invalid/[sensitive-path] suffix",
                "valid URL case {case_id} did not render its canonical sensitive path"
            );
            assert_eq!(
                PrivacySanitizer::sanitize(SanitizationContext::Url, &redacted),
                redacted,
                "valid URL case {case_id} was not idempotent"
            );
        }

        let malformed_cases = [
            (
                "fully-encoded-scheme",
                format!(
                    "%68%74%74%70%73%3A%2F%2Fexample.invalid%252Fhome%252F{marker}%252F.ssh%252Fid_rsa"
                ),
            ),
            (
                "literal-scheme-encoded-separators",
                format!("https:%2F%2Fexample.invalid%252Fhome%252F{marker}%252F.ssh%252Fid_rsa"),
            ),
            (
                "encoded-scheme-literal-separators",
                format!("https%3A//example.invalid%252Fhome%252F{marker}%252F.ssh%252Fid_rsa"),
            ),
            (
                "double-encoded-full-scheme",
                format!(
                    "%2568%2574%2574%2570%2573%253A%252F%252Fexample.invalid%25252Fhome%25252F{marker}%25252F.ssh%25252Fid_rsa"
                ),
            ),
        ];
        for (case_id, input) in malformed_cases {
            let redacted = PrivacySanitizer::sanitize(
                SanitizationContext::Url,
                &format!("prefix {input} suffix"),
            );
            assert!(
                !redacted.contains(marker),
                "malformed URL case {case_id} retained marker"
            );
            assert!(
                redacted == "prefix [redacted-url] suffix",
                "malformed URL case {case_id} did not fail closed atomically"
            );
            assert_eq!(
                PrivacySanitizer::sanitize(SanitizationContext::Url, &redacted),
                redacted,
                "malformed URL case {case_id} was not idempotent"
            );
        }

        let ordinary = "ordinary percent text %6e%6f%74%2D%61%2D%75%72%6c %2Fhome%2Fsafe";
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, ordinary),
            ordinary,
            "ordinary percent-encoded non-URL text changed"
        );

        let over_depth = "%252568%252574%252574%252570%252573%25253A%25252F%25252Fexample.invalid%25252Fsafe%25252Fpath";
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, over_depth),
            over_depth,
            "URL recognition exceeded its bounded decode depth"
        );
    }

    #[test]
    fn encoded_url_components_keep_immutable_boundaries_during_local_classification() {
        let path_marker = "TT_PRIVACY_COMPONENT_PATH_25";
        let query_marker = "TT_PRIVACY_COMPONENT_QUERY_25";
        let fragment_marker = "TT_PRIVACY_COMPONENT_FRAGMENT_25";
        let boundary_input = format!(
            "https%3A%2F%2Fexample.invalid%2Fsafe%253Ftoken%253D{path_marker}%2523safe%253D{path_marker}%3Ftoken%3D{query_marker}%23token%3D{fragment_marker}"
        );
        let boundary_output = PrivacySanitizer::sanitize(SanitizationContext::Url, &boundary_input);

        for marker in [path_marker, query_marker, fragment_marker] {
            assert!(
                !boundary_output.contains(marker),
                "encoded URL component retained a controlled marker"
            );
        }
        assert_eq!(
            boundary_output,
            "https://example.invalid/[redacted-secret]?token=[redacted-secret]#[redacted-secret]"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, &boundary_output),
            boundary_output,
            "component-local URL sanitization must be idempotent"
        );

        let safe_fully_encoded =
            "https%3A%2F%2Fexample.invalid%2Fsafe%252Fpath%252fsegment%3Fnext%3Dok%23section";
        let safe_fully_encoded_output =
            PrivacySanitizer::sanitize(SanitizationContext::Url, safe_fully_encoded);
        assert_eq!(
            safe_fully_encoded_output,
            "https://example.invalid/safe%2Fpath%2fsegment?next=ok#section"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, &safe_fully_encoded_output),
            safe_fully_encoded_output,
            "safe fully encoded URL sanitization must be idempotent"
        );

        let double_encoded_safe =
            "https%253A%252F%252Fexample.invalid%252Fsafe%25252Fpath%253Fnext%253Dok%2523section";
        let double_encoded_output =
            PrivacySanitizer::sanitize(SanitizationContext::Url, double_encoded_safe);
        assert_eq!(
            double_encoded_output,
            "https://example.invalid/safe%2Fpath?next=ok#section"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, &double_encoded_output),
            double_encoded_output,
            "double-encoded safe URL sanitization must be idempotent"
        );

        let query_fragment_boundary_input = format!(
            "https://example.invalid/safe?next=value%3Ftoken%3D{query_marker}%23tail&safe=ok#fragment%3Ftoken%3D{fragment_marker}%23tail"
        );
        let query_fragment_boundary_output =
            PrivacySanitizer::sanitize(SanitizationContext::Url, &query_fragment_boundary_input);
        assert_eq!(
            query_fragment_boundary_output,
            "https://example.invalid/safe?next=[redacted-secret]&safe=ok#[redacted-secret]"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, &query_fragment_boundary_output),
            query_fragment_boundary_output,
            "query and fragment component sanitization must be idempotent"
        );

        let userinfo_marker = "TT_PRIVACY_COMPONENT_USERINFO_25";
        let userinfo = format!("https://user:{userinfo_marker}@example.invalid/safe?next=value");
        let userinfo_output = PrivacySanitizer::sanitize(SanitizationContext::Url, &userinfo);
        assert!(!userinfo_output.contains(userinfo_marker));
        assert_eq!(userinfo_output, "https://example.invalid/safe?next=value");
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, &userinfo_output),
            userinfo_output,
            "literal URL userinfo removal must be idempotent"
        );

        let sensitive_path_marker = "TT_PRIVACY_COMPONENT_SENSITIVE_PATH_25";
        let sensitive_path = format!(
            "https%3A%2F%2Fexample.invalid%2Fhome%252Fuser%252F.ssh%252F{sensitive_path_marker}%252Fid_rsa%3Fsafe%3Dok"
        );
        let sensitive_path_output =
            PrivacySanitizer::sanitize(SanitizationContext::Url, &sensitive_path);
        assert!(!sensitive_path_output.contains(sensitive_path_marker));
        assert_eq!(
            sensitive_path_output,
            "https://example.invalid/[sensitive-path]?safe=ok"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, &sensitive_path_output),
            sensitive_path_output,
            "encoded sensitive URL path sanitization must be idempotent"
        );
    }

    #[test]
    fn nested_encoded_urls_inside_literal_components_freeze_first_scheme_boundaries() {
        let marker = "TT_PRIVACY_NESTED_BOUNDARY_25";
        let cases = [
            (
                "query-path",
                format!("https://outer.invalid/?next=https%3A%2F%2Finner.invalid%252F{marker}"),
            ),
            (
                "query-query",
                format!(
                    "https://outer.invalid/?next=https%3A%2F%2Finner.invalid%253Ftoken%253D{marker}"
                ),
            ),
            (
                "query-fragment",
                format!(
                    "https://outer.invalid/?next=https%3A%2F%2Finner.invalid%2523token%253D{marker}"
                ),
            ),
            (
                "query-userinfo",
                format!(
                    "https://outer.invalid/?next=https%3A%2F%2Finner.invalid%2540{marker}%252Fsafe"
                ),
            ),
            (
                "path",
                format!("https://outer.invalid/redirect/https%3A%2F%2Finner.invalid%252F{marker}"),
            ),
            (
                "fragment",
                format!("https://outer.invalid/#next=https%3A%2F%2Finner.invalid%252F{marker}"),
            ),
        ];

        for (case_id, input) in cases {
            for context in [
                SanitizationContext::Evidence,
                SanitizationContext::Diagnostic,
                SanitizationContext::Url,
                SanitizationContext::Path,
                SanitizationContext::CommandResult,
                SanitizationContext::Summary,
                SanitizationContext::Metadata,
            ] {
                let redacted = PrivacySanitizer::sanitize(context, &input);
                assert!(
                    !redacted.contains(marker),
                    "nested URL case {case_id} retained its controlled marker"
                );
                assert!(
                    !redacted.contains("https%3A%2F%2Finner.invalid"),
                    "nested URL case {case_id} retained a raw encoded URL prefix"
                );
                assert!(
                    redacted.contains("[redacted-url]"),
                    "nested URL case {case_id} was not replaced atomically"
                );
                let expected = match case_id {
                    "path" => "https://outer.invalid/redirect/[redacted-url]",
                    "fragment" => "https://outer.invalid/#next=[redacted-url]",
                    _ => "https://outer.invalid/?next=[redacted-url]",
                };
                assert!(
                    redacted == expected,
                    "nested URL case {case_id} did not preserve the outer component shape"
                );
                assert_eq!(
                    PrivacySanitizer::sanitize(context, &redacted),
                    redacted,
                    "nested URL case {case_id} was not idempotent"
                );
            }
        }
    }

    #[test]
    fn url_paths_hide_sensitive_filesystem_shapes_and_encoded_segments() {
        let marker = "TT_PRIVACY_URL_PATH_USER_25";
        let cases = [
            format!("https://example.invalid/home/{marker}/.ssh/id_rsa?mode=view"),
            format!("https://example.invalid/home/{marker}/%2Essh/id%5Frsa?mode=view"),
            format!("https://example.invalid/%68%6f%6d%65%2f{marker}%2f%2essh%2fid_rsa"),
            format!("https://example.invalid/Users/{marker}/Library/Application%20Support/private"),
            format!("https://example.invalid/C:/Users/{marker}/.ssh/id_ed25519"),
            format!("file:///home/{marker}/.ssh/id_rsa"),
            format!("file:///Users/{marker}/.ssh/id_ed25519"),
            format!("file:///C:/Users/{marker}/.ssh/id_rsa"),
            format!("file://server/share/Users/{marker}/private"),
        ];

        for input in cases {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::Url, &input);
            assert!(
                !redacted.contains(marker),
                "sensitive URL path retained a controlled username"
            );
            assert!(redacted.contains("[sensitive-path]"));
        }
    }

    #[test]
    fn diagnostic_url_paths_hide_private_paths_and_query_credentials() {
        let user_marker = "TT_PRIVACY_DIAGNOSTIC_URL_USER_25";
        let secret_marker = "TT_PRIVACY_DIAGNOSTIC_URL_SECRET_25";
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Diagnostic,
            &format!(
                "request failed for https://example.invalid/home/{user_marker}/My%20Project/.ssh/id_rsa?token={secret_marker}"
            ),
        );

        assert!(!redacted.contains(user_marker));
        assert!(!redacted.contains(secret_marker));
        assert!(!redacted.contains("id_rsa"));
        assert!(redacted.contains("https://example.invalid/<path>?token=[redacted-secret]"));
    }

    #[test]
    fn ordinary_url_and_dsn_paths_remain_analytically_useful() {
        for safe in [
            "https://example.invalid/api/v1/models",
            "https://docs.example.invalid/security/secrets-management",
            "https://example.invalid/api/tokenization",
            "https://example.invalid/docs/credential-rotation",
            "postgres://db.example.invalid/application",
            "ssh://host.example.invalid/repos/project",
            "git+https://example.invalid/org/repository",
        ] {
            assert_eq!(
                PrivacySanitizer::sanitize(SanitizationContext::Url, safe),
                safe
            );
        }
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, "file:///safe/path"),
            "file:///[sensitive-path]"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(
                SanitizationContext::Url,
                "https://example%2Einvalid/api/v1/models"
            ),
            "https://example%2Einvalid/api/v1/models",
            "decoded authority bytes are classification-only"
        );
    }

    #[test]
    fn sanitizer_redacts_short_high_confidence_credential_forms() {
        for credential in [
            "ghp_12345678",
            "sk-abcdefgh",
            "AKIA1234567890AB",
            "xoxb-12345678",
            "eyJ_12345678.segment_5678.segment_9012",
        ] {
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::Summary, credential);
            assert!(
                !redacted.contains(credential),
                "short high-confidence credential was classified but emitted"
            );
            assert!(redacted.contains("[redacted-secret]"));
        }
    }

    fn input_with_tail_at(start: usize, tail: &str) -> String {
        let prefix = "safe-prefix";
        assert!(start >= prefix.len());
        format!("{prefix}{}{}", " ".repeat(start - prefix.len()), tail)
    }

    #[test]
    fn bounded_truncation_fails_closed_for_ambiguous_lexical_tails() {
        let cases = [
            (
                "base64",
                "QWxhZGRpbjpvcGVuIHNlc2FtZQ==TT_PRIVACY_BASE64_TAIL_25",
                MAX_INPUT_BYTES - 10,
            ),
            (
                "known-prefix",
                "sk-abcdefTT_PRIVACY_KNOWN_PREFIX_TAIL_25",
                MAX_INPUT_BYTES - 10,
            ),
            (
                "assignment",
                "TOKEN=TT_PRIVACY_ASSIGNMENT_TAIL_25",
                MAX_INPUT_BYTES - 4,
            ),
            (
                "url-credential",
                "https://uTT_PRIVACY_URL_CREDENTIAL_TAIL_25",
                MAX_INPUT_BYTES - 10,
            ),
            (
                "opaque",
                "TT_PRIVACY_OPAQUE_TAIL_25_abcdefghijklmnopqrstuvwxyz",
                MAX_INPUT_BYTES - 10,
            ),
            (
                "safe-text",
                "ordinary-safe-tail-that-crosses-the-boundary",
                MAX_INPUT_BYTES - 10,
            ),
        ];

        for (case_id, tail, start) in cases {
            let input = input_with_tail_at(start, tail);
            let retained_prefix = &tail[..MAX_INPUT_BYTES - start];
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

            assert!(
                !redacted.contains(retained_prefix),
                "truncated {case_id} tail retained an ambiguous lexical prefix"
            );
            assert!(redacted.starts_with("safe-prefix"));
            assert!(redacted.contains("[truncated-tail]"));
            assert!(redacted.len() <= 512);
            assert_eq!(
                PrivacySanitizer::sanitize(SanitizationContext::Evidence, &redacted),
                redacted,
                "truncated {case_id} tail was not idempotent"
            );
        }
    }

    #[test]
    fn truncated_quoted_assignment_tail_drops_internal_space_suffix() {
        let tail = "TOKEN=\"fixture secret with spaces TT_PRIVACY_QUOTED_TAIL_25";
        let input = input_with_tail_at(MAX_INPUT_BYTES - 24, tail);
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

        assert!(!redacted.contains("fixture secret"));
        assert!(!redacted.contains("TT_PRIVACY_QUOTED_TAIL_25"));
        assert!(redacted.starts_with("safe-prefix"));
        assert!(redacted.contains("[truncated-tail]"));
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Evidence, &redacted),
            redacted
        );
    }

    #[test]
    fn credentials_ending_before_or_at_the_input_cap_remain_classified() {
        let credential = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
        for (case_id, input_length) in [
            ("ends-before-cap", MAX_INPUT_BYTES - 1),
            ("reaches-cap", MAX_INPUT_BYTES),
        ] {
            let start = input_length - credential.len();
            let input = input_with_tail_at(start, credential);
            let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

            assert!(
                !redacted.contains(credential),
                "complete credential {case_id} survived classification"
            );
            assert!(redacted.contains("[redacted-secret]"));
        }
    }

    #[test]
    fn credential_after_the_input_cap_is_not_promoted_into_output() {
        let tail = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
        let input = input_with_tail_at(MAX_INPUT_BYTES + 10, tail);
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

        assert!(!redacted.contains(tail));
        assert!(redacted.starts_with("safe-prefix"));
        assert!(redacted.len() <= 512);
    }

    #[test]
    fn utf8_truncation_near_the_boundary_is_safe_deterministic_and_private() {
        let tail = "TT_PRIVACY_UTF8_TAIL_25界界界界界";
        let input = input_with_tail_at(MAX_INPUT_BYTES - 24, tail);
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

        assert!(!redacted.contains("TT_PRIVACY_UTF8_TAIL_25"));
        assert!(redacted.len() <= 512);
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input),
            redacted
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Evidence, &redacted),
            redacted
        );
    }

    #[test]
    fn long_benign_input_preserves_a_useful_safe_prefix() {
        let input = format!("safe-prefix {}", "ordinary-safe-word ".repeat(1_000));
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

        assert!(redacted.starts_with("safe-prefix ordinary-safe-word"));
        assert!(redacted.contains("ordinary-safe-word"));
        assert!(redacted.len() <= 512);
    }
}
