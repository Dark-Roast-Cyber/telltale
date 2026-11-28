use std::ops::Range;

use super::{
    ControlledMarker, EvidenceExcerpt, MAX_INPUT_BYTES, MAX_MARKER_DEPTH,
    MAX_SERIALIZED_EVENT_BYTES, PrivacySanitizer, SanitizationContext, SerializedMarkerCheckError,
    check_serialized_event_markers, contains_credential_material,
    contains_high_confidence_credential_marker, redact_error_message, redact_sensitive_text,
};

fn excerpt(text: &str, hit: Option<&str>) -> EvidenceExcerpt {
    let range = hit.map(|hit| {
        let start = text.find(hit).expect("hit in text");
        start..start + hit.len()
    });
    let excerpt = PrivacySanitizer::try_sanitize_excerpt(text, range, &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .unwrap();
    assert!(excerpt.text.len() <= 512, "{}", excerpt.text.len());
    assert!(excerpt.text.split_whitespace().count() <= 80);
    assert_eq!(redact_sensitive_text(&excerpt.text), excerpt.text);
    if let Some(highlight) = &excerpt.highlight {
        assert!(highlight.start < highlight.end && highlight.end <= excerpt.text.len());
        assert!(excerpt.text.is_char_boundary(highlight.start));
        assert!(excerpt.text.is_char_boundary(highlight.end));
    }
    excerpt
}

fn highlighted(excerpt: &EvidenceExcerpt) -> &str {
    &excerpt.text[excerpt.highlight.clone().expect("exact highlight")]
}

const EVERY_CONTEXT: [SanitizationContext; 7] = [
    SanitizationContext::Evidence,
    SanitizationContext::Diagnostic,
    SanitizationContext::Url,
    SanitizationContext::Path,
    SanitizationContext::CommandResult,
    SanitizationContext::Summary,
    SanitizationContext::Metadata,
];

/// Synthetic tokens of each vendor family, assembled here so no literal
/// token-shaped string sits in the source.
fn vendor_tokens() -> Vec<String> {
    let dashed = "aB3_dE6-gH9_jK2-mN5p";
    let plain = "a1B2c3D4e5".repeat(4);
    let mut tokens: Vec<String> = [
        "glpat", "gloas", "gldt", "glrt", "glrtr", "glcbt", "glptt", "glft", "glimt", "glagent",
        "glwt", "glsoat", "glffct",
    ]
    .iter()
    .map(|prefix| format!("{prefix}-{dashed}"))
    .collect();
    tokens.push(format!("github_pat_{}_{}", &plain[..22], plain.repeat(2)));
    tokens.push(format!("hf_{}", &plain[..34]));
    tokens.push(format!("npm_{}", &plain[..36]));
    for family in ["xoxc", "xoxd", "xoxe"] {
        tokens.push(format!("{family}-1-{}", &plain[..24]));
    }
    tokens
}

/// Asserts the sanitized text in every context: `evidence` is the
/// expectation for every context except `Diagnostic`, which uses its own
/// path marker.
fn assert_every_context(input: &str, evidence: &str, diagnostic: &str) {
    for context in [
        SanitizationContext::Evidence,
        SanitizationContext::Url,
        SanitizationContext::Path,
        SanitizationContext::CommandResult,
        SanitizationContext::Summary,
        SanitizationContext::Metadata,
    ] {
        assert_eq!(
            PrivacySanitizer::sanitize(context, input),
            evidence,
            "{context:?}"
        );
    }
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, input),
        diagnostic
    );
}

fn input_with_tail_at(start: usize, tail: &str) -> String {
    let prefix = "safe-prefix";
    assert!(start >= prefix.len());
    format!("{prefix}{}{}", " ".repeat(start - prefix.len()), tail)
}

/// A construct that can span a line, with the markers a single sanitizer
/// call hides.
struct SpanCase {
    template: &'static str,
    /// Whether one call is expected to hide every marker.
    hidden: bool,
}

const SPAN_CASES: &[SpanCase] = &[
    SpanCase {
        template: "password\n= {M}\n",
        hidden: true,
    },
    SpanCase {
        template: "password =\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "api_key:\n\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "\"client_secret\"\n: \"{M}\"\n",
        hidden: true,
    },
    SpanCase {
        template: "--token\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "secret: |\n  {M}\n  {N}\nnext: plain\n",
        hidden: true,
    },
    SpanCase {
        template: "token: >\n\n  {M}\nafter\n",
        hidden: true,
    },
    SpanCase {
        template: "pass\\x77ord\\x3d\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "api_key: |\n\\x20{M}\nafter\n",
        hidden: true,
    },
    SpanCase {
        template: "npm install\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "pnpm\nadd {M}\n",
        hidden: true,
    },
    SpanCase {
        template: "Bearer\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "Basic\n\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "-----BEGIN RSA PRIVATE KEY-----\n{M}\n{N}\n-----END RSA PRIVATE KEY-----\nafter\n",
        hidden: true,
    },
    SpanCase {
        template: "-----BEGIN\nPRIVATE KEY-----\n{M}\n{N}\n",
        hidden: true,
    },
    SpanCase {
        template: "C:\\Users\\{M}\n{N}\\file.txt\n",
        hidden: true,
    },
    SpanCase {
        template: "/home/{M}\n{N}/notes.txt\n",
        hidden: true,
    },
    SpanCase {
        template: "~/{M}\n\n{N}/x\n",
        hidden: true,
    },
    SpanCase {
        template: "\\\\fileserver\\{M}\n{N}\\doc\n",
        hidden: true,
    },
    SpanCase {
        template: "see https://example.invalid/a?token={M}\n",
        hidden: true,
    },
    SpanCase {
        template: "https%3A%2F%2Fexample.invalid%2F%20password%3D\n{M}\n",
        hidden: false,
    },
    SpanCase {
        template: "ghp_{M}{N}\n",
        hidden: true,
    },
    SpanCase {
        template: "x x x x x x x x x x x x x x x x x x x x /srv/{M} {N}/d y y y y y y y y y y y y y y y y y y\n",
        hidden: true,
    },
    SpanCase {
        template: "x x x x x x x x x x /srv/{M} {N} tail/d y y y y y y y y y y y y y y y y y y\n",
        hidden: true,
    },
    SpanCase {
        template: "/srv/{M}\n{N} tail/d y y y y y y y y y y y y y y y y y y y y y y y y y y y y y\n",
        hidden: true,
    },
    SpanCase {
        template: "C:\\Data\\{M} {N} tail\\d y y y y y y y y y y y y y y y y y y y y y y y y\n",
        hidden: true,
    },
    SpanCase {
        template: "y y y y y y y y y y y y y y y y y y y y password=\"{M} {N}\" z z z z z z z z z z z z z z\n",
        hidden: true,
    },
    SpanCase {
        template: "w w w w w w w w w w w w w w w w w w w w w w w w Bearer {M} v v v v v v v v v v v\n",
        hidden: true,
    },
];

const MARKER_FIELDS: [&str; 2] = ["{M}", "{N}"];
const MARKER_WINDOW: usize = 6;

/// Deterministic mixed-case letters: never an encoded blob or token on
/// their own, so only the construct around them hides them.
fn synthetic_letters(length: usize, seed: u64) -> String {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..length)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let letter = b'a' + u8::try_from(state % 26).expect("letter offset");
            char::from(if index == 0 || (index % 3 == 1 && index != 1) {
                letter.to_ascii_uppercase()
            } else {
                letter
            })
        })
        .collect()
}

fn synthetic_token(prefix: &str, length: usize, seed: u64) -> String {
    format!("{prefix}{}", synthetic_letters(length, seed))
}

fn shows_marker_window(output: &str, marker: &str) -> bool {
    marker
        .as_bytes()
        .windows(MARKER_WINDOW)
        .any(|window| output.contains(std::str::from_utf8(window).expect("ASCII marker")))
}

fn span_case_input(case: &SpanCase, case_index: usize, lead: usize) -> (String, Vec<String>) {
    let markers = (0..MARKER_FIELDS.len())
        .map(|field| synthetic_letters(16, (case_index * 7 + field + 1) as u64))
        .collect::<Vec<_>>();
    let mut construct = case.template.to_owned();
    for (field, marker) in MARKER_FIELDS.iter().zip(&markers) {
        construct = construct.replace(field, marker);
    }
    // The lead shifts the construct, and every cut inside it, against
    // the chunk bounds.
    let input = format!(
        "fill line\nfill line\n{} {construct}fill line\nfill end\n",
        "p".repeat(lead)
    );
    (input, markers)
}

/// `line` padded to one full chunk, so the newline after it is the only
/// cut before `rest`.
fn padded_to_a_chunk(line: &str, rest: &str) -> String {
    format!(
        "{}{line}\n{rest}",
        " ".repeat(super::MAX_INPUT_BYTES - line.len())
    )
}

const PLANTED: &str = "AbCdEfGh";

#[test]
fn multiline_reads_url_text_before_private_key_blocks() {
    use super::{collapse_intraline_whitespace, redact_multiline_bounded, redact_sensitive_text};

    let cases = [
        (
            "bracket host",
            "auth: https://[-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY----- AbCdEfGh",
            PLANTED,
        ),
        (
            "query",
            "https://example.invalid/?q=sk-AbCdEf-----BEGIN PRIVATE KEY-----",
            &PLANTED[..6],
        ),
    ];
    for (case, line, planted) in cases {
        let single = collapse_intraline_whitespace(&redact_sensitive_text(line));
        assert!(!single.contains(planted), "case {case}: one call shows it");
        // Fits one call: exactly the single call.
        let (out, truncated) = redact_multiline_bounded(line, 4096);
        assert!(
            out == single && !truncated,
            "case {case} field text: differs from one call"
        );
        // Chunked: the line is the first chunk's first line.
        let long = format!("{line}\n{}", "filler;\n".repeat(600));
        let (out, _) = redact_multiline_bounded(&long, 4096);
        assert!(
            out.split('\n').next() == Some(single.as_str()),
            "case {case} field text: chunked line differs from one call"
        );
    }
}

mod assignments;
mod device_namespace_paths;
mod drive_and_spaced_paths;
mod encoded_urls;
mod escaped_paths;
mod excerpts;
mod flags_and_identifiers;
mod marker_checker;
mod multiline;
mod secrets;
mod truncation;
mod unc_paths;
mod urls;
mod work_budget;
