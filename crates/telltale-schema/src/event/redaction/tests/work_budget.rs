use super::*;

#[test]
fn work_budget_non_escape_percent_avoids_encoded_candidate_scans() {
    for (text, expected) in [
        ("%", false),
        ("%2", false),
        ("%zz", false),
        ("%2g", false),
        ("%π", false),
        ("%00", true),
        ("%aF", true),
        ("%%20", true),
        ("%252f", true),
    ] {
        assert_eq!(super::super::has_percent_escape(text), expected);
    }
    let text = format!("needle {}%", "ordinary ".repeat(368));
    let mut visits = 0usize;
    PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, &text, &mut |bytes| {
        visits += bytes;
        if visits > 1_000_000 {
            Err("work budget")
        } else {
            Ok(())
        }
    })
    .expect("a literal percent sign needs no encoded URL search");
    // Both helpers must reject the non-escape before their candidate loop,
    // including the path used while inspecting nested URL components.
    let punctuation = format!("{}%zz", ":".repeat(4_000));
    assert!(super::super::find_encoded_url_candidate(&punctuation, 0, &[]).is_none());
    let mut component_visits = 0;
    assert_eq!(
        super::super::decode_url_component_for_inspection(&punctuation, &mut |bytes| {
            component_visits += bytes;
            if component_visits > 100_000 {
                Err("component budget")
            } else {
                Ok(())
            }
        })
        .unwrap(),
        punctuation,
    );
    let encoded = "https%3a%2f%2fexample.invalid%2f%3ftoken%3dSYNTHETIC";
    assert!(super::super::find_encoded_url_candidate(encoded, 0, &[]).is_some());
    let mut reserved = false;
    assert!(
        PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, encoded, &mut |bytes| {
            if bytes == encoded.len() * encoded.len() * 4 {
                reserved = true;
                Err("encoded scan reservation")
            } else {
                Ok(())
            }
        },)
        .is_err()
    );
    assert!(reserved);
    let sanitized = PrivacySanitizer::sanitize(SanitizationContext::Evidence, encoded);
    assert!(!sanitized.contains("SYNTHETIC"));
    assert!(sanitized.len() <= 512);
}

#[test]
fn work_budget_percent_fast_path_preserves_synthetic_redaction_outputs() {
    use sha2::{Digest, Sha256};

    let suffixes = [
        "~",
        "%",
        "%z",
        "%zz",
        "%2g",
        "%20",
        "%25",
        "%252f",
        "%68%74%74%70%73%3a%2f%2fexample.invalid%2f%3ftoken%3dSYNTHETIC",
    ];
    let mut digest = Sha256::new();
    let mut cases = 0;
    for length in [0, 1, 16, 80, 368, 500] {
        for suffix in suffixes {
            for prefix in [
                "needle ",
                "token=SYNTHETIC ",
                "https://example.invalid/?token=SYNTHETIC ",
                "π ordinary ",
            ] {
                let input = format!("{prefix}{}{suffix}", "ordinary ".repeat(length));
                let output = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);
                digest.update((output.len() as u64).to_le_bytes());
                digest.update(output.as_bytes());
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 216);
    // Pin the pre-optimization output, including truncation and redaction;
    // this regression changes visited work, not any emitted text.
    assert_eq!(
        hex::encode(digest.finalize()),
        "38146e099800500680c449b99f088770071d00f7e04e24ea03b743a55d52415b"
    );
}

#[test]
fn nested_url_assignment_work_is_reserved_before_assignment_scan() {
    let text = format!("https://example.invalid/{}", "abc.".repeat(750));
    let mut visits = 0usize;
    PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, &text, &mut |bytes| {
        visits += bytes;
        Ok::<_, ()>(())
    })
    .unwrap();
    // The URL owner must reserve its reached nested assignment scan, not
    // rely on a later outer assignment reservation after inspection.
    assert!(visits > 1_000_000);
    let path = format!("/{}", "abc.".repeat(750));
    let mut nested_visits = 0usize;
    assert_eq!(
        super::super::redact_url_path(&path, 0, false, &mut |bytes| {
            nested_visits += bytes;
            if nested_visits > 1_000_000 {
                Err("nested assignment budget")
            } else {
                Ok(())
            }
        }),
        Err("nested assignment budget")
    );
    let punctuation = ":".repeat(4_000);
    assert!(super::super::find_encoded_url_candidate(&punctuation, 0, &[]).is_none());
    assert_eq!(
        super::super::decode_url_component_for_inspection(&punctuation, &mut |_| Ok::<_, ()>(()))
            .unwrap(),
        punctuation
    );
}

#[test]
fn quoted_ordinary_output_reserves_reached_assignment_work_and_redacts_secrets() {
    let input = format!(
        "{{\"api_key\":\"SYNTHETIC-ASSIGNMENT-SECRET\"}}\n{}",
        "{\"ordinary\":\"compiler diagnostic\"}\n".repeat(120)
    );
    let mut visits = 0usize;
    let output =
        PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, &input, &mut |bytes| {
            visits += bytes;
            if visits > 8 * 1024 * 1024 {
                Err("budget")
            } else {
                Ok(())
            }
        })
        .expect("ordinary quoted output must not reserve an entire quadratic preview");
    assert!(!output.contains("SYNTHETIC-ASSIGNMENT-SECRET"));
    assert_eq!(
        output,
        PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input)
    );
    let malicious = "x".repeat(4_000);
    let mut used = 0usize;
    assert!(
        PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, &malicious, &mut |bytes| {
            used += bytes;
            if used > 8 * 1024 * 1024 {
                Err("budget")
            } else {
                Ok(())
            }
        })
        .is_err(),
        "quadratic key attempts still fail before unbounded work"
    );
}
