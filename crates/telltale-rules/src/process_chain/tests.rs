use super::{
    BUNDLED_PROCESS_CHAIN_RULE_COUNT, ProcessChainContext, ProcessChainPack, ProcessObservation,
    ProcessRef, bundled_process_chain_metadata, compile_pack, load_default_process_chain_rules,
    load_process_chain_rules, normalize_process_name,
};

fn observation(parent: &str, child: &str, command_line: &str) -> ProcessObservation {
    ProcessObservation {
        parent: ProcessRef::named(parent),
        child: ProcessRef::named(child).with_command_line(command_line),
        host: Some("host-1".to_string()),
        user: Some("alice".to_string()),
        ..ProcessObservation::default()
    }
}

#[test]
fn bundled_pack_compiles() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    assert!(rules.chain_rule_count() > 300);
    assert!(rules.standalone_rule_count() >= 13);
    assert_eq!(rules.correlations().len(), 6);
    assert!(
        rules
            .correlations()
            .iter()
            .all(|rule| (600..=3600).contains(&rule.window_seconds))
    );
}

#[test]
fn bundled_rule_count_is_the_number_of_listed_rules() {
    // Load-time bounds reserve this many catalog entries for the pack.
    let listed = bundled_process_chain_metadata().expect("pack compiles");
    assert_eq!(listed.len(), BUNDLED_PROCESS_CHAIN_RULE_COUNT);
}

#[test]
fn correlation_window_must_fit_session_duration() {
    let document = |window| {
        format!(
            r#"
version: 1
description: synthetic window bounds
defaults: {{ enabled: true, risk_entity: host, suppression_window_seconds: 3600 }}
categories:
  discovery: {{ detection_class: security_detection, analytic_intent: alert }}
correlations:
  - id: procchain.correlation.window_bound
    title: window bound
    category: discovery
    severity: medium
    score: 45
    confidence: high
    reason: synthetic
    window_seconds: {window}
    entity: host
    sequence: [{{ any_category: [discovery] }}]
"#
        )
    };

    for window in [0, i64::MAX as u64] {
        let yaml = document(window);
        let loaded = load_process_chain_rules(&yaml).expect("representable YAML window");
        assert_eq!(loaded.correlations()[0].window_seconds, window);
        let pack: ProcessChainPack = serde_yaml::from_str(&yaml).unwrap();
        let compiled = compile_pack(pack).expect("representable typed pack window");
        assert_eq!(compiled.correlations()[0].window_seconds, window);
    }

    let yaml = document(u64::MAX);
    let error = load_process_chain_rules(&yaml).unwrap_err().to_string();
    assert!(
        error.contains("procchain.correlation.window_bound"),
        "{error}"
    );
    assert!(error.contains("window_seconds"), "{error}");
    assert!(error.contains("9223372036854775807"), "{error}");
    let pack: ProcessChainPack = serde_yaml::from_str(&yaml).unwrap();
    let error = compile_pack(pack).unwrap_err().to_string();
    assert!(
        error.contains("procchain.correlation.window_bound"),
        "{error}"
    );
    assert!(error.contains("window_seconds"), "{error}");
}

#[test]
fn normalizes_paths_case_and_extension() {
    assert_eq!(
        normalize_process_name(r"C:\Windows\System32\WHOAMI.EXE"),
        "whoami"
    );
    assert_eq!(normalize_process_name("/usr/bin/PowerShell"), "powershell");
    assert_eq!(normalize_process_name("\"cmd.exe\""), "cmd");
    assert_eq!(
        normalize_process_name(r"C:\Program Files\ScreenConnect.ClientService.exe"),
        "screenconnect_clientservice"
    );
    assert_eq!(normalize_process_name("7za.exe"), "7za");
}

#[test]
fn zero_risk_chain_still_emits_an_informational_detection() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let detections = rules.evaluate(&observation("powershell.exe", "hostname.exe", "hostname"));
    let detection = detections
        .iter()
        .find(|detection| detection.rule_id == "procchain.discovery.powershell_hostname")
        .expect("informational detection emitted");
    assert_eq!(detection.score, 0);
    assert_eq!(detection.severity, "informational");
    assert!(detection.informational);
}

#[test]
fn matching_is_case_insensitive_and_path_normalized() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let observation = ProcessObservation {
        parent: ProcessRef::named(r"C:\Windows\System32\CMD.EXE"),
        child: ProcessRef::named(r"C:\Windows\System32\WHOAMI.EXE")
            .with_command_line("whoami /all"),
        ..ProcessObservation::default()
    };
    assert!(
        rules
            .evaluate(&observation)
            .iter()
            .any(|detection| detection.rule_id == "procchain.discovery.cmd_whoami")
    );
}

#[test]
fn similar_binary_names_do_not_collide() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    // `net` must not match `netsh`, and `7z` must not match `7za`.
    let netsh = rules.evaluate(&observation("cmd.exe", "netsh.exe", "netsh firewall show"));
    assert!(
        netsh
            .iter()
            .all(|detection| !detection.rule_id.contains("net_account"))
    );
    let seven_za = rules.evaluate(&observation("cmd.exe", "7za.exe", "7za a out.7z data"));
    assert!(
        seven_za
            .iter()
            .any(|detection| detection.rule_id == "procchain.collection.cmd_7za")
    );
}

#[test]
fn strongest_interpretation_wins_and_keeps_the_other_technique() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let detections = rules.evaluate(&observation(
        "cmd.exe",
        "vssadmin.exe",
        "vssadmin delete shadows /all /quiet",
    ));
    let detection = detections
        .iter()
        .find(|detection| detection.dedup_key == "chain:cmd>vssadmin")
        .expect("one deduplicated finding for the pair");
    assert_eq!(detection.rule_id, "procchain.impact.vssadmin_shadow_delete");
    assert_eq!(detection.severity, "critical");
    assert!(
        detection
            .mitre_attack_techniques
            .contains(&"T1490".to_string())
    );
}

#[test]
fn administrative_shadow_copy_use_is_separated_from_deletion() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let detections = rules.evaluate(&observation(
        "cmd.exe",
        "vssadmin.exe",
        "vssadmin create shadow /for=C:",
    ));
    let detection = detections
        .iter()
        .find(|detection| detection.dedup_key == "chain:cmd>vssadmin")
        .expect("administrative variant emitted");
    assert_eq!(
        detection.rule_id,
        "procchain.credaccess.vssadmin_shadow_access"
    );
    assert_eq!(detection.severity, "medium");
}

#[test]
fn office_to_powershell_scores_far_above_shell_discovery() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let office = rules.evaluate(&observation(
        "winword.exe",
        "powershell.exe",
        "powershell -w hidden",
    ));
    let office_score = office
        .iter()
        .find(|detection| detection.rule_id == "procchain.execution.winword_powershell")
        .map(|detection| detection.score)
        .expect("office chain matched");
    let discovery = rules.evaluate(&observation("cmd.exe", "whoami.exe", "whoami"));
    let discovery_score = discovery
        .iter()
        .find(|detection| detection.rule_id == "procchain.discovery.cmd_whoami")
        .map(|detection| detection.score)
        .expect("discovery chain matched");
    assert!(office_score > discovery_score * 2);
}

#[test]
fn web_server_shell_is_critical() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let detections = rules.evaluate(&observation("w3wp.exe", "cmd.exe", "cmd /c dir"));
    let detection = detections
        .iter()
        .find(|detection| detection.rule_id == "procchain.execution.w3wp_cmd")
        .expect("web shell chain matched");
    assert_eq!(detection.severity, "critical");
    assert!(detection.score >= 80);
}

#[test]
fn approved_admin_context_reduces_risk_without_deleting_the_event() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let mut context = ProcessChainContext::default();
    context.approved_admin_users.insert("alice".to_string());
    let detections =
        rules.evaluate_with_context(&observation("cmd.exe", "whoami.exe", "whoami"), &context);
    let detection = detections
        .iter()
        .find(|detection| detection.rule_id == "procchain.discovery.cmd_whoami")
        .expect("detection retained");
    assert_eq!(detection.score, 0);
    assert!(detection.informational);
    assert_eq!(
        detection.risk_adjustment.as_deref(),
        Some("approved administrative user")
    );
}

#[test]
fn allowlist_does_not_soften_a_command_line_gated_rule() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let mut context = ProcessChainContext::default();
    context.approved_admin_users.insert("alice".to_string());
    let detections = rules.evaluate_with_context(
        &observation(
            "cmd.exe",
            "net.exe",
            "net localgroup administrators evil /add",
        ),
        &context,
    );
    let detection = detections
        .iter()
        .find(|detection| detection.rule_id == "procchain.persistence.net_account_add")
        .expect("gated rule matched");
    assert_eq!(detection.severity, "high");
    assert!(detection.risk_adjustment.is_none());
}

#[test]
fn missing_command_line_still_matches_ungated_rules() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let observation = ProcessObservation {
        parent: ProcessRef::named("winword.exe"),
        child: ProcessRef::named("powershell.exe"),
        ..ProcessObservation::default()
    };
    assert!(
        rules
            .evaluate(&observation)
            .iter()
            .any(|detection| detection.rule_id == "procchain.execution.winword_powershell")
    );
}

#[test]
fn credential_dumping_command_line_scores_critical() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let detections = rules.evaluate(&observation(
        "cmd.exe",
        "rundll32.exe",
        r"rundll32 C:\windows\system32\comsvcs.dll MiniDump 640 out.dmp full",
    ));
    let detection = detections
        .iter()
        .find(|detection| detection.rule_id == "procchain.credaccess.credential_dump_command")
        .expect("credential dump indicator matched");
    assert_eq!(detection.severity, "critical");
    assert!(detection.score >= 80);
}

#[test]
fn inferred_parent_lowers_confidence() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let mut observation = observation("cmd.exe", "mimikatz.exe", "mimikatz");
    observation.parent_inferred = true;
    let detection = rules
        .evaluate(&observation)
        .into_iter()
        .find(|detection| detection.rule_id == "procchain.credaccess.cmd_mimikatz")
        .expect("chain matched");
    assert_eq!(detection.confidence, "medium");
}
