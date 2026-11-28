use super::*;

#[test]
fn historical_rule_replacements_round_trip_with_accounting_and_references() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let replacement = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["rule_ids"][0] = replacement.into();
    wire["risk_contributions"][0]["id"] = replacement.into();
    wire["evidence"][0]["rule_id"] = replacement.into();
    wire["timeline_anchors"][0]["rule_ids"][0] = replacement.into();

    crate::event::sanitize_serialized_event(&mut wire);
    assert!(wire["rule_ids"][0] == replacement, "historical.rule_ids");
    assert!(
        wire["risk_contributions"][0]["id"] == replacement,
        "historical.contribution.id"
    );
    assert!(
        wire["evidence"][0]["rule_id"] == replacement,
        "historical.evidence.rule_id"
    );
    assert!(
        wire["timeline_anchors"][0]["rule_ids"][0] == replacement,
        "historical.anchor.rule_ids"
    );
    let once = wire.clone();
    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire == once,
        "historical rule references are not idempotent"
    );

    let record = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .expect("terminal replacements remain consumable");
    assert_eq!(record.common().risk_score, 5);
    assert!(
        record.common().risk_contributions[0].id() == replacement,
        "consumer.contribution.id"
    );
    assert_eq!(record.common().risk_contributions[0].points(), 2);
}

#[test]
fn historical_derived_rule_replacements_keep_every_process_reference() {
    let (_, mut event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "process_chain")
        .expect("process fixture");
    let replacement = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    event.rule_ids = vec![replacement.to_string()];
    event.evidence[0].rule_id = Some(replacement.to_string());
    let contribution = crate::scoring::historical_risk_contribution(&serde_json::json!({
        "id": replacement,
        "type": "deterministic_rule",
        "points": 2,
        "rationale": "synthetic process"
    }));
    assert!(contribution.is_ok(), "historical contribution was rejected");
    assert!(
        serde_json::from_value::<RiskContribution>(serde_json::json!({
            "id": replacement,
            "type": "deterministic_rule",
            "points": 2,
            "rationale": "synthetic process"
        }))
        .is_err(),
        "generic deserialization admitted a historical replacement"
    );
    assert!(
        contribution
            .as_ref()
            .expect("checked contribution")
            .validate()
            .is_err(),
        "native validation must not admit a terminal replacement"
    );
    event.risk_contributions = vec![contribution.expect("checked contribution")];
    event.process.as_mut().expect("process").secondary_rule_ids = vec![replacement.to_string()];

    let wire = serde_json::to_value(event.historical_derived()).expect("historical event");
    assert!(wire["rule_ids"][0] == replacement, "derived.rule_ids");
    assert!(
        wire["risk_contributions"][0]["id"] == replacement,
        "derived.contribution.id"
    );
    assert!(
        wire["evidence"][0]["rule_id"] == replacement,
        "derived.evidence.rule_id"
    );
    assert!(
        wire["process"]["secondary_rule_ids"][0] == replacement,
        "derived.process.secondary_rule_ids"
    );
    let record = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .expect("historical process remains consumable");
    assert_eq!(record.common().risk_score, 2);
}

#[test]
fn native_emission_does_not_trust_marker_shaped_rule_identifiers() {
    let (_, mut event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "process_chain")
        .expect("process fixture");
    let replacement = "redacted.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    event.rule_ids = vec![replacement.to_string()];
    event.evidence[0].rule_id = Some(replacement.to_string());
    event.timeline_anchors = vec![crate::event::TimelineAnchor {
        entry_index: 0,
        rule_ids: vec![replacement.to_string()],
        categories: vec!["execution".to_string()],
        evidence_fields: vec!["command".to_string()],
    }];
    event.process.as_mut().expect("process").secondary_rule_ids = vec![replacement.to_string()];

    let wire = serde_json::to_value(&event).expect("native event");
    assert!(wire["rule_ids"][0] != replacement, "native.rule_ids");
    assert!(
        wire["evidence"][0]["rule_id"] == wire["rule_ids"][0],
        "native.evidence.rule_id"
    );
    assert!(
        wire["timeline_anchors"][0]["rule_ids"][0] == wire["rule_ids"][0],
        "native.anchor.rule_ids"
    );
    assert!(
        wire["process"]["secondary_rule_ids"][0] == wire["rule_ids"][0],
        "native.process.secondary_rule_ids"
    );
    assert!(
        !wire.to_string().contains(replacement),
        "native marker escaped"
    );
    assert!(
        crate::event::validate_rule_ids(&[replacement.to_string()]).is_err(),
        "native rule admission must remain strict"
    );
    assert!(
        RiskContribution::new(
            replacement,
            RiskContributionType::DeterministicRule,
            2,
            "synthetic process",
        )
        .is_err(),
        "native contribution admission must remain strict"
    );
}

#[test]
fn terminal_consumer_rejects_credential_shaped_anchor_rule_identifiers() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["timeline_anchors"][0]["rule_ids"][0] = "rule.ghp_abcdefghijklmnopqrstuvwx".into();
    let result = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(result, Err("invalid_timeline_anchor"));
}

#[test]
fn terminal_consumer_rejects_credential_shaped_secondary_rule_identifiers() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "process_chain")
        .expect("process fixture");
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["process"]["secondary_rule_ids"] =
        serde_json::json!(["rule.ghp_abcdefghijklmnopqrstuvwx"]);
    let result = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(result, Err("invalid_process_rule_id"));
}

#[test]
fn historical_rule_replacement_restores_contribution_order() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let first = "rule.ghp_aaaaaaaaaaaaaaaaaaaaaaaa";
    let second = "rule.ghp_bbbbbbbbbbbbbbbbbbbbbbbb";
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["rule_ids"] = serde_json::json!([first, second, "aaa.chain"]);
    wire["risk_score"] = 9.into();
    wire["risk_contributions"] = serde_json::json!([
        { "id": first, "type": "deterministic_rule", "points": 2, "rationale": "synthetic alpha" },
        { "id": second, "type": "deterministic_rule", "points": 3, "rationale": "synthetic beta" },
        { "id": "aaa.chain", "type": "chain_modifier", "points": 4, "rationale": "synthetic chain" },
    ]);
    wire["evidence"][0]["rule_id"] = first.into();
    wire["timeline_anchors"][0]["rule_ids"][0] = first.into();

    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire["risk_contributions"][0]["id"]
            == "redacted.80b3d63c8ede5999727c55daa34623102171012766c3a337ab8adc0e43eeb017",
        "historical.contribution_order"
    );
    assert_eq!(wire["risk_contributions"][0]["points"], 3);
    assert!(
        wire["risk_contributions"][1]["id"]
            == "redacted.9f28179bb9eb6878b1673e3ab7fc523b789a8a91bd053448f8494787668fc5de",
        "historical.contribution_order"
    );
    assert_eq!(wire["risk_contributions"][1]["points"], 2);
    assert_eq!(wire["risk_contributions"][2]["id"], "aaa.chain");
    assert_eq!(wire["risk_contributions"][2]["points"], 4);
    assert!(
        wire["evidence"][0]["rule_id"] == wire["risk_contributions"][1]["id"],
        "historical.evidence.rule_id"
    );
    let record = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .expect("canonical historical contribution order");
    assert_eq!(record.common().risk_score, 9);
    assert_eq!(record.common().risk_contributions.len(), 3);
    let once = wire.clone();
    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire == once,
        "historical contribution order changed on readback"
    );
}

#[test]
fn native_rule_replacement_restores_contribution_order() {
    let (_, mut event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let first = format!("redacted.{}", "1".repeat(64));
    let second = format!("redacted.{}", "f".repeat(64));
    event.rule_ids = vec![first.clone(), second.clone()];
    event.evidence[0].rule_id = Some(first.clone());
    event.timeline_anchors[0].rule_ids = vec![first.clone()];
    let contributions = serde_json::json!([
        { "id": first, "type": "deterministic_rule", "points": 2, "rationale": "synthetic alpha" },
        { "id": second, "type": "deterministic_rule", "points": 3, "rationale": "synthetic beta" },
    ])
    .as_array()
    .expect("contribution array")
    .iter()
    .map(crate::scoring::historical_risk_contribution)
    .collect::<Result<Vec<_>, _>>();
    assert!(contributions.is_ok(), "terminal contribution input");
    assert!(
        serde_json::from_value::<RiskContribution>(serde_json::json!({
            "id": first,
            "type": "deterministic_rule",
            "points": 2,
            "rationale": "synthetic alpha"
        }))
        .is_err(),
        "generic deserialization admitted a historical replacement"
    );
    event.risk_contributions = contributions.expect("checked contributions");

    let mut wire = serde_json::to_value(&event).expect("native event");
    assert!(
        wire["risk_contributions"][0]["id"]
            == "redacted.53451715918c77f7e6706fac3adbf0fb15dfd573425bed296d54d95c479270f4",
        "native.contribution_order"
    );
    assert_eq!(wire["risk_contributions"][0]["points"], 3);
    assert!(
        wire["risk_contributions"][1]["id"]
            == "redacted.ba0fb5ed1f56bfd7533f67a029295a1ba3cd0360b66461844dc8aa787bfa7fd5",
        "native.contribution_order"
    );
    assert_eq!(wire["risk_contributions"][1]["points"], 2);
    assert!(
        wire["evidence"][0]["rule_id"] == wire["risk_contributions"][1]["id"],
        "native.evidence.rule_id"
    );
    let record = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .expect("canonical native contribution order");
    assert_eq!(record.common().risk_score, 5);
    assert_eq!(record.common().risk_contributions.len(), 2);
    let once = wire.clone();
    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire == once,
        "native contribution order changed on readback"
    );
}

#[test]
fn unchanged_unordered_contributions_are_not_repaired_by_terminalization() {
    let (_, mut event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    event.risk_contributions.reverse();
    let mut wire = serde_json::to_value(&event).expect("native event");
    let native = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(native, Err("noncanonical_risk_contributions"));

    let contributions = wire["risk_contributions"].clone();
    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire["risk_contributions"] == contributions,
        "unchanged contribution order was repaired"
    );
    let historical = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(historical, Err("noncanonical_risk_contributions"));
}

#[test]
fn historical_rule_replacement_preserves_duplicate_contributions_for_rejection() {
    let (_, event) = positive_constructor_corpus()
        .into_iter()
        .find(|(family, _)| *family == "detection")
        .expect("detection fixture");
    let mut wire = serde_json::to_value(&event).expect("event");
    wire["rule_ids"] = serde_json::json!([
        "rule.ghp_aaaaaaaaaaaaaaaaaaaaaaaa",
        "redacted.9f28179bb9eb6878b1673e3ab7fc523b789a8a91bd053448f8494787668fc5de"
    ]);
    wire["risk_contributions"] = serde_json::json!([
        { "id": "rule.ghp_aaaaaaaaaaaaaaaaaaaaaaaa", "type": "deterministic_rule", "points": 2, "rationale": "synthetic first" },
        { "id": "redacted.9f28179bb9eb6878b1673e3ab7fc523b789a8a91bd053448f8494787668fc5de", "type": "deterministic_rule", "points": 3, "rationale": "synthetic second" }
    ]);
    wire["evidence"] = serde_json::json!([]);
    wire["timeline_anchors"] = serde_json::json!([]);

    crate::event::sanitize_serialized_event(&mut wire);
    assert_eq!(
        wire["risk_contributions"].as_array().expect("array").len(),
        2
    );
    assert!(
        wire["risk_contributions"][0]["id"] == wire["risk_contributions"][1]["id"],
        "historical duplicate contribution identity"
    );
    assert_eq!(wire["risk_contributions"][0]["points"], 2);
    assert_eq!(wire["risk_contributions"][1]["points"], 3);
    assert_eq!(
        wire["risk_contributions"][0]["rationale"],
        "synthetic first"
    );
    assert_eq!(
        wire["risk_contributions"][1]["rationale"],
        "synthetic second"
    );
    let result = Event3Record::from_json(&serde_json::to_vec(&wire).expect("wire"))
        .map(|_| ())
        .map_err(|error| error.code());
    assert_eq!(result, Err("invalid_risk_contributions"));
}

#[test]
fn historical_rule_replacement_does_not_reorder_extended_contributions() {
    let mut wire = serde_json::json!({
        "schema_version": "3.0",
        "risk_contributions": [
            { "id": "rule.ghp_aaaaaaaaaaaaaaaaaaaaaaaa", "type": "deterministic_rule", "points": 2, "rationale": "synthetic first", "extra": 17 },
            { "id": "rule.ghp_bbbbbbbbbbbbbbbbbbbbbbbb", "type": "deterministic_rule", "points": 3, "rationale": "synthetic second" }
        ]
    });

    crate::event::sanitize_serialized_event(&mut wire);
    assert!(
        wire["risk_contributions"][0]["id"]
            == "redacted.9f28179bb9eb6878b1673e3ab7fc523b789a8a91bd053448f8494787668fc5de",
        "historical extended contribution identity"
    );
    assert_eq!(wire["risk_contributions"][0]["points"], 2);
    assert_eq!(wire["risk_contributions"][0]["extra"], 17);
    assert!(
        wire["risk_contributions"][1]["id"]
            == "redacted.80b3d63c8ede5999727c55daa34623102171012766c3a337ab8adc0e43eeb017",
        "historical extended contribution order"
    );
    assert_eq!(wire["risk_contributions"][1]["points"], 3);
}
