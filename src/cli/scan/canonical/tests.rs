use super::*;
use telltale_core::canonical_runtime::FailureStage;

use telltale_detect::v2::compile_rule_v1;
use telltale_rules::load_default_rule_set;
use telltale_schema::clients::{ClientId, SourceKind};
use tempfile::tempdir;

fn clock() -> ObservedAt {
    ObservedAt::new("2026-09-19T00:00:00Z").unwrap()
}

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path,
    }
}

/// A plan with one rule matching `needle` in the field that compiles to the
/// target `target`.
fn plan(target: &str) -> RuleV1CompatibilityPlan {
    let (field, category) = match target {
        "user_context" => ("message.user_text", "message"),
        "assistant_context" => ("message.assistant_text", "message"),
        "url" => ("tool.url", "tool_activity"),
        other => panic!("unmapped target {other}"),
    };
    let yaml = format!(
        "title: synthetic\nid: 1523429f-99fb-4ca1-85ff-dfa1ea08477d\nname: synthetic.target\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: {category}\ndetection:\n    selection:\n        - {field}|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n    analytic_intent: alert\n    detection_class: security_detection\n    signal_type: atomic\n    tags: [synthetic]\n"
    );
    compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&yaml], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap()
}

fn database(path: &std::path::Path) -> Source {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection.execute_batch("CREATE TABLE message (id TEXT, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT);
        CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT);
        INSERT INTO message VALUES ('m','s',1000,1000,'{\"role\":\"user\"}');
        INSERT INTO part VALUES ('p','m','s',1000,1000,'{\"type\":\"text\",\"text\":\"needle\"}');").unwrap();
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: path.into(),
    }
}

mod baseline_staging;
mod failure_reporting;
mod incremental_sqlite;
mod projection;
