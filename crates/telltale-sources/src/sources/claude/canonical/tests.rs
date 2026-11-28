use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;

use telltale_schema::observation::{
    CapabilityAvailability, CapabilityId, ContentPartKind, Fidelity, IngestionMode, JsonValue,
    MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
};
use tempfile::tempdir;

use super::{ClaudeCanonicalOptions, project_claude_native_records};

const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";

fn fixture_source(relative: &str) -> Source {
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path: crate::test_fixture_path(relative),
    }
}

fn project(relative: &str) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
    project_claude_native_records(
        &super::super::native::extract_claude_native_records(&fixture_source(relative)).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .expect("canonical observations")
    .observations
}

fn project_lines(lines: &[&str]) -> super::ClaudeProjection {
    let directory = tempdir().unwrap();
    let path = directory.path().join("session.jsonl");
    fs::write(&path, lines.join("\n")).unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };
    project_claude_native_records(
        &super::super::native::extract_claude_native_records(&source).unwrap(),
        &ClaudeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
    )
    .unwrap()
}

fn project_lines_with(lines: &[&str], options: &ClaudeCanonicalOptions) -> super::ClaudeProjection {
    let directory = tempdir().unwrap();
    let path = directory.path().join("session.jsonl");
    fs::write(&path, lines.join("\n")).unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_owned(),
        path,
    };
    project_claude_native_records(
        &super::super::native::extract_claude_native_records(&source).unwrap(),
        options,
    )
    .unwrap()
}

mod quarantine;
mod session_identity;
mod tool_observations;
