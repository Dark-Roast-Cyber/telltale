//! Canonical normalized transcript schema v1, re-exported from
//! `telltale-schema`. The fixture-driven conversion test stays here because it
//! exercises the root crate's discovery and parser pipeline.

pub use telltale_schema::canonical::*;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use crate::discovery::discover_sources_best_effort;
    use crate::parser::{ParseError, parse_source_records};
    use telltale_schema::clients::ClientId;
    use telltale_sources::clients::supported_clients;

    use super::*;

    #[test]
    fn converts_all_fixture_sources_to_v1_contract() {
        let fixture_root = Path::new("tests/fixtures/session_stores");
        let sources = discover_sources_best_effort(fixture_root);
        let discovered_clients: BTreeSet<_> = sources.iter().map(|source| source.client).collect();
        let expected_clients: BTreeSet<_> =
            supported_clients().iter().map(|client| client.id).collect();

        assert_eq!(discovered_clients, expected_clients);

        let mut covered_clients = BTreeSet::new();
        for source in &sources {
            let records = match parse_source_records(source) {
                Ok(records) => records,
                Err(ParseError::Empty) => continue,
                Err(err) => panic!("failed to parse {}: {err}", source.source_id),
            };
            assert!(
                !records.is_empty(),
                "fixture source {} produced no records",
                source.source_id
            );
            covered_clients.insert(source.client);

            for (idx, record) in records.into_iter().enumerate() {
                assert_eq!(record.client, source.client.as_str());
                assert!(
                    !record.session_id.trim().is_empty(),
                    "record {idx} from {} has empty session_id",
                    source.source_id
                );

                let legacy_kind = record_kind_name(record.kind);
                let source_event_id = format!("{}:{idx}", source.source_id);
                let converted = NormalizedRecordV1::from_legacy(
                    record,
                    Provenance {
                        source_path_hash: format!("fixture:{}", source.source_id),
                        source_event_id: Some(source_event_id.clone()),
                        offset: Some(idx.to_string()),
                    },
                );

                assert_eq!(converted.schema_version(), SCHEMA_VERSION);
                assert_eq!(converted.client(), source.client.as_str());
                assert!(!converted.session_id().trim().is_empty());
                assert_eq!(
                    converted.meta().provenance.source_event_id.as_deref(),
                    Some(source_event_id.as_str())
                );
                assert_eq!(
                    converted.meta().extensions.get("legacy_record_kind"),
                    Some(&serde_json::json!(legacy_kind))
                );

                match converted {
                    NormalizedRecordV1::UserMessage(message)
                    | NormalizedRecordV1::AssistantMessage(message) => {
                        assert!(
                            !message.content.trim().is_empty(),
                            "message record {idx} from {} has empty content",
                            source.source_id
                        );
                    }
                    NormalizedRecordV1::ToolCall(call) => {
                        assert!(
                            !call.tool_name.trim().is_empty(),
                            "tool call record {idx} from {} has empty tool_name",
                            source.source_id
                        );
                    }
                    NormalizedRecordV1::ToolResult(result) => {
                        assert!(
                            result.result.is_some()
                                || result
                                    .result_string
                                    .as_deref()
                                    .is_some_and(|text| { !text.trim().is_empty() }),
                            "tool result record {idx} from {} has no result content",
                            source.source_id
                        );
                    }
                    NormalizedRecordV1::SessionMeta(session) => {
                        assert!(
                            !session.fields.is_empty()
                                || !session.meta.extensions.is_empty()
                                || session.workspace.is_some(),
                            "session meta record {idx} from {} has no metadata",
                            source.source_id
                        );
                    }
                    NormalizedRecordV1::Other(other) => {
                        assert!(
                            !other.content.trim().is_empty(),
                            "other record {idx} from {} has empty content",
                            source.source_id
                        );
                    }
                }
            }
        }

        let expected_clients: BTreeSet<_> =
            supported_clients().iter().map(|client| client.id).collect();
        assert_eq!(covered_clients, expected_clients);
        assert_eq!(covered_clients.len(), 9);
        assert!(covered_clients.contains(&ClientId::Codex));
        assert!(covered_clients.contains(&ClientId::Copilot));
    }
}
