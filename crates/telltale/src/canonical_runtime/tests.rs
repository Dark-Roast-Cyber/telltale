use super::*;
use telltale_detect::v2::{compile_rule_v1, evaluate_source};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::CorrelationOrigin;
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

fn message(
    id: &str,
    session: Option<&str>,
) -> telltale_schema::observation::CanonicalObservationV2 {
    message_with_content(id, session, "needle")
}

fn message_with_content(
    id: &str,
    session: Option<&str>,
    content: &str,
) -> telltale_schema::observation::CanonicalObservationV2 {
    use telltale_schema::observation::*;
    let provenance = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string(content)),
        ),
        ObservationStage::MessageObserved,
        clock(),
        provenance,
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata("message.content", FactMetadata::reported().unwrap())
    .capability_context(
        CapabilityContext::new()
            .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
    );
    if let Some(session) = session {
        builder = builder.session_id(CorrelationId::source_reported(session).unwrap());
    }
    builder.build().unwrap()
}

// The read opens the path `verified_source` resolved, so nothing changed after
// resolution may redirect it. `process_verified` is the seam: each test
// resolves, changes the filesystem, then reads.
#[cfg(unix)]
mod pinned_read {
    use super::*;

    const SESSION: &str = "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"s\"}}\n";

    fn codex(path: std::path::PathBuf) -> Source {
        Source {
            client: ClientId::Codex,
            source_id: "codex.sessions".into(),
            kind: SourceKind::Jsonl,
            path,
        }
    }

    fn read_resolved(
        source: &Source,
        resolved: &Source,
        instance: &CorrelationId,
    ) -> Result<SourceResult, SourceFailure> {
        process_verified(
            source,
            resolved,
            instance,
            clock(),
            None,
            SourceContext {
                mcp_servers: &[],
                rules: &plan("user_context"),
                pre_policy_rules: None,
                process: None,
                prior: &BaselineSnapshotStore::default(),
                baseline_deviation: Default::default(),
            },
            None,
        )
    }

    fn assert_refused(result: Result<SourceResult, SourceFailure>) {
        let failure = result.err().expect("a changed path must not be read");
        assert_eq!(failure.stage, FailureStage::Acquisition);
        assert!(matches!(
            failure.acquisition,
            Some(AcquisitionError::SourceRead)
        ));
    }

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        // macOS temporary directories live under an aliased /var.
        let base = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(base.join("store")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        std::fs::write(base.join("store/session.jsonl"), SESSION).unwrap();
        std::fs::write(base.join("outside/session.jsonl"), SESSION).unwrap();
        (dir, base)
    }

    #[test]
    fn directory_replaced_by_a_link_after_resolution_is_refused() {
        let (_dir, base) = fixture();
        let source = codex(base.join("store/session.jsonl"));
        let (resolved, instance) = verified_source(&source).unwrap();
        read_resolved(&source, &resolved, &instance).expect("control read");
        std::fs::rename(base.join("store"), base.join("retained")).unwrap();
        std::os::unix::fs::symlink(base.join("outside"), base.join("store")).unwrap();
        assert_refused(read_resolved(&source, &resolved, &instance));
    }

    #[test]
    fn file_replaced_by_a_link_after_resolution_is_refused() {
        let (_dir, base) = fixture();
        let source = codex(base.join("store/session.jsonl"));
        let (resolved, instance) = verified_source(&source).unwrap();
        std::fs::remove_file(&resolved.path).unwrap();
        std::os::unix::fs::symlink(base.join("outside/session.jsonl"), &resolved.path).unwrap();
        assert_refused(read_resolved(&source, &resolved, &instance));
    }

    #[test]
    fn fifo_replacing_the_file_after_resolution_does_not_block() {
        use std::os::unix::ffi::OsStrExt;
        let (_dir, base) = fixture();
        let source = codex(base.join("store/session.jsonl"));
        let (resolved, instance) = verified_source(&source).unwrap();
        std::fs::remove_file(&resolved.path).unwrap();
        let name = std::ffi::CString::new(resolved.path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated synthetic pathname.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        let (read_source, read_resolved_source) = (source.clone(), resolved.clone());
        std::thread::spawn(move || {
            let result = read_resolved(&read_source, &read_resolved_source, &instance);
            let _ = sender.send(result.is_err());
        });
        let outcome = receiver.recv_timeout(std::time::Duration::from_secs(10));
        if outcome == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            // Release a reader blocked in open(2) so the thread can end.
            // Nonblocking: with no reader the open fails instead of hanging.
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&resolved.path);
        }
        assert_eq!(outcome, Ok(true), "a FIFO must be refused without blocking");
    }

    #[test]
    fn links_at_or_above_the_resolved_point_are_still_followed() {
        let (_dir, base) = fixture();
        std::os::unix::fs::symlink(&base, base.join("alias")).unwrap();
        std::os::unix::fs::symlink(base.join("store/session.jsonl"), base.join("leaf.jsonl"))
            .unwrap();
        for path in [
            base.join("alias/store/session.jsonl"),
            base.join("leaf.jsonl"),
            base.join("alias/leaf.jsonl"),
        ] {
            let source = codex(path);
            let (resolved, instance) = verified_source(&source).unwrap();
            // The correlation identity names the canonical file, as before.
            assert_eq!(resolved.path, base.join("store/session.jsonl"));
            read_resolved(&source, &resolved, &instance).expect("resolved read");
            let rules = plan("user_context");
            process_source(
                &source,
                clock(),
                None,
                SourceContext {
                    mcp_servers: &[],
                    rules: &rules,
                    pre_policy_rules: None,
                    process: None,
                    prior: &BaselineSnapshotStore::default(),
                    baseline_deviation: Default::default(),
                },
            )
            .expect("a linked coordinate is scanned");
        }
    }
}

mod failure_atomicity;
mod policy_evaluation;
mod source_domains;
