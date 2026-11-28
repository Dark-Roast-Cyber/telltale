use super::*;

#[test]
fn investigation_bounds_and_ambiguous_source_fail_closed() {
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.source_bytes = 16;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::SourceUnavailable(SourceUnavailableReason::LimitExceeded)
    );
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.discovery_entries = 1;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(
            NotLocallyResolvableReason::DiscoveryLimitExceeded
        )
    );
    let mut conflicting = source.clone();
    conflicting.source_id = "codex.archived_sessions".into();
    conflicting.kind = SourceKind::ArchivedJsonl;
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![conflicting, source];
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::AmbiguousSource)
    );
}

#[cfg(unix)]
#[test]
fn investigation_non_regular_source_never_blocks() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    fs::remove_file(&source.path).unwrap();
    let path = std::ffi::CString::new(source.path.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated synthetic pathname.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![source];
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::SourceUnavailable(SourceUnavailableReason::NonRegularSource)
    );
}

#[test]
fn investigation_malformed_depth_and_exact_byte_record_bounds() {
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.source_bytes = JSONL.len();
    config.limits.records = 3;
    assert!(matches!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::Found(_)
    ));
    for payload in ["{\"type\":", "{\"nested\":"] {
        fs::write(&source.path, payload).unwrap();
        assert_eq!(
            SessionInvestigator::new(InvestigationConfig::new(dir.path())).investigate(&input),
            InvestigationResult::SourceUnavailable(SourceUnavailableReason::MalformedSource)
        );
        assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
    }
    fs::write(&source.path, JSONL).unwrap();
    for (bytes, records, depth) in [
        (JSONL.len() - 1, 3, 64),
        (JSONL.len(), 2, 64),
        (JSONL.len(), 3, 1),
    ] {
        let mut config = InvestigationConfig::new(dir.path());
        config.limits.source_bytes = bytes;
        config.limits.records = records;
        config.limits.json_depth = depth;
        assert_eq!(
            SessionInvestigator::new(config).investigate(&input),
            InvestigationResult::SourceUnavailable(SourceUnavailableReason::LimitExceeded)
        );
    }
    assert_eq!(fs::read_to_string(&source.path).unwrap(), JSONL);
}

#[test]
fn investigation_failure_reasons_are_private_and_stateless() {
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    for (payload, expected) in [
        (
            "{PRIVATE_PARSE_CANARY",
            InvestigationResult::SourceUnavailable(SourceUnavailableReason::MalformedSource),
        ),
        // An unknown Codex record is quarantined by itself, so the source
        // parses and the session has nothing left to show.
        (
            r#"{"type":"PRIVATE_DISCRIMINATOR_CANARY","session_id":"synthetic-session"}"#,
            InvestigationResult::SessionUnavailable(SessionUnavailableReason::NoTimeline),
        ),
    ] {
        fs::write(&source.path, payload).unwrap();
        let result = backend.investigate(&input);
        assert_eq!(result, expected);
        let public = format!("{result:?} {}", result.reason_code().unwrap());
        assert!(!public.contains("PRIVATE_"));
        assert!(!public.contains(dir.path().to_str().unwrap()));
        assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
    }
    fs::write(
        &source.path,
        r#"{"type":"user","session_id":"synthetic-session","sessionId":"PRIVATE_OWNER_CANARY"}"#,
    )
    .unwrap();
    assert_eq!(
        backend.investigate(&input),
        InvestigationResult::NotLocallyResolvable(
            NotLocallyResolvableReason::ConflictingSessionOwnership
        )
    );
    fs::write(&source.path, JSONL).unwrap();
    assert!(matches!(
        backend.investigate(&input),
        InvestigationResult::Found(_)
    ));
}

#[test]
fn investigation_invalid_limits_and_unsupported_source_are_distinct() {
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.source_bytes = 0;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::InvalidLimits)
    );
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.discovery_entries = 0;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::InvalidLimits)
    );
    let unsupported = Source {
        client: ClientId::Copilot,
        kind: SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".into(),
        path: dir.path().join("PRIVATE_PATH_CANARY"),
    };
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources.push(unsupported.clone());
    assert_eq!(
        SessionInvestigator::new(config).investigate(&event(&unsupported, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnsupportedSource)
    );
}

#[cfg(unix)]
#[test]
fn investigation_discovery_failure_is_not_source_loss() {
    use std::os::unix::fs::symlink;
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    fs::rename(dir.path().join("codex/sessions"), dir.path().join("saved")).unwrap();
    symlink(dir.path().join("saved"), dir.path().join("codex/sessions")).unwrap();
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources.push(source);
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::DiscoverySymlinkRoot)
    );
}

#[cfg(unix)]
#[test]
fn investigation_reads_never_follow_links_below_the_root() {
    use std::os::unix::fs::symlink;
    let dir = tempdir();
    let root = dir.path().join("root");
    let outside = dir.path().join("outside");
    fs::create_dir_all(root.join("codex/sessions")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("synthetic.jsonl"), JSONL).unwrap();
    symlink(&outside, root.join("linked")).unwrap();
    symlink(
        outside.join("synthetic.jsonl"),
        root.join("codex/sessions/leaf.jsonl"),
    )
    .unwrap();
    let known = |path: std::path::PathBuf| Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".into(),
        path,
    };
    // A caller-supplied coordinate reached through a linked ancestor, or that
    // is itself a link, is not read: discovery would not have returned it.
    for path in [
        root.join("linked/synthetic.jsonl"),
        root.join("linked/../linked/synthetic.jsonl"),
        root.join("codex/sessions/leaf.jsonl"),
    ] {
        let source = known(path.clone());
        let mut config = InvestigationConfig::new(&root);
        config.known_sources.push(source.clone());
        assert_eq!(
            SessionInvestigator::new(config).investigate(&event(&source, "synthetic-session")),
            InvestigationResult::SourceUnavailable(SourceUnavailableReason::NonRegularSource),
            "{}",
            path.display()
        );
    }
    // A link-free known coordinate outside the root is still read, as before.
    let source = known(outside.join("synthetic.jsonl"));
    let mut config = InvestigationConfig::new(&root);
    config.known_sources.push(source.clone());
    assert!(matches!(
        SessionInvestigator::new(config).investigate(&event(&source, "synthetic-session")),
        InvestigationResult::Found(_)
    ));
    // The approved root itself is resolved once: a linked root still reads,
    // and the coordinate keeps the caller's spelling.
    let alias = dir.path().join("alias");
    symlink(&root, &alias).unwrap();
    let source = codex(&alias, JSONL);
    assert!(source.path.starts_with(&alias));
    assert!(matches!(
        SessionInvestigator::new(InvestigationConfig::new(&alias))
            .investigate(&event(&source, "synthetic-session")),
        InvestigationResult::Found(_)
    ));
}
