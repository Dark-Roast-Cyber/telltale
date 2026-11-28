use super::*;

fn grant(scope: GrantScope, by: &str, rule_ids: &[&str], input: Option<&str>) -> Grant {
    Grant {
        scope,
        tool_name: "Bash".into(),
        rule_ids: rule_ids.iter().map(|id| (*id).to_owned()).collect(),
        input_sha256: input.map(str::to_owned),
        granted_by: by.into(),
        offer_record_id: format!("offer-{by}"),
    }
}

/// A state file written before grants existed loads with no offer and
/// no grants.
#[test]
fn a_state_file_without_grant_fields_loads() {
    let mut value = serde_json::to_value(SessionState::default()).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("offer");
    object.remove("grants");
    let state: SessionState = serde_json::from_value(value).unwrap();
    assert_eq!(state.offer, None);
    assert!(state.grants.is_empty());
}

/// The grant past the bound replaces the oldest one.
#[test]
fn the_grant_past_the_bound_replaces_the_oldest() {
    let mut state = SessionState::default();
    for n in 0..=MAX_GRANTS {
        state.add_grant(grant(GrantScope::Session, &format!("g{n}"), &["r"], None));
    }
    assert_eq!(state.grants.len(), MAX_GRANTS);
    assert_eq!(state.grants[0].granted_by, "g1");
    assert_eq!(
        state.grants[MAX_GRANTS - 1].granted_by,
        format!("g{MAX_GRANTS}")
    );
}

/// A matching `once` grant is preferred over a session grant and is used
/// up; a session grant covers only its tool and only calls all of whose
/// detections it names itself: two grants are not combined.
#[test]
fn grants_cover_by_tool_input_and_every_detection() {
    let ids = |list: &[&str]| list.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
    let mut state = SessionState::default();
    state.add_grant(grant(GrantScope::Session, "s1", &["a"], None));
    state.add_grant(grant(GrantScope::Session, "s2", &["b"], None));
    state.add_grant(grant(GrantScope::Session, "s3", &["a", "d"], None));
    state.add_grant(grant(GrantScope::Once, "o1", &["a", "c"], Some("h1")));
    assert_eq!(
        state.use_grant("Bash", "h1", &ids(&["a", "c"])),
        Some((GrantScope::Once, "o1".into()))
    );
    assert_eq!(state.use_grant("Bash", "h1", &ids(&["a", "c"])), None);
    assert_eq!(state.use_grant("Bash", "h2", &ids(&["a", "b"])), None);
    assert_eq!(
        state.use_grant("Bash", "h2", &ids(&["a"])),
        Some((GrantScope::Session, "s3".into()))
    );
    assert_eq!(
        state.use_grant("Bash", "h2", &ids(&["b"])),
        Some((GrantScope::Session, "s2".into()))
    );
    assert_eq!(state.use_grant("Read", "h2", &ids(&["a"])), None);
    assert_eq!(state.use_grant("Bash", "h2", &[]), None);
}

#[test]
fn journal_ids_keep_safe_keys_and_encode_the_rest_injectively() {
    let state = SessionState::default();
    assert_eq!(state.journal_id("toolu_01:a%b.c", 7), "toolu_01:a%b.c~7");
    let encoded = state.journal_id("a/b", 7);
    assert!(encoded.starts_with("tth-esc-") && encoded.ends_with("~7"));
    assert_eq!(encoded.len(), "tth-esc-".len() + 32 + 2);
    assert_ne!(state.journal_id("a\\b", 7), encoded);
    for key in ["", "..", "a..b", "a\nb", "a\rb", "a\0b", &"k".repeat(257)] {
        assert!(state.journal_id(key, 1).starts_with("tth-esc-"), "{key:?}");
    }
    assert_eq!(state.journal_id(&"k".repeat(256), 1).len(), 256 + 2);
}

fn decision(id: &str) -> PendingDecision {
    PendingDecision {
        record_id: id.into(),
        verdict: Verdict::Allow,
        returned: false,
        action_score: 0,
        tool_name: "Bash".into(),
        agent_id: None,
        decided_at: String::new(),
        returned_verdict: None,
        prompt_id: None,
        call_id: None,
    }
}

#[test]
fn times_strictly_increase() {
    let mut state = SessionState::default();
    assert_eq!(state.next_time_ms(1000), 1000);
    assert_eq!(state.next_time_ms(1000), 1001);
    assert_eq!(state.next_time_ms(900), 1002);
    assert_eq!(state.next_time_ms(5000), 5000);
}

#[test]
fn state_round_trips_under_lock() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut handle = SessionHandle::open(dir.path(), "claude-code", "s1").unwrap();
        handle.state.cumulative_score = 42;
        handle.state.remember("toolu_1", decision("r1"));
        handle.save().unwrap();
    }
    let mut handle = SessionHandle::open(dir.path(), "claude-code", "s1").unwrap();
    assert_eq!(handle.state.cumulative_score, 42);
    assert_eq!(handle.state.take("toolu_1").unwrap().1.record_id, "r1");
    assert!(handle.state.take("toolu_1").is_none());
}

/// Older state files keyed entries by the harness call ID and had no
/// `call_id` field: they still correlate.
#[test]
fn entries_without_a_call_id_field_correlate_by_key() {
    let json = serde_json::json!({
        "version": STATE_VERSION, "last_time_ms": 5, "cumulative_score": 0,
        "scored_actions": 0, "denied_attempts": 0, "asked_attempts": 0,
        "pending": {"toolu_old": {"record_id": "r", "verdict": "deny", "returned": true,
            "action_score": 90, "tool_name": "Bash", "agent_id": null, "decided_at": ""}},
        "pending_order": ["toolu_old"], "agents": {}, "prompts": 0
    });
    let mut state: SessionState = serde_json::from_value(json).unwrap();
    let (journal_id, decision) = state.take("toolu_old").unwrap();
    assert_eq!(journal_id, "toolu_old");
    assert_eq!(decision.effective_verdict(), Verdict::Deny);
    assert_eq!(decision.call_id("toolu_old"), "toolu_old");
}

/// The same correlation key pending twice (a harness without call IDs, or
/// a nested call reusing its parent's ID): journal IDs stay unique, in
/// parallel and in sequence, and outcomes settle first in, first out.
#[test]
fn repeated_keys_get_unique_journal_ids_and_settle_fifo() {
    let mut state = SessionState::default();
    let first = state.journal_id("k", 1000);
    assert_eq!(first, "k~1000");
    state.remember(
        &first,
        PendingDecision {
            call_id: Some("k".into()),
            ..decision("r1")
        },
    );
    let second = state.journal_id("k", 1001);
    assert_eq!(second, "k~1001");
    state.remember(
        &second,
        PendingDecision {
            call_id: Some("k".into()),
            ..decision("r2")
        },
    );
    // A harness ID that happens to look like a journal ID cannot collide.
    state.remember("k~1002", decision("legacy"));
    assert_eq!(state.journal_id("k", 1002), "k~1002~");

    let (id, d) = state.take("k").unwrap();
    assert_eq!((id.as_str(), d.record_id.as_str()), ("k~1000", "r1"));
    state.settle(
        &id,
        Settled {
            decision: d,
            outcome_record_id: "o1".into(),
        },
    );
    let (id, d) = state.take("k").unwrap();
    assert_eq!((id.as_str(), d.record_id.as_str()), ("k~1001", "r2"));
    assert!(state.take("k").is_none());
    // Sequential repeats get fresh IDs too.
    assert_eq!(state.journal_id("k", 1003), "k~1003");

    // A settled entry is only matched by the same agent and turn.
    assert!(state.take_settled("k", Some("agent"), None).is_none());
    assert!(state.take_settled("k", None, Some("turn-9")).is_none());
    let (id, settled) = state.take_settled("k", None, None).unwrap();
    assert_eq!(
        (id.as_str(), settled.outcome_record_id.as_str()),
        ("k~1000", "o1")
    );
    assert!(state.take_settled("k", None, None).is_none());
}

#[test]
fn pending_is_bounded() {
    let mut state = SessionState::default();
    for i in 0..(MAX_PENDING + 5) {
        state.remember(&format!("t{i}"), decision("r"));
    }
    assert_eq!(state.pending.len(), MAX_PENDING);
    assert!(!state.pending.contains_key("t0"));
}

#[test]
fn session_key_hides_raw_ids() {
    let key = session_key("claude-code", "../../etc/passwd");
    assert_eq!(key.len(), 32);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
}
