use super::*;

#[test]
fn forked_thread_ordinals_continue_from_the_parent_history_base() {
    each(|source| {
        let base = json!({"history_base":{"thread_id":"thread-parent","end_ordinal_exclusive":40,"end_byte_offset":9000}});
        let fork = numbered(40, vec![meta(base.clone()), user("synthetic fork")]);
        let batch = acquire(source, &fork).unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(batch.observations[0].sequence(), Some(41));
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource
        );

        let mut invalid = Vec::new();
        // Ordinals must start exactly at the base.
        invalid.push(numbered(0, vec![meta(base.clone()), user("x")]));
        invalid.push(numbered(41, vec![meta(base.clone()), user("x")]));
        // The base is exactly a parent thread and two offsets.
        for history_base in [
            json!(0),
            json!({"end_ordinal_exclusive":40}),
            json!({"thread_id":"","end_ordinal_exclusive":40,"end_byte_offset":9000}),
            json!({"thread_id":"thread-parent","end_ordinal_exclusive":-1,"end_byte_offset":9000}),
            json!({"thread_id":"thread-parent","end_ordinal_exclusive":40,"end_byte_offset":"9000"}),
            json!({"thread_id":"thread-parent","end_ordinal_exclusive":40,"end_byte_offset":9000,"extra":1}),
        ] {
            invalid.push(numbered(
                40,
                vec![meta(json!({ "history_base": history_base })), user("x")],
            ));
        }
        // A base needs native ordinals, and only the first record may carry it.
        let mut unnumbered = vec![meta(base.clone()), user("x")];
        invalid.push(unnumbered.clone());
        unnumbered.insert(0, meta(json!({})));
        invalid.push(numbered(0, unnumbered));
        // Inherited subagent history is still unsupported.
        invalid.push(numbered(
            40,
            vec![
                meta(json!({"history_base": base["history_base"], "subagent_history_start_ordinal": 3})),
                user("x"),
            ],
        ));
        for values in invalid {
            assert!(acquire(source, &values).is_err(), "{values:?}");
        }
    });
}

#[test]
fn subagent_inherited_parent_context_is_quarantined_and_only_child_history_is_attributed() {
    each(|source| {
        let inherited = parent_context();
        let start = 1 + inherited.len() as u64;
        let values = subagent_rollout(json!(start), inherited.clone(), child_history());
        let batch = acquire(source, &values).expect("copied subagent rollout must parse");

        // Every observation is the child's own and keeps its native ordinal.
        assert!(!batch.observations.is_empty());
        for o in &batch.observations {
            assert_eq!(o.session_id().unwrap().value(), "thread-child");
            assert!(
                o.sequence().unwrap() >= start,
                "child observation precedes its own history boundary"
            );
        }
        let only_child = acquire(
            source,
            &subagent_rollout(json!(1), Vec::new(), child_history()),
        )
        .unwrap();
        assert_eq!(batch.observations.len(), only_child.observations.len());

        // Each inherited unit stays visible by itself, content-free, under the
        // file's owner at its native ordinal; nothing is silently dropped.
        assert_eq!(
            batch
                .quarantined
                .iter()
                .map(|unit| (
                    unit.code,
                    unit.session_id.as_deref(),
                    unit.native_id.as_str(),
                    unit.source_sequence
                ))
                .collect::<Vec<_>>(),
            (1..start)
                .map(|sequence| ("foreign_thread_item", Some("thread-child"), "", sequence))
                .collect::<Vec<_>>()
        );
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);

        // The copied parent metadata never opens a second session, and the
        // parent's calls are never counted as the child's activity.
        assert_eq!(batch.accounting.sessions.len(), 1);
        let session = &batch.accounting.sessions[0];
        assert_eq!(session.session_id.value(), "thread-child");
        assert_eq!(session.counts.native_units, values.len() as u64);
        assert_eq!(session.counts.record_counts.session_meta, 1);
        assert_eq!(
            session.counts.contributions,
            only_child.accounting.sessions[0].counts.contributions
        );
        assert!(!private(&batch));
        assert!(!format!("{:?}", batch.accounting).contains("PRIVATE"));

        // Child identities derive from child coordinates only: replay and
        // different inherited content with the same boundary keep them.
        let replay = acquire(source, &values).unwrap();
        let mut other = parent_context();
        other[1] = user("different parent prompt");
        other[6] = json!({"type":"another_future","payload":{}});
        let changed = acquire(
            source,
            &subagent_rollout(json!(start), other, child_history()),
        )
        .unwrap();
        for run in [&replay, &changed] {
            assert_eq!(
                batch
                    .observations
                    .iter()
                    .map(|o| (o.observation_id(), o.sequence()))
                    .collect::<Vec<_>>(),
                run.observations
                    .iter()
                    .map(|o| (o.observation_id(), o.sequence()))
                    .collect::<Vec<_>>()
            );
        }

        // An empty inherited prefix is complete and quarantines nothing.
        assert!(only_child.quarantined.is_empty());
        assert_eq!(
            only_child.accounting.coverage,
            AccountingCoverage::CompleteSource
        );

        // A child-owned item under another thread is still foreign, and an
        // inherited parent message never stands in for a child mirror.
        let mut own = child_history();
        own.push(completed(
            "thread-root",
            json!({"type":"Reasoning","id":"reason-root","summary_text":["PRIVATE"]}),
        ));
        let batch = acquire(
            source,
            &subagent_rollout(json!(start), parent_context(), own),
        )
        .unwrap();
        let last = batch.quarantined.last().unwrap();
        assert_eq!(
            (last.code, last.native_id.as_str()),
            ("foreign_thread_item", "reason-root")
        );
    });
}

#[test]
fn subagent_history_boundary_is_end_exclusive_at_the_files_last_ordinal() {
    each(|source| {
        // Metadata only, boundary 1: an empty prefix and no child history yet.
        let batch = acquire(source, &subagent_rollout(json!(1), Vec::new(), Vec::new())).unwrap();
        assert!(batch.observations.is_empty() && batch.quarantined.is_empty());
        assert_eq!(batch.accounting.sessions.len(), 1);
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource
        );

        // The file ends exactly at its last copied record: the boundary is one
        // past the final ordinal and the child has no own records yet.
        let inherited = parent_context();
        let start = 1 + inherited.len() as u64;
        let values = subagent_rollout(json!(start), inherited.clone(), Vec::new());
        assert_eq!(values.last().unwrap()["ordinal"], json!(start - 1));
        let batch = acquire(source, &values).unwrap();
        assert!(batch.observations.is_empty());
        assert_eq!(
            batch
                .quarantined
                .iter()
                .map(|unit| (unit.code, unit.source_sequence))
                .collect::<Vec<_>>(),
            (1..start)
                .map(|sequence| ("foreign_thread_item", sequence))
                .collect::<Vec<_>>()
        );
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);

        // One further past the final ordinal is an incomplete copied prefix.
        for values in [
            subagent_rollout(json!(start + 1), inherited, Vec::new()),
            subagent_rollout(json!(2), Vec::new(), Vec::new()),
        ] {
            assert!(acquire(source, &values).is_err());
        }
    });
}

#[test]
fn malformed_or_unsupported_subagent_history_boundaries_fail_the_source() {
    each(|source| {
        let inherited = parent_context();
        let start = 1 + inherited.len() as u64;
        let mut invalid = Vec::new();
        // The boundary is a u64 past the child's own metadata.
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("3"),
            json!({"end_ordinal_exclusive":3}),
        ] {
            invalid.push(subagent_rollout(bad, inherited.clone(), child_history()));
        }
        // An incomplete copied prefix: the boundary lies past the last record.
        invalid.push(subagent_rollout(
            json!(start + 10),
            inherited.clone(),
            Vec::new(),
        ));
        invalid.push(subagent_rollout(
            json!(start),
            inherited[..2].to_vec(),
            Vec::new(),
        ));
        // A copied prefix and a referenced history base are never combined.
        let mut both = subagent_rollout(json!(start), inherited.clone(), child_history());
        both[0]["payload"]["history_base"] =
            json!({"thread_id":"thread-root","end_ordinal_exclusive":0,"end_byte_offset":0});
        invalid.push(both);
        // Unpaginated rollouts have no ordinal boundary to honor.
        let mut legacy = subagent_rollout(json!(start), inherited.clone(), child_history());
        for value in &mut legacy {
            value.as_object_mut().unwrap().remove("ordinal");
        }
        invalid.push(legacy.clone());
        legacy[0]["payload"]["history_mode"] = json!("legacy");
        invalid.push(legacy);
        // Only the child's first metadata may carry the boundary.
        let mut own = child_history();
        own.push(json!({"type":"session_meta","payload":{"id":"thread-child","subagent_history_start_ordinal":1}}));
        invalid.push(subagent_rollout(json!(start), inherited.clone(), own));
        // An inherited unit is still a typed rollout record.
        for bad in [json!({}), json!({"type":7})] {
            let mut prefix = inherited.clone();
            prefix[2] = bad;
            invalid.push(subagent_rollout(json!(start), prefix, child_history()));
        }
        // Child-owned coordinates keep their checks after the boundary.
        let mut own = child_history();
        own[1]["payload"]["thread_id"] = json!("thread-root");
        invalid.push(subagent_rollout(json!(start), inherited.clone(), own));
        let mut gap = subagent_rollout(json!(start), inherited, child_history());
        gap.last_mut().unwrap()["ordinal"] = json!(99);
        invalid.push(gap);
        for values in invalid {
            let error = acquire(source, &values)
                .err()
                .unwrap_or_else(|| panic!("must fail: {}", values[0]["payload"]));
            assert!(!format!("{error:?} {error}").contains("PRIVATE"));
        }
    });
}

#[test]
fn a_parents_copies_of_subagent_items_are_quarantined_not_attributed() {
    each(|source| {
        let values = numbered(
            0,
            vec![
                meta(json!({})),
                user("synthetic parent"),
                completed(
                    "thread-subagent",
                    json!({"type":"CommandExecution","id":"call-sub","command":["PRIVATE"],"status":"completed","aggregated_output":"PRIVATE"}),
                ),
                completed(
                    "thread-subagent",
                    json!({"type":"Reasoning","id":"reason-sub","summary_text":["PRIVATE"]}),
                ),
            ],
        );
        let batch = acquire(source, &values).unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(
            batch.accounting.sessions.len(),
            1,
            "no subagent session here"
        );
        assert_eq!(
            batch
                .quarantined
                .iter()
                .map(|unit| (
                    unit.code,
                    unit.session_id.as_deref(),
                    unit.native_id.as_str(),
                    unit.source_sequence
                ))
                .collect::<Vec<_>>(),
            [
                ("foreign_thread_item", Some("thread-a"), "call-sub", 2),
                ("foreign_thread_item", Some("thread-a"), "reason-sub", 3),
            ]
        );
        assert!(!private(&batch));
    });
}

#[test]
fn inter_agent_response_items_stay_unit_quarantined_not_legacy_events() {
    each(|source| {
        // The pinned harness persists inter-agent messages as their own
        // response item type; it is not a misplaced legacy assistant event.
        let inter_agent = json!({"type":"response_item","payload":{"type":"agent_message","id":"amsg-synthetic","author":"/root","recipient":"/root/worker","content":[{"type":"input_text","text":"PRIVATE"}],"internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"}},"metadata":{"user_input_order":1}});
        // Unmapped content, even tool-shaped, is neither a tool fact nor evidence.
        let mut tool_shaped = Vec::new();
        for part in [
            json!({"type":"tool_use","id":"call-x","name":"shell","input":{"command":"curl https://private.invalid/PRIVATE /tmp/x"}}),
            json!({"type":"tool_result","tool_use_id":"call-x","content":"PRIVATE"}),
        ] {
            let mut record = inter_agent.clone();
            record["payload"]["content"] = json!([part]);
            tool_shaped.push(record);
        }
        for record in std::iter::once(&inter_agent).chain(&tool_shaped) {
            for history in ["legacy", "paginated"] {
                let batch = acquire(
                    source,
                    &[
                        meta(json!({"history_mode":history})),
                        user("before"),
                        record.clone(),
                        assistant(&["after"]),
                    ],
                )
                .expect("one unmapped unit must not fail the source");
                assert_eq!(batch.observations.len(), 2);
                assert_eq!(
                    batch
                        .quarantined
                        .iter()
                        .map(|unit| (unit.source_sequence, unit.code))
                        .collect::<Vec<_>>(),
                    [(2, "unknown_discriminator")]
                );
                assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
                let counts = &batch.accounting.sessions[0].counts;
                let kinds = &counts.record_counts;
                assert_eq!(
                    (
                        kinds.assistant_message,
                        kinds.tool_call,
                        kinds.tool_result,
                        kinds.other
                    ),
                    (1, 0, 0, 1)
                );
                assert_eq!(counts.contributions, Default::default());
                assert!(!private(&batch));
                let native =
                    super::super::super::native::extract_codex_native_records(source).unwrap();
                assert!(native[2].blocks.is_none() && native[2].message_content.is_none());
                assert!(native[2].contribution_strings.is_empty());
            }
        }
        // An exact wrapper is required: a nested payload is still integrity drift.
        let nested = json!({"type":"response_item","payload":{"type":"agent_message","payload":{"type":"agent_message","message":"PRIVATE"}}});
        let error = acquire(
            source,
            &[meta(json!({})), user("supported neighbor"), nested],
        )
        .err()
        .expect("nested wrapper must fail the source");
        assert!(!format!("{error:?} {error}").contains("PRIVATE"));
    });
}
