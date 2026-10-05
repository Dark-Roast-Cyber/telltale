//! Local synthetic semantic overlap, not production inference integration.
use std::collections::BTreeMap;

use serde_json::{Value, json};
use telltale_inference::{
    CapturePolicy, EndReason, Identity, Limits, Normalizer, Profile, ResponseFormat,
};
use telltale_schema::{
    clients::{ClientId, SourceKind},
    observation::*,
    source::Source,
};
use telltale_sources::acquisition::{
    AcquisitionOptions, OpenCodeSqliteReadOptions, acquire_opencode_sqlite, acquire_source,
};

use telltale_detect::v2::{
    RuleV1CompatibilityPlan, RuleV1DetectorOutcome, compile_rule_v1, equivalence_rule_v1_outcomes,
    equivalence_tool_process_chain_session, equivalence_tool_process_chains,
};

const USER: &str = "Synthetic equivalence user message.";
const ASSISTANT: &str = "Synthetic equivalence assistant message.";
const RESULT: &str = "Synthetic equivalence result.";
const CALL: &str = "synthetic-equivalence-call";
const COMMAND: &str = "cmd.exe /c whoami";
const PROFILES: [Profile; 4] = [
    Profile::OpenAiChat,
    Profile::AnthropicMessages,
    Profile::OpenAiResponses,
    Profile::OllamaChat,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Classification {
    Equivalent,
    ExpectedCapabilityDifference,
    Defect,
}

// No payload-bearing Debug in failures, even for synthetic fixture values.
fn equivalent<T: PartialEq>(case: &str, field: &str, left: T, right: T) {
    let classification = if left == right {
        Classification::Equivalent
    } else {
        Classification::Defect
    };
    assert!(
        classification == Classification::Equivalent,
        "{case}: {field}: {classification:?}"
    );
}

// Expected differences are pinned pairs, not a fallback for failed equivalence.
fn difference<T: PartialEq>(
    case: &str,
    field: &str,
    left: T,
    right: T,
    expected_left: T,
    expected_right: T,
) {
    let classification = if left == expected_left && right == expected_right && left != right {
        Classification::ExpectedCapabilityDifference
    } else {
        Classification::Defect
    };
    assert!(
        classification == Classification::ExpectedCapabilityDifference,
        "{case}: {field}: {classification:?}"
    );
}

fn at() -> ObservedAt {
    ObservedAt::new("2026-10-01T00:00:00Z").unwrap()
}
fn normalizer(profile: Profile) -> Normalizer {
    Normalizer::with_profile(
        profile,
        Identity {
            verified_installation: Some("11111111111111111111111111111111"),
            native_coordinate: Some("synthetic-equivalence-capture"),
            stable_sequence: None,
            request_id: None,
        },
        CapturePolicy::LocalSensitive,
        Limits::default(),
    )
    .unwrap()
}

fn request(profile: Profile, stream: bool, result_id: bool, command: &str, result: &str) -> Value {
    request_with_args(
        profile,
        stream,
        result_id,
        &json!({"command":command}),
        result,
    )
}

fn request_with_args(
    profile: Profile,
    stream: bool,
    result_id: bool,
    args: &Value,
    result: &str,
) -> Value {
    let mut tool_result = match profile {
        Profile::AnthropicMessages => {
            json!({"type":"tool_result","content":result,"is_error":false})
        }
        Profile::OpenAiResponses => json!({"type":"function_call_output","output":result}),
        _ => json!({"role":"tool","content":result}),
    };
    if result_id {
        tool_result[match profile {
            Profile::AnthropicMessages => "tool_use_id",
            Profile::OpenAiResponses => "call_id",
            _ => "tool_call_id",
        }] = json!(CALL);
    }
    if profile == Profile::OllamaChat {
        tool_result["tool_name"] = json!("shell");
    }
    let mut req = json!({"model":"synthetic-model","stream":stream});
    match profile {
        Profile::AnthropicMessages => {
            req["messages"] = json!([
                {"role":"user","content":USER},
                {"role":"assistant","content":[{"type":"tool_use","id":CALL,"name":"shell","input":args}]},
                {"role":"user","content":[tool_result]}]);
            req["tools"] = json!([{"name":"shell","input_schema":{"type":"object"}}]);
        }
        Profile::OpenAiResponses => {
            req["input"] = json!([
                {"role":"user","content":USER},
                {"type":"function_call","call_id":CALL,"name":"shell","arguments":args.to_string()}, tool_result]);
            req["tools"] =
                json!([{"type":"function","name":"shell","parameters":{"type":"object"}}]);
        }
        _ => {
            let call = if profile == Profile::OllamaChat {
                json!({"id":CALL,"function":{"name":"shell","arguments":args}})
            } else {
                json!({"id":CALL,"type":"function","function":{"name":"shell","arguments":args.to_string()}})
            };
            req["messages"] = json!([{"role":"user","content":USER},
                {"role":"assistant","content":"","tool_calls":[call]}, tool_result]);
            req["tools"] = json!([{"type":"function","function":{"name":"shell","parameters":{"type":"object"}}}]);
        }
    }
    req
}

fn response_with_args(profile: Profile, usage: bool, args: &Value) -> Value {
    let mut value = match profile {
        Profile::OpenAiChat => {
            json!({"id":"synthetic-response","model":"synthetic-model","choices":[{"index":0,"message":{"role":"assistant","content":ASSISTANT,"tool_calls":[{"id":CALL,"type":"function","function":{"name":"shell","arguments":args.to_string()}}]},"finish_reason":"tool_calls"}]})
        }
        Profile::AnthropicMessages => {
            json!({"id":"synthetic-response","type":"message","role":"assistant","model":"synthetic-model","content":[{"type":"text","text":ASSISTANT},{"type":"tool_use","id":CALL,"name":"shell","input":args}],"stop_reason":"tool_use"})
        }
        Profile::OpenAiResponses => {
            json!({"id":"synthetic-response","object":"response","status":"completed","model":"synthetic-model","output":[{"id":"synthetic-message","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":ASSISTANT,"annotations":[]}]},{"id":"synthetic-item","type":"function_call","call_id":CALL,"name":"shell","arguments":args.to_string(),"status":"completed"}]})
        }
        Profile::OllamaChat => {
            json!({"model":"synthetic-model","message":{"role":"assistant","content":ASSISTANT,"tool_calls":[{"id":CALL,"function":{"name":"shell","arguments":args}}]},"done":true,"done_reason":"stop"})
        }
    };
    if usage {
        match profile {
            Profile::OpenAiChat => {
                value["usage"] = json!({"prompt_tokens":7,"completion_tokens":9})
            }
            Profile::OllamaChat => {
                value["prompt_eval_count"] = json!(7);
                value["eval_count"] = json!(9);
            }
            _ => value["usage"] = json!({"input_tokens":7,"output_tokens":9}),
        }
    }
    value
}

fn stream(profile: Profile, value: &Value) -> (ResponseFormat, Vec<u8>) {
    let args = match profile {
        Profile::AnthropicMessages => value["content"][1]["input"].to_string(),
        Profile::OpenAiResponses => value["output"][1]["arguments"].as_str().unwrap().to_owned(),
        _ => String::new(),
    };
    let events = match profile {
        Profile::OpenAiChat => {
            let mut delta = value["choices"][0]["message"].clone();
            delta["tool_calls"][0]["index"] = json!(0);
            return (ResponseFormat::Sse, format!("data: {}\n\ndata: [DONE]\n\n", json!({"id":"synthetic-response","model":"synthetic-model","choices":[{"index":0,"delta":delta,"finish_reason":"tool_calls"}]})).into_bytes());
        }
        Profile::OllamaChat => return (ResponseFormat::Ndjson, format!("{value}\n").into_bytes()),
        Profile::AnthropicMessages => vec![
            json!({"type":"message_start","message":{"id":"synthetic-response","type":"message","role":"assistant","model":"synthetic-model","content":[],"stop_reason":null}}),
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":ASSISTANT}}),
            json!({"type":"content_block_stop","index":0}),
            json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":CALL,"name":"shell","input":{}}}),
            json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":args}}),
            json!({"type":"content_block_stop","index":1}),
            json!({"type":"message_delta","delta":{"stop_reason":"tool_use"}}),
            json!({"type":"message_stop"}),
        ],
        Profile::OpenAiResponses => vec![
            json!({"type":"response.created","response":{"id":"synthetic-response","object":"response","status":"in_progress","model":"synthetic-model","output":[]}}),
            json!({"type":"response.output_item.added","output_index":0,"item":{"id":"synthetic-message","type":"message","role":"assistant","status":"in_progress","content":[]}}),
            json!({"type":"response.content_part.added","output_index":0,"item_id":"synthetic-message","content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}),
            json!({"type":"response.output_text.delta","output_index":0,"item_id":"synthetic-message","content_index":0,"delta":ASSISTANT}),
            json!({"type":"response.output_text.done","output_index":0,"item_id":"synthetic-message","content_index":0,"text":ASSISTANT}),
            json!({"type":"response.content_part.done","output_index":0,"item_id":"synthetic-message","content_index":0,"part":value["output"][0]["content"][0]}),
            json!({"type":"response.output_item.done","output_index":0,"item":value["output"][0]}),
            json!({"type":"response.output_item.added","output_index":1,"item":{"id":"synthetic-item","type":"function_call","call_id":CALL,"name":"shell","arguments":"","status":"in_progress"}}),
            json!({"type":"response.function_call_arguments.delta","output_index":1,"item_id":"synthetic-item","delta":args}),
            json!({"type":"response.function_call_arguments.done","output_index":1,"item_id":"synthetic-item","arguments":args}),
            json!({"type":"response.output_item.done","output_index":1,"item":value["output"][1]}),
            json!({"type":"response.completed","response":value}),
        ],
    };
    let mut wire = String::new();
    for (sequence, mut event) in events.into_iter().enumerate() {
        if profile == Profile::OpenAiResponses {
            event["sequence_number"] = json!(sequence);
        }
        wire.push_str(&format!(
            "event: {}\ndata: {event}\n\n",
            event["type"].as_str().unwrap()
        ));
    }
    (ResponseFormat::Sse, wire.into_bytes())
}

fn inference(
    profile: Profile,
    streaming: bool,
    usage: bool,
    command: &str,
    result: &str,
) -> Vec<CanonicalObservationV2> {
    inference_with_args(
        profile,
        streaming,
        usage,
        &json!({"command":command}),
        result,
    )
}

fn inference_with_args(
    profile: Profile,
    streaming: bool,
    usage: bool,
    args: &Value,
    result: &str,
) -> Vec<CanonicalObservationV2> {
    let mut n = normalizer(profile);
    let mut facts = n
        .accept_request(
            &serde_json::to_vec(&request_with_args(profile, streaming, true, args, result))
                .unwrap(),
            at(),
        )
        .unwrap();
    let value = response_with_args(profile, usage, args);
    let (format, wire) = if streaming {
        stream(profile, &value)
    } else {
        (ResponseFormat::Json, serde_json::to_vec(&value).unwrap())
    };
    n.begin_response(format).unwrap();
    for chunk in wire.chunks(13) {
        n.push_response(chunk, 1).unwrap();
    }
    facts.extend(n.finish(EndReason::Complete, at(), 2).unwrap());
    facts
}

fn native(client: ClientId, command: &str, result: &str) -> Vec<CanonicalObservationV2> {
    native_with_args(client, &json!({"command":command}), result)
}

fn native_with_args(client: ClientId, args: &Value, result: &str) -> Vec<CanonicalObservationV2> {
    let dir = tempfile::tempdir().unwrap();
    let (source_id, kind) = match client {
        ClientId::Claude => ("claude.projects", SourceKind::Jsonl),
        ClientId::Codex => ("codex.sessions", SourceKind::Jsonl),
        ClientId::OpenClaw => ("openclaw.agents", SourceKind::Jsonl),
        ClientId::Qwen => ("qwen.projects", SourceKind::Jsonl),
        ClientId::Copilot => ("copilot.process_log", SourceKind::CopilotProcessLog),
        ClientId::OpenCode => ("opencode.sqlite", SourceKind::Sqlite),
        _ => unreachable!(),
    };
    let source = Source {
        client,
        source_id: source_id.into(),
        kind,
        path: dir.path().join("synthetic-equivalence-store"),
    };
    let user = json!({"type":"user","session_id":"synthetic-session","content":USER});
    let assistant =
        json!({"type":"assistant","session_id":"synthetic-session","content":ASSISTANT});
    let values = match client {
        ClientId::Claude => vec![
            user,
            assistant,
            json!({"type":"assistant","session_id":"synthetic-session","message":{"role":"assistant","content":[{"type":"tool_use","id":CALL,"name":"shell","input":args}]}}),
            json!({"type":"user","session_id":"synthetic-session","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":CALL,"content":result,"is_error":false}]}}),
        ],
        ClientId::Codex => vec![
            user,
            assistant,
            json!({"type":"assistant","session_id":"synthetic-session","content":[{"type":"tool_use","id":CALL,"name":"shell","input":args}]}),
            json!({"type":"assistant","session_id":"synthetic-session","content":[{"type":"tool_result","call_id":CALL,"content":result,"is_error":false}]}),
        ],
        _ => vec![
            user,
            assistant,
            json!({"type":"tool_call","session_id":"synthetic-session","call_id":CALL,"name":"shell","arguments":args}),
            json!({"type":"tool_result","session_id":"synthetic-session","call_id":CALL,"content":result,"is_error":false}),
        ],
    };
    if client == ClientId::OpenCode {
        let conn = rusqlite::Connection::open(&source.path).unwrap();
        conn.execute_batch("CREATE TABLE message (id TEXT, session_id TEXT, data TEXT); CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);").unwrap();
        for (id, role, text) in [
            ("synthetic-user", "user", USER),
            ("synthetic-assistant", "assistant", ASSISTANT),
        ] {
            conn.execute(
                "INSERT INTO message VALUES (?1, 'synthetic-session', ?2)",
                rusqlite::params![id, json!({"role":role,"content":text}).to_string()],
            )
            .unwrap();
        }
        for (id, state) in [
            (
                "synthetic-request",
                json!({"status":"pending","input":args}),
            ),
            (
                "synthetic-result",
                json!({"output":result,"is_error":false}),
            ),
        ] {
            conn.execute(
                "INSERT INTO part VALUES (?1, NULL, 'synthetic-session', 1, ?2)",
                rusqlite::params![
                    id,
                    json!({"type":"tool","tool":"shell","callID":CALL,"state":state}).to_string()
                ],
            )
            .unwrap();
        }
        return acquire_opencode_sqlite(
            &source,
            AcquisitionOptions::new(at()),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: None,
                part_limit: 100,
            },
        )
        .unwrap()
        .observations;
    }
    let wire = if client == ClientId::Copilot {
        let items = json!([
            {"type":"message","role":"assistant","content":[{"type":"output_text","text":ASSISTANT}]},
            {"type":"function_call","name":"shell","call_id":CALL,"arguments":args.to_string(),"status":"completed","message":result}]);
        format!(
            "2026-10-01T00:00:00Z [INFO] Workspace initialized: synthetic-session (checkpoints: 0)\n2026-10-01T00:00:01Z [INFO] Accumulated output items (2): {items}\n"
        )
    } else {
        values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    };
    std::fs::write(&source.path, wire).unwrap();
    acquire_source(&source, AcquisitionOptions::new(at()))
        .unwrap()
        .observations
}

fn tool(facts: &[CanonicalObservationV2], stage: ObservationStage) -> &CanonicalObservationV2 {
    facts
        .iter()
        .find(|o| o.kind() == ObservationFamily::Tool && o.stage() == stage)
        .expect("synthetic case: tool.stage missing")
}
fn tool_body(o: &CanonicalObservationV2) -> &ToolObservation {
    let ObservationBody::Tool(body) = o.body() else {
        panic!("synthetic case: tool.family")
    };
    body
}
fn message_text(
    facts: &[CanonicalObservationV2],
    role: MessageRole,
    text: &str,
) -> Option<(ObservationFamily, ObservationStage, MessageRole, JsonValue)> {
    facts.iter().find_map(|o| {
        let ObservationBody::Message(body) = o.body() else {
            return None;
        };
        if body.role() != Some(role) {
            return None;
        }
        let wanted = JsonValue::string(text);
        let found = body.content() == Some(&wanted)
            || body
                .content_parts()
                .iter()
                .any(|p| p.kind() == ContentPartKind::Text && p.value() == &wanted);
        found.then_some((o.kind(), o.stage(), role, wanted))
    })
}

fn overlap(
    case: &str,
    inference: &[CanonicalObservationV2],
    native: &[CanonicalObservationV2],
    client: ClientId,
    profile: Profile,
) {
    for (role, text) in [
        (MessageRole::User, USER),
        (MessageRole::Assistant, ASSISTANT),
    ] {
        let expected = Some((
            ObservationFamily::Message,
            ObservationStage::MessageObserved,
            role,
            JsonValue::string(text),
        ));
        equivalent(
            case,
            "inference.message.role_text",
            message_text(inference, role, text),
            expected.clone(),
        );
        if client == ClientId::Copilot && role == MessageRole::User {
            difference(
                case,
                "message.user",
                message_text(inference, role, text),
                message_text(native, role, text),
                expected,
                None,
            );
        } else {
            equivalent(
                case,
                "message.role_text",
                message_text(native, role, text),
                expected,
            );
        }
    }
    let proposal = tool(inference, ObservationStage::ToolProposed);
    let requested = tool(native, ObservationStage::ToolRequested);
    equivalent(case, "tool.family", proposal.kind(), requested.kind());
    difference(
        case,
        "tool.stage",
        proposal.stage(),
        requested.stage(),
        ObservationStage::ToolProposed,
        ObservationStage::ToolRequested,
    );
    for o in [proposal, requested] {
        equivalent(case, "tool.name", tool_body(o).name(), Some("shell"));
        equivalent(
            case,
            "tool.arguments",
            tool_body(o).arguments(),
            Some(&JsonValue::object([("command".into(), JsonValue::string(COMMAND))]).unwrap()),
        );
        equivalent(
            case,
            "tool.call_id",
            o.correlation().call_id().map(CorrelationId::value),
            Some(CALL),
        );
    }
    equivalent(
        case,
        "inference.command.text",
        proposal
            .facets()
            .get("command.text")
            .map(SemanticFacet::value),
        Some(&JsonValue::string(COMMAND)),
    );
    equivalent(
        case,
        "native.command.text",
        requested
            .facets()
            .get("command.text")
            .map(SemanticFacet::value),
        Some(&JsonValue::string(COMMAND)),
    );
    equivalent(
        case,
        "inference.command.provenance",
        proposal.fact_metadata()["command.text"].provenance(),
        FactProvenance::Parsed,
    );
    equivalent(
        case,
        "inference.command.sensitivity",
        proposal.fact_metadata()["command.text"].sensitivity(),
        Sensitivity::Sensitive,
    );
    equivalent(
        case,
        "inference.searchable_arguments_unavailable",
        tool_body(proposal).searchable_arguments(),
        None,
    );
    let a = tool(inference, ObservationStage::ToolResultReturned);
    let b = tool(native, ObservationStage::ToolResultReturned);
    equivalent(
        case,
        "result.family_stage",
        (a.kind(), a.stage()),
        (b.kind(), b.stage()),
    );
    for o in [a, b] {
        equivalent(
            case,
            "tool.result",
            tool_body(o).result(),
            Some(&JsonValue::string(RESULT)),
        );
        equivalent(
            case,
            "result.call_id",
            o.correlation().call_id().map(CorrelationId::value),
            Some(CALL),
        );
    }
    let a_error = tool_body(a).is_error();
    let b_error = tool_body(b).is_error();
    equivalent(
        case,
        "inference.tool.is_error",
        a_error,
        if profile == Profile::AnthropicMessages {
            Some(false)
        } else {
            None
        },
    );
    if a_error == Some(false) && client == ClientId::Copilot {
        difference(
            case,
            "tool.is_error.availability",
            a_error,
            b_error,
            Some(false),
            None,
        );
    } else if a_error == Some(false) || client == ClientId::Copilot {
        equivalent(case, "tool.is_error", a_error, b_error);
    } else {
        difference(
            case,
            "tool.is_error.availability",
            a_error,
            b_error,
            None,
            Some(false),
        );
    }
    let inference_caps = proposal
        .capability_context()
        .expect("synthetic case: inference.capabilities");
    for o in native {
        let caps = o
            .capability_context()
            .expect("synthetic case: native.capabilities");
        equivalent(
            case,
            "capability.tool_call",
            inference_caps.resolve(CapabilityId::ToolCall),
            caps.resolve(CapabilityId::ToolCall),
        );
        if client == ClientId::Copilot {
            difference(
                case,
                "capability.user_context",
                inference_caps.resolve(CapabilityId::UserContext),
                caps.resolve(CapabilityId::UserContext),
                CapabilityAvailability::Supported,
                CapabilityAvailability::Unsupported,
            );
        } else {
            equivalent(
                case,
                "capability.user_context",
                inference_caps.resolve(CapabilityId::UserContext),
                caps.resolve(CapabilityId::UserContext),
            );
        }
        if matches!(client, ClientId::Claude | ClientId::Codex) {
            equivalent(
                case,
                "capability.execution",
                inference_caps.resolve(CapabilityId::ToolExecution),
                caps.resolve(CapabilityId::ToolExecution),
            );
        } else {
            difference(
                case,
                "capability.execution",
                inference_caps.resolve(CapabilityId::ToolExecution),
                caps.resolve(CapabilityId::ToolExecution),
                CapabilityAvailability::Unsupported,
                if client == ClientId::OpenCode {
                    CapabilityAvailability::Supported
                } else {
                    CapabilityAvailability::Unknown
                },
            );
        }
    }
    equivalent(
        case,
        "native.execution_absent",
        native.iter().any(is_execution),
        false,
    );
    difference(
        case,
        "definition.availability",
        inference
            .iter()
            .any(|o| o.kind() == ObservationFamily::ToolDefinition),
        native
            .iter()
            .any(|o| o.kind() == ObservationFamily::ToolDefinition),
        true,
        false,
    );
}

fn shared_projection(
    facts: &[CanonicalObservationV2],
) -> Vec<(
    ObservationFamily,
    ObservationStage,
    BTreeMap<&'static str, JsonValue>,
)> {
    facts
        .iter()
        .filter_map(|o| {
            let mut fields = BTreeMap::new();
            match o.body() {
                ObservationBody::Message(body) => {
                    // Empty historical assistant messages are accepted in Chat and
                    // Ollama, but are not part of the shared nonempty text case.
                    let Some(JsonValue::String(text)) = body.content() else {
                        return None;
                    };
                    if text.is_empty() {
                        return None;
                    }
                    fields.insert("message.role", JsonValue::string(body.role()?.as_str()));
                    fields.insert("message.text", JsonValue::string(text));
                }
                ObservationBody::Tool(body) => {
                    if let Some(name) = body.name() {
                        fields.insert("tool.name", JsonValue::string(name));
                    }
                    if let Some(args) = body.arguments() {
                        fields.insert("tool.arguments", args.clone());
                    }
                    if let Some(result) = body.result() {
                        fields.insert("tool.result", result.clone());
                    }
                    if let Some(call) = o.correlation().call_id() {
                        fields.insert("tool.call_id", JsonValue::string(call.value()));
                    }
                    // is_error is reported only by the Anthropic profile.
                }
                ObservationBody::ToolDefinition(body) => {
                    fields.insert("definition.name", JsonValue::string(body.name()?));
                    fields.insert("definition.change", JsonValue::string(body.change()?));
                }
                _ => return None,
            }
            Some((o.kind(), o.stage(), fields))
        })
        .collect()
}

#[test]
fn cross_profile_shared_semantic_projection_is_equivalent() {
    let baseline = shared_projection(&inference(
        Profile::OpenAiChat,
        false,
        false,
        COMMAND,
        RESULT,
    ));
    equivalent(
        "synthetic-cross-profile",
        "shared.projection.count",
        baseline.len(),
        6,
    );
    for profile in PROFILES {
        for streaming in [false, true] {
            let case = format!("{}/streaming-{streaming}", profile.version());
            equivalent(
                &case,
                "shared.family_stage_messages_name_arguments_result_definition_call_id",
                shared_projection(&inference(profile, streaming, false, COMMAND, RESULT)),
                baseline.clone(),
            );
        }
    }
}

fn is_execution(o: &CanonicalObservationV2) -> bool {
    o.kind() == ObservationFamily::Process
        || matches!(
            o.stage(),
            ObservationStage::ToolExecutionStarted | ObservationStage::ToolExecutionCompleted
        )
}

#[test]
fn profiles_json_stream_and_native_semantic_matrix() {
    for profile in PROFILES {
        let case = profile.version();
        let json = inference(profile, false, false, COMMAND, RESULT);
        let streaming = inference(profile, true, false, COMMAND, RESULT);
        let semantic = |facts: &[CanonicalObservationV2]| {
            facts
                .iter()
                .filter(|o| o.kind() != ObservationFamily::Inference)
                .map(|o| {
                    (
                        o.kind(),
                        o.stage(),
                        o.body().clone(),
                        o.correlation().call_id().cloned(),
                    )
                })
                .collect::<Vec<_>>()
        };
        equivalent(
            case,
            "json_stream.semantic",
            semantic(&json),
            semantic(&streaming),
        );
        for facts in [&json, &streaming] {
            for o in facts {
                o.validate().unwrap();
                equivalent(case, "inference.execution_absent", is_execution(o), false);
                let caps = o
                    .capability_context()
                    .expect("synthetic case: inference.capabilities");
                equivalent(
                    case,
                    "inference.capability.execution",
                    caps.resolve(CapabilityId::ToolExecution),
                    CapabilityAvailability::Unsupported,
                );
                equivalent(
                    case,
                    "inference.capability.user_context",
                    caps.resolve(CapabilityId::UserContext),
                    CapabilityAvailability::Supported,
                );
                equivalent(
                    case,
                    "inference.capability.tool_call",
                    caps.resolve(CapabilityId::ToolCall),
                    CapabilityAvailability::Supported,
                );
            }
            let definition = facts
                .iter()
                .find(|o| o.kind() == ObservationFamily::ToolDefinition)
                .expect("synthetic case: definition missing");
            equivalent(
                case,
                "definition.stage",
                definition.stage(),
                ObservationStage::DefinitionChanged,
            );
            let ObservationBody::ToolDefinition(body) = definition.body() else {
                unreachable!()
            };
            equivalent(case, "definition.name", body.name(), Some("shell"));
            equivalent(case, "definition.change", body.change(), Some("present"));
            for client in [
                ClientId::Claude,
                ClientId::Codex,
                ClientId::OpenCode,
                ClientId::OpenClaw,
                ClientId::Qwen,
                ClientId::Copilot,
            ] {
                let case = format!("{case}/{client:?}");
                overlap(
                    &case,
                    facts,
                    &native(client, COMMAND, RESULT),
                    client,
                    profile,
                );
            }
        }
        let reported = inference(profile, false, true, COMMAND, RESULT);
        let completed_metrics = |facts: &[CanonicalObservationV2]| {
            let o = facts
                .iter()
                .find(|o| o.stage() == ObservationStage::InferenceCompleted)
                .expect("synthetic case: completed missing");
            let ObservationBody::Inference(body) = o.body() else {
                unreachable!()
            };
            body.metrics().clone()
        };
        equivalent(
            case,
            "usage.absent",
            completed_metrics(&json),
            InferenceMetrics::default(),
        );
        equivalent(
            case,
            "stream.usage.absent",
            completed_metrics(&streaming),
            InferenceMetrics::default(),
        );
        equivalent(
            case,
            "usage.reported",
            completed_metrics(&reported),
            InferenceMetrics::default()
                .with_input_tokens(7)
                .with_output_tokens(9),
        );
    }
}

#[test]
fn missing_result_ids_do_not_join_by_name_or_position() {
    for profile in PROFILES {
        let case = profile.version();
        let facts = normalizer(profile)
            .accept_request(
                &serde_json::to_vec(&request(profile, false, false, COMMAND, RESULT)).unwrap(),
                at(),
            )
            .unwrap();
        equivalent(
            case,
            "proposal.explicit_id",
            tool(&facts, ObservationStage::ToolProposed)
                .correlation()
                .call_id()
                .map(CorrelationId::value),
            Some(CALL),
        );
        equivalent(
            case,
            "result.missing_id",
            tool(&facts, ObservationStage::ToolResultReturned)
                .correlation()
                .call_id(),
            None,
        );
        equivalent(
            case,
            "result.not_execution",
            facts.iter().any(is_execution),
            false,
        );
    }
}

fn synthetic_plan(target: &str) -> RuleV1CompatibilityPlan {
    let positive = match target {
        "command" => r"cmd\.exe /c whoami",
        "file_path" => r"^synthetic-equivalence/synthetic\.txt$",
        _ => "^shell$",
    };
    let rules: telltale_rules::RuleSet = serde_json::from_value(json!({
        "version":1,"description":"Synthetic equivalence rules","defaults":{"case_insensitive":false,"enabled":true},"modifiers":[],
        "rules":[
            {"id":"synthetic.equivalence.positive","category":"synthetic","severity":"low","score":10,"targets":[target],"regex":positive,"tags":[],"explanation":"Synthetic shared fact match."},
            {"id":"synthetic.equivalence.nonmatch","category":"synthetic","severity":"low","score":10,"targets":[target],"regex":"synthetic-value-never-present","tags":[],"explanation":"Synthetic explicit non-match."}
        ]})).unwrap();
    compile_rule_v1(&rules.compile(None).unwrap().compatibility_export()).unwrap()
}

#[test]
fn shared_object_command_rule_v1_equivalence_gate() {
    let plan = synthetic_plan("command");
    let native_cases = [
        ClientId::Codex,
        ClientId::OpenCode,
        ClientId::OpenClaw,
        ClientId::Qwen,
        ClientId::Copilot,
        ClientId::Claude,
    ]
    .into_iter()
    .map(|client| {
        (
            format!("synthetic-object-command/{client:?}"),
            native(client, COMMAND, RESULT),
        )
    });
    let inference_cases = PROFILES.into_iter().flat_map(|profile| {
        [false, true].map(|streaming| {
            (
                format!("{}/object-command/streaming-{streaming}", profile.version()),
                inference(profile, streaming, false, COMMAND, RESULT),
            )
        })
    });
    // Exercise the command member through the existing command.text selector,
    // not an expansion of generic structured-argument matching.
    let outcomes = inference_cases
        .chain(native_cases)
        .map(|(case, facts)| (case, rule_outcomes(&plan, &facts)))
        .collect::<Vec<_>>();
    for (case, outcome) in &outcomes {
        equivalent(
            case,
            "command.explicit_nonmatch",
            outcome["synthetic.equivalence.nonmatch"],
            RuleV1DetectorOutcome::NoMatch,
        );
    }
    for (case, outcome) in outcomes {
        equivalent(
            &case,
            "command.positive",
            outcome["synthetic.equivalence.positive"],
            RuleV1DetectorOutcome::Match,
        );
    }
}

#[test]
fn cmd_only_command_equivalence_gate() {
    let plan = synthetic_plan("command");
    let args = json!({"cmd":COMMAND});
    let native_cases = [
        ClientId::Claude,
        ClientId::Codex,
        ClientId::OpenCode,
        ClientId::OpenClaw,
        ClientId::Qwen,
        ClientId::Copilot,
    ]
    .into_iter()
    .map(|client| {
        (
            format!("synthetic-cmd/{client:?}"),
            native_with_args(client, &args, RESULT),
        )
    });
    let inference_cases = PROFILES.into_iter().flat_map(|profile| {
        [false, true].map(|streaming| {
            (
                format!("{}/cmd/streaming-{streaming}", profile.version()),
                inference_with_args(profile, streaming, false, &args, RESULT),
            )
        })
    });
    for (case, facts) in native_cases.chain(inference_cases) {
        let stage = if facts[0].source().adapter_id().starts_with("inference.") {
            ObservationStage::ToolProposed
        } else {
            ObservationStage::ToolRequested
        };
        equivalent(
            &case,
            "cmd.tool.stage_present",
            tool(&facts, stage).stage(),
            stage,
        );
        for proposal in facts.iter().filter(|o| o.stage() == stage) {
            equivalent(
                &case,
                "cmd.command.text",
                proposal
                    .facets()
                    .get("command.text")
                    .map(SemanticFacet::value),
                Some(&JsonValue::string(COMMAND)),
            );
            equivalent(
                &case,
                "cmd.command.provenance",
                proposal.fact_metadata()["command.text"].provenance(),
                FactProvenance::Parsed,
            );
            equivalent(
                &case,
                "cmd.command.sensitivity",
                proposal.fact_metadata()["command.text"].sensitivity(),
                if stage == ObservationStage::ToolProposed {
                    Sensitivity::Sensitive
                } else {
                    Sensitivity::Normal
                },
            );
        }
        let outcomes = rule_outcomes(&plan, &facts);
        equivalent(
            &case,
            "cmd.rule_v1.positive",
            outcomes["synthetic.equivalence.positive"],
            RuleV1DetectorOutcome::Match,
        );
        equivalent(
            &case,
            "cmd.rule_v1.nonmatch",
            outcomes["synthetic.equivalence.nonmatch"],
            RuleV1DetectorOutcome::NoMatch,
        );
        equivalent(
            &case,
            "cmd.bundled.process_ids",
            process_ids(&facts),
            vec!["procchain.discovery.cmd_whoami".to_owned()],
        );
        let results = facts
            .into_iter()
            .filter(|o| o.stage() == ObservationStage::ToolResultReturned)
            .collect::<Vec<_>>();
        equivalent(
            &case,
            "cmd.results.no_command_facet",
            results
                .iter()
                .any(|o| o.facets().get("command.text").is_some()),
            false,
        );
        equivalent(
            &case,
            "cmd.results.process_ids",
            process_ids(&results),
            Vec::<String>::new(),
        );
    }
}

#[test]
fn inference_command_precedence_and_string_fallback_gate() {
    for profile in PROFILES {
        for streaming in [false, true] {
            for (args, expected) in [
                (
                    json!({"command":COMMAND,"cmd":"synthetic benign command"}),
                    Some(COMMAND),
                ),
                (json!({"command":17,"cmd":COMMAND}), Some(COMMAND)),
                (json!({"command":null,"cmd":COMMAND}), Some(COMMAND)),
                (json!({"command":"","cmd":COMMAND}), Some("")),
                (json!({"command":false,"cmd":17}), None),
            ] {
                let facts = inference_with_args(profile, streaming, false, &args, COMMAND);
                for proposal in facts
                    .iter()
                    .filter(|o| o.stage() == ObservationStage::ToolProposed)
                {
                    equivalent(
                        profile.version(),
                        "command.string_precedence",
                        proposal
                            .facets()
                            .get("command.text")
                            .map(SemanticFacet::value),
                        expected.map(JsonValue::string).as_ref(),
                    );
                }
                let result = tool(&facts, ObservationStage::ToolResultReturned);
                equivalent(
                    profile.version(),
                    "result.command_absent",
                    result.facets().get("command.text"),
                    None,
                );
                equivalent(
                    profile.version(),
                    "result.command_metadata_absent",
                    result.fact_metadata().contains_key("command.text"),
                    false,
                );
            }
        }
    }
}

#[test]
fn path_selector_expected_difference_gate() {
    let plan = synthetic_plan("file_path");
    let bundled = compile_rule_v1(
        &telltale_rules::load_default_rule_set()
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    for key in ["file_path", "path"] {
        let args = json!({key:"synthetic-equivalence/synthetic.txt"});
        let native = native_with_args(ClientId::Qwen, &args, RESULT);
        let expected_bundled = rule_outcomes(&bundled, &native);
        let expected_process = process_ids(&native);
        for profile in PROFILES {
            let facts = inference_with_args(profile, false, false, &args, RESULT);
            let case = format!("{}/{key}", profile.version());
            difference(
                profile.version(),
                "path.selector.outcome",
                rule_outcomes(&plan, &native)["synthetic.equivalence.positive"],
                rule_outcomes(&plan, &facts)["synthetic.equivalence.positive"],
                RuleV1DetectorOutcome::Match,
                RuleV1DetectorOutcome::NoMatch,
            );
            equivalent(
                profile.version(),
                "path.arguments.preserved",
                tool_body(tool(&facts, ObservationStage::ToolProposed)).arguments(),
                Some(&JsonValue::try_from_source_value(&args).unwrap()),
            );
            let outcomes = rule_outcomes(&bundled, &facts);
            equivalent(
                &case,
                "path.bundled.detector_ids",
                outcomes.keys().collect::<Vec<_>>(),
                expected_bundled.keys().collect::<Vec<_>>(),
            );
            for (id, expected) in &expected_bundled {
                assert_eq!(
                    *expected, outcomes[id],
                    "{case}: bundled.{id}: Qwen vs inference"
                );
            }
            equivalent(
                &case,
                "path.bundled.process_ids",
                process_ids(&facts),
                expected_process.clone(),
            );
        }
    }
}

fn rule_outcomes(
    plan: &RuleV1CompatibilityPlan,
    facts: &[CanonicalObservationV2],
) -> BTreeMap<String, RuleV1DetectorOutcome> {
    let refs = facts.iter().collect::<Vec<_>>();
    equivalence_rule_v1_outcomes(plan, &refs).unwrap()
}

fn process_ids(facts: &[CanonicalObservationV2]) -> Vec<String> {
    let rules = telltale_rules::process_chain::load_default_process_chain_rules().unwrap();
    let context = telltale_rules::process_chain::ProcessChainContext::default();
    let mut ids = Vec::new();
    for o in facts {
        ids.extend(
            equivalence_tool_process_chains(&rules, o, &context)
                .unwrap()
                .iter()
                .map(|d| d.detector().id().to_owned()),
        );
    }
    ids.sort();
    ids.dedup();
    let refs = facts.iter().collect::<Vec<_>>();
    let session = equivalence_tool_process_chain_session(&rules, &refs, &context).unwrap();
    let mut session_ids = session
        .iter()
        .map(|d| d.detector().id().to_owned())
        .collect::<Vec<_>>();
    session_ids.sort();
    session_ids.dedup();
    equivalent(
        "synthetic-command-text",
        "atomic_session.detector_ids",
        ids.clone(),
        session_ids,
    );
    ids
}

#[test]
fn real_detectors_match_command_text_across_paths_not_returned_execution() {
    let plan = synthetic_plan("tool_name");
    let bundled = compile_rule_v1(
        &telltale_rules::load_default_rule_set()
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let baseline = native(ClientId::Codex, COMMAND, RESULT);
    let expected = rule_outcomes(&plan, &baseline);
    equivalent(
        "synthetic",
        "positive.outcome",
        expected["synthetic.equivalence.positive"],
        RuleV1DetectorOutcome::Match,
    );
    equivalent(
        "synthetic",
        "nonmatch.outcome",
        expected["synthetic.equivalence.nonmatch"],
        RuleV1DetectorOutcome::NoMatch,
    );
    let expected_bundled = rule_outcomes(&bundled, &baseline);
    let expected_process = process_ids(&baseline);
    equivalent(
        "synthetic",
        "command_text.detector_id",
        expected_process.clone(),
        vec!["procchain.discovery.cmd_whoami".to_owned()],
    );
    let paths = PROFILES
        .into_iter()
        .flat_map(|p| {
            [
                inference(p, false, false, COMMAND, RESULT),
                inference(p, true, false, COMMAND, RESULT),
            ]
        })
        .chain(
            [
                ClientId::Codex,
                ClientId::OpenCode,
                ClientId::OpenClaw,
                ClientId::Qwen,
                ClientId::Copilot,
            ]
            .into_iter()
            .map(|c| native(c, COMMAND, RESULT)),
        );
    for (index, facts) in paths.enumerate() {
        let case = format!("synthetic-detector-path-{index}");
        equivalent(
            &case,
            "rule_v1.outcomes",
            rule_outcomes(&plan, &facts),
            expected.clone(),
        );
        let outcomes = rule_outcomes(&bundled, &facts);
        equivalent(
            &case,
            "bundled.rule_v1.detector_count",
            outcomes.len(),
            expected_bundled.len(),
        );
        let copilot = facts
            .iter()
            .any(|o| o.source().adapter_id() == "copilot.process_log");
        for (id, baseline) in &expected_bundled {
            let field = format!("bundled.{id}.outcome");
            if copilot
                && matches!(
                    id.as_str(),
                    "approval.bypass.context"
                        | "credential.api_key.pattern"
                        | "mcp.server_enumeration"
                        | "mcp.tool_metadata.prompt_injection"
                        | "network.controlled_test_domain.darkroast"
                        | "secret.env.read"
                        | "tool.injection.shape"
                )
            {
                difference(
                    &case,
                    &field,
                    *baseline,
                    outcomes[id],
                    RuleV1DetectorOutcome::NoMatch,
                    RuleV1DetectorOutcome::Indeterminate,
                );
            } else {
                equivalent(&case, &field, *baseline, outcomes[id]);
            }
        }
        equivalent(
            &case,
            "process_chain.command_text_ids",
            process_ids(&facts),
            expected_process.clone(),
        );
        let results = facts
            .into_iter()
            .filter(|o| o.stage() == ObservationStage::ToolResultReturned)
            .collect::<Vec<_>>();
        equivalent(
            &case,
            "result.only.process_ids",
            process_ids(&results),
            Vec::<String>::new(),
        );
    }
    // Put the command ONLY in result bodies; proposals/requests are benign.
    for profile in PROFILES {
        let facts = inference(profile, false, false, "synthetic benign command", COMMAND);
        equivalent(
            profile.version(),
            "result.command.process_ids",
            process_ids(&facts),
            Vec::<String>::new(),
        );
        equivalent(
            profile.version(),
            "result.command.rule_v1.nonmatch",
            rule_outcomes(&plan, &facts)["synthetic.equivalence.nonmatch"],
            RuleV1DetectorOutcome::NoMatch,
        );
    }
    for client in [
        ClientId::Claude,
        ClientId::Codex,
        ClientId::OpenCode,
        ClientId::OpenClaw,
        ClientId::Qwen,
        ClientId::Copilot,
    ] {
        let facts = native(client, "synthetic benign command", COMMAND);
        equivalent(
            "synthetic-native-result-command",
            "process_ids",
            process_ids(&facts),
            Vec::<String>::new(),
        );
        equivalent(
            "synthetic-native-result-command",
            "rule_v1.nonmatch",
            rule_outcomes(&plan, &facts)["synthetic.equivalence.nonmatch"],
            RuleV1DetectorOutcome::NoMatch,
        );
    }
}

#[test]
fn claude_object_command_detector_equivalence_gate() {
    let plan = synthetic_plan("tool_name");
    let bundled = compile_rule_v1(
        &telltale_rules::load_default_rule_set()
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let facts = native(ClientId::Claude, COMMAND, RESULT);
    let baseline = inference(Profile::OpenAiChat, false, false, COMMAND, RESULT);
    equivalent(
        "synthetic-claude-object-command",
        "synthetic.rule_v1.outcomes",
        rule_outcomes(&plan, &facts),
        rule_outcomes(&plan, &baseline),
    );
    equivalent(
        "synthetic-claude-object-command",
        "command.facet_and_bundled.rule_v1_and_process_chain.command_text",
        (
            tool(&facts, ObservationStage::ToolRequested)
                .facets()
                .get("command.text"),
            rule_outcomes(&bundled, &facts),
            process_ids(&facts),
        ),
        (
            tool(&baseline, ObservationStage::ToolProposed)
                .facets()
                .get("command.text"),
            rule_outcomes(&bundled, &baseline),
            process_ids(&baseline),
        ),
    );
}

#[test]
fn native_execution_is_an_expected_difference_not_a_returned_result() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-execution.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE part (id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);",
    )
    .unwrap();
    conn.execute("INSERT INTO part VALUES ('synthetic-execution', 'synthetic-session', 1, ?1)", [json!({"type":"tool","tool":"shell","callID":CALL,"state":{"status":"completed","input":{"command":COMMAND},"output":RESULT}}).to_string()]).unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path,
    };
    let facts = acquire_opencode_sqlite(
        &source,
        AcquisitionOptions::new(at()),
        OpenCodeSqliteReadOptions {
            part_min_time_updated: None,
            part_limit: 100,
        },
    )
    .unwrap()
    .observations;
    let completed = tool(&facts, ObservationStage::ToolExecutionCompleted);
    equivalent(
        "synthetic-native-execution",
        "capability.execution",
        completed
            .capability_context()
            .unwrap()
            .resolve(CapabilityId::ToolExecution),
        CapabilityAvailability::Supported,
    );
    for profile in PROFILES {
        let inference = inference(profile, false, false, COMMAND, RESULT);
        difference(
            profile.version(),
            "execution.capability",
            completed
                .capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolExecution),
            tool(&inference, ObservationStage::ToolProposed)
                .capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Supported,
            CapabilityAvailability::Unsupported,
        );
        difference(
            profile.version(),
            "execution.observed",
            facts.iter().any(is_execution),
            inference.iter().any(is_execution),
            true,
            false,
        );
        equivalent(
            profile.version(),
            "returned_result.not_execution",
            is_execution(tool(&facts, ObservationStage::ToolResultReturned)),
            false,
        );
    }
}
