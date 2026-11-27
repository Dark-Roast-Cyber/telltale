//! The terminal commands for always grants (docs/hooks/adr/0010-grants.md):
//! `telltale hooks allow` makes a project or user grant from a stopped call's
//! decision record after the person at the terminal confirms it, `grants`
//! lists the grants and the files left out, and `revoke` removes one. They
//! write and read only `grants.d` of the root the hook reads grants from
//! ([`super::grants_root`]); the hook only reads it. `allow` and `revoke`
//! leave a lifecycle record in the hook's records file.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use telltale_core::hooks::config::{Config, GrantCover, HOST_RULE_ID_PREFIX};
use telltale_core::hooks::grants::{self, AlwaysGrant, AlwaysScope, GRANTS_DIR};
use telltale_core::hooks::harness::Harness;
use telltale_core::hooks::runtime::Runtime;
use telltale_core::hooks::telemetry::{Sink, is_record_too_large, label, sha256_hex};
use telltale_schema::event::SanitizationContext::Metadata;
use telltale_schema::hooks_record::{
    HOOK_LABEL_MAX_BYTES, HOOKS_RECORD_MAX_INPUT_BYTES, escaped_hook_label, readable_hook_text,
};

/// Where an `allow` grant reaches.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum AllowScope {
    /// `--project [DIR]`: the directory named, else the current one.
    Project(Option<PathBuf>),
    /// `--user`.
    User,
}

/// `allow` arguments: the config roots, the record ID and the scope.
pub(super) fn allow_flags(flags: &[&str]) -> Option<(Vec<PathBuf>, String, AllowScope)> {
    let mut roots = Vec::new();
    let mut record = None;
    let mut scope = None;
    let mut flags = flags.iter().copied().peekable();
    while let Some(flag) = flags.next() {
        let next = match flag {
            "--user" => Some(AllowScope::User),
            "--project" => Some(AllowScope::Project(
                flags
                    .next_if(|value| !value.starts_with('-'))
                    .map(PathBuf::from),
            )),
            _ => match flag.strip_prefix("--project=") {
                Some(dir) if !dir.is_empty() => Some(AllowScope::Project(Some(dir.into()))),
                Some(_) => return None,
                None => None,
            },
        };
        if next.is_some() {
            if scope.is_some() {
                return None;
            }
            scope = next;
            continue;
        }
        match flag {
            "--config-dir" => {
                roots.push(flag);
                roots.push(flags.next()?);
            }
            _ if flag.starts_with('-') => roots.push(flag),
            _ if record.is_none() => record = Some(flag.to_owned()),
            _ => return None,
        }
    }
    Some((super::config_dirs(&roots)?, record?, scope?))
}

/// `grants` arguments: the config roots and `--json`.
pub(super) fn list_flags(flags: &[&str]) -> Option<(Vec<PathBuf>, bool)> {
    let json = flags.contains(&"--json");
    let roots: Vec<&str> = flags.iter().copied().filter(|f| *f != "--json").collect();
    Some((super::config_dirs(&roots)?, json))
}

/// `revoke` arguments: the config roots and the grant ID.
pub(super) fn revoke_flags(flags: &[&str]) -> Option<(Vec<PathBuf>, String)> {
    let mut roots = Vec::new();
    let mut id = None;
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        match flag {
            "--config-dir" => {
                roots.push(flag);
                roots.push(flags.next()?);
            }
            _ if flag.starts_with('-') => roots.push(flag),
            _ if id.is_none() => id = Some(flag.to_owned()),
            _ => return None,
        }
    }
    Some((super::config_dirs(&roots)?, id?))
}

/// Text with control characters replaced, for a line of output.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            // Control characters, and the format characters that reorder
            // or hide text, would make the confirmation show something else.
            let hidden = c.is_control()
                || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}');
            if hidden { ' ' } else { c }
        })
        .collect()
}

/// The `grants.d` folder the hook reads grants from under `config_dirs`.
fn grants_dir(config_dirs: &[PathBuf]) -> Result<PathBuf, String> {
    super::grants_root(config_dirs)
        .map(|root| root.join(GRANTS_DIR))
        .ok_or_else(|| "no user configuration root (set HOME or XDG_CONFIG_HOME)".to_owned())
}

/// The project directory of `--project [DIR]`, absolute and not resolved
/// through symlinks: the hook compares directories as written.
pub(super) fn project_dir(dir: Option<&Path>) -> std::io::Result<PathBuf> {
    match dir {
        Some(dir) => std::path::absolute(dir),
        None => std::env::current_dir(),
    }
}

/// The decision record `record_id` in the records file at `path`: the first
/// bounded line with that ID. Oversized and malformed lines are passed over.
fn find_record(path: &Path, record_id: &str) -> Result<Value, String> {
    use telltale_sources::journal::{self, JournalFile};
    let read_error = |error| format!("cannot read the records file {}: {error}", path.display());
    let discovery = journal::discover_generations(path, usize::MAX).map_err(read_error)?;
    if discovery.generations.is_empty() {
        return Err(read_error(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )));
    }
    let mut line = Vec::new();
    for generation in discovery.generations.into_iter().rev() {
        let file = JournalFile::open(&generation.path).map_err(read_error)?;
        if file.identity() != generation.identity {
            return Err(read_error(std::io::Error::other(
                "records rotated during lookup; retry",
            )));
        }
        let mut reader = std::io::BufReader::new(file.into_file());
        loop {
            line.clear();
            if reader
                .by_ref()
                .take(HOOKS_RECORD_MAX_INPUT_BYTES as u64)
                .read_until(b'\n', &mut line)
                .map_err(read_error)?
                == 0
            {
                break;
            }
            if line.len() == HOOKS_RECORD_MAX_INPUT_BYTES && !line.ends_with(b"\n") {
                reader.skip_until(b'\n').map_err(read_error)?;
                continue;
            }
            let Ok(record) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            if record["record_id"] == record_id {
                return Ok(record);
            }
        }
    }
    Err(format!(
        "no record {} in {}",
        printable(record_id),
        path.display()
    ))
}

/// What a grant made from `record` would allow: its harness, tool and
/// detections (sorted, without repeats), or why a grant could not cover it.
/// The same rules as the hook's (`RequestDecision::grantable`), as far as
/// the record carries them: the evaluation must be `complete` with no
/// visibility limits.
fn grantable(
    record: &Value,
    covers: GrantCover,
) -> Result<(&'static str, String, Vec<String>), String> {
    if record["kind"] != "decision" {
        return Err("it is not a decision record".to_owned());
    }
    let decision = &record["decision"];
    if decision["returned"] != true {
        return Err("nothing was returned for it: the call was not stopped".to_owned());
    }
    match (decision["verdict"].as_str(), covers) {
        (Some("ask"), _) | (Some("deny"), GrantCover::AskAndDeny) => {}
        (Some("deny"), GrantCover::Ask) => {
            return Err("it was denied, and hooks.grants.covers is ask".to_owned());
        }
        _ => return Err("its verdict is neither ask nor deny".to_owned()),
    }
    let basis = decision["basis"].as_str().unwrap_or_default();
    if !matches!(basis, "action_score" | "session_score" | "repeated_denials") {
        return Err(format!(
            "it was decided by {}, not by the policy's scores",
            printable(basis)
        ));
    }
    let mut rule_ids: Vec<String> = decision["rule_ids"]
        .as_array()
        .map(|ids| {
            ids.iter()
                .filter_map(|id| id.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    rule_ids.sort();
    rule_ids.dedup();
    if rule_ids.is_empty() {
        return Err("it matched no rule".to_owned());
    }
    if rule_ids
        .iter()
        .any(|id| id.starts_with(HOST_RULE_ID_PREFIX))
    {
        return Err(format!(
            "it matched a rule under {HOST_RULE_ID_PREFIX}, which no grant covers"
        ));
    }
    let evaluation = &record["evaluation"];
    if evaluation["status"] != "complete"
        || evaluation["visibility_limits"]
            .as_array()
            .is_none_or(|limits| !limits.is_empty())
    {
        return Err("the hook did not see the whole call".to_owned());
    }
    let harness = record["harness"]["name"]
        .as_str()
        .and_then(Harness::from_name)
        .ok_or("it names no known harness")?
        .name();
    let tool = record["action"]["tool_name"]
        .as_str()
        .filter(|tool| !tool.is_empty())
        .ok_or("it names no tool")?
        .to_owned();
    Ok((harness, tool, rule_ids))
}

/// A grant `allow` wrote.
#[derive(Debug)]
pub(super) struct Allowed {
    pub(super) id: String,
    pub(super) path: PathBuf,
}

/// The decision of `allow`: the grant for the decision record `record_id` in
/// `records`, under `config`, written to `dir` once the person at the
/// terminal (`terminal`: stdin and stderr are both terminals) types `allow`
/// on `input` after reading what it allows on `out`. `project` is the
/// project directory, absolute, or `None` for a user grant. An error is the
/// message to print; nothing is written then.
#[allow(clippy::too_many_arguments)]
pub(super) fn allow(
    config: &Config,
    records: &Path,
    dir: &Path,
    record_id: &str,
    project: Option<PathBuf>,
    terminal: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Allowed, String> {
    if !config.grants.enabled {
        return Err("grants are off (hooks.grants.enabled: false)".to_owned());
    }
    let record = find_record(records, record_id)?;
    let (harness, tool_label, rule_ids) = grantable(&record, config.grants.covers)
        .map_err(|cause| format!("record {} cannot be allowed: {cause}", printable(record_id)))?;
    if !terminal {
        return Err("run this in a terminal yourself; it asks you to confirm".to_owned());
    }
    // A terminal grant stores the original tool name for exact matching.
    // Recover that name from the operator, without displaying it, when the
    // record contains only a stand-in.
    let tool = if escaped_hook_label(&tool_label) {
        let _ =
            out.write_all(b"The record hides the tool name. Enter the exact native tool name: ");
        let _ = out.flush();
        let mut entered = String::new();
        if input.read_line(&mut entered).is_err() {
            return Err("nothing allowed".to_owned());
        }
        let entered = entered.strip_suffix('\n').map_or(entered.as_str(), |line| {
            line.strip_suffix('\r').unwrap_or(line)
        });
        if !readable_hook_text(entered, HOOK_LABEL_MAX_BYTES)
            || entered != entered.trim()
            || label(entered, Metadata) != tool_label
        {
            return Err("tool name does not match the record; nothing allowed".to_owned());
        }
        entered.to_owned()
    } else {
        tool_label.clone()
    };
    let mut grant = AlwaysGrant {
        id: String::new(),
        version: grants::GRANT_FILE_VERSION,
        scope: if project.is_some() {
            AlwaysScope::Project
        } else {
            AlwaysScope::User
        },
        project,
        harness: harness.to_owned(),
        tool,
        rule_ids,
        created_at: String::new(),
        from_record: record_id.to_owned(),
    };
    let sink = Sink::with_rotation(records.to_owned(), config.telemetry_rotation.clone());
    // The assigned ID replaces a same-width ASCII ID in this exact record,
    // so the size cannot change after the grant has been stored.
    let mut telemetry = Runtime::new(config.clone())
        .terminal_record(harness, grant_lifecycle(&grant, "g-000000000000"));
    Sink::check_record_size(&telemetry).map_err(|error| {
        if is_record_too_large(&error) {
            "grant record exceeds the Hooks telemetry line limit; nothing allowed".to_owned()
        } else {
            format!("cannot encode the grant record: {error}; nothing allowed")
        }
    })?;
    let reach = match &grant.project {
        Some(project) => format!(
            "project {} and below",
            printable(&project.display().to_string())
        ),
        None => "user (every directory)".to_owned(),
    };
    let shown = format!(
        "This allows, from now on and without asking again, calls of\n  \
         tool: {}\n  harness: {harness}\n  detections: {}\n  scope: {reach}\n  \
         stopped call: {}\n\
         Telltale will no longer stop such a call; the harness's own permission rules still apply.\n\
         Type allow to confirm: ",
        printable(&tool_label),
        printable(&grant.rule_ids.join(", ")),
        printable(record_id),
    );
    let _ = out.write_all(shown.as_bytes());
    let _ = out.flush();
    let mut answer = String::new();
    if input.read_line(&mut answer).is_err() || answer.trim() != "allow" {
        return Err("nothing allowed".to_owned());
    }
    grant.created_at = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|now| {
            now.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default();
    let id = grants::write(dir, &grant)
        .map_err(|error| format!("cannot write the grant in {}: {error}", dir.display()))?;
    if let Some(lifecycle) = &mut telemetry.lifecycle {
        lifecycle["grant_id"] = json!(id);
    }
    if let Err(error) = sink.write(&telemetry) {
        eprintln!("telltale hooks: telemetry write failed: {error}");
    }
    Ok(Allowed {
        path: dir.join(format!("{id}.yaml")),
        id,
    })
}

/// The lifecycle details of a terminal grant record.
fn grant_lifecycle(grant: &AlwaysGrant, id: &str) -> Value {
    let mut lifecycle = json!({
        "event": "grant",
        "scope": grant.scope.as_str(),
        "tool": grant.tool,
        "rule_ids": grant.rule_ids,
        "offer_record_id": grant.from_record,
        "grant_id": id,
    });
    if let Some(project) = &grant.project {
        lifecycle["project_sha256"] = sha256_hex(project.to_string_lossy().as_bytes()).into();
    }
    lifecycle
}

/// `telltale hooks allow`.
pub(super) fn run_allow(config_dirs: &[PathBuf], record_id: &str, scope: AllowScope) -> i32 {
    let fail = |message: &str| {
        eprintln!("telltale hooks allow: {message}");
        1
    };
    let config = match super::load_config(config_dirs) {
        Ok(config) => config,
        Err(error) => return fail(&format!("config: {error}")),
    };
    let records = match config.resolved_telemetry_path() {
        Ok(path) => path,
        Err(error) => return fail(&format!("no records file: {error}")),
    };
    let dir = match grants_dir(config_dirs) {
        Ok(dir) => dir,
        Err(error) => return fail(&error),
    };
    let project = match scope {
        AllowScope::User => None,
        AllowScope::Project(dir) => match project_dir(dir.as_deref()) {
            Ok(dir) => Some(dir),
            Err(error) => return fail(&format!("no project directory: {error}")),
        },
    };
    let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let allowed = allow(
        &config,
        &records,
        &dir,
        record_id,
        project,
        terminal,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr(),
    );
    match allowed {
        Ok(allowed) => {
            println!("allowed: {} ({})", allowed.id, allowed.path.display());
            0
        }
        Err(error) => fail(&error),
    }
}

/// `telltale hooks grants`.
pub(super) fn run_list(config_dirs: &[PathBuf], as_json: bool) -> i32 {
    let config = match super::load_config(config_dirs) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("telltale hooks grants: config: {error}");
            return 1;
        }
    };
    let dir = match grants_dir(config_dirs) {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("telltale hooks grants: {error}");
            return 1;
        }
    };
    let (always, left_out) = grants::load_dir(&dir);
    if as_json {
        let document = json!({
            "grants_enabled": config.grants.enabled,
            "root": dir.parent().map(Path::to_path_buf),
            "grants": always.iter().map(|grant| json!({
                "id": grant.id,
                "scope": grant.scope.as_str(),
                "project": grant.project,
                "harness": grant.harness,
                "tool": grant.tool,
                "rule_ids": grant.rule_ids,
                "created_at": grant.created_at,
                "from_record": grant.from_record,
            })).collect::<Vec<_>>(),
            "left_out": left_out.iter().map(|entry| json!({
                "path": entry.path,
                "cause": entry.cause,
            })).collect::<Vec<_>>(),
        });
        println!("{document}");
        return 0;
    }
    println!(
        "grants: {} ({} always grants in {})",
        if config.grants.enabled {
            "on (hooks.grants.enabled: true)"
        } else {
            "off (hooks.grants.enabled: false): the grants below cover nothing"
        },
        always.len(),
        dir.display()
    );
    for grant in &always {
        let scope = match &grant.project {
            Some(project) => format!(
                "project {} and below",
                printable(&project.display().to_string())
            ),
            None => "user".to_owned(),
        };
        println!("grant {}", grant.id);
        println!("  scope: {scope}");
        println!("  harness: {}", printable(&grant.harness));
        println!("  tool: {}", printable(&grant.tool));
        println!("  detections: {}", printable(&grant.rule_ids.join(", ")));
        println!("  created_at: {}", printable(&grant.created_at));
        println!("  from_record: {}", printable(&grant.from_record));
    }
    for entry in &left_out {
        println!(
            "grant left out: {}: {}",
            printable(&entry.path.display().to_string()),
            entry.cause
        );
    }
    0
}

/// `telltale hooks revoke`.
pub(super) fn run_revoke(config_dirs: &[PathBuf], id: &str) -> i32 {
    let fail = |message: &str| {
        eprintln!("telltale hooks revoke: {message}");
        1
    };
    if !grants::is_grant_id(id) {
        return fail(&format!("{} is not a grant ID", printable(id)));
    }
    let config = match super::load_config(config_dirs) {
        Ok(config) => config,
        Err(error) => return fail(&format!("config: {error}")),
    };
    let dir = match grants_dir(config_dirs) {
        Ok(dir) => dir,
        Err(error) => return fail(&error),
    };
    // The harness of the record, when the file still names a known one.
    let harness = grants::load_file(&dir.join(format!("{id}.yaml")))
        .ok()
        .and_then(|grant| Harness::from_name(&grant.harness))
        .map_or("", Harness::name);
    match grants::remove(&dir, id) {
        Ok(()) => {
            println!("revoked: {id}");
            Runtime::new(config)
                .record_terminal(harness, json!({"event": "grant_revoked", "grant_id": id}));
            0
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fail(&format!("no grant {id} in {}", dir.display()))
        }
        Err(error) => fail(&format!("cannot remove {id}: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hooks_allow_finds_a_rotated_decision() {
        let fixture = Fixture::new(&decision(|_| {}));
        let active = fixture.dir.path().join("records.jsonl");
        std::fs::rename(&active, active.with_file_name("records-2026-11-26.1.jsonl")).unwrap();
        std::fs::write(active, b"{}\n").unwrap();
        assert!(fixture.allow(true, "allow\n", None).is_ok());
        assert_eq!(fixture.written()[0].from_record, RECORD_ID);
    }
    #[test]
    fn find_record_skips_oversized_lines_and_resumes_at_the_next_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.jsonl");
        let mut oversized =
            serde_json::to_vec(&json!({"record_id": "synthetic-oversized"})).unwrap();
        oversized.resize(16 * 1024 * 1024, b' ');
        oversized.extend_from_slice(b"\n{\"record_id\":\"synthetic-next\"}\n");
        std::fs::write(&path, oversized).unwrap();
        assert!(find_record(&path, "synthetic-oversized").is_err());
        assert_eq!(
            find_record(&path, "synthetic-next").unwrap()["record_id"],
            "synthetic-next"
        );
        let mut at_limit = serde_json::to_vec(&json!({"record_id": "synthetic-exact"})).unwrap();
        at_limit.resize(HOOKS_RECORD_MAX_INPUT_BYTES - 1, b' ');
        at_limit.push(b'\n');
        std::fs::write(&path, at_limit).unwrap();
        assert_eq!(
            find_record(&path, "synthetic-exact").unwrap()["record_id"],
            "synthetic-exact"
        );
    }

    #[test]
    fn an_oversized_grant_lifecycle_is_refused_before_storing_the_grant() {
        let mut record = decision(|_| {});
        record["decision"]["rule_ids"] = json!([""]);
        let overhead = serde_json::to_vec(&record).unwrap().len() + 1;
        record["decision"]["rule_ids"][0] = json!("a".repeat(16 * 1024 * 1024 - overhead));
        let dir = tempfile::tempdir().unwrap();
        let records = dir.path().join("records.jsonl");
        std::fs::write(&records, format!("{record}\n")).unwrap();
        let mut config = Config::default();
        config.grants.enabled = true;
        let grants = dir.path().join("grants.d");
        let original_len = std::fs::metadata(&records).unwrap().len();
        let result = allow(
            &config,
            &records,
            &grants,
            RECORD_ID,
            None,
            true,
            &mut "allow\n".as_bytes(),
            &mut std::io::sink(),
        );
        assert!(matches!(result, Err(error) if error.contains("grant record exceeds")));
        assert!(!grants.exists());
        assert_eq!(std::fs::metadata(&records).unwrap().len(), original_len);
    }

    /// What the confirmation prints cannot be reordered or hidden by the
    /// text of a record.
    #[test]
    fn printable_text_has_no_control_or_reordering_characters() {
        assert_eq!(
            printable("a\u{202e}b\u{1b}[2Jc\u{2066}d\u{200b}e"),
            "a b [2Jc d e"
        );
        assert_eq!(printable("tth.test.deny, Bash"), "tth.test.deny, Bash");
    }

    const RECORD_ID: &str = "tth:0123456789abcdef0123456789abcdef";

    fn decision(edit: impl FnOnce(&mut Value)) -> Value {
        let mut record = json!({
            "record_id": RECORD_ID,
            "kind": "decision",
            "harness": {"name": "claude-code", "hook_event": "PreToolUse", "permission_mode": null},
            "action": {"tool_name": "Bash"},
            "evaluation": {"status": "complete", "visibility_limits": []},
            "decision": {
                "verdict": "ask", "returned": true, "basis": "action_score",
                "rule_ids": ["synthetic.b", "synthetic.a", "synthetic.b"],
            },
        });
        edit(&mut record);
        record
    }

    struct Fixture {
        dir: tempfile::TempDir,
        config: Config,
    }

    impl Fixture {
        fn new(record: &Value) -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("records.jsonl"),
                format!("not json\n{{\"record_id\": \"other\"}}\n{record}\n"),
            )
            .unwrap();
            let mut config = Config::default();
            config.grants.enabled = true;
            Self { dir, config }
        }

        fn grants(&self) -> PathBuf {
            self.dir.path().join("grants.d")
        }

        fn allow(
            &self,
            terminal: bool,
            answer: &str,
            project: Option<&str>,
        ) -> Result<Allowed, String> {
            let mut out = Vec::new();
            allow(
                &self.config,
                &self.dir.path().join("records.jsonl"),
                &self.grants(),
                RECORD_ID,
                project.map(PathBuf::from),
                terminal,
                &mut answer.as_bytes(),
                &mut out,
            )
        }

        fn written(&self) -> Vec<AlwaysGrant> {
            let (grants, left_out) = grants::load_dir(&self.grants());
            assert_eq!(left_out, []);
            grants
        }

        fn last_lifecycle(&self) -> Value {
            let wire = std::fs::read_to_string(self.dir.path().join("records.jsonl")).unwrap();
            let record =
                telltale_core::HooksRecordV1::from_json(wire.lines().last().unwrap().as_bytes())
                    .unwrap();
            serde_json::to_value(record.lifecycle.unwrap()).unwrap()
        }
    }

    fn project() -> String {
        if cfg!(windows) {
            r"C:\work\app".to_owned()
        } else {
            "/work/app".to_owned()
        }
    }

    /// Without a terminal nothing is asked and nothing written.
    #[test]
    fn without_a_terminal_nothing_is_allowed() {
        let f = Fixture::new(&decision(|_| {}));
        let error = f.allow(false, "allow\n", None).unwrap_err();
        assert_eq!(
            error,
            "run this in a terminal yourself; it asks you to confirm"
        );
        assert!(!f.grants().exists());
    }

    /// Any answer but `allow` writes nothing.
    #[test]
    fn another_answer_allows_nothing() {
        let f = Fixture::new(&decision(|_| {}));
        for answer in ["", "\n", "yes\n", "allow it\n", "Allow\n"] {
            assert_eq!(f.allow(true, answer, None).unwrap_err(), "nothing allowed");
        }
        assert!(!f.grants().exists());
    }

    /// `allow` writes the grant the record names, and says what it allows.
    #[test]
    fn allow_writes_the_grant_of_the_record() {
        let f = Fixture::new(&decision(|_| {}));
        let mut out = Vec::new();
        let allowed = allow(
            &f.config,
            &f.dir.path().join("records.jsonl"),
            &f.grants(),
            RECORD_ID,
            Some(PathBuf::from(project())),
            true,
            &mut "  allow \n".as_bytes(),
            &mut out,
        )
        .unwrap();
        let shown = String::from_utf8(out).unwrap();
        assert!(
            shown.contains(&format!("scope: project {} and below", project())),
            "{shown}"
        );
        assert!(
            shown.contains("detections: synthetic.a, synthetic.b"),
            "{shown}"
        );
        assert!(shown.ends_with("Type allow to confirm: "), "{shown}");
        let written = f.written();
        assert_eq!(written.len(), 1);
        let grant = &written[0];
        assert_eq!(grant.id, allowed.id);
        assert_eq!(
            allowed.path,
            f.grants().join(format!("{}.yaml", allowed.id))
        );
        assert_eq!(grant.scope, AlwaysScope::Project);
        assert_eq!(grant.project, Some(PathBuf::from(project())));
        assert_eq!(grant.harness, "claude-code");
        assert_eq!(grant.tool, "Bash");
        assert_eq!(grant.rule_ids, ["synthetic.a", "synthetic.b"]);
        assert_eq!(grant.from_record, RECORD_ID);
        let lifecycle = f.last_lifecycle();
        assert_eq!(lifecycle["event"], "grant");
        assert_eq!(lifecycle["scope"], "project");
        assert_eq!(lifecycle["grant_id"], allowed.id.as_str());
        assert_eq!(lifecycle["offer_record_id"], RECORD_ID);
        assert_eq!(
            lifecycle["project_sha256"],
            sha256_hex(project().as_bytes()).as_str()
        );

        let user = f.allow(true, "allow\n", None).unwrap();
        let written = f.written();
        let grant = written.iter().find(|grant| grant.id == user.id).unwrap();
        assert_eq!(grant.scope, AlwaysScope::User);
        assert_eq!(grant.project, None);
        let lifecycle = f.last_lifecycle();
        assert_eq!(lifecycle["grant_id"], user.id);
        assert!(lifecycle.get("project_sha256").is_none());
        assert_eq!(written.len(), 2);
    }

    #[test]
    fn an_escaped_tool_label_requires_its_native_name_before_confirmation() {
        const NATIVE: &str = "AKIASYNTHETIC0000000";
        let f = Fixture::new(&decision(|record| {
            record["action"]["tool_name"] = json!("tth-esc-5faaaacc6cfeecf6f7080b39f21abf8f");
        }));
        let error = f.allow(true, "synthetic-other\nallow\n", None).unwrap_err();
        assert_eq!(
            error,
            "tool name does not match the record; nothing allowed"
        );
        assert!(!f.grants().exists());

        let mut out = Vec::new();
        allow(
            &f.config,
            &f.dir.path().join("records.jsonl"),
            &f.grants(),
            RECORD_ID,
            None,
            true,
            &mut format!("{NATIVE}\nallow\n").as_bytes(),
            &mut out,
        )
        .unwrap();
        assert!(!String::from_utf8(out).unwrap().contains(NATIVE));
        let grant = f.written().remove(0);
        assert!(grant.covers("claude-code", NATIVE, None, &["synthetic.a".into()]));
        assert!(!grant.covers(
            "claude-code",
            "tth-esc-5faaaacc6cfeecf6f7080b39f21abf8f",
            None,
            &["synthetic.a".into()],
        ));
    }

    /// A record a grant could not cover is refused before anything is
    /// asked, with the cause.
    #[test]
    fn a_record_no_grant_could_cover_is_refused() {
        type Edit = fn(&mut Value);
        let cases: [(&str, Edit); 10] = [
            ("not a decision record", |r| r["kind"] = "outcome".into()),
            ("not stopped", |r| r["decision"]["returned"] = false.into()),
            ("neither ask nor deny", |r| {
                r["decision"]["verdict"] = "allow".into()
            }),
            ("not by the policy's scores", |r| {
                r["decision"]["basis"] = "on_unevaluable".into()
            }),
            ("matched no rule", |r| r["decision"]["rule_ids"] = json!([])),
            ("tth.tamper.", |r| {
                r["decision"]["rule_ids"] = json!(["a", "tth.tamper.x"])
            }),
            ("did not see the whole call", |r| {
                r["evaluation"]["status"] = "visibility_limited".into();
            }),
            ("did not see the whole call", |r| {
                r["evaluation"]["visibility_limits"] = json!(["state_dir_unresolved"]);
            }),
            ("no known harness", |r| {
                r["harness"]["name"] = "other".into()
            }),
            ("no tool", |r| r["action"]["tool_name"] = Value::Null),
        ];
        for (cause, edit) in cases {
            let f = Fixture::new(&decision(edit));
            let error = f.allow(true, "allow\n", None).unwrap_err();
            assert!(error.contains(cause), "{cause}: {error}");
            assert!(error.contains("cannot be allowed"), "{error}");
            assert!(!f.grants().exists(), "{cause}");
        }
    }

    /// Under `covers: ask` a deny is refused; by default it is allowed.
    #[test]
    fn covers_ask_refuses_a_deny() {
        let mut f = Fixture::new(&decision(|r| r["decision"]["verdict"] = "deny".into()));
        f.config.grants.covers = GrantCover::Ask;
        let error = f.allow(true, "allow\n", None).unwrap_err();
        assert!(error.contains("hooks.grants.covers is ask"), "{error}");
        assert!(!f.grants().exists());
        f.config.grants.covers = GrantCover::AskAndDeny;
        assert!(f.allow(true, "allow\n", None).is_ok());
    }

    /// Grants off, an unknown record, or a missing records file: refused.
    #[test]
    fn grants_off_or_no_record_is_refused() {
        let mut f = Fixture::new(&decision(|_| {}));
        f.config.grants.enabled = false;
        assert_eq!(
            f.allow(true, "allow\n", None).unwrap_err(),
            "grants are off (hooks.grants.enabled: false)"
        );
        let f = Fixture::new(&decision(|r| r["record_id"] = "tth:other".into()));
        assert!(
            f.allow(true, "allow\n", None)
                .unwrap_err()
                .starts_with("no record ")
        );
        std::fs::remove_file(f.dir.path().join("records.jsonl")).unwrap();
        assert!(
            f.allow(true, "allow\n", None)
                .unwrap_err()
                .starts_with("cannot read the records file")
        );
        assert!(!f.grants().exists());
    }

    /// A relative `--project` is made absolute against the current
    /// directory, without resolving symlinks; none means the current one.
    #[test]
    fn the_project_directory_is_made_absolute() {
        let current = std::env::current_dir().unwrap();
        assert_eq!(project_dir(None).unwrap(), current);
        let dir = project_dir(Some(Path::new("some/dir"))).unwrap();
        assert!(dir.is_absolute());
        assert_eq!(dir, current.join("some").join("dir"));
    }

    #[test]
    fn allow_takes_one_record_and_exactly_one_scope() {
        let parse = |flags: &[&str]| allow_flags(flags).map(|(_, id, scope)| (id, scope));
        assert_eq!(
            parse(&["tth:1", "--user"]),
            Some(("tth:1".into(), AllowScope::User))
        );
        assert_eq!(
            parse(&["tth:1", "--project"]),
            Some(("tth:1".into(), AllowScope::Project(None)))
        );
        assert_eq!(
            parse(&["--project", "dir", "tth:1"]),
            Some(("tth:1".into(), AllowScope::Project(Some("dir".into()))))
        );
        assert_eq!(
            parse(&["tth:1", "--project=dir", "--config-dir", "r"]),
            Some(("tth:1".into(), AllowScope::Project(Some("dir".into()))))
        );
        for refused in [
            &["tth:1"][..],
            &["--user"],
            &["tth:1", "--user", "--project"],
            &["tth:1", "tth:2", "--user"],
            &["tth:1", "--user", "--bogus"],
            &["tth:1", "--project="],
        ] {
            assert_eq!(parse(refused), None, "{refused:?}");
        }
    }
}
