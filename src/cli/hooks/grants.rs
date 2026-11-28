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
            "grant record exceeds the Hooks telemetry line or array limits; nothing allowed"
                .to_owned()
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
mod tests;
