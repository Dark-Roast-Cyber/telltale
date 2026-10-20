//! Upstream harness format cases.
//!
//! Each `tests/upstream_formats/cases/<client>/<case>.json` holds a synthetic
//! store shaped like what a pinned upstream harness release writes, links to
//! the pinned upstream lines that define that shape, and Telltale's outcome.
//! `supported` cases assert a floor. `known_gap` and `out_of_scope` cases
//! assert the current failure exactly, so fixing a gap fails its case until it
//! is promoted to `supported`. See `tests/upstream_formats/README.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rusqlite::{Connection, types::Value as SqlValue};
use serde::Deserialize;
use serde_json::Value;
use telltale_schema::observation::{ObservationBody, ObservedAt};
use telltale_schema::source::Source;
use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};
use telltale_sources::clients::{ClientDef, ClientSourceDef, supported_clients};

const CASES: &str = "tests/upstream_formats/cases";
const HARNESSES: &str = "tests/upstream_formats/harnesses.json";
const OBSERVED_AT: &str = "2026-10-13T00:00:00Z";

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Status {
    Supported,
    KnownGap,
    OutOfScope,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    description: String,
    harness: String,
    upstream: Vec<String>,
    status: Status,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
    #[serde(default)]
    acquire: Option<Acquire>,
    #[serde(default)]
    discover: Option<Discover>,
    expect: Expect,
}

/// One native source read through the library acquisition API.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acquire {
    source_id: String,
    #[serde(flatten)]
    input: Input,
}

/// Session-store files under a synthetic home, read by the scan binary with
/// environment-resolved discovery (`--root .`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Discover {
    client: String,
    files: BTreeMap<String, Input>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    #[serde(default)]
    jsonl: Option<Vec<Value>>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    hex: Option<String>,
    #[serde(default)]
    fixture: Option<String>,
    #[serde(default)]
    sqlite: Option<Sqlite>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sqlite {
    schema: Vec<String>,
    #[serde(default)]
    rows: BTreeMap<String, Vec<BTreeMap<String, Value>>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    observations: Option<usize>,
    #[serde(default)]
    min_observations: Option<usize>,
    #[serde(default)]
    min_families: BTreeMap<String, usize>,
    /// Exact sorted unique quarantine codes; none when omitted.
    #[serde(default)]
    quarantine_codes: Option<Vec<String>>,
    /// Exact number of message observations with no content; zero when omitted.
    #[serde(default)]
    empty_messages: Option<usize>,
    #[serde(default)]
    selected_sources: Option<u64>,
    #[serde(default)]
    min_records: Option<u64>,
    #[serde(default)]
    failure_codes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Harness {
    client: String,
    repository: String,
    tag: String,
    commit: String,
    checked: String,
    tag_pattern: String,
    /// Guidance for whoever re-reads the upstream code; not used by the tests.
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load_harnesses() -> BTreeMap<String, Harness> {
    let text = fs::read_to_string(repo_path(HARNESSES)).expect("harness manifest");
    serde_json::from_str(&text).expect("harness manifest JSON")
}

fn load_cases() -> Vec<(String, Case)> {
    let mut cases = Vec::new();
    let root = repo_path(CASES);
    let mut clients = fs::read_dir(&root)
        .expect("cases directory")
        .map(|entry| entry.expect("client directory").path())
        .collect::<Vec<_>>();
    clients.sort();
    for client in clients {
        let mut files = fs::read_dir(&client)
            .expect("client cases")
            .map(|entry| entry.expect("case file").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect::<Vec<_>>();
        files.sort();
        for path in files {
            let name = path
                .strip_prefix(&root)
                .expect("case path")
                .with_extension("")
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path).expect("case file");
            let case = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{name}: invalid case: {error}"));
            cases.push((name, case));
        }
    }
    assert!(!cases.is_empty(), "no upstream format cases found");
    cases
}

fn client_def(client: &str) -> &'static ClientDef {
    supported_clients()
        .iter()
        .find(|def| def.id.as_str() == client)
        .unwrap_or_else(|| panic!("{client} is not a registered client"))
}

fn source_def(source_id: &str) -> (&'static ClientDef, ClientSourceDef) {
    supported_clients()
        .iter()
        .find_map(|client| {
            client
                .sources
                .iter()
                .find(|source| source.id == source_id)
                .map(|source| (client, *source))
        })
        .unwrap_or_else(|| panic!("{source_id} is not a registered source identity"))
}

/// Whether `url` points into the harness repository at its pinned commit.
fn cites_pinned_harness(url: &str, harness: &Harness) -> bool {
    url.starts_with(&format!(
        "https://github.com/{}/blob/{}/",
        harness.repository, harness.commit
    ))
}

const PLATFORMS: &[&str] = &["linux", "macos", "windows"];

/// Writes one case input to `path`.
fn write_input(name: &str, input: &Input, path: &Path) {
    fs::create_dir_all(path.parent().expect("input parent")).expect("input parent");
    let given = [
        input.jsonl.is_some(),
        input.text.is_some(),
        input.hex.is_some(),
        input.fixture.is_some(),
        input.sqlite.is_some(),
    ];
    assert_eq!(
        given.iter().filter(|given| **given).count(),
        1,
        "{name}: give exactly one of jsonl, text, hex, fixture or sqlite"
    );
    if let Some(records) = &input.jsonl {
        let text = records
            .iter()
            .map(|record| serde_json::to_string(record).expect("record") + "\n")
            .collect::<String>();
        fs::write(path, text).expect("write JSONL");
    } else if let Some(text) = &input.text {
        fs::write(path, text).expect("write text");
    } else if let Some(hex) = &input.hex {
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
            .collect::<Vec<_>>();
        fs::write(path, bytes).expect("write bytes");
    } else if let Some(fixture) = &input.fixture {
        fs::copy(repo_path(fixture), path)
            .unwrap_or_else(|error| panic!("{name}: copy {fixture}: {error}"));
    } else if let Some(sqlite) = &input.sqlite {
        write_sqlite(name, sqlite, path);
    }
}

/// Builds a SQLite store; object and array cell values are stored as compact
/// JSON text, the way the harnesses store their `data` columns. Tables are
/// filled in name order, so foreign keys are only enforced by the schema.
fn write_sqlite(name: &str, sqlite: &Sqlite, path: &Path) {
    let connection = Connection::open(path).expect("open SQLite");
    connection
        .execute_batch("PRAGMA foreign_keys = OFF")
        .expect("disable foreign keys while seeding");
    connection
        .execute_batch(&sqlite.schema.join(";\n"))
        .unwrap_or_else(|error| panic!("{name}: schema: {error}"));
    for (table, rows) in &sqlite.rows {
        for row in rows {
            let columns = row.keys().cloned().collect::<Vec<_>>();
            let placeholders = vec!["?"; columns.len()].join(", ");
            let sql = format!(
                "INSERT INTO {table} ({}) VALUES ({placeholders})",
                columns.join(", ")
            );
            let values = row
                .values()
                .map(|value| match value {
                    Value::Null => SqlValue::Null,
                    Value::Bool(value) => SqlValue::Integer(i64::from(*value)),
                    Value::Number(number) => number
                        .as_i64()
                        .map(SqlValue::Integer)
                        .unwrap_or_else(|| SqlValue::Real(number.as_f64().expect("number"))),
                    Value::String(text) => SqlValue::Text(text.clone()),
                    other => SqlValue::Text(serde_json::to_string(other).expect("JSON cell")),
                })
                .collect::<Vec<_>>();
            connection
                .execute(&sql, rusqlite::params_from_iter(values))
                .unwrap_or_else(|error| panic!("{name}: insert into {table}: {error}"));
        }
    }
}

/// What Telltale did with a case, in the vocabulary of `expect`.
#[derive(Debug, Default)]
struct Outcome {
    error: Option<String>,
    observations: usize,
    families: BTreeMap<String, usize>,
    quarantine_codes: Vec<String>,
    empty_messages: usize,
    selected_sources: u64,
    records: u64,
    failure_codes: Vec<String>,
}

fn run_acquire(name: &str, acquire: &Acquire, dir: &Path) -> Outcome {
    let (client, def) = source_def(&acquire.source_id);
    let file_name = if acquire.input.sqlite.is_some() {
        "opencode.db"
    } else {
        "input.jsonl"
    };
    let path = dir.join(file_name);
    write_input(name, &acquire.input, &path);
    let source = Source {
        client: client.id,
        kind: def.kind,
        source_id: def.id.to_owned(),
        path,
    };
    match acquire_source(
        &source,
        AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).expect("observed time")),
    ) {
        Ok(batch) => {
            let mut families = BTreeMap::new();
            let mut empty_messages = 0;
            for observation in &batch.observations {
                let family = serde_json::to_value(observation.kind()).expect("family");
                *families
                    .entry(family.as_str().expect("family name").to_owned())
                    .or_insert(0) += 1;
                if let ObservationBody::Message(message) = observation.body()
                    && message.content().is_none()
                    && message.content_parts().is_empty()
                {
                    empty_messages += 1;
                }
            }
            Outcome {
                observations: batch.observations.len(),
                families,
                empty_messages,
                quarantine_codes: batch
                    .quarantined
                    .iter()
                    .map(|unit| unit.code.to_owned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                ..Outcome::default()
            }
        }
        Err(error) => Outcome {
            error: Some(error.code().to_owned()),
            ..Outcome::default()
        },
    }
}

fn run_discover(name: &str, discover: &Discover, dir: &Path) -> Outcome {
    client_def(&discover.client);
    let home = dir.join("home");
    let work = dir.join("work");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&work).expect("work");
    for (relative, input) in &discover.files {
        write_input(name, input, &home.join(relative));
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command
        .env_clear()
        .current_dir(&work)
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .args(["scan", "--once", "--dry-run", "--client", &discover.client])
        .args(["--no-local-config", "--install-inventory-disabled"])
        .arg("--state-path")
        .arg(dir.join("state.json"))
        .arg("--log-path")
        .arg(dir.join("events.jsonl"));
    for key in ["PATH", "SystemRoot", "windir"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let home_text = home.to_string_lossy().into_owned();
    for (key, value) in &discover.env {
        command.env(key, value.replace("{home}", &home_text));
    }
    let output = command.output().expect("run telltale scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let health = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .rfind(|event| event.get("source_processing").is_some())
        .unwrap_or_else(|| {
            panic!(
                "{name}: no health event (exit {:?})\nstdout: {stdout}\nstderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let processing = &health["source_processing"];
    let failure_codes = processing["failures"]
        .as_array()
        .map(|failures| {
            failures
                .iter()
                .filter_map(|failure| failure["acquisition_code"].as_str())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    Outcome {
        selected_sources: processing["selected_source_count"].as_u64().unwrap_or(0),
        records: processing["parsed_record_count"].as_u64().unwrap_or(0),
        failure_codes,
        ..Outcome::default()
    }
}

/// Returns the mismatches between a case's expectation and its outcome.
fn compare(case: &Case, outcome: &Outcome) -> Vec<String> {
    let expect = &case.expect;
    let mut problems = Vec::new();
    if case.acquire.is_some() {
        if expect.error != outcome.error {
            problems.push(format!(
                "error: expected {:?}, got {:?}",
                expect.error, outcome.error
            ));
        }
        if let Some(exact) = expect.observations
            && exact != outcome.observations
        {
            problems.push(format!(
                "observations: expected {exact}, got {}",
                outcome.observations
            ));
        }
        if let Some(floor) = expect.min_observations
            && outcome.observations < floor
        {
            problems.push(format!(
                "observations: expected at least {floor}, got {}",
                outcome.observations
            ));
        }
        for (family, floor) in &expect.min_families {
            let got = outcome.families.get(family).copied().unwrap_or(0);
            if got < *floor {
                problems.push(format!(
                    "{family} observations: expected at least {floor}, got {got}"
                ));
            }
        }
        let codes = expect.quarantine_codes.clone().unwrap_or_default();
        if codes != outcome.quarantine_codes {
            problems.push(format!(
                "quarantine codes: expected {codes:?}, got {:?}",
                outcome.quarantine_codes
            ));
        }
        let empty = expect.empty_messages.unwrap_or(0);
        if empty != outcome.empty_messages {
            problems.push(format!(
                "messages without content: expected {empty}, got {}",
                outcome.empty_messages
            ));
        }
    } else {
        if let Some(exact) = expect.selected_sources
            && exact != outcome.selected_sources
        {
            problems.push(format!(
                "selected sources: expected {exact}, got {}",
                outcome.selected_sources
            ));
        }
        if let Some(floor) = expect.min_records
            && outcome.records < floor
        {
            problems.push(format!(
                "records: expected at least {floor}, got {}",
                outcome.records
            ));
        }
        let codes = expect.failure_codes.clone().unwrap_or_default();
        if codes != outcome.failure_codes {
            problems.push(format!(
                "failure codes: expected {codes:?}, got {:?}",
                outcome.failure_codes
            ));
        }
    }
    problems
}

/// Rejects cases whose expectation could not fail or whose provenance is
/// not pinned, before anything runs.
fn validate_case(name: &str, case: &Case, harnesses: &BTreeMap<String, Harness>) {
    assert!(!case.description.trim().is_empty(), "{name}: description");
    let harness = harnesses
        .get(&case.harness)
        .unwrap_or_else(|| panic!("{name}: harness {} is not in {HARNESSES}", case.harness));
    assert!(
        case.upstream
            .iter()
            .any(|url| cites_pinned_harness(url, harness)),
        "{name}: cite at least one https://github.com/{}/blob/{}/ URL",
        harness.repository,
        harness.commit
    );
    assert!(
        case.status == Status::Supported || case.note.is_some(),
        "{name}: explain a known_gap or out_of_scope case in note"
    );
    if let Some(platforms) = &case.platforms {
        assert!(
            !platforms.is_empty()
                && platforms
                    .iter()
                    .all(|platform| PLATFORMS.contains(&platform.as_str())),
            "{name}: platforms must name one or more of {PLATFORMS:?}"
        );
    }
    let expect = &case.expect;
    match (&case.acquire, &case.discover) {
        (Some(acquire), None) => {
            let (client, _) = source_def(&acquire.source_id);
            assert_eq!(
                client.id.as_str(),
                harness.client,
                "{name}: source belongs to another client"
            );
            assert!(
                expect.selected_sources.is_none()
                    && expect.min_records.is_none()
                    && expect.failure_codes.is_none(),
                "{name}: acquire cases use error/observations expectations"
            );
            if case.status == Status::Supported {
                assert!(
                    expect.error.is_none() && expect.min_observations.unwrap_or(0) > 0,
                    "{name}: a supported acquire case needs no error and min_observations > 0"
                );
                assert!(
                    expect.quarantine_codes.as_ref().is_none_or(Vec::is_empty)
                        && expect.empty_messages.unwrap_or(0) == 0,
                    "{name}: a supported case quarantines nothing and keeps message content"
                );
            } else {
                assert!(
                    expect.error.is_some() || expect.observations.is_some(),
                    "{name}: a gap must assert an exact error or observation count"
                );
            }
        }
        (None, Some(discover)) => {
            assert_eq!(
                discover.client, harness.client,
                "{name}: discover client differs from the harness client"
            );
            assert!(
                expect.selected_sources.is_some(),
                "{name}: discover cases assert selected_sources"
            );
            assert!(
                expect.error.is_none()
                    && expect.observations.is_none()
                    && expect.min_observations.is_none()
                    && expect.min_families.is_empty()
                    && expect.quarantine_codes.is_none()
                    && expect.empty_messages.is_none(),
                "{name}: discover cases use selected_sources/min_records/failure_codes"
            );
            if case.status == Status::Supported {
                assert!(
                    expect.selected_sources.unwrap_or(0) > 0 && expect.min_records.unwrap_or(0) > 0,
                    "{name}: a supported discover case selects a source and reads records"
                );
            }
        }
        _ => panic!("{name}: give exactly one of acquire or discover"),
    }
}

fn runs_on_this_platform(case: &Case) -> bool {
    case.platforms.as_ref().is_none_or(|platforms| {
        platforms
            .iter()
            .any(|platform| platform == std::env::consts::OS)
    })
}

#[test]
fn upstream_harness_formats_match_recorded_outcomes() {
    let harnesses = load_harnesses();
    let scratch = tempfile::tempdir().expect("scratch directory");
    let mut failures = Vec::new();
    let mut ran = 0;
    for (index, (name, case)) in load_cases().iter().enumerate() {
        validate_case(name, case, &harnesses);
        if !runs_on_this_platform(case) {
            continue;
        }
        let dir = scratch.path().join(index.to_string());
        fs::create_dir_all(&dir).expect("case directory");
        let outcome = match (&case.acquire, &case.discover) {
            (Some(acquire), None) => run_acquire(name, acquire, &dir),
            (None, Some(discover)) => run_discover(name, discover, &dir),
            _ => unreachable!("validated"),
        };
        ran += 1;
        let problems = compare(case, &outcome);
        if !problems.is_empty() {
            let hint = match case.status {
                Status::Supported => "a supported shape regressed",
                Status::KnownGap | Status::OutOfScope => {
                    "the recorded gap changed; if Telltale now reads this shape, promote the case to supported"
                }
            };
            failures.push(format!(
                "{name} ({:?}): {hint}\n  {}\n  outcome: {outcome:?}",
                case.status,
                problems.join("\n  ")
            ));
        }
    }
    assert!(ran > 0, "no upstream format case ran on this platform");
    assert!(
        failures.is_empty(),
        "{} upstream format case(s) differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_harness_is_pinned_and_has_cases() {
    let harnesses = load_harnesses();
    let cases = load_cases();
    for (key, harness) in &harnesses {
        client_def(&harness.client);
        assert!(
            harness.commit.len() == 40 && harness.commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "{key}: commit must be a full SHA"
        );
        assert!(
            harness.repository.split('/').count() == 2,
            "{key}: repository is owner/name"
        );
        assert!(
            !harness.tag.is_empty() && !harness.checked.is_empty(),
            "{key}"
        );
        assert!(!harness.tag_pattern.is_empty(), "{key}: tag_pattern");
        assert!(
            cases.iter().any(|(_, case)| &case.harness == key),
            "{key}: add at least one case for this harness"
        );
    }
}
