//! Privacy-safe, read-only Hooks diagnostics.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use telltale_core::EffectiveConfigurationV1;
use telltale_core::hooks::config::{AskRoute, Config, Mode, OnError, ReasonDetail};
use telltale_core::hooks::engine::{Engine, EngineError};
use telltale_core::hooks::{evaluator, identity};

mod installation;
mod telemetry;

const SCHEMA_ID: &str = "telltale_hooks.status.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Location {
    User,
    System,
    Managed,
    Project,
}

#[derive(Serialize)]
struct ConfigSource {
    origin: Location,
    path_sha256: String,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigurationError {
    ConfigInvalid,
    RuleContentUnreadable,
    PipelineBuildFailed,
    SemanticProvenanceFailed,
    StateDirUnresolved,
}

impl From<EngineError> for ConfigurationError {
    fn from(error: EngineError) -> Self {
        match error {
            EngineError::Content(..) => Self::RuleContentUnreadable,
            EngineError::Provenance(_) => Self::SemanticProvenanceFailed,
            _ => Self::PipelineBuildFailed,
        }
    }
}

#[derive(Default, Serialize)]
struct Configuration {
    origin: Option<Location>,
    sources: Vec<ConfigSource>,
    content_sha256: Option<String>,
    valid: bool,
    error_code: Option<ConfigurationError>,
    semantic_identity: Option<String>,
    mode: Option<Mode>,
    on_error: Option<OnError>,
    on_unevaluable: Option<OnError>,
    reason_detail: Option<ReasonDetail>,
    ask: Option<AskRoute>,
    telemetry_rotation: Option<Rotation>,
    tamper_prevention: Option<bool>,
    self_protection_rules: Option<bool>,
}

#[derive(Serialize)]
struct Rotation {
    max_size_bytes: u64,
    keep: usize,
}

pub(super) struct CheckedEngine {
    pub(super) engine: Engine,
    pub(super) effective: Result<EffectiveConfigurationV1, EngineError>,
}

/// The same validation and effective pipeline as the legacy text check.
pub(super) fn checked(
    config_dirs: &[PathBuf],
    observe: impl FnMut(&Path, &[u8]),
) -> Result<(Config, Result<CheckedEngine, EngineError>), String> {
    let config = super::load_config_observing_files(config_dirs, observe)?;
    let engine =
        Engine::new(&config.rules, &config.grants, &config.protected_paths()).map(|engine| {
            let effective = engine.effective_configuration();
            CheckedEngine { engine, effective }
        });
    Ok((config, engine))
}

fn configuration(config_dirs: &[PathBuf]) -> (Configuration, Option<Config>) {
    let system = crate::config::system_config_root();
    let user = crate::config::pinned_user_config_root()
        .map(Path::to_path_buf)
        .or_else(crate::config::user_config_root);
    let absolute = |root: Option<PathBuf>| root.and_then(|p| std::path::absolute(p).ok());
    let (system, user) = (absolute(system), absolute(user));
    let mut hash = Sha256::new();
    let mut view = Configuration::default();
    let checked = checked(config_dirs, |path, bytes| {
        let path = std::path::absolute(path).unwrap_or_else(|_| path.to_owned());
        let root = path.parent().and_then(Path::parent);
        let origin = if root.is_some() && root == system.as_deref() {
            Location::System
        } else if root.is_some() && root == user.as_deref() {
            Location::User
        } else {
            Location::Managed
        };
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        view.origin = Some(origin);
        view.sources.push(ConfigSource {
            origin,
            path_sha256: digest_path(&path),
        });
    });
    if !view.sources.is_empty() {
        view.content_sha256 = Some(hex::encode(hash.finalize()));
    }
    let (config, checked) = match checked {
        Ok(checked) => checked,
        Err(_) => {
            view.error_code = Some(ConfigurationError::ConfigInvalid);
            return (view, None);
        }
    };
    view.mode = Some(config.mode);
    view.on_error = Some(config.on_error);
    view.on_unevaluable = Some(config.on_unevaluable);
    view.reason_detail = Some(config.reason_detail);
    view.ask = Some(config.ask);
    view.telemetry_rotation = Some(Rotation {
        max_size_bytes: config.telemetry_rotation.max_size_bytes,
        keep: config.telemetry_rotation.keep,
    });
    view.tamper_prevention = Some(config.rules.tamper_prevention);
    view.self_protection_rules = Some(config.rules.self_protection);
    let checked = match checked {
        Ok(checked) => checked,
        Err(error) => {
            view.error_code = Some(error.into());
            return (view, Some(config));
        }
    };
    view.semantic_identity = Some(checked.engine.semantic_identity().to_owned());
    view.error_code = if let Err(error) = checked.effective {
        Some(error.into())
    } else if config.resolved_state_dir().is_err() || config.resolved_telemetry_path().is_err() {
        Some(ConfigurationError::StateDirUnresolved)
    } else {
        None
    };
    view.valid = view.error_code.is_none();
    (view, Some(config))
}

fn digest_path(path: &Path) -> String {
    telltale_core::hooks::telemetry::sha256_hex(path.to_string_lossy().as_bytes())
}

#[derive(Serialize)]
struct Status {
    schema: &'static str,
    version: &'static str,
    telltale_rev: &'static str,
    configuration: Configuration,
    harnesses: Vec<installation::HarnessStatus>,
    evaluator: evaluator::Probe,
    telemetry: telemetry::Summary,
}

pub(super) fn run(config_dirs: &[PathBuf], json: bool) -> i32 {
    let (configuration, config) = configuration(config_dirs);
    let telemetry_path = config.as_ref().map_or_else(
        || super::fallback_config().resolved_telemetry_path(),
        Config::resolved_telemetry_path,
    );
    let report = Status {
        schema: SCHEMA_ID,
        version: env!("CARGO_PKG_VERSION"),
        telltale_rev: identity::revision(),
        configuration,
        harnesses: installation::detect(),
        evaluator: config
            .as_ref()
            .map_or(evaluator::Probe::ConfigInvalid, evaluator::probe),
        telemetry: telemetry::summarize(telemetry_path.as_deref().ok()),
    };
    output(|out| {
        if json {
            json_line(out, &report)
        } else {
            report.write_text(out)
        }
    })
}

pub(super) fn check_json(config_dirs: &[PathBuf]) -> i32 {
    let (view, _) = configuration(config_dirs);
    match output(|out| json_line(out, &view)) {
        0 if !view.valid => 1,
        code => code,
    }
}

fn output(write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> i32 {
    let mut stdout = io::stdout().lock();
    if write(&mut stdout).and_then(|()| stdout.flush()).is_ok() {
        0
    } else {
        eprintln!("telltale hooks: could not write report");
        1
    }
}

fn json_line(out: &mut dyn Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    writeln!(out)
}

impl Status {
    fn write_text(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "Telltale Hooks {} (revision {})",
            self.version, self.telltale_rev
        )?;
        let view = serde_json::to_value(&self.configuration)?;
        write_fields(out, "configuration", &view)?;
        for harness in &self.harnesses {
            write_fields(out, harness.name, &serde_json::to_value(harness)?)?;
        }
        writeln!(
            out,
            "evaluator: {}",
            serde_json::to_value(self.evaluator)?
                .as_str()
                .unwrap_or_default()
        )?;
        write_fields(out, "telemetry", &serde_json::to_value(&self.telemetry)?)
    }
}

fn write_fields(out: &mut dyn Write, heading: &str, value: &serde_json::Value) -> io::Result<()> {
    writeln!(out, "{heading}:")?;
    for (key, value) in value.as_object().into_iter().flatten() {
        if key == "name" {
            continue;
        }
        if let Some(label) = value.as_str() {
            writeln!(out, "  {key}: {label}")?;
        } else {
            writeln!(out, "  {key}: {value}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
