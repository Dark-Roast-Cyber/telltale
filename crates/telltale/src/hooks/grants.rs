//! Always grants: what the user allowed for a project or for themselves, kept
//! as one YAML file per grant in `grants.d` of the user's configuration root
//! (docs/hooks/adr/0010-grants.md). The CLI reads them while
//! `hooks.grants.enabled` is on ([`load_dir`]) into
//! [`crate::hooks::config::Grants::always`]; the runtime asks
//! [`covering`] after the session's own grants. A file this module cannot
//! take is left out and reported ([`LeftOut`]), never a grant and never
//! invalid configuration.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hooks::config::HOST_RULE_ID_PREFIX;
use crate::hooks::harness::Harness;

/// The folder of a configuration root that holds always grants.
pub const GRANTS_DIR: &str = "grants.d";

/// At most this many grant files are read; the rest are left out.
pub const MAX_GRANT_FILES: usize = 256;

/// A grant file larger than this is left out.
pub const MAX_GRANT_FILE_BYTES: u64 = 64 * 1024;

/// The only grant file format version.
pub const GRANT_FILE_VERSION: u32 = 1;

/// How far an always grant reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlwaysScope {
    /// Calls whose working directory is the project directory or below it.
    Project,
    /// Calls anywhere.
    User,
}

impl AlwaysScope {
    /// The name in a grant file and in `decision.grant.scope`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::User => "user",
        }
    }
}

/// One grant file: the detections allowed on one tool of one harness, for a
/// project or for the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlwaysGrant {
    /// The grant ID: the file name without `.yaml`, `g-` and 12 lowercase
    /// hex characters. Not a key in the file.
    #[serde(skip)]
    pub id: String,
    pub version: u32,
    pub scope: AlwaysScope,
    /// The project directory, absolute: present for a project grant only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<PathBuf>,
    /// The harness name, as `telltale hooks harnesses` prints it.
    pub harness: String,
    /// The native tool name.
    pub tool: String,
    /// The detections allowed: non-empty, sorted, no duplicates.
    pub rule_ids: Vec<String>,
    pub created_at: String,
    /// The decision record of the stopped call the grant was made for.
    pub from_record: String,
}

/// A grant file that was left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftOut {
    pub path: PathBuf,
    pub cause: &'static str,
}

impl AlwaysGrant {
    /// Why this grant cannot be taken, if it cannot.
    fn defect(&self) -> Option<&'static str> {
        if self.version != GRANT_FILE_VERSION {
            return Some("unsupported version");
        }
        match (self.scope, &self.project) {
            (AlwaysScope::Project, None) => return Some("a project grant names no project"),
            (AlwaysScope::Project, Some(project)) if !project.is_absolute() => {
                return Some("the project path is not absolute");
            }
            (AlwaysScope::User, Some(_)) => return Some("a user grant names a project"),
            _ => {}
        }
        if Harness::from_name(&self.harness).is_none() {
            return Some("names no known harness");
        }
        if self.tool.is_empty() {
            return Some("names no tool");
        }
        if self.rule_ids.is_empty() {
            return Some("names no rule");
        }
        if self.rule_ids.iter().any(|id| id.is_empty()) {
            return Some("names an empty rule ID");
        }
        if self
            .rule_ids
            .iter()
            .any(|id| id.starts_with(HOST_RULE_ID_PREFIX))
        {
            return Some("names a tth.tamper. rule, which no grant covers");
        }
        if !self.rule_ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return Some("the rule IDs are not sorted or repeat");
        }
        None
    }

    /// Whether this grant covers a call of `tool` on `harness`, in `cwd`,
    /// that matched `rule_ids` (each of them must be granted here).
    pub fn covers(
        &self,
        harness: &str,
        tool: &str,
        cwd: Option<&str>,
        rule_ids: &[String],
    ) -> bool {
        self.harness == harness
            && self.tool == tool
            && !rule_ids.is_empty()
            && rule_ids.iter().all(|id| self.rule_ids.contains(id))
            && match (self.scope, &self.project) {
                (AlwaysScope::User, _) => true,
                (AlwaysScope::Project, Some(project)) => {
                    cwd.is_some_and(|cwd| within(project, Path::new(cwd)))
                }
                (AlwaysScope::Project, None) => false,
            }
    }
}

/// The always grant that covers a call, project grants before user grants;
/// the first that covers wins. Grants are never combined.
pub fn covering<'a>(
    grants: &'a [AlwaysGrant],
    harness: &str,
    tool: &str,
    cwd: Option<&str>,
    rule_ids: &[String],
) -> Option<&'a AlwaysGrant> {
    [AlwaysScope::Project, AlwaysScope::User]
        .into_iter()
        .find_map(|scope| {
            grants
                .iter()
                .find(|grant| grant.scope == scope && grant.covers(harness, tool, cwd, rule_ids))
        })
}

/// Whether `path` is `dir` or below it, by path components after lexical
/// normalization (`.` dropped, `..` taken back). No filesystem access: a
/// symlink is not resolved. Relative paths are never within. Case matters,
/// except on Windows.
pub fn within(dir: &Path, path: &Path) -> bool {
    match (normalized(dir), normalized(path)) {
        (Some(dir), Some(path)) => path.starts_with(dir),
        _ => false,
    }
}

fn normalized(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                // `pop` keeps the root: `/..` is `/`.
                if out.parent().is_some() {
                    out.pop();
                }
            }
        }
    }
    // Windows paths are case-insensitive, and a terminal's current directory
    // and a harness's cwd can spell a drive or folder in another case. A path
    // that is not UTF-8 matches nothing there.
    #[cfg(windows)]
    let out = PathBuf::from(out.to_str()?.to_lowercase());
    Some(out)
}

/// Whether `id` is a grant ID: `g-` and 12 lowercase hex characters.
pub fn is_grant_id(id: &str) -> bool {
    id.strip_prefix("g-").is_some_and(|hex| {
        hex.len() == 12 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Every grant in `dir` that can be taken, and every file left out. A
/// missing folder holds no grants. Files are read in name order, at most
/// [`MAX_GRANT_FILES`] of them.
pub fn load_dir(dir: &Path) -> (Vec<AlwaysGrant>, Vec<LeftOut>) {
    let mut grants = Vec::new();
    let mut left_out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (grants, left_out),
        Err(_) => {
            left_out.push(LeftOut {
                path: dir.to_owned(),
                cause: "the folder cannot be read",
            });
            return (grants, left_out);
        }
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    paths.sort();
    for (index, path) in paths.into_iter().enumerate() {
        if index >= MAX_GRANT_FILES {
            left_out.push(LeftOut {
                path,
                cause: "more grant files than the 256 read",
            });
            continue;
        }
        match load_file(&path) {
            Ok(grant) => grants.push(grant),
            Err(cause) => left_out.push(LeftOut { path, cause }),
        }
    }
    (grants, left_out)
}

/// The grant in the file at `path`, or why it is left out.
pub fn load_file(path: &Path) -> Result<AlwaysGrant, &'static str> {
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".yaml"))
        .filter(|id| is_grant_id(id))
        .ok_or("the file name is not a grant ID followed by .yaml")?;
    // A grant is a file `write` made: a link to a file elsewhere could be
    // changed without touching the configuration root.
    if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file()) {
        return Err("not a regular file (a link or a folder)");
    }
    let file = crate::hooks::state::open_operator_input(path).map_err(|_| "cannot be read")?;
    let mut bytes = Vec::new();
    file.take(MAX_GRANT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot be read")?;
    if bytes.len() as u64 > MAX_GRANT_FILE_BYTES {
        return Err("larger than 64 KiB");
    }
    let text = String::from_utf8(bytes).map_err(|_| "not UTF-8")?;
    let mut grant: AlwaysGrant = serde_yaml::from_str(&text)
        .map_err(|_| "not a grant: does not parse, misses a key or has an unknown one")?;
    if let Some(defect) = grant.defect() {
        return Err(defect);
    }
    grant.id = id.to_owned();
    Ok(grant)
}

/// Write `grant` to a new file in `dir` (created if missing) under a new
/// random ID, and return the ID. `grant.id` is ignored. A grant that
/// [`load_dir`] would leave out is refused.
pub fn write(dir: &Path, grant: &AlwaysGrant) -> std::io::Result<String> {
    if let Some(defect) = grant.defect() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            defect,
        ));
    }
    let text = serde_yaml::to_string(grant).map_err(std::io::Error::other)?;
    std::fs::create_dir_all(dir)?;
    loop {
        let mut bytes = [0u8; 6];
        getrandom::fill(&mut bytes).map_err(|error| std::io::Error::other(error.to_string()))?;
        let id = format!("g-{}", hex::encode(bytes));
        let path = dir.join(format!("{id}.yaml"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(text.as_bytes())?;
                file.sync_all()?;
                return Ok(id);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Remove the grant `id` from `dir`. An ID that is not a grant ID is refused.
pub fn remove(dir: &Path, id: &str) -> std::io::Result<()> {
    if !is_grant_id(id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a grant ID",
        ));
    }
    std::fs::remove_file(dir.join(format!("{id}.yaml")))
}

#[cfg(test)]
mod tests;
