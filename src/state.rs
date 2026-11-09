//! Incremental scanning state.
//!
//! For every repository the state file records the tip of each branch / tag
//! at the last scan that **passed** (no unresolved findings). The next scan
//! then runs `git log <current tips> ^<recorded tips>`: exactly the commits
//! that were never scanned, across every branch, including new branches and
//! merges, with no per-branch bookkeeping. Tips that vanished (force-push,
//! deleted branch) are ignored; if none of them still exist the repository
//! is scanned in full.
//!
//! The baseline only advances when a scan passes, so a leak keeps being
//! reported on every run until it is fixed or allowlisted (`--state-policy
//! always` overrides this).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoState {
    /// `refname -> commit id` at the last passing scan.
    pub refs: BTreeMap<String, String>,
    /// RFC 3339 time of that scan.
    pub scanned_at: String,
    /// Commits scanned by that run.
    #[serde(default)]
    pub commits_scanned: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    repos: BTreeMap<String, RepoState>,
}

/// When the baseline may move forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Policy {
    /// Only after a scan with no unresolved findings (default).
    Pass,
    /// After every completed scan.
    Always,
}

pub struct State {
    path: PathBuf,
    file: StateFile,
}

impl State {
    /// Load `path`; a missing file is an empty state.
    pub fn load(path: &Path) -> Result<Self> {
        let file = match std::fs::read(path) {
            Ok(bytes) => {
                let f: StateFile = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing state file {}", path.display()))?;
                if f.version != VERSION {
                    bail!(
                        "state file {} has version {}, expected {VERSION}",
                        path.display(),
                        f.version
                    );
                }
                f
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StateFile {
                version: VERSION,
                repos: BTreeMap::new(),
            },
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    pub fn get(&self, repo: &str) -> Option<&RepoState> {
        self.file.repos.get(repo)
    }

    pub fn set(&mut self, repo: &str, st: RepoState) {
        self.file.repos.insert(repo.to_string(), st);
    }

    pub fn repos(&self) -> impl Iterator<Item = (&String, &RepoState)> {
        self.file.repos.iter()
    }

    /// Write atomically (temp file + rename) with mode 0600.
    pub fn save(&self) -> Result<()> {
        let mut data = serde_json::to_vec_pretty(&self.file)?;
        data.push(b'\n');
        write_private(&self.path, &data)
    }
}

/// Write `data` to `path` atomically (temp file in the same directory,
/// fsync, rename) with mode 0600 on Unix.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".kubera-tmp-")
        .tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Stable key for a repository: the credential-free remote URL, or the
/// canonical path of a local repository.
pub fn repo_key(target: &str) -> String {
    match crate::sources::remote::parse(target) {
        Ok(Some(r)) => r.display().to_string(),
        _ => std::fs::canonicalize(target)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| target.to_string()),
    }
}

pub fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_atomic_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/state.json");
        let mut s = State::load(&p).unwrap();
        assert!(s.get("r").is_none());
        let mut refs = BTreeMap::new();
        refs.insert("refs/heads/main".to_string(), "a".repeat(40));
        s.set(
            "r",
            RepoState {
                refs: refs.clone(),
                scanned_at: now(),
                commits_scanned: 3,
            },
        );
        s.save().unwrap();
        let back = State::load(&p).unwrap();
        assert_eq!(back.get("r").unwrap().refs, refs);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::write(&p, r#"{"version": 99, "repos": {}}"#).unwrap();
        assert!(State::load(&p).is_err());
    }
}
