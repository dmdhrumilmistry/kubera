//! Resumable history scans.
//!
//! A checkpoint records which commits of a git scan are finished and the
//! findings so far, so an interrupted multi-hour scan continues where it
//! stopped. It holds raw secrets (they are needed to verify and report on
//! resume), so it is written atomically with mode 0600 and deleted as soon
//! as the scan completes.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::finding::{Finding, Location};

const VERSION: u32 = 1;

static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Ask running checkpointed scans to stop and save (first Ctrl-C).
pub fn request_stop() {
    INTERRUPTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Whether [`request_stop`] was called.
pub fn stop_requested() -> bool {
    INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed)
}
/// Minimum time between two writes of the checkpoint file.
const SAVE_EVERY: Duration = Duration::from_secs(2);

/// A finding as stored in the checkpoint (re-hydrated from its template).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Saved {
    pub detector: String,
    pub secret: BTreeMap<String, String>,
    pub location: Location,
}

impl From<&Finding> for Saved {
    fn from(f: &Finding) -> Self {
        Self {
            detector: f.detector.clone(),
            secret: f.secret.clone(),
            location: f.location.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FileData {
    version: u32,
    scope: String,
    done: Vec<String>,
    findings: Vec<Saved>,
}

/// Identity of a scan: a checkpoint is only resumed by the same scan.
pub fn scope(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    hex::encode(&h.finalize()[..16])
}

pub struct Checkpoint {
    path: PathBuf,
    scope: String,
    done: Mutex<HashSet<String>>,
    last_save: Mutex<Instant>,
}

impl Checkpoint {
    /// Open `path`, resuming it when it belongs to the same scan. Returns
    /// the checkpoint and the findings saved by the interrupted run.
    pub fn open(path: &Path, scope: &str) -> Result<(Self, Vec<Saved>)> {
        let (done, findings) = match std::fs::read(path) {
            Ok(bytes) => {
                let f: FileData = serde_json::from_slice(&bytes)
                    .with_context(|| format!("reading checkpoint {}", path.display()))?;
                if f.version != VERSION || f.scope != scope {
                    bail!(
                        "checkpoint {} belongs to a different scan (other repository, \
                         revisions or detectors); delete it to start over",
                        path.display()
                    );
                }
                (f.done.into_iter().collect(), f.findings)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (HashSet::new(), Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok((
            Self {
                path: path.to_path_buf(),
                scope: scope.to_string(),
                done: Mutex::new(done),
                last_save: Mutex::new(Instant::now()),
            },
            findings,
        ))
    }

    pub fn is_done(&self, commit: &str) -> bool {
        self.done.lock().unwrap().contains(commit)
    }

    pub fn done_count(&self) -> usize {
        self.done.lock().unwrap().len()
    }

    /// Record finished commits; writes the file at most every
    /// [`SAVE_EVERY`] (`findings` is only called when writing).
    pub fn mark(&self, commits: &[String], findings: impl FnOnce() -> Vec<Saved>) -> Result<()> {
        self.done.lock().unwrap().extend(commits.iter().cloned());
        let mut last = self.last_save.lock().unwrap();
        if last.elapsed() >= SAVE_EVERY {
            self.write(findings())?;
            *last = Instant::now();
        }
        Ok(())
    }

    /// Write the checkpoint now.
    pub fn write(&self, findings: Vec<Saved>) -> Result<()> {
        let mut done: Vec<String> = self.done.lock().unwrap().iter().cloned().collect();
        done.sort();
        let data = serde_json::to_vec(&FileData {
            version: VERSION,
            scope: self.scope.clone(),
            done,
            findings,
        })?;
        crate::state::write_private(&self.path, &data)
    }

    /// The scan completed: remove the file (it holds raw secrets).
    pub fn finish(self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("removing {}", self.path.display()))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resumes_same_scope_and_refuses_others() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cp.json");
        let (cp, saved) = Checkpoint::open(&p, "a").unwrap();
        assert!(saved.is_empty());
        cp.mark(&["c1".into(), "c2".into()], Vec::new).unwrap();
        cp.write(vec![Saved {
            detector: "d".into(),
            secret: BTreeMap::new(),
            location: Location::default(),
        }])
        .unwrap();
        let (cp2, saved) = Checkpoint::open(&p, "a").unwrap();
        assert!(cp2.is_done("c1") && cp2.is_done("c2") && !cp2.is_done("c3"));
        assert_eq!(saved.len(), 1);
        assert!(Checkpoint::open(&p, "b").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        cp2.finish().unwrap();
        assert!(!p.exists());
    }
}
