//! Baselines and triage decisions.
//!
//! A baseline file (default `.kubera-baseline.json`, loaded automatically
//! when present) lists findings that should no longer be reported:
//!
//! * `baseline` - existing findings accepted when kubera was adopted
//!   (`--update-baseline`), so CI only fails on *new* secrets;
//! * `false_positive` / `accepted` - decisions made while triaging, e.g.
//!   with `x` / `m` in the TUI.
//!
//! Entries match on the finding fingerprint (detector + secret), so a
//! decision follows the secret wherever it moves. The file never contains
//! secret values (only fingerprints, which cannot be reversed, and
//! locations for humans), is machine-managed, and is meant to be committed.
//! Hand-written `.kubera.yaml` files are never rewritten.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::finding::Finding;

pub const DEFAULT_FILE: &str = ".kubera-baseline.json";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Baseline,
    FalsePositive,
    Accepted,
}

impl Decision {
    pub fn label(self) -> &'static str {
        match self {
            Decision::Baseline => "baseline",
            Decision::FalsePositive => "false positive",
            Decision::Accepted => "accepted risk",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub fingerprint: String,
    pub detector: String,
    pub decision: Decision,
    /// Where it was seen when recorded (for humans; not used to match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub added: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileData {
    version: u32,
    entries: Vec<Entry>,
}

#[derive(Debug)]
pub struct Baseline {
    pub path: PathBuf,
    pub entries: Vec<Entry>,
}

impl Baseline {
    /// Load `path`; a missing file is an empty baseline.
    pub fn load(path: &Path) -> Result<Self> {
        let entries = match std::fs::read(path) {
            Ok(b) => {
                let f: FileData = serde_json::from_slice(&b)
                    .with_context(|| format!("parsing baseline {}", path.display()))?;
                if f.version != VERSION {
                    bail!(
                        "baseline {} has unsupported version {}",
                        path.display(),
                        f.version
                    );
                }
                f.entries
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// The baseline in effect: `explicit`, else [`DEFAULT_FILE`] in the
    /// current directory.
    pub fn resolve(explicit: Option<&Path>) -> Result<Self> {
        Self::load(explicit.unwrap_or(Path::new(DEFAULT_FILE)))
    }

    pub fn fingerprints(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.fingerprint.as_str())
    }

    pub fn get(&self, fingerprint: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.fingerprint == fingerprint)
    }

    /// Record a decision for `f` (replacing an earlier one). Returns
    /// whether the fingerprint was new.
    pub fn add(&mut self, f: &Finding, decision: Decision, note: Option<String>) -> bool {
        let entry = Entry {
            fingerprint: f.fingerprint.clone(),
            detector: f.detector.clone(),
            decision,
            path: f.location.path.clone().map(|p| match &f.location.entry {
                Some(e) => format!("{p}!/{e}"),
                None => p,
            }),
            line: (f.location.line > 0).then_some(f.location.line),
            commit: f.location.commit.clone(),
            note,
            added: crate::state::now(),
        };
        match self
            .entries
            .iter_mut()
            .find(|e| e.fingerprint == f.fingerprint)
        {
            Some(e) => {
                *e = entry;
                false
            }
            None => {
                self.entries.push(entry);
                true
            }
        }
    }

    /// Remove the decision for `fingerprint` (undo).
    pub fn remove(&mut self, fingerprint: &str) -> bool {
        let n = self.entries.len();
        self.entries.retain(|e| e.fingerprint != fingerprint);
        n != self.entries.len()
    }

    /// Write atomically, sorted for stable diffs.
    pub fn save(&mut self) -> Result<()> {
        self.entries
            .sort_by(|a, b| (&a.detector, &a.fingerprint).cmp(&(&b.detector, &b.fingerprint)));
        let mut data = serde_json::to_vec_pretty(&FileData {
            version: VERSION,
            entries: self.entries.clone(),
        })?;
        data.push(b'\n');
        crate::state::write_private(&self.path, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Location;

    fn finding(secret: &str) -> Finding {
        let t = crate::template::builtin()
            .unwrap()
            .into_iter()
            .find(|l| l.template.id == "github-token")
            .unwrap()
            .template;
        let mut parts = std::collections::BTreeMap::new();
        parts.insert(t.detect.patterns[0].name.clone(), secret.to_string());
        Finding::new(
            &t,
            parts,
            Location {
                path: Some("a.env".into()),
                line: 3,
                ..Default::default()
            },
        )
    }

    #[test]
    fn roundtrip_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(DEFAULT_FILE);
        let mut b = Baseline::load(&p).unwrap();
        assert!(b.entries.is_empty());
        let f = finding("the-secret-value-xyz");
        assert!(b.add(&f, Decision::FalsePositive, Some("test fixture".into())));
        assert!(!b.add(&f, Decision::Accepted, None));
        b.save().unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains("the-secret-value-xyz"));
        let b = Baseline::load(&p).unwrap();
        assert_eq!(b.entries.len(), 1);
        assert_eq!(b.get(&f.fingerprint).unwrap().decision, Decision::Accepted);
        assert_eq!(b.entries[0].line, Some(3));
    }
}
