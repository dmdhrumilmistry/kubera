//! Project configuration (`.kubera.yaml`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;

pub const DEFAULT_FILE: &str = ".kubera.yaml";

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Extra template files/directories (relative to the config file).
    pub templates: Vec<PathBuf>,
    /// Disable the templates compiled into the binary.
    pub no_builtin: bool,
    /// Only run these detectors.
    pub detectors: Vec<String>,
    /// Never run these detectors.
    pub exclude_detectors: Vec<String>,
    /// Glob patterns of paths to skip (matched against the path relative to
    /// the scan root, e.g. `**/testdata/**`).
    pub exclude_paths: Vec<String>,
    pub allowlist: Allowlist,
    /// Skip files larger than this many bytes.
    pub max_file_size: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Allowlist {
    /// Finding fingerprints to ignore (see the `fingerprint` field).
    pub fingerprints: Vec<String>,
    /// Regexes; a finding is ignored when any secret part matches one.
    pub secrets: Vec<String>,
}

impl Config {
    /// Load `path`, or `.kubera.yaml` from the current directory if present.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let (path, required) = match path {
            Some(p) => (p.to_path_buf(), true),
            None => (PathBuf::from(DEFAULT_FILE), false),
        };
        if !required && !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Config = serde_yaml::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        cfg.templates = cfg
            .templates
            .into_iter()
            .map(|t| if t.is_absolute() { t } else { base.join(t) })
            .collect();
        Ok(cfg)
    }
}

/// Post-detection filter built from config + CLI flags.
pub struct Filter {
    pub exclude_paths: GlobSet,
    fingerprints: HashSet<String>,
    secrets: Vec<Regex>,
}

impl Filter {
    pub fn new(exclude_paths: &[String], allow: &Allowlist) -> Result<Self> {
        let mut b = GlobSetBuilder::new();
        for g in exclude_paths {
            b.add(Glob::new(g).with_context(|| format!("invalid exclude glob `{g}`"))?);
        }
        Ok(Self {
            exclude_paths: b.build()?,
            fingerprints: allow.fingerprints.iter().cloned().collect(),
            secrets: allow
                .secrets
                .iter()
                .map(|r| Regex::new(r).with_context(|| format!("invalid allowlist regex `{r}`")))
                .collect::<Result<_>>()?,
        })
    }

    pub fn path_excluded(&self, rel: &Path) -> bool {
        self.exclude_paths.is_match(rel)
    }

    pub fn allowed(&self, fingerprint: &str, parts: impl Iterator<Item = impl AsRef<str>>) -> bool {
        if self.fingerprints.contains(fingerprint) {
            return true;
        }
        let parts: Vec<_> = parts.collect();
        parts
            .iter()
            .any(|p| self.secrets.iter().any(|r| r.is_match(p.as_ref())))
    }
}
