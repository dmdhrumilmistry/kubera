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
    /// Skip [`DEFAULT_EXCLUDES`] (dependency directories and lockfiles).
    /// Set to `false` to scan them too.
    pub default_excludes: Option<bool>,
    /// Record every scan in the findings database: `true` for the default
    /// file, or a path (relative to the config file).
    pub db: Option<DbSetting>,
}

/// `db: true` / `db: false` / `db: path/to/findings.jsonl`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum DbSetting {
    Enabled(bool),
    Path(PathBuf),
}

/// Paths skipped unless disabled (`--no-default-excludes` or
/// `default_excludes: false`): third-party dependency trees and lockfiles.
/// They are large, generated, and rarely hold your own credentials.
/// Minified bundles and source maps are deliberately *not* here: frontend
/// builds are a common place for real keys to leak.
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "**/node_modules/**",
    "**/bower_components/**",
    "**/vendor/**",
    "**/.venv/**",
    "**/site-packages/**",
    "**/Pods/**",
    "**/package-lock.json",
    "**/npm-shrinkwrap.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/bun.lockb",
    "**/Cargo.lock",
    "**/go.sum",
    "**/poetry.lock",
    "**/uv.lock",
    "**/Pipfile.lock",
    "**/composer.lock",
    "**/Gemfile.lock",
    "**/Podfile.lock",
    "**/packages.lock.json",
    "**/gradle.lockfile",
    "**/flake.lock",
];

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
        if let Some(DbSetting::Path(p)) = &cfg.db
            && p.is_relative()
        {
            cfg.db = Some(DbSetting::Path(base.join(p)));
        }
        Ok(cfg)
    }
}

impl Config {
    /// The findings database to record scans in: `--db [PATH]` (an empty
    /// path means the default file), else the config's `db:`.
    pub fn db_path(&self, flag: Option<&Path>, disabled: bool) -> anyhow::Result<Option<PathBuf>> {
        if disabled {
            return Ok(None);
        }
        match (flag, &self.db) {
            (Some(p), _) if !p.as_os_str().is_empty() => Ok(Some(p.to_path_buf())),
            (Some(_), _) | (None, Some(DbSetting::Enabled(true))) => {
                Ok(Some(crate::db::default_path()?))
            }
            (None, Some(DbSetting::Path(p))) => Ok(Some(p.clone())),
            _ => Ok(None),
        }
    }

    /// Every exclude glob in effect: the defaults (unless disabled by the
    /// config or `no_defaults`), the config's, then `extra`.
    pub fn excludes(&self, extra: &[String], no_defaults: bool) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        if !no_defaults && self.default_excludes.unwrap_or(true) {
            v.extend(DEFAULT_EXCLUDES.iter().map(|s| s.to_string()));
        }
        v.extend(self.exclude_paths.iter().cloned());
        v.extend(extra.iter().cloned());
        v
    }
}

/// Post-detection filter built from config + CLI flags.
pub struct Filter {
    pub exclude_paths: GlobSet,
    /// The exclude globs as written (handed to git as pathspecs).
    pub exclude_globs: Vec<String>,
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
            exclude_globs: exclude_paths.to_vec(),
            fingerprints: allow.fingerprints.iter().cloned().collect(),
            secrets: allow
                .secrets
                .iter()
                .map(|r| Regex::new(r).with_context(|| format!("invalid allowlist regex `{r}`")))
                .collect::<Result<_>>()?,
        })
    }

    /// Also drop findings with these fingerprints (baselines, triage).
    pub fn suppress<'a>(&mut self, fingerprints: impl Iterator<Item = &'a str>) {
        self.fingerprints.extend(fingerprints.map(str::to_string));
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
