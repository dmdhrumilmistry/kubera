//! Scan pipeline: sources -> detection engine -> filter -> (verify).

use std::collections::HashSet;
use std::sync::Mutex;

use rayon::prelude::*;

use crate::config::Filter;
use crate::detect::{Engine, line_of};
use crate::finding::Finding;
use crate::sources::Chunk;

/// Turn the candidates of one chunk into findings.
pub fn scan_chunk(engine: &Engine, filter: &Filter, chunk: &Chunk) -> Vec<Finding> {
    let mut out = Vec::new();
    for c in engine.scan(&chunk.text) {
        let det = &engine.detectors[c.detector];
        let line_idx = line_of(&chunk.text, c.offset);
        let line = match &chunk.line_map {
            Some(map) => map.get(line_idx - 1).copied().unwrap_or(line_idx),
            None => line_idx,
        };
        let mut loc = chunk.location.clone();
        loc.line = line;
        let f = Finding::new(&det.template, c.parts, loc);
        if filter.allowed(&f.fingerprint, f.secret.values()) {
            continue;
        }
        out.push(f);
    }
    out
}

/// (fingerprint, path, line, commit)
type DedupKey = (String, Option<String>, usize, Option<String>);

/// Collects findings from many chunks (possibly in parallel), de-duplicating
/// identical (secret, location) pairs.
#[derive(Default)]
pub struct Collector {
    findings: Mutex<Vec<Finding>>,
    seen: Mutex<HashSet<DedupKey>>,
}

impl Collector {
    pub fn push(&self, found: Vec<Finding>) {
        if found.is_empty() {
            return;
        }
        let mut seen = self.seen.lock().unwrap();
        let mut all = self.findings.lock().unwrap();
        for f in found {
            let key = (
                f.fingerprint.clone(),
                f.location.path.clone(),
                f.location.line,
                f.location.commit.clone(),
            );
            if seen.insert(key) {
                all.push(f);
            }
        }
    }

    pub fn into_findings(self) -> Vec<Finding> {
        let mut v = self.findings.into_inner().unwrap();
        v.sort_by(|a, b| {
            (&a.location.path, a.location.line, &a.detector).cmp(&(
                &b.location.path,
                b.location.line,
                &b.detector,
            ))
        });
        v
    }
}

/// What to scan.
// Built once per scan, so the size difference between variants is irrelevant.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Target {
    /// Files and directories.
    Paths(Vec<std::path::PathBuf>),
    /// A git repository: local path, URL, scp-like or `host/owner/repo`.
    Git {
        repo: String,
        options: crate::sources::git::GitOptions,
        auth: crate::sources::remote::Auth,
        /// Ref tips already scanned (incremental mode, see [`crate::state`]).
        baseline: Option<std::collections::BTreeMap<String, String>>,
        /// Persistent bare mirror for remote repositories: fetched instead
        /// of cloned on later runs (mass scanning).
        mirror: Option<std::path::PathBuf>,
    },
    /// In-memory text (stdin).
    Text(String),
    /// A container image (pulled, exported from Docker, or an archive).
    Image(std::sync::Arc<crate::sources::image::Image>),
}

/// Progress notifications emitted while scanning.
#[derive(Debug, Clone)]
pub enum Progress {
    /// Cloning a remote repository (URL without credentials).
    Cloning(String),
    /// Files scanned so far / total.
    Files { done: usize, total: usize },
    /// File diffs from git history scanned so far.
    Diffs(usize),
}

/// Result of [`run_detailed`].
#[derive(Debug, Default)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    /// Git targets: commits scanned.
    pub commits_scanned: usize,
    /// Git targets: ref tips at scan time (for incremental state).
    pub tips: std::collections::BTreeMap<String, String>,
}

/// Scan a target end to end and return de-duplicated, sorted findings.
pub fn run(
    engine: &Engine,
    filter: &Filter,
    target: &Target,
    max_file_size: u64,
    progress: &(dyn Fn(Progress) + Sync),
) -> anyhow::Result<Vec<Finding>> {
    Ok(run_detailed(engine, filter, target, max_file_size, progress)?.findings)
}

/// Like [`run`], with scan statistics.
pub fn run_detailed(
    engine: &Engine,
    filter: &Filter,
    target: &Target,
    max_file_size: u64,
    progress: &(dyn Fn(Progress) + Sync),
) -> anyhow::Result<Outcome> {
    use crate::sources::{self, git, remote};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let collector = Collector::default();
    match target {
        Target::Paths(paths) => {
            let mut files = Vec::new();
            for root in paths {
                if !root.exists() {
                    anyhow::bail!("{} does not exist", root.display());
                }
                files.extend(sources::fs::list_files(root, filter, max_file_size)?);
            }
            let total = files.len();
            let done = AtomicUsize::new(0);
            progress(Progress::Files { done: 0, total });
            files.par_iter().for_each(|p| {
                if let Some(chunk) = sources::fs::read_chunk(p) {
                    collector.push(scan_chunk(engine, filter, &chunk));
                }
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                progress(Progress::Files { done: n, total });
            });
        }
        Target::Git {
            repo,
            options,
            auth,
            baseline,
            mirror,
        } => {
            let remote_repo = remote::parse(repo)?;
            let (_tmp, path, web) = match (&remote_repo, mirror) {
                (Some(r), Some(dir)) => {
                    progress(Progress::Cloning(r.display().to_string()));
                    git::update_mirror(r, auth, dir)?;
                    (None, dir.clone(), Some(r.clone()))
                }
                (Some(r), None) => {
                    progress(Progress::Cloning(r.display().to_string()));
                    // A shallow clone cannot express "since the baseline".
                    let mut opts = options.clone();
                    if baseline.is_some() {
                        opts.max_depth = None;
                    }
                    let (d, p) = git::clone(r, auth, &opts)?;
                    (Some(d), p, Some(r.clone()))
                }
                (None, _) => {
                    let p = std::path::PathBuf::from(repo);
                    let origin = git::origin_remote(&p);
                    (None, p, origin)
                }
            };
            let mut options = options.clone();
            let tips = git::ref_tips(&path, options.branch.as_deref())?;
            if let Some(base) = baseline {
                if options.since_commit.is_some() {
                    anyhow::bail!("incremental state cannot be combined with --since-commit");
                }
                let mut include: Vec<String> = tips.values().cloned().collect();
                include.sort();
                include.dedup();
                let mut exclude: Vec<String> = base
                    .values()
                    .filter(|sha| git::commit_exists(&path, sha))
                    .cloned()
                    .collect();
                exclude.sort();
                exclude.dedup();
                if include.iter().all(|t| exclude.contains(t)) {
                    // Nothing new since the last passing scan.
                    return Ok(Outcome {
                        findings: Vec::new(),
                        commits_scanned: 0,
                        tips,
                    });
                }
                options.branch = None;
                options.include = include;
                options.exclude = exclude;
            }
            let diffs = AtomicUsize::new(0);
            let mut batch: Vec<sources::Chunk> = Vec::new();
            let flush = |batch: &mut Vec<sources::Chunk>| {
                batch.par_iter().for_each(|c| {
                    let excluded = c
                        .location
                        .path
                        .as_deref()
                        .is_some_and(|p| filter.path_excluded(std::path::Path::new(p)));
                    if !excluded {
                        collector.push(scan_chunk(engine, filter, c));
                    }
                });
                let n = diffs.fetch_add(batch.len(), Ordering::Relaxed) + batch.len();
                progress(Progress::Diffs(n));
                batch.clear();
            };
            let commits = git::scan(&path, &options, |chunk| {
                batch.push(chunk);
                if batch.len() >= 256 {
                    flush(&mut batch);
                }
            })?;
            flush(&mut batch);
            let mut findings = collector.into_findings();
            if let Some(r) = web {
                for f in &mut findings {
                    let loc = &mut f.location;
                    loc.repository = Some(r.display().to_string());
                    if let (Some(c), Some(p)) = (&loc.commit, &loc.path) {
                        loc.link = r.link(c, p, loc.line);
                    }
                }
            }
            return Ok(Outcome {
                findings,
                commits_scanned: commits,
                tips,
            });
        }
        Target::Image(img) => {
            let mut batch: Vec<crate::sources::Chunk> = Vec::new();
            let files = AtomicUsize::new(0);
            let flush = |batch: &mut Vec<crate::sources::Chunk>| {
                batch.par_iter().for_each(|c| {
                    collector.push(scan_chunk(engine, filter, c));
                });
                let n = files.fetch_add(batch.len(), Ordering::Relaxed) + batch.len();
                progress(Progress::Files { done: n, total: 0 });
                batch.clear();
            };
            crate::sources::image::walk(img, max_file_size, &mut |chunk| {
                let excluded = chunk.location.path.as_deref().is_some_and(|p| {
                    filter.path_excluded(std::path::Path::new(p.trim_start_matches('/')))
                });
                if !excluded {
                    batch.push(chunk);
                }
                if batch.len() >= 256 {
                    flush(&mut batch);
                }
            })?;
            flush(&mut batch);
        }
        Target::Text(text) => {
            let chunk = crate::sources::Chunk {
                text: text.clone(),
                location: crate::finding::Location {
                    source: crate::finding::SourceKind::Stdin,
                    ..Default::default()
                },
                line_map: None,
            };
            collector.push(scan_chunk(engine, filter, &chunk));
        }
    }
    Ok(Outcome {
        findings: collector.into_findings(),
        ..Default::default()
    })
}
