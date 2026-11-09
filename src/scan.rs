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
#[derive(Debug, Clone)]
pub enum Target {
    /// Files and directories.
    Paths(Vec<std::path::PathBuf>),
    /// A git repository: local path, URL, scp-like or `host/owner/repo`.
    Git {
        repo: String,
        options: crate::sources::git::GitOptions,
        auth: crate::sources::remote::Auth,
    },
    /// In-memory text (stdin).
    Text(String),
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

/// Scan a target end to end and return de-duplicated, sorted findings.
pub fn run(
    engine: &Engine,
    filter: &Filter,
    target: &Target,
    max_file_size: u64,
    progress: &(dyn Fn(Progress) + Sync),
) -> anyhow::Result<Vec<Finding>> {
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
        } => {
            let remote_repo = remote::parse(repo)?;
            let (_tmp, path, web) = match &remote_repo {
                Some(r) => {
                    progress(Progress::Cloning(r.display().to_string()));
                    let (d, p) = git::clone(r, auth, options)?;
                    (Some(d), p, Some(r.clone()))
                }
                None => {
                    let p = std::path::PathBuf::from(repo);
                    let origin = git::origin_remote(&p);
                    (None, p, origin)
                }
            };
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
            git::scan(&path, options, |chunk| {
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
            return Ok(findings);
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
    Ok(collector.into_findings())
}
