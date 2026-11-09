//! Scan pipeline: sources -> detection engine -> filter -> (verify).

use std::collections::HashSet;
use std::sync::Mutex;

use rayon::prelude::*;

use crate::config::Filter;
use crate::detect::{Engine, line_of};
use crate::finding::Finding;
use crate::sources::Chunk;

/// Turn the candidates of one chunk into findings: the raw text, then
/// (unless disabled) its decoded form.
pub fn scan_chunk(engine: &Engine, filter: &Filter, chunk: &Chunk) -> Vec<Finding> {
    let mut out = Vec::new();
    let real_line = |idx: usize| match &chunk.line_map {
        Some(map) => map.get(idx - 1).copied().unwrap_or(idx),
        None => idx,
    };
    let mut raw = std::collections::HashSet::new();
    for c in engine.scan(&chunk.text) {
        let det = &engine.detectors[c.detector];
        let mut loc = chunk.location.clone();
        loc.line = real_line(line_of(&chunk.text, c.offset));
        let f = Finding::new(&det.template, c.parts, loc);
        raw.insert(f.fingerprint.clone());
        if filter.allowed(&f.fingerprint, f.secret.values()) {
            continue;
        }
        out.push(f);
    }
    if !engine.decode {
        return out;
    }
    let decoded = crate::decode::decode(&chunk.text);
    if decoded.is_empty() {
        return out;
    }
    for c in engine.scan(&decoded.text) {
        let det = &engine.detectors[c.detector];
        let idx = line_of(&decoded.text, c.offset);
        let mut loc = chunk.location.clone();
        loc.line = real_line(decoded.line_map.get(idx - 1).copied().unwrap_or(1));
        loc.decoder = decoded.decoders.get(idx - 1).map(|d| d.name().to_string());
        let f = Finding::new(&det.template, c.parts, loc);
        // Already reported in plain text (e.g. the decoded line repeats it).
        if raw.contains(&f.fingerprint) || filter.allowed(&f.fingerprint, f.secret.values()) {
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

    /// Findings so far, in checkpoint form.
    pub fn snapshot(&self) -> Vec<crate::checkpoint::Saved> {
        self.findings
            .lock()
            .unwrap()
            .iter()
            .map(Into::into)
            .collect()
    }

    pub fn into_findings(self) -> Vec<Finding> {
        let mut v = self.findings.into_inner().unwrap();
        // Parallel sources deliver in any order: sort on every location
        // field so output is deterministic.
        v.sort_by(|a, b| {
            let (x, y) = (&a.location, &b.location);
            (&x.path, x.line, &a.detector, &x.date, &x.commit, &x.layer).cmp(&(
                &y.path,
                y.line,
                &b.detector,
                &y.date,
                &y.commit,
                &y.layer,
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
    /// Git commits finished so far / total selected.
    Commits { done: usize, total: usize },
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
                for chunk in sources::fs::read_chunks(p, max_file_size, filter) {
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
            let mut commits = git::rev_list(&path, &options)?;
            let total_commits = commits.len();
            let checkpoint = match &options.checkpoint {
                Some(file) => {
                    let mut ids: Vec<&str> = engine
                        .detectors
                        .iter()
                        .map(|d| d.template.id.as_str())
                        .collect();
                    ids.sort_unstable();
                    let tips_s: Vec<String> =
                        tips.iter().map(|(k, v)| format!("{k}={v}")).collect();
                    let rev = format!(
                        "{:?}",
                        (
                            &options.include,
                            &options.exclude,
                            &options.branch,
                            &options.since_commit,
                            options.max_depth
                        )
                    );
                    let scope = crate::checkpoint::scope(&[
                        &crate::state::repo_key(repo),
                        &rev,
                        &tips_s.join(","),
                        &ids.join(","),
                    ]);
                    let (cp, saved) = crate::checkpoint::Checkpoint::open(file, &scope)?;
                    let by_id: std::collections::HashMap<&str, &crate::template::Template> = engine
                        .detectors
                        .iter()
                        .map(|d| (d.template.id.as_str(), d.template.as_ref()))
                        .collect();
                    collector.push(
                        saved
                            .into_iter()
                            .filter_map(|s| {
                                let t = by_id.get(s.detector.as_str())?;
                                Some(Finding::new(t, s.secret, s.location))
                            })
                            .collect(),
                    );
                    commits.retain(|c| !cp.is_done(c));
                    Some(cp)
                }
                None => None,
            };
            let diffs = AtomicUsize::new(0);
            let commits_done = AtomicUsize::new(total_commits - commits.len());
            progress(Progress::Commits {
                done: commits_done.load(Ordering::Relaxed),
                total: total_commits,
            });
            let plan = git::ScanPlan {
                jobs: options.jobs,
                // Git checks every path of every commit against every
                // pathspec (~16% slower on cargo's history with the six
                // default directory globs), so only the user's own globs,
                // usually naming something heavy, are pushed down; the
                // defaults are applied by `sink` like everything else.
                exclude_globs: filter
                    .exclude_globs
                    .iter()
                    .filter(|g| !crate::config::DEFAULT_EXCLUDES.contains(&g.as_str()))
                    .cloned()
                    .collect(),
                max_file_size: Some(max_file_size),
            };
            let sink = |c: sources::Chunk| {
                let excluded = c
                    .location
                    .path
                    .as_deref()
                    .is_some_and(|p| filter.path_excluded(std::path::Path::new(p)));
                if !excluded {
                    collector.push(scan_chunk(engine, filter, &c));
                }
                let n = diffs.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_multiple_of(256) {
                    progress(Progress::Diffs(n));
                }
            };
            let cp_error: std::sync::Mutex<Option<anyhow::Error>> = Default::default();
            let done = |part: &[String]| {
                let n = commits_done.fetch_add(part.len(), Ordering::Relaxed) + part.len();
                progress(Progress::Commits {
                    done: n,
                    total: total_commits,
                });
                if let Some(cp) = &checkpoint
                    && let Err(e) = cp.mark(part, || collector.snapshot())
                {
                    cp_error.lock().unwrap().get_or_insert(e);
                }
            };
            let scanned = git::scan_commits(&path, &commits, &plan, &sink, &done);
            if let Err(e) = scanned {
                if let (Some(cp), Some(file)) = (&checkpoint, &options.checkpoint) {
                    // Keep what finished so a rerun resumes from here.
                    cp.write(collector.snapshot())?;
                    return Err(e.context(format!(
                        "scan stopped after {} of {total_commits} commits; progress saved to {} \
                         - run the same command again to resume",
                        cp.done_count(),
                        file.display()
                    )));
                }
                return Err(e);
            }
            if let Some(e) = cp_error.into_inner().unwrap() {
                return Err(e.context("writing the checkpoint"));
            }
            progress(Progress::Diffs(diffs.load(Ordering::Relaxed)));
            if let Some(cp) = checkpoint {
                cp.finish()?;
            }
            let commits = total_commits;
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
                let loc = &chunk.location;
                let excluded = loc.path.as_deref().is_some_and(|p| {
                    filter.path_excluded(std::path::Path::new(p.trim_start_matches('/')))
                }) || loc
                    .entry
                    .as_deref()
                    .is_some_and(|e| filter.path_excluded(std::path::Path::new(e)));
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
