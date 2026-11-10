//! Git history source.
//!
//! Shells out to `git log -p` and scans only *added* lines of every commit.
//! The repository may be untrusted, so git is invoked defensively:
//! external diff drivers, textconv filters, hooks and fsmonitor are disabled
//! (they can execute commands configured by the repository), revisions are
//! passed after `--end-of-options`, and clones never prompt for credentials.
//! Remote URL handling and authentication live in [`super::remote`].

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use super::Chunk;
use super::remote::{Auth, RemoteRepo, Transport, clone_env};
use crate::finding::{Location, SourceKind};

const COMMIT_MARKER: &str = "\u{1}kubera-commit ";
/// Cap per file-diff chunk to keep memory bounded on huge generated diffs.
const MAX_CHUNK: usize = 10 * 1024 * 1024;

#[derive(Debug, Default, Clone)]
pub struct GitOptions {
    /// Branch / ref to scan; all refs when `None`.
    pub branch: Option<String>,
    /// Only scan commits after this one.
    pub since_commit: Option<String>,
    /// Maximum number of commits.
    pub max_depth: Option<usize>,
    /// Explicit tips to scan (commit ids). When set, replaces `--all` /
    /// `branch` and is combined with `exclude`.
    pub include: Vec<String>,
    /// Commits whose history is already scanned (`^sha`): only commits
    /// reachable from `include` but not from these are scanned.
    pub exclude: Vec<String>,
    /// Parallel `git log` processes (0: one per CPU).
    pub jobs: usize,
    /// Resume file for long scans (see [`crate::checkpoint`]).
    pub checkpoint: Option<PathBuf>,
    /// Scan results of file changes, shared by the repositories of one run
    /// (see [`crate::dedup`]).
    pub shared: Option<std::sync::Arc<crate::dedup::Results>>,
}

fn is_sha(s: &str) -> bool {
    (7..=64).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Tips of all branches and tags (`refname -> commit id`), or of `branch`
/// only when given.
pub fn ref_tips(
    repo: &Path,
    branch: Option<&str>,
) -> Result<std::collections::BTreeMap<String, String>> {
    let out = git()
        .arg("-C")
        .arg(repo)
        .args([
            "for-each-ref",
            "--format=%(objectname) %(*objectname) %(refname)",
            "refs/heads",
            "refs/tags",
            "refs/remotes",
        ])
        .stdin(Stdio::null())
        .output()
        .context("running git for-each-ref")?;
    if !out.status.success() {
        bail!(
            "git for-each-ref failed; is {} a git repository?",
            repo.display()
        );
    }
    let mut tips = std::collections::BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.split(' ');
        let (Some(obj), Some(peeled), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if name.ends_with("/HEAD") {
            continue;
        }
        if let Some(b) = branch {
            let short = name
                .strip_prefix("refs/heads/")
                .or_else(|| name.strip_prefix("refs/tags/"))
                .or_else(|| name.strip_prefix("refs/remotes/origin/"));
            if short != Some(b) {
                continue;
            }
        }
        // Annotated tags: use the commit they point to.
        let commit = if peeled.is_empty() { obj } else { peeled };
        tips.insert(name.to_string(), commit.to_string());
    }
    Ok(tips)
}

/// Whether `sha` names a commit present in the repository (history may have
/// been rewritten or pruned since it was recorded).
pub fn commit_exists(repo: &Path, sha: &str) -> bool {
    is_sha(sha)
        && git()
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "-e", &format!("{sha}^{{commit}}")])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

/// Keep a persistent bare mirror of `repo` in `dir`: clone it the first
/// time, afterwards only fetch what changed (pruning deleted refs).
pub fn update_mirror(repo: &RemoteRepo, auth: &Auth, dir: &Path) -> Result<()> {
    if !dir.join("HEAD").exists() {
        let parent = dir.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = tempfile::Builder::new()
            .prefix(".clone-")
            .tempdir_in(parent)?;
        let (_guard, cloned) = clone_into(repo, auth, &GitOptions::default(), tmp.path())?;
        std::fs::rename(&cloned, dir)
            .with_context(|| format!("moving clone into {}", dir.display()))?;
        return Ok(());
    }
    let mut cmd = git();
    cmd.arg("-C").arg(dir).args([
        "fetch",
        "--quiet",
        "--prune",
        "--force",
        "--no-write-fetch-head",
        "--",
    ]);
    cmd.arg(&repo.clone_url)
        .arg("+refs/heads/*:refs/heads/*")
        .arg("+refs/tags/*:refs/tags/*");
    for (k, v) in clone_env(repo, auth)? {
        cmd.env(k, v);
    }
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("running git fetch")?;
    if !out.status.success() {
        bail!(
            "git fetch of {} failed: {}",
            repo.display(),
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("unknown error")
        );
    }
    Ok(())
}

fn git() -> Command {
    let mut c = Command::new("git");
    c.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.ext.allow=never",
    ]);
    c.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_EXTERNAL_DIFF");
    c
}

/// Clone a remote repository into a temp dir (bare, no checkout).
///
/// Credentials are passed through the environment (see
/// [`super::remote::clone_env`]), never on the command line.
pub fn clone(
    repo: &RemoteRepo,
    auth: &Auth,
    opts: &GitOptions,
) -> Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::tempdir()?;
    let (_, dest) = clone_into(repo, auth, opts, dir.path())?;
    Ok((dir, dest))
}

fn clone_into(
    repo: &RemoteRepo,
    auth: &Auth,
    opts: &GitOptions,
    parent: &Path,
) -> Result<((), PathBuf)> {
    let dest = parent.join("repo.git");
    let mut cmd = git();
    cmd.args(["clone", "--bare", "--quiet"]);
    if let (Some(n), None) = (opts.max_depth, &opts.since_commit) {
        cmd.arg(format!("--depth={n}"));
    }
    if let Some(b) = &opts.branch {
        check_rev(b)?;
        // Commit ids cannot be cloned as a branch; fetch everything then.
        let is_sha = b.len() >= 7 && b.chars().all(|c| c.is_ascii_hexdigit());
        if !is_sha {
            cmd.args(["--single-branch", "--branch", b]);
        }
    }
    cmd.arg("--").arg(&repo.clone_url).arg(&dest);
    for (k, v) in clone_env(repo, auth)? {
        cmd.env(k, v);
    }
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("running git clone (is git installed?)")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let hint = match repo.transport {
            Transport::Ssh => {
                " (check your SSH key / agent and host key; kubera never prompts when stdin is not a terminal)"
            }
            Transport::Https | Transport::Http => {
                " (private repository? pass a token with --token-env)"
            }
            _ => "",
        };
        bail!(
            "git clone of {} failed: {}{hint}",
            repo.display(),
            err.trim().lines().last().unwrap_or("unknown error")
        );
    }
    Ok(((), dest))
}

/// The `origin` remote of a local repository, if it is a known forge
/// (used to link findings to the web UI).
pub fn origin_remote(repo: &Path) -> Option<RemoteRepo> {
    let out = git()
        .arg("-C")
        .arg(repo)
        .args(["config", "--get", "remote.origin.url"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let url = String::from_utf8(out.stdout).ok()?;
    let r = super::remote::parse(url.trim()).ok()??;
    r.web.is_some().then_some(r)
}

fn check_rev(r: &str) -> Result<()> {
    if r.starts_with('-') || r.contains("..") || r.trim().is_empty() {
        bail!("invalid revision `{r}`");
    }
    Ok(())
}

struct Commit {
    hash: String,
    author: String,
    email: String,
    date: String,
}

struct FileDiff {
    path: Option<String>,
    /// Old and new blob ids from the `index` line.
    blobs: Option<u128>,
    text: String,
    lines: Vec<usize>,
}

/// Performance knobs for [`scan_commits`].
#[derive(Debug, Clone, Default)]
pub struct ScanPlan {
    /// Parallel `git log` processes (0: one per CPU).
    pub jobs: usize,
    /// Path globs git should not diff at all. Only an optimisation: callers
    /// still apply their own path filter to every chunk.
    pub exclude_globs: Vec<String>,
    /// Files larger than this are treated as binary by git (not diffed).
    pub max_file_size: Option<u64>,
}

/// Number of worker processes for `jobs` (0 = one per CPU).
pub fn effective_jobs(jobs: usize) -> usize {
    if jobs > 0 {
        jobs
    } else {
        std::thread::available_parallelism().map_or(4, |n| n.get())
    }
}

/// Append the revision selection described by `opts` to a `git log` /
/// `git rev-list` command, ending with `--`.
fn push_revisions(cmd: &mut Command, opts: &GitOptions) -> Result<()> {
    if let Some(n) = opts.max_depth {
        cmd.arg(format!("--max-count={n}"));
    }
    let explicit = !opts.include.is_empty();
    if explicit && (opts.branch.is_some() || opts.since_commit.is_some()) {
        bail!("explicit revisions cannot be combined with branch / since-commit");
    }
    if !explicit && opts.branch.is_none() && opts.since_commit.is_none() {
        cmd.arg("--all");
    }
    // Everything after this is a revision, never an option.
    cmd.arg("--end-of-options");
    if explicit {
        for r in opts.include.iter().chain(&opts.exclude) {
            if !is_sha(r) {
                bail!("invalid commit id `{r}`");
            }
        }
        cmd.args(&opts.include);
        cmd.args(opts.exclude.iter().map(|e| format!("^{e}")));
    }
    let tip = match &opts.branch {
        Some(b) => {
            check_rev(b)?;
            Some(b.clone())
        }
        None => None,
    };
    match (&opts.since_commit, tip) {
        (Some(since), tip) => {
            check_rev(since)?;
            cmd.arg(format!("{since}..{}", tip.unwrap_or_else(|| "HEAD".into())));
        }
        (None, Some(tip)) => {
            cmd.arg(tip);
        }
        (None, None) => {}
    }
    cmd.arg("--");
    Ok(())
}

/// Commits selected by `opts`, newest first.
pub fn rev_list(repo: &Path, opts: &GitOptions) -> Result<Vec<String>> {
    let mut cmd = git();
    cmd.arg("-C").arg(repo).arg("rev-list");
    push_revisions(&mut cmd, opts)?;
    let out = cmd
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("running git rev-list (is git installed?)")?;
    if !out.status.success() {
        bail!(
            "git rev-list failed ({}); is {} a git repository?",
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("unknown error"),
            repo.display()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| is_sha(l))
        .map(str::to_string)
        .collect())
}

/// Stream every added hunk of every commit selected by `opts` to `sink`.
/// Returns the number of commits scanned.
pub fn scan(
    repo: &Path,
    opts: &GitOptions,
    plan: &ScanPlan,
    sink: &(dyn Fn(Chunk) + Sync),
) -> Result<usize> {
    let commits = rev_list(repo, opts)?;
    scan_commits(repo, &commits, plan, sink, &|_| {})?;
    Ok(commits.len())
}

/// Scan the lines added by the staged changes (`git diff --cached`): what
/// the next commit would add. Used by the pre-commit hook.
pub fn scan_staged(repo: &Path, sink: &(dyn Fn(Chunk) + Sync)) -> Result<()> {
    let mut cmd = git();
    cmd.arg("-C").arg(repo).args([
        "diff",
        "--cached",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--diff-filter=ACMR",
        "--",
    ]);
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running git diff (is git installed?)")?;
    let stdout = child.stdout.take().expect("piped stdout");
    let parsed = parse_log(BufReader::new(stdout), sink);
    let out = child.wait_with_output()?;
    parsed?;
    if !out.status.success() {
        bail!(
            "git diff --cached failed: {}; is {} a git repository?",
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("unknown error"),
            repo.display()
        );
    }
    Ok(())
}

/// Turn a user exclude glob into a git `:(exclude,glob)` pathspec when git's
/// matching is guaranteed to be at most as broad as the caller's filter
/// (git's `*` never crosses `/`; a literal name would also match a whole
/// directory, so those are left to the post-filter).
fn exclude_pathspec(glob: &str) -> Option<String> {
    let last = glob.rsplit('/').next().unwrap_or(glob);
    let wild = last.contains('*') || last.contains('?') || last.contains('[');
    if glob.is_empty() || !wild || glob.contains('{') || glob.starts_with(':') {
        return None;
    }
    Some(format!(":(exclude,glob){glob}"))
}

/// Scan the diffs of `commits` (each against its first parent) with
/// `plan.jobs` parallel `git log` processes. Commits are split into
/// partitions handed out to workers; each worker parses its process's output
/// while git is still producing it. `sink` is called from worker threads,
/// and `done` with each partition once every chunk of it went through
/// `sink` (used for checkpoints).
pub fn scan_commits(
    repo: &Path,
    commits: &[String],
    plan: &ScanPlan,
    sink: &(dyn Fn(Chunk) + Sync),
    done: &(dyn Fn(&[String]) + Sync),
) -> Result<()> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    if commits.is_empty() {
        return Ok(());
    }
    let jobs = effective_jobs(plan.jobs);
    // Several partitions per worker balance uneven commits and bound the
    // work an interrupted scan repeats; large ones keep git's caches warm.
    let size = (commits.len() / (jobs * 8)).clamp(64, 2000);
    let parts: Vec<&[String]> = commits.chunks(size).collect();
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let failed: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..jobs.min(parts.len()) {
            s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    if crate::checkpoint::stop_requested() {
                        stop.store(true, Ordering::Relaxed);
                        failed
                            .lock()
                            .unwrap()
                            .get_or_insert_with(|| anyhow::anyhow!("interrupted"));
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(part) = parts.get(i) else { break };
                    match log_partition(repo, part, plan, sink) {
                        Ok(()) => done(part),
                        Err(e) => {
                            stop.store(true, Ordering::Relaxed);
                            failed.lock().unwrap().get_or_insert(e);
                            break;
                        }
                    }
                }
            });
        }
    });
    match failed.into_inner().unwrap() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn log_partition(
    repo: &Path,
    commits: &[String],
    plan: &ScanPlan,
    sink: &(dyn Fn(Chunk) + Sync),
) -> Result<()> {
    use std::io::Write;

    let mut cmd = git();
    if let Some(n) = plan.max_file_size {
        cmd.arg("-c").arg(format!("core.bigFileThreshold={n}"));
    }
    cmd.arg("-C").arg(repo).args([
        "log",
        "-p",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--full-history",
        "--no-walk=unsorted",
        "--stdin",
        // Blob ids identify repeated changes (see `crate::dedup`); a fixed
        // diff algorithm makes the text of a change depend on its blobs
        // only, not on repository or user configuration.
        "--full-index",
        "--diff-algorithm=myers",
        "--indent-heuristic",
        "--format=%x01kubera-commit %H%x00%an%x00%ae%x00%aI",
        "--",
    ]);
    let specs: Vec<String> = plan
        .exclude_globs
        .iter()
        .filter_map(|g| exclude_pathspec(g))
        .collect();
    if !specs.is_empty() {
        cmd.arg(".").args(specs);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running git log (is git installed?)")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    // Feed commit ids from a separate thread: git starts writing output
    // before it has read all of its input.
    let ids = commits.join("\n") + "\n";
    let (parsed, err) = std::thread::scope(|s| {
        s.spawn(move || {
            let _ = stdin.write_all(ids.as_bytes());
        });
        let e = s.spawn(move || {
            let mut buf = String::new();
            let _ = std::io::Read::read_to_string(&mut stderr, &mut buf);
            buf
        });
        let parsed = parse_log(BufReader::with_capacity(256 * 1024, stdout), sink);
        (parsed, e.join().unwrap_or_default())
    });
    let status = child.wait()?;
    parsed?;
    if !status.success() && crate::checkpoint::stop_requested() {
        // Ctrl-C reached git too.
        bail!("interrupted");
    }
    if !status.success() {
        bail!(
            "git log failed ({status}): {}",
            err.trim().lines().last().unwrap_or("unknown error")
        );
    }
    Ok(())
}

/// Parse `git log -p -U0` output into one chunk per (commit, file) holding
/// the added lines. Returns the number of commits seen.
fn parse_log(mut reader: impl BufRead, sink: &(dyn Fn(Chunk) + Sync)) -> Result<usize> {
    let mut commits = 0usize;
    let mut commit: Option<Commit> = None;
    let mut file: Option<FileDiff> = None;
    let mut in_hunk = false;
    let mut next_line = 0usize;

    // Staged diffs (`git diff --cached`) have no commit header.
    let flush = |commit: &Option<Commit>, file: &mut Option<FileDiff>| {
        if let Some(f) = file.take() {
            if f.text.is_empty() || f.path.is_none() {
                return;
            }
            sink(Chunk {
                text: f.text,
                location: Location {
                    source: SourceKind::Git,
                    path: f.path,
                    line: 0,
                    commit: commit.as_ref().map(|c| c.hash.clone()),
                    author: commit.as_ref().map(|c| c.author.clone()),
                    email: commit.as_ref().map(|c| c.email.clone()),
                    date: commit.as_ref().map(|c| c.date.clone()),
                    ..Default::default()
                },
                line_map: Some(f.lines),
                content_id: f.blobs,
            });
        }
    };

    let mut raw = Vec::new();
    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&raw);
        let line = line.strip_suffix('\n').unwrap_or(&line);
        let line = line.strip_suffix('\r').unwrap_or(line);

        if let Some(rest) = line.strip_prefix(COMMIT_MARKER) {
            if crate::checkpoint::stop_requested() {
                bail!("interrupted");
            }
            commits += 1;
            flush(&commit, &mut file);
            let mut it = rest.split('\0');
            commit = Some(Commit {
                hash: it.next().unwrap_or_default().to_string(),
                author: it.next().unwrap_or_default().to_string(),
                email: it.next().unwrap_or_default().to_string(),
                date: it.next().unwrap_or_default().to_string(),
            });
            in_hunk = false;
            continue;
        }
        if line.starts_with("diff --git ") {
            flush(&commit, &mut file);
            file = Some(FileDiff {
                path: None,
                blobs: None,
                text: String::new(),
                lines: Vec::new(),
            });
            in_hunk = false;
            continue;
        }
        let Some(f) = file.as_mut() else { continue };
        if !in_hunk && let Some(ids) = line.strip_prefix("index ") {
            f.blobs = blob_pair(ids);
        }
        if !in_hunk && let Some(p) = line.strip_prefix("+++ ") {
            f.path = p.strip_prefix("b/").map(unquote);
        }
        if let Some(h) = line.strip_prefix("@@ ") {
            in_hunk = true;
            next_line = parse_hunk_start(h).unwrap_or(1);
            continue;
        }
        if !in_hunk {
            continue;
        }
        if let Some(added) = line.strip_prefix('+') {
            if f.text.len() < MAX_CHUNK {
                f.text.push_str(added);
                f.text.push('\n');
                f.lines.push(next_line);
            }
            next_line += 1;
        } else if line.starts_with(' ') {
            next_line += 1;
        }
    }
    flush(&commit, &mut file);
    Ok(commits)
}

/// `<old>..<new>[ <mode>]` of an `index` line as one id: the first 64 bits
/// of each blob id (full ids with `--full-index`; abbreviated ones are
/// rejected, they could collide).
fn blob_pair(ids: &str) -> Option<u128> {
    let (old, new) = ids.split(' ').next()?.split_once("..")?;
    let prefix = |h: &str| {
        (h.len() >= 40)
            .then(|| u64::from_str_radix(h.get(..16)?, 16).ok())
            .flatten()
    };
    Some((u128::from(prefix(old)?) << 64) | u128::from(prefix(new)?))
}

/// Parse `-a,b +c,d @@` and return `c`.
fn parse_hunk_start(h: &str) -> Option<usize> {
    let plus = h.split_whitespace().find(|p| p.starts_with('+'))?;
    plus[1..].split(',').next()?.parse().ok()
}

fn unquote(p: &str) -> String {
    p.trim_matches('"').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_pairs_need_full_ids() {
        let a = "1".repeat(40);
        let b = format!("{}{}", "abcdef0123456789", "0".repeat(24));
        let id = blob_pair(&format!("{a}..{b} 100644")).unwrap();
        assert_eq!(id >> 64, 0x1111_1111_1111_1111);
        assert_eq!(id as u64, 0xabcd_ef01_2345_6789);
        assert_eq!(blob_pair(&format!("{a}..{b}")), Some(id));
        assert_ne!(blob_pair(&format!("{b}..{a}")), Some(id));
        assert!(blob_pair("1234567..89abcde 100644").is_none());
        assert!(blob_pair(&format!("{a}{b}")).is_none());
    }

    #[test]
    fn hunk_header() {
        assert_eq!(parse_hunk_start("-0,0 +12,3 @@ fn x"), Some(12));
        assert_eq!(parse_hunk_start("-1 +7 @@"), Some(7));
    }

    #[test]
    fn exclude_pathspecs_never_widen_the_filter() {
        assert_eq!(
            exclude_pathspec("**/node_modules/**").as_deref(),
            Some(":(exclude,glob)**/node_modules/**")
        );
        assert!(exclude_pathspec("*.min.js").is_some());
        // A literal name would also exclude a directory's contents.
        assert!(exclude_pathspec("vendor").is_none());
        assert!(exclude_pathspec("{a,b}/*.js").is_none());
        assert!(exclude_pathspec(":(top)x*").is_none());
    }

    #[test]
    fn rejects_option_like_revisions() {
        assert!(check_rev("--output=/tmp/x").is_err());
        assert!(check_rev("a..b").is_err());
        assert!(check_rev("main").is_ok());
    }
}
