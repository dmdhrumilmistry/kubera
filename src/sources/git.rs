//! Git history source.
//!
//! Shells out to `git log -p` and scans only *added* lines of every commit.
//! The repository may be untrusted, so git is invoked defensively:
//! external diff drivers, textconv filters, hooks and fsmonitor are disabled
//! (they can execute commands configured by the repository), revisions are
//! passed after `--end-of-options`, and clones never prompt for credentials.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use super::Chunk;
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

pub fn is_remote(target: &str) -> bool {
    ["https://", "http://", "ssh://", "git://", "git@"]
        .iter()
        .any(|p| target.starts_with(p))
}

/// Clone a remote repository into a temp dir (bare, no checkout).
pub fn clone(url: &str) -> Result<(tempfile::TempDir, PathBuf)> {
    if url.starts_with('-') {
        bail!("refusing suspicious repository url `{url}`");
    }
    let dir = tempfile::tempdir()?;
    let dest = dir.path().join("repo.git");
    let status = git()
        .args(["clone", "--bare", "--quiet", "--"])
        .arg(url)
        .arg(&dest)
        .stdin(Stdio::null())
        .status()
        .context("running git clone (is git installed?)")?;
    if !status.success() {
        bail!("git clone of {url} failed ({status})");
    }
    Ok((dir, dest))
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
    text: String,
    lines: Vec<usize>,
}

/// Stream every added hunk of every commit to `sink`.
pub fn scan(repo: &Path, opts: &GitOptions, mut sink: impl FnMut(Chunk)) -> Result<()> {
    let mut cmd = git();
    cmd.arg("-C").arg(repo).args([
        "log",
        "-p",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--full-history",
        "--format=%x01kubera-commit %H%x00%an%x00%ae%x00%aI",
    ]);
    if let Some(n) = opts.max_depth {
        cmd.arg(format!("--max-count={n}"));
    }
    if opts.branch.is_none() && opts.since_commit.is_none() {
        cmd.arg("--all");
    }
    // Everything after this is a revision, never an option.
    cmd.arg("--end-of-options");
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
    let mut child = cmd
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .context("running git log (is git installed?)")?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);

    let mut commit: Option<Commit> = None;
    let mut file: Option<FileDiff> = None;
    let mut in_hunk = false;
    let mut next_line = 0usize;

    let flush =
        |commit: &Option<Commit>, file: &mut Option<FileDiff>, sink: &mut dyn FnMut(Chunk)| {
            if let (Some(c), Some(f)) = (commit, file.take()) {
                if f.text.is_empty() || f.path.is_none() {
                    return;
                }
                sink(Chunk {
                    text: f.text,
                    location: Location {
                        source: SourceKind::Git,
                        path: f.path,
                        line: 0,
                        commit: Some(c.hash.clone()),
                        author: Some(c.author.clone()),
                        email: Some(c.email.clone()),
                        date: Some(c.date.clone()),
                    },
                    line_map: Some(f.lines),
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
            flush(&commit, &mut file, &mut sink);
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
            flush(&commit, &mut file, &mut sink);
            file = Some(FileDiff {
                path: None,
                text: String::new(),
                lines: Vec::new(),
            });
            in_hunk = false;
            continue;
        }
        let Some(f) = file.as_mut() else { continue };
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
    flush(&commit, &mut file, &mut sink);
    let status = child.wait()?;
    if !status.success() {
        bail!(
            "git log failed ({status}); is {} a git repository?",
            repo.display()
        );
    }
    Ok(())
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
    fn hunk_header() {
        assert_eq!(parse_hunk_start("-0,0 +12,3 @@ fn x"), Some(12));
        assert_eq!(parse_hunk_start("-1 +7 @@"), Some(7));
    }

    #[test]
    fn rejects_option_like_revisions() {
        assert!(check_rev("--output=/tmp/x").is_err());
        assert!(check_rev("a..b").is_err());
        assert!(check_rev("main").is_ok());
    }
}
