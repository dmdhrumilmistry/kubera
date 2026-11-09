//! Scanning many repositories: bounded concurrency, persistent mirrors and
//! per-repository incremental baselines.
//!
//! Cost model: the first run clones each repository once into the cache;
//! later runs `git fetch` only new objects and, with a state file, `git log`
//! only commits that were never scanned. Network, disk I/O and CPU therefore
//! scale with what changed, not with the size of the organisation.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use crate::config::Filter;
use crate::detect::Engine;
use crate::finding::Finding;
use crate::scan::{self, Target};
use crate::sources::git::GitOptions;
use crate::sources::remote::Auth;
use crate::state;

pub struct Options {
    /// Repositories scanned in parallel.
    pub concurrency: usize,
    /// Directory of persistent bare mirrors (fetch instead of clone).
    pub cache_dir: Option<PathBuf>,
    pub git: GitOptions,
    pub auth: Auth,
    /// `repo key -> ref tips` of the last passing scan.
    pub baselines: HashMap<String, BTreeMap<String, String>>,
    pub max_file_size: u64,
}

#[derive(Debug)]
pub struct RepoResult {
    pub key: String,
    pub findings: Vec<Finding>,
    pub commits_scanned: usize,
    pub tips: BTreeMap<String, String>,
    pub error: Option<String>,
}

/// Mirror directory for a repository: readable name plus a hash of the key.
pub fn mirror_dir(cache: &std::path::Path, key: &str) -> PathBuf {
    let hash = hex::encode(&Sha256::digest(key.as_bytes())[..6]);
    let tail: String = key
        .trim_end_matches(".git")
        .rsplit(['/', ':'])
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("_")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    cache.join(format!("{tail}-{hash}.git"))
}

/// Scan every repository; `on_done` is called as each one finishes.
pub fn run(
    engine: &Engine,
    filter: &Filter,
    repos: &[String],
    opts: &Options,
    on_done: &(dyn Fn(&RepoResult) + Sync),
) -> Vec<RepoResult> {
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(repos.len()));
    let workers = opts.concurrency.clamp(1, 64).min(repos.len().max(1));
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(repo) = repos.get(i) else { break };
                    let key = state::repo_key(repo);
                    let is_remote = matches!(crate::sources::remote::parse(repo), Ok(Some(_)));
                    let target = Target::Git {
                        repo: repo.clone(),
                        options: opts.git.clone(),
                        auth: opts.auth.clone(),
                        baseline: opts.baselines.get(&key).cloned(),
                        mirror: match (&opts.cache_dir, is_remote) {
                            (Some(c), true) => Some(mirror_dir(c, &key)),
                            _ => None,
                        },
                    };
                    let res = match scan::run_detailed(
                        engine,
                        filter,
                        &target,
                        opts.max_file_size,
                        &|_| {},
                    ) {
                        Ok(o) => RepoResult {
                            key,
                            findings: o.findings,
                            commits_scanned: o.commits_scanned,
                            tips: o.tips,
                            error: None,
                        },
                        Err(e) => RepoResult {
                            key,
                            findings: Vec::new(),
                            commits_scanned: 0,
                            tips: BTreeMap::new(),
                            error: Some(format!("{e:#}")),
                        },
                    };
                    on_done(&res);
                    results.lock().unwrap().push(res);
                }
            });
        }
    });
    let mut v = results.into_inner().unwrap();
    v.sort_by(|a, b| a.key.cmp(&b.key));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_dirs_are_stable_and_safe() {
        let c = std::path::Path::new("/cache");
        let a = mirror_dir(c, "https://github.com/acme/api.git");
        assert_eq!(a, mirror_dir(c, "https://github.com/acme/api.git"));
        assert!(a.to_str().unwrap().starts_with("/cache/acme_api-"));
        assert_ne!(a, mirror_dir(c, "https://gitlab.com/acme/api.git"));
        let weird = mirror_dir(c, "git@host:../../etc/passwd");
        assert!(weird.starts_with(c) && !weird.to_str().unwrap()[7..].contains('/'));
    }
}
