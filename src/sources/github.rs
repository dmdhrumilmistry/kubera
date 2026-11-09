//! GitHub beyond the code: issues and pull requests, their comments,
//! review comments, GitHub Actions logs, wikis and gists.
//!
//! Secrets pasted into an issue, a PR review or printed by a CI job never
//! show up in a repository scan. Text items become chunks whose location
//! links back to the exact comment or run; wikis and gists are git
//! repositories and are returned for the history scanner (so their edits
//! and deleted revisions are covered too).
//!
//! All API traffic goes through [`crate::forge::Client`]: rate-limit
//! aware, same-origin pagination, and Actions logs fetched from their
//! pre-signed storage URL without the token.

use anyhow::Result;
use serde_json::Value;

use super::Chunk;
use crate::finding::{Location, SourceKind};
use crate::forge::Client;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum What {
    /// Issue and pull request titles and descriptions.
    Issues,
    /// Issue / PR conversation comments and review comments.
    Comments,
    /// GitHub Actions run logs (most recent runs, see --max-runs).
    Actions,
    /// The repository wiki (git history).
    Wiki,
    /// Gists of --user accounts (git history).
    Gists,
}

pub const ALL: [What; 5] = [
    What::Issues,
    What::Comments,
    What::Actions,
    What::Wiki,
    What::Gists,
];

#[derive(Debug, Clone)]
pub struct Options {
    /// API base, e.g. https://api.github.com or https://ghe.example.com/api/v3.
    pub api: String,
    /// `owner/name` repositories.
    pub repos: Vec<String>,
    /// Users whose gists are scanned.
    pub gist_users: Vec<String>,
    pub what: Vec<What>,
    /// Issues / comments per repository and kind.
    pub max_items: usize,
    /// Actions runs per repository.
    pub max_runs: usize,
    /// Largest Actions log archive downloaded.
    pub max_log_size: u64,
    pub max_file_size: u64,
}

/// What [`collect`] gathered.
#[derive(Default)]
pub struct Collected {
    pub chunks: Vec<Chunk>,
    /// Git repositories to scan with the history scanner: (clone URL, label).
    pub git: Vec<(String, String)>,
    /// Non-fatal problems (e.g. Actions disabled, no access).
    pub warnings: Vec<String>,
}

/// Web base for an API base (`https://api.github.com` -> `https://github.com`,
/// `https://ghe/api/v3` -> `https://ghe`).
pub fn web_base(api: &str) -> String {
    let api = api.trim_end_matches('/');
    if api == "https://api.github.com" {
        return "https://github.com".into();
    }
    api.strip_suffix("/api/v3").unwrap_or(api).to_string()
}

fn text_chunk(repo: &str, path: String, link: Option<&str>, text: String) -> Chunk {
    Chunk {
        text,
        location: Location {
            source: SourceKind::GitHub,
            repository: Some(repo.to_string()),
            path: Some(path),
            link: link
                .filter(|l| l.starts_with("https://"))
                .map(str::to_string),
            ..Default::default()
        },
        line_map: None,
    }
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Gather everything selected in `o`. `progress` receives short status
/// lines.
pub async fn collect(client: &Client, o: &Options, progress: &dyn Fn(String)) -> Result<Collected> {
    let api = o.api.trim_end_matches('/');
    let web = web_base(api);
    let mut out = Collected::default();
    let want = |w: What| o.what.contains(&w);
    for repo in &o.repos {
        let Some((owner, name)) = repo.split_once('/') else {
            anyhow::bail!("`{repo}` is not owner/name");
        };
        let (owner, name) = (enc(owner), enc(name));
        let label = format!("{}/{repo}", web.trim_start_matches("https://"));
        let base = format!("{api}/repos/{owner}/{name}");

        if want(What::Issues) {
            progress(format!("{repo}: issues and pull requests"));
            let items = client
                .github_list(
                    &format!("{base}/issues?state=all&per_page=100"),
                    o.max_items,
                )
                .await?;
            for it in items {
                let kind = if it.get("pull_request").is_some() {
                    "pull"
                } else {
                    "issues"
                };
                let n = it.get("number").and_then(Value::as_u64).unwrap_or(0);
                let text = format!("{}\n{}", s(&it, "title"), s(&it, "body"));
                out.chunks.push(text_chunk(
                    &label,
                    format!("{kind}/{n}"),
                    Some(s(&it, "html_url")),
                    text,
                ));
            }
        }
        if want(What::Comments) {
            progress(format!("{repo}: comments"));
            for (endpoint, prefix) in [("issues/comments", "comment"), ("pulls/comments", "review")]
            {
                let items = client
                    .github_list(&format!("{base}/{endpoint}?per_page=100"), o.max_items)
                    .await?;
                for it in items {
                    let id = it.get("id").and_then(Value::as_u64).unwrap_or(0);
                    let mut path = format!("{prefix}/{id}");
                    if prefix == "review" && !s(&it, "path").is_empty() {
                        path = format!("{path} ({})", s(&it, "path"));
                    }
                    out.chunks.push(text_chunk(
                        &label,
                        path,
                        Some(s(&it, "html_url")),
                        s(&it, "body").to_string(),
                    ));
                }
            }
        }
        if want(What::Actions) {
            progress(format!("{repo}: Actions logs"));
            match client
                .github_list(&format!("{base}/actions/runs?per_page=100"), o.max_runs)
                .await
            {
                Ok(runs) => {
                    for run in runs {
                        let id = run.get("id").and_then(Value::as_u64).unwrap_or(0);
                        let link = s(&run, "html_url").to_string();
                        let url = format!("{base}/actions/runs/{id}/logs");
                        let zip = match client.github_download(&url, o.max_log_size).await {
                            Ok(Some(z)) => z,
                            Ok(None) => continue,
                            Err(e) => {
                                out.warnings.push(format!("{repo}: run {id} logs: {e:#}"));
                                continue;
                            }
                        };
                        let limits = super::archive::Limits::new(o.max_file_size);
                        let Some(kind) = super::archive::kind(&zip) else {
                            continue;
                        };
                        let res = super::archive::walk(
                            kind,
                            std::io::Cursor::new(zip),
                            limits,
                            &mut |e| {
                                out.chunks.push(text_chunk(
                                    &label,
                                    format!("actions/runs/{id}/{}", e.path),
                                    Some(&link),
                                    e.text,
                                ))
                            },
                        );
                        if let Err(e) = res {
                            out.warnings.push(format!("{repo}: run {id} logs: {e:#}"));
                        }
                    }
                }
                Err(e) => out.warnings.push(format!("{repo}: Actions runs: {e:#}")),
            }
        }
        if want(What::Wiki) {
            out.git.push((
                format!("{web}/{owner}/{name}.wiki.git"),
                format!("{label} (wiki)"),
            ));
        }
    }
    if want(What::Gists) {
        for u in &o.gist_users {
            progress(format!("{u}: gists"));
            let gists = client
                .github_list(
                    &format!("{api}/users/{}/gists?per_page=100", enc(u)),
                    o.max_items,
                )
                .await?;
            for g in gists {
                let url = s(&g, "git_pull_url");
                if url.starts_with("https://") {
                    out.git
                        .push((url.to_string(), format!("gist {} by {u}", s(&g, "id"))));
                }
            }
        }
    }
    Ok(out)
}

fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_bases() {
        assert_eq!(web_base("https://api.github.com/"), "https://github.com");
        assert_eq!(
            web_base("https://ghe.example.com/api/v3"),
            "https://ghe.example.com"
        );
    }
}
