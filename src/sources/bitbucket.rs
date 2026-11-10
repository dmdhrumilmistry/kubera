//! Bitbucket Cloud beyond the code: issues, pull requests, their comments,
//! Pipelines step logs and workspace snippets (2.0 API).
//!
//! Like [`super::github`]: text items become chunks whose location links
//! back to the issue, comment or pipeline; snippets are git repositories
//! and are returned for the history scanner, but only when they are served
//! from the web host the API names, so the token stays on Bitbucket.
//!
//! All API traffic goes through [`crate::forge::Client`]: basic auth with
//! `--token-user` (app passwords, API tokens) or a bearer access token,
//! rate-limit aware, `next` pagination followed on the same origin only,
//! and step logs that redirect to storage fetched without credentials.

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::{Collected, json_id, json_str, log_chunks, text_chunk};
use crate::finding::SourceKind;
use crate::forge::{Client, Kind, enc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum What {
    /// Issue titles and descriptions (repositories with the issue tracker).
    Issues,
    /// Pull request titles and descriptions.
    PullRequests,
    /// Issue and pull request comments, inline comments included.
    Comments,
    /// Bitbucket Pipelines step logs (most recent runs, see --max-runs).
    Pipelines,
    /// Snippets of the repositories' workspaces (git history).
    Snippets,
}

pub const ALL: [What; 5] = [
    What::Issues,
    What::PullRequests,
    What::Comments,
    What::Pipelines,
    What::Snippets,
];

#[derive(Debug, Clone)]
pub struct Options {
    /// API base, e.g. https://api.bitbucket.org/2.0.
    pub api: String,
    /// `workspace/repo` repositories.
    pub repos: Vec<String>,
    /// Workspaces whose snippets are scanned.
    pub snippet_workspaces: Vec<String>,
    pub what: Vec<What>,
    /// Issues / pull requests / comments per repository and kind.
    pub max_items: usize,
    /// Pipelines whose step logs are read per repository.
    pub max_runs: usize,
    /// Largest step log downloaded.
    pub max_log_size: u64,
    pub max_file_size: u64,
}

/// Web host for an API base (`https://api.bitbucket.org/2.0` ->
/// `https://bitbucket.org`); other bases are their own web host.
pub fn web_base(api: &str) -> String {
    let api = api.trim_end_matches('/');
    if api == "https://api.bitbucket.org/2.0" {
        return "https://bitbucket.org".into();
    }
    api.strip_suffix("/2.0").unwrap_or(api).to_string()
}

fn raw<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Gather everything selected in `o`.
pub async fn collect(client: &Client, o: &Options, progress: &dyn Fn(String)) -> Result<Collected> {
    let api = o.api.trim_end_matches('/');
    let web = web_base(api);
    let web_origin = reqwest::Url::parse(&web)
        .context("invalid --api-url")?
        .origin();
    let mut out = Collected::default();
    let want = |w: What| o.what.contains(&w);
    let max_text = usize::try_from(o.max_file_size).unwrap_or(usize::MAX);
    let label_host = web
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    for repo in &o.repos {
        let Some((ws, name)) = repo.split_once('/') else {
            bail!("`{repo}` is not workspace/repo");
        };
        let base = format!("{api}/repositories/{}/{}", enc(ws), enc(name));
        let info = client
            .get_json(Kind::Bitbucket, &base)
            .await
            .with_context(|| format!("repository {repo}"))?;
        let html = Some(raw(&info, "/links/html/href"))
            .filter(|h| h.starts_with("https://"))
            .map(str::to_string)
            .unwrap_or_else(|| format!("{web}/{repo}"));
        let label = format!("{label_host}/{repo}");
        let mut lists: Vec<(&str, &str, Vec<Value>)> = Vec::new();
        let has_issues = info.get("has_issues").and_then(Value::as_bool) != Some(false);
        if (want(What::Issues) || want(What::Comments)) && has_issues {
            progress(format!("{repo}: issues"));
            match client
                .paginate(
                    Kind::Bitbucket,
                    &format!("{base}/issues?pagelen=50"),
                    o.max_items,
                )
                .await
            {
                Ok(items) => lists.push(("issues", "issues", items)),
                Err(e) => out.warnings.push(format!("{repo}: issues: {e:#}")),
            }
        }
        if want(What::PullRequests) || want(What::Comments) {
            progress(format!("{repo}: pull requests"));
            let url = format!(
                "{base}/pullrequests?state=OPEN&state=MERGED&state=DECLINED&state=SUPERSEDED&pagelen=50"
            );
            match client.paginate(Kind::Bitbucket, &url, o.max_items).await {
                Ok(items) => lists.push(("pull-requests", "pullrequests", items)),
                Err(e) => out.warnings.push(format!("{repo}: pull requests: {e:#}")),
            }
        }
        for (kind, endpoint, items) in &lists {
            let what = if *endpoint == "issues" {
                What::Issues
            } else {
                What::PullRequests
            };
            if want(what) {
                for it in items {
                    let body = match raw(it, "/content/raw") {
                        "" => raw(it, "/summary/raw"),
                        b => b,
                    };
                    out.chunks.push(text_chunk(
                        SourceKind::Bitbucket,
                        &label,
                        format!("{kind}/{}", json_id(it, "id")),
                        Some(raw(it, "/links/html/href")),
                        format!("{}\n{body}", json_str(it, "title")),
                    ));
                }
            }
            if !want(What::Comments) {
                continue;
            }
            let mut budget = o.max_items;
            for it in items {
                if budget == 0 {
                    break;
                }
                if it.get("comment_count").and_then(Value::as_u64) == Some(0) {
                    continue;
                }
                let id = json_id(it, "id");
                let url = format!("{base}/{endpoint}/{}/comments?pagelen=100", enc(&id));
                let comments = match client.paginate(Kind::Bitbucket, &url, budget).await {
                    Ok(c) => c,
                    Err(e) => {
                        out.warnings.push(format!("{repo}: {kind} comments: {e:#}"));
                        break;
                    }
                };
                budget = budget.saturating_sub(comments.len());
                for c in comments {
                    if c.get("deleted").and_then(Value::as_bool) == Some(true) {
                        continue;
                    }
                    let mut p = format!("{kind}/{id}/comments/{}", json_id(&c, "id"));
                    let file = raw(&c, "/inline/path");
                    if !file.is_empty() {
                        p = format!("{p} ({file})");
                    }
                    out.chunks.push(text_chunk(
                        SourceKind::Bitbucket,
                        &label,
                        p,
                        Some(raw(&c, "/links/html/href")),
                        raw(&c, "/content/raw").to_string(),
                    ));
                }
            }
        }
        if want(What::Pipelines) {
            progress(format!("{repo}: pipeline logs"));
            let url = format!("{base}/pipelines/?pagelen=50&sort=-created_on");
            match client.paginate(Kind::Bitbucket, &url, o.max_runs).await {
                Ok(runs) => {
                    for run in runs {
                        let uuid = json_str(&run, "uuid").to_string();
                        let number = json_id(&run, "build_number");
                        let link = format!("{html}/pipelines/results/{}", enc(&number));
                        let steps_url =
                            format!("{base}/pipelines/{}/steps/?pagelen=100", enc(&uuid));
                        let steps = match client.paginate(Kind::Bitbucket, &steps_url, 100).await {
                            Ok(s) => s,
                            Err(e) => {
                                out.warnings
                                    .push(format!("{repo}: pipeline {number} steps: {e:#}"));
                                continue;
                            }
                        };
                        for step in steps {
                            let step_uuid = json_str(&step, "uuid");
                            let log_url = format!(
                                "{base}/pipelines/{}/steps/{}/log",
                                enc(&uuid),
                                enc(step_uuid)
                            );
                            let log = match client
                                .download(Kind::Bitbucket, &log_url, o.max_log_size)
                                .await
                            {
                                Ok(Some(l)) if !l.is_empty() => l,
                                Ok(_) => continue,
                                Err(e) => {
                                    out.warnings
                                        .push(format!("{repo}: pipeline {number} log: {e:#}"));
                                    continue;
                                }
                            };
                            // Unnamed steps have no `name`.
                            let step_name = match json_str(&step, "name") {
                                "" => step_uuid.trim_matches(['{', '}']),
                                n => n,
                            };
                            let p = format!("pipelines/{number}/{step_name}");
                            out.chunks.extend(log_chunks(
                                SourceKind::Bitbucket,
                                &label,
                                &p,
                                Some(&link),
                                &log,
                                max_text,
                            ));
                        }
                    }
                }
                // Repositories without Pipelines answer 404.
                Err(e) => out.warnings.push(format!("{repo}: pipelines: {e:#}")),
            }
        }
    }
    if want(What::Snippets) {
        for ws in &o.snippet_workspaces {
            progress(format!("{ws}: snippets"));
            let url = format!("{api}/snippets/{}?pagelen=100", enc(ws));
            let snippets = match client.paginate(Kind::Bitbucket, &url, o.max_items).await {
                Ok(s) => s,
                Err(e) => {
                    out.warnings.push(format!("{ws}: snippets: {e:#}"));
                    continue;
                }
            };
            for sn in snippets {
                let Some(href) = sn
                    .pointer("/links/clone")
                    .and_then(Value::as_array)
                    .and_then(|l| l.iter().find(|c| c["name"] == "https"))
                    .and_then(|c| c["href"].as_str())
                else {
                    continue;
                };
                // Drop an embedded user name; credentials come from env.
                let Ok(mut u) = reqwest::Url::parse(href) else {
                    continue;
                };
                let _ = u.set_username("");
                let _ = u.set_password(None);
                if u.origin() != web_origin {
                    out.warnings.push(format!(
                        "{ws}: snippet {} is served from another host; skipped",
                        json_id(&sn, "id")
                    ));
                    continue;
                }
                out.git.push((
                    u.to_string(),
                    format!("{label_host} snippet {ws}/{}", json_id(&sn, "id")),
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_bases() {
        assert_eq!(
            web_base("https://api.bitbucket.org/2.0/"),
            "https://bitbucket.org"
        );
        assert_eq!(web_base("http://127.0.0.1:9/2.0"), "http://127.0.0.1:9");
    }
}
