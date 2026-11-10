//! GitLab beyond the code: issues, merge requests, their comments (notes),
//! CI job logs, snippets and wikis, on gitlab.com or a self-managed
//! instance (API v4).
//!
//! Like [`super::github`]: text items become chunks whose location links
//! back to the exact issue, note or job; snippets and wikis are git
//! repositories and are returned for the history scanner. Their clone URLs
//! are built from the API's own host (a snippet URL on any other host is
//! dropped), so the token only ever reaches that host.
//!
//! All API traffic goes through [`crate::forge::Client`]: `PRIVATE-TOKEN`
//! auth, rate-limit aware (`RateLimit-*` headers), same-origin pagination,
//! and job traces that redirect to object storage fetched without the token.

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::{Collected, json_id, json_str, log_chunks, text_chunk};
use crate::finding::SourceKind;
use crate::forge::{Client, Kind, enc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum What {
    /// Issue titles and descriptions.
    Issues,
    /// Merge request titles and descriptions.
    MergeRequests,
    /// Comments (notes) on issues and merge requests, diff comments included.
    Comments,
    /// CI job logs (most recent jobs, see --max-jobs).
    CiLogs,
    /// Project snippets (git history).
    Snippets,
    /// The project wiki (git history).
    Wiki,
}

pub const ALL: [What; 6] = [
    What::Issues,
    What::MergeRequests,
    What::Comments,
    What::CiLogs,
    What::Snippets,
    What::Wiki,
];

#[derive(Debug, Clone)]
pub struct Options {
    /// API base, e.g. https://gitlab.com/api/v4.
    pub api: String,
    /// `group[/subgroup]/project` paths.
    pub projects: Vec<String>,
    pub what: Vec<What>,
    /// Issues / merge requests / notes per project and kind.
    pub max_items: usize,
    /// CI jobs whose logs are read per project.
    pub max_jobs: usize,
    /// Largest job log downloaded.
    pub max_log_size: u64,
    pub max_file_size: u64,
}

/// Web base for an API base (`https://gitlab.com/api/v4` ->
/// `https://gitlab.com`).
pub fn web_base(api: &str) -> String {
    let api = api.trim_end_matches('/');
    api.strip_suffix("/api/v4").unwrap_or(api).to_string()
}

/// Whether a project feature is on (missing flags count as on).
fn enabled(project: &Value, flag: &str) -> bool {
    project.get(flag).and_then(Value::as_bool) != Some(false)
}

/// Gather everything selected in `o`. `progress` receives short status
/// lines.
pub async fn collect(client: &Client, o: &Options, progress: &dyn Fn(String)) -> Result<Collected> {
    let api = o.api.trim_end_matches('/');
    let web = web_base(api);
    let web_origin = reqwest::Url::parse(&web)
        .context("invalid --api-url")?
        .origin();
    let mut out = Collected::default();
    let want = |w: What| o.what.contains(&w);
    let max_text = usize::try_from(o.max_file_size).unwrap_or(usize::MAX);
    for project in &o.projects {
        let path = project.trim_matches('/');
        if !path.contains('/') {
            bail!("`{project}` is not group/project");
        }
        let base = format!("{api}/projects/{}", enc(path));
        let info = client
            .get_json(Kind::GitLab, &base)
            .await
            .with_context(|| format!("project {path}"))?;
        let host = web
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let label = format!("{host}/{path}");
        let mut lists: Vec<(&str, Vec<Value>)> = Vec::new();
        for (what, kind, flag) in [
            (What::Issues, "issues", "issues_enabled"),
            (
                What::MergeRequests,
                "merge_requests",
                "merge_requests_enabled",
            ),
        ] {
            if !(want(what) || want(What::Comments)) || !enabled(&info, flag) {
                continue;
            }
            progress(format!("{path}: {}", kind.replace('_', " ")));
            let url = format!("{base}/{kind}?state=all&per_page=100&order_by=created_at&sort=desc");
            match client.paginate(Kind::GitLab, &url, o.max_items).await {
                Ok(items) => {
                    if want(what) {
                        for it in &items {
                            out.chunks.push(text_chunk(
                                SourceKind::GitLab,
                                &label,
                                format!("{kind}/{}", json_id(it, "iid")),
                                Some(json_str(it, "web_url")),
                                format!(
                                    "{}\n{}",
                                    json_str(it, "title"),
                                    json_str(it, "description")
                                ),
                            ));
                        }
                    }
                    lists.push((kind, items));
                }
                Err(e) => out.warnings.push(format!("{path}: {kind}: {e:#}")),
            }
        }
        if want(What::Comments) {
            progress(format!("{path}: comments"));
            for (kind, items) in &lists {
                let mut budget = o.max_items;
                for it in items {
                    if budget == 0 {
                        break;
                    }
                    // Only user comments count; skip items without any.
                    if it.get("user_notes_count").and_then(Value::as_u64) == Some(0) {
                        continue;
                    }
                    let iid = json_id(it, "iid");
                    let url = format!("{base}/{kind}/{iid}/notes?per_page=100&sort=asc");
                    let notes = match client.paginate(Kind::GitLab, &url, budget).await {
                        Ok(n) => n,
                        // gitlab.com answers 401 to anonymous note lists:
                        // one warning, not one per item.
                        Err(e) => {
                            out.warnings.push(format!("{path}: {kind} comments: {e:#}"));
                            break;
                        }
                    };
                    budget = budget.saturating_sub(notes.len());
                    for n in notes {
                        // System notes ("changed the description") are
                        // written by GitLab, not people.
                        if n.get("system").and_then(Value::as_bool) == Some(true) {
                            continue;
                        }
                        let id = json_id(&n, "id");
                        let mut p = format!("{kind}/{iid}/notes/{id}");
                        if let Some(file) = n.pointer("/position/new_path").and_then(Value::as_str)
                        {
                            p = format!("{p} ({file})");
                        }
                        let link = format!("{}#note_{id}", json_str(it, "web_url"));
                        out.chunks.push(text_chunk(
                            SourceKind::GitLab,
                            &label,
                            p,
                            Some(&link),
                            json_str(&n, "body").to_string(),
                        ));
                    }
                }
            }
        }
        if want(What::CiLogs) && enabled(&info, "jobs_enabled") {
            progress(format!("{path}: CI job logs"));
            match client
                .paginate(
                    Kind::GitLab,
                    &format!("{base}/jobs?per_page=100"),
                    o.max_jobs,
                )
                .await
            {
                Ok(jobs) => {
                    for job in jobs {
                        let id = json_id(&job, "id");
                        let url = format!("{base}/jobs/{}/trace", enc(&id));
                        let log = match client.download(Kind::GitLab, &url, o.max_log_size).await {
                            Ok(Some(l)) if !l.is_empty() => l,
                            Ok(_) => continue,
                            Err(e) => {
                                out.warnings.push(format!("{path}: job {id} log: {e:#}"));
                                continue;
                            }
                        };
                        let p = format!("jobs/{id} ({})", json_str(&job, "name"));
                        out.chunks.extend(log_chunks(
                            SourceKind::GitLab,
                            &label,
                            &p,
                            Some(json_str(&job, "web_url")),
                            &log,
                            max_text,
                        ));
                    }
                }
                Err(e) => out.warnings.push(format!("{path}: CI jobs: {e:#}")),
            }
        }
        if want(What::Snippets) && enabled(&info, "snippets_enabled") {
            progress(format!("{path}: snippets"));
            match client
                .paginate(
                    Kind::GitLab,
                    &format!("{base}/snippets?per_page=100"),
                    o.max_items,
                )
                .await
            {
                Ok(snippets) => {
                    for sn in snippets {
                        let url = json_str(&sn, "http_url_to_repo");
                        // Clone only from the API's own host: the token is
                        // attached to the clone.
                        let same_host = reqwest::Url::parse(url)
                            .map(|u| u.origin() == web_origin)
                            .unwrap_or(false);
                        if same_host {
                            out.git.push((
                                url.to_string(),
                                format!("{label} snippet {}", json_id(&sn, "id")),
                            ));
                        } else if !url.is_empty() {
                            out.warnings.push(format!(
                                "{path}: snippet {} is served from another host; skipped",
                                json_id(&sn, "id")
                            ));
                        }
                    }
                }
                Err(e) => out.warnings.push(format!("{path}: snippets: {e:#}")),
            }
        }
        if want(What::Wiki) && enabled(&info, "wiki_enabled") {
            let repo_path = path
                .split('/')
                .map(enc_segment)
                .collect::<Vec<_>>()
                .join("/");
            out.git.push((
                format!("{web}/{repo_path}.wiki.git"),
                format!("{label} (wiki)"),
            ));
        }
    }
    Ok(out)
}

/// Encode one path segment, keeping the characters GitLab paths use.
fn enc_segment(s: &str) -> String {
    const SEG: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.');
    percent_encoding::utf8_percent_encode(s, SEG).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_bases() {
        assert_eq!(web_base("https://gitlab.com/api/v4/"), "https://gitlab.com");
        assert_eq!(
            web_base("https://git.example.com/gitlab/api/v4"),
            "https://git.example.com/gitlab"
        );
        assert_eq!(enc_segment("my.group-1"), "my.group-1");
        assert_eq!(enc_segment("a b"), "a%20b");
    }
}
