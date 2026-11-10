//! Jira Cloud: issue summaries, descriptions, environments, comments and
//! the earlier values kept in each issue's change history.
//!
//! Issues are found with a JQL search (`/rest/api/3/search/jql`, token
//! pagination), so the API decides nothing about where requests go: every
//! URL is built from `--site`. Rich text arrives as Atlassian Document
//! Format and is flattened to plain text (link targets included, since
//! URLs carry credentials too).
//!
//! Credentials: an Atlassian account email and API token (basic auth), a
//! bearer token (OAuth / Data Center personal access token) without the
//! email, or none for public sites. Sent only to the site, over HTTPS,
//! through [`crate::forge::Client`] (rate limits and `Retry-After`
//! honoured, no redirects).

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::{Collected, json_id, json_str, text_chunk};
use crate::finding::SourceKind;
use crate::forge::{Client, Kind, enc};

pub struct Options {
    /// `https://<site>.atlassian.net`.
    pub site: String,
    pub jql: String,
    pub max_issues: usize,
    /// Scan earlier values from the change history.
    pub history: bool,
}

/// Default search when no `--jql` is given: Jira Cloud refuses unbounded
/// queries, so bound it by a creation date far in the past.
pub const DEFAULT_JQL: &str = "created >= -36500d ORDER BY created DESC";

/// The site's base URL: `https` (or `http` with `allow_http`), no path.
pub fn site_base(site: &str, allow_http: bool) -> Result<String> {
    let with_scheme = if site.contains("://") {
        site.to_string()
    } else {
        format!("https://{site}")
    };
    let u = reqwest::Url::parse(&with_scheme).with_context(|| format!("invalid site `{site}`"))?;
    match u.scheme() {
        "https" => {}
        "http" if allow_http => {}
        s => bail!("refusing `{s}` site; Atlassian sites are reached over https"),
    }
    let host = u.host_str().context("site without a host")?;
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = u.path().trim_end_matches('/');
    Ok(format!("{}://{host}{port}{path}", u.scheme()))
}

/// Flatten Atlassian Document Format (or a plain string) to text.
pub fn adf_to_text(v: &Value) -> String {
    let mut out = String::new();
    adf_walk(v, &mut out, 0);
    out
}

fn adf_walk(v: &Value, out: &mut String, depth: usize) {
    if depth > 64 {
        return;
    }
    match v {
        Value::String(s) => out.push_str(s),
        Value::Array(a) => a.iter().for_each(|x| adf_walk(x, out, depth + 1)),
        Value::Object(o) => {
            let ty = o.get("type").and_then(Value::as_str).unwrap_or_default();
            if let Some(t) = o.get("text").and_then(Value::as_str) {
                out.push_str(t);
            }
            for m in o
                .get("marks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(h) = m.pointer("/attrs/href").and_then(Value::as_str) {
                    out.push(' ');
                    out.push_str(h);
                }
            }
            let attrs = o.get("attrs");
            let attr = |k: &str| attrs.and_then(|a| a.get(k)).and_then(Value::as_str);
            match ty {
                "hardBreak" => out.push('\n'),
                "mention" | "status" => out.push_str(attr("text").unwrap_or_default()),
                "emoji" => out.push_str(attr("shortName").unwrap_or_default()),
                "inlineCard" | "blockCard" | "embedCard" => {
                    out.push_str(attr("url").unwrap_or_default())
                }
                _ => {}
            }
            if let Some(c) = o.get("content") {
                adf_walk(c, out, depth + 1);
            }
            if matches!(
                ty,
                "paragraph"
                    | "heading"
                    | "codeBlock"
                    | "blockquote"
                    | "listItem"
                    | "tableRow"
                    | "tableCell"
                    | "tableHeader"
                    | "panel"
                    | "rule"
                    | "blockCard"
                    | "embedCard"
            ) && !out.ends_with('\n')
            {
                out.push('\n');
            }
        }
        _ => {}
    }
}

/// Text fields whose earlier values are worth scanning.
const HISTORY_FIELDS: [&str; 4] = ["description", "summary", "environment", "Comment"];

/// Gather issues, comments and history.
pub async fn collect(client: &Client, o: &Options, progress: &dyn Fn(String)) -> Result<Collected> {
    let site = o.site.trim_end_matches('/');
    let host = site.split("://").nth(1).unwrap_or(site);
    let repo = format!("jira:{host}");
    let mut out = Collected::default();
    let mut token = String::new();
    let mut seen = 0usize;
    let expand = if o.history { "&expand=changelog" } else { "" };
    loop {
        let mut url = format!(
            "{site}/rest/api/3/search/jql?jql={}&maxResults=100&fields=summary,description,environment,comment{expand}",
            enc(&o.jql)
        );
        if !token.is_empty() {
            url.push_str(&format!("&nextPageToken={}", enc(&token)));
        }
        let page = client
            .get_json(Kind::Other, &url)
            .await
            .context("Jira search")?;
        let issues = page["issues"].as_array().cloned().unwrap_or_default();
        if issues.is_empty() {
            break;
        }
        for issue in issues {
            if seen >= o.max_issues {
                break;
            }
            seen += 1;
            issue_chunks(client, site, &repo, &issue, o.history, &mut out).await;
        }
        progress(format!("{host}: {seen} issue(s)"));
        token = json_str(&page, "nextPageToken").to_string();
        if token.is_empty() || seen >= o.max_issues || page["isLast"] == true {
            break;
        }
    }
    Ok(out)
}

async fn issue_chunks(
    client: &Client,
    site: &str,
    repo: &str,
    issue: &Value,
    history: bool,
    out: &mut Collected,
) {
    let key = json_str(issue, "key");
    // Keys are PROJECT-123; anything else would make odd paths and URLs.
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return;
    }
    let f = &issue["fields"];
    let link = format!("{site}/browse/{key}");
    let mut text = format!("{}\n", json_str(f, "summary"));
    for field in ["description", "environment"] {
        if !f[field].is_null() {
            text.push_str(&adf_to_text(&f[field]));
            text.push('\n');
        }
    }
    out.chunks.push(text_chunk(
        SourceKind::Jira,
        repo,
        key.to_string(),
        Some(&link),
        text,
    ));

    let mut comments = f
        .pointer("/comment/comments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total = f
        .pointer("/comment/total")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    while comments.len() < total && comments.len() < 10_000 {
        let url = format!(
            "{site}/rest/api/3/issue/{}/comment?startAt={}&maxResults=100",
            enc(key),
            comments.len()
        );
        match client.get_json(Kind::Other, &url).await {
            Ok(v) => {
                let more = v["comments"].as_array().cloned().unwrap_or_default();
                if more.is_empty() {
                    break;
                }
                comments.extend(more);
            }
            Err(e) => {
                out.warnings.push(format!("{key}: comments: {e:#}"));
                break;
            }
        }
    }
    for c in comments {
        let id = json_id(&c, "id");
        out.chunks.push(text_chunk(
            SourceKind::Jira,
            repo,
            format!("{key}/comment/{id}"),
            Some(&format!("{link}?focusedCommentId={}", enc(&id))),
            adf_to_text(&c["body"]),
        ));
    }

    if !history {
        return;
    }
    let mut histories = issue
        .pointer("/changelog/histories")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total = issue
        .pointer("/changelog/total")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    if histories.len() < total {
        // The search embeds only the first page; read the full log.
        histories.clear();
        while histories.len() < total && histories.len() < 10_000 {
            let url = format!(
                "{site}/rest/api/3/issue/{}/changelog?startAt={}&maxResults=100",
                enc(key),
                histories.len()
            );
            match client.get_json(Kind::Other, &url).await {
                Ok(v) => {
                    let more = v["values"].as_array().cloned().unwrap_or_default();
                    if more.is_empty() {
                        break;
                    }
                    histories.extend(more);
                }
                Err(e) => {
                    out.warnings.push(format!("{key}: change history: {e:#}"));
                    break;
                }
            }
        }
    }
    for h in histories {
        // Every earlier value is the `fromString` of the change that
        // replaced it; the current one is in the issue itself.
        let old: Vec<&str> = h["items"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|i| HISTORY_FIELDS.contains(&json_str(i, "field")))
            .map(|i| json_str(i, "fromString"))
            .filter(|s| !s.is_empty())
            .collect();
        if old.is_empty() {
            continue;
        }
        out.chunks.push(text_chunk(
            SourceKind::Jira,
            repo,
            format!("{key}/history/{}", json_id(&h, "id")),
            Some(&link),
            old.join("\n"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adf_flattens_to_text_with_links() {
        let doc = serde_json::json!({"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [
                {"type": "text", "text": "token: "},
                {"type": "text", "text": "abc", "marks": [{"type": "code"}]},
                {"type": "hardBreak"},
                {"type": "text", "text": "db", "marks": [{"type": "link", "attrs": {"href": "https://u:p@db.example"}}]}
            ]},
            {"type": "codeBlock", "content": [{"type": "text", "text": "export K=1"}]},
            {"type": "bulletList", "content": [{"type": "listItem", "content": [
                {"type": "paragraph", "content": [{"type": "mention", "attrs": {"text": "@dana"}}]}
            ]}]}
        ]});
        assert_eq!(
            adf_to_text(&doc),
            "token: abc\ndb https://u:p@db.example\nexport K=1\n@dana\n"
        );
        assert_eq!(
            adf_to_text(&Value::String("wiki *text*".into())),
            "wiki *text*"
        );
    }

    #[test]
    fn sites() {
        assert_eq!(
            site_base("acme.atlassian.net", false).unwrap(),
            "https://acme.atlassian.net"
        );
        assert_eq!(
            site_base("https://acme.atlassian.net/", false).unwrap(),
            "https://acme.atlassian.net"
        );
        assert!(site_base("http://acme.atlassian.net", false).is_err());
    }
}
