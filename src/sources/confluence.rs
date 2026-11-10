//! Confluence Cloud: page and blog post bodies, their comments, and
//! (optionally) earlier page versions (REST API v2).
//!
//! Spaces are listed (or picked with `--space`), then each space's pages
//! and blog posts are read with their storage-format bodies, which are
//! turned into text: tags dropped, entities decoded, CDATA (code macros)
//! kept verbatim, link targets kept. Every URL is built from `--site`;
//! `_links.next` pagination is followed on the same origin only.
//!
//! Credentials work as for [`super::jira`]: email + API token, a bearer
//! token, or none for public sites.

use anyhow::{Context, Result};
use serde_json::Value;

use super::{Collected, json_id, json_str, text_chunk};
use crate::finding::SourceKind;
use crate::forge::{Client, Kind, enc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum What {
    /// Page bodies.
    Pages,
    /// Blog post bodies.
    Blogposts,
    /// Footer and inline comments on pages and blog posts.
    Comments,
}

pub const ALL: [What; 3] = [What::Pages, What::Blogposts, What::Comments];

pub struct Options {
    /// `https://<site>.atlassian.net` (no `/wiki`).
    pub site: String,
    /// Space keys; every space when empty.
    pub spaces: Vec<String>,
    pub what: Vec<What>,
    /// Pages or blog posts read per space.
    pub max_pages: usize,
    /// Earlier versions read per page (0: none).
    pub max_versions: usize,
}

/// Decode HTML / XML character references (named ones Confluence emits,
/// and numeric ones); unknown ones are kept as they are.
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let end = tail[..tail.len().min(12)].find(';');
        let Some(end) = end else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let ent = &tail[1..end];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            "mdash" => Some('\u{2014}'),
            "ndash" => Some('\u{2013}'),
            "lsquo" => Some('\u{2018}'),
            "rsquo" => Some('\u{2019}'),
            "ldquo" => Some('\u{201c}'),
            "rdquo" => Some('\u{201d}'),
            "hellip" => Some('\u{2026}'),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                u32::from_str_radix(&ent[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => out.push(c),
            None => out.push_str(&tail[..=end]),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Tags after which text continues on a new line.
const BLOCK: [&str; 20] = [
    "p",
    "br",
    "div",
    "li",
    "tr",
    "td",
    "th",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "table",
    "blockquote",
    "hr",
    "ac:parameter",
    "ac:plain-text-body",
    "ac:rich-text-body",
];

/// Attributes whose values are worth scanning (link and resource targets).
const KEEP_ATTRS: [&str; 4] = ["href", "src", "ri:value", "ri:url"];

/// Confluence storage format (XHTML with `ac:` / `ri:` macros) to text.
pub fn storage_to_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('<') {
        out.push_str(&decode_entities(&rest[..i]));
        let tail = &rest[i..];
        if let Some(body) = tail.strip_prefix("<![CDATA[") {
            let end = body.find("]]>").unwrap_or(body.len());
            out.push_str(&body[..end]);
            rest = body.get(end + 3..).unwrap_or_default();
            continue;
        }
        if let Some(body) = tail.strip_prefix("<!--") {
            let end = body.find("-->").map(|e| e + 3).unwrap_or(body.len());
            rest = &body[end..];
            continue;
        }
        // The end of the tag, skipping `>` inside quoted attribute values.
        let mut quote = None;
        let mut end = tail.len();
        for (j, c) in tail.char_indices().skip(1) {
            match (quote, c) {
                (None, '"' | '\'') => quote = Some(c),
                (Some(q), c) if c == q => quote = None,
                (None, '>') => {
                    end = j;
                    break;
                }
                _ => {}
            }
        }
        let tag = &tail[1..end];
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '/' && *c != '>')
            .collect::<String>()
            .to_ascii_lowercase();
        for attr in KEEP_ATTRS {
            for quote in ['"', '\''] {
                let pat = format!(" {attr}={quote}");
                let mut t = tag;
                while let Some(p) = t.find(&pat) {
                    let v = &t[p + pat.len()..];
                    let Some(e) = v.find(quote) else { break };
                    // Spaced, so the value never glues to the text.
                    out.push(' ');
                    out.push_str(&decode_entities(&v[..e]));
                    out.push(' ');
                    t = &v[e..];
                }
            }
        }
        if BLOCK.contains(&name.as_str()) && !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        rest = tail.get(end + 1..).unwrap_or_default();
    }
    out.push_str(&decode_entities(rest));
    out
}

fn body(v: &Value) -> String {
    storage_to_text(
        v.pointer("/body/storage/value")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
}

/// Gather pages, blog posts and comments.
pub async fn collect(client: &Client, o: &Options, progress: &dyn Fn(String)) -> Result<Collected> {
    let site = o.site.trim_end_matches('/');
    let api = format!("{site}/wiki/api/v2");
    let host = site.split("://").nth(1).unwrap_or(site);
    let repo = format!("confluence:{host}");
    let want = |w: What| o.what.contains(&w);
    let mut out = Collected::default();

    let spaces_url = if o.spaces.is_empty() {
        format!("{api}/spaces?limit=250")
    } else {
        format!("{api}/spaces?limit=250&keys={}", enc(&o.spaces.join(",")))
    };
    let spaces = client
        .paginate(Kind::Other, &spaces_url, 100_000)
        .await
        .context("listing Confluence spaces")?;
    for want_key in &o.spaces {
        if !spaces.iter().any(|s| json_str(s, "key") == want_key) {
            out.warnings
                .push(format!("space `{want_key}` not found (or no access)"));
        }
    }
    let link = |v: &Value| {
        let w = v.pointer("/_links/webui").and_then(Value::as_str)?;
        w.starts_with('/').then(|| format!("{site}/wiki{w}"))
    };
    for space in spaces {
        let key = json_str(&space, "key").to_string();
        let id = json_id(&space, "id");
        for (what, kind) in [(What::Pages, "pages"), (What::Blogposts, "blogposts")] {
            if !want(what) && !want(What::Comments) {
                continue;
            }
            progress(format!("{key}: {kind}"));
            let url = format!(
                "{api}/spaces/{}/{kind}?body-format=storage&limit=250",
                enc(&id)
            );
            let items = match client.paginate(Kind::Other, &url, o.max_pages).await {
                Ok(i) => i,
                Err(e) => {
                    out.warnings.push(format!("{key}: {kind}: {e:#}"));
                    continue;
                }
            };
            for it in &items {
                let item_id = json_id(it, "id");
                let path = format!("{key}/{kind}/{item_id}");
                if want(what) {
                    out.chunks.push(text_chunk(
                        SourceKind::Confluence,
                        &repo,
                        path.clone(),
                        link(it).as_deref(),
                        format!("{}\n{}", json_str(it, "title"), body(it)),
                    ));
                }
                if want(What::Comments) {
                    for ckind in ["footer-comments", "inline-comments"] {
                        let url = format!(
                            "{api}/{kind}/{}/{ckind}?body-format=storage&limit=250",
                            enc(&item_id)
                        );
                        match client.paginate(Kind::Other, &url, 10_000).await {
                            Ok(comments) => {
                                for c in comments {
                                    out.chunks.push(text_chunk(
                                        SourceKind::Confluence,
                                        &repo,
                                        format!("{path}/comments/{}", json_id(&c, "id")),
                                        link(&c).or_else(|| link(it)).as_deref(),
                                        body(&c),
                                    ));
                                }
                            }
                            Err(e) => out.warnings.push(format!("{path}: {ckind}: {e:#}")),
                        }
                    }
                }
                if want(what) && o.max_versions > 0 {
                    versions(
                        client,
                        &api,
                        kind,
                        it,
                        &path,
                        &repo,
                        o.max_versions,
                        &mut out,
                    )
                    .await;
                }
            }
        }
    }
    Ok(out)
}

/// Earlier versions of a page or blog post (secrets edited out of the
/// current text are still in its history).
#[allow(clippy::too_many_arguments)]
async fn versions(
    client: &Client,
    api: &str,
    kind: &str,
    item: &Value,
    path: &str,
    repo: &str,
    max: usize,
    out: &mut Collected,
) {
    let current = item
        .pointer("/version/number")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let id = json_id(item, "id");
    // Newest earlier versions first.
    for n in (1..current).rev().take(max) {
        let url = format!("{api}/{kind}/{}?version={n}&body-format=storage", enc(&id));
        match client.get_json(Kind::Other, &url).await {
            Ok(v) => out.chunks.push(text_chunk(
                SourceKind::Confluence,
                repo,
                format!("{path}/versions/{n}"),
                None,
                format!("{}\n{}", json_str(&v, "title"), body(&v)),
            )),
            Err(e) => {
                out.warnings.push(format!("{path}: version {n}: {e:#}"));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_format_to_text() {
        let s = r#"<p>Use the <a href="https://u:p@db.example/x?a=1&amp;b=2">db</a> key&nbsp;below&mdash;</p><ac:structured-macro ac:name="code"><ac:parameter ac:name="language">bash</ac:parameter><ac:plain-text-body><![CDATA[export TOKEN=<abc>
echo ok]]></ac:plain-text-body></ac:structured-macro><!-- note --><p title="a>b">x &lt;y&gt; &#65;&#x42; &bogus;</p>"#;
        assert_eq!(
            storage_to_text(s),
            "Use the  https://u:p@db.example/x?a=1&b=2 db key below\u{2014}\nbash\nexport TOKEN=<abc>\necho ok\nx <y> AB &bogus;\n"
        );
    }
}
