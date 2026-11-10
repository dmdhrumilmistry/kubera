//! Slack: channel messages and thread replies (Web API).
//!
//! Credentials get pasted into chat more than anywhere else. Channels are
//! listed with `conversations.list`, read with `conversations.history`,
//! and threads with `conversations.replies`; every message becomes a chunk
//! whose location names the channel and message timestamp and links to the
//! message in Slack.
//!
//! The token (bot `xoxb-` or user `xoxp-`) comes from an environment
//! variable and is only sent to the API host as a bearer header, through
//! [`crate::forge::Client`]: Slack's `429` + `Retry-After` is honoured, up
//! to `--max-rate-wait`. Calls are read-only; a bot only sees the channels
//! it was added to.

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::{Collected, json_str, text_chunk};
use crate::finding::SourceKind;
use crate::forge::{Client, Kind, enc};

pub struct Options {
    /// API base, e.g. https://slack.com/api.
    pub api: String,
    /// Channel names (`general`, `#general`) or ids (`C0123ABCD`); all
    /// visible channels when empty.
    pub channels: Vec<String>,
    /// Only messages after this Unix time.
    pub oldest: Option<i64>,
    /// Also read direct and group messages (user tokens).
    pub include_dms: bool,
    pub include_archived: bool,
    /// Messages read per channel (thread replies included).
    pub max_messages: usize,
}

/// Parse `--since`: `YYYY-MM-DD`, RFC 3339, or Unix seconds.
pub fn parse_since(s: &str) -> Result<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Ok(n);
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(t.timestamp());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(d
            .and_hms_opt(0, 0, 0)
            .context("invalid date")?
            .and_utc()
            .timestamp());
    }
    bail!("`{s}` is not a date (YYYY-MM-DD), an RFC 3339 time or Unix seconds")
}

/// One Web API call; Slack reports errors as `{"ok": false}` with HTTP 200.
async fn call(client: &Client, api: &str, method: &str, query: &str) -> Result<Value> {
    let url = format!("{api}/{method}?{query}");
    let v = client.get_json(Kind::Other, &url).await?;
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        bail!("{method}: {}", json_str(&v, "error"));
    }
    Ok(v)
}

/// Every item under `key` of a cursor-paginated method, up to `max`.
async fn cursor_list(
    client: &Client,
    api: &str,
    method: &str,
    query: &str,
    key: &str,
    max: usize,
) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    let mut cursor = String::new();
    for _ in 0..100_000 {
        let q = if cursor.is_empty() {
            query.to_string()
        } else {
            format!("{query}&cursor={}", enc(&cursor))
        };
        let v = call(client, api, method, &q).await?;
        out.extend(v[key].as_array().cloned().unwrap_or_default());
        cursor = v
            .pointer("/response_metadata/next_cursor")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if cursor.is_empty() || out.len() >= max {
            break;
        }
    }
    out.truncate(max);
    Ok(out)
}

/// The text of a message: body, attachments and file previews.
fn message_text(m: &Value) -> String {
    let mut parts = vec![json_str(m, "text").to_string()];
    for a in m["attachments"].as_array().into_iter().flatten() {
        for k in ["pretext", "title", "text", "fallback", "footer"] {
            parts.push(json_str(a, k).to_string());
        }
        for f in a["fields"].as_array().into_iter().flatten() {
            parts.push(json_str(f, "value").to_string());
        }
    }
    for f in m["files"].as_array().into_iter().flatten() {
        // Snippets and posts carry their text inline; other files are not
        // downloaded (they live on files.slack.com).
        for k in ["title", "preview", "plain_text"] {
            parts.push(json_str(f, k).to_string());
        }
    }
    parts.retain(|p| !p.is_empty());
    parts.dedup();
    parts.join("\n")
}

/// `1700000000.000100` -> RFC 3339.
fn ts_date(ts: &str) -> Option<String> {
    let secs: i64 = ts.split('.').next()?.parse().ok()?;
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.to_rfc3339())
}

fn is_channel_id(s: &str) -> bool {
    s.len() >= 9
        && matches!(s.as_bytes()[0], b'C' | b'G' | b'D')
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Gather the messages selected in `o`.
pub async fn collect(client: &Client, o: &Options, progress: &dyn Fn(String)) -> Result<Collected> {
    let api = o.api.trim_end_matches('/');
    let auth = call(client, api, "auth.test", "").await?;
    let team = match json_str(&auth, "team") {
        "" => "workspace".to_string(),
        t => t.to_string(),
    };
    let web = Some(json_str(&auth, "url"))
        .filter(|u| u.starts_with("https://"))
        .map(|u| u.trim_end_matches('/').to_string());
    let repo = format!("slack:{team}");
    let mut out = Collected::default();

    let mut types = vec!["public_channel", "private_channel"];
    if o.include_dms {
        types.extend(["im", "mpim"]);
    }
    let query = format!(
        "types={}&exclude_archived={}&limit=200",
        types.join(","),
        !o.include_archived
    );
    progress(format!("{team}: listing channels"));
    let listed = match cursor_list(
        client,
        api,
        "conversations.list",
        &query,
        "channels",
        100_000,
    )
    .await
    {
        Ok(l) => l,
        // Channel ids still work without the list scopes.
        Err(e) if o.channels.iter().all(|c| is_channel_id(c)) && !o.channels.is_empty() => {
            out.warnings.push(format!("listing channels: {e:#}"));
            Vec::new()
        }
        Err(e) => {
            return Err(e).context("listing channels (scopes channels:read, groups:read)");
        }
    };
    // (id, display name)
    let mut channels: Vec<(String, String)> = Vec::new();
    let name_of = |c: &Value| match json_str(c, "name") {
        "" => format!("dm-{}", json_str(c, "user")),
        n => n.to_string(),
    };
    if o.channels.is_empty() {
        channels.extend(
            listed
                .iter()
                .map(|c| (json_str(c, "id").to_string(), name_of(c))),
        );
    } else {
        for want in &o.channels {
            let want = want.trim_start_matches('#');
            match listed
                .iter()
                .find(|c| json_str(c, "id") == want || json_str(c, "name") == want)
            {
                Some(c) => channels.push((json_str(c, "id").to_string(), name_of(c))),
                // Not visible in the list (e.g. a private channel of a
                // user token): try the id directly.
                None if is_channel_id(want) => channels.push((want.to_string(), want.to_string())),
                None => bail!("channel `{want}` not found (is the app a member?)"),
            }
        }
    }
    channels.sort();
    channels.dedup();

    let oldest = o.oldest.map(|t| format!("&oldest={t}")).unwrap_or_default();
    for (id, name) in &channels {
        progress(format!("{team}: #{name}"));
        let q = format!("channel={}&limit=200{oldest}", enc(id));
        let messages = match cursor_list(
            client,
            api,
            "conversations.history",
            &q,
            "messages",
            o.max_messages,
        )
        .await
        {
            Ok(m) => m,
            Err(e) => {
                let hint = if e.to_string().contains("not_in_channel") {
                    " (invite the app to the channel)"
                } else {
                    ""
                };
                out.warnings.push(format!("#{name}: {e:#}{hint}"));
                continue;
            }
        };
        let mut budget = o.max_messages.saturating_sub(messages.len());
        for m in &messages {
            let ts = json_str(m, "ts");
            push_message(&mut out, &repo, web.as_deref(), id, name, m, None);
            let threaded = m.get("reply_count").and_then(Value::as_u64).unwrap_or(0) > 0
                && json_str(m, "thread_ts") == ts;
            if !threaded || budget == 0 {
                continue;
            }
            let q = format!("channel={}&ts={}&limit=200{oldest}", enc(id), enc(ts));
            match cursor_list(
                client,
                api,
                "conversations.replies",
                &q,
                "messages",
                budget + 1,
            )
            .await
            {
                Ok(replies) => {
                    for r in replies.iter().filter(|r| json_str(r, "ts") != ts) {
                        budget = budget.saturating_sub(1);
                        push_message(&mut out, &repo, web.as_deref(), id, name, r, Some(ts));
                    }
                }
                Err(e) => out.warnings.push(format!("#{name}: thread {ts}: {e:#}")),
            }
        }
    }
    Ok(out)
}

fn push_message(
    out: &mut Collected,
    repo: &str,
    web: Option<&str>,
    channel: &str,
    name: &str,
    m: &Value,
    thread: Option<&str>,
) {
    let text = message_text(m);
    if text.is_empty() {
        return;
    }
    let ts = json_str(m, "ts");
    let (path, link) = match thread {
        Some(parent) => (
            format!("#{name}/{parent}/{ts}"),
            web.map(|w| {
                format!(
                    "{w}/archives/{channel}/p{}?thread_ts={parent}&cid={channel}",
                    ts.replace('.', "")
                )
            }),
        ),
        None => (
            format!("#{name}/{ts}"),
            web.map(|w| format!("{w}/archives/{channel}/p{}", ts.replace('.', ""))),
        ),
    };
    let mut c = text_chunk(SourceKind::Slack, repo, path, link.as_deref(), text);
    c.location.date = ts_date(ts);
    if let Some(u) = m.get("user").and_then(Value::as_str) {
        c.location.author = Some(u.to_string());
    }
    out.chunks.push(c);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_formats() {
        assert_eq!(parse_since("2026-01-02").unwrap(), 1_767_312_000);
        assert_eq!(parse_since("1767312000").unwrap(), 1_767_312_000);
        assert_eq!(
            parse_since("2026-01-02T01:00:00+01:00").unwrap(),
            1_767_312_000
        );
        assert!(parse_since("yesterday").is_err());
    }

    #[test]
    fn message_text_includes_attachments_and_snippets() {
        let m = serde_json::json!({
            "text": "see below",
            "attachments": [{"text": "a", "fallback": "a", "fields": [{"value": "f"}]}],
            "files": [{"title": "creds", "preview": "KEY=1"}]
        });
        assert_eq!(message_text(&m), "see below\na\nf\ncreds\nKEY=1");
        assert!(is_channel_id("C0123ABCD") && !is_channel_id("general"));
    }
}
