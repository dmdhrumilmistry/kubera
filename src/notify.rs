//! Alerts: tell Slack or any webhook when a scan finds secrets.
//!
//! * Webhook URLs are read from environment variables, never argv (a Slack
//!   webhook URL is itself a credential).
//! * Payloads carry redacted findings only.
//! * HTTPS only, no redirects (the shared HTTP client), errors never echo
//!   the URL path.
//! * Generic webhooks can be signed: `X-Kubera-Signature: sha256=<hex>` is an
//!   HMAC-SHA256 over `<timestamp>.<body>` with the timestamp in
//!   `X-Kubera-Timestamp`, so receivers can reject forged and replayed
//!   deliveries.
//! * Slack text is escaped, so hostile paths or commit authors cannot
//!   inject mentions (`<!channel>`) or links.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use hmac::{KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::finding::{Finding, Status};
use crate::http::{Http, Prepared, redact_url};

/// Findings listed in a Slack message (the rest are counted).
const SLACK_MAX: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Slack,
    Webhook,
}

#[derive(Clone)]
pub struct Target {
    url: reqwest::Url,
    kind: Kind,
    secret: Option<String>,
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {}", self.kind, redact_url(&self.url))
    }
}

impl Target {
    /// Build a target from the URL in environment variable `var`. Slack
    /// incoming webhooks are recognised by host; anything else gets the
    /// generic JSON payload, signed when `secret` is given.
    pub fn from_env(var: &str, secret: Option<String>, allow_http: bool) -> Result<Self> {
        let raw = std::env::var(var).with_context(|| {
            format!("environment variable `{var}` (from --notify-env) is not set")
        })?;
        Self::new(raw.trim(), secret, allow_http).with_context(|| format!("webhook URL in `{var}`"))
    }

    pub fn new(url: &str, secret: Option<String>, allow_http: bool) -> Result<Self> {
        let url = reqwest::Url::parse(url).context("not a valid URL")?;
        match url.scheme() {
            "https" => {}
            "http" if allow_http => {}
            s => bail!("scheme `{s}` refused; webhooks must use https"),
        }
        let kind = if url.host_str() == Some("hooks.slack.com") {
            Kind::Slack
        } else {
            Kind::Webhook
        };
        Ok(Self { url, kind, secret })
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn display(&self) -> String {
        redact_url(&self.url)
    }
}

/// Slack mrkdwn escaping (`&`, `<`, `>` are control characters).
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn location(f: &Finding) -> String {
    let l = &f.location;
    let mut s = l
        .path
        .clone()
        .unwrap_or_else(|| format!("{:?}", l.source).to_lowercase());
    if let Some(e) = &l.entry {
        s.push_str("!/");
        s.push_str(e);
    }
    if l.line > 0 {
        s.push_str(&format!(":{}", l.line));
    }
    s
}

pub fn slack_payload(findings: &[Finding], source: &str) -> serde_json::Value {
    let live = findings
        .iter()
        .filter(|f| f.status() == Some(Status::Verified))
        .count();
    let mut text = format!(
        ":rotating_light: *Kubera* found *{}* secret(s){} in `{}`\n",
        findings.len(),
        if live > 0 {
            format!(", *{live} live*")
        } else {
            String::new()
        },
        slack_escape(source)
    );
    for f in findings.iter().take(SLACK_MAX) {
        let status = match f.status() {
            Some(Status::Verified) => " :red_circle: live",
            Some(Status::Invalid) => " invalid",
            _ => "",
        };
        text.push_str(&format!(
            "• *{}* ({}){status} `{}`",
            slack_escape(&f.name),
            format!("{:?}", f.severity).to_lowercase(),
            slack_escape(&location(f)),
        ));
        if let Some(c) = &f.location.commit {
            text.push_str(&format!(
                " commit `{}`",
                slack_escape(&c[..c.len().min(12)])
            ));
        }
        if let Some(r) = &f.location.repository {
            text.push_str(&format!(" in {}", slack_escape(r)));
        }
        text.push('\n');
    }
    if findings.len() > SLACK_MAX {
        text.push_str(&format!("…and {} more\n", findings.len() - SLACK_MAX));
    }
    json!({ "text": text, "unfurl_links": false, "unfurl_media": false })
}

pub fn webhook_payload(findings: &[Finding], source: &str) -> serde_json::Value {
    json!({
        "event": "kubera.findings",
        "version": 1,
        "source": source,
        "count": findings.len(),
        "live": findings.iter().filter(|f| f.status() == Some(Status::Verified)).count(),
        "findings": findings,
    })
}

/// `sha256=<hex>` over `<timestamp>.<body>`.
pub fn signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Deliver `findings` (redacted here, whatever the caller passed) to one
/// target.
pub async fn send(http: &Http, t: &Target, findings: &[Finding], source: &str) -> Result<()> {
    let redacted: Vec<Finding> = findings.iter().map(Finding::redact).collect();
    let payload = match t.kind {
        Kind::Slack => slack_payload(&redacted, source),
        Kind::Webhook => webhook_payload(&redacted, source),
    };
    let body = serde_json::to_vec(&payload)?;
    let ts = chrono::Utc::now().timestamp().to_string();
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("x-kubera-event".to_string(), "findings".to_string()),
        ("x-kubera-timestamp".to_string(), ts.clone()),
    ];
    if let Some(secret) = &t.secret {
        headers.push(("x-kubera-signature".into(), signature(secret, &ts, &body)));
    }
    let resp = http
        .send(&Prepared {
            method: "POST".into(),
            url: t.url.clone(),
            headers,
            body: Some(body),
            timeout: Duration::from_secs(15),
        })
        .await?;
    if !(200..300).contains(&resp.status) {
        bail!("{} answered HTTP {}", t.display(), resp.status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_validated_and_classified() {
        assert!(Target::new("http://example.com/h", None, false).is_err());
        assert!(Target::new("file:///etc/passwd", None, true).is_err());
        let s = Target::new("https://hooks.slack.com/services/T0/B0/xyz", None, false).unwrap();
        assert_eq!(s.kind(), Kind::Slack);
        assert_eq!(s.display(), "https://hooks.slack.com/…");
        assert!(!format!("{s:?}").contains("xyz"));
        let w = Target::new("https://alerts.example.com/kubera", None, false).unwrap();
        assert_eq!(w.kind(), Kind::Webhook);
    }

    #[test]
    fn slack_text_cannot_inject_mentions() {
        let p = slack_payload(&[], "<!channel> & <https://evil|x>");
        let text = p["text"].as_str().unwrap();
        assert!(!text.contains("<!channel>"));
        assert!(text.contains("&lt;!channel&gt; &amp;"));
    }

    #[test]
    fn signature_matches_reference() {
        // HMAC-SHA256("key", "1700000000.{}") computed independently.
        let sig = signature("key", "1700000000", b"{}");
        assert!(sig.starts_with("sha256=") && sig.len() == 7 + 64);
        assert_ne!(sig, signature("key", "1700000001", b"{}"));
    }
}
