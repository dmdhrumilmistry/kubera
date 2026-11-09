//! Executes template requests and evaluates responses.
//!
//! Security notes:
//! * Only `https://` URLs are allowed unless the caller explicitly opts in
//!   (`HttpOptions::allow_http`, used by tests and local mocks).
//! * Redirects are never followed, so credentials cannot be bounced to a
//!   different host.
//! * Response bodies are capped to `MAX_BODY` bytes.

pub mod jsonpath;
pub mod sigv4;
pub mod tls;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use serde_json::Value;

use crate::render::{self, Vars};
use crate::template::{Auth, Extract, Matcher, Request};

/// Maximum response body kept in memory.
pub const MAX_BODY: usize = 1024 * 1024;
const DEFAULT_TIMEOUT: u64 = 15;

const FORM_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Debug, Clone, Default)]
pub struct HttpOptions {
    /// Permit plain `http://` URLs (never enable for real credentials).
    pub allow_http: bool,
    /// Default request timeout in seconds.
    pub timeout: Option<u64>,
}

#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    opts: HttpOptions,
}

/// A fully rendered request, ready to send (or to display in a dry run).
#[derive(Debug, Clone)]
pub struct Prepared {
    pub method: String,
    pub url: reqwest::Url,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// Lower-cased header name -> values joined with `, `.
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub json: Option<Value>,
}

impl Http {
    pub fn new(opts: HttpOptions) -> Result<Self> {
        #[allow(unused_mut)]
        let mut builder = reqwest::Client::builder()
            .user_agent(concat!("kubera/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10));
        // The OS verifier needs a JVM on Android (unavailable to a native CLI
        // such as under Termux), so verify against explicit roots there.
        #[cfg(target_os = "android")]
        {
            let (roots, _source) = tls::android_roots();
            builder = builder.tls_certs_only(roots);
        }
        let client = builder.build().context("building HTTP client")?;
        Ok(Self { client, opts })
    }

    /// Render a template request against `vars`.
    pub fn prepare(&self, req: &Request, vars: &Vars) -> Result<Prepared> {
        let method = req.method.to_uppercase();
        let mut url = reqwest::Url::parse(&render::render(&req.url, vars)?)
            .context("request url is not a valid URL")?;
        match url.scheme() {
            "https" => {}
            "http" if self.opts.allow_http => {}
            s => {
                bail!("refusing to send a credential over `{s}://` ({url}); only https is allowed")
            }
        }
        if !req.query.is_empty() {
            let mut q = url.query_pairs_mut();
            for (k, v) in &req.query {
                q.append_pair(&render::render(k, vars)?, &render::render(v, vars)?);
            }
        }

        let mut headers: Vec<(String, String)> = Vec::new();
        for (k, v) in &req.headers {
            headers.push((render::render(k, vars)?, render::render(v, vars)?));
        }
        let has_header =
            |h: &[(String, String)], n: &str| h.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));

        let body: Option<Vec<u8>> = if let Some(b) = &req.body {
            Some(render::render(b, vars)?.into_bytes())
        } else if let Some(form) = &req.form {
            if !has_header(&headers, "content-type") {
                headers.push((
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ));
            }
            let mut parts = Vec::new();
            for (k, v) in form {
                let v = render::render(v, vars)?;
                parts.push(format!(
                    "{}={}",
                    utf8_percent_encode(k, FORM_ENCODE),
                    utf8_percent_encode(&v, FORM_ENCODE)
                ));
            }
            Some(parts.join("&").into_bytes())
        } else if let Some(j) = &req.json {
            if !has_header(&headers, "content-type") {
                headers.push(("content-type".into(), "application/json".into()));
            }
            Some(serde_json::to_vec(&render::render_json(j, vars)?)?)
        } else {
            None
        };

        match &req.auth {
            None => {}
            Some(Auth::Basic { username, password }) => {
                use base64::Engine;
                let raw = format!(
                    "{}:{}",
                    render::render(username, vars)?,
                    render::render(password, vars)?
                );
                headers.push((
                    "authorization".into(),
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(raw)
                    ),
                ));
            }
            Some(Auth::Bearer { token }) => {
                headers.push((
                    "authorization".into(),
                    format!("Bearer {}", render::render(token, vars)?),
                ));
            }
            Some(Auth::AwsSigv4 {
                access_key,
                secret_key,
                session_token,
                region,
                service,
            }) => {
                let ak = render::render(access_key, vars)?;
                let sk = render::render(secret_key, vars)?;
                let st = session_token
                    .as_ref()
                    .map(|s| render::render(s, vars))
                    .transpose()?;
                let region = render::render(region, vars)?;
                let service = render::render(service, vars)?;
                let creds = sigv4::Credentials {
                    access_key: &ak,
                    secret_key: &sk,
                    session_token: st.as_deref(),
                    region: &region,
                    service: &service,
                };
                let extra = sigv4::sign(
                    &creds,
                    &method,
                    &url,
                    &headers,
                    body.as_deref().unwrap_or_default(),
                    chrono::Utc::now(),
                );
                headers.extend(extra);
            }
        }

        Ok(Prepared {
            method,
            url,
            headers,
            body,
            timeout: Duration::from_secs(
                req.timeout.or(self.opts.timeout).unwrap_or(DEFAULT_TIMEOUT),
            ),
        })
    }

    pub async fn send(&self, p: &Prepared) -> Result<Response> {
        let method = reqwest::Method::from_bytes(p.method.as_bytes())?;
        let mut rb = self
            .client
            .request(method, p.url.clone())
            .timeout(p.timeout);
        for (k, v) in &p.headers {
            rb = rb.header(k, v);
        }
        if let Some(b) = &p.body {
            rb = rb.body(b.clone());
        }
        let resp = rb
            .send()
            .await
            // reqwest embeds the full URL in its errors; paths can carry
            // credentials (e.g. `/bot<token>/getMe`), so drop it.
            .map_err(reqwest::Error::without_url)
            .with_context(|| format!("{} {}", p.method, redact_url(&p.url)))?;
        let status = resp.status().as_u16();
        let mut headers: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in resp.headers() {
            let v = String::from_utf8_lossy(v.as_bytes()).to_string();
            headers
                .entry(k.as_str().to_lowercase())
                .and_modify(|e| {
                    e.push_str(", ");
                    e.push_str(&v);
                })
                .or_insert(v);
        }
        let mut buf: Vec<u8> = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp.chunk().await? {
            let room = MAX_BODY.saturating_sub(buf.len());
            buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
            if buf.len() >= MAX_BODY {
                break;
            }
        }
        let body = String::from_utf8_lossy(&buf).to_string();
        let json = serde_json::from_str(&body).ok();
        Ok(Response {
            status,
            headers,
            body,
            json,
        })
    }

    pub async fn execute(&self, req: &Request, vars: &Vars) -> Result<Response> {
        let p = self.prepare(req, vars)?;
        self.send(&p).await
    }
}

/// Reduce a URL to `scheme://host[:port]/…` for logs and errors: paths and
/// query strings may embed credentials (e.g. `/bot<token>/getMe`).
pub fn redact_url(u: &reqwest::Url) -> String {
    let host = u.host_str().unwrap_or_default();
    match u.port() {
        Some(p) => format!("{}://{host}:{p}/…", u.scheme()),
        None => format!("{}://{host}/…", u.scheme()),
    }
}

/// Evaluate a matcher; on failure returns a short reason.
pub fn check(m: &Matcher, r: &Response) -> Result<(), String> {
    if !m.status.is_empty() && !m.status.contains(&r.status) {
        return Err(format!("status {} not in {:?}", r.status, m.status));
    }
    for s in &m.body_contains {
        if !r.body.contains(s.as_str()) {
            return Err(format!("body does not contain {s:?}"));
        }
    }
    for s in &m.body_not_contains {
        if r.body.contains(s.as_str()) {
            return Err(format!("body contains {s:?}"));
        }
    }
    for c in &m.json {
        let got = r
            .json
            .as_ref()
            .and_then(|j| jsonpath::get(j, &c.path))
            .filter(|v| !v.is_null());
        if let Some(exists) = c.exists
            && got.is_some() != exists
        {
            return Err(format!(
                "json `{}` {}",
                c.path,
                if exists { "missing" } else { "present" }
            ));
        }
        if let Some(want) = &c.equals
            && got.as_ref() != Some(want)
        {
            return Err(format!("json `{}` != {want}", c.path));
        }
    }
    for h in &m.headers {
        match r.headers.get(&h.name.to_lowercase()) {
            None => return Err(format!("header `{}` missing", h.name)),
            Some(v) => {
                if let Some(c) = &h.contains
                    && !v.contains(c.as_str())
                {
                    return Err(format!("header `{}` does not contain {c:?}", h.name));
                }
            }
        }
    }
    Ok(())
}

/// Run an extractor against a response.
pub fn extract(e: &Extract, r: &Response) -> Option<Value> {
    if let Some(path) = &e.json {
        return r
            .json
            .as_ref()
            .and_then(|j| jsonpath::get(j, path))
            .filter(|v| !v.is_null());
    }
    if let Some(h) = &e.header {
        return r.headers.get(&h.to_lowercase()).cloned().map(Value::String);
    }
    if let Some(re) = &e.regex {
        let re = Regex::new(re).ok()?;
        let pick = |caps: regex::Captures<'_>| -> Option<Value> {
            let m = caps
                .iter()
                .skip(1)
                .flatten()
                .find(|m| !m.as_str().is_empty())
                .or_else(|| caps.get(0))?;
            Some(Value::String(m.as_str().to_string()))
        };
        if e.all {
            let all: Vec<Value> = re.captures_iter(&r.body).filter_map(pick).collect();
            return (!all.is_empty()).then_some(Value::Array(all));
        }
        return pick(re.captures(&r.body)?);
    }
    None
}

/// Render an extracted value as a template variable.
pub fn value_to_var(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A short, single-line excerpt of a response body for diagnostics.
pub fn snippet(body: &str) -> String {
    let one: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > 160 {
        format!("{}…", one.chars().take(160).collect::<String>())
    } else {
        one
    }
}
