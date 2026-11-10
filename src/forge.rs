//! Repository discovery on GitHub, GitLab and Bitbucket, with rate-limit
//! aware HTTP.
//!
//! Rate limiting strategy:
//! * `Retry-After` (seconds) on 429/403/503 is always honoured.
//! * Primary limits: on 403/429 with `x-ratelimit-remaining: 0` (GitHub) or
//!   `ratelimit-remaining: 0` (GitLab), wait until the advertised reset.
//! * Proactive: when the remaining budget drops to the last couple of
//!   requests, pause until the reset instead of hitting the wall.
//! * 5xx and transport errors: exponential backoff with jitter.
//! * Waits longer than `max_wait` fail fast with the reset time, so a CI job
//!   never sleeps for an hour unnoticed.
//!
//! Pagination follows `Link: rel="next"` (GitHub, GitLab) or the `next`
//! field (Bitbucket), and only ever to the same origin as the API base, so
//! the token cannot be sent to another host.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    GitHubOrg(String),
    GitHubUser(String),
    GitLabGroup(String),
    BitbucketWorkspace(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoInfo {
    pub full_name: String,
    pub clone_url: String,
    pub archived: bool,
    pub fork: bool,
}

#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    pub token: Option<String>,
    /// Bitbucket app-password user (basic auth); otherwise bearer tokens.
    pub user: Option<String>,
    pub max_wait: Duration,
    pub retries: u32,
    pub allow_http: bool,
}

/// Which API a request goes to: decides the auth header and `Accept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    GitHub,
    /// `PRIVATE-TOKEN` header.
    GitLab,
    /// Basic auth with `user`, otherwise a bearer token.
    Bitbucket,
    /// Any other JSON API (Slack, Jira, Docker Hub, ...): basic auth with
    /// `user`, otherwise a bearer token.
    Other,
}

impl Client {
    pub fn new(token: Option<String>, user: Option<String>, max_wait: Duration) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("kubera/", env!("CARGO_PKG_VERSION")))
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(120))
                .build()?,
            token,
            user,
            max_wait,
            retries: 5,
            allow_http: false,
        })
    }

    fn authorize(&self, kind: Kind, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let Some(tok) = &self.token else { return rb };
        match (kind, &self.user) {
            (Kind::GitLab, _) => rb.header("PRIVATE-TOKEN", tok),
            (Kind::Bitbucket | Kind::Other, Some(u)) => rb.basic_auth(u, Some(tok)),
            _ => rb.bearer_auth(tok),
        }
    }

    /// Send an authorized GET, retrying transport errors, 5xx answers and
    /// rate limits. Redirects are not followed; any other response is
    /// returned whatever its status.
    async fn send(
        &self,
        kind: Kind,
        url: &reqwest::Url,
        accept: Option<&str>,
    ) -> Result<reqwest::Response> {
        if url.scheme() != "https" && !(self.allow_http && url.scheme() == "http") {
            bail!(
                "refusing non-https API url {}",
                crate::http::redact_url(url)
            );
        }
        let mut attempt = 0u32;
        loop {
            let mut rb = self.http.get(url.clone());
            rb = match (kind, accept) {
                (_, Some(a)) => rb.header("Accept", a),
                (Kind::GitHub, None) => rb.header("Accept", "application/vnd.github+json"),
                (_, None) => rb.header("Accept", "application/json"),
            };
            if kind == Kind::GitHub {
                rb = rb.header("X-GitHub-Api-Version", "2022-11-28");
            }
            let res = self
                .authorize(kind, rb)
                .send()
                .await
                .map_err(reqwest::Error::without_url);
            let resp = match res {
                Ok(r) => r,
                Err(e) if attempt < self.retries => {
                    attempt += 1;
                    let d = backoff(attempt);
                    eprintln!("api: {} ({e}); retrying in {}s", host(url), d.as_secs());
                    tokio::time::sleep(d).await;
                    continue;
                }
                Err(e) => return Err(e).context(format!("GET {}", host(url))),
            };
            let status = resp.status().as_u16();
            if let Some(wait) = rate_limit_wait(status, resp.headers()) {
                if attempt >= self.retries {
                    bail!("{}: still rate limited after {attempt} retries", host(url));
                }
                if wait > self.max_wait {
                    bail!(
                        "{}: rate limited for {}s (more than --max-rate-wait {}s); \
                         use a token or retry later",
                        host(url),
                        wait.as_secs(),
                        self.max_wait.as_secs()
                    );
                }
                attempt += 1;
                eprintln!(
                    "api: rate limited by {}; waiting {}s",
                    host(url),
                    wait.as_secs()
                );
                tokio::time::sleep(wait).await;
                continue;
            }
            if (500..600).contains(&status) && attempt < self.retries {
                attempt += 1;
                let d = backoff(attempt);
                eprintln!(
                    "api: {} answered {status}; retrying in {}s",
                    host(url),
                    d.as_secs()
                );
                tokio::time::sleep(d).await;
                continue;
            }
            return Ok(resp);
        }
    }

    /// GET with retries and rate-limit handling. Returns the JSON body and
    /// response headers.
    async fn get(
        &self,
        kind: Kind,
        url: &reqwest::Url,
    ) -> Result<(Value, reqwest::header::HeaderMap)> {
        let resp = self.send(kind, url, None).await?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = read_capped(resp, MAX_JSON).await?;
        let body = String::from_utf8_lossy(&body);
        if !(200..300).contains(&status) {
            bail!(
                "{} answered HTTP {status}: {}",
                host(url),
                crate::http::snippet(&body)
            );
        }
        // Proactive slow-down before the budget is exhausted.
        if let Some(wait) = near_limit_wait(&headers).filter(|w| *w <= self.max_wait) {
            eprintln!("api: rate limit nearly used; pausing {}s", wait.as_secs());
            tokio::time::sleep(wait).await;
        }
        let json = serde_json::from_str(&body).context("API returned invalid JSON")?;
        Ok((json, headers))
    }

    /// One JSON document (an object, or a single page).
    pub async fn get_json(&self, kind: Kind, url: &str) -> Result<Value> {
        let u = reqwest::Url::parse(url).context("invalid API url")?;
        Ok(self.get(kind, &u).await?.0)
    }

    /// List the repositories of an org / user / group / workspace.
    pub async fn list(&self, source: &Source, api: Option<&str>) -> Result<Vec<RepoInfo>> {
        let (kind, first) = match source {
            Source::GitHubOrg(o) => (
                Kind::GitHub,
                format!(
                    "{}/orgs/{}/repos?per_page=100&type=all",
                    api.unwrap_or("https://api.github.com"),
                    enc(o)
                ),
            ),
            Source::GitHubUser(u) => (
                Kind::GitHub,
                format!(
                    "{}/users/{}/repos?per_page=100&type=owner",
                    api.unwrap_or("https://api.github.com"),
                    enc(u)
                ),
            ),
            Source::GitLabGroup(g) => (
                Kind::GitLab,
                format!(
                    "{}/groups/{}/projects?per_page=100&include_subgroups=true&order_by=id&sort=asc",
                    api.unwrap_or("https://gitlab.com/api/v4"),
                    enc(g)
                ),
            ),
            Source::BitbucketWorkspace(w) => (
                Kind::Bitbucket,
                format!(
                    "{}/repositories/{}?pagelen=100",
                    api.unwrap_or("https://api.bitbucket.org/2.0"),
                    enc(w)
                ),
            ),
        };
        let base = reqwest::Url::parse(&first).context("invalid API url")?;
        let mut next = Some(base.clone());
        let mut out = Vec::new();
        let mut pages = 0;
        while let Some(url) = next.take() {
            pages += 1;
            if pages > 1000 {
                bail!("too many pages from {}", host(&base));
            }
            let (json, headers) = self.get(kind, &url).await?;
            let items: Vec<Value> = match kind {
                Kind::Bitbucket => json["values"].as_array().cloned().unwrap_or_default(),
                _ => json.as_array().cloned().unwrap_or_default(),
            };
            for it in items {
                if let Some(r) = repo_info(kind, &it) {
                    out.push(r);
                }
            }
            let candidate = match kind {
                Kind::Bitbucket => json["next"].as_str().map(str::to_string),
                _ => link_next(&headers),
            };
            next = match candidate {
                Some(n) => {
                    let u = reqwest::Url::parse(&n).context("invalid pagination url")?;
                    if u.origin() != base.origin() {
                        bail!(
                            "refusing to follow pagination to another host: {}",
                            host(&u)
                        );
                    }
                    Some(u)
                }
                None => None,
            };
        }
        Ok(out)
    }
}

impl Client {
    /// One GitHub API call (`GET`, `POST`, ...) with a JSON body. Rate
    /// limits are waited out for every method (the request was rejected,
    /// not processed); transport errors and 5xx are retried for `GET` only,
    /// so a `POST` is never sent twice. Returns the status and the JSON body
    /// (`Null` if empty or not JSON) without failing on 4xx/5xx.
    pub async fn github_call(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value)> {
        let url = reqwest::Url::parse(url).context("invalid API url")?;
        if url.scheme() != "https" && !(self.allow_http && url.scheme() == "http") {
            bail!("refusing non-https API url {}", host(&url));
        }
        let idempotent = method == reqwest::Method::GET;
        let mut attempt = 0u32;
        loop {
            let mut rb = self
                .http
                .request(method.clone(), url.clone())
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
            if let Some(b) = body {
                rb = rb.json(b);
            }
            let resp = match self.authorize(Kind::GitHub, rb).send().await {
                Ok(r) => r,
                Err(e) if idempotent && attempt < self.retries => {
                    attempt += 1;
                    tokio::time::sleep(backoff(attempt)).await;
                    let _ = e;
                    continue;
                }
                Err(e) => {
                    return Err(e.without_url()).context(format!("{method} {}", host(&url)));
                }
            };
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            if let Some(wait) = rate_limit_wait(status, &headers) {
                if attempt >= self.retries {
                    bail!("{}: still rate limited after {attempt} retries", host(&url));
                }
                if wait > self.max_wait {
                    bail!(
                        "{}: rate limited for {}s (more than the {}s limit); retry later",
                        host(&url),
                        wait.as_secs(),
                        self.max_wait.as_secs()
                    );
                }
                attempt += 1;
                eprintln!(
                    "api: rate limited by {}; waiting {}s",
                    host(&url),
                    wait.as_secs()
                );
                tokio::time::sleep(wait).await;
                continue;
            }
            if idempotent && (500..600).contains(&status) && attempt < self.retries {
                attempt += 1;
                tokio::time::sleep(backoff(attempt)).await;
                continue;
            }
            let text = resp.text().await.unwrap_or_default();
            return Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)));
        }
    }

    /// Every item of a paginated GitHub list endpoint (JSON array), up to
    /// `max` items, following `Link: rel="next"` on the same origin only.
    pub async fn github_list(&self, url: &str, max: usize) -> Result<Vec<Value>> {
        self.paginate(Kind::GitHub, url, max).await
    }

    /// Every item of a paginated list endpoint, up to `max` items. A page is
    /// a JSON array or an object wrapping one (`{"values": [...]}`); the next
    /// page comes from `Link: rel="next"` or a `next` / `_links.next` URL in
    /// the body (Bitbucket, Docker Hub, Confluence; absolute or relative),
    /// and is only followed on the same origin.
    pub async fn paginate(&self, kind: Kind, url: &str, max: usize) -> Result<Vec<Value>> {
        let base = reqwest::Url::parse(url).context("invalid API url")?;
        let mut next = Some(base.clone());
        let mut out = Vec::new();
        let mut pages = 0;
        while let Some(u) = next.take() {
            pages += 1;
            if pages > 10_000 {
                bail!("too many pages from {}", host(&base));
            }
            let (json, headers) = self.get(kind, &u).await?;
            // Some endpoints wrap the array (`{"workflow_runs": [...]}`).
            let items = match &json {
                Value::Array(a) => a.clone(),
                Value::Object(o) => ["values", "results", "items"]
                    .iter()
                    .find_map(|k| o.get(*k).and_then(Value::as_array).cloned())
                    .or_else(|| o.values().find_map(|v| v.as_array().cloned()))
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            let empty = items.is_empty();
            out.extend(items);
            if out.len() >= max {
                out.truncate(max);
                break;
            }
            if empty {
                break;
            }
            let candidate = link_next(&headers).or_else(|| {
                json.get("next")
                    .or_else(|| json.pointer("/_links/next"))
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
            });
            next = match candidate {
                Some(n) => Some(same_origin(&base, &n)?),
                None => None,
            };
        }
        Ok(out)
    }

    /// Download a resource that may redirect to pre-signed storage (GitHub
    /// Actions logs, CI traces, LFS files): the token goes to the API only,
    /// never to the redirect target, which must be https. At most `max`
    /// bytes; `None` when it is larger, or gone (404/410).
    pub async fn download(&self, kind: Kind, url: &str, max: u64) -> Result<Option<Vec<u8>>> {
        let u = reqwest::Url::parse(url).context("invalid API url")?;
        let accept = (kind != Kind::GitHub).then_some("*/*");
        let resp = self.send(kind, &u, accept).await?;
        let status = resp.status().as_u16();
        let resp = if (300..400).contains(&status) {
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .context("redirect without a location")?;
            let to = u.join(loc).context("invalid redirect")?;
            if to.scheme() != "https" && !(self.allow_http && to.scheme() == "http") {
                bail!("refusing non-https download from {}", host(&to));
            }
            // Pre-signed URL: no Authorization header.
            self.http
                .get(to.clone())
                .send()
                .await
                .map_err(reqwest::Error::without_url)
                .with_context(|| format!("GET {}", host(&to)))?
        } else {
            resp
        };
        match resp.status().as_u16() {
            200..=299 => {}
            // Expired or deleted logs, no access: nothing to scan.
            404 | 410 => return Ok(None),
            s => bail!("{} answered HTTP {s}", host(&u)),
        }
        if resp.content_length().is_some_and(|n| n > max) {
            return Ok(None);
        }
        let buf = read_capped(resp, max.saturating_add(1)).await?;
        Ok((buf.len() as u64 <= max).then_some(buf))
    }

    /// [`Client::download`] from the GitHub API.
    pub async fn github_download(&self, url: &str, max: u64) -> Result<Option<Vec<u8>>> {
        self.download(Kind::GitHub, url, max).await
    }
}

/// Largest JSON response read.
const MAX_JSON: u64 = 64 * 1024 * 1024;

/// Read at most `max` bytes of a body.
async fn read_capped(mut resp: reqwest::Response, max: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(reqwest::Error::without_url)? {
        let room = usize::try_from(max)
            .unwrap_or(usize::MAX)
            .saturating_sub(buf.len());
        buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if buf.len() as u64 >= max {
            break;
        }
    }
    Ok(buf)
}

/// Resolve a pagination URL (absolute or relative to `base`) and refuse it
/// unless it stays on `base`'s origin, so a token is never sent elsewhere.
pub fn same_origin(base: &reqwest::Url, next: &str) -> Result<reqwest::Url> {
    let u = base.join(next).context("invalid pagination url")?;
    if u.origin() != base.origin() {
        bail!(
            "refusing to follow pagination to another host: {}",
            host(&u)
        );
    }
    Ok(u)
}

/// Percent-encode one URL path or query component (unreserved characters
/// `-._~` are kept).
pub fn enc(s: &str) -> String {
    const COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    // `.` and `..` would be collapsed by URL normalisation.
    if s.chars().all(|c| c == '.') {
        return s.replace('.', "%2E");
    }
    percent_encoding::utf8_percent_encode(s, COMPONENT).to_string()
}

fn host(u: &reqwest::Url) -> String {
    u.host_str().unwrap_or_default().to_string()
}

fn repo_info(kind: Kind, v: &Value) -> Option<RepoInfo> {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str).map(str::to_string);
    let b = |p: &str| v.pointer(p).and_then(Value::as_bool).unwrap_or(false);
    Some(match kind {
        Kind::GitHub | Kind::Other => RepoInfo {
            full_name: s("/full_name")?,
            clone_url: s("/clone_url")?,
            archived: b("/archived"),
            fork: b("/fork"),
        },
        Kind::GitLab => RepoInfo {
            full_name: s("/path_with_namespace")?,
            clone_url: s("/http_url_to_repo")?,
            archived: b("/archived"),
            fork: v.get("forked_from_project").is_some_and(|f| !f.is_null()),
        },
        Kind::Bitbucket => RepoInfo {
            full_name: s("/full_name")?,
            clone_url: v
                .pointer("/links/clone")?
                .as_array()?
                .iter()
                .find(|l| l["name"] == "https")?["href"]
                .as_str()?
                // Bitbucket embeds the username; credentials come from env.
                .split_once('@')
                .map(|(_, h)| format!("https://{h}"))
                .or_else(|| s("/links/html/href"))?,
            archived: false,
            fork: v.get("parent").is_some_and(|p| !p.is_null()),
        },
    })
}

/// `Link: <url>; rel="next"`.
pub fn link_next(h: &reqwest::header::HeaderMap) -> Option<String> {
    let link = h.get("link")?.to_str().ok()?;
    link.split(',').find_map(|part| {
        let (url, rest) = part.split_once(';')?;
        rest.contains("rel=\"next\"").then(|| {
            url.trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string()
        })
    })
}

fn header_u64(h: &reqwest::header::HeaderMap, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|n| {
        h.get(*n)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
    })
}

fn until_epoch(reset: u64) -> Duration {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    Duration::from_secs(reset.saturating_sub(now) + 1)
}

/// How long to wait before retrying, if this response is a rate limit.
pub fn rate_limit_wait(status: u16, h: &reqwest::header::HeaderMap) -> Option<Duration> {
    if !matches!(status, 403 | 429 | 503) {
        return None;
    }
    if let Some(s) = header_u64(h, &["retry-after"]) {
        return Some(Duration::from_secs(s.max(1)));
    }
    let remaining = header_u64(h, &["x-ratelimit-remaining", "ratelimit-remaining"]);
    if remaining == Some(0) || status == 429 {
        if let Some(reset) = header_u64(h, &["x-ratelimit-reset", "ratelimit-reset"]) {
            return Some(until_epoch(reset));
        }
        return Some(Duration::from_secs(60));
    }
    None
}

fn near_limit_wait(h: &reqwest::header::HeaderMap) -> Option<Duration> {
    let remaining = header_u64(h, &["x-ratelimit-remaining", "ratelimit-remaining"])?;
    if remaining > 1 {
        return None;
    }
    let reset = header_u64(h, &["x-ratelimit-reset", "ratelimit-reset"])?;
    Some(until_epoch(reset))
}

fn backoff(attempt: u32) -> Duration {
    let base = 2u64.saturating_pow(attempt.min(6));
    let jitter = (chrono::Utc::now().timestamp_subsec_millis() % 1000) as u64;
    Duration::from_millis(base * 1000 + jitter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn h(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn rate_limit_decisions() {
        assert_eq!(
            rate_limit_wait(429, &h(&[("retry-after", "7")])),
            Some(Duration::from_secs(7))
        );
        let reset = (chrono::Utc::now().timestamp() + 30).to_string();
        let w = rate_limit_wait(
            403,
            &h(&[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset", &reset),
            ]),
        )
        .unwrap();
        assert!(w.as_secs() >= 29 && w.as_secs() <= 32, "{w:?}");
        // A plain 403 (permission) is not a rate limit.
        assert_eq!(
            rate_limit_wait(403, &h(&[("x-ratelimit-remaining", "12")])),
            None
        );
        assert_eq!(rate_limit_wait(200, &h(&[("retry-after", "5")])), None);
        assert!(
            near_limit_wait(&h(&[
                ("ratelimit-remaining", "1"),
                ("ratelimit-reset", &reset)
            ]))
            .is_some()
        );
        assert!(
            near_limit_wait(&h(&[
                ("ratelimit-remaining", "50"),
                ("ratelimit-reset", &reset)
            ]))
            .is_none()
        );
    }

    #[test]
    fn link_header() {
        let m = h(&[(
            "link",
            r#"<https://api.github.com/orgs/x/repos?page=2>; rel="next", <https://api.github.com/orgs/x/repos?page=5>; rel="last""#,
        )]);
        assert_eq!(
            link_next(&m).unwrap(),
            "https://api.github.com/orgs/x/repos?page=2"
        );
        assert!(link_next(&h(&[("link", r#"<https://a/?page=1>; rel="prev""#)])).is_none());
    }

    #[test]
    fn bitbucket_clone_url_drops_embedded_user() {
        let v = serde_json::json!({
            "full_name": "ws/repo",
            "links": {"clone": [
                {"name": "https", "href": "https://alice@bitbucket.org/ws/repo.git"},
                {"name": "ssh", "href": "git@bitbucket.org:ws/repo.git"}
            ]}
        });
        let r = repo_info(Kind::Bitbucket, &v).unwrap();
        assert_eq!(r.clone_url, "https://bitbucket.org/ws/repo.git");
    }
}
