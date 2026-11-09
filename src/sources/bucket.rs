//! Cloud object storage: Amazon S3 (and S3-compatible stores such as MinIO
//! or Cloudflare R2) and Google Cloud Storage.
//!
//! Objects are listed, filtered by path excludes and size *before* they are
//! downloaded, fetched concurrently, and turned into chunks with the same
//! text / archive logic as files on disk.
//!
//! Credentials: S3 requests are SigV4-signed with the standard
//! `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`
//! variables (unsigned with `anonymous`, for public buckets); GCS takes an
//! OAuth access token (e.g. `gcloud auth print-access-token`). They are only
//! ever sent to the storage endpoint, over HTTPS, without following
//! redirects.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use regex::Regex;
use sha2::{Digest, Sha256};

use super::Chunk;
use crate::config::Filter;
use crate::finding::{Location, SourceKind};
use crate::http::sigv4;

/// URL path / query component encoding that keeps unreserved characters.
const COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, COMPONENT).to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Store {
    S3,
    Gcs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketRef {
    pub store: Store,
    pub bucket: String,
    pub prefix: String,
}

/// `s3://bucket/prefix` or `gs://bucket/prefix`.
pub fn parse(url: &str) -> Result<BucketRef> {
    let (store, rest) = if let Some(r) = url.strip_prefix("s3://") {
        (Store::S3, r)
    } else if let Some(r) = url.strip_prefix("gs://") {
        (Store::Gcs, r)
    } else {
        bail!("expected s3://bucket[/prefix] or gs://bucket[/prefix], got `{url}`");
    };
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    let ok = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_');
    if bucket.len() < 3 || bucket.len() > 222 || !bucket.chars().all(ok) {
        bail!("`{bucket}` is not a valid bucket name");
    }
    Ok(BucketRef {
        store,
        bucket: bucket.to_string(),
        prefix: prefix.to_string(),
    })
}

#[derive(Clone)]
pub struct AwsCreds {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl AwsCreds {
    /// From the standard environment variables, if set.
    pub fn from_env() -> Option<Self> {
        Some(Self {
            access_key: std::env::var("AWS_ACCESS_KEY_ID").ok()?,
            secret_key: std::env::var("AWS_SECRET_ACCESS_KEY").ok()?,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
        })
    }
}

pub struct Options {
    pub aws: Option<AwsCreds>,
    pub gcs_token: Option<String>,
    /// S3 region (detected from the bucket when `None`).
    pub region: Option<String>,
    /// S3-compatible endpoint, or the GCS API base (tests, emulators).
    pub endpoint: Option<String>,
    pub max_objects: usize,
    pub max_file_size: u64,
    pub concurrency: usize,
    pub allow_http: bool,
}

struct Object {
    key: String,
    size: u64,
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("kubera/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()?)
}

fn check_scheme(u: &reqwest::Url, allow_http: bool) -> Result<()> {
    match u.scheme() {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        s => bail!("refusing `{s}` endpoint; storage must be reached over https"),
    }
}

/// Decode the five XML entities and numeric references.
fn xml_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(end) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let ent = &tail[1..end];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") => u32::from_str_radix(&ent[2..], 16)
                .ok()
                .and_then(char::from_u32),
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

struct S3 {
    http: reqwest::Client,
    base: String,
    bucket: String,
    region: String,
    creds: Option<AwsCreds>,
}

impl S3 {
    fn url(&self, key: &str, query: &[(&str, &str)]) -> Result<reqwest::Url> {
        // Encode each segment; `.` and `..` would otherwise be collapsed by
        // URL normalisation (wrong object, broken signature).
        let path = key
            .split('/')
            .map(|seg| match seg {
                "." => "%2E".to_string(),
                ".." => "%2E%2E".to_string(),
                s => sigv4::aws_encode(s),
            })
            .collect::<Vec<_>>()
            .join("/");
        let raw = if key.is_empty() {
            format!("{}/{}", self.base, self.bucket)
        } else {
            format!("{}/{}/{path}", self.base, self.bucket)
        };
        let mut u = reqwest::Url::parse(&raw)?;
        if !query.is_empty() {
            let q = query
                .iter()
                .map(|(k, v)| format!("{}={}", sigv4::aws_encode(k), sigv4::aws_encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            u.set_query(Some(&q));
        }
        Ok(u)
    }

    async fn get(&self, u: reqwest::Url) -> Result<reqwest::Response> {
        let empty = hex::encode(Sha256::digest(b""));
        let mut headers = vec![("x-amz-content-sha256".to_string(), empty)];
        if let Some(c) = &self.creds {
            let creds = sigv4::Credentials {
                access_key: &c.access_key,
                secret_key: &c.secret_key,
                session_token: c.session_token.as_deref(),
                region: &self.region,
                service: "s3",
            };
            let extra = sigv4::sign(&creds, "GET", &u, &headers, b"", chrono::Utc::now());
            headers.extend(extra);
        }
        let mut rb = self.http.get(u.clone());
        for (k, v) in &headers {
            rb = rb.header(k, v);
        }
        rb.send()
            .await
            .map_err(reqwest::Error::without_url)
            .with_context(|| format!("GET {}", crate::http::redact_url(&u)))
    }

    async fn list(&self, prefix: &str, max: usize) -> Result<Vec<Object>> {
        let contents = Regex::new(r"(?s)<Contents>(.*?)</Contents>")?;
        let key = Regex::new(r"(?s)<Key>(.*?)</Key>")?;
        let size = Regex::new(r"<Size>(\d+)</Size>")?;
        let next = Regex::new(r"<NextContinuationToken>(.*?)</NextContinuationToken>")?;
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut q = vec![("list-type", "2"), ("max-keys", "1000"), ("prefix", prefix)];
            if let Some(t) = &token {
                q.push(("continuation-token", t));
            }
            let resp = self.get(self.url("", &q)?).await?;
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status != 200 {
                bail!(
                    "listing s3://{} failed: HTTP {status} {}",
                    self.bucket,
                    s3_error(&body)
                );
            }
            for c in contents.captures_iter(&body) {
                let block = &c[1];
                let (Some(k), Some(s)) = (key.captures(block), size.captures(block)) else {
                    continue;
                };
                out.push(Object {
                    key: xml_unescape(&k[1]),
                    size: s[1].parse().unwrap_or(u64::MAX),
                });
            }
            token = next.captures(&body).map(|c| xml_unescape(&c[1]));
            if token.is_none() || out.len() >= max {
                break;
            }
        }
        out.truncate(max);
        Ok(out)
    }
}

fn s3_error(body: &str) -> String {
    Regex::new(r"<Code>(.*?)</Code>")
        .ok()
        .and_then(|r| r.captures(body).map(|c| c[1].to_string()))
        .unwrap_or_default()
}

/// The bucket's region from `x-amz-bucket-region` (answered even to
/// anonymous requests).
async fn detect_region(http: &reqwest::Client, bucket: &str) -> Option<String> {
    let resp = http
        .head(format!("https://s3.amazonaws.com/{bucket}"))
        .send()
        .await
        .ok()?;
    resp.headers()
        .get("x-amz-bucket-region")?
        .to_str()
        .ok()
        .map(str::to_string)
}

/// Turn one downloaded object into chunks (text or archive entries).
fn object_chunks(data: Vec<u8>, location: Location, max_size: u64, filter: &Filter) -> Vec<Chunk> {
    use super::archive;
    if let Some(kind) = archive::kind(&data) {
        let mut out = Vec::new();
        let res = archive::walk(
            kind,
            std::io::Cursor::new(data),
            archive::Limits::new(max_size),
            &mut |e| {
                if !filter.path_excluded(std::path::Path::new(&e.path)) {
                    out.push(Chunk {
                        text: e.text,
                        location: Location {
                            entry: Some(e.path),
                            ..location.clone()
                        },
                        line_map: None,
                    });
                }
            },
        );
        if let Err(e) = res {
            eprintln!("warning: {}: {e:#}", location.path.as_deref().unwrap_or(""));
        }
        return out;
    }
    if data.len() as u64 > max_size || super::is_binary(&data) {
        return Vec::new();
    }
    vec![Chunk {
        text: String::from_utf8_lossy(&data).into_owned(),
        location,
        line_map: None,
    }]
}

fn wanted(o: &Object, max_size: u64, filter: &Filter) -> bool {
    let limit = if super::archive::archive_name(&o.key) {
        super::archive::DEFAULT_MAX_ARCHIVE_SIZE
    } else {
        max_size
    };
    o.size > 0
        && o.size <= limit
        && !o.key.ends_with('/')
        && !filter.path_excluded(std::path::Path::new(&o.key))
}

/// Scan a bucket: chunks go to `sink` as objects arrive. Returns the number
/// of objects downloaded.
pub async fn scan(
    b: &BucketRef,
    o: &Options,
    filter: &Filter,
    sink: &mut (dyn FnMut(Chunk) + Send),
) -> Result<usize> {
    let http = client()?;
    match b.store {
        Store::S3 => {
            let region = match (&o.region, &o.endpoint) {
                (Some(r), _) => r.clone(),
                (None, Some(_)) => "us-east-1".into(),
                (None, None) => detect_region(&http, &b.bucket)
                    .await
                    .unwrap_or_else(|| "us-east-1".into()),
            };
            let base = match &o.endpoint {
                Some(e) => e.trim_end_matches('/').to_string(),
                None => format!("https://s3.{region}.amazonaws.com"),
            };
            check_scheme(&reqwest::Url::parse(&base)?, o.allow_http)?;
            let s3 = S3 {
                http,
                base,
                bucket: b.bucket.clone(),
                region,
                creds: o.aws.clone(),
            };
            let objects: Vec<Object> = s3
                .list(&b.prefix, o.max_objects)
                .await?
                .into_iter()
                .filter(|x| wanted(x, o.max_file_size, filter))
                .collect();
            let mut stream = futures::stream::iter(objects.into_iter().map(|obj| {
                let s3 = &s3;
                async move {
                    let resp = s3.get(s3.url(&obj.key, &[])?).await?;
                    if resp.status().as_u16() != 200 {
                        bail!("{}: HTTP {}", obj.key, resp.status().as_u16());
                    }
                    Ok((obj.key, resp.bytes().await?.to_vec()))
                }
            }))
            .buffer_unordered(o.concurrency.max(1));
            let mut n = 0;
            while let Some(r) = stream.next().await {
                match r {
                    Ok((key, data)) => {
                        n += 1;
                        let loc = location(b, &key);
                        for c in object_chunks(data, loc, o.max_file_size, filter) {
                            sink(c);
                        }
                    }
                    Err(e) => eprintln!("warning: s3://{}/{e:#}", b.bucket),
                }
            }
            Ok(n)
        }
        Store::Gcs => {
            let base = o
                .endpoint
                .clone()
                .unwrap_or_else(|| "https://storage.googleapis.com".into());
            let base = base.trim_end_matches('/').to_string();
            check_scheme(&reqwest::Url::parse(&base)?, o.allow_http)?;
            let auth = |rb: reqwest::RequestBuilder| match &o.gcs_token {
                Some(t) => rb.bearer_auth(t),
                None => rb,
            };
            let mut objects = Vec::new();
            let mut page: Option<String> = None;
            loop {
                let mut url = format!(
                    "{base}/storage/v1/b/{}/o?prefix={}&maxResults=1000&fields=items(name,size),nextPageToken",
                    enc(&b.bucket),
                    enc(&b.prefix)
                );
                if let Some(p) = &page {
                    url.push_str(&format!("&pageToken={}", enc(p)));
                }
                let resp = auth(http.get(&url))
                    .send()
                    .await
                    .map_err(reqwest::Error::without_url)
                    .context("listing GCS objects")?;
                let status = resp.status().as_u16();
                let v: serde_json::Value = resp.json().await.unwrap_or_default();
                if status != 200 {
                    bail!(
                        "listing gs://{} failed: HTTP {status} {}",
                        b.bucket,
                        v.pointer("/error/message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("")
                    );
                }
                for it in v["items"].as_array().into_iter().flatten() {
                    let (Some(name), Some(size)) = (it["name"].as_str(), it["size"].as_str())
                    else {
                        continue;
                    };
                    objects.push(Object {
                        key: name.to_string(),
                        size: size.parse().unwrap_or(u64::MAX),
                    });
                }
                page = v["nextPageToken"].as_str().map(str::to_string);
                if page.is_none() || objects.len() >= o.max_objects {
                    break;
                }
            }
            objects.truncate(o.max_objects);
            objects.retain(|x| wanted(x, o.max_file_size, filter));
            let mut stream = futures::stream::iter(objects.into_iter().map(|obj| {
                let (http, base) = (&http, &base);
                async move {
                    let url = format!(
                        "{base}/storage/v1/b/{}/o/{}?alt=media",
                        enc(&b.bucket),
                        enc(&obj.key)
                    );
                    let resp = auth(http.get(&url))
                        .send()
                        .await
                        .map_err(reqwest::Error::without_url)?;
                    if resp.status().as_u16() != 200 {
                        bail!("{}: HTTP {}", obj.key, resp.status().as_u16());
                    }
                    Ok((obj.key, resp.bytes().await?.to_vec()))
                }
            }))
            .buffer_unordered(o.concurrency.max(1));
            let mut n = 0;
            while let Some(r) = stream.next().await {
                match r {
                    Ok((key, data)) => {
                        n += 1;
                        for c in object_chunks(data, location(b, &key), o.max_file_size, filter) {
                            sink(c);
                        }
                    }
                    Err(e) => eprintln!("warning: gs://{}/{e:#}", b.bucket),
                }
            }
            Ok(n)
        }
    }
}

fn location(b: &BucketRef, key: &str) -> Location {
    let (scheme, link) = match b.store {
        Store::S3 => (
            "s3",
            format!(
                "https://s3.console.aws.amazon.com/s3/object/{}?prefix={}",
                enc(&b.bucket),
                enc(key)
            ),
        ),
        Store::Gcs => (
            "gs",
            format!(
                "https://console.cloud.google.com/storage/browser/_details/{}/{}",
                enc(&b.bucket),
                key.split('/').map(enc).collect::<Vec<_>>().join("/")
            ),
        ),
    };
    Location {
        source: SourceKind::Bucket,
        repository: Some(format!("{scheme}://{}", b.bucket)),
        path: Some(key.to_string()),
        link: Some(link),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_urls() {
        assert_eq!(
            parse("s3://my-bucket/logs/2026/").unwrap(),
            BucketRef {
                store: Store::S3,
                bucket: "my-bucket".into(),
                prefix: "logs/2026/".into()
            }
        );
        assert_eq!(parse("gs://b.example.com").unwrap().prefix, "");
        assert!(parse("s3://UPPER").is_err());
        assert!(parse("s3://ab").is_err());
        assert!(parse("https://x").is_err());
    }

    #[test]
    fn xml_entities() {
        assert_eq!(
            xml_unescape("a&amp;b&lt;&#x41;&#66;&bogus;"),
            "a&b<AB&bogus;"
        );
    }
}
