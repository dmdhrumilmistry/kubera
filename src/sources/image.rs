//! Container image source: registries (no daemon needed), `docker save`
//! tarballs, OCI image layouts, and the local Docker daemon.
//!
//! Every layer is scanned, so a secret added in one layer and deleted in a
//! later one is still found (it ships in the image). The image config is
//! scanned too: `ENV`, labels and the build history (`created_by`), where
//! build-argument secrets often end up.
//!
//! Safety:
//! * Registry blobs are verified against their sha256 digest **before**
//!   they are parsed, and capped by `max_layer_size`.
//! * Archives are streamed, never unpacked to disk, so path traversal and
//!   symlink tricks inside a hostile image cannot write anywhere.
//! * Registry and token-realm URLs must be https (unless the test-only
//!   `allow_http` is set); credentials are never sent elsewhere.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{Chunk, is_binary};
use crate::finding::{Location, SourceKind};

pub const DEFAULT_MAX_LAYER_SIZE: u64 = 4 * 1024 * 1024 * 1024;
const MAX_JSON: u64 = 8 * 1024 * 1024;

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
application/vnd.docker.distribution.manifest.list.v2+json, \
application/vnd.oci.image.manifest.v1+json, \
application/vnd.docker.distribution.manifest.v2+json";

/// `[registry/]repository[:tag][@digest]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Host (and port) of the registry API.
    pub registry: String,
    pub repository: String,
    /// Tag or `sha256:` digest.
    pub reference: String,
}

impl ImageRef {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() || s.starts_with('-') || s.contains(char::is_whitespace) {
            bail!("invalid image reference `{s}`");
        }
        let (name, digest) = match s.split_once('@') {
            Some((n, d)) => (n, Some(d.to_string())),
            None => (s, None),
        };
        let (first, rest) = match name.split_once('/') {
            Some((f, r)) if f.contains('.') || f.contains(':') || f == "localhost" => {
                (Some(f), r.to_string())
            }
            _ => (None, name.to_string()),
        };
        let (repo, tag) = match rest.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r.to_string(), Some(t.to_string())),
            _ => (rest.clone(), None),
        };
        let registry = match first {
            None | Some("docker.io") | Some("index.docker.io") => {
                "registry-1.docker.io".to_string()
            }
            Some(h) => h.to_string(),
        };
        let repository = if registry == "registry-1.docker.io" && !repo.contains('/') {
            format!("library/{repo}")
        } else {
            repo
        };
        if repository.is_empty()
            || !repository
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-/".contains(c))
        {
            bail!("invalid image repository in `{s}`");
        }
        let reference = digest.or(tag).unwrap_or_else(|| "latest".to_string());
        Ok(Self {
            registry,
            repository,
            reference,
        })
    }

    pub fn display(&self) -> String {
        let sep = if self.reference.starts_with("sha256:") {
            '@'
        } else {
            ':'
        };
        let reg = if self.registry == "registry-1.docker.io" {
            "docker.io".to_string()
        } else {
            self.registry.clone()
        };
        format!("{reg}/{}{sep}{}", self.repository, self.reference)
    }
}

/// A layer ready to be scanned.
#[derive(Debug)]
pub enum Layer {
    /// Verified blob downloaded from a registry.
    File { digest: String, path: PathBuf },
    /// Entry inside an archive (streamed in a second pass).
    InArchive { digest: String, entry: String },
}

/// An image whose config and layers can be scanned locally.
#[derive(Debug)]
pub struct Image {
    pub display: String,
    pub config: Option<Vec<u8>>,
    pub layers: Vec<Layer>,
    pub archive: Option<PathBuf>,
    _tmp: Option<tempfile::TempDir>,
}

// ----- registry --------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PullOptions {
    /// `os/arch[/variant]`, e.g. `linux/amd64`.
    pub platform: String,
    pub user: Option<String>,
    pub token: Option<String>,
    pub allow_http: bool,
    pub max_layer_size: u64,
}

impl Default for PullOptions {
    fn default() -> Self {
        Self {
            platform: "linux/amd64".into(),
            user: None,
            token: None,
            allow_http: false,
            max_layer_size: DEFAULT_MAX_LAYER_SIZE,
        }
    }
}

struct Registry {
    http: reqwest::Client,
    base: String,
    opts: PullOptions,
    bearer: Option<String>,
    repo: String,
}

/// Parse `Bearer realm="...",service="...",scope="..."`.
pub fn parse_challenge(h: &str) -> Option<(String, HashMap<String, String>)> {
    let (scheme, rest) = h.trim().split_once(' ')?;
    let mut params = HashMap::new();
    let mut cur = rest.trim();
    while !cur.is_empty() {
        let (k, after) = cur.split_once('=')?;
        let after = after.trim_start();
        let (v, next) = if let Some(stripped) = after.strip_prefix('"') {
            let end = stripped.find('"')?;
            (&stripped[..end], &stripped[end + 1..])
        } else {
            match after.find(',') {
                Some(i) => (&after[..i], &after[i..]),
                None => (after, ""),
            }
        };
        params.insert(k.trim().to_ascii_lowercase(), v.to_string());
        cur = next.trim_start_matches([',', ' ']);
    }
    Some((scheme.to_ascii_lowercase(), params))
}

impl Registry {
    fn new(r: &ImageRef, opts: &PullOptions) -> Result<Self> {
        let scheme = if opts.allow_http { "http" } else { "https" };
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("kubera/", env!("CARGO_PKG_VERSION")))
                // Blob downloads redirect to CDNs; reqwest drops the
                // Authorization header when the host changes.
                .redirect(reqwest::redirect::Policy::limited(5))
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()?,
            base: format!("{scheme}://{}", r.registry),
            opts: opts.clone(),
            bearer: None,
            repo: r.repository.clone(),
        })
    }

    fn check_url(&self, u: &str) -> Result<()> {
        let url = reqwest::Url::parse(u).context("invalid URL from registry")?;
        match url.scheme() {
            "https" => Ok(()),
            "http" if self.opts.allow_http => Ok(()),
            s => bail!("refusing {s}:// URL from registry"),
        }
    }

    async fn authenticate(&mut self, challenge: &str) -> Result<()> {
        let Some((scheme, p)) = parse_challenge(challenge) else {
            bail!("registry sent an unparseable auth challenge");
        };
        if scheme == "basic" {
            if self.opts.token.is_none() {
                bail!("registry requires credentials (use --registry-token-env)");
            }
            return Ok(());
        }
        let realm = p.get("realm").context("auth challenge without realm")?;
        self.check_url(realm)?;
        let mut url = reqwest::Url::parse(realm)?;
        {
            let mut q = url.query_pairs_mut();
            if let Some(s) = p.get("service") {
                q.append_pair("service", s);
            }
            let scope = p
                .get("scope")
                .cloned()
                .unwrap_or_else(|| format!("repository:{}:pull", self.repo));
            q.append_pair("scope", &scope);
        }
        let mut rb = self.http.get(url);
        if let Some(tok) = &self.opts.token {
            rb = rb.basic_auth(self.opts.user.as_deref().unwrap_or("kubera"), Some(tok));
        }
        let resp = rb.send().await.context("requesting registry token")?;
        if !resp.status().is_success() {
            bail!("registry token request failed: HTTP {}", resp.status());
        }
        let v: Value = resp.json().await.context("invalid token response")?;
        let tok = v["token"]
            .as_str()
            .or_else(|| v["access_token"].as_str())
            .context("token response without token")?;
        self.bearer = Some(tok.to_string());
        Ok(())
    }

    async fn get(&mut self, path: &str, accept: Option<&str>) -> Result<reqwest::Response> {
        let url = format!("{}/v2/{}/{path}", self.base, self.repo);
        let mut authed = false;
        let mut throttled = 0;
        loop {
            let mut rb = self.http.get(&url);
            if let Some(a) = accept {
                rb = rb.header("Accept", a);
            }
            rb = match (&self.bearer, &self.opts.token) {
                (Some(b), _) => rb.bearer_auth(b),
                (None, Some(t)) if authed => {
                    rb.basic_auth(self.opts.user.as_deref().unwrap_or("kubera"), Some(t))
                }
                _ => rb,
            };
            let resp = rb
                .send()
                .await
                .with_context(|| format!("GET {}", self.base))?;
            match resp.status().as_u16() {
                401 if !authed => {
                    let ch = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    self.authenticate(&ch).await?;
                    authed = true;
                }
                429 if throttled < 3 => {
                    throttled += 1;
                    let wait = crate::forge::rate_limit_wait(429, resp.headers())
                        .unwrap_or(std::time::Duration::from_secs(10))
                        .min(std::time::Duration::from_secs(120));
                    eprintln!("registry: rate limited; waiting {}s", wait.as_secs());
                    tokio::time::sleep(wait).await;
                }
                s if (200..300).contains(&s) => return Ok(resp),
                s => {
                    let body = resp.text().await.unwrap_or_default();
                    bail!(
                        "registry answered HTTP {s} for {path}: {}",
                        crate::http::snippet(&body)
                    );
                }
            }
        }
    }

    async fn json(&mut self, path: &str, accept: Option<&str>) -> Result<Value> {
        let resp = self.get(path, accept).await?;
        let bytes = resp.bytes().await?;
        if bytes.len() as u64 > MAX_JSON {
            bail!("registry document too large");
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Download a blob to `dest`, verifying its digest and size.
    async fn blob(&mut self, digest: &str, dest: &Path) -> Result<()> {
        let hex = digest
            .strip_prefix("sha256:")
            .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
            .with_context(|| format!("unsupported digest `{digest}`"))?;
        let mut resp = self.get(&format!("blobs/{digest}"), None).await?;
        let mut f = std::fs::File::create(dest)?;
        let mut h = Sha256::new();
        let mut size = 0u64;
        while let Some(chunk) = resp.chunk().await? {
            size += chunk.len() as u64;
            if size > self.opts.max_layer_size {
                bail!("blob {digest} exceeds --max-layer-size");
            }
            h.update(&chunk);
            f.write_all(&chunk)?;
        }
        f.sync_all()?;
        if hex::encode(h.finalize()) != hex.to_ascii_lowercase() {
            bail!("digest mismatch for blob {digest}; refusing to scan it");
        }
        Ok(())
    }
}

fn platform_matches(p: &Value, want: &str) -> bool {
    let mut it = want.split('/');
    let (os, arch, variant) = (it.next(), it.next(), it.next());
    p["os"].as_str() == os
        && p["architecture"].as_str() == arch
        && (variant.is_none() || p["variant"].as_str() == variant)
}

/// Pull image metadata and layers from a registry (no Docker needed).
pub async fn pull(reference: &str, opts: &PullOptions) -> Result<Image> {
    let r = ImageRef::parse(reference)?;
    let mut reg = Registry::new(&r, opts)?;
    let mut manifest = reg
        .json(&format!("manifests/{}", r.reference), Some(ACCEPT))
        .await?;
    if manifest.get("fsLayers").is_some() {
        bail!("legacy schema-1 manifests are not supported");
    }
    if let Some(list) = manifest["manifests"].as_array() {
        let chosen = list
            .iter()
            .find(|m| platform_matches(&m["platform"], &opts.platform))
            .or_else(|| (list.len() == 1).then(|| &list[0]))
            .with_context(|| {
                let avail: Vec<String> = list
                    .iter()
                    .filter_map(|m| {
                        Some(format!(
                            "{}/{}",
                            m["platform"]["os"].as_str()?,
                            m["platform"]["architecture"].as_str()?
                        ))
                    })
                    .collect();
                format!(
                    "no {} image in {} (available: {})",
                    opts.platform,
                    r.display(),
                    avail.join(", ")
                )
            })?;
        let digest = chosen["digest"]
            .as_str()
            .context("manifest without digest")?;
        manifest = reg
            .json(&format!("manifests/{digest}"), Some(ACCEPT))
            .await?;
    }
    let tmp = tempfile::tempdir()?;
    let config = match manifest["config"]["digest"].as_str() {
        Some(d) => {
            let p = tmp.path().join("config.json");
            reg.blob(d, &p).await?;
            Some(std::fs::read(&p)?)
        }
        None => None,
    };
    let mut layers = Vec::new();
    for (i, l) in manifest["layers"]
        .as_array()
        .context("manifest without layers")?
        .iter()
        .enumerate()
    {
        let digest = l["digest"]
            .as_str()
            .context("layer without digest")?
            .to_string();
        let path = tmp.path().join(format!("layer-{i}"));
        reg.blob(&digest, &path).await?;
        layers.push(Layer::File { digest, path });
    }
    Ok(Image {
        display: r.display(),
        config,
        layers,
        archive: None,
        _tmp: Some(tmp),
    })
}

// ----- archives ---------------------------------------------------------------

/// Read the metadata of a `docker save` or OCI-layout tarball (first pass;
/// layers are streamed later).
pub fn open_archive(path: &Path, platform: &str) -> Result<Image> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut small: HashMap<String, Vec<u8>> = HashMap::new();
    let mut ar = tar::Archive::new(BufReader::new(f));
    for e in ar.entries()? {
        let mut e = e?;
        if !e.header().entry_type().is_file() || e.size() > MAX_JSON {
            continue;
        }
        let name = e
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        let mut buf = Vec::new();
        e.read_to_end(&mut buf)?;
        if buf.first() == Some(&b'{') || buf.first() == Some(&b'[') {
            small.insert(name, buf);
        }
    }
    let blob_path = |digest: &str| format!("blobs/{}", digest.replacen(':', "/", 1));
    let display_default = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // docker save: manifest.json lists config + layer paths.
    if let Some(m) = small.get("manifest.json") {
        let v: Value = serde_json::from_slice(m).context("invalid manifest.json")?;
        let first = v.get(0).context("empty manifest.json")?;
        let config = first["Config"]
            .as_str()
            .and_then(|c| small.get(c.trim_start_matches("./")).cloned());
        let layers = first["Layers"]
            .as_array()
            .context("manifest.json without Layers")?
            .iter()
            .filter_map(|l| l.as_str())
            .map(|l| Layer::InArchive {
                digest: l.trim_start_matches("blobs/").replacen('/', ":", 1),
                entry: l.trim_start_matches("./").to_string(),
            })
            .collect();
        let display = first["RepoTags"][0]
            .as_str()
            .map(str::to_string)
            .unwrap_or(display_default);
        return Ok(Image {
            display,
            config,
            layers,
            archive: Some(path.to_path_buf()),
            _tmp: None,
        });
    }
    // OCI image layout: index.json -> (index ->) manifest -> blobs.
    let index: Value = serde_json::from_slice(
        small
            .get("index.json")
            .context("not an image archive (no manifest.json or index.json)")?,
    )?;
    let mut doc = index;
    for _ in 0..4 {
        let Some(list) = doc["manifests"].as_array() else {
            break;
        };
        let chosen = list
            .iter()
            .find(|m| platform_matches(&m["platform"], platform))
            .or_else(|| list.first())
            .context("empty image index")?;
        let d = chosen["digest"]
            .as_str()
            .context("index entry without digest")?;
        doc = serde_json::from_slice(
            small
                .get(&blob_path(d))
                .with_context(|| format!("missing blob {d}"))?,
        )?;
    }
    let config = doc["config"]["digest"]
        .as_str()
        .and_then(|d| small.get(&blob_path(d)).cloned());
    let layers = doc["layers"]
        .as_array()
        .context("OCI manifest without layers")?
        .iter()
        .filter_map(|l| l["digest"].as_str())
        .map(|d| Layer::InArchive {
            digest: d.to_string(),
            entry: blob_path(d),
        })
        .collect();
    Ok(Image {
        display: display_default,
        config,
        layers,
        archive: Some(path.to_path_buf()),
        _tmp: None,
    })
}

/// Export an image from the local Docker daemon and open it.
pub fn from_docker(reference: &str, platform: &str) -> Result<Image> {
    if reference.starts_with('-') || reference.trim().is_empty() {
        bail!("invalid image reference `{reference}`");
    }
    let tmp = tempfile::tempdir()?;
    let out = tmp.path().join("image.tar");
    let status = Command::new("docker")
        .arg("save")
        .arg("-o")
        .arg(&out)
        .arg(reference)
        .stdin(Stdio::null())
        .status()
        .context("running `docker save` (is Docker installed and running?)")?;
    if !status.success() {
        bail!("`docker save {reference}` failed ({status})");
    }
    let mut img = open_archive(&out, platform)?;
    img.display = reference.to_string();
    img._tmp = Some(tmp);
    Ok(img)
}

// ----- scanning ---------------------------------------------------------------

/// Decompress (gzip / zstd / none, by magic bytes) and walk a layer tar,
/// sending each text file to `sink`.
pub fn walk_layer<R: Read>(
    reader: R,
    digest: &str,
    image: &str,
    max_file_size: u64,
    sink: &mut dyn FnMut(Chunk),
) -> Result<()> {
    let mut br = BufReader::with_capacity(64 * 1024, reader);
    let magic = br
        .fill_buf()?
        .get(..4)
        .map(|m| m.to_vec())
        .unwrap_or_default();
    let decoded: Box<dyn Read> = if magic.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(br))
    } else if magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Box::new(
            ruzstd::decoding::StreamingDecoder::new(br)
                .map_err(|e| anyhow::anyhow!("zstd layer {digest}: {e}"))?,
        )
    } else {
        Box::new(br)
    };
    let mut ar = tar::Archive::new(decoded);
    for e in ar
        .entries()
        .with_context(|| format!("reading layer {digest}"))?
    {
        let mut e = e?;
        if !e.header().entry_type().is_file() || e.size() == 0 {
            continue;
        }
        let p = e
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        let file = p.rsplit('/').next().unwrap_or_default();
        if file.starts_with(".wh.") {
            continue;
        }
        let location = Location {
            source: SourceKind::Container,
            path: Some(format!("/{p}")),
            repository: Some(image.to_string()),
            layer: Some(digest.to_string()),
            ..Default::default()
        };
        // Archives (jars, wheels, tarballs) inside the layer.
        let limits = super::archive::Limits::new(max_file_size);
        if e.size() <= limits.max_nested && super::archive::archive_name(file) {
            let mut data = Vec::with_capacity(e.size() as usize);
            e.read_to_end(&mut data)?;
            if let Some(kind) = super::archive::kind(&data) {
                let res =
                    super::archive::walk(kind, std::io::Cursor::new(data), limits, &mut |x| {
                        sink(Chunk {
                            text: x.text,
                            location: Location {
                                entry: Some(x.path),
                                ..location.clone()
                            },
                            line_map: None,
                        })
                    });
                if let Err(err) = res {
                    eprintln!("warning: /{p} in layer {digest}: {err:#}");
                }
            }
            continue;
        }
        if e.size() > max_file_size {
            continue;
        }
        let mut buf = Vec::with_capacity(e.size() as usize);
        e.read_to_end(&mut buf)?;
        if is_binary(&buf) {
            continue;
        }
        sink(Chunk {
            text: String::from_utf8_lossy(&buf).into_owned(),
            location,
            line_map: None,
        });
    }
    Ok(())
}

/// Stream every layer (and the config) of `img` to `sink`.
pub fn walk(img: &Image, max_file_size: u64, sink: &mut dyn FnMut(Chunk)) -> Result<()> {
    if let Some(cfg) = &img.config {
        // Pretty-print so findings point at a meaningful line.
        let text = serde_json::from_slice::<Value>(cfg)
            .ok()
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or_else(|| String::from_utf8_lossy(cfg).into_owned());
        sink(Chunk {
            text,
            location: Location {
                source: SourceKind::Container,
                path: Some("<image config: env, labels, history>".into()),
                repository: Some(img.display.clone()),
                ..Default::default()
            },
            line_map: None,
        });
    }
    let mut in_archive: HashMap<&str, &str> = HashMap::new();
    for l in &img.layers {
        match l {
            Layer::File { digest, path } => {
                let f = std::fs::File::open(path)?;
                walk_layer(f, digest, &img.display, max_file_size, sink)?;
            }
            Layer::InArchive { digest, entry } => {
                in_archive.insert(entry.as_str(), digest.as_str());
            }
        }
    }
    if let (Some(archive), false) = (&img.archive, in_archive.is_empty()) {
        let f = std::fs::File::open(archive)?;
        let mut ar = tar::Archive::new(BufReader::new(f));
        for e in ar.entries()? {
            let e = e?;
            let name = e
                .path()?
                .to_string_lossy()
                .trim_start_matches("./")
                .to_string();
            if let Some(digest) = in_archive.get(name.as_str()) {
                walk_layer(e, digest, &img.display, max_file_size, sink)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_references() {
        let r = ImageRef::parse("alpine").unwrap();
        assert_eq!(
            (
                r.registry.as_str(),
                r.repository.as_str(),
                r.reference.as_str()
            ),
            ("registry-1.docker.io", "library/alpine", "latest")
        );
        assert_eq!(r.display(), "docker.io/library/alpine:latest");
        let r = ImageRef::parse("ghcr.io/acme/api:1.2.3").unwrap();
        assert_eq!(
            (
                r.registry.as_str(),
                r.repository.as_str(),
                r.reference.as_str()
            ),
            ("ghcr.io", "acme/api", "1.2.3")
        );
        let r = ImageRef::parse("localhost:5000/team/app@sha256:abcd").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.reference, "sha256:abcd");
        let r = ImageRef::parse("acme/app:dev").unwrap();
        assert_eq!(r.repository, "acme/app");
        assert!(ImageRef::parse("--output=/x").is_err());
        assert!(ImageRef::parse("ghcr.io/Acme/UPPER").is_err());
    }

    #[test]
    fn auth_challenges() {
        let (s, p) = parse_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        )
        .unwrap();
        assert_eq!(s, "bearer");
        assert_eq!(p["realm"], "https://auth.docker.io/token");
        assert_eq!(p["scope"], "repository:library/alpine:pull");
        let (s, p) = parse_challenge(r#"Basic realm="Registry""#).unwrap();
        assert_eq!((s.as_str(), p["realm"].as_str()), ("basic", "Registry"));
    }

    #[test]
    fn platforms() {
        let p = serde_json::json!({"os": "linux", "architecture": "arm64", "variant": "v8"});
        assert!(platform_matches(&p, "linux/arm64"));
        assert!(platform_matches(&p, "linux/arm64/v8"));
        assert!(!platform_matches(&p, "linux/amd64"));
    }
}
