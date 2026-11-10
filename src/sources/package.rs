//! Published packages: npm tarballs, PyPI sdists and wheels, and crates.io
//! `.crate` files, downloaded from the official registry and scanned with
//! the archive walker.
//!
//! What gets published is not always what is in the repository: a build
//! step, a stray `.env` or `.npmrc` in the working directory, a test
//! fixture. Each artifact is verified against the digest the registry
//! publishes (npm `integrity` sha512, PyPI and crates.io sha256) before it
//! is opened, and a mismatch stops the scan.
//!
//! No credentials are involved. Downloads are capped (`--max-package-size`,
//! sizes checked before downloading when the registry gives them), only
//! fetched over https from the registry or its file host, and never
//! written to disk.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

use super::Chunk;
use crate::config::Filter;
use crate::finding::{Location, SourceKind};
use crate::forge::{Client, Kind, enc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registry {
    Npm,
    Pypi,
    Crates,
}

impl Registry {
    fn prefix(self) -> &'static str {
        match self {
            Registry::Npm => "npm",
            Registry::Pypi => "pypi",
            Registry::Crates => "crates",
        }
    }
}

/// `npm:<name>[@version]`, `pypi:<name>[==version]`, `crates:<name>[@version]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub registry: Registry,
    pub name: String,
    pub version: Option<String>,
}

pub fn parse(spec: &str) -> Result<PackageRef> {
    let (registry, rest) = if let Some(r) = spec.strip_prefix("npm:") {
        (Registry::Npm, r)
    } else if let Some(r) = spec.strip_prefix("pypi:") {
        (Registry::Pypi, r)
    } else if let Some(r) = spec.strip_prefix("crates:") {
        (Registry::Crates, r)
    } else {
        bail!(
            "expected npm:<name>[@version], pypi:<name>[==version] or crates:<name>[@version], got `{spec}`"
        );
    };
    let (name, version) = match registry {
        Registry::Pypi => match rest.split_once("==") {
            Some((n, v)) => (n, Some(v)),
            None => (rest, None),
        },
        // `@scope/name@1.0`: the version separator is the last `@` after
        // the first character.
        _ => match rest.rfind('@').filter(|i| *i > 0) {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        },
    };
    let name_ok = |c: char| match registry {
        Registry::Npm => c.is_ascii_lowercase() || c.is_ascii_digit() || "-._~@/".contains(c),
        Registry::Pypi => c.is_ascii_alphanumeric() || "-._".contains(c),
        Registry::Crates => c.is_ascii_alphanumeric() || "-_".contains(c),
    };
    if name.is_empty() || name.len() > 214 || !name.chars().all(name_ok) || name.starts_with('.') {
        bail!("`{name}` is not a valid {} package name", registry.prefix());
    }
    if registry == Registry::Npm && name.matches('/').count() > usize::from(name.starts_with('@')) {
        bail!("`{name}` is not a valid npm package name");
    }
    if let Some(v) = version
        && (v.is_empty()
            || !v
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._+!".contains(c)))
    {
        bail!("`{v}` is not a valid version");
    }
    Ok(PackageRef {
        registry,
        name: name.to_string(),
        version: version.map(str::to_string),
    })
}

pub struct Options {
    /// Every published version (newest first, up to `max_versions`)
    /// instead of the latest or the one asked for.
    pub all_versions: bool,
    pub max_versions: usize,
    /// Largest artifact downloaded.
    pub max_size: u64,
    pub max_file_size: u64,
    /// One base replacing every registry API and file host (tests,
    /// mirrors).
    pub registry_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum Expected {
    Sha256(String),
    Sha512(Vec<u8>),
}

/// One file to download and scan.
#[derive(Debug, Clone)]
struct Artifact {
    version: String,
    file: String,
    url: String,
    size: Option<u64>,
    digest: Option<Expected>,
}

/// Order versions: numeric components, then releases after pre-releases.
fn version_key(v: &str) -> (Vec<u64>, bool, String) {
    let (core, pre) = match v.find(['-', '+']) {
        Some(i) => (&v[..i], v[i..].starts_with('-')),
        None => (v, false),
    };
    // PEP 440 pre-releases (1.0a1, 1.0rc2) have letters in the core.
    let alpha = core.chars().any(|c| c.is_ascii_alphabetic());
    let nums = core
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap_or(u64::MAX))
        .collect();
    (nums, !(pre || alpha), v.to_string())
}

fn newest_first(versions: &mut [String]) {
    versions.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
}

struct Bases {
    api: String,
    /// Origins artifacts may be downloaded from.
    files: Vec<String>,
}

fn bases(r: Registry, o: &Options) -> Bases {
    if let Some(u) = &o.registry_url {
        let u = u.trim_end_matches('/').to_string();
        return Bases {
            api: u.clone(),
            files: vec![u],
        };
    }
    match r {
        Registry::Npm => Bases {
            api: "https://registry.npmjs.org".into(),
            files: vec!["https://registry.npmjs.org".into()],
        },
        Registry::Pypi => Bases {
            api: "https://pypi.org".into(),
            files: vec!["https://files.pythonhosted.org".into()],
        },
        Registry::Crates => Bases {
            api: "https://crates.io".into(),
            files: vec!["https://static.crates.io".into()],
        },
    }
}

fn s<'a>(v: &'a Value, p: &str) -> &'a str {
    v.pointer(p).and_then(Value::as_str).unwrap_or_default()
}

async fn npm(client: &Client, b: &Bases, p: &PackageRef, o: &Options) -> Result<Vec<Artifact>> {
    // Scoped names keep their `@` and encode the `/`.
    let url = format!("{}/{}", b.api, p.name.replace('/', "%2F"));
    let doc = client
        .get_json(Kind::Other, &url)
        .await
        .with_context(|| format!("npm:{}", p.name))?;
    let mut versions: Vec<String> = match (&p.version, o.all_versions) {
        (Some(v), false) => vec![v.clone()],
        (None, false) => vec![s(&doc, "/dist-tags/latest").to_string()],
        (_, true) => doc["versions"]
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default(),
    };
    newest_first(&mut versions);
    versions.truncate(o.max_versions.max(1));
    let mut out = Vec::new();
    for v in versions {
        let meta = &doc["versions"][&v];
        if meta.is_null() {
            bail!("npm:{} has no version `{v}`", p.name);
        }
        let tarball = s(meta, "/dist/tarball");
        let integrity = s(meta, "/dist/integrity");
        let digest = integrity.strip_prefix("sha512-").and_then(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .ok()
                .map(Expected::Sha512)
        });
        out.push(Artifact {
            file: tarball
                .rsplit('/')
                .next()
                .unwrap_or("package.tgz")
                .to_string(),
            url: tarball.to_string(),
            size: None,
            digest,
            version: v,
        });
    }
    Ok(out)
}

/// The sdist and one wheel (a pure-Python one when there is one).
fn pick_pypi_files(files: &[Value]) -> Vec<&Value> {
    let sdist = files.iter().find(|f| s(f, "/packagetype") == "sdist");
    let wheels: Vec<&Value> = files
        .iter()
        .filter(|f| s(f, "/packagetype") == "bdist_wheel")
        .collect();
    let wheel = wheels
        .iter()
        .find(|f| s(f, "/filename").ends_with("-none-any.whl"))
        .or(wheels.first())
        .copied();
    let mut out: Vec<&Value> = sdist.into_iter().chain(wheel).collect();
    if out.is_empty() {
        // Eggs and other legacy formats: take the first file.
        out.extend(files.first());
    }
    out
}

async fn pypi(client: &Client, b: &Bases, p: &PackageRef, o: &Options) -> Result<Vec<Artifact>> {
    let url = match (&p.version, o.all_versions) {
        (Some(v), false) => format!("{}/pypi/{}/{}/json", b.api, enc(&p.name), enc(v)),
        _ => format!("{}/pypi/{}/json", b.api, enc(&p.name)),
    };
    let doc = client
        .get_json(Kind::Other, &url)
        .await
        .with_context(|| format!("pypi:{}", p.name))?;
    let releases: Vec<(String, Vec<Value>)> = if o.all_versions {
        let mut r: Vec<(String, Vec<Value>)> = doc["releases"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_array().cloned().unwrap_or_default()))
                    .filter(|(_, f)| !f.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        // Newest upload first (PEP 440 ordering is not needed for that).
        r.sort_by_key(|(_, f)| std::cmp::Reverse(s(&f[0], "/upload_time_iso_8601").to_string()));
        r.truncate(o.max_versions.max(1));
        r
    } else {
        vec![(
            s(&doc, "/info/version").to_string(),
            doc["urls"].as_array().cloned().unwrap_or_default(),
        )]
    };
    let mut out = Vec::new();
    for (v, files) in releases {
        for f in pick_pypi_files(&files) {
            let sha = s(f, "/digests/sha256");
            out.push(Artifact {
                version: v.clone(),
                file: s(f, "/filename").to_string(),
                url: s(f, "/url").to_string(),
                size: f.get("size").and_then(Value::as_u64),
                digest: (!sha.is_empty()).then(|| Expected::Sha256(sha.to_ascii_lowercase())),
            });
        }
    }
    Ok(out)
}

async fn crates(client: &Client, b: &Bases, p: &PackageRef, o: &Options) -> Result<Vec<Artifact>> {
    let api = format!("{}/api/v1/crates/{}", b.api, enc(&p.name));
    let versions: Vec<Value> = match (&p.version, o.all_versions) {
        (Some(v), false) => {
            let doc = client
                .get_json(Kind::Other, &format!("{api}/{}", enc(v)))
                .await
                .with_context(|| format!("crates:{}@{v}", p.name))?;
            vec![doc["version"].clone()]
        }
        (None, false) => {
            let doc = client
                .get_json(Kind::Other, &api)
                .await
                .with_context(|| format!("crates:{}", p.name))?;
            let latest = match s(&doc, "/crate/default_version") {
                "" => s(&doc, "/crate/max_stable_version"),
                v => v,
            };
            let latest = if latest.is_empty() {
                s(&doc, "/crate/max_version")
            } else {
                latest
            };
            let doc = client
                .get_json(Kind::Other, &format!("{api}/{}", enc(latest)))
                .await
                .with_context(|| format!("crates:{}@{latest}", p.name))?;
            vec![doc["version"].clone()]
        }
        // Newest first; yanked versions included (yanking does not
        // unpublish, and is often why a version was pulled).
        (_, true) => {
            let mut all = Vec::new();
            let mut query = "?per_page=100".to_string();
            while all.len() < o.max_versions.max(1) {
                let doc = client
                    .get_json(Kind::Other, &format!("{api}/versions{query}"))
                    .await
                    .with_context(|| format!("crates:{} versions", p.name))?;
                all.extend(doc["versions"].as_array().cloned().unwrap_or_default());
                match s(&doc, "/meta/next_page") {
                    q if q.starts_with('?') => query = q.to_string(),
                    _ => break,
                }
            }
            all.truncate(o.max_versions.max(1));
            all
        }
    };
    let files = b.files[0].clone();
    Ok(versions
        .iter()
        .map(|v| {
            let num = s(v, "/num").to_string();
            let sha = s(v, "/checksum");
            Artifact {
                file: format!("{}-{num}.crate", p.name),
                url: format!(
                    "{files}/crates/{}/{}-{}.crate",
                    enc(&p.name),
                    enc(&p.name),
                    enc(&num)
                ),
                size: v.get("crate_size").and_then(Value::as_u64),
                digest: (!sha.is_empty()).then(|| Expected::Sha256(sha.to_ascii_lowercase())),
                version: num,
            }
        })
        .collect())
}

fn link(p: &PackageRef, version: &str) -> String {
    match p.registry {
        Registry::Npm => format!(
            "https://www.npmjs.com/package/{}/v/{}",
            p.name,
            enc(version)
        ),
        Registry::Pypi => format!("https://pypi.org/project/{}/{}/", p.name, enc(version)),
        Registry::Crates => format!("https://crates.io/crates/{}/{}", p.name, enc(version)),
    }
}

fn verify(data: &[u8], want: &Option<Expected>) -> Result<bool> {
    match want {
        None => Ok(false),
        Some(Expected::Sha256(hex)) => {
            let got = hex::encode(Sha256::digest(data));
            if &got != hex {
                bail!("sha256 mismatch (registry says {hex}, download is {got})");
            }
            Ok(true)
        }
        Some(Expected::Sha512(want)) => {
            if Sha512::digest(data).as_slice() != want.as_slice() {
                bail!("sha512 integrity mismatch");
            }
            Ok(true)
        }
    }
}

/// Resolve, download, verify and scan each package. Chunks go to `sink`.
pub async fn scan(
    client: &Client,
    packages: &[PackageRef],
    o: &Options,
    filter: &Filter,
    progress: &dyn Fn(String),
    sink: &mut dyn FnMut(Chunk),
) -> Result<usize> {
    let mut scanned = 0;
    for p in packages {
        let b = bases(p.registry, o);
        let artifacts = match p.registry {
            Registry::Npm => npm(client, &b, p, o).await?,
            Registry::Pypi => pypi(client, &b, p, o).await?,
            Registry::Crates => crates(client, &b, p, o).await?,
        };
        if artifacts.is_empty() {
            bail!("{}:{}: no published files", p.registry.prefix(), p.name);
        }
        for a in artifacts {
            let label = format!("{}:{}@{}", p.registry.prefix(), p.name, a.version);
            let url = reqwest::Url::parse(&a.url)
                .with_context(|| format!("{label}: invalid download URL"))?;
            let origin = url.origin().ascii_serialization();
            if !b.files.iter().chain([&b.api]).any(|f| *f == origin) {
                bail!(
                    "{label}: refusing to download from {} (not the registry's file host)",
                    crate::http::redact_url(&url)
                );
            }
            if a.size.is_some_and(|n| n > o.max_size) {
                eprintln!(
                    "warning: {label}: {} is larger than --max-package-size; skipped",
                    a.file
                );
                continue;
            }
            progress(format!("{label}: {}", a.file));
            let Some(data) = client.download(Kind::Other, &a.url, o.max_size).await? else {
                eprintln!(
                    "warning: {label}: {} is missing or larger than --max-package-size; skipped",
                    a.file
                );
                continue;
            };
            if !verify(&data, &a.digest).with_context(|| format!("{label}: {}", a.file))? {
                eprintln!(
                    "warning: {label}: the registry publishes no sha256/sha512 for {}; not verified",
                    a.file
                );
            }
            let location = Location {
                source: SourceKind::Package,
                repository: Some(label),
                path: Some(super::printable(&a.file)),
                link: Some(link(p, &a.version)),
                ..Default::default()
            };
            for c in super::bucket::object_chunks(data, location, o.max_file_size, filter) {
                sink(c);
            }
            scanned += 1;
        }
    }
    Ok(scanned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_specs() {
        let p = parse("npm:@acme/cli@2.1.0").unwrap();
        assert_eq!(
            (p.name.as_str(), p.version.as_deref()),
            ("@acme/cli", Some("2.1.0"))
        );
        assert_eq!(parse("npm:@acme/cli").unwrap().version, None);
        assert_eq!(parse("npm:left-pad").unwrap().name, "left-pad");
        let p = parse("pypi:requests==2.32.3").unwrap();
        assert_eq!(
            (p.name.as_str(), p.version.as_deref()),
            ("requests", Some("2.32.3"))
        );
        assert_eq!(
            parse("crates:serde@1.0.0").unwrap().version.as_deref(),
            Some("1.0.0")
        );
        for bad in [
            "gem:rails",
            "npm:../x",
            "npm:a/b/c",
            "crates:a/b",
            "pypi:x==1 2",
            "npm:x@",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn versions_sort_newest_first() {
        let mut v: Vec<String> = ["1.2.0", "1.10.0", "1.10.0-rc.1", "0.9", "2.0.0a1", "1.9.9"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        newest_first(&mut v);
        assert_eq!(
            v,
            ["2.0.0a1", "1.10.0", "1.10.0-rc.1", "1.9.9", "1.2.0", "0.9"]
        );
    }

    #[test]
    fn digests_are_checked() {
        let sha = hex::encode(Sha256::digest(b"abc"));
        assert!(verify(b"abc", &Some(Expected::Sha256(sha.clone()))).unwrap());
        assert!(verify(b"abd", &Some(Expected::Sha256(sha))).is_err());
        let sha512 = Sha512::digest(b"abc").to_vec();
        assert!(verify(b"abc", &Some(Expected::Sha512(sha512.clone()))).unwrap());
        assert!(verify(b"x", &Some(Expected::Sha512(sha512))).is_err());
        assert!(!verify(b"x", &None).unwrap());
    }
}
