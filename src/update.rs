//! `kubera update`: replace the running executable with a release build.
//!
//! Security notes:
//! * Nothing here runs unless the user invokes `kubera update`: there are
//!   no background checks and nothing is reported anywhere.
//! * HTTPS only. Redirects are followed one hop at a time and only to the
//!   GitHub API, download and release-asset hosts ([`GITHUB_HOSTS`]); the
//!   pre-signed storage URL GitHub redirects downloads to is never logged
//!   with its query string.
//! * No credentials are sent (the release API is public).
//! * The archive must match the release's `<asset>.sha256` file and, when
//!   the API reports one, the asset's digest. Nothing on disk is touched
//!   before that check passes.
//! * The new binary is written next to the old one, flushed to disk, run
//!   once with `--version`, and only then renamed over the old one, so an
//!   interrupted or failed update leaves the installed binary as it was.

use std::fmt;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use reqwest::Url;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The repository releases come from.
pub const REPO: &str = "dmdhrumilmistry/kubera";
/// The workflow that builds and attests releases.
pub const RELEASE_WORKFLOW: &str = "dmdhrumilmistry/kubera/.github/workflows/release.yml";
/// The Rust target triple this binary was compiled for (set by build.rs).
pub const BUILD_TARGET: &str = env!("KUBERA_BUILD_TARGET");
/// Hosts release lookups and downloads may touch, redirects included.
pub const GITHUB_HOSTS: &[&str] = &[
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

/// Targets that have a prebuilt archive on every release (release.yml).
pub const RELEASE_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "i686-unknown-linux-musl",
    "armv7-unknown-linux-musleabihf",
    "arm-unknown-linux-musleabihf",
    "riscv64gc-unknown-linux-gnu",
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "x86_64-linux-android",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-unknown-freebsd",
];

const MAX_API_BODY: usize = 8 << 20;
const MAX_CHECKSUM_BODY: usize = 4 << 10;
const MAX_ARCHIVE: usize = 256 << 20;
const MAX_BINARY: u64 = 512 << 20;
const MAX_REDIRECTS: usize = 5;

/// The release archive target for a binary built for `build_target`.
///
/// Release targets map to themselves. Other builds of the same platform
/// (for example a glibc build from source) map to the release archive
/// `install.sh` would pick for that machine.
pub fn release_target(build_target: &str) -> Option<&'static str> {
    if let Some(t) = RELEASE_TARGETS.iter().find(|t| **t == build_target) {
        return Some(t);
    }
    Some(match build_target {
        "x86_64-unknown-linux-gnu" => "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-gnu" => "aarch64-unknown-linux-musl",
        "i686-unknown-linux-gnu" => "i686-unknown-linux-musl",
        "armv7-unknown-linux-gnueabihf" => "armv7-unknown-linux-musleabihf",
        "arm-unknown-linux-gnueabihf" => "arm-unknown-linux-musleabihf",
        "riscv64gc-unknown-linux-musl" => "riscv64gc-unknown-linux-gnu",
        "x86_64-pc-windows-gnu" | "x86_64-pc-windows-gnullvm" => "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-gnullvm" => "aarch64-pc-windows-msvc",
        _ => return None,
    })
}

/// Fallback from `std::env::consts::{OS, ARCH}`, named like `install.sh`'s
/// choices. 32-bit ARM is left out: ARMv6 and ARMv7 need different
/// archives and `ARCH` does not tell them apart.
pub fn target_for(os: &str, arch: &str) -> Option<&'static str> {
    Some(match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("linux", "x86") => "i686-unknown-linux-musl",
        ("linux", "riscv64") => "riscv64gc-unknown-linux-gnu",
        ("android", "aarch64") => "aarch64-linux-android",
        ("android", "x86_64") => "x86_64-linux-android",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        ("freebsd", "x86_64") => "x86_64-unknown-freebsd",
        _ => return None,
    })
}

/// The release archive target for the running binary, if there is one.
pub fn platform_target() -> Option<&'static str> {
    release_target(BUILD_TARGET)
        .or_else(|| target_for(std::env::consts::OS, std::env::consts::ARCH))
}

/// The release asset holding the binary for `target`.
pub fn asset_name(target: &str) -> String {
    if target.contains("-windows-") {
        format!("kubera-{target}.zip")
    } else {
        format!("kubera-{target}.tar.gz")
    }
}

/// A release version: `MAJOR.MINOR.PATCH[-PRERELEASE]`, compared like semver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>,
}

impl Version {
    /// Parse `1.2.3`, `v1.2.3` or `1.2.3-rc.1` (build metadata is not used).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let mut num = || -> Option<u64> {
            let p = parts.next()?;
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse().ok()
        };
        let (major, minor, patch) = (num()?, num()?, num()?);
        if parts.next().is_some() {
            return None;
        }
        if let Some(p) = pre
            && (p.is_empty()
                || !p.split('.').all(|id| {
                    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }))
        {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
            pre: pre.map(str::to_string),
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(p) = &self.pre {
            write!(f, "-{p}")?;
        }
        Ok(())
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => {
                    let mut a = a.split('.');
                    let mut b = b.split('.');
                    loop {
                        match (a.next(), b.next()) {
                            (None, None) => return Ordering::Equal,
                            (None, Some(_)) => return Ordering::Less,
                            (Some(_), None) => return Ordering::Greater,
                            (Some(x), Some(y)) => {
                                let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                                    (Ok(x), Ok(y)) => x.cmp(&y),
                                    (Ok(_), Err(_)) => Ordering::Less,
                                    (Err(_), Ok(_)) => Ordering::Greater,
                                    (Err(_), Err(_)) => x.cmp(y),
                                };
                                if o != Ordering::Equal {
                                    return o;
                                }
                            }
                        }
                    }
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The version of this binary.
pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("CARGO_PKG_VERSION is a valid version")
}

/// A release tag as the user typed it (`0.3.0` or `v0.3.0`), normalized.
pub fn normalize_tag(tag: &str) -> Result<String> {
    match Version::parse(tag) {
        Some(v) => Ok(format!("v{v}")),
        None => bail!("`{tag}` is not a release version (expected vX.Y.Z)"),
    }
}

#[derive(Debug, Clone)]
pub struct Release {
    pub tag: String,
    pub version: Version,
    pub prerelease: bool,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub url: Url,
    pub size: u64,
    /// SHA-256 reported by the GitHub API (`digest: "sha256:…"`), if any.
    pub sha256: Option<String>,
}

impl Release {
    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    digest: Option<String>,
}

/// Where releases come from. Tests point this at a local mock server.
#[derive(Debug, Clone)]
pub struct Source {
    /// GitHub REST API base, e.g. `https://api.github.com/`.
    pub api: Url,
    pub repo: String,
    /// Hosts that may be contacted, redirects included.
    pub hosts: Vec<String>,
    /// Permit `http://` (mock servers in tests only).
    pub allow_http: bool,
}

impl Default for Source {
    fn default() -> Self {
        Self {
            api: Url::parse("https://api.github.com/").expect("valid URL"),
            repo: REPO.to_string(),
            hosts: GITHUB_HOSTS.iter().map(|h| h.to_string()).collect(),
            allow_http: false,
        }
    }
}

pub struct Updater {
    client: reqwest::Client,
    source: Source,
}

/// `scheme://host[:port]/path`, without the query: GitHub's redirect to
/// release storage carries a pre-signed token there.
fn shown(u: &Url) -> String {
    let mut u = u.clone();
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

impl Updater {
    pub fn new(source: Source) -> Result<Self> {
        let client = crate::http::client_builder()
            .timeout(Duration::from_secs(600))
            .build()
            .context("building HTTP client")?;
        Ok(Self { client, source })
    }

    fn allowed(&self, u: &Url) -> Result<()> {
        match u.scheme() {
            "https" => {}
            "http" if self.source.allow_http => {}
            s => bail!(
                "refusing to fetch `{s}://` URL {}; only https is allowed",
                shown(u)
            ),
        }
        ensure!(
            u.username().is_empty() && u.password().is_none(),
            "refusing a URL with credentials"
        );
        let host = u.host_str().unwrap_or_default();
        ensure!(
            self.source
                .hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(host)),
            "refusing to contact {host}: not a GitHub release host ({})",
            shown(u)
        );
        Ok(())
    }

    /// GET with a size cap, following redirects only to allowed hosts.
    async fn get(&self, url: Url, accept: &str, max: usize) -> Result<Vec<u8>> {
        let mut url = url;
        for _ in 0..=MAX_REDIRECTS {
            self.allowed(&url)?;
            let mut resp = self
                .client
                .get(url.clone())
                .header(reqwest::header::ACCEPT, accept)
                .header("x-github-api-version", "2022-11-28")
                .send()
                .await
                .map_err(reqwest::Error::without_url)
                .with_context(|| format!("GET {}", shown(&url)))?;
            let status = resp.status();
            if status.is_redirection() {
                let loc = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .with_context(|| format!("redirect without a location from {}", shown(&url)))?;
                url = url.join(loc).context("redirect location is not a URL")?;
                continue;
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                bail!("not found: {}", shown(&url));
            }
            ensure!(
                status.is_success(),
                "GET {} returned HTTP {status}",
                shown(&url)
            );
            if let Some(len) = resp.content_length() {
                ensure!(
                    len <= max as u64,
                    "{} is too large ({len} bytes)",
                    shown(&url)
                );
            }
            let mut buf = Vec::new();
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(reqwest::Error::without_url)
                .with_context(|| format!("reading {}", shown(&url)))?
            {
                ensure!(
                    buf.len() + chunk.len() <= max,
                    "{} is larger than {max} bytes",
                    shown(&url)
                );
                buf.extend_from_slice(&chunk);
            }
            return Ok(buf);
        }
        bail!("too many redirects")
    }

    /// The latest release, or the release tagged `tag`.
    pub async fn release(&self, tag: Option<&str>) -> Result<Release> {
        let path = match tag {
            None => format!("repos/{}/releases/latest", self.source.repo),
            Some(t) => format!(
                "repos/{}/releases/tags/{}",
                self.source.repo,
                normalize_tag(t)?
            ),
        };
        let url = self.source.api.join(&path).context("release API URL")?;
        let what = tag.map_or_else(
            || "the latest release".to_string(),
            |t| format!("release {t}"),
        );
        let body = self
            .get(url, "application/vnd.github+json", MAX_API_BODY)
            .await
            .with_context(|| format!("looking up {what} of {}", self.source.repo))?;
        let api: ApiRelease =
            serde_json::from_slice(&body).context("parsing the GitHub release response")?;
        ensure!(!api.draft, "{} is a draft release", api.tag_name);
        let version = Version::parse(&api.tag_name)
            .with_context(|| format!("release tag `{}` is not a version", api.tag_name))?;
        let assets = api
            .assets
            .into_iter()
            .filter_map(|a| {
                let url = Url::parse(&a.browser_download_url).ok()?;
                let sha256 = a
                    .digest
                    .as_deref()
                    .and_then(|d| d.strip_prefix("sha256:"))
                    .map(str::to_ascii_lowercase)
                    .filter(|h| is_sha256_hex(h));
                Some(Asset {
                    name: a.name,
                    url,
                    size: a.size,
                    sha256,
                })
            })
            .collect();
        Ok(Release {
            tag: api.tag_name,
            version,
            prerelease: api.prerelease,
            assets,
        })
    }

    /// Download the archive for `target` and verify it against the
    /// release's checksum file (and the API digest, when present).
    pub async fn download(&self, release: &Release, target: &str) -> Result<Vec<u8>> {
        let name = asset_name(target);
        let asset = release
            .asset(&name)
            .with_context(|| format!("release {} has no {name}", release.tag))?;
        let sum_name = format!("{name}.sha256");
        let sum_asset = release.asset(&sum_name).with_context(|| {
            format!(
                "release {} has no {sum_name}; refusing an unverifiable download",
                release.tag
            )
        })?;
        let sum = self
            .get(
                sum_asset.url.clone(),
                "application/octet-stream",
                MAX_CHECKSUM_BODY,
            )
            .await
            .with_context(|| format!("downloading {sum_name}"))?;
        let expected = parse_checksum(&sum, &name)?;
        if let Some(api) = &asset.sha256 {
            ensure!(
                *api == expected,
                "GitHub reports sha256 {api} for {name}, but {sum_name} says {expected}; refusing to update"
            );
        }
        ensure!(
            asset.size <= MAX_ARCHIVE as u64,
            "{name} is too large ({} bytes)",
            asset.size
        );
        let archive = self
            .get(asset.url.clone(), "application/octet-stream", MAX_ARCHIVE)
            .await
            .with_context(|| format!("downloading {name}"))?;
        let actual = sha256_hex(&archive);
        ensure!(
            actual == expected,
            "checksum mismatch for {name}: expected {expected}, got {actual}; nothing was changed"
        );
        Ok(archive)
    }

    /// Download, verify and install `release` over the executable at `exe`.
    pub async fn install(&self, release: &Release, target: &str, exe: &Path) -> Result<()> {
        check_writable(exe)?;
        let archive = self.download(release, target).await?;
        let binary = extract_binary(&archive, target)?;
        replace_exe(exe, &binary, &release.version)
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Parse a `sha256sum`-style file (`<hex>  <name>`, LF or CRLF) for `name`.
pub fn parse_checksum(text: &[u8], name: &str) -> Result<String> {
    let text = std::str::from_utf8(text).context("checksum file is not text")?;
    let mut fields = text.lines().next().unwrap_or_default().split_whitespace();
    let hash = fields.next().unwrap_or_default().to_ascii_lowercase();
    ensure!(
        is_sha256_hex(&hash),
        "checksum file for {name} has no SHA-256"
    );
    if let Some(file) = fields.next() {
        let file = file.trim_start_matches('*');
        ensure!(file == name, "checksum file is for {file}, not {name}");
    }
    Ok(hash)
}

/// The `kubera` executable inside a release archive.
pub fn extract_binary(archive: &[u8], target: &str) -> Result<Vec<u8>> {
    let name = asset_name(target);
    if name.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(Cursor::new(archive))
            .with_context(|| format!("{name} is not a zip archive"))?;
        for path in [
            "kubera.exe".to_string(),
            format!("kubera-{target}/kubera.exe"),
        ] {
            let Ok(mut f) = zip.by_name(&path) else {
                continue;
            };
            ensure!(f.is_file(), "{path} in {name} is not a file");
            return read_capped(&mut f, &name);
        }
    } else {
        let want = format!("kubera-{target}/kubera");
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
        for entry in tar.entries().with_context(|| format!("reading {name}"))? {
            let mut entry = entry.with_context(|| format!("reading {name}"))?;
            if entry.path()?.to_str() == Some(want.as_str()) {
                ensure!(
                    entry.header().entry_type().is_file(),
                    "{want} in {name} is not a regular file"
                );
                return read_capped(&mut entry, &name);
            }
        }
    }
    bail!("{name} does not contain the kubera executable")
}

fn read_capped(r: &mut impl Read, name: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    r.take(MAX_BINARY + 1)
        .read_to_end(&mut out)
        .with_context(|| format!("extracting from {name}"))?;
    ensure!(
        out.len() as u64 <= MAX_BINARY,
        "the binary in {name} is too large"
    );
    ensure!(!out.is_empty(), "the binary in {name} is empty");
    Ok(out)
}

/// A package manager that owns an installed binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Homebrew,
    Nix,
    Cargo,
    Scoop,
    Winget,
    /// The operating system's package manager (pacman for the AUR's
    /// kubera-bin, apt, dnf, pkg and so on).
    System,
}

impl Manager {
    pub fn name(self) -> &'static str {
        match self {
            Manager::Homebrew => "Homebrew",
            Manager::Nix => "Nix",
            Manager::Cargo => "cargo",
            Manager::Scoop => "Scoop",
            Manager::Winget => "winget",
            Manager::System => "the system package manager",
        }
    }

    /// The command that upgrades kubera through this package manager.
    pub fn upgrade_command(self) -> &'static str {
        match self {
            Manager::Homebrew => "brew upgrade kubera",
            Manager::Nix => {
                "nix profile upgrade kubera (or update the flake input that provides it)"
            }
            Manager::Cargo => "cargo install kubera-cli --locked",
            Manager::Scoop => "scoop update kubera",
            Manager::Winget => "winget upgrade dmdhrumilmistry.kubera",
            Manager::System => "your package manager, e.g. paru -Syu kubera-bin on Arch Linux",
        }
    }
}

/// Which package manager, if any, owns the executable at `exe`, judged by
/// its path. `cargo_home` is `$CARGO_HOME` (default `~/.cargo`).
pub fn managed_by(exe: &Path, cargo_home: Option<&Path>) -> Option<Manager> {
    let s = exe.to_string_lossy().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    if s.starts_with("/nix/store/") {
        return Some(Manager::Nix);
    }
    if s.contains("/Cellar/")
        || s.starts_with("/opt/homebrew/")
        || s.starts_with("/home/linuxbrew/.linuxbrew/")
        || s.contains("/.linuxbrew/")
    {
        return Some(Manager::Homebrew);
    }
    if lower.contains("/scoop/apps/") || lower.contains("/scoop/shims/") {
        return Some(Manager::Scoop);
    }
    if lower.contains("/microsoft/winget/") {
        return Some(Manager::Winget);
    }
    let parent = exe.parent();
    if let (Some(home), Some(parent)) = (cargo_home, parent)
        && same_dir(parent, &home.join("bin"))
    {
        return Some(Manager::Cargo);
    }
    if lower.contains("/.cargo/bin/") {
        return Some(Manager::Cargo);
    }
    let parent = parent.map(|p| p.to_string_lossy().replace('\\', "/"));
    if matches!(
        parent.as_deref(),
        Some("/usr/bin" | "/bin" | "/usr/sbin" | "/sbin")
    ) {
        return Some(Manager::System);
    }
    None
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Fail early, before downloading, if `exe`'s directory is not writable.
pub fn check_writable(exe: &Path) -> Result<()> {
    let dir = exe_dir(exe)?;
    match tempfile::Builder::new()
        .prefix(".kubera-update-")
        .tempfile_in(dir)
    {
        Ok(_) => Ok(()),
        Err(e) => {
            let mut msg = format!("cannot write to {}: {e}", dir.display());
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                msg.push_str("; re-run with the permissions used to install kubera");
            }
            if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
                msg.push_str(
                    " (in the kubera container image, pull a newer image instead: \
                     docker pull ghcr.io/dmdhrumilmistry/kubera:latest)",
                );
            }
            bail!(msg)
        }
    }
}

fn exe_dir(exe: &Path) -> Result<&Path> {
    exe.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .with_context(|| format!("{} has no parent directory", exe.display()))
}

/// Run the freshly written binary once; it must report `version`.
fn check_new_binary(path: &Path, version: &Version) -> Result<()> {
    let out = std::process::Command::new(path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()
        .context("running the downloaded kubera")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    ensure!(
        out.status.success() && stdout.split_whitespace().any(|w| w == version.to_string()),
        "the downloaded kubera does not run on this system or is not version {version} \
         (`--version` printed {:?}); nothing was changed",
        stdout.trim()
    );
    Ok(())
}

/// Atomically replace the executable at `exe` with `binary`.
///
/// Unix: the new file is written in the same directory, fsynced, checked,
/// renamed over `exe` (atomic), and the directory is fsynced. Windows: a
/// running executable cannot be overwritten but can be renamed, so the old
/// one is moved to `<name>.old` first (removed now if possible, else on the
/// next update) and moved back if the new one cannot be put in place.
pub fn replace_exe(exe: &Path, binary: &[u8], version: &Version) -> Result<()> {
    let dir = exe_dir(exe)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(".kubera-update-");
    if cfg!(windows) {
        builder.suffix(".exe");
    }
    let mut tmp = builder
        .tempfile_in(dir)
        .with_context(|| format!("creating a temporary file in {}", dir.display()))?;
    tmp.write_all(binary).context("writing the new binary")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(exe)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o755)
            | 0o500;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .context("making the new binary executable")?;
    }
    tmp.as_file()
        .sync_all()
        .context("flushing the new binary")?;
    // Close it before running it (Linux refuses to exec an open file).
    let tmp = tmp.into_temp_path();
    check_new_binary(&tmp, version)?;

    #[cfg(not(windows))]
    {
        tmp.persist(exe)
            .map_err(|e| e.error)
            .with_context(|| format!("replacing {}", exe.display()))?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(windows)]
    {
        let old = old_path(exe);
        let _ = std::fs::remove_file(&old);
        std::fs::rename(exe, &old).with_context(|| format!("moving {} aside", exe.display()))?;
        if let Err(e) = tmp.persist(exe) {
            let _ = std::fs::rename(&old, exe);
            return Err(e.error).with_context(|| format!("replacing {}", exe.display()));
        }
        // Fails while the old binary is still running; the next update
        // removes it.
        let _ = std::fs::remove_file(&old);
    }
    Ok(())
}

/// Where Windows keeps the previous executable during an update.
pub fn old_path(exe: &Path) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(".old");
    exe.with_file_name(name)
}

/// Verify the archive's GitHub build provenance with `gh attestation
/// verify` (opt-in: `KUBERA_VERIFY_ATTESTATION=1`).
pub fn verify_attestation(archive: &[u8], name: &str) -> Result<()> {
    let dir = tempfile::tempdir().context("creating a temporary directory")?;
    let path = dir.path().join(name);
    std::fs::write(&path, archive).context("writing the archive for gh")?;
    let status = std::process::Command::new("gh")
        .args(["attestation", "verify"])
        .arg(&path)
        .args(["--repo", REPO, "--signer-workflow", RELEASE_WORKFLOW])
        .stdout(std::process::Stdio::null())
        .status()
        .context(
            "running `gh attestation verify` (KUBERA_VERIFY_ATTESTATION=1 needs the GitHub CLI)",
        )?;
    ensure!(
        status.success(),
        "attestation verification failed for {name}; nothing was changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_targets_map_to_themselves() {
        for t in RELEASE_TARGETS {
            assert_eq!(release_target(t), Some(*t));
        }
    }

    #[test]
    fn source_builds_map_like_install_sh() {
        assert_eq!(
            release_target("x86_64-unknown-linux-gnu"),
            Some("x86_64-unknown-linux-musl")
        );
        assert_eq!(
            release_target("armv7-unknown-linux-gnueabihf"),
            Some("armv7-unknown-linux-musleabihf")
        );
        assert_eq!(
            release_target("arm-unknown-linux-gnueabihf"),
            Some("arm-unknown-linux-musleabihf")
        );
        assert_eq!(
            release_target("x86_64-pc-windows-gnu"),
            Some("x86_64-pc-windows-msvc")
        );
        assert_eq!(release_target("powerpc64le-unknown-linux-gnu"), None);
        assert_eq!(
            target_for("android", "aarch64"),
            Some("aarch64-linux-android")
        );
        assert_eq!(target_for("macos", "aarch64"), Some("aarch64-apple-darwin"));
        assert_eq!(target_for("linux", "arm"), None);
        assert_eq!(
            asset_name("aarch64-pc-windows-msvc"),
            "kubera-aarch64-pc-windows-msvc.zip"
        );
        assert_eq!(
            asset_name("aarch64-linux-android"),
            "kubera-aarch64-linux-android.tar.gz"
        );
    }

    #[test]
    fn this_build_has_a_target_string() {
        assert!(!BUILD_TARGET.is_empty());
    }

    #[test]
    fn versions_compare_like_semver() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("0.10.0") > v("0.9.9"));
        assert!(v("v1.0.0") > v("1.0.0-rc.2"));
        assert!(v("1.0.0-rc.10") > v("1.0.0-rc.2"));
        assert!(v("1.0.0-beta") > v("1.0.0-alpha.1"));
        assert_eq!(v("v0.2.0"), v("0.2.0"));
        assert_eq!(v("1.2.3-rc.1").to_string(), "1.2.3-rc.1");
        for bad in [
            "1.2",
            "1.2.3.4",
            "1.x.3",
            "",
            "v",
            "1.2.3-",
            "1.2.3-a..b",
            "../1.2.3",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad}");
        }
        assert!(normalize_tag("0.3.0").unwrap() == "v0.3.0");
        assert!(normalize_tag("latest/../x").is_err());
    }

    #[test]
    fn checksum_files() {
        let h = "a".repeat(64);
        let name = "kubera-x86_64-pc-windows-msvc.zip";
        assert_eq!(
            parse_checksum(format!("{h}  {name}\r\n").as_bytes(), name).unwrap(),
            h
        );
        assert_eq!(
            parse_checksum(format!("{}\n", h.to_uppercase()).as_bytes(), name).unwrap(),
            h
        );
        assert_eq!(
            parse_checksum(format!("{h} *{name}\n").as_bytes(), name).unwrap(),
            h
        );
        assert!(parse_checksum(format!("{h}  other.zip\n").as_bytes(), name).is_err());
        assert!(parse_checksum(b"not a hash\n", name).is_err());
        assert!(parse_checksum(b"", name).is_err());
    }

    #[test]
    fn package_manager_paths() {
        let m = |p: &str| managed_by(Path::new(p), Some(Path::new("/home/u/.cargo")));
        assert_eq!(m("/opt/homebrew/bin/kubera"), Some(Manager::Homebrew));
        assert_eq!(
            m("/usr/local/Cellar/kubera/0.2.0/bin/kubera"),
            Some(Manager::Homebrew)
        );
        assert_eq!(
            m("/home/linuxbrew/.linuxbrew/bin/kubera"),
            Some(Manager::Homebrew)
        );
        assert_eq!(
            m("/nix/store/abc-kubera-0.2.0/bin/kubera"),
            Some(Manager::Nix)
        );
        assert_eq!(m("/home/u/.cargo/bin/kubera"), Some(Manager::Cargo));
        assert_eq!(m("/root/.cargo/bin/kubera"), Some(Manager::Cargo));
        assert_eq!(m("/usr/bin/kubera"), Some(Manager::System));
        assert_eq!(
            m(r"C:\Users\u\scoop\apps\kubera\current\kubera.exe"),
            Some(Manager::Scoop)
        );
        assert_eq!(
            m(
                r"C:\Users\u\AppData\Local\Microsoft\WinGet\Packages\dmdhrumilmistry.kubera_x\kubera.exe"
            ),
            Some(Manager::Winget)
        );
        assert_eq!(m("/home/u/.local/bin/kubera"), None);
        assert_eq!(m("/usr/local/bin/kubera"), None);
        assert_eq!(m("/data/data/com.termux/files/usr/bin/kubera"), None);
        assert_eq!(
            m(r"C:\Users\u\AppData\Local\Programs\kubera\bin\kubera.exe"),
            None
        );
    }

    #[test]
    fn extracts_from_zip_and_tar() {
        let exe = b"MZ fake".to_vec();
        let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
        z.start_file("README.md", zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(b"readme").unwrap();
        z.start_file("kubera.exe", zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(&exe).unwrap();
        let zip = z.finish().unwrap().into_inner();
        assert_eq!(extract_binary(&zip, "x86_64-pc-windows-msvc").unwrap(), exe);

        let t = "aarch64-apple-darwin";
        let mut tar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(4);
        h.set_mode(0o755);
        h.set_cksum();
        tar.append_data(&mut h, format!("kubera-{t}/kubera"), &b"\x7fELF"[..])
            .unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar.into_inner().unwrap()).unwrap();
        let tgz = gz.finish().unwrap();
        assert_eq!(extract_binary(&tgz, t).unwrap(), b"\x7fELF");
        // The archive of another target does not have this path.
        assert!(extract_binary(&tgz, "x86_64-apple-darwin").is_err());
    }

    #[test]
    fn old_path_appends_suffix() {
        assert_eq!(
            old_path(Path::new("/x/kubera.exe")),
            Path::new("/x/kubera.exe.old")
        );
    }
}
