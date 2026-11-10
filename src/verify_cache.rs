//! Persistent cache of verification results (`--verify-cache`).
//!
//! Scheduled CI runs and mass scans find the same secrets again and again,
//! and verifying them again sends the same requests to the same vendors.
//! With the cache enabled, a result is reused while it is fresh:
//!
//! * **live** results for [`DEFAULT_LIVE_TTL`] (1 hour), so a key revoked
//!   during incident response shows up as revoked on the next hourly run;
//! * **invalid** results for [`DEFAULT_INVALID_TTL`] (24 hours): a revoked,
//!   expired or fake credential practically never comes back to life;
//! * **unknown** results (network errors, rate limits, odd responses) are
//!   not cached by default, so the next run asks again.
//!
//! Entries are keyed by finding fingerprint (a truncated SHA-256 of the
//! detector and secret, which cannot be reversed) and also record a hash of
//! the template's verifier, so editing a template re-verifies its secrets.
//! They hold the status, the (already masked) message, the extracted details
//! (account names, scopes; extractors marked `secret` are redacted) and the
//! time of the check, never a secret value. The file is still treated as
//! sensitive: it is written atomically with mode `0600`, in a directory
//! created with mode `0700`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::finding::{Status, Verification};
use crate::template::Template;

const VERSION: u32 = 1;
/// Reuse of a live result.
pub const DEFAULT_LIVE_TTL: Duration = Duration::from_secs(3600);
/// Reuse of an invalid result.
pub const DEFAULT_INVALID_TTL: Duration = Duration::from_secs(24 * 3600);
/// Entries older than this (or than the longest TTL, if longer) are dropped
/// when the file is written.
const KEEP: Duration = Duration::from_secs(30 * 24 * 3600);

/// How long a result of each status may be reused (`0`: never cached).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl {
    pub live: Duration,
    pub invalid: Duration,
    pub unknown: Duration,
}

impl Default for Ttl {
    fn default() -> Self {
        Self {
            live: DEFAULT_LIVE_TTL,
            invalid: DEFAULT_INVALID_TTL,
            unknown: Duration::ZERO,
        }
    }
}

impl Ttl {
    /// Apply `live=1h,invalid=7d,unknown=10m` (any subset), or a bare
    /// duration that sets both `live` and `invalid`.
    pub fn apply(&mut self, spec: &str) -> Result<()> {
        for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match item.split_once('=') {
                None => {
                    let d = parse_duration(item)?;
                    self.live = d;
                    self.invalid = d;
                }
                Some((k, v)) => {
                    let d = parse_duration(v.trim())?;
                    match k.trim() {
                        "live" | "verified" => self.live = d,
                        "invalid" => self.invalid = d,
                        "unknown" => self.unknown = d,
                        other => bail!(
                            "unknown status `{other}` in cache TTL `{spec}` (use live, invalid or unknown)"
                        ),
                    }
                }
            }
        }
        Ok(())
    }

    fn of(&self, s: Status) -> Duration {
        match s {
            Status::Verified => self.live,
            Status::Invalid => self.invalid,
            Status::Unknown => self.unknown,
            // No request is sent for these anyway.
            Status::Unsupported => Duration::ZERO,
        }
    }

    fn longest(&self) -> Duration {
        self.live.max(self.invalid).max(self.unknown)
    }
}

/// `0`, `90s`, `15m`, `1h`, `7d` (a bare number is seconds).
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => s.split_at(i),
        None => (s, "s"),
    };
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid duration `{s}` (examples: 0, 90s, 15m, 1h, 7d)"))?;
    let secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => bail!("invalid duration `{s}` (examples: 0, 90s, 15m, 1h, 7d)"),
    };
    n.checked_mul(secs)
        .map(Duration::from_secs)
        .with_context(|| format!("duration `{s}` is too long"))
}

/// Default cache file: `$XDG_CACHE_HOME/kubera/verify.json`, else
/// `~/.cache/kubera/verify.json`; `%LOCALAPPDATA%\kubera\verify.json` on
/// Windows.
pub fn default_path() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        env("LOCALAPPDATA")
    } else {
        env("XDG_CACHE_HOME")
            .filter(|p| p.is_absolute())
            .or_else(|| env("HOME").map(|h| h.join(".cache")))
    }?;
    Some(base.join("kubera").join("verify.json"))
}

/// Where the cache settings come from: the config file and command-line
/// flags (which win).
#[derive(Debug, Default, Clone)]
pub struct Request<'a> {
    pub config: Option<&'a crate::config::VerifyCacheSetting>,
    /// `--verify-cache[=FILE]`: `Some(None)` for the default location.
    pub flag: Option<Option<PathBuf>>,
    /// `--no-verify-cache`.
    pub disabled: bool,
    /// `--verify-cache-ttl` values (setting one also enables the cache).
    pub ttl: Vec<String>,
}

/// The cache to use, if any.
pub fn resolve(req: &Request) -> Result<Option<Cache>> {
    use crate::config::VerifyCacheSetting as S;
    if req.disabled {
        return Ok(None);
    }
    let mut ttl = Ttl::default();
    let mut path = None;
    let mut enabled = false;
    match req.config {
        Some(S::Enabled(on)) => enabled = *on,
        Some(S::Settings(c)) => {
            enabled = true;
            path = c.path.clone();
            for (status, d) in &c.ttl {
                ttl.apply(&format!("{status}={d}"))
                    .context("verify_cache.ttl in the config file")?;
            }
        }
        None => {}
    }
    if let Some(flag) = &req.flag {
        enabled = true;
        if let Some(p) = flag {
            path = Some(p.clone());
        }
    }
    for spec in &req.ttl {
        enabled = true;
        ttl.apply(spec).context("--verify-cache-ttl")?;
    }
    if !enabled {
        return Ok(None);
    }
    let path = match path.or_else(default_path) {
        Some(p) => p,
        None => bail!(
            "no cache directory (HOME / XDG_CACHE_HOME / LOCALAPPDATA unset); pass --verify-cache=FILE"
        ),
    };
    Ok(Some(Cache::open(&path, ttl)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    details: BTreeMap<String, Value>,
    /// When the platform was asked (RFC 3339, UTC).
    checked_at: String,
    /// Hash of the template's verifier when the result was obtained.
    verifier: String,
}

impl Entry {
    fn age(&self, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
        let at = chrono::DateTime::parse_from_rfc3339(&self.checked_at).ok()?;
        // A time in the future (clock changed) counts as expired.
        (now - at.with_timezone(&chrono::Utc)).to_std().ok()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct FileData {
    version: u32,
    entries: BTreeMap<String, Entry>,
}

/// Hash of what decides a template's verification result.
fn verifier_hash(t: &Template) -> String {
    let spec = serde_json::to_string(&t.verify).unwrap_or_default();
    hex::encode(&Sha256::digest(spec.as_bytes())[..8])
}

pub struct Cache {
    path: PathBuf,
    ttl: Ttl,
    entries: Mutex<BTreeMap<String, Entry>>,
    dirty: AtomicBool,
}

impl Cache {
    /// Open the cache at `path`. A missing, unreadable or corrupt file is
    /// not an error (it is a cache): it starts empty and is replaced on
    /// [`Cache::save`].
    pub fn open(path: &Path, ttl: Ttl) -> Self {
        let entries = match read(path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("warning: verification cache {}: {e:#}", path.display());
                BTreeMap::new()
            }
        };
        Self {
            path: path.to_path_buf(),
            ttl,
            entries: Mutex::new(entries),
            dirty: AtomicBool::new(false),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// A fresh cached result for `fingerprint`, marked as cached.
    pub fn get(&self, fingerprint: &str, t: &Template) -> Option<Verification> {
        let entries = self.entries.lock().unwrap();
        let e = entries.get(fingerprint)?;
        let ttl = self.ttl.of(e.status);
        let fresh = e.age(chrono::Utc::now()).is_some_and(|age| age < ttl);
        if !fresh || e.verifier != verifier_hash(t) {
            return None;
        }
        Some(Verification {
            status: e.status,
            message: e.message.clone(),
            details: e.details.clone(),
            cached: true,
            checked_at: Some(e.checked_at.clone()),
        })
    }

    /// Remember a result just obtained from the platform. Statuses with a
    /// zero TTL are not stored.
    pub fn put(&self, fingerprint: &str, t: &Template, v: &Verification) {
        if v.cached || self.ttl.of(v.status).is_zero() {
            return;
        }
        self.entries.lock().unwrap().insert(
            fingerprint.to_string(),
            Entry {
                status: v.status,
                message: v.message.clone(),
                details: v.details.clone(),
                checked_at: crate::state::now(),
                verifier: verifier_hash(t),
            },
        );
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Write new results to disk, merged with entries other processes wrote
    /// meanwhile (the newest check wins) and without stale entries.
    pub fn save(&self) -> Result<()> {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        let mut merged = read(&self.path).unwrap_or_default();
        for (fp, e) in self.entries.lock().unwrap().iter() {
            let newer = merged
                .get(fp)
                .is_none_or(|old| old.checked_at <= e.checked_at);
            if newer {
                merged.insert(fp.clone(), e.clone());
            }
        }
        let now = chrono::Utc::now();
        let keep = KEEP.max(self.ttl.longest());
        merged.retain(|_, e| e.age(now).is_some_and(|a| a < keep));
        let mut data = serde_json::to_vec_pretty(&FileData {
            version: VERSION,
            entries: merged,
        })?;
        data.push(b'\n');
        if let Some(dir) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_private_dir(dir)?;
        }
        crate::state::write_private(&self.path, &data)
            .with_context(|| format!("writing verification cache {}", self.path.display()))
    }
}

fn read(path: &Path) -> Result<BTreeMap<String, Entry>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e).context("reading it"),
    };
    let f: FileData = serde_json::from_slice(&bytes).context("not a kubera cache file")?;
    if f.version != VERSION {
        bail!("unsupported version {}; starting a new cache", f.version);
    }
    Ok(f.entries)
}

/// Create `dir` (and parents) when missing; the last component gets mode
/// `0700` on Unix. Existing directories are left as they are.
fn create_private_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    match b.create(dir) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            Err(e).with_context(|| format!("creating {}", dir.display()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(url: &str) -> Template {
        let yaml = format!(
            r#"
id: t
name: T
detect:
  keywords: [t_]
  patterns:
    - name: token
      regex: 't_[a-z]{{8}}'
verify:
  request: {{ url: "{url}" }}
  valid: {{ status: [200] }}
  invalid: {{ status: [401] }}
"#
        );
        crate::template::parse(&yaml, "test").unwrap()
    }

    fn result(status: Status) -> Verification {
        Verification {
            status,
            message: Some("m".into()),
            details: BTreeMap::from([("Owner".to_string(), Value::from("alice"))]),
            cached: false,
            checked_at: None,
        }
    }

    #[test]
    fn durations_and_ttl_specs() {
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
        assert!(parse_duration("1w").is_err() && parse_duration("h").is_err());
        let mut t = Ttl::default();
        assert_eq!(t.unknown, Duration::ZERO);
        t.apply("live=10m, unknown=5m").unwrap();
        assert_eq!(t.live, Duration::from_secs(600));
        assert_eq!(t.invalid, DEFAULT_INVALID_TTL);
        assert_eq!(t.unknown, Duration::from_secs(300));
        t.apply("3h").unwrap();
        assert_eq!(
            (t.live, t.invalid),
            (Duration::from_secs(10_800), Duration::from_secs(10_800))
        );
        assert!(t.apply("revoked=1h").is_err());
    }

    #[test]
    fn roundtrip_freshness_verifier_and_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/verify.json");
        let t = template("https://a.example/me");
        let c = Cache::open(&path, Ttl::default());
        assert!(c.get("fp1", &t).is_none());
        c.put("fp1", &t, &result(Status::Verified));
        c.put("fp2", &t, &result(Status::Unknown)); // not cached by default
        c.save().unwrap();

        let c = Cache::open(&path, Ttl::default());
        let v = c.get("fp1", &t).unwrap();
        assert!(v.cached && v.checked_at.is_some());
        assert_eq!(v.details["Owner"], "alice");
        assert!(c.get("fp2", &t).is_none());
        // Another verifier (edited template) does not reuse the result.
        assert!(c.get("fp1", &template("https://b.example/me")).is_none());
        // A zero TTL disables reuse without deleting the entry.
        let strict = Cache::open(
            &path,
            Ttl {
                live: Duration::ZERO,
                ..Ttl::default()
            },
        );
        assert!(strict.get("fp1", &t).is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("fp1") && !text.contains("fp2"));
    }

    #[test]
    fn stale_entries_expire_and_corrupt_files_are_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify.json");
        let t = template("https://a.example/me");
        let old = |status: &str, hours: i64| {
            let at = (chrono::Utc::now() - chrono::Duration::hours(hours))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            serde_json::json!({"status": status, "checked_at": at, "verifier": verifier_hash(&t)})
        };
        let file = serde_json::json!({"version": 1, "entries": {
            "live2h": old("verified", 2), "invalid2h": old("invalid", 2),
            "ancient": old("invalid", 24 * 400), "future": old("invalid", -5),
        }});
        std::fs::write(&path, file.to_string()).unwrap();
        let c = Cache::open(&path, Ttl::default());
        assert!(
            c.get("live2h", &t).is_none(),
            "live results expire after 1h"
        );
        assert!(c.get("invalid2h", &t).is_some());
        assert!(c.get("future", &t).is_none());
        c.put("new", &t, &result(Status::Invalid));
        c.save().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("invalid2h") && text.contains("new") && !text.contains("ancient"));

        std::fs::write(&path, "not json").unwrap();
        let c = Cache::open(&path, Ttl::default());
        assert!(c.get("new", &t).is_none());
        c.put("again", &t, &result(Status::Invalid));
        c.save().unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("again"));
    }
}
