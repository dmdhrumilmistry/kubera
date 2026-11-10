//! Findings database: every scan recorded, for trends and a dashboard
//! (`kubera serve`).
//!
//! Storage is one JSON-lines file (default
//! `<user data dir>/kubera/findings.jsonl`): one line per scan, appended
//! with a single write, so the file never needs rewriting and stays
//! readable with `jq`. It is created with mode `0600` in a `0700`
//! directory. **No secret values are stored**: findings are redacted
//! first and identified by fingerprint, exactly like `-f json` output.
//!
//! Per finding the aggregate view (see [`Aggregate`]) derives first / last
//! seen, how many scans reported it, the latest verification status, the
//! triage decision recorded in the baseline, and a state:
//!
//! * `triaged` - the baseline in effect at the latest scan has a decision;
//! * `resolved` - a later *full* scan of every target it was seen in no
//!   longer reports it (incremental scans never resolve anything, since
//!   they only read new commits);
//! * `open` - otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::baseline::Baseline;
use crate::finding::{Finding, Status};

pub const VERSION: u32 = 1;
pub const FILE_NAME: &str = "findings.jsonl";

/// Where user data lives: `$XDG_DATA_HOME` or `~/.local/share` (Linux,
/// BSD, Android), `~/Library/Application Support` (macOS),
/// `%LOCALAPPDATA%` (Windows).
pub fn data_dir() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        return env("LOCALAPPDATA").or_else(|| env("APPDATA"));
    }
    if cfg!(target_os = "macos") {
        return env("HOME").map(|h| h.join("Library/Application Support"));
    }
    env("XDG_DATA_HOME")
        .filter(|p| p.is_absolute())
        .or_else(|| env("HOME").map(|h| h.join(".local/share")))
}

/// The default database file.
pub fn default_path() -> Result<PathBuf> {
    Ok(data_dir()
        .context("cannot find a user data directory (set HOME); pass --db PATH")?
        .join("kubera")
        .join(FILE_NAME))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    pub total: usize,
    pub live: usize,
    pub invalid: usize,
    pub unknown: usize,
    pub unsupported: usize,
    pub unverified: usize,
}

impl Counts {
    pub fn of(findings: &[FindingRecord]) -> Self {
        let mut c = Counts::default();
        let mut seen = BTreeSet::new();
        for f in findings {
            if !seen.insert(&f.fingerprint) {
                continue;
            }
            c.total += 1;
            match f.status {
                Some(Status::Verified) => c.live += 1,
                Some(Status::Invalid) => c.invalid += 1,
                Some(Status::Unknown) => c.unknown += 1,
                Some(Status::Unsupported) => c.unsupported += 1,
                None => c.unverified += 1,
            }
        }
        c
    }
}

/// One finding as stored: redacted, no secret values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingRecord {
    pub fingerprint: String,
    pub detector: String,
    pub name: String,
    #[serde(default)]
    pub platform: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// Redacted secret parts (`ghp_********Uo`), for recognition only.
    #[serde(default)]
    pub preview: String,
    #[serde(default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub line: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Commit date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

impl FindingRecord {
    pub fn from_finding(f: &Finding) -> Self {
        // Whatever the caller passed, only redacted values are kept.
        let r = if f.redacted { f.clone() } else { f.redact() };
        let l = &r.location;
        let path = l.path.clone().map(|p| match &l.entry {
            Some(e) => format!("{p}!/{e}"),
            None => p,
        });
        Self {
            fingerprint: r.fingerprint.clone(),
            detector: r.detector.clone(),
            name: r.name.clone(),
            platform: r.platform.clone(),
            severity: r.severity.to_string(),
            status: r.status(),
            preview: r
                .secret
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" "),
            source: serde_json::to_value(l.source)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            repository: l.repository.clone(),
            path,
            line: l.line,
            commit: l.commit.clone(),
            date: l.date.clone(),
            link: l.link.clone(),
        }
    }
}

/// One scan (one line of the file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub version: u32,
    pub id: String,
    /// RFC 3339 UTC.
    pub time: String,
    /// What was scanned (a repository URL, a canonical path, an image...).
    pub target: String,
    /// `fs`, `git`, `repos`, `image`, `github`, `bucket`, `k8s`, `stdin`,
    /// `staged`.
    pub kind: String,
    /// Only part of the target was read (new commits, staged changes), so
    /// a missing finding does not mean it is gone.
    #[serde(default)]
    pub incremental: bool,
    /// Verification ran.
    #[serde(default)]
    pub verified: bool,
    pub counts: Counts,
    pub findings: Vec<FindingRecord>,
    /// Triage decisions of the baseline in effect (fingerprint -> decision).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub decisions: BTreeMap<String, String>,
    #[serde(default)]
    pub kubera: String,
}

impl ScanRecord {
    pub fn new(
        target: &str,
        kind: &str,
        incremental: bool,
        verified: bool,
        findings: &[Finding],
        baseline: Option<&Baseline>,
    ) -> Self {
        let findings: Vec<FindingRecord> =
            findings.iter().map(FindingRecord::from_finding).collect();
        let time = crate::state::now();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        Self {
            version: VERSION,
            id: format!(
                "{}-{:08x}",
                time.replace([':', '-'], ""),
                nanos ^ std::process::id()
            ),
            time,
            target: target.to_string(),
            kind: kind.to_string(),
            incremental,
            verified,
            counts: Counts::of(&findings),
            findings,
            decisions: baseline
                .map(|b| {
                    b.entries
                        .iter()
                        .map(|e| (e.fingerprint.clone(), e.decision.label().to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            kubera: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Append one scan. The line is written with a single `write` on a file
/// opened for appending, so concurrent scans do not interleave.
pub fn append(path: &Path, rec: &ScanRecord) -> Result<()> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut line = serde_json::to_vec(rec)?;
    line.push(b'\n');
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    // A torn last line (an interrupted write) must not swallow this one.
    if !ends_with_newline(path) {
        line.insert(0, b'\n');
    }
    f.write_all(&line)
        .with_context(|| format!("writing {}", path.display()))?;
    f.sync_data()?;
    Ok(())
}

fn ends_with_newline(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return true;
    };
    if f.seek(SeekFrom::End(-1)).is_err() {
        return true; // empty
    }
    let mut b = [0u8; 1];
    f.read_exact(&mut b).is_err() || b[0] == b'\n'
}

/// Every scan in the file, oldest first. A missing file is empty; lines
/// that do not parse (an interrupted write) are counted and skipped.
pub fn load(path: &Path) -> Result<(Vec<ScanRecord>, usize)> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut scans = Vec::new();
    let mut bad = 0;
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<ScanRecord>(l) {
            Ok(r) if r.version == VERSION => scans.push(r),
            _ => bad += 1,
        }
    }
    // Stable: same-second scans keep their file order.
    scans.sort_by(|a, b| a.time.cmp(&b.time));
    Ok((scans, bad))
}

#[derive(Debug, Clone, Serialize)]
pub struct Place {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

/// One secret across every scan.
#[derive(Debug, Clone, Serialize)]
pub struct FindingView {
    pub fingerprint: String,
    pub detector: String,
    pub name: String,
    pub platform: String,
    pub severity: String,
    /// Latest verification result: `live`, `invalid`, `unknown`,
    /// `unsupported`, or `unverified` (never verified).
    pub status: String,
    /// `open`, `resolved` or `triaged`.
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    /// Scans that reported it.
    pub times_seen: usize,
    pub preview: String,
    /// Targets (scans) it was reported by.
    pub targets: Vec<String>,
    /// Repositories (or targets, when the finding has none).
    pub repositories: Vec<String>,
    /// Distinct places, most recent first (at most 50).
    pub locations: Vec<Place>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanView {
    pub id: String,
    pub time: String,
    pub target: String,
    pub kind: String,
    pub incremental: bool,
    pub verified: bool,
    pub counts: Counts,
    /// Fingerprints first seen in this scan.
    pub new: usize,
    /// Every fingerprint reported, and the live subset (for trends).
    pub fingerprints: Vec<String>,
    pub live: Vec<String>,
}

pub fn status_label(s: Option<Status>) -> &'static str {
    match s {
        Some(Status::Verified) => "live",
        Some(Status::Invalid) => "invalid",
        Some(Status::Unknown) => "unknown",
        Some(Status::Unsupported) => "unsupported",
        None => "unverified",
    }
}

/// The database folded into per-finding and per-scan views.
#[derive(Debug, Clone, Serialize)]
pub struct Aggregate {
    pub findings: Vec<FindingView>,
    /// Newest first.
    pub scans: Vec<ScanView>,
    pub skipped_lines: usize,
}

pub fn aggregate(scans: &[ScanRecord], skipped_lines: usize) -> Aggregate {
    struct Acc {
        latest: FindingRecord,
        status: Option<Status>,
        first: usize,
        last: usize,
        times: usize,
        /// target -> index of the last scan of it reporting this finding.
        targets: BTreeMap<String, usize>,
        repos: BTreeSet<String>,
        places: Vec<(usize, Place)>,
    }
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    let mut first_seen_in: Vec<usize> = vec![0; scans.len()];
    for (i, s) in scans.iter().enumerate() {
        let mut in_scan = BTreeSet::new();
        for r in &s.findings {
            let new_here = !acc.contains_key(&r.fingerprint);
            let a = acc.entry(r.fingerprint.clone()).or_insert_with(|| Acc {
                latest: r.clone(),
                status: None,
                first: i,
                last: i,
                times: 0,
                targets: BTreeMap::new(),
                repos: BTreeSet::new(),
                places: Vec::new(),
            });
            if new_here {
                first_seen_in[i] += 1;
            }
            a.latest = r.clone();
            a.last = i;
            if r.status.is_some() {
                a.status = r.status;
            }
            if in_scan.insert(r.fingerprint.clone()) {
                a.times += 1;
            }
            a.targets.insert(s.target.clone(), i);
            a.repos
                .insert(r.repository.clone().unwrap_or_else(|| s.target.clone()));
            let place = Place {
                repository: r.repository.clone(),
                path: r.path.clone(),
                line: r.line,
                commit: r.commit.clone(),
                date: r.date.clone(),
                link: r.link.clone(),
            };
            let same = |p: &Place| {
                p.repository == place.repository
                    && p.path == place.path
                    && p.line == place.line
                    && p.commit == place.commit
            };
            match a.places.iter_mut().find(|(_, p)| same(p)) {
                Some(e) => e.0 = i,
                None => a.places.push((i, place)),
            }
        }
    }
    // Latest full scan per target.
    let mut last_full: BTreeMap<&str, usize> = BTreeMap::new();
    let mut last_any: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, s) in scans.iter().enumerate() {
        last_any.insert(&s.target, i);
        if !s.incremental {
            last_full.insert(&s.target, i);
        }
    }
    let mut findings: Vec<FindingView> = acc
        .into_iter()
        .map(|(fp, mut a)| {
            // The decision recorded by the most recent scan of any target
            // the finding was seen in.
            let latest_scan = a
                .targets
                .keys()
                .filter_map(|t| last_any.get(t.as_str()).copied())
                .max()
                .unwrap_or(a.last);
            let decision = scans[latest_scan].decisions.get(&fp).cloned();
            let resolved = a
                .targets
                .iter()
                .all(|(t, seen)| last_full.get(t.as_str()).is_some_and(|f| f > seen));
            let state = if decision.is_some() {
                "triaged"
            } else if resolved {
                "resolved"
            } else {
                "open"
            };
            a.places.sort_by_key(|p| std::cmp::Reverse(p.0));
            a.places.truncate(50);
            FindingView {
                fingerprint: fp,
                detector: a.latest.detector.clone(),
                name: a.latest.name.clone(),
                platform: a.latest.platform.clone(),
                severity: a.latest.severity.clone(),
                status: status_label(a.status).into(),
                state: state.into(),
                decision,
                first_seen: scans[a.first].time.clone(),
                last_seen: scans[a.last].time.clone(),
                times_seen: a.times,
                preview: a.latest.preview.clone(),
                targets: a.targets.keys().cloned().collect(),
                repositories: a.repos.into_iter().collect(),
                locations: a.places.into_iter().map(|(_, p)| p).collect(),
            }
        })
        .collect();
    let rank = |f: &FindingView| {
        (
            match f.state.as_str() {
                "open" => 0,
                "triaged" => 1,
                _ => 2,
            },
            if f.status == "live" { 0 } else { 1 },
            std::cmp::Reverse(f.last_seen.clone()),
        )
    };
    findings.sort_by_key(rank);
    let mut views: Vec<ScanView> = scans
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut fps = BTreeSet::new();
            let mut live = BTreeSet::new();
            for f in &s.findings {
                fps.insert(f.fingerprint.clone());
                if f.status == Some(Status::Verified) {
                    live.insert(f.fingerprint.clone());
                }
            }
            ScanView {
                id: s.id.clone(),
                time: s.time.clone(),
                target: s.target.clone(),
                kind: s.kind.clone(),
                incremental: s.incremental,
                verified: s.verified,
                counts: s.counts.clone(),
                new: first_seen_in[i],
                fingerprints: fps.into_iter().collect(),
                live: live.into_iter().collect(),
            }
        })
        .collect();
    views.reverse();
    Aggregate {
        findings,
        scans: views,
        skipped_lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(fp: &str, status: Option<Status>) -> FindingRecord {
        FindingRecord {
            fingerprint: fp.into(),
            detector: "d".into(),
            name: "D".into(),
            platform: String::new(),
            severity: "high".into(),
            status,
            preview: "token=abcd********yz".into(),
            source: "git".into(),
            repository: None,
            path: Some("a.env".into()),
            line: 1,
            commit: None,
            date: None,
            link: None,
        }
    }

    fn scan(time: &str, target: &str, inc: bool, f: Vec<FindingRecord>) -> ScanRecord {
        ScanRecord {
            version: VERSION,
            id: time.into(),
            time: time.into(),
            target: target.into(),
            kind: "git".into(),
            incremental: inc,
            verified: true,
            counts: Counts::of(&f),
            findings: f,
            decisions: BTreeMap::new(),
            kubera: String::new(),
        }
    }

    #[test]
    fn states_follow_full_scans_and_decisions() {
        let mut scans = vec![
            scan(
                "2026-01-01T00:00:00Z",
                "r",
                false,
                vec![rec("a", None), rec("b", None)],
            ),
            scan(
                "2026-01-02T00:00:00Z",
                "r",
                false,
                vec![rec("a", Some(Status::Verified)), rec("c", None)],
            ),
            // Incremental: c not reported, still open.
            scan("2026-01-03T00:00:00Z", "r", true, vec![rec("a", None)]),
        ];
        scans[2]
            .decisions
            .insert("c".into(), "false positive".into());
        let agg = aggregate(&scans, 0);
        let get = |fp: &str| agg.findings.iter().find(|f| f.fingerprint == fp).unwrap();
        assert_eq!(get("a").state, "open");
        assert_eq!(get("a").status, "live", "latest known status kept");
        assert_eq!(get("a").times_seen, 3);
        assert_eq!(get("a").first_seen, "2026-01-01T00:00:00Z");
        assert_eq!(get("b").state, "resolved");
        assert_eq!(get("c").state, "triaged");
        assert_eq!(get("c").decision.as_deref(), Some("false positive"));
        assert_eq!(agg.scans[0].time, "2026-01-03T00:00:00Z", "newest first");
        assert_eq!(agg.scans[2].new, 2);
        assert_eq!(agg.scans[1].new, 1);
        assert_eq!(agg.scans[1].live, vec!["a".to_string()]);
        // Open live findings sort first.
        assert_eq!(agg.findings[0].fingerprint, "a");
    }

    #[test]
    fn append_is_private_and_load_skips_torn_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/findings.jsonl");
        append(
            &p,
            &scan("2026-01-01T00:00:00Z", "r", false, vec![rec("a", None)]),
        )
        .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .unwrap()
            .write_all(b"{\"version\":1,\"id")
            .unwrap();
        append(&p, &scan("2026-01-02T00:00:00Z", "r", false, vec![])).unwrap();
        let (scans, bad) = load(&p).unwrap();
        assert_eq!((scans.len(), bad), (2, 1));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let mode = std::fs::metadata(p.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
        assert!(load(&dir.path().join("missing")).unwrap().0.is_empty());
    }
}
