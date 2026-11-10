//! Remediation from a findings file (`kubera scan ... -f json`):
//!
//! * [`issues`]: one GitHub issue per leaked secret (fingerprint), with a
//!   hidden marker so re-runs never open a duplicate. Dry run unless the
//!   caller executes it.
//! * [`purge`]: prepare a `git filter-repo --replace-text` rewrite of the
//!   leaked values. The raw values come from re-scanning the repository (a
//!   redacted findings file only has fingerprints) or from a
//!   `--show-secrets` file. Nothing is rewritten or pushed here.
//!
//! Findings files are redacted by default; both flows work from
//! fingerprints and locations only. Values from the file (paths, authors,
//! links) come from scanned content and are treated as hostile when they
//! are put into Markdown.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Value, json};

use crate::finding::{Finding, Status, redact};
use crate::forge::Client;

/// Hidden marker identifying the issue of a fingerprint.
pub const MARKER: &str = "kubera-fingerprint:";

/// Read findings: a JSON array (`-f json`) or JSON lines (`-f jsonl`).
/// `-` reads stdin.
pub fn load_findings(path: &Path) -> Result<Vec<Finding>> {
    let text = if path == Path::new("-") {
        let mut s = String::new();
        std::io::stdin()
            .take(256 * 1024 * 1024)
            .read_to_string(&mut s)
            .context("reading findings from stdin")?;
        s
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
    };
    let t = text.trim_start();
    if t.starts_with('[') {
        return serde_json::from_str(t)
            .context("not a kubera findings file (expected the output of `scan -f json`)");
    }
    t.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str(l)
                .with_context(|| format!("findings line {}: not a finding", i + 1))
        })
        .collect()
}

/// `true` for a fingerprint as kubera writes it (24 hex digits).
pub fn valid_fingerprint(s: &str) -> bool {
    s.len() == 24 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn status_label(f: &Finding) -> &'static str {
    match f.status() {
        Some(Status::Verified) => "live",
        Some(Status::Invalid) => "invalid",
        Some(Status::Unknown) => "unknown",
        Some(Status::Unsupported) => "not verifiable",
        None => "not verified",
    }
}

/// Findings grouped by fingerprint (one secret, every place it was seen),
/// in first-seen order. A verified sighting comes first in its group. A verified sighting comes first in its group.
pub fn group(findings: &[Finding]) -> Vec<Vec<Finding>> {
    let mut order: Vec<String> = Vec::new();
    let mut by: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for f in findings {
        if !by.contains_key(&f.fingerprint) {
            order.push(f.fingerprint.clone());
        }
        by.entry(f.fingerprint.clone()).or_default().push(f.clone());
    }
    order
        .into_iter()
        .filter_map(|k| by.remove(&k))
        .map(|mut g| {
            g.sort_by_key(|f| f.status() != Some(Status::Verified));
            g
        })
        .collect()
}

// ---------------------------------------------------------------- issues

/// A GitHub repository `owner/name` from `github:<owner>/<repo>`.
pub fn parse_github(dest: &str) -> Result<(String, String)> {
    let rest = dest
        .strip_prefix("github:")
        .with_context(|| format!("--issues `{dest}`: expected github:<owner>/<repo>"))?;
    let (o, r) = rest
        .split_once('/')
        .with_context(|| format!("--issues `{dest}`: expected github:<owner>/<repo>"))?;
    let ok = |s: &str, extra: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    if !ok(o, "-") || !ok(r, "-_.") || r.starts_with('.') {
        bail!("--issues `{dest}`: invalid repository");
    }
    Ok((o.to_string(), r.to_string()))
}

/// Inline code that hostile text cannot break out of: control characters
/// and newlines removed, a fence longer than any backtick run inside.
/// Mentions and links are not rendered inside code.
pub fn code(s: &str) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect();
    let longest = clean.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    format!("{fence} {clean} {fence}")
}

/// Plain text for a title: only harmless characters survive.
fn title_text(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || " ._-()/:".contains(*c))
        .take(80)
        .collect::<String>()
        .trim()
        .to_string()
}

fn safe_link(l: &str) -> Option<&str> {
    (l.starts_with("https://")
        && l.len() < 2000
        && !l
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "()<>[]\"'`".contains(c)))
    .then_some(l)
}

fn valid_login(s: &str) -> bool {
    (1..=39).contains(&s.len())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !s.starts_with('-')
}

fn valid_sha(s: &str) -> bool {
    (7..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Secret parts as shown in an issue: always masked, whatever the file says.
fn shown_secret(f: &Finding) -> String {
    f.secret
        .iter()
        .map(|(k, v)| {
            let v = if f.redacted { v.clone() } else { redact(v) };
            format!("{k}={v}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn location_text(f: &Finding) -> String {
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

pub fn title(group: &[Finding]) -> String {
    let f = &group[0];
    let live = if f.status() == Some(Status::Verified) {
        "Live "
    } else {
        "Leaked "
    };
    format!(
        "{live}{} ({})",
        title_text(&f.name),
        &f.fingerprint[..8.min(f.fingerprint.len())]
    )
}

/// Issue body (Markdown) for the findings of one fingerprint.
pub fn body(group: &[Finding], mention: Option<&str>) -> String {
    let f = &group[0];
    let mut b = format!("<!-- {MARKER} {} -->\n", f.fingerprint);
    b.push_str(&format!(
        "Kubera found a leaked **{}** credential ({}). Verification status: **{}**.\n\n",
        title_text(&f.name),
        title_text(&format!("{:?}", f.severity).to_lowercase()),
        status_label(f),
    ));
    b.push_str(&format!("- **Detector:** {}\n", code(&f.detector)));
    b.push_str(&format!("- **Fingerprint:** {}\n", code(&f.fingerprint)));
    b.push_str(&format!(
        "- **Secret (redacted):** {}\n",
        code(&shown_secret(f))
    ));
    if let Some(m) = f.verification.as_ref().and_then(|v| v.message.as_deref()) {
        b.push_str(&format!("- **Verification:** {}\n", code(m)));
    }
    if let Some(login) = mention {
        b.push_str(&format!("- **Committed by:** @{login}\n"));
    }
    b.push_str("\n### Where it was found\n\n");
    for g in group.iter().take(25) {
        let l = &g.location;
        b.push_str(&format!("- {}", code(&location_text(g))));
        if let Some(r) = &l.repository {
            b.push_str(&format!(" in {}", code(r)));
        }
        if let Some(c) = &l.commit {
            b.push_str(&format!(" at commit {}", code(&c[..c.len().min(12)])));
        }
        if let Some(d) = &l.date {
            b.push_str(&format!(" ({})", code(d)));
        }
        if let Some(link) = l.link.as_deref().and_then(safe_link) {
            b.push_str(&format!(" [view]({link})"));
        }
        b.push('\n');
    }
    if group.len() > 25 {
        b.push_str(&format!("- ... and {} more\n", group.len() - 25));
    }
    let d = &f.detector;
    b.push_str(&format!(
        "\n### What to do\n\n\
         1. **Rotate or revoke it now**, before anything else. Plan it with `kubera rotate {d}` (dry run), then add `--execute`. Platforms without an API print manual steps.\n\
         2. Update every consumer of the credential (`kubera rotate --store` can write CI secrets, Vault and AWS Secrets Manager).\n\
         3. Confirm the old value is dead: `kubera verify {d}` exits with 2.\n\
         4. Check the vendor's audit log for use of the credential since the commit date.\n\
         5. Remove it from the code. If policy requires it, prepare a history rewrite with `kubera purge`.\n\
         6. Close this issue.\n\n\
         _Opened by Kubera. This issue never contains the secret value; the fingerprint identifies it._\n"
    ));
    b
}

/// Fingerprint markers in existing issue bodies.
pub fn markers(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find(MARKER) {
        let after = rest[i + MARKER.len()..].trim_start();
        let fp: String = after
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if valid_fingerprint(&fp) {
            out.push(fp.to_ascii_lowercase());
        }
        rest = &rest[i + MARKER.len()..];
    }
    out
}

pub struct IssueOptions {
    pub owner: String,
    pub repo: String,
    /// API base, e.g. `https://api.github.com`.
    pub api: String,
    pub labels: Vec<String>,
    pub mention_committer: bool,
    /// Allow opening issues in a public repository.
    pub allow_public: bool,
    pub execute: bool,
    /// Most open issues read for the duplicate check.
    pub max_existing: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueResult {
    pub fingerprint: String,
    pub detector: String,
    pub status: String,
    pub locations: usize,
    pub title: String,
    /// `would_open`, `opened`, `exists`, `failed`.
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mention: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuesReport {
    pub repository: String,
    pub executed: bool,
    /// Whether open issues were read to skip duplicates.
    pub checked_existing: bool,
    pub results: Vec<IssueResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// The GitHub repository a finding came from, if its location says so.
fn finding_repo(f: &Finding) -> Option<(String, String)> {
    let r = f.location.repository.as_deref()?;
    let rest = r
        .split_once("github.com/")
        .or_else(|| r.split_once("github.com:"))?
        .1;
    let mut it = rest.trim_end_matches(".git").splitn(3, '/');
    let (o, n) = (it.next()?, it.next()?);
    (!o.is_empty() && !n.is_empty()).then(|| (o.to_string(), n.to_string()))
}

async fn committer(client: &Client, o: &IssueOptions, f: &Finding) -> Result<Option<String>> {
    let Some(sha) = f.location.commit.as_deref().filter(|s| valid_sha(s)) else {
        return Ok(None);
    };
    let (owner, repo) = finding_repo(f).unwrap_or((o.owner.clone(), o.repo.clone()));
    let url = format!(
        "{}/repos/{}/{}/commits/{sha}",
        o.api,
        enc(&owner),
        enc(&repo)
    );
    let (status, v) = client.github_call(reqwest::Method::GET, &url, None).await?;
    if status != 200 {
        bail!(
            "commit {} in {owner}/{repo}: HTTP {status}",
            &sha[..sha.len().min(12)]
        );
    }
    Ok(v.pointer("/author/login")
        .and_then(Value::as_str)
        .filter(|l| valid_login(l))
        .map(str::to_string))
}

fn enc(s: &str) -> String {
    const SEG: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.');
    percent_encoding::utf8_percent_encode(s, SEG).to_string()
}

/// Plan (or, with `execute`, open) one issue per fingerprint. `client` is
/// `None` without a token: the plan is then built offline, without the
/// duplicate check.
pub async fn issues(
    client: Option<&Client>,
    o: &IssueOptions,
    groups: &[Vec<Finding>],
) -> Result<IssuesReport> {
    let repo_label = format!("{}/{}", o.owner, o.repo);
    let mut report = IssuesReport {
        repository: repo_label.clone(),
        executed: o.execute,
        checked_existing: false,
        results: Vec::new(),
        warnings: Vec::new(),
    };
    let base = format!("{}/repos/{}/{}", o.api, enc(&o.owner), enc(&o.repo));
    let mut existing: BTreeMap<String, (u64, String)> = BTreeMap::new();
    if let Some(c) = client {
        // Issues are as public as the repository: never advertise a leak.
        let (status, meta) = c.github_call(reqwest::Method::GET, &base, None).await?;
        match status {
            200 => {}
            404 => bail!("{repo_label}: repository not found, or the token cannot see it"),
            s => bail!("{repo_label}: HTTP {s} reading the repository"),
        }
        let private = meta["private"].as_bool().unwrap_or(false);
        if !private && !o.allow_public {
            bail!(
                "{repo_label} is public: an issue would tell everyone where a secret leaked. \
                 Track it in a private repository, or pass --allow-public-repo"
            );
        }
        if meta["has_issues"] == Value::Bool(false) {
            bail!("{repo_label} has issues disabled");
        }
        let open = c
            .github_list(
                &format!("{base}/issues?state=open&per_page=100"),
                o.max_existing,
            )
            .await
            .context("listing open issues")?;
        if open.len() >= o.max_existing {
            report.warnings.push(format!(
                "only the first {} open issues were checked for duplicates",
                o.max_existing
            ));
        }
        for i in open.iter().filter(|i| i.get("pull_request").is_none()) {
            let (Some(n), Some(body)) = (i["number"].as_u64(), i["body"].as_str()) else {
                continue;
            };
            let url = i["html_url"].as_str().unwrap_or_default().to_string();
            for fp in markers(body) {
                existing.entry(fp).or_insert((n, url.clone()));
            }
        }
        report.checked_existing = true;
    } else if o.execute {
        bail!("opening issues needs a GitHub token (--token-env)");
    } else {
        report
            .warnings
            .push("no token (--token-env): open issues were not checked for duplicates".into());
    }

    let mut first = true;
    for g in groups {
        let f = &g[0];
        let mut r = IssueResult {
            fingerprint: f.fingerprint.clone(),
            detector: f.detector.clone(),
            status: status_label(f).into(),
            locations: g.len(),
            title: title(g),
            action: "would_open".into(),
            issue: None,
            url: None,
            mention: None,
            error: None,
        };
        if let Some((n, url)) = existing.get(&f.fingerprint.to_ascii_lowercase()) {
            r.action = "exists".into();
            r.issue = Some(*n);
            r.url = Some(url.clone()).filter(|u| !u.is_empty());
            report.results.push(r);
            continue;
        }
        if o.mention_committer
            && let Some(c) = client
        {
            match committer(c, o, f).await {
                Ok(m) => r.mention = m,
                Err(e) => report
                    .warnings
                    .push(format!("{}: committer not resolved ({e:#})", f.fingerprint)),
            }
        }
        if o.execute {
            let c = client.expect("checked above");
            if !first {
                // GitHub asks for a pause between content-creating calls.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            first = false;
            let payload = json!({
                "title": r.title,
                "body": body(g, r.mention.as_deref()),
                "labels": o.labels,
            });
            match c
                .github_call(
                    reqwest::Method::POST,
                    &format!("{base}/issues"),
                    Some(&payload),
                )
                .await
            {
                Ok((201, v)) => {
                    r.action = "opened".into();
                    r.issue = v["number"].as_u64();
                    r.url = v["html_url"].as_str().map(str::to_string);
                }
                Ok((s, v)) => {
                    r.action = "failed".into();
                    r.error = Some(format!(
                        "HTTP {s}: {}",
                        v["message"].as_str().unwrap_or("unexpected response")
                    ));
                }
                Err(e) => {
                    r.action = "failed".into();
                    r.error = Some(format!("{e:#}"));
                }
            }
        }
        report.results.push(r);
    }
    Ok(report)
}

// ----------------------------------------------------------------- purge

pub struct PurgeOptions {
    pub repo: PathBuf,
    pub output: PathBuf,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PurgeReport {
    pub repository: String,
    pub expressions_file: String,
    /// Distinct values written to the file.
    pub values: usize,
    /// Fingerprints whose values will be replaced.
    pub resolved: Vec<String>,
    /// Fingerprints not found in the repository's history.
    pub not_found: Vec<String>,
    pub warnings: Vec<String>,
    pub commands: Vec<String>,
}

/// Values shorter than this are not replaced: a global replacement of a
/// short string would corrupt unrelated content.
pub const MIN_VALUE_LEN: usize = 8;

/// Escape a value for a filter-repo `regex:` line (Python `re`).
fn regex_escape(v: &str) -> String {
    let mut out = String::new();
    for c in v.chars() {
        match c {
            '\n' => out.push_str("\\r?\\n"),
            '\r' => {}
            '\t' => out.push_str("\\t"),
            c if c.is_ascii_alphanumeric() || !c.is_ascii() => out.push(c),
            c => {
                out.push('\\');
                out.push(c);
            }
        }
    }
    out
}

/// One `--replace-text` expression. Single-line values are literals;
/// values spanning lines (private keys) or containing `==>` become escaped
/// regexes, since the file is line based.
pub fn expression(value: &str, replacement: &str) -> String {
    if value.contains('\n') || value.contains('\r') || value.contains("==>") {
        format!("regex:{}==>{replacement}", regex_escape(value))
    } else {
        format!("literal:{value}==>{replacement}")
    }
}

/// The raw secret values of `found`, per fingerprint: sensitive parts only
/// (identifiers such as AWS key ids are left alone).
pub fn values_of(found: &[Finding]) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for f in found.iter().filter(|f| !f.redacted) {
        let e = out.entry(f.fingerprint.clone()).or_default();
        for (k, v) in &f.secret {
            if f.sensitive.is_empty() || f.sensitive.contains(k) {
                e.insert(v.clone());
            }
        }
    }
    out
}

/// Top-level directory of the work tree containing `p` (or `p` itself).
pub fn toplevel(repo: &Path) -> Result<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--show-toplevel"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .context("running git")?;
    if out.status.success() {
        return Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()));
    }
    // Bare repositories have no work tree.
    std::fs::canonicalize(repo)
        .with_context(|| format!("{} is not a git repository", repo.display()))
}

/// `origin`'s URL without credentials, if any.
pub fn origin_url(repo: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["remote", "get-url", "origin"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    match crate::sources::remote::parse(&raw) {
        Ok(Some(r)) => Some(r.display().to_string()),
        _ => None,
    }
}

/// Single-quote for a POSIX shell.
fn sh(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-:@+=,".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Write the expressions file for `found` (raw findings) and return the
/// report with the commands to run. `wanted` are the fingerprints asked for.
pub fn purge(o: &PurgeOptions, wanted: &[Finding], found: &[Finding]) -> Result<PurgeReport> {
    if o.replacement.contains("==>") || o.replacement.contains('\n') {
        bail!("--replacement must be one line without `==>`");
    }
    let top = toplevel(&o.repo)?;
    let out_abs = absolute(&o.output)?;
    if out_abs.starts_with(&top) {
        bail!(
            "{} is inside the repository; write the expressions file outside it (it holds the raw secrets and must never be committed)",
            out_abs.display()
        );
    }
    if out_abs.exists() {
        bail!(
            "{} already exists; refusing to overwrite",
            out_abs.display()
        );
    }
    let values = values_of(found);
    let mut warnings = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut resolved = Vec::new();
    let mut not_found = Vec::new();
    let mut wanted_fps: Vec<&Finding> = Vec::new();
    for f in wanted {
        if !wanted_fps.iter().any(|w| w.fingerprint == f.fingerprint) {
            wanted_fps.push(f);
        }
    }
    for f in &wanted_fps {
        let Some(vals) = values.get(&f.fingerprint) else {
            not_found.push(f.fingerprint.clone());
            continue;
        };
        let mut used = false;
        for v in vals {
            if v.chars().count() < MIN_VALUE_LEN {
                warnings.push(format!(
                    "{} ({}): a value shorter than {MIN_VALUE_LEN} characters is not replaced; remove it by hand",
                    f.fingerprint, f.detector
                ));
                continue;
            }
            used = true;
            if seen.insert(v.clone()) {
                lines.push(expression(v, &o.replacement));
            }
        }
        if used {
            resolved.push(f.fingerprint.clone());
        }
        if found
            .iter()
            .any(|x| x.fingerprint == f.fingerprint && x.location.decoder.is_some())
        {
            warnings.push(format!(
                "{} ({}): found after decoding (base64 / URL / escapes); the encoded text in the file will not match. Remove it by hand and check with a scan",
                f.fingerprint, f.detector
            ));
        }
    }
    if lines.is_empty() {
        bail!(
            "none of the {} finding(s) was found in the history of {} (nothing to purge)",
            wanted_fps.len(),
            top.display()
        );
    }
    let mut data = lines.join("\n");
    data.push('\n');
    write_new_private(&out_abs, data.as_bytes())?;

    let origin = origin_url(&top);
    let name = top
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "repo".into());
    let source = origin.clone().unwrap_or_else(|| top.display().to_string());
    let clone_dir = format!("{name}-purge.git");
    let file = out_abs.display().to_string();
    let mut commands = vec![
        "# 0. Rotate or revoke every credential first: a rewrite does not un-leak it.".to_string(),
        "# 1. Rewrite a fresh bare clone (filter-repo refuses a used clone), every branch and tag:"
            .to_string(),
        format!("git clone --bare {} {}", sh(&source), sh(&clone_dir)),
        format!("cd {}", sh(&clone_dir)),
        format!(
            "git filter-repo --replace-text {f} --replace-message {f}",
            f = sh(&file)
        ),
        "# 2. Check that nothing is left:".to_string(),
        "kubera scan git . --no-baseline".to_string(),
        "# 3. Force push (filter-repo removed the origin remote):".to_string(),
        format!("git remote add origin {}", sh(&source)),
        "git push --force --all origin".to_string(),
        "git push --force --tags origin".to_string(),
        "# 4. Delete the expressions file: it holds the raw secrets.".to_string(),
        format!("rm {}", sh(&file)),
    ];
    if origin.is_none() {
        commands.insert(
            0,
            "# No `origin` remote: replace the local path below with the shared repository's URL."
                .into(),
        );
    }
    Ok(PurgeReport {
        repository: top.display().to_string(),
        expressions_file: file,
        values: lines.len(),
        resolved,
        not_found,
        warnings,
        commands,
    })
}

fn absolute(p: &Path) -> Result<PathBuf> {
    let p = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()?.join(p)
    };
    // Resolve the parent (the file itself does not exist yet).
    let parent = p.parent().context("invalid output path")?;
    let parent = std::fs::canonicalize(parent)
        .with_context(|| format!("{} does not exist", parent.display()))?;
    Ok(parent.join(p.file_name().context("invalid output path")?))
}

/// Create a new file (never overwrite) with mode 0600.
fn write_new_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut file = o
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_spans_contain_hostile_text() {
        assert_eq!(code("a`b"), "`` a`b ``");
        assert_eq!(code("x\ny"), "` x y `");
        let c = code("@everyone ``` <!-- -->");
        assert!(c.starts_with("```` "), "{c}");
        assert_eq!(title_text("Evil @team <b>name</b>\n"), "Evil team bname/b");
    }

    #[test]
    fn markers_roundtrip() {
        let fp = "0123456789abcdef01234567";
        assert_eq!(markers(&format!("<!-- {MARKER} {fp} -->\ntext")), vec![fp]);
        assert!(markers(&format!("{MARKER} nothex")).is_empty());
        assert!(safe_link("https://github.com/a/b/blob/c/x#L1").is_some());
        assert!(safe_link("https://x/a) [y](javascript:z").is_none());
        assert!(safe_link("javascript:alert(1)").is_none());
    }

    #[test]
    fn filter_repo_expressions() {
        assert_eq!(expression("abc==>x", "R"), "regex:abc\\=\\=\\>x==>R");
        assert_eq!(expression("tok_123", "R"), "literal:tok_123==>R");
        let pem = "-----BEGIN KEY-----\nAAA+/=\n-----END KEY-----";
        let e = expression(pem, "R");
        assert!(e.starts_with("regex:\\-\\-"), "{e}");
        assert!(e.contains("\\r?\\nAAA\\+\\/\\=\\r?\\n"), "{e}");
        assert!(!e.contains('\n'));
    }
}
