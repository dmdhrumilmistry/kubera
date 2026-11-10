//! Output formatting.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use anyhow::Result;
use owo_colors::OwoColorize;
use serde_json::{Value, json};

use crate::finding::{Finding, Status};
use crate::template::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Pretty,
    Json,
    Jsonl,
    Sarif,
    /// Self-contained interactive HTML page.
    Html,
}

pub fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

pub struct Style {
    pub color: bool,
}

impl Style {
    pub fn bold(&self, s: &str) -> String {
        if self.color {
            s.bold().to_string()
        } else {
            s.to_string()
        }
    }
    pub fn dim(&self, s: &str) -> String {
        if self.color {
            s.dimmed().to_string()
        } else {
            s.to_string()
        }
    }
    pub fn red(&self, s: &str) -> String {
        if self.color {
            s.red().bold().to_string()
        } else {
            s.to_string()
        }
    }
    pub fn green(&self, s: &str) -> String {
        if self.color {
            s.green().bold().to_string()
        } else {
            s.to_string()
        }
    }
    pub fn yellow(&self, s: &str) -> String {
        if self.color {
            s.yellow().to_string()
        } else {
            s.to_string()
        }
    }
    pub fn cyan(&self, s: &str) -> String {
        if self.color {
            s.cyan().to_string()
        } else {
            s.to_string()
        }
    }

    pub fn gold(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[38;5;214m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    /// Inverse-video severity label, e.g. ` CRITICAL `.
    pub fn severity_badge(&self, s: Severity) -> String {
        let t = format!(" {} ", s.to_string().to_uppercase());
        if !self.color {
            return t.trim().to_string();
        }
        let code = match s {
            Severity::Critical => "1;97;45",
            Severity::High => "1;97;41",
            Severity::Medium => "1;30;43",
            Severity::Low => "1;97;44",
            Severity::Info => "1;97;100",
        };
        format!("\x1b[{code}m{t}\x1b[0m")
    }

    pub fn status(&self, s: Status) -> String {
        match s {
            Status::Verified => self.red("VERIFIED (live)"),
            Status::Invalid => self.green("invalid"),
            Status::Unknown => self.yellow("unknown"),
            Status::Unsupported => self.dim("not verifiable"),
        }
    }

    pub fn severity(&self, s: Severity) -> String {
        let t = s.to_string();
        match s {
            Severity::Critical | Severity::High => self.red(&t),
            Severity::Medium => self.yellow(&t),
            _ => self.dim(&t),
        }
    }
}

pub fn write_findings(
    out: &mut dyn Write,
    findings: &[Finding],
    format: Format,
    style: &Style,
) -> Result<()> {
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut *out, findings)?;
            writeln!(out)?;
        }
        Format::Jsonl => {
            for f in findings {
                serde_json::to_writer(&mut *out, f)?;
                writeln!(out)?;
            }
        }
        Format::Sarif => {
            serde_json::to_writer_pretty(&mut *out, &sarif(findings))?;
            writeln!(out)?;
        }
        Format::Html => out.write_all(crate::report_html::render(findings).as_bytes())?,
        Format::Pretty => pretty(out, findings, style)?,
    }
    Ok(())
}

/// Pad a label *before* styling it (escape codes would break `{:<n}`).
fn pad(k: &str) -> String {
    format!("{k:<12}")
}

/// Width of the card rules: the terminal width, capped for readability.
fn card_width() -> usize {
    ratatui::crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(80)
        .clamp(40, 88)
}

fn pretty(out: &mut dyn Write, findings: &[Finding], st: &Style) -> Result<()> {
    let width = card_width();
    for f in findings {
        let sev_plain = f.severity.to_string().to_uppercase();
        let status_plain = match f.status() {
            Some(Status::Verified) => "● LIVE",
            Some(Status::Invalid) => "✓ invalid",
            Some(Status::Unknown) => "? unknown",
            Some(Status::Unsupported) => "- not verifiable",
            None => "",
        };
        // Header: ╭─ CRITICAL  GitHub Token ─────────── ● LIVE
        let head_plain = format!("╭─ {sev_plain}  {} ", f.name);
        let used = head_plain.chars().count() + status_plain.chars().count() + 2;
        let rule = "─".repeat(width.saturating_sub(used).max(3));
        let status = match f.status() {
            Some(s) => st.status(s),
            None => String::new(),
        };
        writeln!(
            out,
            "{} {}  {} {}{}",
            st.gold("╭─"),
            st.severity_badge(f.severity),
            st.bold(&f.name),
            st.gold(&rule),
            if status.is_empty() {
                String::new()
            } else {
                format!(" {status}")
            }
        )?;
        let bar = st.gold("│");
        let loc = &f.location;
        match &loc.path {
            Some(p) => {
                let entry = loc
                    .entry
                    .as_deref()
                    .map(|e| format!("!/{e}"))
                    .unwrap_or_default();
                writeln!(
                    out,
                    "{bar} {}",
                    st.cyan(&format!("{p}{entry}:{}", loc.line))
                )?
            }
            None => writeln!(
                out,
                "{bar} {}",
                st.cyan(&format!("{:?} line {}", loc.source, loc.line).to_lowercase())
            )?,
        }
        if let Some(r) = &loc.repository {
            writeln!(out, "{bar} {}", st.dim(r))?;
        }
        if let Some(c) = &loc.commit {
            writeln!(
                out,
                "{bar} {} {} {}",
                st.gold(&c[..c.len().min(12)]),
                st.dim(&format!(
                    "{} <{}>",
                    loc.author.as_deref().unwrap_or(""),
                    loc.email.as_deref().unwrap_or("")
                )),
                st.dim(loc.date.as_deref().unwrap_or(""))
            )?;
        }
        if let Some(layer) = &loc.layer {
            writeln!(
                out,
                "{bar} {} {}",
                st.dim("layer"),
                st.gold(&layer[..layer.len().min(19)])
            )?;
        }
        if let Some(d) = &loc.decoder {
            writeln!(out, "{bar} {} {}", st.dim("decoded from"), st.gold(d))?;
        }
        if let Some(l) = &loc.link {
            writeln!(out, "{bar} {} {}", st.dim("↗"), st.cyan(l))?;
        }
        writeln!(out, "{bar}")?;
        for (k, v) in &f.secret {
            writeln!(out, "{bar} {} {}", st.dim(&pad(k)), st.bold(v))?;
        }
        if let Some(v) = &f.verification {
            if let Some(m) = &v.message {
                writeln!(out, "{bar} {} {}", st.dim(&pad("message")), m)?;
            }
            if v.cached {
                writeln!(
                    out,
                    "{bar} {} {}",
                    st.dim(&pad("cached")),
                    st.dim(&cached_note(v))
                )?;
            }
            for (k, val) in &v.details {
                writeln!(out, "{bar} {} {}", st.dim(&pad(k)), display_value(val))?;
            }
        }
        writeln!(
            out,
            "{} {}",
            st.gold("╰─"),
            st.dim(&format!("{} · {}", f.detector, f.fingerprint))
        )?;
        writeln!(out)?;
    }
    Ok(())
}

/// "result from <time>, no request sent" for a cached verification.
pub fn cached_note(v: &crate::finding::Verification) -> String {
    format!(
        "result from {}, no request sent",
        v.checked_at.as_deref().unwrap_or("an earlier run")
    )
}

pub fn display_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) if a.iter().all(|x| !x.is_object() && !x.is_array()) => {
            a.iter().map(display_value).collect::<Vec<_>>().join(", ")
        }
        other => other.to_string(),
    }
}

/// Summary line for stderr.
pub fn summary(findings: &[Finding], st: &Style) -> String {
    let mut counts: BTreeMap<u8, (usize, &str)> = BTreeMap::new();
    for f in findings {
        let (order, label) = match f.status() {
            Some(Status::Verified) => (0, "live"),
            Some(Status::Unknown) => (1, "unknown"),
            Some(Status::Invalid) => (2, "invalid"),
            Some(Status::Unsupported) => (3, "unverifiable"),
            None => (4, "unverified"),
        };
        counts.entry(order).or_insert((0, label)).0 += 1;
    }
    let parts: Vec<String> = counts
        .values()
        .map(|(n, label)| match *label {
            "live" => st.red(&format!("● {n} live")),
            "invalid" => st.green(&format!("✓ {n} invalid")),
            "unknown" => st.yellow(&format!("? {n} unknown")),
            other => st.dim(&format!("{n} {other}")),
        })
        .collect();
    let cached = findings
        .iter()
        .filter(|f| f.verification.as_ref().is_some_and(|v| v.cached))
        .count();
    let mut parts = parts;
    if cached > 0 {
        parts.push(st.dim(&format!("{cached} cached")));
    }
    let total = if findings.is_empty() {
        st.green("no secrets found")
    } else {
        st.bold(&format!("{} finding(s)", findings.len()))
    };
    format!(
        "{} {total}{}",
        st.gold("◆ kubera"),
        if parts.is_empty() {
            String::new()
        } else {
            format!("  {}", parts.join(&st.dim(" · ")))
        }
    )
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    }
}

fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

/// SARIF 2.1.0 log (GitHub code scanning compatible).
pub fn sarif(findings: &[Finding]) -> Value {
    let mut rules: BTreeMap<&str, Value> = BTreeMap::new();
    for f in findings {
        rules.entry(&f.detector).or_insert_with(|| {
            json!({
                "id": f.detector,
                "name": f.name,
                "shortDescription": { "text": format!("{} detected", f.name) },
                "properties": {
                    "tags": ["security", "secret"],
                    "security-severity": security_severity(f.severity),
                }
            })
        });
    }
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let status = f
                .verification
                .as_ref()
                .map(|v| {
                    let cached = if v.cached { ", cached" } else { "" };
                    format!(" (verification: {}{cached})", v.status)
                })
                .unwrap_or_default();
            let mut loc = json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": match (&f.location.path, &f.location.entry) {
                        (Some(p), Some(e)) => format!("{p}!/{e}"),
                        (Some(p), None) => p.clone(),
                        _ => "stdin".into(),
                    } },
                    "region": { "startLine": f.location.line.max(1) }
                }
            });
            if let Some(c) = &f.location.commit {
                loc["properties"] = json!({ "commit": c });
            }
            json!({
                "ruleId": f.detector,
                "level": sarif_level(f.severity),
                "message": { "text": format!("{} found{status}", f.name) },
                "locations": [loc],
                "partialFingerprints": { "kubera/v1": f.fingerprint },
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "kubera",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/dmdhrumilmistry/kubera",
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": results,
        }]
    })
}
