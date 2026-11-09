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
        Format::Pretty => pretty(out, findings, style)?,
    }
    Ok(())
}

fn pretty(out: &mut dyn Write, findings: &[Finding], st: &Style) -> Result<()> {
    for f in findings {
        let status = f
            .verification
            .as_ref()
            .map(|v| format!("  {}", st.status(v.status)))
            .unwrap_or_default();
        writeln!(
            out,
            "{} {} [{}]{}",
            st.bold("●"),
            st.bold(&f.name),
            st.severity(f.severity),
            status
        )?;
        writeln!(out, "  {:<12} {}", st.dim("detector"), f.detector)?;
        let loc = &f.location;
        if let Some(p) = &loc.path {
            writeln!(
                out,
                "  {:<12} {}:{}",
                st.dim("location"),
                st.cyan(p),
                loc.line
            )?;
        } else {
            writeln!(
                out,
                "  {:<12} {:?} line {}",
                st.dim("location"),
                loc.source,
                loc.line
            )?;
        }
        if let Some(c) = &loc.commit {
            writeln!(
                out,
                "  {:<12} {} {} <{}> {}",
                st.dim("commit"),
                &c[..c.len().min(12)],
                loc.author.as_deref().unwrap_or(""),
                loc.email.as_deref().unwrap_or(""),
                st.dim(loc.date.as_deref().unwrap_or(""))
            )?;
        }
        for (k, v) in &f.secret {
            writeln!(out, "  {:<12} {}", st.dim(k), v)?;
        }
        if let Some(v) = &f.verification {
            if let Some(m) = &v.message {
                writeln!(out, "  {:<12} {}", st.dim("message"), m)?;
            }
            for (k, val) in &v.details {
                writeln!(out, "  {:<12} {}", st.dim(k), display_value(val))?;
            }
        }
        writeln!(
            out,
            "  {:<12} {}",
            st.dim("fingerprint"),
            st.dim(&f.fingerprint)
        )?;
        writeln!(out)?;
    }
    Ok(())
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
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in findings {
        let k = match f.status() {
            Some(Status::Verified) => "verified",
            Some(Status::Invalid) => "invalid",
            Some(Status::Unknown) => "unknown",
            Some(Status::Unsupported) => "unverifiable",
            None => "unverified",
        };
        *counts.entry(k).or_default() += 1;
    }
    let parts: Vec<String> = counts.iter().map(|(k, v)| format!("{v} {k}")).collect();
    format!(
        "{} {} finding(s){}",
        st.bold("kubera:"),
        findings.len(),
        if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join(", "))
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
                .status()
                .map(|s| format!(" (verification: {s})"))
                .unwrap_or_default();
            let mut loc = json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": f.location.path.clone().unwrap_or_else(|| "stdin".into()) },
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
