//! Findings and secret redaction.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::template::{Severity, Template};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Filesystem,
    Git,
    Stdin,
}

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub source: SourceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The platform confirmed the credential is live.
    Verified,
    /// The platform rejected the credential.
    Invalid,
    /// Verification was attempted but was inconclusive (network error,
    /// unexpected response, rate limit, ...).
    Unknown,
    /// The template has no verifier.
    Unsupported,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Status::Verified => "verified",
            Status::Invalid => "invalid",
            Status::Unknown => "unknown",
            Status::Unsupported => "unsupported",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Labelled values extracted from the verification response.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub detector: String,
    pub name: String,
    pub platform: String,
    pub severity: Severity,
    /// Stable identifier of (detector, secret); safe to put in allowlists.
    pub fingerprint: String,
    /// Secret parts. Redacted before output unless explicitly revealed.
    pub secret: BTreeMap<String, String>,
    #[serde(skip)]
    pub sensitive: BTreeSet<String>,
    pub redacted: bool,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
}

impl Finding {
    pub fn new(t: &Template, parts: BTreeMap<String, String>, location: Location) -> Self {
        let sensitive = t
            .detect
            .patterns
            .iter()
            .filter(|p| p.secret)
            .flat_map(|p| std::iter::once(p.name.clone()).chain(p.captures.iter().cloned()))
            .collect::<BTreeSet<_>>();
        // Captures embedded in a non-secret part are not sensitive either.
        let sensitive = sensitive
            .into_iter()
            .filter(|n| {
                !t.detect
                    .patterns
                    .iter()
                    .any(|p| !p.secret && p.captures.contains(n))
            })
            .collect();
        Self {
            detector: t.id.clone(),
            name: t.name.clone(),
            platform: t.platform.clone(),
            severity: t.severity,
            fingerprint: fingerprint(&t.id, &parts),
            secret: parts,
            sensitive,
            redacted: false,
            location,
            verification: None,
        }
    }

    /// Copy of this finding with sensitive parts masked.
    pub fn redact(&self) -> Self {
        let mut f = self.clone();
        for (k, v) in f.secret.iter_mut() {
            if self.sensitive.contains(k) {
                *v = redact(v);
            }
        }
        f.redacted = true;
        f
    }

    pub fn status(&self) -> Option<Status> {
        self.verification.as_ref().map(|v| v.status)
    }
}

pub fn fingerprint(detector: &str, parts: &BTreeMap<String, String>) -> String {
    let mut h = Sha256::new();
    h.update(detector.as_bytes());
    for (k, v) in parts {
        h.update([0u8]);
        h.update(k.as_bytes());
        h.update([0u8]);
        h.update(v.as_bytes());
    }
    hex::encode(&h.finalize()[..12])
}

/// Mask a secret, keeping just enough to recognise it.
pub fn redact(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n >= 16 {
        let head: String = chars[..4.min(n / 4)].iter().collect();
        let tail: String = chars[n - 2..].iter().collect();
        format!("{head}{}{tail}", "*".repeat(8))
    } else if n >= 6 {
        format!("{}{}", chars[0], "*".repeat(8))
    } else {
        "*".repeat(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_never_reveals_much() {
        assert_eq!(redact("abcdefghijklmnopqrstuvwxyz"), "abcd********yz");
        assert_eq!(redact("abcdefgh"), "a********");
        assert_eq!(redact("abc"), "********");
    }

    #[test]
    fn fingerprint_is_stable_and_order_independent() {
        let mut a = BTreeMap::new();
        a.insert("id".to_string(), "x".to_string());
        a.insert("secret".to_string(), "y".to_string());
        let f1 = fingerprint("d", &a);
        assert_eq!(f1.len(), 24);
        assert_eq!(f1, fingerprint("d", &a.clone()));
        assert_ne!(f1, fingerprint("e", &a));
    }
}
