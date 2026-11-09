//! Serde schema for detector templates.
//!
//! A template is a YAML document that describes how to *detect* a secret
//! (regex patterns + keyword prefilter), how to *verify* it against the
//! issuing platform, how to *analyze* what it can access, and how to
//! *rotate* (or revoke) it. See `docs/TEMPLATES.md` for the full reference.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    /// Unique, kebab-case identifier (e.g. `github-pat`).
    pub id: String,
    /// Human readable name.
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Platform / vendor this secret belongs to (e.g. `GitHub`).
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Links to vendor docs about the credential.
    #[serde(default)]
    pub references: Vec<String>,

    pub detect: Detect,

    #[serde(default)]
    pub verify: Option<Verify>,

    #[serde(default)]
    pub analyze: Option<Analyze>,

    #[serde(default)]
    pub rotate: Option<Rotate>,

    /// Sample inputs used by `kubera templates test` and the test-suite.
    #[serde(default)]
    pub tests: Option<Tests>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    /// Case-insensitive keywords. A chunk is only regex-scanned for this
    /// detector when at least one keyword occurs in it. Keep them specific.
    pub keywords: Vec<String>,
    /// One pattern per secret *part*. Multi-part secrets (e.g. an AWS key id
    /// plus its secret) declare several patterns; every combination of
    /// matches found close to each other is reported as a candidate.
    pub patterns: Vec<Pattern>,
    /// Maximum distance in bytes between the parts of a multi-part secret.
    #[serde(default = "default_max_distance")]
    pub max_distance: usize,
}

fn default_max_distance() -> usize {
    1024
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pattern {
    /// Name of the part; becomes a variable usable in requests (`{{ token }}`).
    pub name: String,
    pub regex: String,
    /// Capture group holding the secret. Defaults to the group named after the
    /// part, else group 1, else the whole match.
    #[serde(default)]
    pub group: Option<usize>,
    /// Minimum Shannon entropy (bits per char) for a match to be kept.
    #[serde(default)]
    pub min_entropy: Option<f64>,
    /// Matches that also match any of these regexes are discarded
    /// (placeholders, documentation examples, ...).
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Extra named capture groups exposed as variables (e.g. the key id
    /// embedded inside a SendGrid key).
    #[serde(default)]
    pub captures: Vec<String>,
    /// Whether this part is sensitive and must be redacted in output.
    #[serde(default = "default_true")]
    pub secret: bool,
}

pub fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Verify {
    pub request: Request,
    /// The secret is live when every condition here holds.
    pub valid: Matcher,
    /// The secret is definitively dead when every condition here holds.
    /// Anything that matches neither is reported as `unknown`.
    #[serde(default)]
    pub invalid: Option<Matcher>,
    /// Values pulled from the verification response and attached to the
    /// finding (e.g. the account name).
    #[serde(default)]
    pub extract: Vec<Extract>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Analyze {
    /// Free text shown at the top of the analysis report.
    #[serde(default)]
    pub notes: Option<String>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rotate {
    /// Manual instructions. Always shown; the only thing shown when the
    /// platform offers no API for rotation.
    #[serde(default)]
    pub instructions: Option<String>,
    /// User supplied inputs (`--set name=value`) with optional defaults.
    #[serde(default)]
    pub inputs: Vec<Input>,
    /// API calls executed in order. Values extracted by earlier steps are
    /// available to later ones.
    #[serde(default)]
    pub steps: Vec<Step>,
    /// Variables to present as the rotated credential once all steps succeed.
    #[serde(default)]
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub request: Request,
    /// Conditions that must hold for the step to count as successful.
    #[serde(default)]
    pub expect: Option<Matcher>,
    #[serde(default)]
    pub extract: Vec<Extract>,
    /// When true a failure of this step does not abort the run.
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default = "default_method")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default)]
    pub auth: Option<Auth>,
    /// Raw body (templated).
    #[serde(default)]
    pub body: Option<String>,
    /// `application/x-www-form-urlencoded` body (values templated).
    #[serde(default)]
    pub form: Option<BTreeMap<String, String>>,
    /// JSON body; every string inside is templated.
    #[serde(default)]
    pub json: Option<serde_json::Value>,
    /// Request timeout in seconds.
    #[serde(default)]
    pub timeout: Option<u64>,
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Auth {
    Basic {
        username: String,
        #[serde(default)]
        password: String,
    },
    Bearer {
        token: String,
    },
    /// AWS Signature Version 4.
    AwsSigv4 {
        access_key: String,
        secret_key: String,
        #[serde(default)]
        session_token: Option<String>,
        region: String,
        service: String,
    },
}

/// A set of conditions evaluated against an HTTP response. All present
/// conditions must hold.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    /// Accepted status codes.
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub body_contains: Vec<String>,
    #[serde(default)]
    pub body_not_contains: Vec<String>,
    #[serde(default)]
    pub json: Vec<JsonCondition>,
    #[serde(default)]
    pub headers: Vec<HeaderCondition>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonCondition {
    /// Dot path into the JSON body (`data.0.name`, `items.*.id`).
    pub path: String,
    #[serde(default)]
    pub equals: Option<serde_json::Value>,
    /// `true`: path must resolve to a non-null value. `false`: must not.
    #[serde(default)]
    pub exists: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderCondition {
    pub name: String,
    #[serde(default)]
    pub contains: Option<String>,
}

/// Pull a value out of a response into a variable.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Extract {
    pub name: String,
    /// Human friendly label used in reports.
    #[serde(default)]
    pub label: Option<String>,
    /// Dot path into the JSON body.
    #[serde(default)]
    pub json: Option<String>,
    /// Response header name.
    #[serde(default)]
    pub header: Option<String>,
    /// Regex applied to the raw body; the first non-empty capture group (or
    /// the whole match) is used.
    #[serde(default)]
    pub regex: Option<String>,
    /// With `regex`: collect every match into a list instead of the first.
    #[serde(default)]
    pub all: bool,
    /// Marks the value as sensitive (redacted unless explicitly revealed).
    #[serde(default)]
    pub secret: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tests {
    /// Inputs that must produce at least one finding. Each string is rendered
    /// through the template engine first, so a sample can be written as
    /// `xox{{'b'}}-...` to keep the literal token out of the repository.
    #[serde(default)]
    pub positive: Vec<String>,
    /// Inputs that must produce no finding.
    #[serde(default)]
    pub negative: Vec<String>,
}
