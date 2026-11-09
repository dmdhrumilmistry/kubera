//! Credential analysis: who owns it, what it can reach, how it is scoped.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::finding::{Status, Verification};
use crate::http::Http;
use crate::steps::{self, StepResult};
use crate::template::Template;
use crate::verify;

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub detector: String,
    pub name: String,
    pub platform: String,
    pub verification: Verification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub steps: Vec<StepResult>,
}

impl Report {
    pub fn redacted(&self) -> Self {
        let mut r = self.clone();
        r.steps = r.steps.iter().map(StepResult::redacted).collect();
        r
    }
}

/// Verify the secret, then run every analysis step. Steps keep going after a
/// failure (they are usually independent permission probes); a step whose
/// variables could not be resolved is reported as failed.
pub async fn analyze(
    http: &Http,
    t: &Template,
    parts: &BTreeMap<String, String>,
    force: bool,
) -> Report {
    let out = verify::verify(http, t, parts).await;
    let mut vars = out.vars;
    let mut report = Report {
        detector: t.id.clone(),
        name: t.name.clone(),
        platform: t.platform.clone(),
        verification: out.verification,
        notes: t.analyze.as_ref().and_then(|a| a.notes.clone()),
        steps: Vec::new(),
    };
    let live = matches!(
        report.verification.status,
        Status::Verified | Status::Unsupported
    );
    if !live && !force {
        return report;
    }
    if let Some(a) = &t.analyze {
        for step in &a.steps {
            let mut res = steps::run(http, step, &mut vars).await;
            res.error = res.error.map(|e| verify::mask_secrets(&e, parts));
            report.steps.push(res);
        }
    }
    report
}
