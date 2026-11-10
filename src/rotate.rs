//! Credential rotation / revocation.
//!
//! Safety model:
//! * Planning (dry run) is the default; nothing is sent except the
//!   verification request.
//! * Execution requires an explicit opt-in from the caller.
//! * The current credential must verify as live unless forced.
//! * Steps run strictly in order and stop at the first failure. Every value
//!   extracted so far (e.g. a freshly created replacement key) is returned
//!   even on failure so it is never lost.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Serialize;

use crate::finding::{Status, Verification};
use crate::http::Http;
use crate::render::{self, Vars};
use crate::steps::{self, StepResult};
use crate::template::Template;
use crate::verify;

#[derive(Debug, Clone, Serialize)]
pub struct PlannedStep {
    pub name: String,
    pub description: String,
    pub request: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub detector: String,
    pub executed: bool,
    pub verification: Verification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub plan: Vec<PlannedStep>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<StepResult>,
    /// True when every step succeeded.
    pub completed: bool,
    /// The new credential (template `outputs`). Contains raw secrets.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub outputs: BTreeMap<String, String>,
    /// Secret store updates (`--store`): planned, or their results.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stores: Vec<crate::store::StoreResult>,
}

pub struct Options {
    pub execute: bool,
    pub force: bool,
    /// `--set name=value` overrides for template inputs.
    pub inputs: BTreeMap<String, String>,
}

fn resolve_inputs(
    t: &Template,
    vars: &mut Vars,
    given: &BTreeMap<String, String>,
    dry_run: bool,
) -> Result<()> {
    let Some(r) = &t.rotate else { return Ok(()) };
    for k in given.keys() {
        if !r.inputs.iter().any(|i| &i.name == k) {
            bail!(
                "unknown input `{k}` for {} (accepted: {})",
                t.id,
                r.inputs
                    .iter()
                    .map(|i| i.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    for i in &r.inputs {
        let v = match (given.get(&i.name), &i.default) {
            (Some(v), _) => v.clone(),
            (None, Some(d)) => match render::render(d, vars) {
                Ok(v) => v,
                // e.g. the default uses a value only a live credential yields.
                Err(_) if dry_run => format!("<{}>", i.name),
                Err(e) => return Err(e.context(format!("input `{}`", i.name))),
            },
            (None, None) => bail!(
                "missing required input `{}` (use --set {}=...)",
                i.name,
                i.name
            ),
        };
        vars.insert(i.name.clone(), v);
    }
    Ok(())
}

pub async fn rotate(
    http: &Http,
    t: &Template,
    parts: &BTreeMap<String, String>,
    opts: &Options,
) -> Result<Report> {
    let Some(r) = &t.rotate else {
        bail!("detector `{}` has no rotation support", t.id);
    };
    let out = verify::verify(http, t, parts).await;
    let mut vars = out.vars;
    let dry_run = !opts.execute || r.steps.is_empty();
    let status = out.verification.status;
    if !dry_run && status != Status::Verified && !opts.force {
        bail!(
            "refusing to rotate: credential is {status} ({}). Use --force to override.",
            out.verification.message.clone().unwrap_or_default()
        );
    }
    resolve_inputs(t, &mut vars, &opts.inputs, dry_run)?;

    let mut report = Report {
        detector: t.id.clone(),
        executed: false,
        verification: out.verification,
        instructions: r.instructions.clone(),
        plan: Vec::new(),
        steps: Vec::new(),
        completed: false,
        outputs: BTreeMap::new(),
        stores: Vec::new(),
    };

    let secrets: Vec<String> = parts.values().cloned().collect();

    if dry_run {
        // Dry run: render each request, using placeholders for values that
        // only exist once earlier steps have run.
        let mut plan_vars = vars.clone();
        for s in &r.steps {
            let request = match http.prepare(&s.request, &plan_vars) {
                Ok(p) => steps::describe(&p, &secrets),
                Err(e) => format!("<cannot render: {e:#}>"),
            };
            report.plan.push(PlannedStep {
                name: s.name.clone(),
                description: s.description.clone(),
                request,
            });
            for e in &s.extract {
                plan_vars.insert(e.name.clone(), format!("<{} from {}>", e.name, s.name));
            }
        }
        return Ok(report);
    }

    report.executed = true;
    let mut all_ok = true;
    for s in &r.steps {
        let mut res = steps::run(http, s, &mut vars).await;
        res.error = res.error.map(|e| verify::mask_secrets(&e, parts));
        let ok = res.ok;
        report.steps.push(res);
        if !ok && !s.optional {
            all_ok = false;
            break;
        }
    }
    report.completed = all_ok;
    // Surface outputs even on partial failure so new keys are not lost.
    for o in &r.outputs {
        if let Some(v) = vars.get(o) {
            report.outputs.insert(o.clone(), v.clone());
        }
    }
    // Any secret extracted by an executed step is also preserved.
    for st in &report.steps {
        for v in st.values.iter().filter(|v| v.secret) {
            report
                .outputs
                .entry(v.name.clone())
                .or_insert_with(|| crate::http::value_to_var(&v.value));
        }
    }
    Ok(report)
}
