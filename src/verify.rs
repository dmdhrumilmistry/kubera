//! Live verification of candidate secrets against the issuing platform.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::Mutex;

use crate::finding::{Finding, Status, Verification};
use crate::http::{self, Http};
use crate::render::{self, Vars};
use crate::template::Template;
use crate::verify_cache::Cache as VerifyCache;

/// Variables available to requests for a given secret.
pub fn secret_vars(parts: &BTreeMap<String, String>) -> Vars {
    let mut v = render::builtin_vars();
    v.extend(parts.iter().map(|(k, v)| (k.clone(), v.clone())));
    v
}

/// Outcome of a verification plus the variables it extracted.
pub struct Outcome {
    pub verification: Verification,
    pub vars: Vars,
}

/// Verify one secret. Never returns an error: failures map to `Unknown`.
pub async fn verify(http: &Http, t: &Template, parts: &BTreeMap<String, String>) -> Outcome {
    let mut vars = secret_vars(parts);
    let Some(v) = &t.verify else {
        return Outcome {
            verification: Verification::new(
                Status::Unsupported,
                Some("template has no verifier".into()),
                BTreeMap::new(),
            ),
            vars,
        };
    };
    // Primary endpoint first, then fallbacks until one verifies the secret.
    let attempts = std::iter::once((None, &v.request, &v.valid, v.invalid.as_ref())).chain(
        v.fallbacks.iter().map(|f| {
            (
                Some(f.label.clone().unwrap_or_else(|| f.request.url.clone())),
                &f.request,
                f.valid.as_ref().unwrap_or(&v.valid),
                f.invalid.as_ref().or(v.invalid.as_ref()),
            )
        }),
    );
    let mut status = Status::Unknown;
    let mut message = None;
    let mut verified_resp = None;
    let mut endpoint = None;
    let mut all_invalid = true;
    let mut first_invalid = None;
    let mut unknown_reasons = Vec::new();
    for (label, req, valid, invalid) in attempts {
        let resp = match http.execute(req, &vars).await {
            Ok(r) => r,
            Err(e) => {
                all_invalid = false;
                unknown_reasons.push(format!("{e:#}"));
                continue;
            }
        };
        match http::check(valid, &resp) {
            Ok(()) => {
                status = Status::Verified;
                endpoint = label;
                verified_resp = Some(resp);
                break;
            }
            Err(why_not_valid) => match invalid {
                Some(inv) if http::check(inv, &resp).is_ok() => {
                    first_invalid.get_or_insert_with(|| {
                        format!("HTTP {}: {}", resp.status, http::snippet(&resp.body))
                    });
                }
                _ => {
                    all_invalid = false;
                    unknown_reasons.push(format!(
                        "unexpected response ({why_not_valid}): {}",
                        http::snippet(&resp.body)
                    ));
                }
            },
        }
    }
    if status != Status::Verified {
        if all_invalid {
            status = Status::Invalid;
            message = first_invalid;
        } else {
            message = Some(unknown_reasons.join(" | "));
        }
    }
    let mut details = BTreeMap::new();
    if let Some(resp) = &verified_resp {
        if let Some(ep) = endpoint {
            details.insert("Endpoint".to_string(), serde_json::Value::String(ep));
        }
        for e in &v.extract {
            if let Some(val) = http::extract(e, resp) {
                vars.insert(e.name.clone(), http::value_to_var(&val));
                let shown = if e.secret {
                    serde_json::Value::String(crate::finding::redact(&http::value_to_var(&val)))
                } else {
                    val
                };
                details.insert(e.label.clone().unwrap_or_else(|| e.name.clone()), shown);
            }
        }
    }
    Outcome {
        verification: Verification::new(status, message.map(|m| mask_secrets(&m, parts)), details),
        vars,
    }
}

/// Defence in depth: never echo a secret back inside a diagnostic message.
pub fn mask_secrets(msg: &str, parts: &BTreeMap<String, String>) -> String {
    let mut out = msg.to_string();
    for v in parts.values().filter(|v| v.len() >= 6) {
        out = out.replace(v.as_str(), &crate::finding::redact(v));
    }
    out
}

/// Verify one secret through the cache: a fresh cached result is returned
/// as is (marked [`Verification::cached`], nothing is sent); otherwise the
/// platform is asked and the result stored. `fresh` skips the lookup (an
/// explicit re-check) but still stores the new result.
pub async fn verify_cached(
    http: &Http,
    t: &Template,
    parts: &BTreeMap<String, String>,
    cache: Option<&VerifyCache>,
    fresh: bool,
) -> Verification {
    let fingerprint = crate::finding::fingerprint(&t.id, parts);
    if let Some(c) = cache
        && !fresh
        && let Some(v) = c.get(&fingerprint, t)
    {
        return v;
    }
    let v = verify(http, t, parts).await.verification;
    if let Some(c) = cache {
        c.put(&fingerprint, t, &v);
    }
    v
}

/// Verify a batch of findings concurrently. Identical secrets are verified
/// once (keyed by fingerprint) to avoid hammering vendor APIs, and with a
/// `cache` results of earlier runs are reused while fresh (the caller saves
/// it).
pub async fn verify_findings(
    http: &Http,
    templates: &HashMap<String, Arc<Template>>,
    findings: &mut [Finding],
    concurrency: usize,
    cache: Option<&VerifyCache>,
) {
    let results: Mutex<HashMap<String, Verification>> = Mutex::new(HashMap::new());
    let mut unique: BTreeMap<String, (String, BTreeMap<String, String>)> = BTreeMap::new();
    for f in findings.iter() {
        unique
            .entry(f.fingerprint.clone())
            .or_insert_with(|| (f.detector.clone(), f.secret.clone()));
    }
    futures::stream::iter(unique)
        .map(|(fp, (det, parts))| {
            let results = &results;
            async move {
                let Some(t) = templates.get(&det) else { return };
                let v = verify_cached(http, t, &parts, cache, false).await;
                results.lock().await.insert(fp, v);
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<()>>()
        .await;
    let results = results.into_inner();
    for f in findings.iter_mut() {
        f.verification = results.get(&f.fingerprint).cloned();
    }
}
