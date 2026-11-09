//! Shared step runner for `analyze` and `rotate` flows.

use serde::Serialize;
use serde_json::Value;

use crate::finding::redact;
use crate::http::{self, Http, Prepared};
use crate::render::Vars;
use crate::template::Step;

#[derive(Debug, Clone, Serialize)]
pub struct Extracted {
    pub name: String,
    pub label: String,
    pub value: Value,
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<Extracted>,
}

impl StepResult {
    /// Copy with secret values masked (for display / JSON output).
    pub fn redacted(&self) -> Self {
        let mut s = self.clone();
        for v in &mut s.values {
            if v.secret {
                v.value = Value::String(redact(&http::value_to_var(&v.value)));
            }
        }
        s
    }
}

/// Execute one step; extracted values are added to `vars`.
pub async fn run(http: &Http, step: &Step, vars: &mut Vars) -> StepResult {
    let mut res = StepResult {
        name: step.name.clone(),
        description: step.description.clone(),
        ok: false,
        http_status: None,
        error: None,
        values: Vec::new(),
    };
    let resp = match http.execute(&step.request, vars).await {
        Ok(r) => r,
        Err(e) => {
            res.error = Some(format!("{e:#}"));
            return res;
        }
    };
    res.http_status = Some(resp.status);
    let expect_default;
    let expect = match &step.expect {
        Some(m) => m,
        None => {
            // Without an explicit expectation any 2xx counts as success.
            expect_default = crate::template::Matcher {
                status: (200..300).collect(),
                ..Default::default()
            };
            &expect_default
        }
    };
    if let Err(why) = http::check(expect, &resp) {
        res.error = Some(format!("{why}: {}", http::snippet(&resp.body)));
        return res;
    }
    res.ok = true;
    for e in &step.extract {
        if let Some(val) = http::extract(e, &resp) {
            vars.insert(e.name.clone(), http::value_to_var(&val));
            res.values.push(Extracted {
                name: e.name.clone(),
                label: e.label.clone().unwrap_or_else(|| e.name.clone()),
                value: val,
                secret: e.secret,
            });
        }
    }
    res
}

/// Human readable rendering of a prepared request with secrets masked.
pub fn describe(p: &Prepared, secrets: &[String]) -> String {
    let mask = |s: &str| -> String {
        let mut out = s.to_string();
        for sec in secrets.iter().filter(|s| s.len() >= 4) {
            let enc =
                percent_encoding::utf8_percent_encode(sec, percent_encoding::NON_ALPHANUMERIC)
                    .to_string();
            out = out.replace(sec.as_str(), &redact(sec));
            out = out.replace(&enc, &redact(sec));
        }
        out
    };
    let mut s = format!("{} {}\n", p.method, mask(p.url.as_str()));
    for (k, v) in &p.headers {
        let lk = k.to_lowercase();
        let sensitive = ["auth", "token", "key", "secret", "cookie", "signature"]
            .iter()
            .any(|w| lk.contains(w));
        let v = if sensitive {
            "<redacted>".to_string()
        } else {
            mask(v)
        };
        s.push_str(&format!("  {k}: {v}\n"));
    }
    if let Some(b) = &p.body {
        s.push_str(&format!("  body: {}\n", mask(&String::from_utf8_lossy(b))));
    }
    s
}
