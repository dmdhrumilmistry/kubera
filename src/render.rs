//! Tiny, strict string templating used inside detector templates.
//!
//! Syntax: `{{ expr }}` where `expr` is a variable name or a quoted literal,
//! optionally followed by filters: `{{ token | base64 }}`,
//! `{{ 'user:' }}{{ pass | urlencode }}`.
//!
//! Referencing an unknown variable is an error, so typos in templates are
//! caught by `kubera templates validate` instead of silently sending an
//! empty credential.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use sha2::{Digest, Sha256};

pub type Vars = BTreeMap<String, String>;

pub const FILTERS: &[&str] = &[
    "base64",
    "base64url",
    "urlencode",
    "upper",
    "lower",
    "sha256",
    "trim",
    "json",
];

/// Variables available to every template.
pub fn builtin_vars() -> Vars {
    let now = chrono::Utc::now();
    let mut v = Vars::new();
    v.insert("now".into(), now.timestamp().to_string());
    v.insert("date".into(), now.format("%Y-%m-%d").to_string());
    v.insert(
        "datetime".into(),
        now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    );
    v
}

#[derive(Debug, PartialEq)]
enum Term {
    Var(String),
    Lit(String),
}

#[derive(Debug)]
struct Expr {
    term: Term,
    filters: Vec<String>,
}

fn parse_expr(src: &str) -> Result<Expr> {
    let mut parts = split_pipes(src)?.into_iter();
    let head = parts.next().unwrap_or_default();
    let head = head.trim();
    if head.is_empty() {
        bail!("empty expression in `{{{{ {src} }}}}`");
    }
    let term = if let Some(lit) = parse_literal(head) {
        Term::Lit(lit)
    } else {
        if !head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            bail!("invalid variable name `{head}`");
        }
        Term::Var(head.to_string())
    };
    let mut filters = Vec::new();
    for f in parts {
        let f = f.trim().to_string();
        if !FILTERS.contains(&f.as_str()) {
            bail!("unknown filter `{f}` (available: {})", FILTERS.join(", "));
        }
        filters.push(f);
    }
    Ok(Expr { term, filters })
}

/// Split on `|` while respecting quoted literals.
fn split_pipes(src: &str) -> Result<Vec<String>> {
    let mut out = vec![String::new()];
    let mut quote: Option<char> = None;
    for c in src.chars() {
        match (quote, c) {
            (None, '\'' | '"') => {
                quote = Some(c);
                out.last_mut().unwrap().push(c);
            }
            (Some(q), _) if c == q => {
                quote = None;
                out.last_mut().unwrap().push(c);
            }
            (None, '|') => out.push(String::new()),
            _ => out.last_mut().unwrap().push(c),
        }
    }
    if quote.is_some() {
        bail!("unterminated string literal in `{src}`");
    }
    Ok(out)
}

fn parse_literal(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() >= 2 {
        let (f, l) = (s.as_bytes()[0], s.as_bytes()[s.len() - 1]);
        if (f == b'\'' || f == b'"') && f == l {
            return Some(s[1..s.len() - 1].to_string());
        }
    }
    None
}

fn apply_filter(name: &str, v: String) -> String {
    match name {
        "base64" => base64::engine::general_purpose::STANDARD.encode(v),
        "base64url" => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v),
        "urlencode" => {
            percent_encoding::utf8_percent_encode(&v, percent_encoding::NON_ALPHANUMERIC)
                .to_string()
        }
        "upper" => v.to_uppercase(),
        "lower" => v.to_lowercase(),
        "sha256" => hex::encode(Sha256::digest(v.as_bytes())),
        "trim" => v.trim().to_string(),
        "json" => {
            let s = serde_json::to_string(&v).unwrap_or_default();
            s[1..s.len() - 1].to_string()
        }
        _ => v,
    }
}

/// Iterate over `(literal_prefix, Some(expr_src))` segments.
fn segments(input: &str) -> Result<Vec<(&str, Option<&str>)>> {
    let mut out = Vec::new();
    let mut rest = input;
    loop {
        match rest.find("{{") {
            None => {
                out.push((rest, None));
                return Ok(out);
            }
            Some(start) => {
                let after = &rest[start + 2..];
                let end = after
                    .find("}}")
                    .ok_or_else(|| anyhow!("unclosed `{{{{` in `{input}`"))?;
                out.push((&rest[..start], Some(&after[..end])));
                rest = &after[end + 2..];
            }
        }
    }
}

/// Render `input` with `vars`.
pub fn render(input: &str, vars: &Vars) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    for (lit, expr) in segments(input)? {
        out.push_str(lit);
        if let Some(src) = expr {
            let e = parse_expr(src)?;
            let mut v = match e.term {
                Term::Lit(l) => l,
                Term::Var(name) => vars
                    .get(&name)
                    .cloned()
                    .with_context(|| format!("unknown variable `{name}`"))?,
            };
            for f in &e.filters {
                v = apply_filter(f, v);
            }
            out.push_str(&v);
        }
    }
    Ok(out)
}

/// Render every string inside a JSON value.
pub fn render_json(value: &serde_json::Value, vars: &Vars) -> Result<serde_json::Value> {
    use serde_json::Value;
    Ok(match value {
        Value::String(s) => Value::String(render(s, vars)?),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|v| render_json(v, vars))
                .collect::<Result<_>>()?,
        ),
        Value::Object(o) => {
            let mut m = serde_json::Map::new();
            for (k, v) in o {
                m.insert(render(k, vars)?, render_json(v, vars)?);
            }
            Value::Object(m)
        }
        other => other.clone(),
    })
}

/// Variables referenced by `input` (used for static validation).
pub fn referenced_vars(input: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for (_, expr) in segments(input)? {
        if let Some(src) = expr
            && let Term::Var(v) = parse_expr(src)?.term
        {
            out.push(v);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vars {
        let mut v = Vars::new();
        v.insert("token".into(), "abc".into());
        v.insert("user".into(), "me@x.io".into());
        v
    }

    #[test]
    fn renders_vars_literals_and_filters() {
        let v = vars();
        assert_eq!(render("Bearer {{ token }}", &v).unwrap(), "Bearer abc");
        assert_eq!(render("{{token|upper}}", &v).unwrap(), "ABC");
        assert_eq!(render("{{ token | base64 }}", &v).unwrap(), "YWJj");
        assert_eq!(render("{{ user | urlencode }}", &v).unwrap(), "me%40x%2Eio");
        assert_eq!(render("xo{{'x'}}b-1", &v).unwrap(), "xoxb-1");
        assert_eq!(render("{{ 'a|b' | upper }}", &v).unwrap(), "A|B");
        assert_eq!(render("no braces", &v).unwrap(), "no braces");
    }

    #[test]
    fn rejects_unknowns() {
        let v = vars();
        assert!(render("{{ nope }}", &v).is_err());
        assert!(render("{{ token | rot13 }}", &v).is_err());
        assert!(render("{{ token ", &v).is_err());
    }

    #[test]
    fn renders_json_recursively() {
        let v = vars();
        let j = serde_json::json!({"credentials": ["{{token}}"], "n": 1});
        assert_eq!(
            render_json(&j, &v).unwrap(),
            serde_json::json!({"credentials": ["abc"], "n": 1})
        );
    }

    #[test]
    fn lists_referenced_vars() {
        assert_eq!(
            referenced_vars("{{a}}-{{ 'x' }}-{{ b | upper }}").unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
    }
}
