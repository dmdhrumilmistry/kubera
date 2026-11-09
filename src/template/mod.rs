//! Loading and validating detector templates.

pub mod schema;
pub mod testing;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use include_dir::{Dir, include_dir};
use regex::Regex;

pub use schema::*;

use crate::render;

static BUILTIN: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// A template together with where it was loaded from.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub template: Template,
    pub source: String,
}

pub fn parse(yaml: &str, source: &str) -> Result<Template> {
    // Resolve anchors + `<<` merge keys first so templates can share request
    // fragments (typed deserialization does not apply merges by itself).
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(yaml).with_context(|| format!("failed to parse template {source}"))?;
    value
        .apply_merge()
        .with_context(|| format!("failed to resolve merge keys in {source}"))?;
    let t: Template = serde_yaml::from_value(value)
        .with_context(|| format!("failed to parse template {source}"))?;
    validate(&t).with_context(|| format!("invalid template {source} ({})", t.id))?;
    Ok(t)
}

/// Templates compiled into the binary.
pub fn builtin() -> Result<Vec<Loaded>> {
    let mut out = Vec::new();
    for file in BUILTIN.files() {
        let path = file.path();
        if !is_yaml(path) {
            continue;
        }
        let src = format!("builtin:{}", path.display());
        let yaml = file
            .contents_utf8()
            .with_context(|| format!("{src} is not utf-8"))?;
        out.push(Loaded {
            template: parse(yaml, &src)?,
            source: src,
        });
    }
    out.sort_by(|a, b| a.template.id.cmp(&b.template.id));
    Ok(out)
}

fn is_yaml(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("yaml") | Some("yml")
    )
}

/// Load every `*.yaml`/`*.yml` template below `path` (or the file itself).
pub fn load_path(path: &Path) -> Result<Vec<Loaded>> {
    let mut files: Vec<PathBuf> = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else {
        for entry in walkdir::WalkDir::new(path).sort_by_file_name() {
            let entry = entry?;
            if entry.file_type().is_file() && is_yaml(entry.path()) {
                files.push(entry.into_path());
            }
        }
    }
    files
        .into_iter()
        .map(|f| {
            let yaml =
                std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
            let src = f.display().to_string();
            Ok(Loaded {
                template: parse(&yaml, &src)?,
                source: src,
            })
        })
        .collect()
}

/// Build the active template set: builtin (unless disabled) overlaid with
/// user templates (same id replaces the builtin one), then filtered.
pub fn load_set(
    extra: &[PathBuf],
    include_builtin: bool,
    only: &[String],
    exclude: &[String],
) -> Result<Vec<Loaded>> {
    let mut by_id: BTreeMap<String, Loaded> = BTreeMap::new();
    if include_builtin {
        for l in builtin()? {
            by_id.insert(l.template.id.clone(), l);
        }
    }
    for p in extra {
        for l in load_path(p)? {
            by_id.insert(l.template.id.clone(), l);
        }
    }
    for id in only.iter().chain(exclude) {
        if !by_id.contains_key(id) {
            bail!("unknown detector `{id}` (see `kubera templates list`)");
        }
    }
    Ok(by_id
        .into_values()
        .filter(|l| only.is_empty() || only.contains(&l.template.id))
        .filter(|l| !exclude.contains(&l.template.id))
        .collect())
}

pub fn find<'a>(set: &'a [Loaded], id: &str) -> Result<&'a Template> {
    set.iter()
        .map(|l| &l.template)
        .find(|t| t.id == id)
        .with_context(|| format!("unknown detector `{id}` (see `kubera templates list`)"))
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Names that patterns expose as variables (part names + extra captures).
pub fn secret_vars(t: &Template) -> BTreeSet<String> {
    let mut v = BTreeSet::new();
    for p in &t.detect.patterns {
        v.insert(p.name.clone());
        v.extend(p.captures.iter().cloned());
    }
    v
}

/// Static checks: ids, regexes, capture groups, and that every `{{ var }}`
/// used in a request is defined at that point of the flow.
pub fn validate(t: &Template) -> Result<()> {
    if !valid_ident(&t.id) {
        bail!("id `{}` must be non-empty and use [A-Za-z0-9_-]", t.id);
    }
    if t.detect.patterns.is_empty() {
        bail!("detect.patterns must not be empty");
    }
    if t.detect.patterns.iter().all(|p| p.optional) {
        bail!("at least one pattern must not be optional");
    }
    if t.detect.keywords.iter().any(|k| k.trim().is_empty()) || t.detect.keywords.is_empty() {
        bail!("detect.keywords must contain at least one non-empty keyword");
    }
    let mut names = BTreeSet::new();
    for p in &t.detect.patterns {
        if !valid_ident(&p.name) {
            bail!("pattern name `{}` must use [A-Za-z0-9_-]", p.name);
        }
        if !names.insert(p.name.clone()) {
            bail!("duplicate pattern name `{}`", p.name);
        }
        let re = Regex::new(&p.regex)
            .with_context(|| format!("pattern `{}` has an invalid regex", p.name))?;
        if let Some(g) = p.group
            && g >= re.captures_len()
        {
            bail!("pattern `{}` group {g} does not exist in its regex", p.name);
        }
        let groups: BTreeSet<&str> = re.capture_names().flatten().collect();
        for c in &p.captures {
            if !groups.contains(c.as_str()) {
                bail!("pattern `{}` capture `{c}` is not a named group", p.name);
            }
            if !names.insert(c.clone()) {
                bail!("capture `{c}` clashes with another variable");
            }
        }
        for ex in &p.exclude {
            Regex::new(ex).with_context(|| format!("pattern `{}` exclude regex", p.name))?;
        }
    }

    let mut vars: BTreeSet<String> = secret_vars(t);
    vars.extend(render::builtin_vars().into_keys());

    if let Some(v) = &t.verify {
        check_request(&v.request, &vars).context("verify.request")?;
        check_matcher(&v.valid)?;
        if let Some(m) = &v.invalid {
            check_matcher(m)?;
        }
        for (i, fb) in v.fallbacks.iter().enumerate() {
            check_request(&fb.request, &vars)
                .with_context(|| format!("verify.fallbacks[{i}].request"))?;
            for m in fb.valid.iter().chain(fb.invalid.iter()) {
                check_matcher(m)?;
            }
        }
        check_extracts(&v.extract)?;
        vars.extend(v.extract.iter().map(|e| e.name.clone()));
    }

    if let Some(a) = &t.analyze {
        let mut avars = vars.clone();
        check_steps(&a.steps, &mut avars).context("analyze")?;
    }

    if let Some(r) = &t.rotate {
        if r.instructions.is_none() && r.steps.is_empty() {
            bail!("rotate needs `instructions` and/or `steps`");
        }
        let mut rvars = vars.clone();
        for i in &r.inputs {
            if !valid_ident(&i.name) {
                bail!("rotate input `{}` must use [A-Za-z0-9_-]", i.name);
            }
            if let Some(d) = &i.default {
                check_str(d, &rvars).with_context(|| format!("rotate input `{}`", i.name))?;
            }
            rvars.insert(i.name.clone());
        }
        check_steps(&r.steps, &mut rvars).context("rotate")?;
        for o in &r.outputs {
            if !rvars.contains(o) {
                bail!("rotate output `{o}` is never extracted");
            }
        }
    }

    if let Some(tests) = &t.tests {
        let builtins = render::builtin_vars();
        for s in tests.positive.iter().chain(&tests.negative) {
            render::render(s, &builtins).context("tests sample")?;
        }
    }
    Ok(())
}

fn check_steps(steps: &[Step], vars: &mut BTreeSet<String>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for s in steps {
        if !seen.insert(s.name.clone()) {
            bail!("duplicate step name `{}`", s.name);
        }
        check_request(&s.request, vars).with_context(|| format!("step `{}`", s.name))?;
        if let Some(m) = &s.expect {
            check_matcher(m)?;
        }
        check_extracts(&s.extract).with_context(|| format!("step `{}`", s.name))?;
        vars.extend(s.extract.iter().map(|e| e.name.clone()));
    }
    Ok(())
}

fn check_extracts(ex: &[Extract]) -> Result<()> {
    for e in ex {
        if !valid_ident(&e.name) {
            bail!("extract name `{}` must use [A-Za-z0-9_-]", e.name);
        }
        let n = [e.json.is_some(), e.header.is_some(), e.regex.is_some()]
            .iter()
            .filter(|b| **b)
            .count();
        if n != 1 {
            bail!(
                "extract `{}` needs exactly one of `json`, `header`, `regex`",
                e.name
            );
        }
        if let Some(r) = &e.regex {
            Regex::new(r).with_context(|| format!("extract `{}` regex", e.name))?;
        }
    }
    Ok(())
}

fn check_matcher(m: &Matcher) -> Result<()> {
    for j in &m.json {
        if j.equals.is_none() && j.exists.is_none() {
            bail!("json condition on `{}` needs `equals` or `exists`", j.path);
        }
    }
    m.any.iter().try_for_each(check_matcher)
}

fn check_str(s: &str, vars: &BTreeSet<String>) -> Result<()> {
    for v in render::referenced_vars(s)? {
        if !vars.contains(&v) {
            bail!(
                "`{s}` references undefined variable `{v}` (defined here: {})",
                vars.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }
    Ok(())
}

fn check_json(v: &serde_json::Value, vars: &BTreeSet<String>) -> Result<()> {
    match v {
        serde_json::Value::String(s) => check_str(s, vars),
        serde_json::Value::Array(a) => a.iter().try_for_each(|x| check_json(x, vars)),
        serde_json::Value::Object(o) => o.iter().try_for_each(|(k, x)| {
            check_str(k, vars)?;
            check_json(x, vars)
        }),
        _ => Ok(()),
    }
}

fn check_request(r: &Request, vars: &BTreeSet<String>) -> Result<()> {
    reqwest::Method::from_bytes(r.method.to_uppercase().as_bytes())
        .with_context(|| format!("invalid method `{}`", r.method))?;
    check_str(&r.url, vars)?;
    for (k, v) in r.headers.iter().chain(&r.query) {
        check_str(k, vars)?;
        check_str(v, vars)?;
    }
    if let Some(f) = &r.form {
        for v in f.values() {
            check_str(v, vars)?;
        }
    }
    if let Some(b) = &r.body {
        check_str(b, vars)?;
    }
    if let Some(j) = &r.json {
        check_json(j, vars)?;
    }
    let bodies = [r.body.is_some(), r.form.is_some(), r.json.is_some()]
        .iter()
        .filter(|b| **b)
        .count();
    if bodies > 1 {
        bail!("request may only set one of `body`, `form`, `json`");
    }
    match &r.auth {
        Some(Auth::Basic { username, password }) => {
            check_str(username, vars)?;
            check_str(password, vars)?;
        }
        Some(Auth::Bearer { token }) => check_str(token, vars)?,
        Some(Auth::AwsSigv4 {
            access_key,
            secret_key,
            session_token,
            region,
            service,
        }) => {
            for s in [access_key, secret_key, region, service] {
                check_str(s, vars)?;
            }
            if let Some(s) = session_token {
                check_str(s, vars)?;
            }
        }
        None => {}
    }
    Ok(())
}
