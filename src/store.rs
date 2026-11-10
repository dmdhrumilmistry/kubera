//! Secret stores: after `rotate --execute`, write the new credential to
//! where its consumers read it ("close the loop").
//!
//! Destinations (`--store`, repeatable):
//!
//! * `github:<owner>/<repo>:<SECRET_NAME>[=<output>]` - a GitHub Actions
//!   repository secret. The value is encrypted on this machine with the
//!   repository's public key (libsodium sealed box), so GitHub only ever
//!   receives ciphertext. Token from `--store-token-env`.
//! * `vault:<mount>/<path>#<key>[=<output>]` - HashiCorp Vault KV v2. The
//!   key is merged into the secret (`PATCH`), other keys are kept; a
//!   missing secret is created (`POST` with `cas=0`). `VAULT_ADDR`,
//!   `VAULT_TOKEN`, optional `VAULT_NAMESPACE`.
//! * `aws-sm:<secret-id>[#<json-key>][=<output>]` - AWS Secrets Manager
//!   `PutSecretValue`, SigV4 signed with the standard `AWS_*` variables.
//!   With a JSON key the current value is read, the key set, and the whole
//!   object written back as a new version.
//!
//! `=<output>` picks the rotation output to store; it defaults to the
//! template's only secret output. Several keys for the same Vault path or
//! AWS secret are written in one request, so consumers never see a new key
//! id next to an old secret.
//!
//! Safety: credentials only come from environment variables; every request
//! goes to the configured host over HTTPS (the shared client never follows
//! redirects); plans and errors never show values; nothing is written to
//! disk.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde::Serialize;
use serde_json::{Value, json};

use crate::http::{Http, Prepared, Response, redact_url, sigv4};
use crate::template::Template;

const TIMEOUT: Duration = Duration::from_secs(20);
pub const GITHUB_API: &str = "https://api.github.com";

/// Where one value goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dest {
    GitHub {
        owner: String,
        repo: String,
        name: String,
    },
    Vault {
        mount: String,
        path: String,
        key: String,
    },
    AwsSm {
        secret_id: String,
        json_key: Option<String>,
    },
}

/// One parsed `--store` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub dest: Dest,
    /// Rotation output stored there.
    pub output: String,
}

/// The outputs a template declares, and the default one to store.
pub fn outputs_of(t: &Template) -> (Vec<String>, Option<String>) {
    let Some(r) = &t.rotate else {
        return (Vec::new(), None);
    };
    let secret: Vec<&String> = r
        .outputs
        .iter()
        .filter(|o| {
            r.steps
                .iter()
                .flat_map(|s| &s.extract)
                .any(|e| &e.name == *o && e.secret)
        })
        .collect();
    let default = match (r.outputs.len(), secret.as_slice()) {
        (1, _) => Some(r.outputs[0].clone()),
        (_, [one]) => Some((*one).clone()),
        _ => None,
    };
    (r.outputs.clone(), default)
}

fn valid_name(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

/// Parse `--store` against the template's outputs.
pub fn parse(raw: &str, outputs: &[String], default: Option<&str>) -> Result<Spec> {
    let (kind, rest) = raw
        .split_once(':')
        .with_context(|| format!("--store `{raw}`: expected github:, vault: or aws-sm:"))?;
    // `=output` only when it names a declared output (AWS secret names may
    // contain `=`).
    let (rest, output) = match rest.rsplit_once('=') {
        Some((l, o)) if outputs.iter().any(|x| x == o) => (l, o.to_string()),
        Some((_, o)) if kind == "github" || kind == "vault" => bail!(
            "--store `{raw}`: `{o}` is not an output of this rotation (outputs: {})",
            outputs.join(", ")
        ),
        _ => match default {
            Some(d) => (rest, d.to_string()),
            None => bail!(
                "--store `{raw}`: say which output to store with `=<output>` (outputs: {})",
                outputs.join(", ")
            ),
        },
    };
    let dest = match kind {
        "github" => {
            let (repo, name) = rest.rsplit_once(':').with_context(|| {
                format!("--store `{raw}`: expected github:<owner>/<repo>:<SECRET_NAME>")
            })?;
            let (owner, repo) = repo
                .split_once('/')
                .with_context(|| format!("--store `{raw}`: expected <owner>/<repo>"))?;
            if !valid_name(owner, "-") || !valid_name(repo, "-_.") || repo.starts_with('.') {
                bail!("--store `{raw}`: invalid repository `{owner}/{repo}`");
            }
            if !valid_name(name, "_")
                || name.starts_with(|c: char| c.is_ascii_digit())
                || name.to_ascii_uppercase().starts_with("GITHUB_")
            {
                bail!(
                    "--store `{raw}`: invalid secret name `{name}` (letters, digits and _, not starting with a digit or GITHUB_)"
                );
            }
            Dest::GitHub {
                owner: owner.into(),
                repo: repo.into(),
                name: name.into(),
            }
        }
        "vault" => {
            let (loc, key) = rest
                .rsplit_once('#')
                .with_context(|| format!("--store `{raw}`: expected vault:<mount>/<path>#<key>"))?;
            let (mount, path) = loc
                .trim_matches('/')
                .split_once('/')
                .with_context(|| format!("--store `{raw}`: expected vault:<mount>/<path>#<key>"))?;
            let segs_ok = |s: &str| {
                s.split('/')
                    .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
            };
            if !segs_ok(mount) || !segs_ok(path) || key.is_empty() {
                bail!("--store `{raw}`: invalid Vault path or key");
            }
            Dest::Vault {
                mount: mount.into(),
                path: path.into(),
                key: key.into(),
            }
        }
        "aws-sm" => {
            let (id, key) = match rest.split_once('#') {
                Some((id, k)) if !k.is_empty() => (id, Some(k.to_string())),
                Some(_) => bail!("--store `{raw}`: empty JSON key"),
                None => (rest, None),
            };
            if id.is_empty() || id.len() > 2048 {
                bail!("--store `{raw}`: invalid secret id");
            }
            Dest::AwsSm {
                secret_id: id.into(),
                json_key: key,
            }
        }
        k => bail!("--store `{raw}`: unknown store `{k}` (github, vault, aws-sm)"),
    };
    Ok(Spec { dest, output })
}

/// One write: a destination and the `(key, output)` pairs it receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub target: Target,
    /// `(key, output)`; the key is `None` for a whole-value write.
    pub entries: Vec<(Option<String>, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    GitHub {
        owner: String,
        repo: String,
        name: String,
    },
    Vault {
        mount: String,
        path: String,
    },
    AwsSm {
        secret_id: String,
    },
}

impl Target {
    pub fn label(&self) -> String {
        match self {
            Target::GitHub { owner, repo, name } => format!("github:{owner}/{repo}:{name}"),
            Target::Vault { mount, path } => format!("vault:{mount}/{path}"),
            Target::AwsSm { secret_id } => format!("aws-sm:{secret_id}"),
        }
    }
}

/// Merge specs that write to the same place; reject conflicting ones.
pub fn group(specs: &[Spec]) -> Result<Vec<Group>> {
    let mut groups: Vec<Group> = Vec::new();
    for s in specs {
        let (target, key) = match &s.dest {
            Dest::GitHub { owner, repo, name } => (
                Target::GitHub {
                    owner: owner.clone(),
                    repo: repo.clone(),
                    name: name.clone(),
                },
                None,
            ),
            Dest::Vault { mount, path, key } => (
                Target::Vault {
                    mount: mount.clone(),
                    path: path.clone(),
                },
                Some(key.clone()),
            ),
            Dest::AwsSm {
                secret_id,
                json_key,
            } => (
                Target::AwsSm {
                    secret_id: secret_id.clone(),
                },
                json_key.clone(),
            ),
        };
        match groups.iter_mut().find(|g| g.target == target) {
            None => groups.push(Group {
                target,
                entries: vec![(key, s.output.clone())],
            }),
            Some(g) => {
                if key.is_none() || g.entries.iter().any(|(k, _)| k.is_none() || *k == key) {
                    bail!(
                        "--store {} is given twice for the same {}",
                        g.target.label(),
                        if key.is_none() { "secret" } else { "key" }
                    );
                }
                g.entries.push((key, s.output.clone()));
            }
        }
    }
    Ok(groups)
}

/// Credentials and endpoints, all from the environment or flags.
#[derive(Clone, Default)]
pub struct Config {
    pub github_api: String,
    pub github_token: Option<String>,
    /// Name of the variable the GitHub token comes from (messages).
    pub github_token_env: Option<String>,
    pub vault_addr: Option<String>,
    pub vault_token: Option<String>,
    pub vault_namespace: Option<String>,
    pub aws: Option<crate::sources::bucket::AwsCreds>,
    pub aws_region: Option<String>,
    pub aws_endpoint: Option<String>,
    pub allow_http: bool,
}

impl Config {
    /// Read everything from the environment. `token_env` names the variable
    /// with the GitHub token; `region` overrides `AWS_REGION`.
    pub fn from_env(
        token_env: Option<&str>,
        github_api: Option<&str>,
        region: Option<&str>,
        allow_http: bool,
    ) -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self {
            github_api: github_api
                .unwrap_or(GITHUB_API)
                .trim_end_matches('/')
                .to_string(),
            github_token: token_env.and_then(env),
            github_token_env: token_env.map(str::to_string),
            vault_addr: env("VAULT_ADDR").map(|a| a.trim_end_matches('/').to_string()),
            vault_token: env("VAULT_TOKEN"),
            vault_namespace: env("VAULT_NAMESPACE"),
            aws: crate::sources::bucket::AwsCreds::from_env(),
            aws_region: region
                .map(str::to_string)
                .or_else(|| env("AWS_REGION"))
                .or_else(|| env("AWS_DEFAULT_REGION")),
            aws_endpoint: env("AWS_ENDPOINT_URL_SECRETS_MANAGER")
                .or_else(|| env("AWS_ENDPOINT_URL")),
            allow_http,
        }
    }

    /// Problems that would make a write fail, found before anything runs.
    pub fn problems(&self, groups: &[Group]) -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |m: String| {
            if !out.contains(&m) {
                out.push(m)
            }
        };
        for g in groups {
            match &g.target {
                Target::GitHub { .. } => {
                    match (&self.github_token_env, &self.github_token) {
                        (None, _) => push("github stores need --store-token-env <ENV_VAR> (a token allowed to write Actions secrets)".into()),
                        (Some(v), None) => push(format!("environment variable `{v}` (from --store-token-env) is not set")),
                        _ => {}
                    }
                    if let Err(e) = self.base_url(&self.github_api) {
                        push(format!("GitHub API: {e:#}"));
                    }
                }
                Target::Vault { .. } => match (&self.vault_addr, &self.vault_token) {
                    (None, _) => push("vault stores need VAULT_ADDR".into()),
                    (_, None) => push("vault stores need VAULT_TOKEN".into()),
                    (Some(a), _) => {
                        if let Err(e) = self.base_url(a) {
                            push(format!("VAULT_ADDR: {e:#}"));
                        }
                    }
                },
                Target::AwsSm { .. } => {
                    if self.aws.is_none() {
                        push(
                            "aws-sm stores need AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY".into(),
                        );
                    }
                    if self.aws_region.is_none() {
                        push("aws-sm stores need a region: --store-region, AWS_REGION or AWS_DEFAULT_REGION".into());
                    }
                    if let Some(e) = &self.aws_endpoint
                        && let Err(err) = self.base_url(e)
                    {
                        push(format!("AWS endpoint: {err:#}"));
                    }
                }
            }
        }
        out
    }

    fn base_url(&self, raw: &str) -> Result<reqwest::Url> {
        let u = reqwest::Url::parse(raw).context("not a valid URL")?;
        match u.scheme() {
            "https" => Ok(u),
            "http" if self.allow_http => Ok(u),
            s => bail!("refusing `{s}://`; secret stores must use https"),
        }
    }

    fn aws_url(&self) -> Result<reqwest::Url> {
        let region = self.aws_region.as_deref().context("no AWS region")?;
        match &self.aws_endpoint {
            Some(e) => self.base_url(e),
            None => self.base_url(&format!("https://secretsmanager.{region}.amazonaws.com/")),
        }
    }

    fn url(&self, base: &str, path: &str) -> Result<reqwest::Url> {
        let b = self.base_url(base)?;
        let joined = format!("{}{path}", b.as_str().trim_end_matches('/'));
        reqwest::Url::parse(&joined).context("invalid URL")
    }
}

/// RFC 3986 unreserved characters stay, everything else is encoded.
const SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, SEGMENT).to_string()
}

/// Percent-encode each segment, keeping the slashes.
fn enc_path(p: &str) -> String {
    p.split('/').map(enc).collect::<Vec<_>>().join("/")
}

/// Result of one store write (or its plan, when not executed).
#[derive(Debug, Clone, Serialize)]
pub struct StoreResult {
    pub target: String,
    /// `key <- output` (or just the output for a whole-value write).
    pub values: Vec<String>,
    /// The requests, without values.
    pub plan: String,
    pub executed: bool,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn values_label(g: &Group) -> Vec<String> {
    g.entries
        .iter()
        .map(|(k, o)| match k {
            Some(k) => format!("{k} <- {o}"),
            None => o.clone(),
        })
        .collect()
}

/// Human readable plan for a group (no values, no credentials).
pub fn describe(cfg: &Config, g: &Group) -> String {
    let show = |r: Result<reqwest::Url>| match r {
        Ok(u) => u.to_string(),
        Err(e) => format!("<{e:#}>"),
    };
    match &g.target {
        Target::GitHub { owner, repo, name } => {
            let base = format!("/repos/{}/{}/actions/secrets", enc(owner), enc(repo));
            format!(
                "GET {}\nPUT {}\n  body: encrypted_value (sealed box with the repository public key), key_id",
                show(cfg.url(&cfg.github_api, &format!("{base}/public-key"))),
                show(cfg.url(&cfg.github_api, &format!("{base}/{}", enc(name)))),
            )
        }
        Target::Vault { mount, path } => {
            let addr = cfg.vault_addr.as_deref().unwrap_or("$VAULT_ADDR");
            let u = cfg
                .url(
                    addr,
                    &format!("/v1/{}/data/{}", enc_path(mount), enc_path(path)),
                )
                .map(|u| u.to_string())
                .unwrap_or_else(|_| format!("{addr}/v1/{mount}/data/{path}"));
            format!(
                "PATCH {u}\n  body: merge keys {} (other keys kept; POST with cas=0 creates a missing secret)",
                g.entries
                    .iter()
                    .filter_map(|(k, _)| k.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Target::AwsSm { secret_id } => {
            let u = cfg
                .aws_url()
                .map(|u| u.to_string())
                .unwrap_or_else(|_| "https://secretsmanager.<region>.amazonaws.com/".into());
            if g.entries[0].0.is_none() {
                format!(
                    "POST {u} PutSecretValue\n  SecretId: {secret_id}\n  SecretString: <{}>",
                    g.entries[0].1
                )
            } else {
                format!(
                    "POST {u} GetSecretValue\nPOST {u} PutSecretValue\n  SecretId: {secret_id}\n  SecretString: current JSON with keys {} replaced",
                    g.entries
                        .iter()
                        .filter_map(|(k, _)| k.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
    }
}

/// Dry-run entries for every group.
pub fn plan(cfg: &Config, groups: &[Group]) -> Vec<StoreResult> {
    groups
        .iter()
        .map(|g| StoreResult {
            target: g.target.label(),
            values: values_label(g),
            plan: describe(cfg, g),
            executed: false,
            ok: false,
            error: None,
        })
        .collect()
}

/// A GitHub repository public key (`key_id`, raw 32-byte key).
#[derive(Clone)]
pub struct PublicKey {
    pub key_id: String,
    pub key: [u8; 32],
}

fn github_headers(cfg: &Config) -> Vec<(String, String)> {
    vec![
        ("accept".into(), "application/vnd.github+json".into()),
        ("x-github-api-version".into(), "2022-11-28".into()),
        (
            "authorization".into(),
            format!("Bearer {}", cfg.github_token.clone().unwrap_or_default()),
        ),
    ]
}

async fn send(
    http: &Http,
    method: &str,
    url: reqwest::Url,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
) -> Result<Response> {
    http.send(&Prepared {
        method: method.into(),
        url,
        headers,
        body,
        timeout: TIMEOUT,
    })
    .await
}

fn fail(what: &str, url: &reqwest::Url, r: &Response) -> anyhow::Error {
    anyhow::anyhow!(
        "{what}: {} answered HTTP {}: {}",
        redact_url(url),
        r.status,
        crate::http::snippet(&r.body)
    )
}

/// Fetch the public key used to encrypt secrets for `owner/repo`.
pub async fn github_public_key(
    http: &Http,
    cfg: &Config,
    owner: &str,
    repo: &str,
) -> Result<PublicKey> {
    let url = cfg.url(
        &cfg.github_api,
        &format!(
            "/repos/{}/{}/actions/secrets/public-key",
            enc(owner),
            enc(repo)
        ),
    )?;
    let r = send(http, "GET", url.clone(), github_headers(cfg), None).await?;
    if r.status != 200 {
        return Err(fail("reading the repository public key", &url, &r));
    }
    let j = r
        .json
        .as_ref()
        .context("public key: response is not JSON")?;
    let key_id = j["key_id"]
        .as_str()
        .context("public key: no key_id")?
        .to_string();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(j["key"].as_str().context("public key: no key")?)
        .context("public key: not base64")?;
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key: expected 32 bytes"))?;
    Ok(PublicKey { key_id, key })
}

/// libsodium `crypto_box_seal`, base64 encoded (what GitHub expects).
pub fn seal(key: &[u8; 32], value: &[u8]) -> Result<String> {
    let pk = crypto_box::PublicKey::from(*key);
    let ct = pk
        .seal(&mut crypto_box::aead::OsRng, value)
        .map_err(|_| anyhow::anyhow!("sealed box encryption failed"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(ct))
}

/// Fetch what is needed before anything is rotated: GitHub public keys
/// (also a check that the token works). Keyed by `owner/repo`.
pub async fn preflight(
    http: &Http,
    cfg: &Config,
    groups: &[Group],
) -> Result<BTreeMap<String, PublicKey>> {
    let mut keys = BTreeMap::new();
    for g in groups {
        if let Target::GitHub { owner, repo, .. } = &g.target {
            let k = format!("{owner}/{repo}");
            if let std::collections::btree_map::Entry::Vacant(e) = keys.entry(k) {
                let pk = github_public_key(http, cfg, owner, repo)
                    .await
                    .with_context(|| format!("github:{owner}/{repo}"))?;
                e.insert(pk);
            }
        }
    }
    Ok(keys)
}

fn value<'a>(outputs: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    outputs
        .get(name)
        .map(String::as_str)
        .with_context(|| format!("the rotation produced no `{name}`"))
}

async fn write_github(
    http: &Http,
    cfg: &Config,
    keys: &BTreeMap<String, PublicKey>,
    owner: &str,
    repo: &str,
    name: &str,
    v: &str,
) -> Result<()> {
    let pk = match keys.get(&format!("{owner}/{repo}")) {
        Some(k) => k.clone(),
        None => github_public_key(http, cfg, owner, repo).await?,
    };
    let body = json!({ "encrypted_value": seal(&pk.key, v.as_bytes())?, "key_id": pk.key_id });
    let url = cfg.url(
        &cfg.github_api,
        &format!(
            "/repos/{}/{}/actions/secrets/{}",
            enc(owner),
            enc(repo),
            enc(name)
        ),
    )?;
    let mut h = github_headers(cfg);
    h.push(("content-type".into(), "application/json".into()));
    let r = send(
        http,
        "PUT",
        url.clone(),
        h,
        Some(serde_json::to_vec(&body)?),
    )
    .await?;
    if !matches!(r.status, 201 | 204) {
        return Err(fail("writing the secret", &url, &r));
    }
    Ok(())
}

async fn write_vault(
    http: &Http,
    cfg: &Config,
    mount: &str,
    path: &str,
    data: &serde_json::Map<String, Value>,
) -> Result<()> {
    let addr = cfg.vault_addr.as_deref().context("VAULT_ADDR is not set")?;
    let url = cfg.url(
        addr,
        &format!("/v1/{}/data/{}", enc_path(mount), enc_path(path)),
    )?;
    let mut h = vec![(
        "x-vault-token".to_string(),
        cfg.vault_token.clone().context("VAULT_TOKEN is not set")?,
    )];
    if let Some(ns) = &cfg.vault_namespace {
        h.push(("x-vault-namespace".into(), ns.clone()));
    }
    let mut patch_h = h.clone();
    patch_h.push(("content-type".into(), "application/merge-patch+json".into()));
    let body = serde_json::to_vec(&json!({ "data": data }))?;
    let r = send(http, "PATCH", url.clone(), patch_h, Some(body)).await?;
    match r.status {
        200 | 204 => Ok(()),
        // No such secret yet: create it, but only if it still does not
        // exist (check-and-set 0), so a concurrent write is never clobbered.
        404 => {
            let mut post_h = h;
            post_h.push(("content-type".into(), "application/json".into()));
            let body = serde_json::to_vec(&json!({ "data": data, "options": { "cas": 0 } }))?;
            let r = send(http, "POST", url.clone(), post_h, Some(body)).await?;
            if !matches!(r.status, 200 | 204) {
                return Err(fail("creating the secret", &url, &r));
            }
            Ok(())
        }
        _ => Err(fail("writing the secret", &url, &r)),
    }
}

async fn aws_call(http: &Http, cfg: &Config, action: &str, body: &Value) -> Result<Response> {
    let url = cfg.aws_url()?;
    let creds = cfg.aws.as_ref().context("no AWS credentials")?;
    let region = cfg.aws_region.as_deref().context("no AWS region")?;
    let body = serde_json::to_vec(body)?;
    let mut headers = vec![
        (
            "content-type".to_string(),
            "application/x-amz-json-1.1".to_string(),
        ),
        (
            "x-amz-target".to_string(),
            format!("secretsmanager.{action}"),
        ),
    ];
    let signed = sigv4::sign(
        &sigv4::Credentials {
            access_key: &creds.access_key,
            secret_key: &creds.secret_key,
            session_token: creds.session_token.as_deref(),
            region,
            service: "secretsmanager",
        },
        "POST",
        &url,
        &headers,
        &body,
        chrono::Utc::now(),
    );
    headers.extend(signed);
    let r = send(http, "POST", url.clone(), headers, Some(body)).await?;
    if r.status != 200 {
        return Err(fail(action, &url, &r));
    }
    Ok(r)
}

/// A random RFC 4122 version 4 UUID (idempotency token for PutSecretValue).
fn uuid4() -> String {
    use crypto_box::aead::rand_core::RngCore;
    let mut b = [0u8; 16];
    crypto_box::aead::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

async fn write_aws(
    http: &Http,
    cfg: &Config,
    secret_id: &str,
    g: &Group,
    outputs: &BTreeMap<String, String>,
) -> Result<()> {
    let secret_string = if let [(None, o)] = g.entries.as_slice() {
        value(outputs, o)?.to_string()
    } else {
        let cur = aws_call(
            http,
            cfg,
            "GetSecretValue",
            &json!({ "SecretId": secret_id }),
        )
        .await?;
        let text = cur
            .json
            .as_ref()
            .and_then(|j| j["SecretString"].as_str())
            .context("GetSecretValue: the secret has no SecretString (binary secrets are not supported with #json-key)")?;
        let mut obj: serde_json::Map<String, Value> = match serde_json::from_str(text) {
            Ok(Value::Object(m)) => m,
            _ => bail!(
                "the current value of {secret_id} is not a JSON object; store the whole value (no #json-key) instead"
            ),
        };
        for (k, o) in &g.entries {
            let k = k
                .clone()
                .context("mixed whole-value and #json-key writes")?;
            obj.insert(k, Value::String(value(outputs, o)?.to_string()));
        }
        serde_json::to_string(&obj)?
    };
    aws_call(
        http,
        cfg,
        "PutSecretValue",
        &json!({ "SecretId": secret_id, "SecretString": secret_string, "ClientRequestToken": uuid4() }),
    )
    .await?;
    Ok(())
}

/// Write every group, continuing after failures. `keys` comes from
/// [`preflight`]. Errors are masked with every known secret value.
pub async fn write_all(
    http: &Http,
    cfg: &Config,
    groups: &[Group],
    keys: &BTreeMap<String, PublicKey>,
    outputs: &BTreeMap<String, String>,
    mask: &BTreeMap<String, String>,
) -> Vec<StoreResult> {
    let mut mask = mask.clone();
    mask.extend(outputs.iter().map(|(k, v)| (format!("out:{k}"), v.clone())));
    for (n, v) in [("gh", &cfg.github_token), ("vault", &cfg.vault_token)] {
        if let Some(v) = v {
            mask.insert(n.into(), v.clone());
        }
    }
    if let Some(a) = &cfg.aws {
        mask.insert("aws".into(), a.secret_key.clone());
    }
    let mut out = Vec::new();
    for g in groups {
        let res: Result<()> = async {
            match &g.target {
                Target::GitHub { owner, repo, name } => {
                    let v = value(outputs, &g.entries[0].1)?;
                    write_github(http, cfg, keys, owner, repo, name, v).await
                }
                Target::Vault { mount, path } => {
                    let mut data = serde_json::Map::new();
                    for (k, o) in &g.entries {
                        data.insert(
                            k.clone().unwrap_or_default(),
                            Value::String(value(outputs, o)?.to_string()),
                        );
                    }
                    write_vault(http, cfg, mount, path, &data).await
                }
                Target::AwsSm { secret_id } => write_aws(http, cfg, secret_id, g, outputs).await,
            }
        }
        .await;
        out.push(StoreResult {
            target: g.target.label(),
            values: values_label(g),
            plan: describe(cfg, g),
            executed: true,
            ok: res.is_ok(),
            error: res
                .err()
                .map(|e| crate::verify::mask_secrets(&format!("{e:#}"), &mask)),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outs() -> Vec<String> {
        vec!["new_key_id".into(), "new_secret".into()]
    }

    #[test]
    fn parse_specs() {
        let s = parse("github:acme/api:DEPLOY_KEY=new_secret", &outs(), None).unwrap();
        assert_eq!(
            s.dest,
            Dest::GitHub {
                owner: "acme".into(),
                repo: "api".into(),
                name: "DEPLOY_KEY".into()
            }
        );
        assert_eq!(s.output, "new_secret");
        let s = parse("vault:secret/apps/api#token", &outs(), Some("new_secret")).unwrap();
        assert_eq!(
            s.dest,
            Dest::Vault {
                mount: "secret".into(),
                path: "apps/api".into(),
                key: "token".into()
            }
        );
        // `=` inside an AWS secret name is not mistaken for an output.
        let s = parse("aws-sm:team=a/app#KEY", &outs(), Some("new_secret")).unwrap();
        assert_eq!(
            s.dest,
            Dest::AwsSm {
                secret_id: "team=a/app".into(),
                json_key: Some("KEY".into())
            }
        );
        let s = parse(
            "aws-sm:arn:aws:secretsmanager:eu-west-1:1:secret:x=new_key_id",
            &outs(),
            None,
        )
        .unwrap();
        assert_eq!(s.output, "new_key_id");
        assert!(
            parse("github:acme/api:DEPLOY_KEY", &outs(), None).is_err(),
            "ambiguous output"
        );
        assert!(parse("github:acme/api:GITHUB_TOKEN=new_secret", &outs(), None).is_err());
        assert!(parse("github:acme/api:BAD-NAME=new_secret", &outs(), None).is_err());
        assert!(parse("github:acme/api:K=nope", &outs(), None).is_err());
        assert!(
            parse("vault:secret#k=new_secret", &outs(), None).is_err(),
            "no path"
        );
        assert!(parse("vault:secret/../x#k=new_secret", &outs(), None).is_err());
        assert!(parse("s3:x=new_secret", &outs(), None).is_err());
    }

    #[test]
    fn grouping_merges_keys_and_rejects_conflicts() {
        let specs = [
            parse("aws-sm:app#ID=new_key_id", &outs(), None).unwrap(),
            parse("aws-sm:app#SECRET=new_secret", &outs(), None).unwrap(),
            parse("vault:kv/a#t=new_secret", &outs(), None).unwrap(),
        ];
        let g = group(&specs).unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].entries.len(), 2);
        let dup = [
            parse("aws-sm:app=new_secret", &outs(), None).unwrap(),
            parse("aws-sm:app#X=new_key_id", &outs(), None).unwrap(),
        ];
        assert!(group(&dup).is_err());
        let dup = [
            parse("github:a/b:X=new_secret", &outs(), None).unwrap(),
            parse("github:a/b:X=new_key_id", &outs(), None).unwrap(),
        ];
        assert!(group(&dup).is_err());
    }

    #[test]
    fn https_is_required_and_plans_hold_no_values() {
        let cfg = Config {
            github_api: GITHUB_API.into(),
            vault_addr: Some("http://vault.local:8200".into()),
            vault_token: Some("t".into()),
            ..Default::default()
        };
        let g = group(&[parse("vault:kv/a#t=new_secret", &outs(), None).unwrap()]).unwrap();
        let p = cfg.problems(&g);
        assert!(p.iter().any(|m| m.contains("https")), "{p:?}");
        let g = group(&[parse("github:a/b:X=new_secret", &outs(), None).unwrap()]).unwrap();
        assert!(
            cfg.problems(&g)
                .iter()
                .any(|m| m.contains("--store-token-env"))
        );
        let d = describe(&cfg, &g[0]);
        assert!(
            d.contains("https://api.github.com/repos/a/b/actions/secrets/X"),
            "{d}"
        );
    }

    #[test]
    fn sealed_box_roundtrip_and_uuid() {
        let sk = crypto_box::SecretKey::from([7u8; 32]);
        let pk = *sk.public_key().as_bytes();
        let ct = seal(&pk, b"value").unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(ct)
            .unwrap();
        assert_eq!(sk.unseal(&raw).unwrap(), b"value");
        let u = uuid4();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }
}
