//! Live Kubernetes clusters: Secrets, ConfigMaps, workload environment
//! variables and object annotations.
//!
//! Credentials end up in clusters in places they should not be: literal
//! `env` values in Deployments, ConfigMaps, and the
//! `kubectl.kubernetes.io/last-applied-configuration` annotation (which
//! repeats a Secret's data in plain text). Secrets themselves are scanned
//! too (decoded), so kubera can tell which platforms' credentials a cluster
//! holds and verify them.
//!
//! Access uses the kubeconfig like kubectl: current (or chosen) context,
//! cluster CA, bearer tokens, client certificates and `exec` credential
//! plugins (EKS, GKE, AKS). Inside a pod the service account is used. TLS
//! trusts only the cluster's CA when one is configured;
//! `insecure-skip-tls-verify` is refused. Read-only `list` calls only.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde_json::Value;

use super::Chunk;
use crate::finding::{Location, SourceKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum What {
    /// Secret data (decoded).
    Secrets,
    /// ConfigMap data.
    Configmaps,
    /// Literal env values and annotations of Deployments, StatefulSets,
    /// DaemonSets, CronJobs, Jobs and standalone Pods.
    Workloads,
}

pub const ALL: [What; 3] = [What::Secrets, What::Configmaps, What::Workloads];

/// How to reach the API server.
pub struct Cluster {
    pub name: String,
    pub server: String,
    http: reqwest::Client,
    token: Option<String>,
}

fn b64(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s.trim())?)
}

fn s<'a>(v: &'a Value, p: &str) -> Option<&'a str> {
    v.pointer(p).and_then(Value::as_str)
}

/// Read data given inline (`*-data`, base64) or as a file path.
fn data_or_file(v: &Value, key: &str, base: &Path) -> Result<Option<Vec<u8>>> {
    if let Some(d) = s(v, &format!("/{key}-data")) {
        return Ok(Some(b64(d).with_context(|| format!("{key}-data"))?));
    }
    if let Some(f) = s(v, &format!("/{key}")) {
        let p = base.join(f);
        return Ok(Some(
            std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?,
        ));
    }
    Ok(None)
}

pub fn default_kubeconfig() -> Option<PathBuf> {
    if let Some(k) = std::env::var_os("KUBECONFIG") {
        // First entry of a path list.
        return std::env::split_paths(&k).next();
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".kube/config"))
}

/// Run an `exec` credential plugin and return its token / client cert.
fn exec_credential(exec: &Value) -> Result<(Option<String>, Option<(Vec<u8>, Vec<u8>)>)> {
    let cmd = s(exec, "/command").context("exec plugin without command")?;
    let mut c = std::process::Command::new(cmd);
    for a in exec["args"].as_array().into_iter().flatten() {
        if let Some(a) = a.as_str() {
            c.arg(a);
        }
    }
    for e in exec["env"].as_array().into_iter().flatten() {
        if let (Some(n), Some(v)) = (s(e, "/name"), s(e, "/value")) {
            c.env(n, v);
        }
    }
    let out = c
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("running credential plugin `{cmd}`"))?;
    if !out.status.success() {
        bail!(
            "credential plugin `{cmd}` failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("")
        );
    }
    let v: Value = serde_json::from_slice(&out.stdout).context("credential plugin output")?;
    let token = s(&v, "/status/token").map(str::to_string);
    let cert = match (
        s(&v, "/status/clientCertificateData"),
        s(&v, "/status/clientKeyData"),
    ) {
        (Some(c), Some(k)) => Some((c.as_bytes().to_vec(), k.as_bytes().to_vec())),
        _ => None,
    };
    Ok((token, cert))
}

fn build_client(
    ca: Option<Vec<u8>>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(concat!("kubera/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60));
    if let Some(ca) = ca {
        let certs = reqwest::Certificate::from_pem_bundle(&ca).context("cluster CA")?;
        // Trust the cluster's CA only, like kubectl.
        b = b.tls_certs_only(certs);
    }
    if let Some((cert, key)) = identity {
        let mut pem = cert;
        pem.push(b'\n');
        pem.extend_from_slice(&key);
        b = b.identity(reqwest::Identity::from_pem(&pem).context("client certificate")?);
    }
    Ok(b.build()?)
}

impl Cluster {
    /// From a kubeconfig file (`context`: default is current-context).
    pub fn from_kubeconfig(path: &Path, context: Option<&str>, allow_http: bool) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading kubeconfig {}", path.display()))?;
        let cfg: Value = serde_yaml::from_str(&text).context("parsing kubeconfig")?;
        let base = path.parent().unwrap_or(Path::new("."));
        let ctx_name = match context {
            Some(c) => c.to_string(),
            None => s(&cfg, "/current-context")
                .context("kubeconfig has no current-context; pass --context")?
                .to_string(),
        };
        let find = |list: &str, name: &str| -> Option<Value> {
            cfg[list]
                .as_array()?
                .iter()
                .find(|e| s(e, "/name") == Some(name))
                .cloned()
        };
        let ctx = find("contexts", &ctx_name)
            .with_context(|| format!("context `{ctx_name}` not in kubeconfig"))?;
        let cluster_name = s(&ctx, "/context/cluster").context("context without cluster")?;
        let cluster = find("clusters", cluster_name)
            .with_context(|| format!("cluster `{cluster_name}` not in kubeconfig"))?;
        let c = &cluster["cluster"];
        if c["insecure-skip-tls-verify"].as_bool() == Some(true) {
            bail!(
                "cluster `{cluster_name}` sets insecure-skip-tls-verify; kubera will not send \
                 credentials without certificate verification"
            );
        }
        let server = s(c, "/server")
            .context("cluster without server")?
            .to_string();
        if !server.starts_with("https://") && !(allow_http && server.starts_with("http://")) {
            bail!("API server {server} is not https");
        }
        let ca = data_or_file(c, "certificate-authority", base)?;
        let user = match s(&ctx, "/context/user") {
            Some(u) => find("users", u)
                .map(|u| u["user"].clone())
                .unwrap_or_default(),
            None => Value::Null,
        };
        let mut token = s(&user, "/token").map(str::to_string);
        if token.is_none()
            && let Some(f) = s(&user, "/tokenFile")
        {
            token = Some(std::fs::read_to_string(base.join(f))?.trim().to_string());
        }
        let mut identity = match (
            data_or_file(&user, "client-certificate", base)?,
            data_or_file(&user, "client-key", base)?,
        ) {
            (Some(c), Some(k)) => Some((c, k)),
            _ => None,
        };
        if token.is_none() && identity.is_none() && user.get("exec").is_some() {
            let (t, i) = exec_credential(&user["exec"])?;
            token = t;
            identity = i;
        }
        Ok(Self {
            name: ctx_name,
            server,
            http: build_client(ca, identity)?,
            token,
        })
    }

    /// Inside a pod: the service account token and CA.
    pub fn in_cluster() -> Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").context("not running in a cluster")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let dir = Path::new("/var/run/secrets/kubernetes.io/serviceaccount");
        let token = std::fs::read_to_string(dir.join("token"))?
            .trim()
            .to_string();
        let ca = std::fs::read(dir.join("ca.crt"))?;
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        Ok(Self {
            name: "in-cluster".into(),
            server: format!("https://{host}:{port}"),
            http: build_client(Some(ca), None)?,
            token: Some(token),
        })
    }

    /// All items of a list endpoint, following `continue` tokens.
    async fn list(&self, path: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut cont: Option<String> = None;
        loop {
            let mut url = format!("{}{path}?limit=500", self.server.trim_end_matches('/'));
            if let Some(c) = &cont {
                url.push_str("&continue=");
                url.push_str(
                    &percent_encoding::utf8_percent_encode(c, percent_encoding::NON_ALPHANUMERIC)
                        .to_string(),
                );
            }
            let mut rb = self.http.get(&url).header("Accept", "application/json");
            if let Some(t) = &self.token {
                rb = rb.bearer_auth(t);
            }
            let resp = rb
                .send()
                .await
                .map_err(reqwest::Error::without_url)
                .with_context(|| format!("GET {path}"))?;
            let status = resp.status().as_u16();
            let v: Value = resp.json().await.unwrap_or_default();
            if status != 200 {
                bail!(
                    "GET {path}: HTTP {status} {}",
                    s(&v, "/message").unwrap_or_default()
                );
            }
            out.extend(v["items"].as_array().cloned().unwrap_or_default());
            cont = s(&v, "/metadata/continue")
                .filter(|c| !c.is_empty())
                .map(str::to_string);
            if cont.is_none() {
                return Ok(out);
            }
        }
    }
}

/// Text of an object's annotations, one `name: value` per line.
fn annotations(obj: &Value) -> String {
    let mut t = String::new();
    if let Some(m) = obj
        .pointer("/metadata/annotations")
        .and_then(Value::as_object)
    {
        for (k, v) in m {
            t.push_str(&format!("{k}: {}\n", v.as_str().unwrap_or_default()));
        }
    }
    t
}

fn chunk(cluster: &str, path: String, text: String) -> Chunk {
    Chunk {
        text,
        location: Location {
            source: SourceKind::Kubernetes,
            repository: Some(cluster.to_string()),
            path: Some(path),
            ..Default::default()
        },
        line_map: None,
    }
}

fn id(obj: &Value) -> String {
    let ns = s(obj, "/metadata/namespace").unwrap_or("-");
    let name = s(obj, "/metadata/name").unwrap_or("?");
    format!("{ns}/{name}")
}

/// Env values, env var names and annotations of a pod spec.
fn pod_spec_text(spec: &Value) -> String {
    let mut t = String::new();
    for kind in ["initContainers", "containers", "ephemeralContainers"] {
        for c in spec[kind].as_array().into_iter().flatten() {
            for e in c["env"].as_array().into_iter().flatten() {
                if let (Some(n), Some(v)) = (s(e, "/name"), s(e, "/value")) {
                    t.push_str(&format!("{n}={v}\n"));
                }
            }
            for a in c["args"]
                .as_array()
                .into_iter()
                .chain(c["command"].as_array())
                .flatten()
            {
                if let Some(a) = a.as_str() {
                    t.push_str(a);
                    t.push('\n');
                }
            }
        }
    }
    t
}

/// Collect chunks for the selected kinds in `namespaces` (all when empty).
/// Non-fatal problems (e.g. RBAC forbids listing Secrets) are returned as
/// warnings.
pub async fn collect(
    c: &Cluster,
    what: &[What],
    namespaces: &[String],
) -> Result<(Vec<Chunk>, Vec<String>)> {
    let mut chunks = Vec::new();
    let mut warnings = Vec::new();
    let scopes: Vec<String> = if namespaces.is_empty() {
        vec![String::new()]
    } else {
        namespaces
            .iter()
            .map(|n| {
                format!(
                    "/namespaces/{}",
                    percent_encoding::utf8_percent_encode(n, percent_encoding::NON_ALPHANUMERIC)
                )
            })
            .collect()
    };
    let label = format!("k8s:{}", c.name);
    for scope in &scopes {
        let get = |api: &str, kind: &str| format!("{api}{scope}/{kind}");
        if what.contains(&What::Secrets) {
            match c.list(&get("/api/v1", "secrets")).await {
                Ok(items) => {
                    for it in items {
                        // Service account tokens are minted by the cluster.
                        if s(&it, "/type") == Some("kubernetes.io/service-account-token") {
                            continue;
                        }
                        let mut t = String::new();
                        for (k, v) in it["data"].as_object().into_iter().flatten() {
                            let raw = v.as_str().and_then(|v| b64(v).ok()).unwrap_or_default();
                            t.push_str(&format!("{k}: {}\n", String::from_utf8_lossy(&raw)));
                        }
                        t.push_str(&annotations(&it));
                        chunks.push(chunk(&label, format!("secret/{}", id(&it)), t));
                    }
                }
                Err(e) => warnings.push(format!("secrets: {e:#}")),
            }
        }
        if what.contains(&What::Configmaps) {
            match c.list(&get("/api/v1", "configmaps")).await {
                Ok(items) => {
                    for it in items {
                        let mut t = String::new();
                        for (k, v) in it["data"].as_object().into_iter().flatten() {
                            t.push_str(&format!("{k}: {}\n", v.as_str().unwrap_or_default()));
                        }
                        for (k, v) in it["binaryData"].as_object().into_iter().flatten() {
                            let raw = v.as_str().and_then(|v| b64(v).ok()).unwrap_or_default();
                            if !super::is_binary(&raw) {
                                t.push_str(&format!("{k}: {}\n", String::from_utf8_lossy(&raw)));
                            }
                        }
                        t.push_str(&annotations(&it));
                        chunks.push(chunk(&label, format!("configmap/{}", id(&it)), t));
                    }
                }
                Err(e) => warnings.push(format!("configmaps: {e:#}")),
            }
        }
        if what.contains(&What::Workloads) {
            let kinds = [
                ("/apis/apps/v1", "deployments", "/spec/template/spec"),
                ("/apis/apps/v1", "statefulsets", "/spec/template/spec"),
                ("/apis/apps/v1", "daemonsets", "/spec/template/spec"),
                (
                    "/apis/batch/v1",
                    "cronjobs",
                    "/spec/jobTemplate/spec/template/spec",
                ),
                ("/apis/batch/v1", "jobs", "/spec/template/spec"),
                ("/api/v1", "pods", "/spec"),
            ];
            for (api, kind, spec_path) in kinds {
                match c.list(&get(api, kind)).await {
                    Ok(items) => {
                        for it in items {
                            // Pods and Jobs created by a controller repeat
                            // their owner's template.
                            if (kind == "pods" || kind == "jobs")
                                && it
                                    .pointer("/metadata/ownerReferences")
                                    .and_then(Value::as_array)
                                    .is_some_and(|o| !o.is_empty())
                            {
                                continue;
                            }
                            let spec = it.pointer(spec_path).cloned().unwrap_or_default();
                            let mut t = pod_spec_text(&spec);
                            t.push_str(&annotations(&it));
                            let singular = kind.trim_end_matches('s');
                            chunks.push(chunk(&label, format!("{singular}/{}", id(&it)), t));
                        }
                    }
                    Err(e) => warnings.push(format!("{kind}: {e:#}")),
                }
            }
        }
    }
    Ok((chunks, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_insecure_and_plain_http_clusters() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config");
        let cfg = |cluster: &str| {
            format!(
                "apiVersion: v1\nkind: Config\ncurrent-context: c\ncontexts:\n- name: c\n  context: {{cluster: k, user: u}}\nclusters:\n- name: k\n  cluster: {cluster}\nusers:\n- name: u\n  user: {{token: abc}}\n"
            )
        };
        std::fs::write(
            &p,
            cfg("{server: 'https://k:6443', insecure-skip-tls-verify: true}"),
        )
        .unwrap();
        assert!(Cluster::from_kubeconfig(&p, None, false).is_err());
        std::fs::write(&p, cfg("{server: 'http://k:6443'}")).unwrap();
        assert!(Cluster::from_kubeconfig(&p, None, false).is_err());
        std::fs::write(&p, cfg("{server: 'https://k:6443'}")).unwrap();
        let c = Cluster::from_kubeconfig(&p, None, false).unwrap();
        assert_eq!(c.server, "https://k:6443");
        assert_eq!(c.token.as_deref(), Some("abc"));
        assert!(Cluster::from_kubeconfig(&p, Some("missing"), false).is_err());
    }

    #[test]
    fn pod_spec_env_and_args() {
        let spec: Value = serde_json::json!({
            "containers": [{"env": [{"name": "DB", "value": "postgres://u:p@h/db"},
                                    {"name": "FROM_SECRET", "valueFrom": {}}],
                            "args": ["--token=abc"]}]
        });
        assert_eq!(
            pod_spec_text(&spec),
            "DB=postgres://u:p@h/db\n--token=abc\n"
        );
    }
}
