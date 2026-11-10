//! `rotate --store`: new credentials written to GitHub Actions secrets,
//! Vault KV v2 and AWS Secrets Manager, end to end against mock servers.

use std::path::Path;
use std::process::{Command, Output};

use base64::Engine as _;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Built at runtime: the repository must not contain token-shaped values.
fn old_token() -> String {
    format!("mk_{}_{}", "ab12", "Zq8Lw2Pm9Xa1")
}
fn new_token() -> String {
    format!("mk_{}_{}", "cd34", "Rt7Yu3Io0Pq5")
}

fn template(dir: &Path, server: &MockServer) {
    let yaml = r#"
id: mock-key
name: Mock Key
platform: Mock
detect:
  keywords: [mk_]
  patterns:
    - name: token
      regex: '\b(mk_[a-z0-9]{4}_[A-Za-z0-9]{12})\b'
verify:
  request:
    url: BASE/me
    auth: { type: bearer, token: "{{ token }}" }
  valid: { status: [200] }
  invalid: { status: [401] }
rotate:
  steps:
    - name: create
      request:
        method: POST
        url: BASE/keys
        auth: { type: bearer, token: "{{ token }}" }
      expect: { status: [201] }
      extract:
        - { name: new_token, json: key, secret: true }
        - { name: new_key_id, json: id }
  outputs: [new_token, new_key_id]
"#
    .replace("BASE", &server.uri());
    std::fs::write(dir.join("mock.yaml"), yaml).unwrap();
}

async fn mount_vendor(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/keys"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({"key": new_token(), "id": "key-2"})),
        )
        .mount(server)
        .await;
}

fn github_key() -> crypto_box::SecretKey {
    crypto_box::SecretKey::from([42u8; 32])
}

async fn mount_github(server: &MockServer, status: u16) {
    let pk = base64::engine::general_purpose::STANDARD.encode(github_key().public_key().as_bytes());
    Mock::given(method("GET"))
        .and(path("/gh/repos/acme/api/actions/secrets/public-key"))
        .and(header("authorization", "Bearer gh-test-token"))
        .respond_with(
            ResponseTemplate::new(status)
                .set_body_json(serde_json::json!({"key_id": "kid-1", "key": pk})),
        )
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/gh/repos/acme/api/actions/secrets/DEPLOY_TOKEN"))
        .and(header("authorization", "Bearer gh-test-token"))
        .respond_with(ResponseTemplate::new(201))
        .mount(server)
        .await;
}

async fn kubera(
    dir: &Path,
    server: &MockServer,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kubera"));
    cmd.current_dir(dir)
        .env("NO_COLOR", "1")
        .env("LEAKED", old_token())
        .env("KUBERA_TEST_GH", "gh-test-token")
        .env("VAULT_ADDR", format!("{}/vault", server.uri()))
        .env("VAULT_TOKEN", "vault-test-token")
        .env("AWS_ACCESS_KEY_ID", "AKIDTEST")
        .env("AWS_SECRET_ACCESS_KEY", "aws-test-secret")
        .env(
            "AWS_ENDPOINT_URL_SECRETS_MANAGER",
            format!("{}/aws/", server.uri()),
        )
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_REGION")
        .env_remove("AWS_DEFAULT_REGION")
        .env_remove("AWS_ENDPOINT_URL")
        .env_remove("VAULT_NAMESPACE");
    for (k, v) in extra_env {
        if v.is_empty() {
            cmd.env_remove(k);
        } else {
            cmd.env(k, v);
        }
    }
    let mut all = vec![
        "--allow-http",
        "--no-builtin",
        "-t",
        "mock.yaml",
        "rotate",
        "mock-key",
        "-e",
        "LEAKED",
        "--store-token-env",
        "KUBERA_TEST_GH",
        "--store-region",
        "eu-west-1",
    ];
    all.extend_from_slice(args);
    let gh_api = format!("{}/gh", server.uri());
    all.extend_from_slice(&["--store-github-api", &gh_api]);
    let all: Vec<String> = all.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || cmd.args(&all).output().unwrap())
        .await
        .unwrap()
}

const STORES: [&str; 8] = [
    "--store",
    "github:acme/api:DEPLOY_TOKEN",
    "--store",
    "vault:secret/apps/api#token",
    "--store",
    "aws-sm:prod/api#API_TOKEN=new_token",
    "--store",
    "aws-sm:prod/api#API_KEY_ID=new_key_id",
];

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn aws_target(r: &Request) -> String {
    r.headers
        .get("x-amz-target")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn dry_run_plans_store_updates_and_sends_nothing() {
    let server = MockServer::start().await;
    mount_vendor(&server).await;
    let dir = tempfile::tempdir().unwrap();
    template(dir.path(), &server);
    let out = kubera(dir.path(), &server, &[], &STORES).await;
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("Secret store updates"), "{t}");
    assert!(t.contains("github:acme/api:DEPLOY_TOKEN"), "{t}");
    assert!(t.contains("/vault/v1/secret/data/apps/api"), "{t}");
    assert!(t.contains("API_TOKEN, API_KEY_ID"), "{t}");
    for secret in [
        "gh-test-token",
        "vault-test-token",
        "aws-test-secret",
        &old_token(),
    ] {
        assert!(!t.contains(secret), "{secret} leaked: {t}");
    }
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "only the verification request");
    assert_eq!(reqs[0].url.path(), "/me");
}

#[tokio::test]
async fn execute_writes_every_store() {
    let server = MockServer::start().await;
    mount_vendor(&server).await;
    mount_github(&server, 200).await;
    Mock::given(method("PATCH"))
        .and(path("/vault/v1/secret/data/apps/api"))
        .and(header("x-vault-token", "vault-test-token"))
        .and(header("content-type", "application/merge-patch+json"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/aws/"))
        .and(header("x-amz-target", "secretsmanager.GetSecretValue"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "SecretString": "{\"OTHER\":\"keep-me\",\"API_TOKEN\":\"old\"}"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/aws/"))
        .and(header("x-amz-target", "secretsmanager.PutSecretValue"))
        .and(body_string_contains("prod/api"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"VersionId": "v2"})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    template(dir.path(), &server);
    let mut args = STORES.to_vec();
    args.extend(["--execute", "--yes", "--format", "json"]);
    let out = kubera(dir.path(), &server, &[], &args).await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["completed"], true);
    assert_eq!(v["stores"].as_array().unwrap().len(), 3, "{v:#}");
    assert!(
        v["stores"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["ok"] == true),
        "{v:#}"
    );
    // Stored everywhere, so the raw value is not printed.
    assert!(v["outputs"].get("new_token").is_none(), "{v:#}");
    assert!(!t.contains(&new_token()), "{t}");

    let reqs = server.received_requests().await.unwrap();
    // GitHub: the public key is read before the rotation runs.
    let pos = |p: &str, m: &str| {
        reqs.iter()
            .position(|r| r.url.path() == p && r.method.as_str() == m)
            .unwrap_or_else(|| panic!("no {m} {p}"))
    };
    assert!(pos("/gh/repos/acme/api/actions/secrets/public-key", "GET") < pos("/keys", "POST"));
    let put = &reqs[pos("/gh/repos/acme/api/actions/secrets/DEPLOY_TOKEN", "PUT")];
    let body: serde_json::Value = serde_json::from_slice(&put.body).unwrap();
    assert_eq!(body["key_id"], "kid-1");
    let ct = base64::engine::general_purpose::STANDARD
        .decode(body["encrypted_value"].as_str().unwrap())
        .unwrap();
    assert_eq!(github_key().unseal(&ct).unwrap(), new_token().as_bytes());
    assert!(!String::from_utf8_lossy(&put.body).contains(&new_token()));

    let patch = &reqs[pos("/vault/v1/secret/data/apps/api", "PATCH")];
    let body: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
    assert_eq!(body["data"]["token"], new_token());

    let put = reqs
        .iter()
        .find(|r| aws_target(r) == "secretsmanager.PutSecretValue")
        .unwrap();
    let auth = put.headers.get("authorization").unwrap().to_str().unwrap();
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/")
            && auth.contains("/eu-west-1/secretsmanager/aws4_request"),
        "{auth}"
    );
    let body: serde_json::Value = serde_json::from_slice(&put.body).unwrap();
    assert_eq!(body["SecretId"], "prod/api");
    assert_eq!(body["ClientRequestToken"].as_str().unwrap().len(), 36);
    let merged: serde_json::Value =
        serde_json::from_str(body["SecretString"].as_str().unwrap()).unwrap();
    assert_eq!(merged["OTHER"], "keep-me");
    assert_eq!(merged["API_TOKEN"], new_token());
    assert_eq!(merged["API_KEY_ID"], "key-2");
    // Both keys in one version: a single GetSecretValue + PutSecretValue.
    assert_eq!(
        reqs.iter()
            .filter(|r| aws_target(r) == "secretsmanager.PutSecretValue")
            .count(),
        1
    );
}

#[tokio::test]
async fn failed_store_keeps_the_new_credential_and_vault_creates_missing_secret() {
    let server = MockServer::start().await;
    mount_vendor(&server).await;
    // Missing secret: PATCH 404, then a create-only POST.
    Mock::given(method("POST"))
        .and(path("/vault/v1/kv/data/new/app"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/vault/v1/kv/data/new/app"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/vault/v1/kv/data/denied"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(serde_json::json!({"errors": ["permission denied"]})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    template(dir.path(), &server);
    let out = kubera(
        dir.path(),
        &server,
        &[],
        &[
            "--store",
            "vault:kv/new/app#token",
            "--store",
            "vault:kv/denied#token",
            "--execute",
            "--yes",
        ],
    )
    .await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(4), "{t}");
    assert!(t.contains("permission denied"), "{t}");
    assert!(t.contains("NOT updated"), "{t}");
    // The store failed: the credential is printed, never lost.
    assert!(t.contains(&new_token()), "{t}");
    assert!(!t.contains("vault-test-token"), "{t}");
    let reqs = server.received_requests().await.unwrap();
    let post = reqs
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path() == "/vault/v1/kv/data/new/app")
        .expect("create after 404");
    let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["options"]["cas"], 0);
    assert_eq!(body["data"]["token"], new_token());

    // With --output-file the credential is on disk before any store runs.
    let out = kubera(
        dir.path(),
        &server,
        &[],
        &[
            "--store",
            "vault:kv/denied#token",
            "--execute",
            "--yes",
            "-o",
            "new.json",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let saved = std::fs::read_to_string(dir.path().join("new.json")).unwrap();
    assert!(saved.contains(&new_token()));
}

#[tokio::test]
async fn nothing_rotates_when_a_store_is_misconfigured() {
    let server = MockServer::start().await;
    mount_vendor(&server).await;
    mount_github(&server, 401).await;
    let dir = tempfile::tempdir().unwrap();
    template(dir.path(), &server);

    // Bad GitHub token: the public key read fails before the rotation.
    let out = kubera(
        dir.path(),
        &server,
        &[],
        &[
            "--store",
            "github:acme/api:DEPLOY_TOKEN",
            "--execute",
            "--yes",
        ],
    )
    .await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("nothing was rotated"), "{t}");
    let reqs = server.received_requests().await.unwrap();
    assert!(
        !reqs.iter().any(|r| r.url.path() == "/keys"),
        "rotation ran"
    );

    // Missing VAULT_TOKEN: refused before any request.
    server.reset().await;
    let out = kubera(
        dir.path(),
        &server,
        &[("VAULT_TOKEN", "")],
        &["--store", "vault:kv/a#token", "--execute", "--yes"],
    )
    .await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("VAULT_TOKEN"), "{t}");
    assert!(server.received_requests().await.unwrap().is_empty());

    // Plain http is refused without the test-only opt-in.
    let out = Command::new(env!("CARGO_BIN_EXE_kubera"))
        .current_dir(dir.path())
        .env("LEAKED", old_token())
        .env("VAULT_ADDR", "http://vault.invalid")
        .env("VAULT_TOKEN", "x")
        .args([
            "--no-builtin",
            "-t",
            "mock.yaml",
            "rotate",
            "mock-key",
            "-e",
            "LEAKED",
            "--store",
            "vault:kv/a#token",
            "--execute",
            "--yes",
        ])
        .output()
        .unwrap();
    let t = text(&out);
    assert!(!out.status.success());
    assert!(t.contains("must use https"), "{t}");
}
