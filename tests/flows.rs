//! Verify / analyze / rotate flows against a local mock server.

use std::collections::BTreeMap;

use kubera::finding::Status;
use kubera::http::{Http, HttpOptions};
use kubera::template::{self, Template};
use kubera::{analyze, rotate, verify};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn http() -> Http {
    Http::new(HttpOptions {
        allow_http: true,
        timeout: Some(5),
    })
    .unwrap()
}

fn tpl(server: &MockServer) -> Template {
    let yaml = r#"
id: mock-key
name: Mock Key
platform: Mock
detect:
  keywords: [mk_]
  patterns:
    - name: token
      regex: '\b(mk_(?P<key_id>[a-z0-9]{4})_[A-Za-z0-9]{12})\b'
      captures: [key_id]
verify:
  request:
    url: BASE/me
    auth: { type: bearer, token: "{{ token }}" }
  valid: { status: [200] }
  invalid: { status: [401] }
  extract:
    - { name: owner, label: Owner, json: user.login }
analyze:
  steps:
    - name: scopes
      request:
        url: BASE/scopes
        auth: { type: bearer, token: "{{ token }}" }
      extract:
        - { name: scopes, label: Scopes, json: "items.*.name" }
    - name: forbidden_probe
      request:
        url: BASE/admin
        auth: { type: bearer, token: "{{ token }}" }
rotate:
  instructions: Rotate it.
  inputs:
    - { name: label, default: "rotated-{{ owner }}" }
  steps:
    - name: create
      request:
        method: POST
        url: BASE/keys
        auth: { type: bearer, token: "{{ token }}" }
        json: { name: "{{ label }}" }
      expect: { status: [201] }
      extract:
        - { name: new_token, json: key, secret: true }
    - name: revoke
      request:
        method: DELETE
        url: "BASE/keys/{{ key_id }}"
        auth: { type: bearer, token: "{{ new_token }}" }
      expect: { status: [204] }
  outputs: [new_token]
"#
    .replace("BASE", &server.uri());
    template::parse(&yaml, "test").unwrap()
}

fn parts() -> BTreeMap<String, String> {
    let mut p = BTreeMap::new();
    p.insert("token".to_string(), "mk_ab12_Zq8Lw2Pm9Xa1".to_string());
    p.insert("key_id".to_string(), "ab12".to_string());
    p
}

#[tokio::test]
async fn verify_statuses() {
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("authorization", "Bearer mk_ab12_Zq8Lw2Pm9Xa1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"user": {"login": "alice"}})),
        )
        .mount(&server)
        .await;
    let out = verify::verify(&http(), &t, &parts()).await;
    assert_eq!(out.verification.status, Status::Verified);
    assert_eq!(out.verification.details["Owner"], "alice");
    assert_eq!(out.vars["owner"], "alice");

    // Wrong token -> mock falls through to 404, which is neither valid nor invalid.
    let mut other = parts();
    other.insert("token".into(), "mk_ab12_000000000000".into());
    let out = verify::verify(&http(), &t, &other).await;
    assert_eq!(out.verification.status, Status::Unknown);
}

#[tokio::test]
async fn verify_invalid_and_https_enforced() {
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(path("/me"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let out = verify::verify(&http(), &t, &parts()).await;
    assert_eq!(out.verification.status, Status::Invalid);

    // Without the explicit opt-in, plain http is refused and the secret is
    // never sent.
    let strict = Http::new(HttpOptions::default()).unwrap();
    let out = verify::verify(&strict, &t, &parts()).await;
    assert_eq!(out.verification.status, Status::Unknown);
    let msg = out.verification.message.unwrap();
    assert!(msg.contains("only https"), "{msg}");
    assert!(
        !msg.contains("Zq8Lw2Pm9Xa1"),
        "secret leaked into message: {msg}"
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(path("/me"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://attacker.invalid/"),
        )
        .mount(&server)
        .await;
    let out = verify::verify(&http(), &t, &parts()).await;
    assert_eq!(out.verification.status, Status::Unknown);
}

#[tokio::test]
async fn analyze_runs_all_steps() {
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(path("/me"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"user": {"login": "alice"}})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/scopes"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"items": [{"name": "read"}, {"name": "write"}]})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/admin"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let rep = analyze::analyze(&http(), &t, &parts(), false).await;
    assert_eq!(rep.verification.status, Status::Verified);
    assert_eq!(rep.steps.len(), 2);
    assert!(rep.steps[0].ok);
    assert_eq!(
        rep.steps[0].values[0].value,
        serde_json::json!(["read", "write"])
    );
    assert!(!rep.steps[1].ok);
    assert_eq!(rep.steps[1].http_status, Some(403));
}

#[tokio::test]
async fn rotate_dry_run_sends_nothing_but_verification() {
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(path("/me"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"user": {"login": "alice"}})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/keys"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    let rep = rotate::rotate(
        &http(),
        &t,
        &parts(),
        &rotate::Options {
            execute: false,
            force: false,
            inputs: BTreeMap::new(),
        },
    )
    .await
    .unwrap();
    assert!(!rep.executed);
    assert_eq!(rep.plan.len(), 2);
    // The plan never shows the raw secret or the auth header.
    for p in &rep.plan {
        assert!(!p.request.contains("Zq8Lw2Pm9Xa1"), "{}", p.request);
    }
    assert!(rep.plan[0].request.contains("rotated-alice"));
    assert!(
        rep.plan[1].request.contains("<new_token from create>")
            || rep.plan[1].request.contains("<redacted>")
    );
}

#[tokio::test]
async fn rotate_executes_in_order() {
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(path("/me"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"user": {"login": "alice"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/keys"))
        .and(body_string_contains("custom-name"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({"key": "mk_cd34_NEWNEWNEWNEW"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/keys/ab12"))
        .and(header("authorization", "Bearer mk_cd34_NEWNEWNEWNEW"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let mut inputs = BTreeMap::new();
    inputs.insert("label".to_string(), "custom-name".to_string());
    let rep = rotate::rotate(
        &http(),
        &t,
        &parts(),
        &rotate::Options {
            execute: true,
            force: false,
            inputs,
        },
    )
    .await
    .unwrap();
    assert!(rep.executed && rep.completed);
    assert_eq!(rep.outputs["new_token"], "mk_cd34_NEWNEWNEWNEW");
}

#[tokio::test]
async fn rotate_partial_failure_keeps_new_secret() {
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(path("/me"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"user": {"login": "alice"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/keys"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({"key": "mk_cd34_NEWNEWNEWNEW"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let rep = rotate::rotate(
        &http(),
        &t,
        &parts(),
        &rotate::Options {
            execute: true,
            force: false,
            inputs: BTreeMap::new(),
        },
    )
    .await
    .unwrap();
    assert!(rep.executed && !rep.completed);
    assert_eq!(rep.outputs["new_token"], "mk_cd34_NEWNEWNEWNEW");
}

#[tokio::test]
async fn rotate_refuses_dead_credential() {
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(path("/me"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(path("/keys"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    let err = rotate::rotate(
        &http(),
        &t,
        &parts(),
        &rotate::Options {
            execute: true,
            force: false,
            inputs: BTreeMap::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("refusing to rotate"));
}

#[test]
fn builtin_templates_are_valid_and_pass_samples() {
    let all = template::builtin().unwrap();
    assert!(all.len() >= 10);
    for l in all {
        let fails = template::testing::run(&l.template).unwrap();
        assert!(fails.is_empty(), "{}: {fails:?}", l.template.id);
        assert!(
            l.template
                .tests
                .as_ref()
                .is_some_and(|t| !t.positive.is_empty()),
            "{} has no positive samples",
            l.template.id
        );
    }
}

#[test]
fn validation_catches_undefined_variables() {
    let yaml = r#"
id: bad
name: Bad
detect:
  keywords: [x_]
  patterns: [{ name: token, regex: 'x_([a-z]+)' }]
verify:
  request: { url: "https://example.com/{{ tokn }}" }
  valid: { status: [200] }
"#;
    let err = format!("{:#}", template::parse(yaml, "t").unwrap_err());
    assert!(err.contains("undefined variable `tokn`"), "{err}");
}

#[tokio::test]
async fn transport_errors_never_include_the_url_path() {
    // Credential in the path, as with Telegram bot tokens; nothing listens
    // on port 9 so the request fails at connect time.
    let yaml = r#"
id: path-token
name: Path Token
detect:
  keywords: [pt_]
  patterns: [{ name: token, regex: '(pt_[a-z]+)' }]
verify:
  request: { url: "http://127.0.0.1:9/bot{{ token }}/private-path" }
  valid: { status: [200] }
"#;
    let t = template::parse(yaml, "t").unwrap();
    let mut p = BTreeMap::new();
    p.insert("token".to_string(), "pt_x".to_string());
    let out = verify::verify(&http(), &t, &p).await;
    assert_eq!(out.verification.status, Status::Unknown);
    let msg = out.verification.message.unwrap();
    assert!(!msg.contains("private-path"), "url path leaked: {msg}");
    assert!(!msg.contains("pt_x"), "token leaked: {msg}");
}

fn parts_token(v: &str) -> BTreeMap<String, String> {
    let mut p = BTreeMap::new();
    p.insert("token".to_string(), v.to_string());
    p
}

#[tokio::test]
async fn every_http_method_and_body_kind_is_configurable() {
    use wiremock::matchers::{body_json, body_string};
    let server = MockServer::start().await;
    let cases = [
        ("PUT", "json: { name: \"{{ token }}\" }"),
        ("PATCH", "body: 'raw={{ token }}'"),
        ("DELETE", "query: { id: \"{{ token }}\" }"),
        ("HEAD", "headers: { X-Key: \"{{ token }}\" }"),
        ("POST", "form: { key: \"{{ token }}\" }"),
        ("OPTIONS", "headers: { X-Key: \"{{ token }}\" }"),
    ];
    Mock::given(method("PUT"))
        .and(body_json(serde_json::json!({"name": "tok123"})))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(body_string("raw=tok123"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(wiremock::matchers::query_param("id", "tok123"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(header("x-key", "tok123"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string("key=tok123"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("OPTIONS"))
        .and(header("x-key", "tok123"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    for (m, extra) in cases {
        let yaml = format!(
            r#"
id: m
name: M
detect:
  keywords: [tok]
  patterns: [{{ name: token, regex: '(tok[0-9]+)' }}]
verify:
  request:
    method: {m}
    url: {base}/endpoint
    {extra}
  valid: {{ status: [200, 204] }}
"#,
            base = server.uri()
        );
        let t = template::parse(&yaml, "t").unwrap();
        let out = verify::verify(&http(), &t, &parts_token("tok123")).await;
        assert_eq!(
            out.verification.status,
            Status::Verified,
            "method {m}: {:?}",
            out.verification.message
        );
    }
}

#[tokio::test]
async fn any_matcher_is_an_or() {
    let server = MockServer::start().await;
    Mock::given(path("/a"))
        .respond_with(ResponseTemplate::new(403).set_body_string("insufficient_scope"))
        .mount(&server)
        .await;
    let yaml = r#"
id: any
name: Any
detect:
  keywords: [tok]
  patterns: [{ name: token, regex: '(tok[0-9]+)' }]
verify:
  request: { url: BASE/a }
  valid:
    any:
      - { status: [200] }
      - { status: [403], body_contains: [insufficient_scope] }
  invalid: { status: [401] }
"#
    .replace("BASE", &server.uri());
    let t = template::parse(&yaml, "t").unwrap();
    let out = verify::verify(&http(), &t, &parts_token("tok1")).await;
    assert_eq!(out.verification.status, Status::Verified);
}

fn fallback_template(server: &MockServer) -> Template {
    let yaml = r#"
id: regional
name: Regional
detect:
  keywords: [tok]
  patterns: [{ name: token, regex: '(tok[0-9]+)' }]
verify:
  request: { url: BASE/us/validate, headers: { K: "{{ token }}" } }
  valid: { status: [200] }
  invalid: { status: [403] }
  extract: [{ name: org, label: Org, json: org }]
  fallbacks:
    - label: EU
      request: { url: BASE/eu/validate, headers: { K: "{{ token }}" } }
    - label: AP
      request: { method: POST, url: BASE/ap/validate, json: { key: "{{ token }}" } }
      valid: { status: [201] }
"#
    .replace("BASE", &server.uri());
    template::parse(&yaml, "t").unwrap()
}

#[tokio::test]
async fn fallbacks_verify_on_any_endpoint() {
    let server = MockServer::start().await;
    Mock::given(path("/us/validate"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    Mock::given(path("/eu/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"org": "acme"})))
        .mount(&server)
        .await;
    Mock::given(path("/ap/validate"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    let out = verify::verify(&http(), &fallback_template(&server), &parts_token("tok1")).await;
    assert_eq!(out.verification.status, Status::Verified);
    assert_eq!(out.verification.details["Endpoint"], "EU");
    assert_eq!(out.verification.details["Org"], "acme");
}

#[tokio::test]
async fn fallbacks_invalid_only_when_every_endpoint_rejects() {
    let server = MockServer::start().await;
    for p in ["/us/validate", "/eu/validate", "/ap/validate"] {
        Mock::given(path(p))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
    }
    let out = verify::verify(&http(), &fallback_template(&server), &parts_token("tok1")).await;
    assert_eq!(out.verification.status, Status::Invalid);

    // One endpoint erroring makes the overall result inconclusive.
    let server = MockServer::start().await;
    Mock::given(path("/us/validate"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    Mock::given(path("/eu/validate"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    Mock::given(path("/ap/validate"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let out = verify::verify(&http(), &fallback_template(&server), &parts_token("tok1")).await;
    assert_eq!(out.verification.status, Status::Unknown);
}

#[tokio::test]
async fn alerts_are_redacted_and_signed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let tok = format!("gh{}_{}", "p", "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo");
    std::fs::write(dir.path().join("a.env"), format!("T={tok}\n")).unwrap();
    let url = format!("{}/hook", server.uri());
    let out = tokio::task::spawn_blocking({
        let d = dir.path().to_path_buf();
        move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_kubera"))
                .args(["--allow-http", "scan", "fs", ".", "-f", "json"])
                .args(["--notify-env", "HOOK", "--notify-secret-env", "HOOK_KEY"])
                .env("HOOK", url)
                .env("HOOK_KEY", "s3cret")
                .current_dir(d)
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    let body = String::from_utf8_lossy(&r.body);
    assert!(!body.contains(&tok), "alerts must be redacted");
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["count"], 1);
    let ts = r
        .headers
        .get("x-kubera-timestamp")
        .unwrap()
        .to_str()
        .unwrap();
    let sig = r
        .headers
        .get("x-kubera-signature")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(sig, kubera::notify::signature("s3cret", ts, &r.body));

    // A failing endpoint makes an otherwise clean exit non-zero.
    let bad = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&bad)
        .await;
    let url = format!("{}/hook", bad.uri());
    let d = dir.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kubera"))
            .args([
                "--allow-http",
                "scan",
                "fs",
                ".",
                "-f",
                "json",
                "--notify-env",
                "HOOK",
            ])
            .env("HOOK", url)
            .current_dir(d)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[tokio::test]
async fn github_issues_comments_and_actions_logs() {
    use std::io::Write as _;
    let server = MockServer::start().await;
    let tok = |body: &str| format!("gh{}_{}", "p", body);
    let issue_tok = tok("9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo");
    let comment_tok = tok("Zz9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1");
    let log_tok = tok("Yy9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1");
    let j = |v: serde_json::Value| ResponseTemplate::new(200).set_body_json(v);
    Mock::given(method("GET"))
        .and(path("/repos/acme/app/issues"))
        .and(header("authorization", "Bearer api-token"))
        .respond_with(j(serde_json::json!([
            {"number": 7, "title": "Deploy broken", "body": format!("tried with\n{issue_tok}"),
             "html_url": "https://github.com/acme/app/issues/7"}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/app/issues/comments"))
        .respond_with(j(serde_json::json!([
            {"id": 99, "body": format!("use {comment_tok}"),
             "html_url": "https://github.com/acme/app/issues/7#issuecomment-99"}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/app/pulls/comments"))
        .respond_with(j(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/app/actions/runs"))
        .respond_with(j(serde_json::json!({"total_count": 1, "workflow_runs": [
            {"id": 5, "html_url": "https://github.com/acme/app/actions/runs/5"}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/app/actions/runs/5/logs"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/blob/logs.zip?sig=x", server.uri())),
        )
        .mount(&server)
        .await;
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file(
        "build/3_Run tests.txt",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    z.write_all(format!("2026-01-01T00:00:00Z echo {log_tok}\n").as_bytes())
        .unwrap();
    let logs = z.finish().unwrap().into_inner();
    Mock::given(method("GET"))
        .and(path("/blob/logs.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(logs))
        .mount(&server)
        .await;

    let api = server.uri();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kubera"))
            .args(["--allow-http", "scan", "github", "acme/app", "-f", "json"])
            .args(["--what", "issues,comments,actions", "--api-url", &api])
            .args(["--token-env", "GH"])
            .env("GH", "api-token")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut paths: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            assert_eq!(f["location"]["source"], "github");
            f["location"]["path"].as_str().unwrap().to_string()
        })
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "actions/runs/5/build/3_Run tests.txt",
            "comment/99",
            "issues/7"
        ]
    );
    // The pre-signed log URL never receives the token.
    let reqs = server.received_requests().await.unwrap();
    let blob = reqs
        .iter()
        .find(|r| r.url.path() == "/blob/logs.zip")
        .unwrap();
    assert!(blob.headers.get("authorization").is_none());
}

#[tokio::test]
async fn buckets_s3_signed_and_gcs() {
    use std::io::Write as _;
    use wiremock::matchers::{header_exists, query_param};
    let tok = format!("gh{}_{}", "p", "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo");
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file("app/.env", zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(format!("T={tok}\n").as_bytes()).unwrap();
    let zip = z.finish().unwrap().into_inner();

    let s3 = MockServer::start().await;
    let listing = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>
<Contents><Key>config/prod &amp; dev.env</Key><Size>60</Size></Contents>
<Contents><Key>backups/site.zip</Key><Size>{}</Size></Contents>
<Contents><Key>node_modules/x/index.js</Key><Size>60</Size></Contents>
<Contents><Key>huge.log</Key><Size>999999999999</Size></Contents>
<IsTruncated>false</IsTruncated></ListBucketResult>"#,
        zip.len()
    );
    Mock::given(method("GET"))
        .and(path("/acme-data"))
        .and(query_param("list-type", "2"))
        .and(header_exists("authorization"))
        .and(header_exists("x-amz-content-sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_string(listing))
        .mount(&s3)
        .await;
    Mock::given(method("GET"))
        .and(path("/acme-data/config/prod%20%26%20dev.env"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("TOKEN={tok}\n")))
        .mount(&s3)
        .await;
    Mock::given(method("GET"))
        .and(path("/acme-data/backups/site.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(zip))
        .mount(&s3)
        .await;
    let run = |args: Vec<String>, env: Vec<(&'static str, &'static str)>| {
        tokio::task::spawn_blocking(move || {
            let out = std::process::Command::new(env!("CARGO_BIN_EXE_kubera"))
                .arg("--allow-http")
                .args(&args)
                .env_remove("AWS_ACCESS_KEY_ID")
                .envs(env)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            let mut got: Vec<String> = v
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    assert_eq!(f["location"]["source"], "bucket");
                    format!(
                        "{}{}",
                        f["location"]["path"].as_str().unwrap(),
                        f["location"]["entry"]
                            .as_str()
                            .map(|e| format!("!/{e}"))
                            .unwrap_or_default()
                    )
                })
                .collect();
            got.sort();
            got
        })
    };
    let got = run(
        vec![
            "scan".into(),
            "bucket".into(),
            "s3://acme-data".into(),
            "--endpoint-url".into(),
            s3.uri(),
            "-f".into(),
            "json".into(),
        ],
        vec![
            ("AWS_ACCESS_KEY_ID", "AKIAFAKEFAKEFAKE0000"),
            ("AWS_SECRET_ACCESS_KEY", "fake/secret"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        got,
        vec!["backups/site.zip!/app/.env", "config/prod & dev.env"]
    );

    let gcs = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/storage/v1/b/acme-gcs/o"))
        .and(header("authorization", "Bearer gcs-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{"name": "dir/a.txt", "size": "60"}]
        })))
        .mount(&gcs)
        .await;
    Mock::given(method("GET"))
        .and(path("/storage/v1/b/acme-gcs/o/dir%2Fa.txt"))
        .and(query_param("alt", "media"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("t={tok}\n")))
        .mount(&gcs)
        .await;
    let got = run(
        vec![
            "scan".into(),
            "bucket".into(),
            "gs://acme-gcs".into(),
            "--endpoint-url".into(),
            gcs.uri(),
            "--token-env".into(),
            "GCS_TOKEN".into(),
            "-f".into(),
            "json".into(),
        ],
        vec![("GCS_TOKEN", "gcs-token")],
    )
    .await
    .unwrap();
    assert_eq!(got, vec!["dir/a.txt"]);
}

#[tokio::test]
async fn kubernetes_secrets_configmaps_and_workloads() {
    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let t = |body: &str| format!("gh{}_{}", "p", body);
    let (t1, t2, t3, t4) = (
        t("9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo"),
        t("Zz9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1"),
        t("Yy9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1"),
        t("Xx9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1"),
    );
    let server = MockServer::start().await;
    let list = |items: serde_json::Value| {
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({"items": items, "metadata": {}}))
    };
    Mock::given(method("GET"))
        .and(path("/api/v1/secrets"))
        .and(header("authorization", "Bearer kube-token"))
        .respond_with(list(serde_json::json!([
            {"metadata": {"namespace": "prod", "name": "ci"}, "type": "Opaque",
             "data": {"GITHUB_TOKEN": b64(&t1)}},
            {"metadata": {"namespace": "prod", "name": "sa"},
             "type": "kubernetes.io/service-account-token", "data": {"token": b64(&t4)}}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/configmaps"))
        .respond_with(list(serde_json::json!([
            {"metadata": {"namespace": "prod", "name": "app",
              "annotations": {"kubectl.kubernetes.io/last-applied-configuration":
                format!("{{\"data\":{{\"token\":\"{t2}\"}}}}")}},
             "data": {"LOG_LEVEL": "info"}}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/apis/apps/v1/deployments"))
        .respond_with(list(serde_json::json!([
            {"metadata": {"namespace": "prod", "name": "api"},
             "spec": {"template": {"spec": {"containers": [
                {"env": [{"name": "GH", "value": t3}]}]}}}}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/pods"))
        .respond_with(list(serde_json::json!([
            {"metadata": {"namespace": "prod", "name": "api-1",
              "ownerReferences": [{"kind": "ReplicaSet"}]},
             "spec": {"containers": [{"env": [{"name": "GH", "value": t3}]}]}}
        ])))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let kc = dir.path().join("config");
    std::fs::write(
        &kc,
        format!(
            "apiVersion: v1\nkind: Config\ncurrent-context: dev\ncontexts:\n- name: dev\n  context: {{cluster: k, user: u}}\nclusters:\n- name: k\n  cluster: {{server: '{}'}}\nusers:\n- name: u\n  user: {{token: kube-token}}\n",
            server.uri()
        ),
    )
    .unwrap();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kubera"))
            .args(["--allow-http", "scan", "k8s", "-f", "json", "--kubeconfig"])
            .arg(&kc)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut paths: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            assert_eq!(f["location"]["source"], "kubernetes");
            assert_eq!(f["location"]["repository"], "k8s:dev");
            f["location"]["path"].as_str().unwrap().to_string()
        })
        .collect();
    paths.sort();
    // The service account token and the controller-owned pod are skipped.
    assert_eq!(
        paths,
        vec![
            "configmap/prod/app",
            "deployment/prod/api",
            "secret/prod/ci"
        ]
    );

    // Path excludes apply to cluster objects too.
    let kc = dir.path().join("config");
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kubera"))
            .args(["--allow-http", "scan", "k8s", "-f", "json", "--kubeconfig"])
            .arg(&kc)
            .args(["--exclude-path", "secret/prod/**"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2);
}

fn finding_for(t: &Template, p: BTreeMap<String, String>) -> kubera::finding::Finding {
    kubera::finding::Finding::new(t, p, Default::default())
}

async fn verify_with_cache(
    t: &Template,
    findings: &mut [kubera::finding::Finding],
    cache: &kubera::verify_cache::Cache,
) {
    let map = std::collections::HashMap::from([(t.id.clone(), std::sync::Arc::new(t.clone()))]);
    verify::verify_findings(&http(), &map, findings, 4, Some(cache)).await;
    cache.save().unwrap();
}

/// Rewrite every entry of a cache file as checked `hours` ago.
fn age_cache(file: &std::path::Path, hours: u64) {
    let mut data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    let then = std::time::SystemTime::now() - std::time::Duration::from_secs(hours * 3600);
    let secs = then
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // RFC 3339 by hand (days from civil), so the test needs no date crate.
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let at = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    for e in data["entries"].as_object_mut().unwrap().values_mut() {
        e["checked_at"] = at.clone().into();
    }
    std::fs::write(file, data.to_string()).unwrap();
}

#[tokio::test]
async fn verify_cache_skips_requests_until_entries_expire() {
    use kubera::verify_cache::{Cache, Ttl};
    let server = MockServer::start().await;
    let t = tpl(&server);
    Mock::given(path("/me"))
        .and(header("authorization", "Bearer mk_ab12_Zq8Lw2Pm9Xa1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"user": {"login": "alice"}})),
        )
        .mount(&server)
        .await;
    // Another token is rejected (invalid); anything else is a server error
    // (unknown).
    Mock::given(path("/me"))
        .and(header("authorization", "Bearer mk_ab12_000000000000"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(path("/me"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let mut unknown = parts();
    unknown.insert("token".into(), "mk_ab12_999999999999".into());
    let mut invalid = parts();
    invalid.insert("token".into(), "mk_ab12_000000000000".into());
    let all = || {
        vec![
            finding_for(&t, parts()),
            finding_for(&t, parts()), // same secret elsewhere: one request
            finding_for(&t, invalid.clone()),
            finding_for(&t, unknown.clone()),
        ]
    };
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("cache/verify.json");
    let requests = || async { server.received_requests().await.unwrap().len() };
    let cached = |f: &kubera::finding::Finding| f.verification.as_ref().unwrap().cached;

    // Run 1: every distinct secret is sent once.
    let mut f = all();
    verify_with_cache(&t, &mut f, &Cache::open(&file, Ttl::default())).await;
    assert_eq!(requests().await, 3);
    let status: Vec<_> = f.iter().map(|f| f.status().unwrap()).collect();
    assert_eq!(
        status,
        [
            Status::Verified,
            Status::Verified,
            Status::Invalid,
            Status::Unknown
        ]
    );
    assert!(f.iter().all(|f| !cached(f)));
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("alice"), "details are kept: {text}");
    assert!(
        !text.contains("Zq8Lw2Pm9Xa1"),
        "secret in the cache: {text}"
    );

    // Run 2 (fresh cache object, same file): only the unknown result is
    // asked again; cached results say so in JSON.
    let mut f = all();
    verify_with_cache(&t, &mut f, &Cache::open(&file, Ttl::default())).await;
    assert_eq!(requests().await, 4);
    let live = f[0].verification.as_ref().unwrap();
    assert!(live.cached && live.checked_at.is_some());
    assert_eq!(live.status, Status::Verified);
    assert_eq!(live.details["Owner"], "alice");
    assert!(cached(&f[1]) && cached(&f[2]) && !cached(&f[3]));
    let json = serde_json::to_value(f[0].redact()).unwrap();
    assert_eq!(json["verification"]["cached"], true);
    let json = serde_json::to_value(f[3].redact()).unwrap();
    assert!(json["verification"].get("cached").is_none());

    // Two hours later: the live result (1h) expired, the invalid one (24h)
    // is still reused.
    age_cache(&file, 2);
    let mut f = all();
    verify_with_cache(&t, &mut f, &Cache::open(&file, Ttl::default())).await;
    assert_eq!(requests().await, 6, "live and unknown verified again");
    assert!(!cached(&f[0]) && cached(&f[2]));

    // A day later the invalid one expires too.
    age_cache(&file, 25);
    let mut f = vec![finding_for(&t, invalid.clone())];
    verify_with_cache(&t, &mut f, &Cache::open(&file, Ttl::default())).await;
    assert_eq!(requests().await, 7);
    assert!(!cached(&f[0]));

    // A TTL of 0 turns reuse off; an explicit re-check (`fresh`) asks the
    // platform even when a fresh result is cached.
    let strict = Ttl {
        invalid: std::time::Duration::ZERO,
        ..Ttl::default()
    };
    let mut f = vec![finding_for(&t, invalid.clone())];
    verify_with_cache(&t, &mut f, &Cache::open(&file, strict)).await;
    assert_eq!(requests().await, 8);
    let cache = Cache::open(&file, Ttl::default());
    let v = verify::verify_cached(&http(), &t, &invalid, Some(&cache), false).await;
    assert!(v.cached);
    assert_eq!(requests().await, 8);
    let v = verify::verify_cached(&http(), &t, &invalid, Some(&cache), true).await;
    assert!(!v.cached && v.status == Status::Invalid);
    assert_eq!(requests().await, 9);
}
