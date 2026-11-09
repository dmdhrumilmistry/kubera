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
