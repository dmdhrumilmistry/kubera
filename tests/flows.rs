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
