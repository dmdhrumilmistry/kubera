//! API sources end to end against local mock servers (`--allow-http`):
//! GitLab, Bitbucket, Slack, Jira, Confluence, package registries, Docker
//! Hub, Azure Blob Storage and Hugging Face.

use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Token-shaped test values, built at runtime so the repository itself
/// holds none.
fn fake_tokens<const N: usize>() -> [String; N] {
    let tails = [
        "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo",
        "Zz9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1",
        "Yy9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1",
        "Xx9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1",
        "Ww9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1",
        "Vv9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1",
    ];
    std::array::from_fn(|i| format!("gh{}_{}", "p", tails[i]))
}

fn json(v: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(v)
}

/// Run kubera with `args` (plus `--allow-http`, JSON output) and return
/// the findings, asserting success.
async fn run(args: &[&str], env: &[(&str, &str)]) -> Vec<serde_json::Value> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_kubera"))
            .arg("--allow-http")
            .args(&args)
            .args(["-f", "json"])
            .envs(env)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v.as_array().unwrap().clone()
    })
    .await
    .unwrap()
}

/// The sorted `location.path`s of `findings`, checking their source kind.
fn paths(findings: &[serde_json::Value], source: &str) -> Vec<String> {
    let mut p: Vec<String> = findings
        .iter()
        .map(|f| {
            assert_eq!(f["location"]["source"], source, "{f}");
            f["location"]["path"].as_str().unwrap().to_string()
        })
        .collect();
    p.sort();
    p
}

#[tokio::test]
async fn gitlab_issues_notes_and_job_logs() {
    let [t1, t2, t3, t4] = fake_tokens();
    let server = MockServer::start().await;
    let uri = server.uri();
    let base = "/projects/acme%2Fapp";
    Mock::given(method("GET"))
        .and(path(base))
        .and(header("private-token", "gl-token"))
        .respond_with(json(serde_json::json!({
            "id": 1, "path_with_namespace": "acme/app",
            "web_url": "https://gitlab.example/acme/app",
            "wiki_enabled": false, "snippets_enabled": true
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/issues")))
        .and(query_param("page", "2"))
        .respond_with(json(serde_json::json!([
            {"iid": 1, "title": "old", "description": format!("key {t4}"), "user_notes_count": 0}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/issues")))
        .and(query_param_is_missing("page"))
        .respond_with(
            json(serde_json::json!([
                {"iid": 3, "title": "Deploy broken", "description": format!("tried\n{t1}"),
                 "web_url": "https://gitlab.example/acme/app/-/issues/3", "user_notes_count": 1}
            ]))
            .insert_header(
                "link",
                format!(r#"<{uri}{base}/issues?page=2&per_page=100>; rel="next""#),
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/merge_requests")))
        .respond_with(json(serde_json::json!([
            {"iid": 4, "title": "fix", "description": "", "user_notes_count": 0}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/issues/3/notes")))
        .respond_with(json(serde_json::json!([
            {"id": 11, "body": format!("use {t2}"), "system": false},
            {"id": 12, "body": format!("changed the description {t1}"), "system": true}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/jobs")))
        .respond_with(json(serde_json::json!([
            {"id": 77, "name": "deploy", "web_url": "https://gitlab.example/acme/app/-/jobs/77"}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/jobs/77/trace")))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{uri}/storage/trace.log?sig=x")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/storage/trace.log"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "\x1b[32;1m$ ./deploy\x1b[0;m\nline two\n\x1b[0;mTOKEN={t3}\n"
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/snippets")))
        .respond_with(json(serde_json::json!([
            {"id": 5, "http_url_to_repo": "https://elsewhere.example/snippets/5.git"}
        ])))
        .mount(&server)
        .await;

    let found = run(
        &[
            "scan",
            "gitlab",
            "acme/app",
            "--api-url",
            &uri,
            "--token-env",
            "GL",
        ],
        &[("GL", "gl-token")],
    )
    .await;
    assert_eq!(
        paths(&found, "gitlab"),
        vec![
            "issues/1",
            "issues/3",
            "issues/3/notes/11",
            "jobs/77 (deploy)"
        ]
    );
    let job = found
        .iter()
        .find(|f| f["location"]["path"] == "jobs/77 (deploy)")
        .unwrap();
    assert_eq!(job["location"]["line"], 3);
    assert_eq!(
        job["location"]["link"],
        "https://gitlab.example/acme/app/-/jobs/77"
    );
    let reqs = server.received_requests().await.unwrap();
    let blob = reqs
        .iter()
        .find(|r| r.url.path() == "/storage/trace.log")
        .unwrap();
    // The pre-signed trace URL never receives the token.
    assert!(blob.headers.get("private-token").is_none());
    // Notes of items without user comments are never requested.
    assert!(
        !reqs
            .iter()
            .any(|r| r.url.path().contains("merge_requests/4"))
    );
}
