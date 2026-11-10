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

#[tokio::test]
async fn bitbucket_issues_pull_requests_and_pipeline_logs() {
    use base64::Engine as _;
    let [t1, t2, t3, t4, t5] = fake_tokens();
    let server = MockServer::start().await;
    let uri = server.uri();
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("ci-bot:bb-token")
    );
    let base = "/repositories/acme/app";
    Mock::given(method("GET"))
        .and(path(base))
        .and(header("authorization", basic.as_str()))
        .respond_with(json(serde_json::json!({
            "full_name": "acme/app", "has_issues": true,
            "links": {"html": {"href": "https://bitbucket.org/acme/app"}}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/issues")))
        .and(query_param("page", "2"))
        .respond_with(json(serde_json::json!({"values": [
            {"id": 5, "title": "old", "content": {"raw": format!("key {t4}")}}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/issues")))
        .and(query_param_is_missing("page"))
        .respond_with(json(serde_json::json!({
            "values": [{"id": 2, "title": "Deploy broken", "content": {"raw": format!("tried {t1}")},
                        "links": {"html": {"href": "https://bitbucket.org/acme/app/issues/2"}}}],
            "next": format!("{uri}{base}/issues?pagelen=50&page=2")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/issues/2/comments")))
        .respond_with(json(serde_json::json!({"values": [
            {"id": 9, "content": {"raw": format!("use {t2}")}}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/issues/5/comments")))
        .respond_with(json(serde_json::json!({"values": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/pullrequests")))
        .respond_with(json(serde_json::json!({"values": [
            {"id": 7, "title": "fix", "summary": {"raw": ""}, "comment_count": 2},
            {"id": 8, "title": "docs", "summary": {"raw": ""}, "comment_count": 0}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/pullrequests/7/comments")))
        .respond_with(json(serde_json::json!({"values": [
            {"id": 3, "content": {"raw": format!("oops {t5}")}, "inline": {"path": "src/a.py"}},
            {"id": 4, "deleted": true, "content": {"raw": format!("gone {t2}")}}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/pipelines/")))
        .respond_with(json(serde_json::json!({"values": [
            {"uuid": "{p-1}", "build_number": 12}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/pipelines/%7Bp-1%7D/steps/")))
        .respond_with(json(serde_json::json!({"values": [
            {"uuid": "{s-1}", "name": "Deploy"}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{base}/pipelines/%7Bp-1%7D/steps/%7Bs-1%7D/log"
        )))
        .respond_with(ResponseTemplate::new(307).insert_header(
            "location",
            format!("{uri}/storage/step.log?X-Amz-Signature=x"),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/storage/step.log"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("+ ./deploy.sh\nTOKEN={t3}\n")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/snippets/acme"))
        .respond_with(json(serde_json::json!({"values": [
            {"id": "abc", "links": {"clone": [
                {"name": "https", "href": "https://ci-bot@elsewhere.example/acme/abc.git"}
            ]}}
        ]})))
        .mount(&server)
        .await;

    let found = run(
        &[
            "scan",
            "bitbucket",
            "acme/app",
            "--api-url",
            &uri,
            "--token-env",
            "BB",
            "--token-user",
            "ci-bot",
        ],
        &[("BB", "bb-token")],
    )
    .await;
    assert_eq!(
        paths(&found, "bitbucket"),
        vec![
            "issues/2",
            "issues/2/comments/9",
            "issues/5",
            "pipelines/12/Deploy",
            "pull-requests/7/comments/3 (src/a.py)"
        ]
    );
    let log = found
        .iter()
        .find(|f| f["location"]["path"] == "pipelines/12/Deploy")
        .unwrap();
    assert_eq!(
        log["location"]["link"],
        "https://bitbucket.org/acme/app/pipelines/results/12"
    );
    let reqs = server.received_requests().await.unwrap();
    let blob = reqs
        .iter()
        .find(|r| r.url.path() == "/storage/step.log")
        .unwrap();
    assert!(blob.headers.get("authorization").is_none());
    assert!(!reqs.iter().any(|r| r.url.path().contains("pullrequests/8")));
}

#[tokio::test]
async fn slack_history_threads_and_rate_limits() {
    let [t1, t2, t3] = fake_tokens();
    let server = MockServer::start().await;
    let ok = |mut v: serde_json::Value| {
        v["ok"] = true.into();
        json(v)
    };
    Mock::given(method("GET"))
        .and(path("/auth.test"))
        .and(header("authorization", "Bearer slack-token"))
        .respond_with(ok(
            serde_json::json!({"team": "Acme", "url": "https://acme.slack.com/"}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ok(serde_json::json!({"channels": [
            {"id": "C01GENERAL", "name": "general"},
            {"id": "C02RANDOM0", "name": "random"}
        ]})))
        .mount(&server)
        .await;
    // The first history call is rate limited: kubera waits and retries.
    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .and(query_param("channel", "C01GENERAL"))
        .and(query_param("oldest", "1672531200"))
        .and(query_param_is_missing("cursor"))
        .respond_with(ok(serde_json::json!({
            "messages": [
                {"ts": "1700000000.000100", "user": "U1", "text": format!("deploy with {t1}")},
                {"ts": "1700000100.000200", "text": "thread", "reply_count": 1,
                 "thread_ts": "1700000100.000200"}
            ],
            "response_metadata": {"next_cursor": "c2"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .and(query_param("channel", "C01GENERAL"))
        .and(query_param("cursor", "c2"))
        .respond_with(ok(serde_json::json!({"messages": [
            {"ts": "1690000000.000300", "attachments": [{"text": format!("TOKEN={t3}")}]}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .and(query_param("channel", "C02RANDOM0"))
        .respond_with(json(
            serde_json::json!({"ok": false, "error": "not_in_channel"}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/conversations.replies"))
        .and(query_param("ts", "1700000100.000200"))
        .respond_with(ok(serde_json::json!({"messages": [
            {"ts": "1700000100.000200", "text": "thread", "thread_ts": "1700000100.000200"},
            {"ts": "1700000200.000400", "text": format!("here {t2}"), "thread_ts": "1700000100.000200"}
        ]})))
        .mount(&server)
        .await;

    let found = run(
        &[
            "scan",
            "slack",
            "--api-url",
            &server.uri(),
            "--token-env",
            "SLACK",
            "--since",
            "2023-01-01",
        ],
        &[("SLACK", "slack-token")],
    )
    .await;
    assert_eq!(
        paths(&found, "slack"),
        vec![
            "#general/1690000000.000300",
            "#general/1700000000.000100",
            "#general/1700000100.000200/1700000200.000400"
        ]
    );
    let reply = found
        .iter()
        .find(|f| f["location"]["path"] == "#general/1700000100.000200/1700000200.000400")
        .unwrap();
    assert_eq!(
        reply["location"]["link"],
        "https://acme.slack.com/archives/C01GENERAL/p1700000200000400?thread_ts=1700000100.000200&cid=C01GENERAL"
    );
    assert_eq!(reply["location"]["repository"], "slack:Acme");
}

fn adf(text: &str) -> serde_json::Value {
    serde_json::json!({"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": "see below"}]},
        {"type": "codeBlock", "content": [{"type": "text", "text": text}]}
    ]})
}

#[tokio::test]
async fn jira_issues_comments_and_history() {
    use base64::Engine as _;
    let [t1, t2, t3, t4, t5] = fake_tokens();
    let server = MockServer::start().await;
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("dana@acme.example:jira-token")
    );
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .and(header("authorization", basic.as_str()))
        .and(query_param(
            "jql",
            r#"project in ("ACME") ORDER BY created DESC"#,
        ))
        .and(query_param_is_missing("nextPageToken"))
        .respond_with(json(serde_json::json!({
            "issues": [{"key": "ACME-1", "fields": {
                "summary": "Deploy broken",
                "description": adf(&format!("export TOKEN={t1}")),
                "comment": {"total": 2, "comments": [{"id": "10001", "body": adf(&t2)}]}
            }, "changelog": {"total": 1, "histories": [
                {"id": "500", "items": [
                    {"field": "description", "fromString": format!("old: {t3}")},
                    {"field": "status", "fromString": "Open"}
                ]}
            ]}}],
            "nextPageToken": "p2"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .and(query_param("nextPageToken", "p2"))
        .respond_with(json(serde_json::json!({
            "issues": [{"key": "ACME-2", "fields": {
                "summary": format!("leaked {t4}"), "description": null,
                "comment": {"total": 0, "comments": []}
            }}],
            "isLast": true
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/ACME-1/comment"))
        .and(query_param("startAt", "1"))
        .respond_with(json(serde_json::json!({
            "comments": [{"id": "10002", "body": adf(&t5)}]
        })))
        .mount(&server)
        .await;

    let site = server.uri();
    let found = run(
        &[
            "scan",
            "jira",
            "--site",
            &site,
            "--project",
            "ACME",
            "--email-env",
            "JIRA_EMAIL",
            "--token-env",
            "JIRA_TOKEN",
        ],
        &[
            ("JIRA_EMAIL", "dana@acme.example"),
            ("JIRA_TOKEN", "jira-token"),
        ],
    )
    .await;
    assert_eq!(
        paths(&found, "jira"),
        vec![
            "ACME-1",
            "ACME-1/comment/10001",
            "ACME-1/comment/10002",
            "ACME-1/history/500",
            "ACME-2"
        ]
    );
    let c = found
        .iter()
        .find(|f| f["location"]["path"] == "ACME-1/comment/10002")
        .unwrap();
    assert_eq!(
        c["location"]["link"].as_str(),
        None,
        "http links are dropped; https ones are kept"
    );
    let issue = found
        .iter()
        .find(|f| f["location"]["path"] == "ACME-1")
        .unwrap();
    // summary, "see below", then the code block.
    assert_eq!(issue["location"]["line"], 3);
}

#[tokio::test]
async fn confluence_pages_comments_and_versions() {
    use wiremock::matchers::path_regex;
    let [t1, t2, t3, t4, t5] = fake_tokens();
    let server = MockServer::start().await;
    let storage = |html: String| serde_json::json!({"storage": {"value": html}});
    let api = "/wiki/api/v2";
    Mock::given(method("GET"))
        .and(path(format!("{api}/spaces")))
        .and(query_param("keys", "OPS"))
        .and(header("authorization", "Bearer conf-token"))
        .respond_with(json(
            serde_json::json!({"results": [{"id": "100", "key": "OPS"}]}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{api}/spaces/100/pages")))
        .and(query_param_is_missing("cursor"))
        .respond_with(json(serde_json::json!({
            "results": [{"id": "1", "title": "Runbook", "version": {"number": 2},
                "_links": {"webui": "/spaces/OPS/pages/1/Runbook"},
                "body": storage(format!(
                    "<p>Deploy:</p><ac:structured-macro ac:name=\"code\"><ac:plain-text-body><![CDATA[TOKEN={t1}]]></ac:plain-text-body></ac:structured-macro>"
                ))}],
            "_links": {"next": format!("{api}/spaces/100/pages?cursor=abc&body-format=storage")}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{api}/spaces/100/pages")))
        .and(query_param("cursor", "abc"))
        .respond_with(json(serde_json::json!({"results": [
            {"id": "2", "title": "Old", "version": {"number": 1},
             "body": storage(format!("<p>key&nbsp;{t4}</p>"))}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{api}/spaces/100/blogposts")))
        .respond_with(json(serde_json::json!({"results": [
            {"id": "9", "title": "News", "body": storage(format!("<p>{t5}</p>"))}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{api}/pages/1/footer-comments")))
        .respond_with(json(serde_json::json!({"results": [
            {"id": "50", "body": storage(format!("<p>try <code>{t2}</code></p>"))}
        ]})))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("-comments$"))
        .respond_with(json(serde_json::json!({"results": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{api}/pages/1")))
        .and(query_param("version", "1"))
        .respond_with(json(serde_json::json!({
            "id": "1", "title": "Runbook", "body": storage(format!("<p>first draft {t3}</p>"))
        })))
        .mount(&server)
        .await;

    let site = server.uri();
    let found = run(
        &[
            "scan",
            "confluence",
            "--site",
            &site,
            "--space",
            "OPS",
            "--max-versions",
            "5",
            "--token-env",
            "CONF",
        ],
        &[("CONF", "conf-token")],
    )
    .await;
    assert_eq!(
        paths(&found, "confluence"),
        vec![
            "OPS/blogposts/9",
            "OPS/pages/1",
            "OPS/pages/1/comments/50",
            "OPS/pages/1/versions/1",
            "OPS/pages/2"
        ]
    );
    let page = found
        .iter()
        .find(|f| f["location"]["path"] == "OPS/pages/1")
        .unwrap();
    assert_eq!(page["location"]["line"], 3);
}

fn tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut b = tar::Builder::new(Vec::new());
    for (n, d) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(d.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, n, *d).unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&b.into_inner().unwrap()).unwrap();
    gz.finish().unwrap()
}

fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (n, d) in files {
        z.start_file(*n, zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(d).unwrap();
    }
    z.finish().unwrap().into_inner()
}

/// `repository path!/entry` of each finding, sorted.
fn entries(found: &[serde_json::Value], source: &str) -> Vec<String> {
    let mut v: Vec<String> = found
        .iter()
        .map(|f| {
            let l = &f["location"];
            assert_eq!(l["source"], source, "{f}");
            format!(
                "{} {}!/{}",
                l["repository"].as_str().unwrap(),
                l["path"].as_str().unwrap(),
                l["entry"].as_str().unwrap_or("")
            )
        })
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn packages_npm_pypi_crates_verified_downloads() {
    use base64::Engine as _;
    use sha2::{Digest, Sha256, Sha512};
    let [t1, t2, t3, t4] = fake_tokens();
    let server = MockServer::start().await;
    let uri = server.uri();
    let npm_tgz = tgz(&[
        ("package/package.json", b"{}"),
        ("package/.env", format!("TOKEN={t1}\n").as_bytes()),
    ]);
    let sdist = tgz(&[("acme_tool-2.0/.env", format!("K={t2}\n").as_bytes())]);
    let wheel = zip(&[(
        "acme_tool/config.py",
        format!("TOKEN = '{t3}'\n").as_bytes(),
    )]);
    let krate = tgz(&[(
        "acme-0.3.0/tests/fixture.toml",
        format!("token = \"{t4}\"\n").as_bytes(),
    )]);
    let sha256 = |b: &[u8]| hex::encode(Sha256::digest(b));
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&npm_tgz))
    );
    Mock::given(method("GET"))
        .and(path("/@acme%2Fcli"))
        .respond_with(json(serde_json::json!({
            "dist-tags": {"latest": "1.1.0"},
            "versions": {
                "1.0.0": {"dist": {"tarball": format!("{uri}/@acme/cli/-/cli-1.0.0.tgz")}},
                "1.1.0": {"dist": {"tarball": format!("{uri}/@acme/cli/-/cli-1.1.0.tgz"),
                                   "integrity": integrity}}
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/@acme/cli/-/cli-1.1.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(npm_tgz.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/pypi/acme-tool/json"))
        .respond_with(json(serde_json::json!({
            "info": {"version": "2.0"},
            "urls": [
                {"packagetype": "bdist_wheel", "filename": "acme_tool-2.0-cp312-cp312-linux_x86_64.whl",
                 "url": format!("{uri}/files/native.whl"), "size": 10, "digests": {"sha256": "00"}},
                {"packagetype": "bdist_wheel", "filename": "acme_tool-2.0-py3-none-any.whl",
                 "url": format!("{uri}/files/acme_tool-2.0-py3-none-any.whl"),
                 "size": wheel.len(), "digests": {"sha256": sha256(&wheel)}},
                {"packagetype": "sdist", "filename": "acme_tool-2.0.tar.gz",
                 "url": format!("{uri}/files/acme_tool-2.0.tar.gz"),
                 "size": sdist.len(), "digests": {"sha256": sha256(&sdist)}}
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/files/acme_tool-2.0-py3-none-any.whl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/files/acme_tool-2.0.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sdist.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/acme"))
        .respond_with(json(
            serde_json::json!({"crate": {"default_version": "0.3.0"}}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/acme/0.3.0"))
        .respond_with(json(serde_json::json!({"version": {
            "num": "0.3.0", "checksum": sha256(&krate), "crate_size": krate.len()
        }})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/crates/acme/acme-0.3.0.crate"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(krate.clone()))
        .mount(&server)
        .await;

    let found = run(
        &[
            "scan",
            "package",
            "npm:@acme/cli",
            "pypi:acme-tool",
            "crates:acme",
            "--registry-url",
            &uri,
        ],
        &[],
    )
    .await;
    assert_eq!(
        entries(&found, "package"),
        vec![
            "crates:acme@0.3.0 acme-0.3.0.crate!/acme-0.3.0/tests/fixture.toml",
            "npm:@acme/cli@1.1.0 cli-1.1.0.tgz!/package/.env",
            "pypi:acme-tool@2.0 acme_tool-2.0-py3-none-any.whl!/acme_tool/config.py",
            "pypi:acme-tool@2.0 acme_tool-2.0.tar.gz!/acme_tool-2.0/.env",
        ]
    );
    // Only the latest npm version and one wheel were downloaded.
    let reqs = server.received_requests().await.unwrap();
    assert!(!reqs.iter().any(|r| r.url.path().ends_with("cli-1.0.0.tgz")));
    assert!(!reqs.iter().any(|r| r.url.path().ends_with("native.whl")));

    // A download that does not match the registry's digest stops the scan.
    let bad = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/acme/0.3.0"))
        .respond_with(json(serde_json::json!({"version": {
            "num": "0.3.0", "checksum": sha256(b"something else")
        }})))
        .mount(&bad)
        .await;
    Mock::given(method("GET"))
        .and(path("/crates/acme/acme-0.3.0.crate"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(krate))
        .mount(&bad)
        .await;
    let bad_uri = bad.uri();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_kubera"))
            .args(["--allow-http", "scan", "package", "crates:acme@0.3.0"])
            .args(["--registry-url", &bad_uri])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("sha256 mismatch"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dockerhub_org_images_are_listed_and_pulled() {
    use sha2::{Digest, Sha256};
    let [t1] = fake_tokens();
    let digest = |b: &[u8]| format!("sha256:{}", hex::encode(Sha256::digest(b)));
    let layer = tgz(&[("app/creds.env", format!("GITHUB_TOKEN={t1}\n").as_bytes())]);
    let cfg = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64", "os": "linux", "config": {}, "history": []
    }))
    .unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": digest(&cfg), "size": cfg.len()},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": digest(&layer), "size": layer.len()}]
    }))
    .unwrap();
    let server = MockServer::start().await;
    let uri = server.uri();
    Mock::given(method("POST"))
        .and(path("/v2/users/login"))
        .respond_with(json(serde_json::json!({"token": "hub-jwt"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/namespaces/acme/repositories"))
        .and(header("authorization", "Bearer hub-jwt"))
        .respond_with(json(serde_json::json!({"next": null, "results": [
            {"name": "app", "repository_type": "image"},
            {"name": "huge", "repository_type": "image"}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/namespaces/acme/repositories/app/tags"))
        .and(query_param("ordering", "last_updated"))
        .respond_with(json(serde_json::json!({"results": [
            {"name": "1.0", "full_size": layer.len()}
        ]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/namespaces/acme/repositories/huge/tags"))
        .respond_with(json(serde_json::json!({"results": [
            {"name": "latest", "full_size": 99_000_000_000u64}
        ]})))
        .mount(&server)
        .await;
    for (p, body) in [
        ("/v2/acme/app/manifests/1.0".to_string(), manifest.clone()),
        (format!("/v2/acme/app/blobs/{}", digest(&cfg)), cfg.clone()),
        (
            format!("/v2/acme/app/blobs/{}", digest(&layer)),
            layer.clone(),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
    }
    let registry = uri.trim_start_matches("http://").to_string();
    let found = run(
        &[
            "scan",
            "dockerhub",
            "acme",
            "--hub-url",
            &uri,
            "--registry",
            &registry,
            "--registry-user",
            "ci",
            "--registry-token-env",
            "HUB_PAT",
        ],
        &[("HUB_PAT", "hub-pat")],
    )
    .await;
    assert_eq!(paths(&found, "container"), vec!["/app/creds.env"]);
    assert_eq!(
        found[0]["location"]["repository"],
        format!("{registry}/acme/app:1.0")
    );
    let reqs = server.received_requests().await.unwrap();
    assert!(!reqs.iter().any(|r| r.url.path().contains("/v2/acme/huge/")));
}
