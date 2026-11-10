//! `remediate --issues` against a mock GitHub API, and `purge` on a real
//! repository, both from findings files written by `scan -f json`.

use std::path::Path;
use std::process::{Command, Output};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Built at runtime so the repository never contains a token-shaped literal.
fn fake_github_token() -> String {
    format!("gh{}_{}", "p", "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo")
}

fn git(dir: &Path, args: &[&str]) {
    let st = Command::new("git")
        .args(["-c", "user.name=Test", "-c", "user.email=t@example.com"])
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?}");
}

/// A repository whose history holds a token that was later deleted.
fn leaky_repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("widgets");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widgets.git",
        ],
    );
    std::fs::write(
        repo.join("cfg.env"),
        format!("TOKEN={}\n", fake_github_token()),
    )
    .unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "add config"]);
    std::fs::write(repo.join("cfg.env"), "TOKEN=from-env\n").unwrap();
    git(&repo, &["commit", "-q", "-am", "remove token"]);
    (root, repo)
}

fn kubera(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kubera"))
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .env("KUBERA_TEST_GH", "gh-issues-token")
        .output()
        .unwrap()
}

async fn kubera_async(cwd: &Path, args: Vec<String>) -> Output {
    let cwd = cwd.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        kubera(&cwd, &a)
    })
    .await
    .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// `scan git -f json` of the repository (redacted, like the default).
fn findings_file(root: &Path, repo: &Path, extra: &[&str]) -> serde_json::Value {
    let mut args = vec!["scan", "git", repo.to_str().unwrap(), "-f", "json"];
    args.extend_from_slice(extra);
    let out = kubera(root, &args);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("findings json");
    assert_eq!(v.as_array().unwrap().len(), 1, "{v:#}");
    v
}

async fn mount_repo(server: &MockServer, private: bool, issues: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/repos/acme/security"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"private": private, "has_issues": true})),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/security/issues"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issues))
        .mount(server)
        .await;
}

#[tokio::test]
async fn issues_are_opened_once_per_secret_without_the_secret() {
    let (root, repo) = leaky_repo();
    let mut v = findings_file(root.path(), &repo, &[]);
    let fp = v[0]["fingerprint"].as_str().unwrap().to_string();
    let commit = v[0]["location"]["commit"].as_str().unwrap().to_string();
    // The same secret seen twice, once verified; plus an unverified one.
    let mut live = v[0].clone();
    live["verification"] = serde_json::json!({"status": "verified"});
    live["location"]["path"] = "other/place.env".into();
    let mut other = v[0].clone();
    other["fingerprint"] = "0123456789abcdef01234567".into();
    v.as_array_mut().unwrap().extend([live, other]);
    let file = root.path().join("findings.json");
    std::fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let file_s = file.to_str().unwrap().to_string();

    // Offline dry run: no token, no network, only the live secret.
    let out = kubera(
        root.path(),
        &[
            "remediate",
            "--findings",
            &file_s,
            "--issues",
            "github:acme/security",
        ],
    );
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("would open") && t.contains("dry run"), "{t}");
    assert!(t.contains("1 to open"), "{t}");
    assert!(t.contains("not checked for duplicates"), "{t}");

    let server = MockServer::start().await;
    mount_repo(
        &server,
        true,
        serde_json::json!([
            {"number": 3, "body": "unrelated", "html_url": "https://github.com/acme/security/issues/3"},
            {"number": 4, "body": "<!-- kubera-fingerprint: 0123456789abcdef01234567 -->", "pull_request": {}}
        ]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/acme/widgets/commits/{commit}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"author": {"login": "alice-dev"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/security/issues"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "number": 7, "html_url": "https://github.com/acme/security/issues/7"
        })))
        .mount(&server)
        .await;
    let base = |extra: &[&str]| {
        let mut a: Vec<String> = [
            "--allow-http",
            "remediate",
            "--findings",
            &file_s,
            "--issues",
            "github:acme/security",
            "--token-env",
            "KUBERA_TEST_GH",
            "--api-url",
            &server.uri(),
            "--all",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        a.extend(extra.iter().map(|s| s.to_string()));
        a
    };

    // Dry run with a token: duplicate check, nothing created.
    let out = kubera_async(root.path(), base(&["--format", "json"])).await;
    assert!(out.status.success(), "{}", text(&out));
    let rep: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["checked_existing"], true);
    // The marker in a pull request does not count as an open issue.
    assert_eq!(rep["results"].as_array().unwrap().len(), 2, "{rep:#}");
    assert!(
        rep["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["action"] == "would_open")
    );
    let reqs = server.received_requests().await.unwrap();
    assert!(reqs.iter().all(|r| r.method.as_str() == "GET"));
    assert!(
        reqs.iter()
            .all(|r| r.headers.get("authorization").unwrap() == "Bearer gh-issues-token")
    );

    // Execute, verified only (default), with a committer mention.
    server.reset().await;
    mount_repo(&server, true, serde_json::json!([])).await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/acme/widgets/commits/{commit}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"author": {"login": "alice-dev"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/security/issues"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "number": 7, "html_url": "https://github.com/acme/security/issues/7"
        })))
        .mount(&server)
        .await;
    let mut args = base(&["--execute", "--mention-committer", "--label", "security"]);
    args.retain(|a| a != "--all");
    let out = kubera_async(root.path(), args).await;
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("opened #7"), "{t}");
    let reqs = server.received_requests().await.unwrap();
    let posts: Vec<_> = reqs
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .collect();
    assert_eq!(posts.len(), 1);
    let issue: serde_json::Value = serde_json::from_slice(&posts[0].body).unwrap();
    let body = issue["body"].as_str().unwrap();
    assert!(
        body.starts_with(&format!("<!-- kubera-fingerprint: {fp} -->")),
        "{body}"
    );
    assert!(body.contains("@alice-dev"), "{body}");
    assert!(
        body.contains("other/place.env") && body.contains("cfg.env"),
        "{body}"
    );
    assert!(
        !body.contains(&fake_github_token()[8..]),
        "secret in issue: {body}"
    );
    assert!(!String::from_utf8_lossy(&posts[0].body).contains(&fake_github_token()));
    assert_eq!(issue["labels"], serde_json::json!(["security"]));
    assert!(
        issue["title"].as_str().unwrap().starts_with("Live GitHub"),
        "{issue}"
    );

    // Run again: the issue exists, nothing is posted.
    server.reset().await;
    mount_repo(
        &server,
        true,
        serde_json::json!([{"number": 7, "body": body, "html_url": "https://github.com/acme/security/issues/7"}]),
    )
    .await;
    let mut args = base(&["--execute"]);
    args.retain(|a| a != "--all");
    let out = kubera_async(root.path(), args).await;
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("already open #7"), "{t}");
    let reqs = server.received_requests().await.unwrap();
    assert!(!reqs.iter().any(|r| r.method.as_str() == "POST"));

    // A public repository is refused.
    server.reset().await;
    mount_repo(&server, false, serde_json::json!([])).await;
    let out = kubera_async(root.path(), base(&["--execute"])).await;
    let t = text(&out);
    assert!(!out.status.success());
    assert!(t.contains("is public"), "{t}");
    let reqs = server.received_requests().await.unwrap();
    assert!(!reqs.iter().any(|r| r.method.as_str() == "POST"));
}

#[test]
fn purge_writes_a_private_expressions_file_and_never_rewrites() {
    let (root, repo) = leaky_repo();
    let v = findings_file(root.path(), &repo, &[]);
    assert_eq!(v[0]["redacted"], true);
    let file = root.path().join("findings.json");
    std::fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let head_before = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&repo)
        .output()
        .unwrap()
        .stdout;

    // Inside the repository: refused (it could be committed).
    let out = kubera(
        root.path(),
        &[
            "purge",
            "--findings",
            file.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
            "-o",
            repo.join("purge.txt").to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(
        text(&out).contains("inside the repository"),
        "{}",
        text(&out)
    );

    // Default location: next to the repository.
    let out = kubera(
        root.path(),
        &[
            "purge",
            "--findings",
            file.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("scanning the history"), "{t}");
    let expr = root.path().join("widgets-kubera-purge.txt");
    let data = std::fs::read_to_string(&expr).unwrap();
    assert_eq!(
        data,
        format!("literal:{}==>***REMOVED***\n", fake_github_token())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&expr).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    for want in [
        "git clone --bare https://github.com/acme/widgets.git widgets-purge.git",
        "git filter-repo --replace-text",
        "--replace-message",
        "git push --force --all origin",
        "Rotate first",
        "re-clone",
    ] {
        assert!(t.contains(want), "missing `{want}`: {t}");
    }
    // The secret is not printed.
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&fake_github_token()));
    // Never overwritten; the repository is untouched.
    let out = kubera(
        root.path(),
        &[
            "purge",
            "--findings",
            file.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(text(&out).contains("refusing to overwrite"));
    let head_after = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&repo)
        .output()
        .unwrap()
        .stdout;
    assert_eq!(head_before, head_after);

    // A --show-secrets file needs no re-scan.
    let v = findings_file(root.path(), &repo, &["--show-secrets"]);
    std::fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let out = kubera(
        root.path(),
        &[
            "purge",
            "--findings",
            file.to_str().unwrap(),
            "--repo",
            repo.to_str().unwrap(),
            "-o",
            "raw.txt",
            "--format",
            "json",
        ],
    );
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(!t.contains("scanning the history"), "{t}");
    let rep: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["values"], 1);
    assert!(
        std::fs::read_to_string(root.path().join("raw.txt"))
            .unwrap()
            .contains(&fake_github_token())
    );
}
