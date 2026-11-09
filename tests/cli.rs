//! End-to-end tests of the `kubera` binary.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Built at runtime so the repository never contains a token-shaped literal.
fn fake_github_token() -> String {
    format!("gh{}_{}", "p", "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo")
}

fn kubera(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kubera"))
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "bad json ({e}): {}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

#[test]
fn scan_fs_redacts_by_default_and_honours_ignores() {
    let dir = tempfile::tempdir().unwrap();
    let tok = fake_github_token();
    std::fs::write(
        dir.path().join("config.env"),
        format!("A=1\nGITHUB_TOKEN={tok}\nB=2\nOTHER={tok} # kubera:ignore\n"),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("vendor")).unwrap();
    std::fs::write(dir.path().join("vendor/x.txt"), &tok).unwrap();

    let out = kubera(
        &[
            "scan",
            "fs",
            ".",
            "-f",
            "json",
            "--exclude-path",
            "vendor/**",
        ],
        dir.path(),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1, "{v:#}");
    assert_eq!(arr[0]["detector"], "github-token");
    assert_eq!(arr[0]["location"]["line"], 2);
    assert_eq!(arr[0]["redacted"], true);
    let shown = arr[0]["secret"]["token"].as_str().unwrap();
    assert!(!shown.contains(&tok[8..]), "secret not redacted: {shown}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&tok));

    let out = kubera(
        &["scan", "fs", ".", "-f", "json", "--show-secrets", "--fail"],
        dir.path(),
    );
    assert_eq!(out.status.code(), Some(183));
    assert!(String::from_utf8_lossy(&out.stdout).contains(&tok));
}

#[test]
fn scan_fs_sarif() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), fake_github_token()).unwrap();
    let out = kubera(&["scan", "fs", ".", "-f", "sarif"], dir.path());
    let v = json(&out);
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["results"][0]["ruleId"], "github-token");
}

#[test]
fn allowlist_in_config_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), fake_github_token()).unwrap();
    std::fs::write(
        dir.path().join(".kubera.yaml"),
        "allowlist:\n  secrets: ['^ghp_9nVq']\n",
    )
    .unwrap();
    let out = kubera(&["scan", "fs", ".", "-f", "json"], dir.path());
    assert_eq!(json(&out).as_array().unwrap().len(), 0);
}

#[test]
fn scan_stdin() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kubera"))
        .args(["scan", "stdin", "-f", "jsonl"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("line1\ntoken {}\n", fake_github_token()).as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let line: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).lines().next().unwrap()).unwrap();
    assert_eq!(line["location"]["source"], "stdin");
    assert_eq!(line["location"]["line"], 2);
}

fn git(dir: &Path, args: &[&str]) {
    let st = Command::new("git")
        .args(["-c", "user.name=Test", "-c", "user.email=t@example.com"])
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(st.success());
}

#[test]
fn scan_git_history_finds_deleted_secret() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    git(d, &["init", "-q", "-b", "main"]);
    std::fs::write(d.join("app.py"), "print('hi')\n").unwrap();
    git(d, &["add", "."]);
    git(d, &["commit", "-q", "-m", "init"]);
    std::fs::write(
        d.join("app.py"),
        format!("print('hi')\nTOKEN = '{}'\n", fake_github_token()),
    )
    .unwrap();
    git(d, &["commit", "-q", "-am", "add token"]);
    std::fs::write(d.join("app.py"), "print('hi')\n").unwrap();
    git(d, &["commit", "-q", "-am", "remove token"]);

    // Working tree is clean...
    let out = kubera(&["scan", "fs", "app.py", "-f", "json"], d);
    assert_eq!(json(&out).as_array().unwrap().len(), 0);

    // ...but history is not.
    let out = kubera(&["scan", "git", ".", "-f", "json"], d);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1, "{v:#}");
    assert_eq!(arr[0]["location"]["source"], "git");
    assert_eq!(arr[0]["location"]["path"], "app.py");
    assert_eq!(arr[0]["location"]["line"], 2);
    assert_eq!(arr[0]["location"]["email"], "t@example.com");
    assert_eq!(arr[0]["location"]["commit"].as_str().unwrap().len(), 40);

    // Option-like revisions are rejected rather than passed to git.
    let out = kubera(&["scan", "git", ".", "--branch=--output=/tmp/pwn"], d);
    assert!(!out.status.success());
}

#[test]
fn templates_validate_and_custom_dir() {
    let dir = tempfile::tempdir().unwrap();
    let skel = kubera(&["templates", "new", "acme-key"], dir.path());
    std::fs::create_dir(dir.path().join("tpl")).unwrap();
    std::fs::write(dir.path().join("tpl/acme.yaml"), &skel.stdout).unwrap();

    let out = kubera(&["templates", "validate", "tpl"], dir.path());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    let out = kubera(
        &[
            "--no-builtin",
            "-t",
            "tpl",
            "templates",
            "list",
            "--format",
            "json",
        ],
        dir.path(),
    );
    let v = json(&out);
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["id"], "acme-key");
    assert_eq!(v[0]["rotate"], "api");
}

#[test]
fn rotate_requires_confirmation_without_tty() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_kubera"))
        .args(["rotate", "github-token", "--secret-env", "T", "--execute"])
        .env("T", fake_github_token())
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--yes"));
}

fn repo_with_secret() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    git(d, &["init", "-q", "-b", "main"]);
    std::fs::write(
        d.join("cfg.env"),
        format!("TOKEN={}\n", fake_github_token()),
    )
    .unwrap();
    git(d, &["add", "."]);
    git(d, &["commit", "-q", "-m", "add"]);
    git(
        d,
        &["remote", "add", "origin", "git@github.com:acme/widgets.git"],
    );
    dir
}

#[test]
fn scan_git_remote_url_and_web_links() {
    let src = repo_with_secret();
    let cwd = tempfile::tempdir().unwrap();

    // Remote transport (clone into a temp dir), exercised offline via file://.
    let url = format!("file://{}", src.path().display());
    let out = kubera(&["scan", "git", &url, "-f", "json"], cwd.path());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    assert_eq!(v[0]["location"]["repository"], url.as_str());
    assert_eq!(v[0]["location"]["path"], "cfg.env");

    // Local repository with a GitHub origin: findings link to the line.
    let out = kubera(
        &["scan", "git", src.path().to_str().unwrap(), "-f", "json"],
        cwd.path(),
    );
    let v = json(&out);
    let link = v[0]["location"]["link"].as_str().unwrap();
    let commit = v[0]["location"]["commit"].as_str().unwrap();
    assert_eq!(
        link,
        format!("https://github.com/acme/widgets/blob/{commit}/cfg.env#L1")
    );
}

#[tokio::test]
async fn private_repo_token_is_sent_as_scoped_header() {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let url = format!("{}/acme/private.git", server.uri());
    let cwd = tempfile::tempdir().unwrap();
    let run = |args: Vec<String>| {
        let cwd = cwd.path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            Command::new(env!("CARGO_BIN_EXE_kubera"))
                .args(&args)
                .current_dir(cwd)
                .env("KUBERA_TEST_TOKEN", "glpat-test-0123")
                .env("NO_COLOR", "1")
                .output()
                .unwrap()
        })
    };

    // Plain http never receives credentials.
    let out = run(vec![
        "scan".into(),
        "git".into(),
        url.clone(),
        "--token-env".into(),
        "KUBERA_TEST_TOKEN".into(),
    ])
    .await
    .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("plain http"));
    assert!(server.received_requests().await.unwrap().is_empty());

    // With the test-only opt-in, git sends the token as a Basic auth header.
    let out = run(vec![
        "--allow-http".into(),
        "scan".into(),
        "git".into(),
        url.clone(),
        "--token-env".into(),
        "KUBERA_TEST_TOKEN".into(),
        "--token-user".into(),
        "oauth2".into(),
    ])
    .await
    .unwrap();
    assert!(!out.status.success()); // the mock is not a git server
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("glpat-test-0123"), "{stderr}");
    let reqs = server.received_requests().await.unwrap();
    assert!(!reqs.is_empty());
    use base64::Engine;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("oauth2:glpat-test-0123")
    );
    assert!(
        reqs.iter().any(|r| r
            .headers
            .get("authorization")
            .is_some_and(|h| h.to_str().unwrap() == expected)),
        "no request carried the expected Authorization header"
    );
}

fn make_repo(dir: &Path, secret: bool) {
    git(dir, &["init", "-q", "-b", "main"]);
    std::fs::write(dir.join("a.txt"), "hello\n").unwrap();
    if secret {
        std::fs::write(dir.join("b.env"), format!("T={}\n", fake_github_token())).unwrap();
    }
    git(dir, &["add", "."]);
    git(dir, &["commit", "-q", "-m", "init"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn mass_scan_github_org_rate_limited_incremental() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let repos = tempfile::tempdir().unwrap();
    let (clean, leaky, fork) = (
        repos.path().join("clean"),
        repos.path().join("leaky"),
        repos.path().join("fork"),
    );
    for (d, s) in [(&clean, false), (&leaky, true), (&fork, true)] {
        std::fs::create_dir(d).unwrap();
        make_repo(d, s);
    }
    let url = |p: &Path| format!("file://{}", p.display());

    let server = MockServer::start().await;
    // Page 1 is rate limited once (Retry-After), then served.
    Mock::given(method("GET"))
        .and(path("/orgs/acme/repos"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"full_name": "acme/fork", "clone_url": url(&fork), "fork": true, "archived": false}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/repos"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/repos"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "link",
                    format!(r#"<{}/orgs/acme/repos?page=2>; rel="next""#, server.uri()).as_str(),
                )
                .set_body_json(serde_json::json!([
                    {"full_name": "acme/clean", "clone_url": url(&clean), "fork": false, "archived": false},
                    {"full_name": "acme/leaky", "clone_url": url(&leaky), "fork": false, "archived": false}
                ])),
        )
        .mount(&server)
        .await;

    let work = tempfile::tempdir().unwrap();
    let cache = work.path().join("cache");
    let state = work.path().join("state.json");
    let api = server.uri();
    let run =
        move |cwd: std::path::PathBuf, cache: std::path::PathBuf, state: std::path::PathBuf| {
            let api = api.clone();
            tokio::task::spawn_blocking(move || {
                Command::new(env!("CARGO_BIN_EXE_kubera"))
                    .args([
                        "--allow-http",
                        "scan",
                        "repos",
                        "--github-org",
                        "acme",
                        "--api-url",
                    ])
                    .arg(&api)
                    .arg("--cache-dir")
                    .arg(&cache)
                    .arg("--state")
                    .arg(&state)
                    .args(["-f", "json"])
                    .current_dir(cwd)
                    .env("NO_COLOR", "1")
                    .output()
                    .unwrap()
            })
        };

    // Run 1: discovers 2 repos (fork skipped), clones, finds the leak.
    let out = run(work.path().into(), cache.clone(), state.clone())
        .await
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{err}");
    assert!(err.contains("rate limited"), "{err}");
    assert!(err.contains("2 repositories (1 skipped"), "{err}");
    let v = json(&out);
    assert_eq!(v.as_array().unwrap().len(), 1, "{v:#}");
    assert!(err.contains("1 baseline(s) advanced, 1 kept"), "{err}");
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 2);

    // Run 2: nothing new in the clean repo; the leaky one is still reported.
    let out = run(work.path().into(), cache.clone(), state.clone())
        .await
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(err.contains("clean.git") || err.contains("/clean"), "{err}");
    assert!(err.contains("0 new commit(s), clean"), "{err}");
    assert_eq!(json(&out).as_array().unwrap().len(), 1);

    // Run 3: one new commit in the clean repo is all that gets scanned there.
    std::fs::write(clean.join("c.txt"), "more\n").unwrap();
    git(&clean, &["add", "."]);
    git(&clean, &["commit", "-q", "-m", "next"]);
    let out = run(work.path().into(), cache.clone(), state.clone())
        .await
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(err.contains("1 new commit(s), clean"), "{err}");
}
