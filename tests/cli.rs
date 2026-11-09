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
