//! Findings database (`scan --db`) and the dashboard server (`serve`).

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

fn fake_github_token() -> String {
    format!("gh{}_{}", "p", "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo")
}

fn kubera(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kubera"))
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

/// Start `kubera serve`, return the child and its base URL. The caller
/// wraps the child in [`Kill`], which kills and reaps it.
#[allow(clippy::zombie_processes)]
fn serve(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (Child, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kubera"));
    cmd.arg("serve")
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(err.read_line(&mut line).unwrap() > 0, "serve exited");
        if let Some(i) = line.find("http://") {
            let url = line[i..].split_whitespace().next().unwrap().to_string();
            // Keep draining stderr so the server never writes to a closed pipe.
            std::thread::spawn(move || {
                let mut sink = String::new();
                while err.read_line(&mut sink).unwrap_or(0) > 0 {
                    sink.clear();
                }
            });
            return (child, url.trim_end_matches('/').to_string());
        }
    }
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn scans_are_recorded_redacted_and_served() {
    let dir = tempfile::tempdir().unwrap();
    let tok = fake_github_token();
    std::fs::write(dir.path().join("a.env"), format!("TOKEN={tok}\n")).unwrap();
    let db = dir.path().join("data/findings.jsonl");
    let db_arg = format!("--db={}", db.display());

    let out = kubera(
        dir.path(),
        &["scan", "fs", ".", &db_arg, "--exclude-path", "data/**"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&db).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(!text.contains(&tok[8..]), "secret stored: {text}");
    let rec: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(rec["kind"], "fs");
    assert_eq!(rec["counts"]["total"], 1);
    assert_eq!(rec["findings"][0]["path"], "./a.env");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // `db:` in the config records too; --no-db overrides it.
    std::fs::write(
        dir.path().join(".kubera.yaml"),
        "db: data/findings.jsonl\nexclude_paths: ['data/**']\n",
    )
    .unwrap();
    assert!(kubera(dir.path(), &["scan", "fs", "."]).status.success());
    assert!(
        kubera(dir.path(), &["scan", "fs", ".", "--no-db"])
            .status
            .success()
    );
    assert_eq!(std::fs::read_to_string(&db).unwrap().lines().count(), 2);
    // Fixed: the next full scan resolves it.
    std::fs::write(dir.path().join("a.env"), "TOKEN=${TOKEN}\n").unwrap();
    assert!(kubera(dir.path(), &["scan", "fs", "."]).status.success());

    let (child, base) = serve(
        dir.path(),
        &["--db", db.to_str().unwrap(), "--listen", "127.0.0.1:0"],
        &[],
    );
    let _guard = Kill(child);
    let http = reqwest::Client::builder().no_proxy().build().unwrap();

    let r = http.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let csp = r.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        csp.starts_with("default-src 'none'; script-src 'sha256-"),
        "{csp}"
    );
    assert!(csp.contains("connect-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.headers()["x-content-type-options"], "nosniff");
    let html = r.text().await.unwrap();
    assert!(html.contains("Kubera findings"));

    let f: serde_json::Value = http
        .get(format!("{base}/api/findings"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let f = f.as_array().unwrap();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0]["detector"], "github-token");
    assert_eq!(f[0]["state"], "resolved");
    assert_eq!(f[0]["times_seen"], 2);
    assert!(!serde_json::to_string(&f).unwrap().contains(&tok[8..]));
    let open: serde_json::Value = http
        .get(format!("{base}/api/findings?state=open"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(open.as_array().unwrap().is_empty());
    let scans: serde_json::Value = http
        .get(format!("{base}/api/scans"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(scans.as_array().unwrap().len(), 3);
    assert_eq!(scans[0]["counts"]["total"], 0, "newest first");
    let sum: serde_json::Value = http
        .get(format!("{base}/api/summary"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sum["resolved"], 1);

    // Read-only, and DNS rebinding is refused.
    let r = http
        .post(format!("{base}/api/findings"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);
    let r = http
        .get(format!("{base}/api/findings"))
        .header("host", "evil.example:8484")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 421);
    let r = http.get(format!("{base}/nope")).send().await.unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn remote_access_needs_opt_in_and_a_token() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("f.jsonl");
    let out = kubera(
        dir.path(),
        &[
            "serve",
            "--db",
            db.to_str().unwrap(),
            "--listen",
            "0.0.0.0:0",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--allow-remote"));
    let out = kubera(
        dir.path(),
        &[
            "serve",
            "--db",
            db.to_str().unwrap(),
            "--listen",
            "0.0.0.0:0",
            "--allow-remote",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("token"));

    let token = "dashboard-test-token-0123";
    let (child, base) = serve(
        dir.path(),
        &[
            "--db",
            db.to_str().unwrap(),
            "--listen",
            "0.0.0.0:0",
            "--allow-remote",
            "--token-env",
            "KUBERA_DASH",
        ],
        &[("KUBERA_DASH", token)],
    );
    let _guard = Kill(child);
    let base = base.replace("0.0.0.0", "127.0.0.1");
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let r = http.get(format!("{base}/api/scans")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = http
        .get(format!("{base}/api/scans"))
        .bearer_auth("wrong-token-wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = http
        .get(format!("{base}/api/scans"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "[]");

    // Sign-in link: sets an HttpOnly cookie and drops the token from the URL.
    let r = http
        .get(format!("{base}/?token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/");
    let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    let pair = cookie.split(';').next().unwrap().to_string();
    let r = http
        .get(format!("{base}/"))
        .header("cookie", pair)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = http
        .get(format!("{base}/?token=nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}
