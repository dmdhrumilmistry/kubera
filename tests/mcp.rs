//! MCP server (`kubera mcp`) over stdio.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

struct Client {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
    next: u64,
}

impl Client {
    /// Spawn `kubera <global args> mcp <mcp args>` and run the handshake.
    fn start(global: &[&str], mcp: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kubera"))
            .args(global)
            .arg("mcp")
            .args(mcp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let mut c = Self {
            child,
            stdin,
            out,
            next: 1,
        };
        let init = c.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}));
        assert_eq!(init["result"]["serverInfo"]["name"], "kubera");
        c.notify("notifications/initialized");
        c
    }

    fn notify(&mut self, method: &str) {
        writeln!(
            self.stdin,
            "{}",
            json!({"jsonrpc": "2.0", "method": method})
        )
        .unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        writeln!(
            self.stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        )
        .unwrap();
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], id);
        v
    }

    fn call(&mut self, tool: &str, args: Value) -> (Value, bool, String) {
        let r = self.request("tools/call", json!({"name": tool, "arguments": args}));
        let res = &r["result"];
        let text = res["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        (
            res["structuredContent"].clone(),
            res["isError"].as_bool().unwrap_or(false),
            text,
        )
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn token() -> String {
    format!("gh{}_{}", "p", "9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo")
}

#[test]
fn offline_server_scans_and_never_returns_raw_secrets() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.env"),
        format!("GITHUB_TOKEN={}\n", token()),
    )
    .unwrap();
    let root = dir.path().to_str().unwrap().to_string();
    let mut c = Client::start(&["--detectors", "github-token"], &[]);

    let tools = c.request("tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"scan_path") && names.contains(&"scan_image"));
    assert!(
        !names.contains(&"verify_finding"),
        "verification must be opt-in: {names:?}"
    );

    let (v, err, text) = c.call("scan_text", json!({"text": format!("x = {}", token())}));
    assert!(!err, "{text}");
    assert_eq!(v["count"], 1);
    assert!(
        !text.contains(&token()[8..]),
        "raw secret leaked to the model: {text}"
    );
    assert_eq!(v["findings"][0]["redacted"], true);

    let (v, err, text) = c.call("scan_path", json!({"path": root}));
    assert!(!err, "{text}");
    assert_eq!(v["count"], 1);

    let (_, err, text) = c.call("verify_finding", json!({"fingerprint": "x"}));
    assert!(err && text.contains("disabled"), "{text}");

    let r = c.request("bogus/method", json!({}));
    assert_eq!(r["error"]["code"], -32601);
}

#[test]
fn root_confines_path_scans() {
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut c = Client::start(&[], &["--root", allowed.path().to_str().unwrap()]);
    let (_, err, text) = c.call(
        "scan_path",
        json!({"path": outside.path().to_str().unwrap()}),
    );
    assert!(err && text.contains("outside the allowed root"), "{text}");
    let (_, err, text) = c.call(
        "scan_path",
        json!({"path": allowed.path().to_str().unwrap()}),
    );
    assert!(!err, "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_by_fingerprint_without_exposing_the_secret() {
    use wiremock::matchers::{header, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(path("/me"))
        .and(header("authorization", "Bearer mk_live_Zq8Lw2Pm9Xa1Bc4D"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"login": "alice"})))
        .mount(&server)
        .await;
    let tpl = tempfile::tempdir().unwrap();
    std::fs::write(
        tpl.path().join("mock.yaml"),
        format!(
            r#"
id: mock-key
name: Mock Key
detect:
  keywords: [mk_live_]
  patterns: [{{ name: token, regex: '\b(mk_live_[A-Za-z0-9]{{16}})\b' }}]
verify:
  request: {{ url: "{}/me", auth: {{ type: bearer, token: "{{{{ token }}}}" }} }}
  valid: {{ status: [200] }}
  extract: [{{ name: login, label: User, json: login }}]
"#,
            server.uri()
        ),
    )
    .unwrap();
    let tpl_path = tpl.path().to_str().unwrap().to_string();
    let res = tokio::task::spawn_blocking(move || {
        let mut c = Client::start(
            &["--allow-http", "--no-builtin", "-t", &tpl_path],
            &["--allow-verify"],
        );
        let (v, err, text) = c.call(
            "scan_text",
            json!({"text": "key: mk_live_Zq8Lw2Pm9Xa1Bc4D"}),
        );
        assert!(!err, "{text}");
        let fp = v["findings"][0]["fingerprint"]
            .as_str()
            .unwrap()
            .to_string();
        c.call("verify_finding", json!({"fingerprint": fp}))
    })
    .await
    .unwrap();
    let (v, err, text) = res;
    assert!(!err, "{text}");
    assert_eq!(v["status"], "verified");
    assert_eq!(v["details"]["User"], "alice");
    assert!(!text.contains("Zq8Lw2Pm9Xa1Bc4D"));
}
