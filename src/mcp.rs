//! Model Context Protocol server (`kubera mcp`): lets AI assistants scan
//! code, repositories and images for leaked secrets.
//!
//! Transport: JSON-RPC 2.0, one message per line on stdin/stdout (MCP stdio).
//! Logs go to stderr.
//!
//! Security model:
//! * **Secrets never reach the model.** Tools return redacted findings and
//!   fingerprints; raw values stay in this process. Follow-up tools
//!   (`verify_finding`, `analyze_finding`, `rotation_plan`) take a
//!   fingerprint, not a secret.
//! * **Network calls with secrets are opt-in** (`--allow-verify`): without
//!   it those tools are not even listed.
//! * **No credential parameters.** The model cannot pass tokens or names of
//!   environment variables (a prompt-injected request could otherwise send a
//!   credential to a host of its choosing). Git auth is configured when the
//!   server starts.
//! * **Rotation is plan-only** (dry run); executing stays a human CLI step.
//! * `--root` confines filesystem scans to one directory tree.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::config::Filter;
use crate::detect::Engine;
use crate::finding::Finding;
use crate::http::Http;
use crate::scan::{self, Target};
use crate::sources::git::GitOptions;
use crate::sources::remote::Auth;
use crate::template::{Loaded, Template};

const PROTOCOL: &str = "2025-06-18";

pub struct Options {
    pub allow_verify: bool,
    pub root: Option<PathBuf>,
    pub git_auth: Auth,
    pub max_file_size: u64,
    pub allow_http: bool,
    /// Verification results reused across runs (`--verify-cache`).
    pub verify_cache: Option<crate::verify_cache::Cache>,
}

pub struct Server {
    engine: Engine,
    filter: Filter,
    templates: Vec<Loaded>,
    http: Http,
    opts: Options,
    /// Raw findings by fingerprint (never sent to the client).
    findings: HashMap<String, Finding>,
}

fn tool(name: &str, description: &str, props: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": props, "required": required},
    })
}

impl Server {
    pub fn new(
        engine: Engine,
        filter: Filter,
        templates: Vec<Loaded>,
        http: Http,
        opts: Options,
    ) -> Self {
        Self {
            engine,
            filter,
            templates,
            http,
            opts,
            findings: HashMap::new(),
        }
    }

    fn tools(&self) -> Vec<Value> {
        let verify_note = if self.opts.allow_verify {
            "Set verify=true to check each secret with its issuing platform."
        } else {
            "Live verification is disabled on this server."
        };
        let mut t = vec![
            tool(
                "scan_path",
                &format!(
                    "Scan files or a directory for leaked secrets. Returns redacted findings with fingerprints. {verify_note}"
                ),
                json!({"path": {"type": "string", "description": "File or directory"},
                       "verify": {"type": "boolean", "default": false}}),
                &["path"],
            ),
            tool(
                "scan_git",
                &format!(
                    "Scan the full history of a git repository (local path, https/ssh URL or github.com/org/repo), including secrets deleted in later commits. {verify_note}"
                ),
                json!({"repo": {"type": "string"},
                       "branch": {"type": "string"},
                       "since_commit": {"type": "string", "description": "Only scan commits after this one"},
                       "max_depth": {"type": "integer", "description": "Maximum commits"},
                       "verify": {"type": "boolean", "default": false}}),
                &["repo"],
            ),
            tool(
                "scan_image",
                &format!(
                    "Scan a container image (registry reference such as alpine:3.20 or ghcr.io/org/app:tag, or a docker-save/OCI tarball path): every layer plus ENV/history. {verify_note}"
                ),
                json!({"image": {"type": "string"},
                       "platform": {"type": "string", "default": "linux/amd64"},
                       "verify": {"type": "boolean", "default": false}}),
                &["image"],
            ),
            tool(
                "scan_text",
                "Scan a snippet of text (config, log, diff) for secrets.",
                json!({"text": {"type": "string"}}),
                &["text"],
            ),
            tool(
                "list_detectors",
                "List the secret detectors and what each can verify, analyze and rotate.",
                json!({}),
                &[],
            ),
        ];
        if self.opts.allow_verify {
            t.push(tool(
                "verify_finding",
                "Check with the issuing platform whether a previously found secret is live. Takes the finding's fingerprint; the secret itself is never exposed. When the server runs with a verification cache, a recent result may be returned with cached=true (no request sent); set fresh=true to ask the platform again.",
                json!({"fingerprint": {"type": "string"},
                       "fresh": {"type": "boolean", "default": false}}),
                &["fingerprint"],
            ));
            t.push(tool(
                "analyze_finding",
                "Read-only analysis of a found credential: owner, scopes and reachable resources.",
                json!({"fingerprint": {"type": "string"}}),
                &["fingerprint"],
            ));
            t.push(tool(
                "rotation_plan",
                "Dry-run rotation plan and manual runbook for a found credential. Nothing is changed.",
                json!({"fingerprint": {"type": "string"}}),
                &["fingerprint"],
            ));
        }
        t
    }

    fn template(&self, id: &str) -> Option<Arc<Template>> {
        self.engine
            .detectors
            .iter()
            .find(|d| d.template.id == id)
            .map(|d| d.template.clone())
    }

    fn confine(&self, p: &str) -> Result<PathBuf> {
        let path = std::fs::canonicalize(p).with_context(|| format!("{p} does not exist"))?;
        if let Some(root) = &self.opts.root {
            let root = std::fs::canonicalize(root)?;
            if !path.starts_with(&root) {
                bail!("{p} is outside the allowed root {}", root.display());
            }
        }
        Ok(path)
    }

    async fn finish(&mut self, mut findings: Vec<Finding>, verify: bool) -> Result<Value> {
        if verify {
            if !self.opts.allow_verify {
                bail!("verification is disabled on this server (start it with --allow-verify)");
            }
            let map = self
                .engine
                .detectors
                .iter()
                .map(|d| (d.template.id.clone(), d.template.clone()))
                .collect();
            let cache = self.opts.verify_cache.as_ref();
            crate::verify::verify_findings(&self.http, &map, &mut findings, 8, cache).await;
            self.save_cache();
        }
        let shown: Vec<Finding> = findings.iter().map(Finding::redact).collect();
        for f in findings {
            self.findings.insert(f.fingerprint.clone(), f);
        }
        Ok(json!({"count": shown.len(), "findings": shown}))
    }

    async fn call(&mut self, name: &str, args: &Value) -> Result<Value> {
        let s = |k: &str| args.get(k).and_then(Value::as_str).map(str::to_string);
        let verify = args.get("verify").and_then(Value::as_bool).unwrap_or(false);
        match name {
            "scan_path" => {
                let p = self.confine(&s("path").context("path is required")?)?;
                let target = Target::Paths(vec![p]);
                let f = self.run(target)?;
                self.finish(f, verify).await
            }
            "scan_git" => {
                let repo = s("repo").context("repo is required")?;
                let is_remote = matches!(crate::sources::remote::parse(&repo), Ok(Some(_)));
                let repo = if is_remote {
                    repo
                } else {
                    self.confine(&repo)?.display().to_string()
                };
                let target = Target::Git {
                    repo,
                    options: GitOptions {
                        branch: s("branch"),
                        since_commit: s("since_commit"),
                        max_depth: args.get("max_depth").and_then(Value::as_u64).map(|n| n as usize),
                        ..Default::default()
                    },
                    auth: self.opts.git_auth.clone(),
                    baseline: None,
                    mirror: None,
                };
                let f = self.run(target)?;
                self.finish(f, verify).await
            }
            "scan_image" => {
                use crate::sources::image;
                let reference = s("image").context("image is required")?;
                let platform = s("platform").unwrap_or_else(|| "linux/amd64".into());
                let img = if Path::new(&reference).is_file() {
                    image::open_archive(&self.confine(&reference)?, &platform)?
                } else {
                    image::pull(
                        &reference,
                        &image::PullOptions {
                            platform,
                            allow_http: self.opts.allow_http,
                            ..Default::default()
                        },
                    )
                    .await?
                };
                let f = self.run(Target::Image(Arc::new(img)))?;
                self.finish(f, verify).await
            }
            "scan_text" => {
                let text = s("text").context("text is required")?;
                let f = self.run(Target::Text(text))?;
                self.finish(f, false).await
            }
            "list_detectors" => Ok(json!(
                self.templates
                    .iter()
                    .map(|l| {
                        let t = &l.template;
                        json!({
                            "id": t.id, "name": t.name, "platform": t.platform,
                            "severity": t.severity, "verify": t.verify.is_some(),
                            "analyze": t.analyze.is_some(),
                            "rotate": t.rotate.as_ref().map(|r| if r.steps.is_empty() { "manual" } else { "api" }),
                        })
                    })
                    .collect::<Vec<_>>()
            )),
            "verify_finding" | "analyze_finding" | "rotation_plan" => {
                if !self.opts.allow_verify {
                    bail!("this tool is disabled (start the server with --allow-verify)");
                }
                let fp = s("fingerprint").context("fingerprint is required")?;
                let f = self
                    .findings
                    .get(&fp)
                    .cloned()
                    .context("unknown fingerprint; scan first")?;
                let t = self.template(&f.detector).context("detector not loaded")?;
                match name {
                    "verify_finding" => {
                        let fresh = args.get("fresh").and_then(Value::as_bool).unwrap_or(false);
                        let cache = self.opts.verify_cache.as_ref();
                        let v =
                            crate::verify::verify_cached(&self.http, &t, &f.secret, cache, fresh)
                                .await;
                        self.save_cache();
                        Ok(serde_json::to_value(v)?)
                    }
                    "analyze_finding" => {
                        let rep = crate::analyze::analyze(&self.http, &t, &f.secret, false).await;
                        Ok(serde_json::to_value(rep.redacted())?)
                    }
                    _ => {
                        let opts = crate::rotate::Options {
                            execute: false,
                            force: false,
                            inputs: Default::default(),
                        };
                        let rep = crate::rotate::rotate(&self.http, &t, &f.secret, &opts).await?;
                        Ok(serde_json::to_value(rep)?)
                    }
                }
            }
            other => bail!("unknown tool `{other}`"),
        }
    }

    fn save_cache(&self) {
        if let Some(c) = &self.opts.verify_cache
            && let Err(e) = c.save()
        {
            eprintln!("warning: {e:#}");
        }
    }

    fn run(&self, target: Target) -> Result<Vec<Finding>> {
        tokio::task::block_in_place(|| {
            scan::run(
                &self.engine,
                &self.filter,
                &target,
                self.opts.max_file_size,
                &|_| {},
            )
        })
    }

    async fn handle(&mut self, msg: Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let method = msg
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        // Notifications (no id) get no response.
        let id = id?;
        let result: Result<Value> = match method {
            "initialize" => Ok(json!({
                "protocolVersion": msg["params"]["protocolVersion"].as_str().unwrap_or(PROTOCOL),
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "kubera", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Secret scanning. Findings are redacted; follow-up tools take fingerprints. Never ask the user to paste secrets.",
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": self.tools()})),
            "tools/call" => {
                let name = msg["params"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let args = msg["params"]["arguments"].clone();
                return Some(match self.call(&name, &args).await {
                    Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": {
                        "content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}],
                        "structuredContent": if v.is_object() { v.clone() } else { json!({"result": v}) },
                        "isError": false
                    }}),
                    // Tool failures are results, so the model can see them.
                    Err(e) => json!({"jsonrpc": "2.0", "id": id, "result": {
                        "content": [{"type": "text", "text": format!("error: {e:#}")}],
                        "isError": true
                    }}),
                });
            }
            other => Err(anyhow::anyhow!("method not found: {other}")),
        };
        Some(match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err(e) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": e.to_string()}})
            }
        })
    }

    /// Serve until stdin closes.
    pub async fn serve(mut self) -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        eprintln!(
            "kubera mcp: ready ({} detectors, verification {})",
            self.engine.detectors.len(),
            if self.opts.allow_verify {
                "enabled"
            } else {
                "disabled"
            }
        );
        while let Some(line) = rx.recv().await {
            if line.trim().is_empty() {
                continue;
            }
            let reply = match serde_json::from_str::<Value>(&line) {
                Ok(msg) => self.handle(msg).await,
                Err(e) => Some(json!({"jsonrpc": "2.0", "id": null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")}})),
            };
            if let Some(r) = reply {
                let mut out = std::io::stdout().lock();
                serde_json::to_writer(&mut out, &r)?;
                out.write_all(b"\n")?;
                out.flush()?;
            }
        }
        Ok(())
    }
}
