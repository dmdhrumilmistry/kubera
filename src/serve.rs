//! `kubera serve`: a local web dashboard over the findings database.
//!
//! * Binds to `127.0.0.1` by default. A non-loopback address needs
//!   `--allow-remote` **and** a token (`--token-env`); requests then need
//!   `Authorization: Bearer <token>` or the cookie set by `/?token=...`.
//! * Loopback mode checks the `Host` header, so a web page in the browser
//!   cannot read the API through DNS rebinding.
//! * GET / HEAD only, no state is changed, the database is read again when
//!   the file changes.
//! * The page is self-contained: a strict Content-Security-Policy allows
//!   only its own script and style (pinned by SHA-256) and requests to its
//!   own origin. Every value is rendered with `textContent`.
//!
//! API: `/api/findings` (filters: `state`, `status`, `detector`,
//! `repository`, `q`), `/api/scans`, `/api/summary`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::db;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8484";
const COOKIE: &str = "kubera_token";

pub struct Options {
    pub db: PathBuf,
    pub listen: SocketAddr,
    pub allow_remote: bool,
    pub token: Option<String>,
}

/// Check the bind policy before anything listens.
pub fn check(o: &Options) -> Result<()> {
    if let Some(t) = &o.token
        && t.len() < 16
    {
        bail!("the dashboard token must be at least 16 characters");
    }
    if !o.listen.ip().is_loopback() {
        if !o.allow_remote {
            bail!(
                "refusing to listen on {}: the dashboard binds to localhost only. Pass --allow-remote and --token-env to expose it",
                o.listen
            );
        }
        if o.token.is_none() {
            bail!("--allow-remote needs a token: pass --token-env <ENV_VAR>");
        }
    }
    Ok(())
}

type Cache = Option<(u64, Option<SystemTime>, Arc<Computed>)>;

struct Computed {
    findings: Value,
    scans: Value,
    summary: Value,
    agg: db::Aggregate,
}

struct State {
    o: Options,
    page: String,
    csp: String,
    cache: Mutex<Cache>,
}

impl State {
    fn data(&self) -> Result<Arc<Computed>> {
        let meta = std::fs::metadata(&self.o.db).ok();
        let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime = meta.as_ref().and_then(|m| m.modified().ok());
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((l, m, c)) = cache.as_ref()
            && *l == len
            && *m == mtime
        {
            return Ok(c.clone());
        }
        let (scans, bad) = db::load(&self.o.db)?;
        let agg = db::aggregate(&scans, bad);
        let c = Arc::new(Computed {
            findings: serde_json::to_value(&agg.findings)?,
            scans: serde_json::to_value(&agg.scans)?,
            summary: summary(&agg),
            agg,
        });
        *cache = Some((len, mtime, c.clone()));
        Ok(c)
    }
}

fn summary(a: &db::Aggregate) -> Value {
    let count = |p: &dyn Fn(&db::FindingView) -> bool| a.findings.iter().filter(|f| p(f)).count();
    let mut by_repo: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    let mut by_det: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    for f in a.findings.iter().filter(|f| f.state == "open") {
        let live = usize::from(f.status == "live");
        for r in &f.repositories {
            let e = by_repo.entry(r).or_default();
            e.0 += 1;
            e.1 += live;
        }
        let e = by_det.entry(&f.name).or_default();
        e.0 += 1;
        e.1 += live;
    }
    let rows = |m: std::collections::BTreeMap<&str, (usize, usize)>| {
        let mut v: Vec<Value> = m
            .into_iter()
            .map(|(k, (open, live))| json!({"name": k, "open": open, "live": live}))
            .collect();
        v.sort_by_key(|x| std::cmp::Reverse(x["open"].as_u64()));
        v
    };
    json!({
        "findings": a.findings.len(),
        "open": count(&|f| f.state == "open"),
        "open_live": count(&|f| f.state == "open" && f.status == "live"),
        "resolved": count(&|f| f.state == "resolved"),
        "triaged": count(&|f| f.state == "triaged"),
        "scans": a.scans.len(),
        "last_scan": a.scans.first().map(|s| s.time.clone()),
        "skipped_lines": a.skipped_lines,
        "by_repository": rows(by_repo),
        "by_detector": rows(by_det),
    })
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn header<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

fn authorized(st: &State, req: &Request<Incoming>) -> bool {
    let Some(tok) = &st.o.token else { return true };
    if let Some(b) = header(req, "authorization").and_then(|h| h.strip_prefix("Bearer "))
        && ct_eq(b.trim().as_bytes(), tok.as_bytes())
    {
        return true;
    }
    header(req, "cookie").is_some_and(|c| {
        c.split(';').any(|kv| {
            kv.trim()
                .strip_prefix(COOKIE)
                .and_then(|r| r.strip_prefix('='))
                .is_some_and(|v| ct_eq(v.as_bytes(), tok.as_bytes()))
        })
    })
}

/// Loopback mode: only `Host: localhost / 127.0.0.1 / [::1]` (DNS
/// rebinding protection).
fn host_ok(st: &State, req: &Request<Incoming>) -> bool {
    if !st.o.listen.ip().is_loopback() {
        return true;
    }
    let Some(h) = header(req, "host") else {
        return false;
    };
    let name = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        h.rsplit_once(':').map(|(n, _)| n).unwrap_or(h)
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn resp(st: &State, status: StatusCode, ctype: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = status;
    let h = r.headers_mut();
    let set = |h: &mut hyper::HeaderMap, k: &'static str, v: &str| {
        if let Ok(v) = hyper::header::HeaderValue::from_str(v) {
            h.insert(k, v);
        }
    };
    set(h, "content-type", ctype);
    set(h, "cache-control", "no-store");
    set(h, "x-content-type-options", "nosniff");
    set(h, "referrer-policy", "no-referrer");
    set(h, "x-frame-options", "DENY");
    set(h, "cross-origin-resource-policy", "same-origin");
    if ctype.starts_with("text/html") {
        set(h, "content-security-policy", &st.csp);
    } else {
        set(
            h,
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        );
    }
    r
}

fn text(st: &State, status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    resp(
        st,
        status,
        "text/plain; charset=utf-8",
        msg.as_bytes().to_vec(),
    )
}

fn query(req: &Request<Incoming>) -> Vec<(String, String)> {
    let q = req.uri().query().unwrap_or_default();
    reqwest::Url::parse(&format!("http://x/?{q}"))
        .map(|u| {
            u.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

/// `/api/findings` with optional filters.
fn filtered(a: &db::Aggregate, q: &[(String, String)]) -> Result<Value> {
    let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let needle = get("q").map(str::to_lowercase);
    let rows: Vec<&db::FindingView> = a
        .findings
        .iter()
        .filter(|f| get("state").is_none_or(|s| f.state == s))
        .filter(|f| get("status").is_none_or(|s| f.status == s))
        .filter(|f| get("detector").is_none_or(|s| f.detector == s))
        .filter(|f| get("repository").is_none_or(|s| f.repositories.iter().any(|r| r == s)))
        .filter(|f| {
            needle.as_ref().is_none_or(|n| {
                [&f.name, &f.detector, &f.fingerprint, &f.platform]
                    .iter()
                    .any(|v| v.to_lowercase().contains(n))
                    || f.repositories.iter().any(|r| r.to_lowercase().contains(n))
                    || f.locations.iter().any(|l| {
                        l.path
                            .as_deref()
                            .is_some_and(|p| p.to_lowercase().contains(n))
                    })
            })
        })
        .collect();
    Ok(serde_json::to_value(rows)?)
}

async fn handle(st: Arc<State>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    if !host_ok(&st, &req) {
        return text(
            &st,
            StatusCode::MISDIRECTED_REQUEST,
            "unexpected Host header\n",
        );
    }
    let head = req.method() == hyper::Method::HEAD;
    if req.method() != hyper::Method::GET && !head {
        return text(&st, StatusCode::METHOD_NOT_ALLOWED, "read-only\n");
    }
    let path = req.uri().path().to_string();
    let q = query(&req);
    // `/?token=...`: check it, set an HttpOnly cookie and drop the token
    // from the address bar.
    if path == "/"
        && let Some(t) = q.iter().find(|(k, _)| k == "token").map(|(_, v)| v.clone())
    {
        let ok =
            st.o.token
                .as_ref()
                .is_some_and(|tok| ct_eq(t.as_bytes(), tok.as_bytes()));
        if !ok {
            return text(&st, StatusCode::UNAUTHORIZED, "invalid token\n");
        }
        let mut r = text(&st, StatusCode::SEE_OTHER, "");
        r.headers_mut()
            .insert("location", hyper::header::HeaderValue::from_static("/"));
        if let Ok(v) = hyper::header::HeaderValue::from_str(&format!(
            "{COOKIE}={t}; HttpOnly; SameSite=Strict; Path=/"
        )) {
            r.headers_mut().insert("set-cookie", v);
        }
        return r;
    }
    if !authorized(&st, &req) {
        return text(
            &st,
            StatusCode::UNAUTHORIZED,
            "token required: open /?token=<token>, or send Authorization: Bearer <token>\n",
        );
    }
    let mut r = match path.as_str() {
        "/" | "/index.html" => resp(
            &st,
            StatusCode::OK,
            "text/html; charset=utf-8",
            st.page.clone().into_bytes(),
        ),
        "/favicon.ico" => text(&st, StatusCode::NO_CONTENT, ""),
        "/api/findings" | "/api/scans" | "/api/summary" => match st.data() {
            Err(e) => text(&st, StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}\n")),
            Ok(d) => {
                let v = match path.as_str() {
                    "/api/findings" if q.is_empty() => Ok(d.findings.clone()),
                    "/api/findings" => filtered(&d.agg, &q),
                    "/api/scans" => Ok(d.scans.clone()),
                    _ => Ok(d.summary.clone()),
                };
                match v.and_then(|v| Ok(serde_json::to_vec(&v)?)) {
                    Ok(b) => resp(&st, StatusCode::OK, "application/json", b),
                    Err(e) => text(&st, StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}\n")),
                }
            }
        },
        _ => text(&st, StatusCode::NOT_FOUND, "not found\n"),
    };
    if head {
        *r.body_mut() = Full::new(Bytes::new());
    }
    r
}

/// Serve until Ctrl-C. `on_listen` gets the bound address (port 0 picks a
/// free one).
pub async fn serve(o: Options, on_listen: impl FnOnce(SocketAddr)) -> Result<()> {
    check(&o)?;
    let listener = tokio::net::TcpListener::bind(o.listen)
        .await
        .with_context(|| format!("listening on {}", o.listen))?;
    on_listen(listener.local_addr()?);
    let state = Arc::new(State {
        page: page(),
        csp: csp(),
        cache: Mutex::new(None),
        o,
    });
    loop {
        tokio::select! {
            r = listener.accept() => {
                let Ok((stream, _)) = r else { continue };
                let st = state.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let st = st.clone();
                        async move { Ok::<_, Infallible>(handle(st, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(10))
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                        .await;
                });
            }
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

fn sha(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(s.as_bytes()))
}

pub fn csp() -> String {
    format!(
        "default-src 'none'; script-src 'sha256-{}'; style-src 'sha256-{}'; connect-src 'self'; \
         img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        sha(SCRIPT),
        sha(STYLE)
    )
}

pub fn page() -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Kubera dashboard</title><style>{STYLE}</style></head>
<body>
<header>{MARK}<div><h1>Kubera findings</h1><div class="meta" id="meta">Loading…</div></div></header>
<main>
<div class="filters" role="search">
<label><span>Range</span><select id="range"><option value="7">Last 7 days</option><option value="30" selected>Last 30 days</option><option value="90">Last 90 days</option><option value="0">All time</option></select></label>
<label><span>Repository</span><select id="repo"><option value="">All repositories</option></select></label>
<label><span>Detector</span><select id="det"><option value="">All detectors</option></select></label>
<label><span>State</span><select id="state"><option value="open" selected>Open</option><option value="">Any state</option><option value="resolved">Resolved</option><option value="triaged">Triaged</option></select></label>
<label><span>Status</span><select id="status"><option value="">Any status</option><option value="live">Live</option><option value="unknown">Unknown</option><option value="unverified">Not verified</option><option value="unsupported">Not verifiable</option><option value="invalid">Invalid</option></select></label>
<label class="grow"><span>Search</span><input id="q" type="search" placeholder="Detector, path, repository, fingerprint…"></label>
</div>
<section class="tiles" id="tiles"></section>
<section class="card"><div class="card-h"><h2>Reported findings over time</h2><div class="legend" id="legend"></div></div>
<p class="sub" id="trend-sub"></p><div class="chart" id="chart" tabindex="0" aria-label="Reported and live findings per day"></div><div class="tip" id="tip" hidden></div></section>
<section class="two"><div class="card"><h2>Open findings by repository</h2><div class="bars" id="by-repo"></div></div>
<div class="card"><h2>Open findings by detector</h2><div class="bars" id="by-det"></div></div></section>
<section class="card"><div class="card-h"><h2>Findings</h2><span class="sub" id="count"></span></div>
<div class="scroll"><table><thead><tr><th>Severity</th><th>Finding</th><th>Status</th><th class="hide-sm">State</th><th class="hide-sm">Repository / location</th><th class="hide-sm">First seen</th><th class="hide-sm">Last seen</th><th class="hide-sm num">Seen</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<section class="card"><div class="card-h"><h2>Recent scans</h2><button type="button" class="more" id="more" hidden>Show all</button></div><div class="scroll"><table><thead><tr><th>Time</th><th>Target</th><th class="hide-sm">Kind</th><th class="num">Findings</th><th class="num">Live</th><th class="num hide-sm">New</th></tr></thead><tbody id="scans"></tbody></table></div></section>
</main>
<script>{SCRIPT}</script>
</body></html>
"#
    )
}

const MARK: &str = r##"<svg width="34" height="34" viewBox="0 0 128 128" aria-hidden="true"><rect width="128" height="128" rx="28" fill="#0b1020"/><polygon points="28,48 46,28 82,28 100,48" fill="#ffe08a"/><polygon points="28,48 100,48 64,104" fill="#f5b700"/><polygon points="82,48 100,48 64,104" fill="#b85a00" fill-opacity="0.35"/><circle cx="64" cy="60" r="7.5" fill="#0b1020"/><polygon points="59.5,64 68.5,64 66,80 62,80" fill="#0b1020"/></svg>"##;

const STYLE: &str = r#"
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;
--ring:rgba(11,11,11,.10);--wash:rgba(11,11,11,.04);--s1:#2a78d6;--s2:#eb6834;--crit:#d03b3b;--good:#0ca30c;--warn:#fab219;--gold:#b97f00}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;
--axis:#383835;--ring:rgba(255,255,255,.10);--wash:rgba(255,255,255,.05);--s1:#3987e5;--s2:#d95926;--gold:#f5b700}}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:16px 24px;border-bottom:1px solid var(--ring);background:var(--surface)}
h1{margin:0;font-size:19px}h2{margin:0 0 8px;font-size:15px}.meta,.sub{color:var(--ink2);font-size:12px}.sub{margin:0 0 6px}
main{padding:16px 24px 40px;max-width:1400px;margin:0 auto;display:grid;gap:14px}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end}
.filters label{display:flex;flex-direction:column;gap:2px;font-size:11px;color:var(--ink2)}.filters .grow{flex:1;min-width:200px}
select,input{background:var(--surface);color:var(--ink);border:1px solid var(--axis);border-radius:8px;padding:7px 9px;font:inherit;font-size:13px;min-width:0;max-width:100%}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.tile{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:10px 14px}
.tile b{display:block;font-size:26px;font-weight:650;line-height:1.2}.tile span{color:var(--ink2);font-size:12px;display:flex;align-items:center;gap:6px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
.card{background:var(--surface);border:1px solid var(--ring);border-radius:12px;padding:14px 16px;min-width:0;position:relative}
.card-h{display:flex;justify-content:space-between;align-items:baseline;gap:10px;flex-wrap:wrap}
.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.legend{display:flex;gap:14px;font-size:12px;color:var(--ink2)}.legend span{display:flex;align-items:center;gap:6px}
.key{width:14px;height:2px;border-radius:1px;display:inline-block}
.chart{width:100%;height:240px;outline:none}.chart:focus-visible{outline:2px solid var(--s1);outline-offset:2px;border-radius:6px}
.chart svg{display:block;width:100%;height:100%;overflow:visible}
.chart text{fill:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}.chart .lab{fill:var(--ink2);font-weight:600}
.tip{position:absolute;pointer-events:none;background:var(--surface);border:1px solid var(--ring);box-shadow:0 4px 14px rgba(0,0,0,.12);border-radius:8px;padding:6px 10px;font-size:12px;min-width:120px;z-index:2}
.tip div{display:flex;align-items:center;gap:6px}.tip b{font-size:13px}.tip .d{color:var(--ink2);margin-bottom:2px}
.bars{display:grid;gap:2px}.bar{display:grid;grid-template-columns:minmax(80px,38%) 1fr;align-items:center;gap:10px;padding:4px 6px;border-radius:6px;cursor:pointer;border:0;background:none;color:inherit;font:inherit;text-align:left;width:100%}
.bar:hover,.bar:focus-visible,.bar.on{background:var(--wash)}.bar .n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.bar .t{display:flex;align-items:center;gap:8px;min-width:0}.bar i{display:block;height:14px;background:var(--s1);border-radius:0 4px 4px 0;min-width:2px}
.bar .v{font-size:12px;color:var(--ink2);white-space:nowrap;font-variant-numeric:tabular-nums}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse}
th,td{padding:7px 8px;border-bottom:1px solid var(--grid);text-align:left;vertical-align:top}th{font-size:12px;color:var(--ink2);font-weight:600}
.num{text-align:right;font-variant-numeric:tabular-nums}tr.row{cursor:pointer}tr.row:hover td{background:var(--wash)}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:12px;white-space:nowrap}
.sev{font-size:12px;font-weight:600;text-transform:capitalize}
.critical,.high{color:var(--crit)}.medium{color:var(--ink)}.low,.info{color:var(--ink2)}
code.show-sm{display:none;word-break:normal;overflow-wrap:anywhere}code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.dim{color:var(--ink2);font-size:12px}
td.loc{word-break:break-all;max-width:420px}tr.detail td{background:var(--wash)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--ink2)}dd{margin:0;word-break:break-all}
a{color:var(--s1)}.more{background:none;border:1px solid var(--axis);color:var(--ink2);border-radius:8px;padding:4px 10px;font:inherit;font-size:12px;cursor:pointer}.more:hover{background:var(--wash)}
.empty{padding:24px;text-align:center;color:var(--ink2)}
@media (max-width:760px){.two{grid-template-columns:1fr}.hide-sm{display:none}.show-sm{display:block!important}main{padding:12px 12px 32px}header{padding:12px}
.filters label{flex:1 1 calc(50% - 8px)}.bar{grid-template-columns:1fr;gap:3px}.filters .grow{flex-basis:100%}.chart{height:200px}.tile b{font-size:22px}}
"#;

const SCRIPT: &str = r#"
(function(){
'use strict';
const $=id=>document.getElementById(id);
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=String(text);return e;};
const NS='http://www.w3.org/2000/svg';
const sv=(tag,attrs)=>{const e=document.createElementNS(NS,tag);for(const k in attrs)e.setAttribute(k,String(attrs[k]));return e;};
const css=v=>getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const STATUS={live:['Live','--crit'],unknown:['Unknown','--warn'],unverified:['Not verified','--muted'],unsupported:['Not verifiable','--muted'],invalid:['Invalid','--good']};
const STATE={open:'Open',resolved:'Resolved',triaged:'Triaged'};
let F=[],S=[],scansAll=false;
const day=t=>t.slice(0,10);
const short=r=>r.replace(/^[a-z]+:\/\//,'').replace(/\.git$/,'');
const fmtDay=d=>new Date(d+'T00:00:00Z').toLocaleDateString(undefined,{month:'short',day:'numeric',timeZone:'UTC'});
const fmtTime=t=>t.replace('T',' ').replace('Z',' UTC');
const nf=new Intl.NumberFormat();
function badge(st){const [label,color]=STATUS[st]||[st,'--muted'];const b=el('span','badge');const d=el('span','dot');d.style.background=css(color);b.append(d,el('span','',label));return b;}
function loc(f){const l=f.locations[0]||{};let s=l.path||'';if(l.line)s+=':'+l.line;return s;}
function filters(){return{range:+$('range').value,repo:$('repo').value,det:$('det').value,state:$('state').value,status:$('status').value,q:$('q').value.trim().toLowerCase()};}
function entityMatch(f,o){
  if(o.repo&&!f.repositories.includes(o.repo))return false;
  if(o.det&&f.detector!==o.det)return false;
  if(o.q){const hay=[f.name,f.detector,f.fingerprint,f.platform,...f.repositories,...f.locations.map(l=>l.path||'')].join(' ').toLowerCase();if(!hay.includes(o.q))return false;}
  return true;}
function sinceDay(o){if(!o.range)return '';const d=new Date();d.setUTCDate(d.getUTCDate()-o.range+1);return d.toISOString().slice(0,10);}
function tiles(rows,o){
  const t=$('tiles');t.replaceChildren();
  const ent=F.filter(f=>entityMatch(f,o));
  const from=sinceDay(o);
  const scans=S.filter(s=>!from||day(s.time)>=from);
  const items=[['Open',ent.filter(f=>f.state==='open').length,null],['Open live',ent.filter(f=>f.state==='open'&&f.status==='live').length,'--crit'],
    ['Resolved',ent.filter(f=>f.state==='resolved').length,'--good'],['Triaged',ent.filter(f=>f.state==='triaged').length,null],
    ['New in range',ent.filter(f=>!from||day(f.first_seen)>=from).length,null],['Scans in range',scans.length,null]];
  for(const [label,n,color] of items){const c=el('div','tile');c.append(el('b','',nf.format(n)));const s=el('span');if(color){const d=el('span','dot');d.style.background=css(color);s.append(d);}s.append(document.createTextNode(label));c.append(s);t.append(c);}
}
function trend(o){
  const keep=new Set(F.filter(f=>entityMatch(f,o)).map(f=>f.fingerprint));
  const chrono=[...S].reverse();
  if(!chrono.length){$('chart').replaceChildren(el('div','empty','No scans recorded yet.'));return;}
  const today=new Date().toISOString().slice(0,10);
  let start=sinceDay(o)||day(chrono[0].time);
  const days=[];for(let d=new Date(start+'T00:00:00Z');d.toISOString().slice(0,10)<=today;d.setUTCDate(d.getUTCDate()+1))days.push(d.toISOString().slice(0,10));
  const per=new Map(),status=new Map();let i=0;const pts=[];
  for(const d of days){
    while(i<chrono.length&&day(chrono[i].time)<=d){const s=chrono[i++];
      const set=s.incremental?(per.get(s.target)||new Set()):new Set();for(const fp of s.fingerprints)set.add(fp);per.set(s.target,set);
      if(s.verified){const live=new Set(s.live);for(const fp of s.fingerprints)status.set(fp,live.has(fp));}else{for(const fp of s.live)status.set(fp,true);}}
    const all=new Set();for(const set of per.values())for(const fp of set)if(keep.has(fp))all.add(fp);
    let live=0;for(const fp of all)if(status.get(fp))live++;
    pts.push({d,total:all.size,live});
  }
  $('trend-sub').textContent='Per day: findings reported by the latest scan of each target (carried forward until the next scan), and how many of them verified live.';
  draw(pts);
}
let lastPts=[];
function draw(pts){
  lastPts=pts;const box=$('chart');box.replaceChildren();
  const W=Math.max(box.clientWidth,280),H=box.clientHeight||240,m={l:40,r:44,t:12,b:24};
  const svg=sv('svg',{viewBox:`0 0 ${W} ${H}`,role:'img'});
  const max=Math.max(1,...pts.map(p=>p.total));
  const step=nice(max/4);const top=Math.ceil(max/step)*step;
  const x=i=>m.l+(pts.length<2?(W-m.l-m.r)/2:i*(W-m.l-m.r)/(pts.length-1));
  const y=v=>H-m.b-(v/top)*(H-m.t-m.b);
  for(let v=0;v<=top;v+=step){svg.append(sv('line',{x1:m.l,x2:W-m.r,y1:y(v),y2:y(v),stroke:css(v===0?'--axis':'--grid'),'stroke-width':1}));
    const t=sv('text',{x:m.l-8,y:y(v)+4,'text-anchor':'end'});t.textContent=nf.format(v);svg.append(t);}
  const n=pts.length,every=Math.max(1,Math.ceil(n/Math.max(2,Math.floor((W-m.l-m.r)/70))));
  pts.forEach((p,i)=>{if(i%every===0||i===n-1){if(i!==n-1&&n-1-i<every*0.6)return;const t=sv('text',{x:x(i),y:H-6,'text-anchor':i===0?'start':i===n-1?'end':'middle'});t.textContent=fmtDay(p.d);svg.append(t);}});
  const series=[['total','--s1','Reported'],['live','--s2','Live']];
  const lg=$('legend');lg.replaceChildren();
  for(const [k,c,label] of series){
    const s=el('span');const key=el('span','key');key.style.background=css(c);s.append(key,document.createTextNode(label));lg.append(s);
    const d=pts.map((p,i)=>(i?'L':'M')+x(i).toFixed(1)+' '+y(p[k]).toFixed(1)).join(' ');
    svg.append(sv('path',{d,fill:'none',stroke:css(c),'stroke-width':2,'stroke-linejoin':'round','stroke-linecap':'round'}));
    const last=pts[n-1];svg.append(sv('circle',{cx:x(n-1),cy:y(last[k]),r:4,fill:css(c),stroke:css('--surface'),'stroke-width':2}));
  }
  const last=pts[n-1];const ly=[y(last.total),y(last.live)];if(Math.abs(ly[0]-ly[1])<14){ly[0]-=7;ly[1]+=7;}
  [[last.total,ly[0]],[last.live,ly[1]]].forEach(([v,yy])=>{const t=sv('text',{x:W-m.r+8,y:yy+4,class:'lab'});t.textContent=nf.format(v);svg.append(t);});
  const cross=sv('line',{y1:m.t,y2:H-m.b,stroke:css('--axis'),'stroke-width':1,visibility:'hidden'});svg.append(cross);
  const marks=series.map(([k,c])=>{const d=sv('circle',{r:4,fill:css(c),stroke:css('--surface'),'stroke-width':2,visibility:'hidden'});svg.append(d);return [k,d];});
  const hit=sv('rect',{x:m.l,y:0,width:Math.max(1,W-m.l-m.r),height:H,fill:'transparent'});svg.append(hit);
  box.append(svg);
  const tip=$('tip');let cur=-1;
  const show=i=>{cur=i;const p=pts[i];cross.setAttribute('x1',x(i));cross.setAttribute('x2',x(i));cross.setAttribute('visibility','visible');for(const [k,d] of marks){d.setAttribute('cx',x(i));d.setAttribute('cy',y(p[k]));d.setAttribute('visibility','visible');}
    tip.replaceChildren(el('div','d',fmtDay(p.d)));for(const [k,c,label] of series){const r=el('div');const key=el('span','key');key.style.background=css(c);r.append(key,el('b','',nf.format(p[k])),el('span','dim',label));tip.append(r);}
    tip.hidden=false;const bx=box.getBoundingClientRect(),cx=box.offsetLeft+x(i)*bx.width/W;
    const left=Math.min(Math.max(cx+12,box.offsetLeft),box.offsetLeft+bx.width-tip.offsetWidth);tip.style.left=(cx+12+tip.offsetWidth>box.offsetLeft+bx.width?cx-12-tip.offsetWidth:left)+'px';tip.style.top=(box.offsetTop+bx.height-tip.offsetHeight-30)+'px';};
  const hide=()=>{cur=-1;cross.setAttribute('visibility','hidden');for(const [,d] of marks)d.setAttribute('visibility','hidden');tip.hidden=true;};
  hit.addEventListener('pointermove',e=>{const r=box.getBoundingClientRect();const px=(e.clientX-r.left)*W/r.width;let best=0,bd=1e9;pts.forEach((p,i)=>{const dd=Math.abs(x(i)-px);if(dd<bd){bd=dd;best=i;}});show(best);});
  hit.addEventListener('pointerleave',hide);
  box.onkeydown=e=>{if(e.key==='ArrowRight'||e.key==='ArrowLeft'){e.preventDefault();show(Math.min(n-1,Math.max(0,(cur<0?n-1:cur)+(e.key==='ArrowRight'?1:-1))));}else if(e.key==='Escape')hide();};
  box.onblur=hide;
}
function nice(v){if(v<=1)return 1;const p=Math.pow(10,Math.floor(Math.log10(v)));const f=v/p;return (f<=1?1:f<=2?2:f<=5?5:10)*p;}
function bars(id,rows,key,o){
  const box=$(id);box.replaceChildren();
  const m=new Map();
  for(const f of rows){const live=f.status==='live'?1:0;const keys=key==='repo'?f.repositories:[f.detector];for(const k of keys){const e=m.get(k)||{open:0,live:0,label:key==='repo'?short(k):f.name};e.open++;e.live+=live;m.set(k,e);}}
  const list=[...m.entries()].sort((a,b)=>b[1].open-a[1].open||a[0].localeCompare(b[0])).slice(0,10);
  if(!list.length){box.append(el('div','empty','No open findings.'));return;}
  const max=list[0][1].open;
  for(const [k,e] of list){
    const b=el('button','bar');b.type='button';const sel=key==='repo'?o.repo:o.det;if(sel===k)b.classList.add('on');
    b.title=e.label+': '+e.open+' open, '+e.live+' live';
    const n=el('span','n',e.label);const t=el('span','t');const i=el('i');i.style.width=Math.max(1,e.open/max*100)*0.8+'%';
    t.append(i,el('span','v',nf.format(e.open)+(e.live?'  ('+nf.format(e.live)+' live)':'')));b.append(n,t);
    b.addEventListener('click',()=>{const s=$(key==='repo'?'repo':'det');s.value=s.value===k?'':k;render();});
    box.append(b);
  }
}
function details(f){
  const dl=el('dl');const add=(k,v)=>{if(v==null||v==='')return;dl.append(el('dt','',k));const dd=el('dd');if(v instanceof Node)dd.append(v);else dd.textContent=String(v);dl.append(dd);};
  add('Fingerprint',el('code','',f.fingerprint));add('Detector',f.detector);add('Platform',f.platform);add('Secret (redacted)',el('code','',f.preview));
  add('Decision',f.decision);add('Targets',f.targets.join(', '));add('Seen in',f.times_seen+' scan(s), first '+fmtTime(f.first_seen)+', last '+fmtTime(f.last_seen));
  const ul=el('div');for(const l of f.locations.slice(0,15)){const d=el('div');let s=(l.repository?l.repository+'  ':'')+(l.path||'')+(l.line?':'+l.line:'');if(l.commit)s+='  @'+l.commit.slice(0,12);d.append(el('code','',s));
    if(l.link&&/^https:\/\//.test(l.link)){const a=el('a','',' view');a.href=l.link;a.rel='noopener noreferrer';a.target='_blank';d.append(a);}ul.append(d);}
  if(f.locations.length>15)ul.append(el('div','dim','… '+(f.locations.length-15)+' more'));add('Locations',ul);return dl;}
function table(rows){
  const body=$('rows');body.replaceChildren();$('count').textContent=nf.format(rows.length)+' of '+nf.format(F.length);
  if(!rows.length){const tr=el('tr');const td=el('td','empty','No findings match these filters.');td.colSpan=8;tr.append(td);body.append(tr);return;}
  for(const f of rows.slice(0,500)){
    const tr=el('tr','row');tr.tabIndex=0;
    const c=(cls,child)=>{const td=el('td',cls);if(child instanceof Node)td.append(child);else td.textContent=child;return td;};
    const name=el('div');name.append(el('div','',f.name),el('div','dim',f.detector),el('code','dim show-sm',short(f.repositories[0]||'')+' '+loc(f)));
    const where=el('div');where.append(el('div','',short(f.repositories[0]||'')),el('code','dim',loc(f)));
    tr.append(c('',el('span','sev '+f.severity,f.severity)),c('',name),c('',badge(f.status)),c('hide-sm',STATE[f.state]||f.state),c('loc hide-sm',where),
      c('hide-sm dim',fmtTime(f.first_seen).slice(0,16)),c('hide-sm dim',fmtTime(f.last_seen).slice(0,16)),c('num hide-sm',nf.format(f.times_seen)));
    const dtr=el('tr','detail');dtr.hidden=true;const dtd=el('td');dtd.colSpan=8;dtd.append(details(f));dtr.append(dtd);
    const toggle=()=>{dtr.hidden=!dtr.hidden;};tr.addEventListener('click',toggle);tr.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}});
    body.append(tr,dtr);}
  if(rows.length>500){const tr=el('tr');const td=el('td','dim','Showing the first 500; narrow the filters to see the rest.');td.colSpan=8;tr.append(td);body.append(tr);}
}
function scans(o){
  const body=$('scans');body.replaceChildren();const from=sinceDay(o);
  const rows=S.filter(s=>(!from||day(s.time)>=from)&&(!o.repo||s.target===o.repo||F.some(f=>f.repositories.includes(o.repo)&&f.targets.includes(s.target))));
  const all=rows.length;const shown=scansAll?rows:rows.slice(0,15);$('more').hidden=all<=15;$('more').textContent=scansAll?'Show fewer':'Show all '+nf.format(all);
  if(!rows.length){const tr=el('tr');const td=el('td','empty','No scans in this range.');td.colSpan=6;tr.append(td);body.append(tr);return;}
  for(const s of shown){const tr=el('tr');const c=(cls,t)=>{const td=el('td',cls);td.textContent=t;return td;};
    tr.append(c('dim',fmtTime(s.time).slice(0,16)),c('loc',short(s.target)+(s.incremental?'  (incremental)':'')),c('hide-sm',s.kind),c('num',nf.format(s.counts.total)),c('num',s.verified?nf.format(s.counts.live):'-'),c('num hide-sm',nf.format(s.new)));body.append(tr);}
}
function render(){
  const o=filters();
  const rows=F.filter(f=>entityMatch(f,o)&&(!o.state||f.state===o.state)&&(!o.status||f.status===o.status));
  tiles(rows,o);trend(o);
  const open=F.filter(f=>f.state==='open'&&(!o.status||f.status===o.status));
  bars('by-repo',open.filter(f=>entityMatch(f,{...o,repo:''})),'repo',o);
  bars('by-det',open.filter(f=>entityMatch(f,{...o,det:''})),'det',o);
  table(rows);scans(o);
}
function options(){
  const add=(id,vals)=>{const s=$(id);for(const [v,l] of vals){const op=el('option','',l);op.value=v;s.append(op);}};
  add('repo',[...new Set(F.flatMap(f=>f.repositories))].sort().map(r=>[r,short(r)]));
  const dets=new Map();for(const f of F)dets.set(f.detector,f.name);add('det',[...dets.entries()].sort((a,b)=>a[1].localeCompare(b[1])));
}
async function load(){
  const get=async u=>{const r=await fetch(u,{credentials:'same-origin',headers:{accept:'application/json'}});if(!r.ok)throw new Error(u+': HTTP '+r.status);return r.json();};
  try{const [f,s,sum]=await Promise.all([get('/api/findings'),get('/api/scans'),get('/api/summary')]);F=f;S=s;
    $('meta').textContent=nf.format(sum.scans)+' scan(s) recorded'+(sum.last_scan?' · last '+fmtTime(sum.last_scan):'')+' · secrets are redacted';
    options();render();}
  catch(e){$('meta').textContent='Could not load data: '+e.message;}
}
for(const id of ['range','repo','det','state','status'])$(id).addEventListener('change',render);
$('q').addEventListener('input',render);
$('more').addEventListener('click',()=>{scansAll=!scansAll;render();});
let rt;window.addEventListener('resize',()=>{clearTimeout(rt);rt=setTimeout(()=>{if(lastPts.length)draw(lastPts);},120);});
matchMedia('(prefers-color-scheme: dark)').addEventListener('change',render);
load();
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_binds_need_opt_in_and_a_token() {
        let o = |listen: &str, allow: bool, token: Option<&str>| Options {
            db: PathBuf::from("x"),
            listen: listen.parse().unwrap(),
            allow_remote: allow,
            token: token.map(str::to_string),
        };
        assert!(check(&o("127.0.0.1:0", false, None)).is_ok());
        assert!(check(&o("[::1]:0", false, None)).is_ok());
        assert!(check(&o("0.0.0.0:8484", false, None)).is_err());
        assert!(check(&o("0.0.0.0:8484", true, None)).is_err());
        assert!(check(&o("0.0.0.0:8484", true, Some("short"))).is_err());
        assert!(check(&o("0.0.0.0:8484", true, Some("a-long-enough-token"))).is_ok());
    }

    #[test]
    fn csp_pins_the_inline_script_and_style() {
        let p = page();
        let c = csp();
        assert!(p.contains(&format!("<script>{SCRIPT}</script>")));
        assert!(p.contains(&format!("<style>{STYLE}</style>")));
        assert!(c.contains(&format!("'sha256-{}'", sha(SCRIPT))));
        assert!(!SCRIPT.contains("innerHTML"));
        assert!(
            !p.contains("http://") || p.matches("http://").count() == 1,
            "no external assets"
        );
        assert!(!p.contains("https://"));
    }
}
