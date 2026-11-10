//! Self-contained HTML report (`-f html`).
//!
//! Findings come from scanned content (paths, commit authors, API responses)
//! and must be treated as hostile. The report therefore:
//!
//! * embeds them as JSON in a non-executable `<script type="application/json">`
//!   block with `<`, `>` and `&` escaped, so no value can close the element;
//! * renders every value with `textContent` (never `innerHTML`) and only
//!   turns `https://` links into anchors;
//! * ships a Content-Security-Policy that blocks every network request and
//!   allows only its own inline script, pinned by SHA-256.
//!
//! Secrets are redacted unless the scan ran with `--show-secrets`, in which
//! case the page carries a visible warning.

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::finding::Finding;

const STYLE: &str = r#"
:root{--bg:#f7f7fb;--card:#fff;--fg:#141826;--dim:#5b6275;--line:#e3e5ee;--gold:#d99a00;--chip:#eef0f6;
--crit:#c0262d;--high:#d9480f;--med:#b7791f;--low:#2f855a;--live:#c0262d;--inv:#5b6275;--unk:#b7791f}
@media (prefers-color-scheme:dark){:root{--bg:#0b1020;--card:#121a2c;--fg:#e8ebf4;--dim:#9aa3b8;--line:#243049;
--gold:#f5b700;--chip:#1b2540;--crit:#ff6b6b;--high:#ff922b;--med:#fcc419;--low:#69db7c;--live:#ff6b6b;--inv:#9aa3b8;--unk:#fcc419}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:20px 24px;border-bottom:1px solid var(--line)}
header h1{margin:0;font-size:20px}header .meta{color:var(--dim);font-size:12px}
main{padding:16px 24px;max-width:1400px;margin:0 auto}
.warn{background:#c0262d;color:#fff;padding:10px 14px;border-radius:8px;margin-bottom:12px;font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,170px));gap:10px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;cursor:pointer;text-align:left;color:inherit;font:inherit}
.card b{display:block;font-size:22px}.card span{color:var(--dim);font-size:12px}.card.on{outline:2px solid var(--gold)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.filters input,.filters select{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit}
.filters input{flex:1;min-width:200px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;color:var(--dim);font-weight:600;background:var(--chip)}
tr.row{cursor:pointer}tr.row:hover{background:var(--chip)}
.sev,.st{display:inline-block;border-radius:999px;padding:1px 8px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low,.info{color:var(--low)}
.verified{color:var(--live)}.invalid{color:var(--inv)}.unknown{color:var(--unk)}.unverified,.unsupported{color:var(--dim)}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.loc{word-break:break-all}.dim{color:var(--dim);font-size:12px}
tr.detail td{background:var(--chip)}dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}
dt{color:var(--dim)}dd{margin:0;word-break:break-all}a{color:var(--gold)}
.empty{padding:30px;text-align:center;color:var(--dim)}
@media (max-width:700px){.hide-sm{display:none}main,header{padding:12px}}
"#;

const SCRIPT: &str = r#"
(function(){
const data=JSON.parse(document.getElementById('kubera-data').textContent);
const $=id=>document.getElementById(id);
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=String(text);return e;};
const status=f=>f.verification?f.verification.status:'unverified';
const loc=f=>{const l=f.location;let s=l.path||l.source;if(l.entry)s+='!/'+l.entry;if(l.line)s+=':'+l.line;return s;};
const sevOrder={critical:0,high:1,medium:2,low:3,info:4};
const stOrder={verified:0,unknown:1,unverified:2,unsupported:3,invalid:4};
data.sort((a,b)=>(stOrder[status(a)]-stOrder[status(b)])||(sevOrder[a.severity]-sevOrder[b.severity])||loc(a).localeCompare(loc(b)));
let stFilter='';
const cards=[['','all'],['verified','live'],['unknown','unknown'],['unverified','unverified'],['invalid','invalid']];
for(const [k,label] of cards){
  const n=k?data.filter(f=>status(f)===k).length:data.length;
  if(k&&!n)continue;
  const c=el('button','card');c.type='button';c.dataset.k=k;
  c.append(el('b',k||'',n),el('span','',label));
  c.addEventListener('click',()=>{stFilter=k;render();});
  $('cards').append(c);
}
const dets=[...new Set(data.map(f=>f.name))].sort();
for(const d of dets){const o=el('option','',d);o.value=d;$('det').append(o);}
for(const id of ['q','sev','det'])$(id).addEventListener('input',render);
function details(f){
  const dl=el('dl');
  const add=(k,v)=>{if(v==null||v==='')return;dl.append(el('dt','',k));const dd=el('dd');
    if(v instanceof Node)dd.append(v);else dd.textContent=typeof v==='object'?JSON.stringify(v):String(v);dl.append(dd);};
  const l=f.location;
  add('Detector',f.detector);add('Platform',f.platform);add('Fingerprint',f.fingerprint);
  add('Repository',l.repository);add('Commit',l.commit);
  if(l.author||l.email)add('Author',(l.author||'')+(l.email?' <'+l.email+'>':''));
  add('Date',l.date);add('Layer',l.layer);add('Decoded from',l.decoder);
  if(l.link&&/^https:\/\//.test(l.link)){const a=el('a','',l.link);a.href=l.link;a.rel='noopener noreferrer';a.target='_blank';add('Link',a);}
  for(const [k,v] of Object.entries(f.secret||{}))add('Secret '+k,el('code','',v));
  const v=f.verification;
  if(v){add('Verification',v.status);add('Message',v.message);if(v.cached)add('Cached','result from '+(v.checked_at||'an earlier run')+', no request sent');for(const [k,x] of Object.entries(v.details||{}))add(k,x);}
  return dl;
}
function render(){
  for(const c of document.querySelectorAll('.card'))c.classList.toggle('on',c.dataset.k===stFilter);
  const q=$('q').value.toLowerCase(),sev=$('sev').value,det=$('det').value;
  const rows=data.filter(f=>(!stFilter||status(f)===stFilter)&&(!sev||f.severity===sev)&&(!det||f.name===det)&&
    (!q||[f.name,f.detector,f.platform,loc(f),f.location.commit||'',f.location.author||'',f.location.repository||''].join(' ').toLowerCase().includes(q)));
  const body=$('rows');body.replaceChildren();
  $('count').textContent=rows.length+' of '+data.length;
  if(!rows.length){const tr=el('tr');const td=el('td','empty','No findings match.');td.colSpan=5;tr.append(td);body.append(tr);return;}
  for(const f of rows){
    const tr=el('tr','row');
    const s=status(f);
    const td1=el('td');td1.append(el('span','sev '+f.severity,f.severity));
    const td2=el('td');td2.append(el('div','',f.name));td2.append(el('div','dim hide-sm',f.platform));
    const td3=el('td');td3.append(el('span','st '+s,s==='verified'?'live':s));
    const td4=el('td','loc');td4.append(el('div','',loc(f)));
    if(f.location.commit)td4.append(el('div','dim',f.location.commit.slice(0,12)+(f.location.date?'  '+f.location.date:'')));
    const td5=el('td','hide-sm');td5.append(el('code','',Object.values(f.secret||{}).join('  ')));
    tr.append(td1,td2,td3,td4,td5);
    const dtr=el('tr','detail');dtr.hidden=true;const dtd=el('td');dtd.colSpan=5;dtd.append(details(f));dtr.append(dtd);
    tr.addEventListener('click',()=>{dtr.hidden=!dtr.hidden;});
    body.append(tr,dtr);
  }
}
render();
})();
"#;

const MARK: &str = r##"<svg width="34" height="34" viewBox="0 0 128 128" aria-hidden="true"><rect width="128" height="128" rx="28" fill="#0b1020"/><polygon points="28,48 46,28 82,28 100,48" fill="#ffe08a"/><polygon points="28,48 100,48 64,104" fill="#f5b700"/><polygon points="82,48 100,48 64,104" fill="#b85a00" fill-opacity="0.35"/><circle cx="64" cy="60" r="7.5" fill="#0b1020"/><polygon points="59.5,64 68.5,64 66,80 62,80" fill="#0b1020"/></svg>"##;

/// JSON that is safe inside a `<script>` element.
fn script_json(findings: &[Finding]) -> String {
    let json = serde_json::to_string(findings).unwrap_or_else(|_| "[]".into());
    json.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Render `findings` (already redacted, or not when `--show-secrets`).
pub fn render(findings: &[Finding]) -> String {
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(SCRIPT.as_bytes()));
    let csp = format!(
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; \
         script-src 'sha256-{hash}'; base-uri 'none'; form-action 'none'"
    );
    let revealed = findings.iter().any(|f| !f.redacted);
    let warn = if revealed {
        r#"<div class="warn">This report contains unredacted secrets (--show-secrets). Do not share it.</div>"#
    } else {
        ""
    };
    let generated = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");
    let version = env!("CARGO_PKG_VERSION");
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="referrer" content="no-referrer">
<title>Kubera report</title><style>{STYLE}</style></head>
<body><header>{MARK}<div><h1>Kubera report</h1><div class="meta">{n} finding(s) · generated {generated} · kubera {version}</div></div></header>
<main>{warn}<div class="cards" id="cards"></div>
<div class="filters"><input id="q" type="search" placeholder="Filter by detector, path, commit, author…" aria-label="Filter">
<select id="sev" aria-label="Severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
<select id="det" aria-label="Detector"><option value="">All detectors</option></select>
<span class="dim" id="count"></span></div>
<table><thead><tr><th>Severity</th><th>Detector</th><th>Status</th><th>Location</th><th class="hide-sm">Secret</th></tr></thead><tbody id="rows"></tbody></table>
</main>
<script id="kubera-data" type="application/json">{data}</script>
<script>{SCRIPT}</script>
</body></html>
"#,
        n = findings.len(),
        data = script_json(findings),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Location;

    #[test]
    fn hostile_values_cannot_break_out_and_csp_pins_the_script() {
        let t = crate::template::builtin()
            .unwrap()
            .into_iter()
            .find(|l| l.template.id == "github-token")
            .unwrap()
            .template;
        let mut parts = std::collections::BTreeMap::new();
        parts.insert(t.detect.patterns[0].name.clone(), "x".repeat(20));
        let f = Finding::new(
            &t,
            parts,
            Location {
                path: Some("</script><script>alert(1)</script>.env".into()),
                author: Some("<img src=x onerror=alert(1)>".into()),
                ..Default::default()
            },
        )
        .redact();
        let html = render(&[f]);
        assert_eq!(
            html.matches("</script>").count(),
            2,
            "only our own closing tags"
        );
        assert!(!html.contains("<img src=x"));
        let hash =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(SCRIPT.as_bytes()));
        assert!(html.contains(&format!("script-src 'sha256-{hash}'")));
        assert!(html.contains(&format!("<script>{SCRIPT}</script>")));
        assert!(!html.contains("unredacted"));
    }
}
