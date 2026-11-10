//! Renders the documentation screenshots from the real TUI and CLI code.
//!
//!     cargo run --example screenshots -- docs/src/images
//!
//! The TUI is drawn into an in-memory terminal and the CLI report is
//! rendered with colours; both are converted to SVG "terminal windows".
//! All data is fake: secrets are placeholders shown redacted.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kubera::analyze;
use kubera::config::{Allowlist, Filter};
use kubera::detect::Engine;
use kubera::finding::{Finding, Location, SourceKind, Status, Verification};
use kubera::http::{Http, HttpOptions};
use kubera::report::{self, Format, Style};
use kubera::rotate;
use kubera::steps::{self, Extracted, StepResult};
use kubera::template;
use kubera::tui::app::{DetailTab, Msg, Screen};
use kubera::tui::theme::Theme;
use kubera::tui::{App, Services, ui};
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier};
use serde_json::json;

const CELL_W: f32 = 8.4;
const CELL_H: f32 = 18.0;
const FONT: &str = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', 'Liberation Mono', monospace";
const BG: (u8, u8, u8) = (13, 17, 23);
const FG: (u8, u8, u8) = (226, 232, 240);

fn services() -> Services {
    let templates = template::builtin().expect("builtin templates");
    Services {
        engine: Engine::new(templates.iter().map(|l| l.template.clone()).collect()).unwrap(),
        filter: Filter::new(&[], &Allowlist::default()).unwrap(),
        templates,
        http: Http::new(HttpOptions::default()).unwrap(),
        max_file_size: 1 << 20,
        runtime: None,
        baseline: None,
    }
}

/// A finding with placeholder secret parts: long enough to redact, never
/// token-shaped. `n` makes the parts (and so the fingerprint) unique when a
/// scene needs several findings of the same detector.
fn placeholder_finding(svc: &Services, id: &str, path: &str, line: usize, n: u8) -> Finding {
    let t = template::find(&svc.templates, id).unwrap();
    let mut parts = BTreeMap::new();
    for p in &t.detect.patterns {
        let v = if p.secret {
            format!("{}-placeholder-value-{n:04}", p.name)
        } else {
            format!("AKIAEXAMPLEPUBLICID{n}")
        };
        parts.insert(p.name.clone(), v);
    }
    Finding::new(
        t,
        parts,
        Location {
            source: SourceKind::Git,
            path: Some(path.into()),
            line,
            repository: Some("https://github.com/acme/payments.git".into()),
            commit: Some("9f3c1e7a2b4d6c8e0f1a3b5c7d9e1f2a4b6c8d0e".into()),
            author: Some("Dana Developer".into()),
            email: Some("dana@acme.example".into()),
            date: Some("2026-10-14T09:12:44Z".into()),
            link: Some(format!(
                "https://github.com/acme/payments/blob/9f3c1e7/{path}#L{line}"
            )),
            layer: None,
            ..Default::default()
        },
    )
}

fn finding(
    svc: &Services,
    id: &str,
    path: &str,
    line: usize,
    status: Option<Status>,
    details: &[(&str, &str)],
) -> Finding {
    let mut f = placeholder_finding(svc, id, path, line, 0);
    f.verification = status.map(|s| Verification {
        status: s,
        message: (s == Status::Invalid).then(|| "HTTP 401: Bad credentials".to_string()),
        details: details
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect(),
    });
    f
}

fn verification(status: Status, message: Option<String>, details: &[(&str, &str)]) -> Verification {
    Verification {
        status,
        message,
        details: details
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect(),
    }
}

/// A typical first run: a handful of findings, then `V` (verify all). The
/// verdicts are what the platforms answer; messages are built the way
/// `verify` builds them.
fn verify_scene(svc: &Services) -> Vec<(Finding, Verification)> {
    let aws_rejected = format!(
        "HTTP 403: {}",
        kubera::http::snippet(
            r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>InvalidClientTokenId</Code>
  <Message>The security token included in the request is invalid.</Message></Error>
</ErrorResponse>"#
        )
    );
    vec![
        (
            placeholder_finding(svc, "aws-access-key", "deploy/terraform.tfvars", 12, 0),
            verification(
                Status::Verified,
                None,
                &[
                    ("ARN", "arn:aws:iam::123456789012:user/ci-deployer"),
                    ("Account", "123456789012"),
                    ("IAM user", "ci-deployer"),
                ],
            ),
        ),
        (
            placeholder_finding(svc, "figma-pat", "design/export-icons.js", 8, 1),
            verification(
                Status::Invalid,
                Some(format!(
                    "HTTP 403: {}",
                    kubera::http::snippet(r#"{"status":403,"err":"Invalid token"}"#)
                )),
                &[],
            ),
        ),
        (
            placeholder_finding(svc, "aws-access-key", "scripts/backup.sh", 5, 2),
            verification(Status::Invalid, Some(aws_rejected.clone()), &[]),
        ),
        (
            placeholder_finding(svc, "aws-access-key", "ci/legacy-pipeline.yml", 31, 3),
            verification(Status::Invalid, Some(aws_rejected), &[]),
        ),
        (
            placeholder_finding(svc, "slack-webhook", ".github/workflows/notify.yml", 22, 4),
            verification(
                Status::Unknown,
                Some(format!(
                    "unexpected response (status 429 not in [400]): {}",
                    kubera::http::snippet("rate_limited")
                )),
                &[],
            ),
        ),
        (
            placeholder_finding(svc, "private-key", "certs/staging.pem", 1, 5),
            verification(
                Status::Unsupported,
                Some("template has no verifier".into()),
                &[],
            ),
        ),
    ]
}

/// The dry-run plan `kubera rotate` (and `p` in the TUI) shows, rendered by
/// the same request code. The SigV4 timestamp is pinned so regenerated
/// images do not change on every run.
fn rotation_plan(svc: &Services, f: &Finding) -> rotate::Report {
    let t = template::find(&svc.templates, &f.detector).unwrap();
    let r = t.rotate.as_ref().expect("detector has rotation");
    let secrets: Vec<String> = f.secret.values().cloned().collect();
    let mut vars = kubera::verify::secret_vars(&f.secret);
    let mut plan = Vec::new();
    for s in &r.steps {
        let request = steps::describe(&svc.http.prepare(&s.request, &vars).unwrap(), &secrets)
            .lines()
            .map(|l| {
                if l.trim_start().starts_with("x-amz-date:") {
                    "  x-amz-date: 20261014T101951Z".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        plan.push(rotate::PlannedStep {
            name: s.name.clone(),
            description: s.description.clone(),
            request,
        });
        for e in &s.extract {
            vars.insert(e.name.clone(), format!("<{} from {}>", e.name, s.name));
        }
    }
    rotate::Report {
        detector: t.id.clone(),
        executed: false,
        verification: f.verification.clone().unwrap(),
        instructions: r.instructions.clone(),
        plan,
        steps: Vec::new(),
        completed: false,
        outputs: BTreeMap::new(),
        stores: Vec::new(),
    }
}

fn key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn demo_findings(svc: &Services) -> Vec<Finding> {
    vec![
        finding(
            svc,
            "aws-access-key",
            "deploy/terraform.tfvars",
            12,
            Some(Status::Verified),
            &[
                ("ARN", "arn:aws:iam::123456789012:user/ci-deployer"),
                ("Account", "123456789012"),
                ("IAM user", "ci-deployer"),
            ],
        ),
        finding(
            svc,
            "github-token",
            "scripts/release.sh",
            4,
            Some(Status::Invalid),
            &[],
        ),
        finding(
            svc,
            "stripe-secret-key",
            "api/config/settings.py",
            41,
            None,
            &[],
        ),
        finding(
            svc,
            "slack-webhook",
            ".github/workflows/notify.yml",
            22,
            None,
            &[],
        ),
        finding(
            svc,
            "private-key",
            "certs/staging.pem",
            1,
            Some(Status::Unsupported),
            &[],
        ),
    ]
}

fn aws_analysis(f: &Finding) -> analyze::Report {
    let v = |name: &str, label: &str, value: serde_json::Value| Extracted {
        name: name.into(),
        label: label.into(),
        value,
        secret: false,
    };
    analyze::Report {
        detector: f.detector.clone(),
        name: f.name.clone(),
        platform: f.platform.clone(),
        verification: f.verification.clone().unwrap(),
        notes: Some("Read-only IAM calls signed with the leaked key.".into()),
        steps: vec![
            StepResult {
                name: "attached_policies".into(),
                description: "Managed policies attached to the user".into(),
                ok: true,
                http_status: Some(200),
                error: None,
                values: vec![v(
                    "policies",
                    "Policies",
                    json!(["AdministratorAccess", "AmazonS3FullAccess"]),
                )],
            },
            StepResult {
                name: "groups".into(),
                description: "Groups the user belongs to".into(),
                ok: true,
                http_status: Some(200),
                error: None,
                values: vec![v("groups", "Groups", json!(["deployers"]))],
            },
            StepResult {
                name: "access_keys".into(),
                description: "All access keys of the user".into(),
                ok: true,
                http_status: Some(200),
                error: None,
                values: vec![
                    v("key_ids", "Access keys", json!(["AKIAEXAMPLEPUBLICID0"])),
                    v("key_status", "Status", json!(["Active"])),
                ],
            },
            StepResult {
                name: "get_user".into(),
                description: "IAM user that owns the key".into(),
                ok: false,
                http_status: Some(403),
                error: Some("status 403 not in [200]: AccessDenied".into()),
                values: vec![],
            },
        ],
    }
}

// ----- SVG rendering ------------------------------------------------------

fn hex((r, g, b): (u8, u8, u8)) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const ANSI16: [(u8, u8, u8); 16] = [
    (13, 17, 23),
    (248, 81, 73),
    (63, 185, 80),
    (210, 153, 34),
    (88, 166, 255),
    (188, 140, 255),
    (57, 197, 207),
    (201, 209, 217),
    (110, 118, 129),
    (255, 123, 114),
    (86, 211, 100),
    (227, 179, 65),
    (121, 192, 255),
    (210, 168, 255),
    (86, 212, 221),
    (240, 246, 252),
];

fn xterm256(n: u8) -> (u8, u8, u8) {
    match n {
        0..=15 => ANSI16[n as usize],
        16..=231 => {
            let n = n - 16;
            let lvl = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            (lvl(n / 36), lvl((n / 6) % 6), lvl(n % 6))
        }
        _ => {
            let g = 8 + (n - 232) * 10;
            (g, g, g)
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
struct Cell {
    fg: (u8, u8, u8),
    bg: Option<(u8, u8, u8)>,
    bold: bool,
    dim: bool,
    underline: bool,
}

/// A grid of styled cells, the common format for both sources.
struct Grid {
    rows: Vec<Vec<(String, Cell)>>,
    width: usize,
}

fn ratatui_color(c: Color) -> Option<(u8, u8, u8)> {
    Some(match c {
        Color::Reset => return None,
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Indexed(i) => xterm256(i),
        Color::Black => ANSI16[0],
        Color::Red => ANSI16[1],
        Color::Green => ANSI16[2],
        Color::Yellow => ANSI16[3],
        Color::Blue => ANSI16[4],
        Color::Magenta => ANSI16[5],
        Color::Cyan => ANSI16[6],
        Color::Gray => ANSI16[7],
        Color::DarkGray => ANSI16[8],
        Color::LightRed => ANSI16[9],
        Color::LightGreen => ANSI16[10],
        Color::LightYellow => ANSI16[11],
        Color::LightBlue => ANSI16[12],
        Color::LightMagenta => ANSI16[13],
        Color::LightCyan => ANSI16[14],
        Color::White => ANSI16[15],
    })
}

fn grid_from_app(app: &App, w: u16, h: u16) -> Grid {
    let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| ui::draw(f, app, &Theme::with_truecolor(true)))
        .unwrap();
    let buf = term.backend().buffer().clone();
    let mut rows = Vec::new();
    for y in 0..h {
        let mut row = Vec::new();
        for x in 0..w {
            let c = &buf[(x, y)];
            let reversed = c.modifier.contains(Modifier::REVERSED);
            let mut fg = ratatui_color(c.fg).unwrap_or(FG);
            let mut bg = ratatui_color(c.bg);
            if reversed {
                let b = bg.unwrap_or(BG);
                bg = Some(fg);
                fg = b;
            }
            row.push((
                c.symbol().to_string(),
                Cell {
                    fg,
                    bg,
                    bold: c.modifier.contains(Modifier::BOLD),
                    dim: c.modifier.contains(Modifier::DIM),
                    underline: c.modifier.contains(Modifier::UNDERLINED),
                },
            ));
        }
        rows.push(row);
    }
    Grid {
        rows,
        width: w as usize,
    }
}

/// Minimal SGR parser (the subset kubera emits).
fn grid_from_ansi(text: &str, width: usize) -> Grid {
    let default = Cell {
        fg: FG,
        bg: None,
        bold: false,
        dim: false,
        underline: false,
    };
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut row = Vec::new();
        let mut cur = default;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                let mut code = String::new();
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                    code.push(c);
                }
                let nums: Vec<u16> = code.split(';').filter_map(|n| n.parse().ok()).collect();
                let mut i = 0;
                if nums.is_empty() {
                    cur = default;
                }
                while i < nums.len() {
                    match nums[i] {
                        0 => cur = default,
                        1 => cur.bold = true,
                        2 => cur.dim = true,
                        4 => cur.underline = true,
                        30..=37 => cur.fg = ANSI16[(nums[i] - 30) as usize],
                        90..=97 => cur.fg = ANSI16[(nums[i] - 82) as usize],
                        40..=47 => cur.bg = Some(ANSI16[(nums[i] - 40) as usize]),
                        100..=107 => cur.bg = Some(ANSI16[(nums[i] - 92) as usize]),
                        38 | 48 if nums.get(i + 1) == Some(&5) => {
                            let c = xterm256(*nums.get(i + 2).unwrap_or(&7) as u8);
                            if nums[i] == 38 {
                                cur.fg = c
                            } else {
                                cur.bg = Some(c)
                            }
                            i += 2;
                        }
                        38 | 48 if nums.get(i + 1) == Some(&2) => {
                            let g = |k: usize| *nums.get(i + k).unwrap_or(&0) as u8;
                            let c = (g(2), g(3), g(4));
                            if nums[i] == 38 {
                                cur.fg = c
                            } else {
                                cur.bg = Some(c)
                            }
                            i += 4;
                        }
                        _ => {}
                    }
                    i += 1;
                }
            } else {
                row.push((ch.to_string(), cur));
            }
        }
        while row.len() < width {
            row.push((" ".into(), default));
        }
        row.truncate(width);
        rows.push(row);
    }
    Grid { rows, width }
}

fn dimmed(c: (u8, u8, u8)) -> (u8, u8, u8) {
    let m = |v: u8, b: u8| ((v as u16 + b as u16) / 2) as u8;
    (m(c.0, BG.0), m(c.1, BG.1), m(c.2, BG.2))
}

fn svg(grid: &Grid, title: &str) -> String {
    let pad = 16.0;
    let bar = 34.0;
    let w = grid.width as f32 * CELL_W + pad * 2.0;
    let h = grid.rows.len() as f32 * CELL_H + pad * 2.0 + bar;
    let mut out = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0}" height="{h:.0}" viewBox="0 0 {w:.0} {h:.0}" role="img" aria-label="{t}">
<rect width="100%" height="100%" rx="10" fill="{bg}"/>
<rect x="0.5" y="0.5" width="{w1:.0}" height="{h1:.0}" rx="10" fill="none" stroke="#30363d"/>
<circle cx="20" cy="17" r="6" fill="#ff5f57"/><circle cx="40" cy="17" r="6" fill="#febc2e"/><circle cx="60" cy="17" r="6" fill="#28c840"/>
<text x="{cx:.0}" y="21" fill="#8b949e" font-family="{FONT}" font-size="12" text-anchor="middle">{t}</text>
<g font-family="{FONT}" font-size="14" xml:space="preserve">
"##,
        bg = hex(BG),
        w1 = w - 1.0,
        h1 = h - 1.0,
        cx = w / 2.0,
        t = xml(title),
    );
    for (y, row) in grid.rows.iter().enumerate() {
        let top = pad + bar + y as f32 * CELL_H;
        // Backgrounds, merged into runs.
        let mut x = 0;
        while x < row.len() {
            if let Some(bg) = row[x].1.bg {
                let start = x;
                while x < row.len() && row[x].1.bg == Some(bg) {
                    x += 1;
                }
                out.push_str(&format!(
                    r#"<rect x="{:.1}" y="{:.1}" width="{:.1}" height="{CELL_H}" fill="{}"/>"#,
                    pad + start as f32 * CELL_W,
                    top,
                    (x - start) as f32 * CELL_W,
                    hex(bg)
                ));
            } else {
                x += 1;
            }
        }
        // Block elements and vertical rules as solid shapes, so they join
        // up the way they do in a real terminal (glyphs leave gaps).
        for (cx, (sym, st)) in row.iter().enumerate() {
            let fg = hex(if st.dim { dimmed(st.fg) } else { st.fg });
            let x0 = pad + cx as f32 * CELL_W;
            let (half_w, half_h) = (CELL_W / 2.0, CELL_H / 2.0);
            let rect = |x: f32, y: f32, w: f32, h: f32| {
                format!(
                    r#"<rect x="{x:.1}" y="{y:.1}" width="{w:.1}" height="{h:.1}" fill="{fg}"/>"#
                )
            };
            let shape = match sym.as_str() {
                "█" => rect(x0, top, CELL_W, CELL_H),
                "▀" => rect(x0, top, CELL_W, half_h),
                "▄" => rect(x0, top + half_h, CELL_W, half_h),
                "▌" => rect(x0, top, half_w, CELL_H),
                "▐" => rect(x0 + half_w, top, half_w, CELL_H),
                "│" => rect(x0 + half_w - 0.6, top, 1.2, CELL_H),
                _ => continue,
            };
            out.push_str(&shape);
        }
        // Text, merged into runs of identical style.
        let mut x = 0;
        while x < row.len() {
            if matches!(row[x].0.as_str(), "█" | "▀" | "▄" | "▌" | "▐" | "│") {
                x += 1;
                continue;
            }
            let style = row[x].1;
            let start = x;
            let mut text = String::new();
            while x < row.len()
                && row[x].1 == style
                && !matches!(row[x].0.as_str(), "█" | "▀" | "▄" | "▌" | "▐" | "│")
            {
                text.push_str(&row[x].0);
                x += 1;
            }
            // Position each run by cell index and size it to its visible
            // glyphs only, so whitespace never stretches the text.
            let lead = text.chars().take_while(|c| *c == ' ').count();
            let body = text.trim_matches(' ');
            if body.is_empty() {
                continue;
            }
            let start = start + lead;
            let text = body.to_string();
            let x = start + text.chars().count();
            let fg = if style.dim {
                dimmed(style.fg)
            } else {
                style.fg
            };
            // One <text> per word at its exact cell: renderers collapse runs
            // of spaces inside a text node, which would distort alignment.
            let mut attrs = format!(r#" fill="{}""#, hex(fg));
            if style.bold {
                attrs.push_str(r#" font-weight="bold""#);
            }
            if style.underline {
                attrs.push_str(r#" text-decoration="underline""#);
            }
            let _ = x;
            let mut word = String::new();
            let mut word_start = start;
            for (col, ch) in (start..).zip(text.chars().chain(std::iter::once(' '))) {
                if ch == ' ' {
                    if !word.is_empty() {
                        out.push_str(&format!(
                            r#"<text x="{:.1}" y="{:.1}" textLength="{:.1}" lengthAdjust="spacingAndGlyphs"{attrs}>{}</text>"#,
                            pad + word_start as f32 * CELL_W,
                            top + CELL_H * 0.78,
                            word.chars().count() as f32 * CELL_W,
                            xml(&word)
                        ));
                        word.clear();
                    }
                    word_start = col + 1;
                } else {
                    if word.is_empty() {
                        word_start = col;
                    }
                    word.push(ch);
                }
            }
        }
        out.push('\n');
    }
    out.push_str("</g>\n</svg>\n");
    out
}

fn write(dir: &Path, name: &str, data: String) {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    println!("wrote {}", p.display());
}

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "docs/src/images".into()),
    );
    std::fs::create_dir_all(&dir).unwrap();

    // TUI: home screen.
    let app = App::new(services());
    write(
        &dir,
        "tui-home.svg",
        svg(&grid_from_app(&app, 104, 28), "kubera"),
    );

    // TUI: results with the overview of a live AWS key.
    let svc = services();
    let findings = demo_findings(&svc);
    let mut app = App::new(svc);
    app.set_results(findings, "https://github.com/acme/payments.git".into());
    write(
        &dir,
        "tui-results.svg",
        svg(&grid_from_app(&app, 120, 34), "kubera tui"),
    );

    // TUI: analysis tab.
    let rep = aws_analysis(app.current().unwrap());
    let fp = app.current().unwrap().fingerprint.clone();
    app.analyses.insert(fp, rep);
    app.tab = DetailTab::Analysis;
    write(
        &dir,
        "tui-analysis.svg",
        svg(&grid_from_app(&app, 120, 34), "kubera tui - analysis"),
    );

    // TUI: phone-width layout (Termux).
    app.tab = DetailTab::Overview;
    app.screen = Screen::Results;
    write(
        &dir,
        "tui-phone.svg",
        svg(&grid_from_app(&app, 50, 44), "Termux"),
    );

    // TUI: after `V` (verify all) - live, invalid, unknown and unverifiable
    // findings, the status line with the totals, and an invalid finding
    // selected so its Verification section shows the platform's answer.
    // Triage writes `.kubera-baseline.json` to the current directory, so
    // these scenes run in a scratch directory and are written afterwards.
    let scratch = tempfile::tempdir().unwrap();
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(scratch.path()).unwrap();
    let mut shots = Vec::new();
    let mut svc = services();
    svc.baseline = Some(PathBuf::from(kubera::baseline::DEFAULT_FILE));
    let scene = verify_scene(&svc);
    let mut app = App::new(svc);
    app.set_results(
        scene.iter().map(|(f, _)| f.clone()).collect(),
        "https://github.com/acme/payments.git".into(),
    );
    app.on_key(key('V'));
    for (f, v) in &scene {
        app.on_msg(Msg::Verified(f.fingerprint.clone(), v.clone()));
    }
    app.on_key(key('j'));
    shots.push((
        "tui-verified.svg",
        svg(
            &grid_from_app(&app, 120, 34),
            "kubera tui - after verification",
        ),
    ));

    // TUI: `m` on the invalid Figma token: saved as an accepted risk, gone
    // from the list, the next finding selected.
    app.on_key(key('m'));
    shots.push((
        "tui-triage.svg",
        svg(&grid_from_app(&app, 120, 34), "kubera tui - triage"),
    ));

    // TUI: `p` on the live AWS key: the dry-run rotation plan.
    app.on_key(key('g'));
    app.on_key(key('p'));
    let plan = rotation_plan(&services(), app.current().unwrap());
    let fp = app.current().unwrap().fingerprint.clone();
    app.on_msg(Msg::Plan(fp, Ok(plan)));
    shots.push((
        "tui-rotation.svg",
        svg(&grid_from_app(&app, 120, 36), "kubera tui - rotation plan"),
    ));
    std::env::set_current_dir(cwd).unwrap();
    drop(scratch);
    for (name, data) in shots {
        write(&dir, name, data);
    }

    // CLI: banner + report cards + summary, with colours.
    let svc = services();
    let shown: Vec<Finding> = demo_findings(&svc)
        .iter()
        .take(3)
        .map(Finding::redact)
        .collect();
    let st = Style { color: true };
    let mut buf = Vec::new();
    report::write_findings(&mut buf, &shown, Format::Pretty, &st).unwrap();
    let text = format!(
        "\x1b[38;5;250m$\x1b[0m kubera scan git https://github.com/acme/payments.git --verify\n{}\x1b[2m› cloning https://github.com/acme/payments.git\x1b[0m\n\n{}{}\n",
        kubera::brand::banner_colored(true),
        String::from_utf8(buf).unwrap(),
        report::summary(&shown, &st)
    );
    let width = 90;
    write(
        &dir,
        "cli-scan.svg",
        svg(&grid_from_ansi(&text, width), "kubera scan"),
    );
}
