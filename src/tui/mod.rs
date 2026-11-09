//! Interactive terminal UI (`kubera tui`, or `kubera` with no arguments).
//!
//! Screens: home menu → target input → live scan progress → findings
//! browser (verify, analyze, rotation plan, reveal, filter, export) and a
//! detector catalogue. Network work runs on the tokio runtime and scanning
//! on a worker thread; both report back over a channel so the UI never
//! blocks.

pub mod app;
pub mod theme;
pub mod ui;

use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyEventKind};

pub use app::{App, Services};
use theme::Theme;

/// Where the TUI starts.
#[allow(clippy::large_enum_variant)] // constructed once
pub enum Start {
    Home,
    Scan(crate::scan::Target, String),
    Results(Vec<crate::finding::Finding>, String),
}

/// Run the TUI until the user quits. Must be called from a multi-threaded
/// tokio runtime context (network work is spawned onto it).
pub fn run(svc: Services, start: Start) -> Result<()> {
    run_with(svc, start, false)
}

/// Like [`run`]; `verify_after_scan` verifies findings when a scan ends.
pub fn run_with(svc: Services, start: Start, verify_after_scan: bool) -> Result<()> {
    let theme = Theme::detect();
    let mut app = App::new(svc);
    app.verify_after_scan = verify_after_scan;
    match start {
        Start::Home => {}
        Start::Scan(target, label) => {
            app.results_back = None;
            app.start_scan(target, label);
        }
        Start::Results(findings, label) => {
            app.results_back = None;
            app.set_results(findings, label);
        }
    }
    // `init` installs a panic hook that restores the terminal.
    let mut terminal = ratatui::init();
    let result = (|| -> Result<()> {
        while !app.should_quit {
            terminal.draw(|f| ui::draw(f, &app, &theme))?;
            if event::poll(Duration::from_millis(80))?
                && let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
            {
                app.on_key(k);
            }
            while let Ok(m) = app.rx.try_recv() {
                app.on_msg(m);
            }
            app.tick = app.tick.wrapping_add(1);
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::app::{InputKind, Screen, StatusFilter};
    use super::*;
    use crate::config::{Allowlist, Filter};
    use crate::detect::Engine;
    use crate::finding::{Finding, Location, SourceKind, Status, Verification};
    use crate::http::{Http, HttpOptions};
    use crate::template;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::collections::BTreeMap;

    fn services() -> Services {
        let templates = template::builtin().unwrap();
        Services {
            engine: Engine::new(templates.iter().map(|l| l.template.clone()).collect()).unwrap(),
            filter: Filter::new(&[], &Allowlist::default()).unwrap(),
            templates,
            http: Http::new(HttpOptions::default()).unwrap(),
            max_file_size: 1 << 20,
            runtime: None,
        }
    }

    fn finding(svc: &Services, id: &str, path: &str, status: Option<Status>) -> Finding {
        let t = &template::find(&svc.templates, id).unwrap();
        let mut parts = BTreeMap::new();
        for p in &t.detect.patterns {
            let v = if p.secret {
                format!("{id}-SECRETVALUE-123456")
            } else {
                format!("{id}-PUBLICID")
            };
            parts.insert(p.name.clone(), v);
        }
        let mut f = Finding::new(
            t,
            parts,
            Location {
                source: SourceKind::Filesystem,
                path: Some(path.into()),
                line: 3,
                ..Default::default()
            },
        );
        f.verification = status.map(|s| Verification {
            status: s,
            message: None,
            details: BTreeMap::new(),
        });
        f
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn render(app: &App, w: u16, h: u16) -> String {
        let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| ui::draw(f, app, &Theme::with_truecolor(true)))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn results_app() -> App {
        let svc = services();
        let fs = vec![
            finding(&svc, "aws-access-key", "infra/.env", Some(Status::Verified)),
            finding(&svc, "github-token", "src/app.py", None),
            finding(&svc, "slack-token", "ci/notify.sh", Some(Status::Invalid)),
        ];
        let mut app = App::new(svc);
        app.set_results(fs, "./demo".into());
        app
    }

    #[test]
    fn home_renders_logo_and_menu() {
        let app = App::new(services());
        let s = render(&app, 100, 30);
        assert!(s.contains("█▀▀▄"), "logo missing:\n{s}");
        assert!(s.contains("Scan a folder"));
        assert!(s.contains("Browse detectors"));
        assert!(s.contains("verify findings live"));
    }

    #[test]
    fn menu_navigation_and_input() {
        let mut app = App::new(services());
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Input);
        assert_eq!(app.input_kind, InputKind::Repository);
        for c in "github.com/org/repo".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.input, "github.com/org/repo");
        assert!(render(&app, 100, 30).contains("git@github.com:org/repo.git"));
        app.on_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Home);
        app.on_key(key(KeyCode::Char('v')));
        assert!(app.verify_after_scan);
        app.on_key(key(KeyCode::Char('3')));
        assert_eq!(app.screen, Screen::Templates);
        assert!(render(&app, 120, 30).contains("aws-access-key"));
    }

    #[test]
    fn results_list_detail_filter_and_reveal() {
        let mut app = results_app();
        let s = render(&app, 120, 32);
        assert!(s.contains("Findings 3/3"));
        assert!(s.contains("AWS Access Key"));
        assert!(s.contains("1 live"));
        // Secrets are masked until revealed, and hidden again on move.
        assert!(!s.contains("SECRETVALUE"));
        app.on_key(key(KeyCode::Char('r')));
        assert!(render(&app, 120, 32).contains("SECRETVALUE"));
        app.on_key(key(KeyCode::Down));
        assert!(!app.reveal);
        // Status and text filters.
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.status_filter, StatusFilter::Live);
        assert_eq!(app.visible.len(), 1);
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.visible.len(), 2); // not invalid
        app.on_key(key(KeyCode::Char('f')));
        app.on_key(key(KeyCode::Char('f')));
        assert_eq!(app.status_filter, StatusFilter::All);
        app.on_key(key(KeyCode::Char('/')));
        for c in "slack".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Enter));
        assert_eq!(app.visible.len(), 1);
        assert_eq!(app.current().unwrap().detector, "slack-token");
    }

    #[test]
    fn narrow_phone_layout_still_renders() {
        let app = results_app();
        let s = render(&app, 48, 40);
        assert!(s.contains("Findings 3/3"));
        assert!(s.contains("Overview"));
        let home = render(&App::new(services()), 48, 30);
        assert!(home.contains("Scan a folder"));
    }

    #[test]
    fn help_overlay_and_quit() {
        let mut app = results_app();
        app.on_key(key(KeyCode::Char('?')));
        assert!(render(&app, 100, 30).contains("reveal / hide the secret"));
        app.on_key(key(KeyCode::Char('x'))); // any key closes help
        assert!(!app.show_help);
        app.on_key(key(KeyCode::Char('q')));
        assert_eq!(app.screen, Screen::Home);
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
    }

    #[test]
    fn scan_runs_in_background_and_shows_results() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.env"),
            format!("T=gh{}_9nVq3kZ1Lr8XwT2pYb6Hd4Fs7Jc0Mg5Ae1Uo\n", "p"),
        )
        .unwrap();
        let mut app = App::new(services());
        let (t, label) =
            App::target_from_input(InputKind::Folder, dir.path().to_str().unwrap()).unwrap();
        app.start_scan(t, label);
        assert_eq!(app.screen, Screen::Scanning);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while app.screen == Screen::Scanning && std::time::Instant::now() < deadline {
            if let Ok(m) = app.rx.recv_timeout(Duration::from_millis(50)) {
                app.on_msg(m);
            }
        }
        assert_eq!(app.screen, Screen::Results);
        assert_eq!(app.findings.len(), 1);
        assert_eq!(app.findings[0].detector, "github-token");
        assert!(App::target_from_input(InputKind::Folder, "/definitely/not/here").is_err());
    }
}
