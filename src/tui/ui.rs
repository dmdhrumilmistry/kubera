//! Rendering. Pure function of [`App`] state; layouts adapt to narrow
//! (phone) terminals by stacking panes vertically.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, Gauge, List, ListItem, ListState, Padding, Paragraph, Wrap,
};

use super::app::{App, DetailTab, InputKind, MENU, Screen};
use super::theme::Theme;
use crate::brand;
use crate::finding::{Finding, redact};
use crate::report::display_value;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn draw(f: &mut Frame, app: &App, theme: &Theme) {
    let area = f.area();
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(area);
    draw_header(f, header, app, theme);
    match app.screen {
        Screen::Home => draw_home(f, body, app, theme),
        Screen::Input => draw_input(f, body, app, theme),
        Screen::Scanning => draw_scanning(f, body, app, theme),
        Screen::Results => draw_results(f, body, app, theme),
        Screen::Templates => draw_templates(f, body, app, theme),
    }
    draw_footer(f, footer, app, theme);
    if app.show_help {
        draw_help(f, area, theme);
    }
}

fn panel<'a>(title: &'a str, theme: &Theme) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(theme.border()))
        .title(Span::styled(format!(" {title} "), theme.title()))
        .padding(Padding::horizontal(1))
}

fn draw_header(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let mut left = vec![
        Span::styled(" ◆ kubera ", theme.title()),
        Span::styled(concat!("v", env!("CARGO_PKG_VERSION")), theme.dim()),
    ];
    let right = header_counts(app, theme);
    let right_w: usize = right.iter().map(|s| s.content.chars().count()).sum();
    let left_w: usize = left.iter().map(|s| s.content.chars().count()).sum();
    let label_w = app.target_label.chars().count() + 5;
    // On narrow (phone) terminals drop the target before overlapping.
    if !app.target_label.is_empty()
        && app.screen != Screen::Home
        && left_w + label_w + right_w < area.width as usize
    {
        left.push(Span::styled("  ›  ", theme.dim()));
        left.push(Span::styled(
            app.target_label.clone(),
            Style::new().fg(theme.text()),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(left)), area);
    if !right.is_empty() && left_w + right_w < area.width as usize {
        f.render_widget(
            Paragraph::new(Line::from(right)).alignment(Alignment::Right),
            area,
        );
    }
}

fn header_counts(app: &App, theme: &Theme) -> Vec<Span<'static>> {
    let mut right = Vec::new();
    if app.screen == Screen::Results {
        let c = app.counts();
        right.push(Span::styled(
            format!("{} findings ", app.findings.len()),
            Style::new().fg(theme.text()),
        ));
        if let Some(n) = c.get("live") {
            right.push(Span::styled(
                format!(" ● {n} live "),
                Style::new().fg(theme.live()).add_modifier(Modifier::BOLD),
            ));
        }
        if let Some(n) = c.get("invalid") {
            right.push(Span::styled(
                format!(" ✓ {n} invalid "),
                Style::new().fg(theme.ok()),
            ));
        }
    }
    right
}

fn key_hints(pairs: &[(&str, &str)], theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (i, (k, d)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", theme.dim()));
        }
        spans.push(Span::styled(k.to_string(), theme.key()));
        spans.push(Span::styled(format!(" {d}"), theme.dim()));
    }
    Line::from(spans)
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let line = if !app.status.is_empty() {
        Line::from(vec![
            Span::styled(" › ", theme.key()),
            Span::styled(app.status.clone(), Style::new().fg(theme.text())),
        ])
    } else {
        let pairs: &[(&str, &str)] = match app.screen {
            Screen::Home => &[
                ("↑↓", "select"),
                ("enter", "open"),
                ("v", "verify on/off"),
                ("?", "help"),
                ("q", "quit"),
            ],
            Screen::Input => &[("enter", "scan"), ("esc", "back"), ("ctrl+u", "clear")],
            Screen::Scanning => &[("ctrl+c", "quit")],
            Screen::Results if app.filtering => {
                &[("type", "filter"), ("enter", "apply"), ("esc", "clear")]
            }
            Screen::Results => &[
                ("↑↓", "move"),
                ("v/V", "verify"),
                ("a", "analyze"),
                ("p", "rotate plan"),
                ("r", "reveal"),
                ("/", "filter"),
                ("f", "status"),
                ("e", "export"),
                ("?", "help"),
                ("q", "back"),
            ],
            Screen::Templates => &[("↑↓", "select"), ("q", "back")],
        };
        key_hints(pairs, theme)
    };
    f.render_widget(Paragraph::new(line), area);
}

fn logo_lines(theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for i in 0..3 {
        let mut spans = vec![Span::styled(
            format!("{} ", brand::MARK[i]),
            Style::new().fg(theme.gold()).add_modifier(Modifier::BOLD),
        )];
        let chars: Vec<char> = brand::WORDMARK[i].chars().collect();
        let n = chars.len() as f32;
        for (j, c) in chars.into_iter().enumerate() {
            spans.push(Span::styled(
                c.to_string(),
                Style::new()
                    .fg(theme.gradient(j as f32 / n))
                    .add_modifier(Modifier::BOLD),
            ));
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn draw_home(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let box_area = centered(area, 60, 18);
    let mut lines = logo_lines(theme);
    lines.push(Line::styled(brand::TAGLINE, theme.dim()));
    lines.push(Line::raw(""));
    for (i, item) in MENU.iter().enumerate() {
        let selected = i == app.menu;
        let marker = if selected { "▸ " } else { "  " };
        let style = if selected {
            Style::new()
                .fg(theme.gold())
                .bg(theme.selection_bg())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(theme.text())
        };
        lines.push(Line::from(vec![
            Span::styled(marker, theme.key()),
            Span::styled(format!("{}  ", i + 1), theme.dim()),
            Span::styled(format!("{item:<40}"), style),
        ]));
    }
    lines.push(Line::raw(""));
    let (check, style) = if app.verify_after_scan {
        (
            "[x]",
            Style::new().fg(theme.gold()).add_modifier(Modifier::BOLD),
        )
    } else {
        ("[ ]", theme.dim())
    };
    lines.push(Line::from(vec![
        Span::styled(format!("{check} "), style),
        Span::styled(
            "verify findings live after scanning ",
            Style::new().fg(theme.text()),
        ),
        Span::styled("(v)", theme.key()),
    ]));
    lines.push(Line::styled(
        "    sends each secret only to the platform that issued it",
        theme.dim(),
    ));
    f.render_widget(Paragraph::new(lines), box_area);
}

fn draw_input(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let (title, hint) = match app.input_kind {
        InputKind::Folder => (
            "Scan a folder",
            vec!["  .", "  ~/projects/api", "  /etc/app/config.yaml"],
        ),
        InputKind::Repository => (
            "Scan a git repository",
            vec![
                "  .                                 (this repository)",
                "  https://github.com/org/repo.git",
                "  git@github.com:org/repo.git",
                "  github.com/org/repo",
            ],
        ),
    };
    let box_area = centered(area, 64, 14);
    let [field, rest] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(box_area);
    let cursor = if (app.tick / 5).is_multiple_of(2) {
        "▏"
    } else {
        " "
    };
    let input = Paragraph::new(Line::from(vec![
        Span::styled(app.input.clone(), Style::new().fg(theme.text())),
        Span::styled(cursor, theme.key()),
    ]))
    .block(panel(title, theme));
    f.render_widget(input, field);
    let mut lines = vec![Line::styled(" Examples", theme.dim())];
    lines.extend(
        hint.into_iter()
            .map(|h| Line::styled(h, Style::new().fg(theme.muted()))),
    );
    if app.input_kind == InputKind::Repository {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            " Private repos: kubera scan git URL --token-env VAR -i",
            theme.dim(),
        ));
    }
    f.render_widget(Paragraph::new(lines), rest);
}

fn draw_scanning(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let box_area = centered(area, 60, 9);
    let [logo, msg, gauge] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .areas(box_area);
    f.render_widget(Paragraph::new(logo_lines(theme)), logo);
    let spin = SPINNER[(app.tick as usize) % SPINNER.len()];
    let detail = if app.progress.total > 0 {
        format!("{} / {} files", app.progress.done, app.progress.total)
    } else if app.progress.done > 0 {
        format!("{} file changes", app.progress.done)
    } else {
        String::new()
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("{spin} "), theme.key()),
            Span::styled(app.progress.phase.clone(), Style::new().fg(theme.text())),
            Span::styled(format!("  {detail}"), theme.dim()),
        ])),
        msg,
    );
    if app.progress.total > 0 {
        let ratio = app.progress.done as f64 / app.progress.total as f64;
        f.render_widget(
            Gauge::default()
                .ratio(ratio.clamp(0.0, 1.0))
                .gauge_style(Style::new().fg(theme.gold()).bg(theme.selection_bg()))
                .label(format!("{:.0}%", ratio * 100.0)),
            gauge,
        );
    }
}

fn finding_item<'a>(f: &Finding, app: &App, theme: &Theme) -> ListItem<'a> {
    let (sev, sev_style) = theme.severity(f.severity);
    let (icon, _, st_style) = if app.verifying.contains(&f.fingerprint) {
        (
            SPINNER[(app.tick as usize) % SPINNER.len()],
            "",
            theme.key(),
        )
    } else {
        theme.status(f.status())
    };
    let loc = match (&f.location.path, f.location.line) {
        (Some(p), l) => format!("{p}:{l}"),
        (None, l) => format!("line {l}"),
    };
    ListItem::new(vec![
        Line::from(vec![
            Span::styled(format!("{icon} "), st_style),
            Span::styled(format!("{sev} "), sev_style),
            Span::styled(f.name.clone(), Style::new().fg(theme.text())),
        ]),
        Line::from(vec![Span::styled(format!("       {loc}"), theme.dim())]),
    ])
}

fn draw_results(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    if app.findings.is_empty() {
        let box_area = centered(area, 50, 6);
        f.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "✓ No secrets found",
                    Style::new().fg(theme.ok()).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::styled(format!("in {}", app.target_label), theme.dim()),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("q", theme.key()),
                    Span::styled(" back", theme.dim()),
                ]),
            ])
            .alignment(Alignment::Center),
            box_area,
        );
        return;
    }
    let narrow = area.width < 100;
    let [list_area, detail_area] = if narrow {
        Layout::vertical([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area)
    } else {
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(area)
    };

    let mut title = format!("Findings {}/{}", app.visible.len(), app.findings.len());
    if app.status_filter != super::app::StatusFilter::All {
        title.push_str(&format!(" · {}", app.status_filter.label()));
    }
    if app.filtering || !app.filter_text.is_empty() {
        title.push_str(&format!(" · /{}", app.filter_text));
        if app.filtering {
            title.push('▏');
        }
    }
    let items: Vec<ListItem> = app
        .visible
        .iter()
        .map(|i| finding_item(&app.findings[*i], app, theme))
        .collect();
    let list = List::new(items)
        .block(panel(&title, theme))
        .highlight_style(Style::new().bg(theme.selection_bg()))
        .highlight_symbol("▌");
    let mut state = ListState::default().with_selected(Some(app.selected));
    f.render_stateful_widget(list, list_area, &mut state);

    let tabs = [
        (DetailTab::Overview, "1 Overview"),
        (DetailTab::Analysis, "2 Analysis"),
        (DetailTab::Rotation, "3 Rotation"),
    ];
    let mut tab_spans = Vec::new();
    for (t, label) in tabs {
        let style = if t == app.tab {
            Style::new()
                .fg(theme.gold())
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            theme.dim()
        };
        tab_spans.push(Span::styled(format!(" {label} "), style));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(theme.border()))
        .title(Line::from(tab_spans))
        .padding(Padding::horizontal(1));
    let text = match app.current() {
        None => Text::styled("No finding matches the filter.", theme.dim()),
        Some(fd) => match app.tab {
            DetailTab::Overview => overview(fd, app, theme),
            DetailTab::Analysis => analysis_text(fd, app, theme),
            DetailTab::Rotation => rotation_text(fd, app, theme),
        },
    };
    f.render_widget(
        Paragraph::new(text)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0)),
        detail_area,
    );
}

/// Label column: 12 wide, but always at least one space after the label.
fn label_col(k: &str) -> String {
    let w = 12.max(k.chars().count() + 1);
    format!("{k:<w$}")
}

fn kv(k: &str, v: impl Into<String>, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(label_col(k), theme.dim()),
        Span::styled(v.into(), Style::new().fg(theme.text())),
    ])
}

fn section(title: &str, theme: &Theme) -> Line<'static> {
    Line::styled(title.to_string(), theme.title())
}

fn overview(fd: &Finding, app: &App, theme: &Theme) -> Text<'static> {
    let (sev, sev_style) = theme.severity(fd.severity);
    let (icon, label, st_style) = theme.status(fd.status());
    let mut l = vec![
        Line::from(vec![
            Span::styled(
                fd.name.clone(),
                Style::new().fg(theme.text()).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!(" {} ", sev.trim()),
                sev_style.add_modifier(Modifier::REVERSED),
            ),
            Span::raw("  "),
            Span::styled(format!("{icon} {label}"), st_style),
        ]),
        Line::raw(""),
        kv("detector", fd.detector.clone(), theme),
        kv("platform", fd.platform.clone(), theme),
        Line::raw(""),
        section("Where", theme),
    ];
    let loc = &fd.location;
    match &loc.path {
        Some(p) => l.push(kv("file", format!("{p}:{}", loc.line), theme)),
        None => l.push(kv("line", loc.line.to_string(), theme)),
    }
    if let Some(r) = &loc.repository {
        l.push(kv("repository", r.clone(), theme));
    }
    if let Some(c) = &loc.commit {
        l.push(kv("commit", c[..c.len().min(12)].to_string(), theme));
        l.push(kv(
            "author",
            format!(
                "{} <{}>",
                loc.author.as_deref().unwrap_or(""),
                loc.email.as_deref().unwrap_or("")
            ),
            theme,
        ));
        if let Some(d) = &loc.date {
            l.push(kv("date", d.clone(), theme));
        }
    }
    if let Some(link) = &loc.link {
        l.push(Line::from(vec![
            Span::styled(label_col("link"), theme.dim()),
            Span::styled(
                link.clone(),
                Style::new()
                    .fg(theme.info())
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]));
    }
    l.push(Line::raw(""));
    l.push(Line::from(vec![
        Span::styled("Secret", theme.title()),
        Span::styled(
            if app.reveal {
                "  (revealed - r to hide)"
            } else {
                "  (r to reveal)"
            },
            theme.dim(),
        ),
    ]));
    for (k, v) in &fd.secret {
        let shown = if app.reveal || !fd.sensitive.contains(k) {
            v.clone()
        } else {
            redact(v)
        };
        l.push(kv(k, shown, theme));
    }
    l.push(kv("fingerprint", fd.fingerprint.clone(), theme));
    l.push(Line::raw(""));
    l.push(section("Verification", theme));
    match &fd.verification {
        None if app.verifying.contains(&fd.fingerprint) => {
            l.push(Line::styled("checking with the platform…", theme.key()))
        }
        None => l.push(Line::from(vec![
            Span::styled("not verified yet - press ", theme.dim()),
            Span::styled("v", theme.key()),
        ])),
        Some(v) => {
            l.push(Line::from(vec![Span::styled(
                format!("{icon} {label}"),
                st_style,
            )]));
            if let Some(m) = &v.message {
                l.push(kv("message", m.clone(), theme));
            }
            for (k, val) in &v.details {
                l.push(kv(k, display_value(val), theme));
            }
        }
    }
    Text::from(l)
}

fn analysis_text(fd: &Finding, app: &App, theme: &Theme) -> Text<'static> {
    let Some(rep) = app.analyses.get(&fd.fingerprint) else {
        if app
            .pending
            .contains(&(fd.fingerprint.clone(), DetailTab::Analysis))
        {
            return Text::styled(
                "Analyzing… (identity, scopes, reachable resources)",
                theme.key(),
            );
        }
        return Text::from(vec![
            Line::styled("What can this credential reach?", theme.title()),
            Line::raw(""),
            Line::from(vec![
                Span::styled("Press ", theme.dim()),
                Span::styled("a", theme.key()),
                Span::styled(
                    " to run read-only analysis calls against the platform.",
                    theme.dim(),
                ),
            ]),
        ]);
    };
    let rep = if app.reveal {
        rep.clone()
    } else {
        rep.redacted()
    };
    let (icon, label, st) = theme.status(Some(rep.verification.status));
    let mut l = vec![Line::from(vec![
        Span::styled("Credential  ", theme.dim()),
        Span::styled(format!("{icon} {label}"), st),
    ])];
    for (k, v) in &rep.verification.details {
        l.push(kv(k, display_value(v), theme));
    }
    if let Some(n) = &rep.notes {
        l.push(Line::raw(""));
        for line in n.trim().lines() {
            l.push(Line::styled(line.to_string(), theme.dim()));
        }
    }
    if rep.steps.is_empty() && rep.verification.status != crate::finding::Status::Verified {
        l.push(Line::raw(""));
        l.push(Line::styled(
            "Analysis runs only for live credentials.",
            theme.dim(),
        ));
    }
    for s in &rep.steps {
        l.push(Line::raw(""));
        let (mark, style) = if s.ok {
            ("✔", Style::new().fg(theme.ok()))
        } else {
            ("✘", Style::new().fg(theme.live()))
        };
        l.push(Line::from(vec![
            Span::styled(format!("{mark} "), style),
            Span::styled(
                s.name.clone(),
                Style::new().fg(theme.text()).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if s.description.is_empty() {
                    String::new()
                } else {
                    format!("  {}", s.description)
                },
                theme.dim(),
            ),
        ]));
        if let Some(e) = &s.error {
            l.push(kv("  error", e.clone(), theme));
        }
        for v in &s.values {
            l.push(kv(
                &format!("  {}", v.label),
                display_value(&v.value),
                theme,
            ));
        }
    }
    Text::from(l)
}

fn rotation_text(fd: &Finding, app: &App, theme: &Theme) -> Text<'static> {
    let Some(res) = app.plans.get(&fd.fingerprint) else {
        if app
            .pending
            .contains(&(fd.fingerprint.clone(), DetailTab::Rotation))
        {
            return Text::styled("Building the rotation plan (dry run)…", theme.key());
        }
        return Text::from(vec![
            Line::styled("Rotate or revoke this credential", theme.title()),
            Line::raw(""),
            Line::from(vec![
                Span::styled("Press ", theme.dim()),
                Span::styled("p", theme.key()),
                Span::styled(
                    " for the rotation plan. Nothing is changed: plans are dry runs.",
                    theme.dim(),
                ),
            ]),
        ]);
    };
    let rep = match res {
        Ok(r) => r,
        Err(e) => return Text::styled(format!("No rotation plan: {e}"), theme.dim()),
    };
    let mut l = Vec::new();
    if let Some(i) = &rep.instructions {
        l.push(section("Instructions", theme));
        for line in i.trim().lines() {
            l.push(Line::styled(
                line.to_string(),
                Style::new().fg(theme.text()),
            ));
        }
    }
    if !rep.plan.is_empty() {
        l.push(Line::raw(""));
        l.push(section("Planned API calls (dry run)", theme));
        for (n, p) in rep.plan.iter().enumerate() {
            l.push(Line::from(vec![
                Span::styled(format!("{}. ", n + 1), theme.key()),
                Span::styled(
                    p.name.clone(),
                    Style::new().fg(theme.text()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {}", p.description), theme.dim()),
            ]));
            for line in p.request.lines() {
                l.push(Line::styled(format!("   {line}"), theme.dim()));
            }
        }
    }
    l.push(Line::raw(""));
    l.push(Line::from(vec![
        Span::styled("To apply: ", theme.dim()),
        Span::styled(
            format!("kubera rotate {} --secret-env VAR --execute", fd.detector),
            theme.key(),
        ),
    ]));
    Text::from(l)
}

fn draw_templates(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let narrow = area.width < 100;
    let [list_area, detail_area] = if narrow {
        Layout::vertical([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area)
    } else {
        Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)]).areas(area)
    };
    let items: Vec<ListItem> = app
        .svc
        .templates
        .iter()
        .map(|l| {
            let t = &l.template;
            let (sev, st) = theme.severity(t.severity);
            let cap = |b: bool, c: &'static str| {
                if b {
                    Span::styled(c, theme.key())
                } else {
                    Span::styled("·", theme.dim())
                }
            };
            let rot = t.rotate.as_ref().is_some_and(|r| !r.steps.is_empty());
            ListItem::new(Line::from(vec![
                Span::styled(format!("{sev} "), st),
                cap(t.verify.is_some(), "V"),
                cap(t.analyze.is_some(), "A"),
                cap(rot, "R"),
                Span::styled(format!(" {}", t.id), Style::new().fg(theme.text())),
            ]))
        })
        .collect();
    let title = format!("Detectors ({})", app.svc.templates.len());
    let list = List::new(items)
        .block(panel(&title, theme))
        .highlight_style(Style::new().bg(theme.selection_bg()))
        .highlight_symbol("▌");
    let mut state = ListState::default().with_selected(Some(app.template_selected));
    f.render_stateful_widget(list, list_area, &mut state);

    let Some(l) = app.svc.templates.get(app.template_selected) else {
        return;
    };
    let t = &l.template;
    let mut lines = vec![
        Line::styled(
            t.name.clone(),
            Style::new().fg(theme.text()).add_modifier(Modifier::BOLD),
        ),
        Line::styled(t.description.clone(), theme.dim()),
        Line::raw(""),
        kv("id", t.id.clone(), theme),
        kv("platform", t.platform.clone(), theme),
        kv("severity", t.severity.to_string(), theme),
        kv("keywords", t.detect.keywords.join(", "), theme),
        kv("source", l.source.clone(), theme),
        Line::raw(""),
        section("Capabilities", theme),
    ];
    match &t.verify {
        Some(v) => l_push(
            &mut lines,
            "verify",
            format!("{} {}", v.request.method, v.request.url),
            theme,
        ),
        None => l_push(&mut lines, "verify", "-".into(), theme),
    }
    match &t.analyze {
        Some(a) => l_push(
            &mut lines,
            "analyze",
            a.steps
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            theme,
        ),
        None => l_push(&mut lines, "analyze", "-".into(), theme),
    }
    let rot = match &t.rotate {
        Some(r) if !r.steps.is_empty() => format!(
            "API: {}",
            r.steps
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                .join(" → ")
        ),
        Some(_) => "manual instructions".into(),
        None => "-".into(),
    };
    l_push(&mut lines, "rotate", rot, theme);
    if !t.references.is_empty() {
        lines.push(Line::raw(""));
        lines.push(section("References", theme));
        for r in &t.references {
            lines.push(Line::styled(r.clone(), Style::new().fg(theme.info())));
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(panel("Detector", theme))
            .wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn l_push(lines: &mut Vec<Line<'static>>, k: &str, v: String, theme: &Theme) {
    lines.push(kv(k, v, theme));
}

fn draw_help(f: &mut Frame, area: Rect, theme: &Theme) {
    let rows: &[(&str, &str)] = &[
        ("↑ ↓  j k", "move"),
        ("g G", "first / last"),
        ("enter", "open / scan"),
        ("v", "verify selected (home: toggle verify)"),
        ("V", "verify every unverified finding"),
        ("a", "analyze selected (read-only API calls)"),
        ("p", "rotation plan for selected (dry run)"),
        ("1 2 3  tab", "overview / analysis / rotation"),
        ("PgUp PgDn", "scroll details"),
        ("r", "reveal / hide the secret"),
        ("/", "filter by text"),
        ("f", "filter by status"),
        ("e", "export findings (redacted JSON, 0600)"),
        ("q  esc", "back / quit"),
        ("ctrl+c", "quit"),
    ];
    let box_area = centered(area, 58, rows.len() as u16 + 4);
    f.render_widget(Clear, box_area);
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::styled(format!("{k:<12}"), theme.key()),
                Span::styled(d.to_string(), Style::new().fg(theme.text())),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(panel("Keys", theme)), box_area);
}
