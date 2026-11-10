//! TUI state and behaviour (no rendering, no terminal I/O).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::analyze;
use crate::config::Filter;
use crate::detect::Engine;
use crate::finding::{Finding, Status, Verification};
use crate::http::Http;
use crate::rotate;
use crate::scan::{self, Progress, Target};
use crate::sources::git::GitOptions;
use crate::sources::remote::{self, Auth};
use crate::template::{Loaded, Template};
use crate::verify;

/// Everything background work needs; shared with worker threads/tasks.
pub struct Services {
    pub engine: Engine,
    pub filter: Filter,
    pub templates: Vec<Loaded>,
    pub http: Http,
    pub max_file_size: u64,
    pub runtime: Option<tokio::runtime::Handle>,
    /// Where triage decisions are saved (`x` / `m`); `None` disables them.
    pub baseline: Option<PathBuf>,
    /// Verification results reused across runs (`--verify-cache`).
    pub verify_cache: Option<Arc<crate::verify_cache::Cache>>,
}

impl Services {
    fn template(&self, id: &str) -> Option<Arc<Template>> {
        self.engine
            .detectors
            .iter()
            .find(|d| d.template.id == id)
            .map(|d| d.template.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    Input,
    Scanning,
    Results,
    Templates,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Folder,
    Repository,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetailTab {
    Overview,
    Analysis,
    Rotation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusFilter {
    All,
    Live,
    NeedsReview,
    Invalid,
}

impl StatusFilter {
    pub fn label(self) -> &'static str {
        match self {
            StatusFilter::All => "all",
            StatusFilter::Live => "live",
            StatusFilter::NeedsReview => "not invalid",
            StatusFilter::Invalid => "invalid",
        }
    }
    fn next(self) -> Self {
        match self {
            StatusFilter::All => StatusFilter::Live,
            StatusFilter::Live => StatusFilter::NeedsReview,
            StatusFilter::NeedsReview => StatusFilter::Invalid,
            StatusFilter::Invalid => StatusFilter::All,
        }
    }
    fn keeps(self, s: Option<Status>) -> bool {
        match self {
            StatusFilter::All => true,
            StatusFilter::Live => s == Some(Status::Verified),
            StatusFilter::NeedsReview => s != Some(Status::Invalid),
            StatusFilter::Invalid => s == Some(Status::Invalid),
        }
    }
}

/// Messages from background work.
pub enum Msg {
    Progress(Progress),
    ScanDone(Result<Vec<Finding>, String>),
    Verified(String, Verification),
    Analysis(String, analyze::Report),
    Plan(String, Result<rotate::Report, String>),
}

#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub phase: String,
    pub done: usize,
    pub total: usize,
}

pub const MENU: [&str; 4] = [
    "Scan a folder",
    "Scan a git repository  (path or URL)",
    "Browse detectors",
    "Quit",
];

pub struct App {
    pub svc: Arc<Services>,
    pub screen: Screen,
    pub menu: usize,
    pub input: String,
    pub input_kind: InputKind,
    pub verify_after_scan: bool,
    pub target_label: String,
    pub progress: ScanProgress,
    pub findings: Vec<Finding>,
    pub visible: Vec<usize>,
    pub selected: usize,
    pub filter_text: String,
    pub filtering: bool,
    pub status_filter: StatusFilter,
    pub reveal: bool,
    pub tab: DetailTab,
    pub detail_scroll: u16,
    pub verifying: HashSet<String>,
    pub analyses: HashMap<String, analyze::Report>,
    pub plans: HashMap<String, Result<rotate::Report, String>>,
    pub pending: HashSet<(String, DetailTab)>,
    pub template_selected: usize,
    pub show_help: bool,
    pub status: String,
    pub tick: u64,
    pub should_quit: bool,
    /// Screen to return to from Results (Home when launched from the menu).
    pub results_back: Option<Screen>,
    /// Last triaged finding and its index, for undo.
    last_triaged: Option<(usize, Finding)>,
    tx: Sender<Msg>,
    pub rx: Receiver<Msg>,
}

impl App {
    pub fn new(svc: Services) -> Self {
        let (tx, rx) = channel();
        Self {
            svc: Arc::new(svc),
            screen: Screen::Home,
            menu: 0,
            input: String::new(),
            input_kind: InputKind::Folder,
            verify_after_scan: false,
            target_label: String::new(),
            progress: ScanProgress::default(),
            findings: Vec::new(),
            visible: Vec::new(),
            selected: 0,
            filter_text: String::new(),
            filtering: false,
            status_filter: StatusFilter::All,
            reveal: false,
            tab: DetailTab::Overview,
            detail_scroll: 0,
            verifying: HashSet::new(),
            analyses: HashMap::new(),
            plans: HashMap::new(),
            pending: HashSet::new(),
            template_selected: 0,
            show_help: false,
            status: String::new(),
            tick: 0,
            should_quit: false,
            results_back: Some(Screen::Home),
            last_triaged: None,
            tx,
            rx,
        }
    }

    // ----- results -------------------------------------------------------

    /// Show findings directly (e.g. `kubera scan ... -i`).
    pub fn set_results(&mut self, mut findings: Vec<Finding>, label: String) {
        // Decisions made in this or an earlier session.
        if let Some(b) = self
            .svc
            .baseline
            .as_deref()
            .and_then(|p| crate::baseline::Baseline::load(p).ok())
        {
            findings.retain(|f| b.get(&f.fingerprint).is_none());
        }
        self.findings = findings;
        self.target_label = label;
        self.selected = 0;
        self.recompute_visible();
        self.screen = Screen::Results;
        self.status.clear();
    }

    pub fn recompute_visible(&mut self) {
        let needle = self.filter_text.to_lowercase();
        self.visible = self
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| self.status_filter.keeps(f.status()))
            .filter(|(_, f)| {
                needle.is_empty()
                    || [
                        f.detector.as_str(),
                        f.name.as_str(),
                        f.platform.as_str(),
                        f.location.path.as_deref().unwrap_or(""),
                        f.location.commit.as_deref().unwrap_or(""),
                    ]
                    .iter()
                    .any(|s| s.to_lowercase().contains(&needle))
            })
            .map(|(i, _)| i)
            .collect();
        if self.selected >= self.visible.len() {
            self.selected = self.visible.len().saturating_sub(1);
        }
    }

    pub fn current(&self) -> Option<&Finding> {
        self.visible
            .get(self.selected)
            .and_then(|i| self.findings.get(*i))
    }

    pub fn counts(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for f in &self.findings {
            let k = match f.status() {
                Some(Status::Verified) => "live",
                Some(Status::Invalid) => "invalid",
                Some(Status::Unknown) => "unknown",
                Some(Status::Unsupported) => "unverifiable",
                None => "unverified",
            };
            *m.entry(k).or_default() += 1;
        }
        m
    }

    // ----- background work ----------------------------------------------

    /// Resolve user input into a scan target.
    pub fn target_from_input(kind: InputKind, input: &str) -> Result<(Target, String), String> {
        let input = input.trim();
        let input = if input.is_empty() { "." } else { input };
        match kind {
            InputKind::Folder => {
                let p = PathBuf::from(input);
                if !p.exists() {
                    return Err(format!("{input} does not exist"));
                }
                Ok((Target::Paths(vec![p]), input.to_string()))
            }
            InputKind::Repository => {
                let label = match remote::parse(input) {
                    Ok(Some(r)) => r.display().to_string(),
                    Ok(None) => input.to_string(),
                    Err(e) => return Err(e.to_string()),
                };
                Ok((
                    Target::Git {
                        repo: input.to_string(),
                        options: GitOptions::default(),
                        // The TUI owns the terminal: never let ssh prompt.
                        auth: Auth::default(),
                        baseline: None,
                        mirror: None,
                    },
                    label,
                ))
            }
        }
    }

    pub fn start_scan(&mut self, target: Target, label: String) {
        self.target_label = label;
        self.findings.clear();
        self.visible.clear();
        self.analyses.clear();
        self.plans.clear();
        self.selected = 0;
        self.progress = ScanProgress {
            phase: "Preparing".into(),
            ..Default::default()
        };
        self.screen = Screen::Scanning;
        let svc = self.svc.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let ptx = tx.clone();
            let progress = move |p: Progress| {
                let send = match &p {
                    Progress::Files { done, total } => done % 25 == 0 || done == total,
                    _ => true,
                };
                if send {
                    let _ = ptx.send(Msg::Progress(p));
                }
            };
            let res = scan::run(
                &svc.engine,
                &svc.filter,
                &target,
                svc.max_file_size,
                &progress,
            )
            .map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::ScanDone(res));
        });
    }

    fn spawn<F>(&self, fut: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        match &self.svc.runtime {
            Some(rt) => {
                rt.spawn(fut);
                true
            }
            None => false,
        }
    }

    /// Verify the selected finding. An explicit re-check: a cached result
    /// is not reused (the new one is stored).
    pub fn verify_selected(&mut self) {
        if let Some(f) = self.current().cloned() {
            self.verify_findings(vec![f], true);
        }
    }

    pub fn verify_all(&mut self) {
        let todo: Vec<Finding> = self
            .findings
            .iter()
            .filter(|f| f.verification.is_none())
            .cloned()
            .collect();
        if todo.is_empty() {
            self.status = "everything is already verified".into();
            return;
        }
        self.verify_findings(todo, false);
    }

    fn verify_findings(&mut self, list: Vec<Finding>, fresh: bool) {
        let mut started = 0;
        let mut seen = HashSet::new();
        for f in list {
            if !seen.insert(f.fingerprint.clone()) || self.verifying.contains(&f.fingerprint) {
                continue;
            }
            let Some(t) = self.svc.template(&f.detector) else {
                continue;
            };
            let svc = self.svc.clone();
            let tx = self.tx.clone();
            let fp = f.fingerprint.clone();
            let parts = f.secret.clone();
            if self.spawn(async move {
                let cache = svc.verify_cache.as_deref();
                let v = verify::verify_cached(&svc.http, &t, &parts, cache, fresh).await;
                let _ = tx.send(Msg::Verified(fp, v));
            }) {
                self.verifying.insert(f.fingerprint.clone());
                started += 1;
            }
        }
        self.status = format!("verifying {started} secret(s) with their platforms…");
    }

    pub fn analyze_selected(&mut self) {
        let Some(f) = self.current().cloned() else {
            return;
        };
        self.tab = DetailTab::Analysis;
        self.detail_scroll = 0;
        if self.analyses.contains_key(&f.fingerprint)
            || self
                .pending
                .contains(&(f.fingerprint.clone(), DetailTab::Analysis))
        {
            return;
        }
        let Some(t) = self.svc.template(&f.detector) else {
            return;
        };
        let svc = self.svc.clone();
        let tx = self.tx.clone();
        let fp = f.fingerprint.clone();
        let key = (fp.clone(), DetailTab::Analysis);
        if self.spawn(async move {
            let rep = analyze::analyze(&svc.http, &t, &f.secret, false).await;
            let _ = tx.send(Msg::Analysis(fp, rep));
        }) {
            self.pending.insert(key);
            self.status = "analyzing…".into();
        }
    }

    pub fn plan_selected(&mut self) {
        let Some(f) = self.current().cloned() else {
            return;
        };
        self.tab = DetailTab::Rotation;
        self.detail_scroll = 0;
        if self.plans.contains_key(&f.fingerprint)
            || self
                .pending
                .contains(&(f.fingerprint.clone(), DetailTab::Rotation))
        {
            return;
        }
        let Some(t) = self.svc.template(&f.detector) else {
            return;
        };
        let svc = self.svc.clone();
        let tx = self.tx.clone();
        let fp = f.fingerprint.clone();
        let key = (fp.clone(), DetailTab::Rotation);
        if self.spawn(async move {
            let opts = rotate::Options {
                execute: false,
                force: false,
                inputs: BTreeMap::new(),
            };
            let res = rotate::rotate(&svc.http, &t, &f.secret, &opts)
                .await
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(Msg::Plan(fp, res));
        }) {
            self.pending.insert(key);
            self.status = "building rotation plan (dry run)…".into();
        }
    }

    /// Record a triage decision for the selected finding in the baseline
    /// file and hide it.
    pub fn triage(&mut self, decision: crate::baseline::Decision) {
        let Some(&idx) = self.visible.get(self.selected) else {
            return;
        };
        let Some(path) = self.svc.baseline.clone() else {
            self.status = "triage is not available here".into();
            return;
        };
        let f = self.findings[idx].clone();
        let res = crate::baseline::Baseline::load(&path).and_then(|mut b| {
            b.add(&f, decision, None);
            b.save()
        });
        match res {
            Ok(()) => {
                self.status = format!(
                    "marked {} as {} in {} - u to undo",
                    f.name,
                    decision.label(),
                    path.display()
                );
                self.findings.remove(idx);
                self.last_triaged = Some((idx, f));
                self.reveal = false;
                self.recompute_visible();
            }
            Err(e) => self.status = format!("could not save triage: {e:#}"),
        }
    }

    /// Undo the last triage decision.
    pub fn undo_triage(&mut self) {
        let (Some((idx, f)), Some(path)) = (self.last_triaged.take(), self.svc.baseline.clone())
        else {
            self.status = "nothing to undo".into();
            return;
        };
        let res = crate::baseline::Baseline::load(&path).and_then(|mut b| {
            b.remove(&f.fingerprint);
            b.save()
        });
        match res {
            Ok(()) => {
                self.status = format!("restored {}", f.name);
                let at = idx.min(self.findings.len());
                self.findings.insert(at, f);
                self.recompute_visible();
                if let Some(pos) = self.visible.iter().position(|&i| i == at) {
                    self.selected = pos;
                }
            }
            Err(e) => self.status = format!("could not undo: {e:#}"),
        }
    }

    /// Write the findings (always redacted) to a new 0600 file.
    pub fn export(&mut self) {
        let name = format!("kubera-findings-{}.json", chrono::Utc::now().timestamp());
        let data: Vec<Finding> = self.findings.iter().map(Finding::redact).collect();
        let res = serde_json::to_vec_pretty(&data)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| write_private(&PathBuf::from(&name), &bytes));
        self.status = match res {
            Ok(()) => format!("exported {} finding(s), redacted, to {name}", data.len()),
            Err(e) => format!("export failed: {e:#}"),
        };
    }

    pub fn on_msg(&mut self, m: Msg) {
        match m {
            Msg::Progress(p) => match p {
                Progress::Cloning(url) => self.progress.phase = format!("Cloning {url}"),
                Progress::Files { done, total } => {
                    self.progress.phase = "Scanning files".into();
                    self.progress.done = done;
                    self.progress.total = total;
                }
                Progress::Commits { done, total } => {
                    self.progress.phase = "Scanning history (commits)".into();
                    self.progress.done = done;
                    self.progress.total = total;
                }
                // Commit counts are the better measure once known.
                Progress::Diffs(_) if self.progress.total > 0 => {}
                Progress::Diffs(n) => {
                    self.progress.phase = "Scanning history".into();
                    self.progress.done = n;
                    self.progress.total = 0;
                }
            },
            Msg::ScanDone(Ok(findings)) => {
                let label = std::mem::take(&mut self.target_label);
                self.set_results(findings, label);
                if self.verify_after_scan {
                    self.verify_all();
                }
            }
            Msg::ScanDone(Err(e)) => {
                self.screen = Screen::Home;
                self.status = format!("scan failed: {e}");
            }
            Msg::Verified(fp, v) => {
                self.verifying.remove(&fp);
                for f in self.findings.iter_mut().filter(|f| f.fingerprint == fp) {
                    f.verification = Some(v.clone());
                }
                if self.verifying.is_empty() {
                    let c = self.counts();
                    let cached = self
                        .findings
                        .iter()
                        .filter(|f| f.verification.as_ref().is_some_and(|v| v.cached))
                        .count();
                    self.status = format!(
                        "verification done: {} live, {} invalid, {} unknown{}",
                        c.get("live").unwrap_or(&0),
                        c.get("invalid").unwrap_or(&0),
                        c.get("unknown").unwrap_or(&0),
                        if cached > 0 {
                            format!(" ({cached} from the cache, no request sent)")
                        } else {
                            String::new()
                        }
                    );
                    if let Some(cache) = &self.svc.verify_cache
                        && let Err(e) = cache.save()
                    {
                        self.status = format!("{}; {e:#}", self.status);
                    }
                }
                self.recompute_visible();
            }
            Msg::Analysis(fp, rep) => {
                self.pending.remove(&(fp.clone(), DetailTab::Analysis));
                for f in self.findings.iter_mut().filter(|f| f.fingerprint == fp) {
                    f.verification = Some(rep.verification.clone());
                }
                self.analyses.insert(fp, rep);
                self.status = "analysis ready".into();
            }
            Msg::Plan(fp, res) => {
                self.pending.remove(&(fp.clone(), DetailTab::Rotation));
                self.plans.insert(fp, res);
                self.status =
                    "rotation plan ready (dry run; run `kubera rotate --execute` to apply)".into();
            }
        }
    }

    // ----- input ---------------------------------------------------------

    pub fn on_key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if self.show_help {
            self.show_help = false;
            return;
        }
        match self.screen {
            Screen::Home => self.key_home(k),
            Screen::Input => self.key_input(k),
            Screen::Scanning => {
                if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) {
                    self.status =
                        "scan continues in the background; results will appear here".into();
                }
            }
            Screen::Results => self.key_results(k),
            Screen::Templates => self.key_templates(k),
        }
    }

    fn key_home(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.menu = self.menu.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.menu = (self.menu + 1).min(MENU.len() - 1),
            KeyCode::Char('v') => self.verify_after_scan = !self.verify_after_scan,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char(c @ '1'..='4') => {
                self.menu = c as usize - '1' as usize;
                self.activate_menu();
            }
            KeyCode::Enter => self.activate_menu(),
            _ => {}
        }
    }

    fn activate_menu(&mut self) {
        match self.menu {
            0 => {
                self.input_kind = InputKind::Folder;
                self.input = ".".into();
                self.screen = Screen::Input;
            }
            1 => {
                self.input_kind = InputKind::Repository;
                self.input.clear();
                self.screen = Screen::Input;
            }
            2 => self.screen = Screen::Templates,
            _ => self.should_quit = true,
        }
    }

    fn key_input(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Esc => self.screen = Screen::Home,
            KeyCode::Enter => match Self::target_from_input(self.input_kind, &self.input) {
                Ok((t, label)) => {
                    self.results_back = Some(Screen::Home);
                    self.status.clear();
                    self.start_scan(t, label);
                }
                Err(e) => self.status = e,
            },
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => self.input.clear(),
            KeyCode::Char(c) => self.input.push(c),
            _ => {}
        }
    }

    fn key_results(&mut self, k: KeyEvent) {
        if self.filtering {
            match k.code {
                KeyCode::Esc => {
                    self.filtering = false;
                    self.filter_text.clear();
                    self.recompute_visible();
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter_text.pop();
                    self.recompute_visible();
                }
                KeyCode::Char(c) => {
                    self.filter_text.push(c);
                    self.recompute_visible();
                }
                _ => {}
            }
            return;
        }
        let last = self.visible.len().saturating_sub(1);
        let before = self.selected;
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.selected = (self.selected + 1).min(last),
            KeyCode::Home | KeyCode::Char('g') => self.selected = 0,
            KeyCode::End | KeyCode::Char('G') => self.selected = last,
            KeyCode::PageDown => self.detail_scroll = self.detail_scroll.saturating_add(5),
            KeyCode::PageUp => self.detail_scroll = self.detail_scroll.saturating_sub(5),
            KeyCode::Tab => {
                self.tab = match self.tab {
                    DetailTab::Overview => DetailTab::Analysis,
                    DetailTab::Analysis => DetailTab::Rotation,
                    DetailTab::Rotation => DetailTab::Overview,
                };
                self.detail_scroll = 0;
            }
            KeyCode::Char('1') => self.tab = DetailTab::Overview,
            KeyCode::Char('2') => self.tab = DetailTab::Analysis,
            KeyCode::Char('3') => self.tab = DetailTab::Rotation,
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Char('f') => {
                self.status_filter = self.status_filter.next();
                self.recompute_visible();
            }
            KeyCode::Char('r') => self.reveal = !self.reveal,
            KeyCode::Char('v') => self.verify_selected(),
            KeyCode::Char('V') => self.verify_all(),
            KeyCode::Char('a') => self.analyze_selected(),
            KeyCode::Char('p') => self.plan_selected(),
            KeyCode::Char('e') => self.export(),
            KeyCode::Char('x') => self.triage(crate::baseline::Decision::FalsePositive),
            KeyCode::Char('m') => self.triage(crate::baseline::Decision::Accepted),
            KeyCode::Char('u') => self.undo_triage(),
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Esc | KeyCode::Char('q') => match self.results_back {
                Some(s) => {
                    self.screen = s;
                    self.reveal = false;
                }
                None => self.should_quit = true,
            },
            _ => {}
        }
        if self.selected != before {
            self.detail_scroll = 0;
            // Never carry a revealed secret over to the next finding.
            self.reveal = false;
        }
    }

    fn key_templates(&mut self, k: KeyEvent) {
        let last = self.svc.templates.len().saturating_sub(1);
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.template_selected = self.template_selected.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.template_selected = (self.template_selected + 1).min(last)
            }
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Home,
            _ => {}
        }
    }
}

fn write_private(path: &std::path::Path, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(data)?;
    Ok(())
}
