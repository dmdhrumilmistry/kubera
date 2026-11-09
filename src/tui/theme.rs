//! Colours for the TUI, degrading to the xterm-256 palette when the terminal
//! does not advertise truecolor.

use ratatui::style::{Color, Modifier, Style};

use crate::brand;
use crate::finding::Status;
use crate::template::Severity;

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    truecolor: bool,
}

impl Theme {
    pub fn detect() -> Self {
        Self {
            truecolor: brand::truecolor(),
        }
    }

    /// Fixed palette mode (used for deterministic screenshots and tests).
    pub fn with_truecolor(truecolor: bool) -> Self {
        Self { truecolor }
    }

    pub fn rgb(&self, c: (u8, u8, u8)) -> Color {
        if self.truecolor {
            Color::Rgb(c.0, c.1, c.2)
        } else {
            Color::Indexed(brand::to_ansi256(c))
        }
    }

    pub fn gold(&self) -> Color {
        self.rgb(brand::GOLD)
    }
    pub fn gradient(&self, t: f32) -> Color {
        self.rgb(brand::gradient(t))
    }
    pub fn text(&self) -> Color {
        self.rgb((226, 232, 240))
    }
    pub fn muted(&self) -> Color {
        self.rgb((136, 146, 164))
    }
    pub fn border(&self) -> Color {
        self.rgb((71, 85, 105))
    }
    pub fn selection_bg(&self) -> Color {
        self.rgb((51, 41, 10))
    }
    pub fn live(&self) -> Color {
        self.rgb((248, 81, 73))
    }
    pub fn ok(&self) -> Color {
        self.rgb((63, 185, 80))
    }
    pub fn warn(&self) -> Color {
        self.rgb((210, 153, 34))
    }
    pub fn info(&self) -> Color {
        self.rgb((88, 166, 255))
    }

    pub fn title(&self) -> Style {
        Style::new().fg(self.gold()).add_modifier(Modifier::BOLD)
    }
    pub fn dim(&self) -> Style {
        Style::new().fg(self.muted())
    }
    pub fn key(&self) -> Style {
        Style::new().fg(self.gold()).add_modifier(Modifier::BOLD)
    }

    pub fn severity(&self, s: Severity) -> (String, Style) {
        let (label, color) = match s {
            Severity::Critical => ("CRIT", self.rgb((255, 92, 138))),
            Severity::High => ("HIGH", self.live()),
            Severity::Medium => ("MED ", self.warn()),
            Severity::Low => ("LOW ", self.info()),
            Severity::Info => ("INFO", self.muted()),
        };
        (
            label.to_string(),
            Style::new().fg(color).add_modifier(Modifier::BOLD),
        )
    }

    /// Icon + label + style for a verification state (`None` = not run).
    pub fn status(&self, s: Option<Status>) -> (&'static str, &'static str, Style) {
        match s {
            Some(Status::Verified) => (
                "●",
                "LIVE",
                Style::new().fg(self.live()).add_modifier(Modifier::BOLD),
            ),
            Some(Status::Invalid) => ("✓", "invalid", Style::new().fg(self.ok())),
            Some(Status::Unknown) => ("?", "unknown", Style::new().fg(self.warn())),
            Some(Status::Unsupported) => ("-", "not verifiable", self.dim()),
            None => ("·", "unverified", self.dim()),
        }
    }
}
