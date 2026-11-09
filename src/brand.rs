//! Logo, palette and banner shared by the CLI and the TUI.
//!
//! Kubera is the guardian of treasure; the mark is a cut gem with a keyhole
//! notch, in gold (the vector logo in `docs/src/images/logo.svg` is the same
//! gem). The wordmark is 29 columns wide so it fits phone terminals
//! (Termux) as well as desktops.

use std::io::IsTerminal;

/// The gem mark (left) and wordmark (right), three rows each.
pub const MARK: [&str; 3] = [" ▄▄▄▄▄ ", "▀██▄██▀", "  ▀█▀  "];
pub const WORDMARK: [&str; 3] = [
    "█ ▄▀ █  █ █▀▀▄ █▀▀▀ █▀▀▄ ▄▀▀▄",
    "█▀▄  █  █ █▀▀▄ █▀▀  █▀▀▄ █▀▀█",
    "▀  ▀ ▀▄▄▀ ▀▀▀  ▀▀▀▀ ▀  ▀ ▀  ▀",
];
pub const TAGLINE: &str = "find · verify · analyze · rotate leaked secrets";

/// Gold gradient stops (left to right).
pub const GOLD_LIGHT: (u8, u8, u8) = (255, 214, 92);
pub const GOLD: (u8, u8, u8) = (245, 183, 0);
pub const AMBER: (u8, u8, u8) = (229, 133, 24);

/// Whether the terminal advertises 24-bit colour.
pub fn truecolor() -> bool {
    std::env::var("COLORTERM")
        .map(|v| v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit"))
        .unwrap_or(false)
}

/// Colour at position `t` (0..=1) along the gold gradient.
pub fn gradient(t: f32) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    let (a, b, u) = if t < 0.5 {
        (GOLD_LIGHT, GOLD, t * 2.0)
    } else {
        (GOLD, AMBER, (t - 0.5) * 2.0)
    };
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * u).round() as u8;
    (mix(a.0, b.0), mix(a.1, b.1), mix(a.2, b.2))
}

/// Nearest xterm-256 colour for terminals without truecolor.
pub fn to_ansi256((r, g, b): (u8, u8, u8)) -> u8 {
    let q = |v: u8| ((v as u16 * 5 + 127) / 255) as u8;
    16 + 36 * q(r) + 6 * q(g) + q(b)
}

fn paint(text: &str, rgb: (u8, u8, u8), truecolor: bool) -> String {
    if truecolor {
        format!("\x1b[1;38;2;{};{};{}m{text}\x1b[0m", rgb.0, rgb.1, rgb.2)
    } else {
        format!("\x1b[1;38;5;{}m{text}\x1b[0m", to_ansi256(rgb))
    }
}

/// The banner as plain text (for `--help` and non-colour output).
pub fn banner_plain() -> String {
    let mut s = String::new();
    for i in 0..3 {
        s.push_str(&format!("  {} {}\n", MARK[i], WORDMARK[i]));
    }
    s.push_str(&format!("  {}\n", TAGLINE));
    s
}

/// The banner with an ANSI gold gradient.
pub fn banner_colored(truecolor: bool) -> String {
    let mut s = String::new();
    for i in 0..3 {
        s.push_str("  ");
        s.push_str(&paint(MARK[i], GOLD, truecolor));
        s.push(' ');
        let chars: Vec<char> = WORDMARK[i].chars().collect();
        let n = chars.len().max(1) as f32;
        for (j, c) in chars.iter().enumerate() {
            if *c == ' ' {
                s.push(' ');
            } else {
                s.push_str(&paint(&c.to_string(), gradient(j as f32 / n), truecolor));
            }
        }
        s.push('\n');
    }
    s.push_str(&format!("  \x1b[2m{}\x1b[0m\n", TAGLINE));
    s
}

/// Print the banner to stderr when it is a colour-capable terminal.
pub fn print_banner_stderr() {
    if std::env::var_os("NO_COLOR").is_some() || !std::io::stderr().is_terminal() {
        return;
    }
    eprint!("{}", banner_colored(truecolor()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_aligned() {
        let w = WORDMARK[0].chars().count();
        assert!(WORDMARK.iter().all(|r| r.chars().count() == w));
        let m = MARK[0].chars().count();
        assert!(MARK.iter().all(|r| r.chars().count() == m));
        assert!(m + 1 + w <= 40, "logo must fit narrow phone terminals");
    }

    #[test]
    fn gradient_endpoints_and_256_fallback() {
        assert_eq!(gradient(0.0), GOLD_LIGHT);
        assert_eq!(gradient(0.5), GOLD);
        assert_eq!(gradient(1.0), AMBER);
        assert_eq!(to_ansi256((0, 0, 0)), 16);
        assert_eq!(to_ansi256((255, 255, 255)), 231);
    }
}
