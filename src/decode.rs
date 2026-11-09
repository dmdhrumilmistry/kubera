//! Decoders: find encoded text (base64, URL / percent encoding, escape
//! sequences) and turn it into plain text the detectors can scan.
//!
//! Kubernetes Secret `data:`, Docker `config.json` auths, JWT payloads, CI
//! variables and many config systems store credentials base64-encoded, so a
//! scanner that only reads raw text misses them.
//!
//! All decoded segments of one chunk are joined into a single virtual text
//! (so multi-part detectors can pair, e.g., an AWS key id and secret stored as
//! two base64 values), with a map from each decoded line back to the line of
//! the original text it came from. Decoding is bounded: candidate runs are
//! length-limited, output must look like text, the total decoded size per
//! chunk is capped, and nesting goes at most [`MAX_DEPTH`] levels deep.

use std::sync::LazyLock;

use base64::Engine as _;
use regex::Regex;

use crate::detect::IGNORE_MARKER;

/// Decoders applied to already decoded text (base64 inside base64, ...).
pub const MAX_DEPTH: usize = 2;
/// Shortest base64 run considered (shorter runs are mostly identifiers).
const MIN_B64: usize = 24;
/// Longest base64 run considered (whole embedded files are rare and slow).
const MAX_B64: usize = 64 * 1024;
/// Cap on decoded output per chunk.
const MAX_DECODED: usize = 4 * 1024 * 1024;

static PERCENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"%[0-9A-Fa-f]{2}").unwrap());
static ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\\(?:u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|/)"#).unwrap());

/// Which decoder produced a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoder {
    Base64,
    Url,
    Escape,
}

impl Decoder {
    pub fn name(self) -> &'static str {
        match self {
            Decoder::Base64 => "base64",
            Decoder::Url => "url",
            Decoder::Escape => "escape",
        }
    }
}

/// Decoded text with a map from each of its lines (0-based) to the 1-based
/// line of the original text.
#[derive(Debug, Default)]
pub struct Decoded {
    pub text: String,
    pub line_map: Vec<usize>,
    /// Decoder of the outermost encoding of each decoded line.
    pub decoders: Vec<Decoder>,
}

impl Decoded {
    fn push(&mut self, segment: &str, line: usize, decoder: Decoder) {
        for l in segment.lines() {
            self.text.push_str(l);
            self.text.push('\n');
            self.line_map.push(line);
            self.decoders.push(decoder);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

/// Decode every encoded span of `text`, recursively up to [`MAX_DEPTH`].
/// Lines carrying the ignore marker are skipped.
pub fn decode(text: &str) -> Decoded {
    let mut out = Decoded::default();
    let mut budget = MAX_DECODED;
    decode_into(text, None, None, 1, &mut out, &mut budget);
    out
}

fn decode_into(
    text: &str,
    // Line map / decoders of `text` itself when it is already decoded.
    map: Option<&[usize]>,
    outer: Option<&[Decoder]>,
    depth: usize,
    out: &mut Decoded,
    budget: &mut usize,
) {
    // Fast path: one pass over the whole chunk per decoder; most chunks
    // contain nothing encoded and stop here.
    let runs = base64_runs(text);
    let has_b64 = !runs.is_empty();
    let has_pct = text.contains('%') && PERCENT.is_match(text);
    let has_esc = text.contains('\\') && ESCAPE.is_match(text);
    if !(has_b64 || has_pct || has_esc) {
        return;
    }
    let starts: Vec<usize> = std::iter::once(0)
        .chain(text.match_indices('\n').map(|(i, _)| i + 1))
        .collect();
    let line_idx = |offset: usize| starts.partition_point(|&s| s <= offset) - 1;
    let line_at = |i: usize| {
        let end = starts.get(i + 1).map_or(text.len(), |e| e - 1);
        &text[starts[i]..end]
    };
    let mut next = Decoded::default();
    let mut emit = |i: usize, seg: String, dec: Decoder, next: &mut Decoded| {
        if *budget == 0 || line_at(i).contains(IGNORE_MARKER) {
            return;
        }
        if seg.len() > *budget {
            *budget = 0;
            return;
        }
        *budget -= seg.len();
        let orig = map.map_or(i + 1, |m| m.get(i).copied().unwrap_or(1));
        let dec = outer.and_then(|d| d.get(i).copied()).unwrap_or(dec);
        next.push(&seg, orig, dec);
    };
    for (start, end) in runs {
        if let Some(s) = decode_base64(&text[start..end]) {
            emit(line_idx(start), s, Decoder::Base64, &mut next);
        }
    }
    let mut lines_with =
        |re: &Regex, f: &dyn Fn(&str) -> Option<String>, dec: Decoder, next: &mut Decoded| {
            let mut last = usize::MAX;
            for m in re.find_iter(text) {
                let i = line_idx(m.start());
                if i == last {
                    continue;
                }
                last = i;
                if let Some(s) = f(line_at(i)) {
                    emit(i, s, dec, next);
                }
            }
        };
    if has_pct {
        lines_with(
            &PERCENT,
            &|l| {
                percent_encoding::percent_decode_str(l)
                    .decode_utf8()
                    .ok()
                    .filter(|s| s != l)
                    .map(|s| s.into_owned())
            },
            Decoder::Url,
            &mut next,
        );
    }
    if has_esc {
        lines_with(&ESCAPE, &unescape, Decoder::Escape, &mut next);
    }
    if next.is_empty() {
        return;
    }
    out.text.push_str(&next.text);
    out.line_map.extend_from_slice(&next.line_map);
    out.decoders.extend_from_slice(&next.decoders);
    if depth < MAX_DEPTH {
        decode_into(
            &next.text,
            Some(&next.line_map),
            Some(&next.decoders),
            depth + 1,
            out,
            budget,
        );
    }
}

/// Byte ranges of base64 / base64url runs worth decoding: one pass, no
/// regex. A run is kept when it is [`MIN_B64`]..=[`MAX_B64`] long (plus
/// `=` padding) and mixes upper case, lower case and digits - base64 of
/// text practically always does, while identifiers (snake_case, CamelCase)
/// and most words do not.
fn base64_runs(text: &str) -> Vec<(usize, usize)> {
    const UP: u8 = 1;
    const LOW: u8 = 2;
    const DIGIT: u8 = 4;
    const OTHER: u8 = 8;
    static CLASS: [u8; 256] = {
        let mut t = [0u8; 256];
        let mut i = 0;
        while i < 256 {
            let c = i as u8;
            t[i] = if c.is_ascii_uppercase() {
                UP
            } else if c.is_ascii_lowercase() {
                LOW
            } else if c.is_ascii_digit() {
                DIGIT
            } else if matches!(c, b'+' | b'/' | b'_' | b'-') {
                OTHER
            } else {
                0
            };
            i += 1;
        }
        t
    };
    let bytes = text.as_bytes();
    let class = |i: usize| CLASS[bytes[i] as usize];
    let mut out = Vec::new();
    // Invariant: `i` is 0 or follows a byte outside the alphabet. A run of
    // MIN_B64 must cover byte `i + MIN_B64 - 1`, so probing it lets most
    // short tokens be skipped without looking at them.
    let mut i = 0;
    while i + MIN_B64 <= bytes.len() {
        let probe = i + MIN_B64 - 1;
        if class(probe) == 0 {
            i = probe + 1;
            continue;
        }
        let mut start = probe;
        while start > i && class(start - 1) != 0 {
            start -= 1;
        }
        let mut end = probe + 1;
        while end < bytes.len() && class(end) != 0 {
            end += 1;
        }
        if end - start >= MIN_B64 {
            let seen = bytes[start..end]
                .iter()
                .fold(0u8, |acc, b| acc | CLASS[*b as usize]);
            let mut stop = end;
            while stop < bytes.len() && stop - end < 2 && bytes[stop] == b'=' {
                stop += 1;
            }
            if end - start <= MAX_B64 && seen & (UP | LOW | DIGIT) == UP | LOW | DIGIT {
                out.push((start, stop));
            }
        }
        i = end + 1;
    }
    out
}

/// Decode a base64 / base64url run when the result looks like text.
fn decode_base64(run: &str) -> Option<String> {
    let body = run.trim_end_matches('=');
    if body.len() < MIN_B64 {
        return None;
    }
    if body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let url = body.contains(['-', '_']);
    if url && body.contains(['+', '/']) {
        return None;
    }
    let engine = if url {
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        &base64::engine::general_purpose::STANDARD_NO_PAD
    };
    // Lengths of 1 mod 4 are never valid; trim one char (runs may be glued
    // to a following identifier character).
    let body = if body.len() % 4 == 1 {
        &body[..body.len() - 1]
    } else {
        body
    };
    let bytes = engine.decode(body).ok()?;
    let s = String::from_utf8(bytes).ok()?;
    looks_like_text(&s).then_some(s)
}

/// Mostly printable ASCII / whitespace, and not trivially short.
fn looks_like_text(s: &str) -> bool {
    if s.len() < 8 {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ' || *c == '\n' || *c == '\t' || *c == '\r')
        .count();
    printable * 100 >= s.chars().count() * 95
}

/// Resolve `\uXXXX`, `\xNN` and `\/` escapes. `None` when nothing changes.
fn unescape(line: &str) -> Option<String> {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.char_indices().peekable();
    let mut changed = false;
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let rest = &line[i + 1..];
        let (decoded, skip) = if let Some(h) = rest.strip_prefix('u').and_then(|r| r.get(..4)) {
            (u32::from_str_radix(h, 16).ok().and_then(char::from_u32), 5)
        } else if let Some(h) = rest.strip_prefix('x').and_then(|r| r.get(..2)) {
            (u8::from_str_radix(h, 16).ok().map(char::from), 3)
        } else if rest.starts_with('/') {
            (Some('/'), 1)
        } else {
            (None, 0)
        };
        match decoded {
            Some(d) => {
                out.push(d);
                changed = true;
                for _ in 0..skip {
                    chars.next();
                }
            }
            None => out.push(c),
        }
    }
    changed.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn kubernetes_secret_values_are_decoded_onto_their_lines() {
        let text = format!(
            "apiVersion: v1\nkind: Secret\ndata:\n  user: {}\n  password: {}\n",
            b64("service-account-admin"),
            b64("s3cr3t-password-value-123")
        );
        let d = decode(&text);
        assert!(d.text.contains("service-account-admin"), "{}", d.text);
        assert!(d.text.contains("s3cr3t-password-value-123"));
        assert_eq!(d.line_map, vec![4, 5]);
        assert!(d.decoders.iter().all(|x| *x == Decoder::Base64));
    }

    #[test]
    fn nested_base64_is_decoded_but_binary_and_hashes_are_not() {
        let inner = b64("token=abcdefghijklmnopqrstuvwxyz0123");
        let text = format!("x: {}\n", b64(&format!("{{\"auth\":\"{inner}\"}}")));
        let d = decode(&text);
        assert!(
            d.text.contains("token=abcdefghijklmnopqrstuvwxyz0123"),
            "{}",
            d.text
        );
        // sha256 hex, an identifier, and random bytes produce nothing.
        let noise = format!(
            "{}\nsome_very_long_identifier_name_here\n{}\n",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            base64::engine::general_purpose::STANDARD.encode([
                0u8, 159, 146, 150, 1, 2, 3, 250, 251, 252, 0, 7, 8, 9, 10, 255, 254, 253
            ])
        );
        assert!(decode(&noise).is_empty(), "{}", decode(&noise).text);
    }

    #[test]
    fn url_and_escape_sequences() {
        let d = decode("u=https%3A%2F%2Fuser%3Apass%40db.example.com\n");
        assert_eq!(d.text, "u=https://user:pass@db.example.com\n");
        assert_eq!(d.decoders, vec![Decoder::Url]);
        let d = decode("{\"k\": \"https:\\/\\/x\\u0040y\"}\n");
        assert_eq!(d.text, "{\"k\": \"https://x@y\"}\n");
        assert!(decode("plain text, nothing encoded\n").is_empty());
    }

    #[test]
    fn ignore_marker_and_budget() {
        let line = format!(
            "{} # {IGNORE_MARKER}\n",
            b64("a secret value that is ignored")
        );
        assert!(decode(&line).is_empty());
        let big = format!("{}\n", b64(&"A1b2C3d4 ".repeat(5000))).repeat(200);
        assert!(decode(&big).text.len() <= MAX_DECODED);
    }
}
