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

use std::cell::OnceCell;

use base64::Engine as _;

use crate::detect::IGNORE_MARKER;

/// Decoders applied to already decoded text (base64 inside base64, ...).
pub const MAX_DEPTH: usize = 2;
/// Shortest base64 run considered (shorter runs are mostly identifiers).
const MIN_B64: usize = 24;
/// Longest base64 run considered (whole embedded files are rare and slow).
const MAX_B64: usize = 64 * 1024;
/// Cap on decoded output per chunk.
const MAX_DECODED: usize = 4 * 1024 * 1024;

/// Offsets of percent-encoded bytes (`%` and two hex digits).
fn percent_at(bytes: &[u8]) -> impl Iterator<Item = usize> + '_ {
    memchr::memchr_iter(b'%', bytes).filter(|&i| hex_follows(bytes, i + 1, 2))
}

/// Offsets of the escapes [`unescape`] resolves: `\uXXXX`, `\xNN`, `\/`.
fn escapes_at(bytes: &[u8]) -> impl Iterator<Item = usize> + '_ {
    memchr::memchr_iter(b'\\', bytes).filter(|&i| escape_at(bytes, i))
}

/// `bytes[i]` is a backslash: does an escape [`unescape`] resolves start?
fn escape_at(bytes: &[u8], i: usize) -> bool {
    match bytes.get(i + 1) {
        Some(b'u') => hex_follows(bytes, i + 2, 4),
        Some(b'x') => hex_follows(bytes, i + 2, 2),
        Some(b'/') => true,
        _ => false,
    }
}

/// Whether `bytes` holds a percent-encoded byte / an escape, in one pass.
fn sequences(bytes: &[u8]) -> (bool, bool) {
    let (mut pct, mut esc) = (false, false);
    for i in memchr::memchr2_iter(b'%', b'\\', bytes) {
        if bytes[i] == b'%' {
            pct = pct || hex_follows(bytes, i + 1, 2);
        } else {
            esc = esc || escape_at(bytes, i);
        }
        if pct && esc {
            break;
        }
    }
    (pct, esc)
}

fn hex_follows(bytes: &[u8], at: usize, n: usize) -> bool {
    bytes
        .get(at..at + n)
        .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit))
}

/// Line starts of a text, indexed on first use: most chunks with a
/// candidate decode nothing, and indexing every line of every such file
/// used to cost more than finding the candidates.
struct LineIndex<'a> {
    text: &'a str,
    starts: OnceCell<Vec<usize>>,
}

impl<'a> LineIndex<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            starts: OnceCell::new(),
        }
    }

    fn starts(&self) -> &[usize] {
        self.starts.get_or_init(|| {
            std::iter::once(0)
                .chain(memchr::memchr_iter(b'\n', self.text.as_bytes()).map(|i| i + 1))
                .collect()
        })
    }

    /// 0-based line holding byte `offset`.
    fn index(&self, offset: usize) -> usize {
        self.starts().partition_point(|&s| s <= offset) - 1
    }

    /// End of line `i` (offset of its newline, or the text length).
    fn end(&self, i: usize) -> usize {
        self.starts().get(i + 1).map_or(self.text.len(), |e| e - 1)
    }

    fn line(&self, i: usize) -> &'a str {
        &self.text[self.starts()[i]..self.end(i)]
    }
}

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
    // Fast path: one cheap pass over the whole chunk per decoder; most
    // chunks contain nothing encoded and stop here.
    let bytes = text.as_bytes();
    let runs = base64_runs(text);
    let (has_pct, has_esc) = sequences(bytes);
    if runs.is_empty() && !has_pct && !has_esc {
        return;
    }
    let lines = LineIndex::new(text);
    let mut next = Decoded::default();
    let mut emit = |i: usize, seg: String, dec: Decoder, next: &mut Decoded| {
        if *budget == 0 || lines.line(i).contains(IGNORE_MARKER) {
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
            emit(lines.index(start), s, Decoder::Base64, &mut next);
        }
    }
    // Percent and escape decoding work on whole lines: decode each line
    // holding at least one sequence, once.
    let mut lines_with = |at: &mut dyn Iterator<Item = usize>,
                          f: &dyn Fn(&str) -> Option<String>,
                          dec: Decoder,
                          next: &mut Decoded| {
        let mut pos = 0;
        for o in at {
            if o < pos {
                continue;
            }
            let i = lines.index(o);
            pos = lines.end(i);
            if let Some(s) = f(lines.line(i)) {
                emit(i, s, dec, next);
            }
        }
    };
    if has_pct {
        lines_with(
            &mut percent_at(bytes),
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
        lines_with(
            &mut escapes_at(bytes),
            &unescape,
            Decoder::Escape,
            &mut next,
        );
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

const UP: u8 = 1;
const LOW: u8 = 2;
const DIGIT: u8 = 4;
const OTHER: u8 = 8;

/// Character class of every byte (0: outside the base64 / base64url
/// alphabet).
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

/// Bit `j` set when `block[j]` (at most 64 bytes) is in the base64 /
/// base64url alphabet. Written without tables or branches so the compiler
/// vectorizes it: this is the only part of base64 detection that touches
/// every byte.
fn alphabet_mask(block: &[u8]) -> u64 {
    let mut flags = [0u8; 64];
    for (f, &b) in flags.iter_mut().zip(block) {
        let letter = (b | 0x20).wrapping_sub(b'a') < 26;
        let digit = b.wrapping_sub(b'0') < 10;
        let other = b == b'+' || b == b'/' || b == b'_' || b == b'-';
        *f = (letter | digit | other) as u8;
    }
    let mut m = 0u64;
    let (words, _) = flags.as_chunks::<8>();
    for (k, c) in words.iter().enumerate() {
        let v = u64::from_le_bytes(*c);
        // Gathers the low bit of each byte into the top byte, in order.
        m |= (v.wrapping_mul(0x0102_0408_1020_4080) >> 56) << (8 * k);
    }
    m
}

/// Byte ranges of base64 / base64url runs worth decoding: one pass, no
/// regex. A run is kept when it is [`MIN_B64`]..=[`MAX_B64`] long (plus
/// `=` padding) and mixes upper case, lower case and digits - base64 of
/// text practically always does, while identifiers (snake_case, CamelCase)
/// and most words do not.
///
/// The text is classified 64 bytes at a time into a bitmask. A block with
/// no [`MIN_B64`] consecutive alphabet bytes (nearly all of them in source
/// code) costs a few bit operations; only blocks holding a long run, or
/// the end of one, are walked run by run.
fn base64_runs(text: &str) -> Vec<(usize, usize)> {
    const _: () = assert!(MIN_B64 == 24, "the run test below checks 24 bits");
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut emit = |start: usize, end: usize| {
        if end - start < MIN_B64 || end - start > MAX_B64 {
            return;
        }
        let seen = bytes[start..end]
            .iter()
            .fold(0u8, |acc, b| acc | CLASS[*b as usize]);
        if seen & (UP | LOW | DIGIT) != UP | LOW | DIGIT {
            return;
        }
        let mut stop = end;
        while stop < bytes.len() && stop - end < 2 && bytes[stop] == b'=' {
            stop += 1;
        }
        out.push((start, stop));
    };
    // Start of the run reaching the end of the previous block, if any.
    let mut open: Option<usize> = None;
    for (w, block) in bytes.chunks(64).enumerate() {
        let base = w * 64;
        let m = alphabet_mask(block);
        if m == u64::MAX {
            open.get_or_insert(base);
            continue;
        }
        // Bit j of `long`: bits j..j+24 of `m` are all set.
        let two = m & (m >> 1);
        let four = two & (two >> 2);
        let eight = four & (four >> 4);
        let sixteen = eight & (eight >> 8);
        let long = sixteen & (eight >> 16);
        if long == 0 {
            // Only a run carried in from the previous block can be long.
            if let Some(s) = open.take() {
                emit(s, base + m.trailing_ones() as usize);
            }
            if m >> 63 == 1 {
                open = Some(base + 64 - m.leading_ones() as usize);
            }
            continue;
        }
        // Walk every run of this block.
        let mut j = 0u32;
        while j < 64 {
            let rest = m >> j;
            match open {
                Some(s) => {
                    j += rest.trailing_ones();
                    if j >= 64 {
                        break;
                    }
                    emit(s, base + j as usize);
                    open = None;
                }
                None => {
                    let zeros = rest.trailing_zeros();
                    if zeros >= 64 - j {
                        break;
                    }
                    j += zeros;
                    open = Some(base + j as usize);
                }
            }
        }
    }
    if let Some(s) = open {
        emit(s, bytes.len());
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

    /// The definition [`base64_runs`] implements with bitmasks: every
    /// maximal run of alphabet bytes, filtered the same way.
    fn runs_reference(text: &str) -> Vec<(usize, usize)> {
        let b = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if CLASS[b[i] as usize] == 0 {
                i += 1;
                continue;
            }
            let start = i;
            while i < b.len() && CLASS[b[i] as usize] != 0 {
                i += 1;
            }
            let seen = b[start..i].iter().fold(0, |a, x| a | CLASS[*x as usize]);
            let mut stop = i;
            while stop < b.len() && stop - i < 2 && b[stop] == b'=' {
                stop += 1;
            }
            let len = i - start;
            if (MIN_B64..=MAX_B64).contains(&len) && seen & (UP | LOW | DIGIT) == UP | LOW | DIGIT {
                out.push((start, stop));
            }
        }
        out
    }

    #[test]
    fn base64_runs_match_the_definition_across_block_boundaries() {
        // Deterministic pseudo-random texts over a small alphabet, so runs
        // of every length start and end at every offset of a 64-byte block.
        let alphabet = b"aZ9+/_-= \n.%";
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for round in 0..400 {
            let len = 1 + (round * 7) % 700;
            // Mostly alphabet bytes, so that long runs are common.
            let text: String = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let r = (x % 100) as usize;
                    let i = if r < 92 { r % 7 } else { 7 + r % 5 };
                    alphabet[i] as char
                })
                .collect();
            assert_eq!(base64_runs(&text), runs_reference(&text), "{text:?}");
        }
        // Exact edges: 23 / 24 bytes, a run ending the text, one spanning
        // two blocks, one filling whole blocks, one longer than MAX_B64.
        let unit = "aB3";
        for (pad, len) in [
            (0, 23),
            (0, 24),
            (40, 24),
            (63, 30),
            (5, 64),
            (0, 128),
            (1, 200),
        ] {
            let run: String = unit.repeat(len).chars().take(len).collect();
            for tail in ["", " x", "=", "==", "===\n"] {
                let text = format!("{}{run}{tail}", " ".repeat(pad));
                assert_eq!(base64_runs(&text), runs_reference(&text), "{text:?}");
            }
        }
        let huge = "aB3".repeat(MAX_B64);
        assert!(base64_runs(&huge).is_empty());
        assert_eq!(base64_runs(&huge), runs_reference(&huge));
    }

    #[test]
    fn sequence_edges_lines_and_end_of_text() {
        // Truncated sequences at the end of the text are not sequences.
        assert!(decode("a=%4").is_empty());
        assert!(decode("a=\\u00").is_empty());
        assert!(decode("a=\\x4").is_empty());
        // Several sequences on a line decode the line once; a line with
        // only invalid ones is left alone; the last line needs no newline.
        let d = decode("x=%41%42\nplain %zz\ny=\\x41\\u0042\\/");
        assert_eq!(d.text, "x=AB\ny=AB/\n");
        assert_eq!(d.line_map, vec![1, 3]);
        assert_eq!(d.decoders, vec![Decoder::Url, Decoder::Escape]);
        // A base64 value that crosses a 64-byte block and ends the text.
        let text = format!("{}{}", " ".repeat(50), b64("password=hunter2-but-longer"));
        let d = decode(&text);
        assert_eq!(d.text, "password=hunter2-but-longer\n");
        assert_eq!(d.line_map, vec![1]);
    }
}
