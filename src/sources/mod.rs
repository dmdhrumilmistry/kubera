//! Input sources. Every source turns its input into [`Chunk`]s of text.

pub mod archive;
pub mod bitbucket;
pub mod bucket;
pub mod confluence;
pub mod dockerhub;
pub mod fs;
pub mod git;
pub mod github;
pub mod gitlab;
pub mod huggingface;
pub mod image;
pub mod jira;
pub mod kube;
pub mod package;
pub mod remote;
pub mod slack;

use crate::finding::Location;

/// A unit of text to scan.
pub struct Chunk {
    pub text: String,
    /// Location template; `line` is filled in per finding.
    pub location: Location,
    /// Optional mapping from 0-based line index within `text` to the real
    /// line number (used for git diffs where only added lines are kept).
    pub line_map: Option<Vec<usize>>,
}

/// Heuristic: treat data with a NUL byte in the first 8 KiB as binary.
pub fn is_binary(data: &[u8]) -> bool {
    data[..data.len().min(8192)].contains(&0)
}

/// What an API source gathered: text chunks to scan, plus git repositories
/// (wikis, snippets, gists) for the history scanner.
#[derive(Default)]
pub struct Collected {
    pub chunks: Vec<Chunk>,
    /// Git repositories to scan with the history scanner: (clone URL, label).
    pub git: Vec<(String, String)>,
    /// Non-fatal problems (e.g. a feature disabled, no access).
    pub warnings: Vec<String>,
}

/// A chunk of text from an API source. `link` is kept only when it is an
/// https URL (it comes from the API answer).
pub fn text_chunk(
    source: crate::finding::SourceKind,
    repository: &str,
    path: String,
    link: Option<&str>,
    text: String,
) -> Chunk {
    Chunk {
        text,
        location: Location {
            source,
            repository: Some(repository.to_string()),
            path: Some(path),
            link: link
                .filter(|l| l.starts_with("https://"))
                .map(str::to_string),
            ..Default::default()
        },
        line_map: None,
    }
}

/// Chunks of a CI log: escape codes removed, split at `max` bytes.
pub fn log_chunks(
    source: crate::finding::SourceKind,
    repository: &str,
    path: &str,
    link: Option<&str>,
    data: &[u8],
    max: usize,
) -> Vec<Chunk> {
    let text = strip_ansi(&String::from_utf8_lossy(data));
    split_text(&text, max)
        .into_iter()
        .map(|(text, map)| Chunk {
            line_map: map,
            ..text_chunk(source, repository, path.to_string(), link, text)
        })
        .collect()
}

/// A string field of a JSON object ("" when missing).
pub(crate) fn json_str<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

/// A numeric or string id field of a JSON object ("" when missing).
pub(crate) fn json_id(v: &serde_json::Value, key: &str) -> String {
    match v.get(key) {
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

/// Split a long text (a CI log) into chunks of at most `max` bytes at line
/// boundaries, each with a line map back to the line numbers of the whole
/// text. Short texts come back as one chunk without a map.
pub fn split_text(text: &str, max: usize) -> Vec<(String, Option<Vec<usize>>)> {
    if text.len() <= max {
        return vec![(text.to_string(), None)];
    }
    let mut out = Vec::new();
    let (mut cur, mut map) = (String::new(), Vec::new());
    for (i, line) in text.split_inclusive('\n').enumerate() {
        if !cur.is_empty() && cur.len() + line.len() > max {
            out.push((std::mem::take(&mut cur), Some(std::mem::take(&mut map))));
        }
        // A single line longer than `max` is cut (bounded memory per chunk).
        let mut end = line.len().min(max);
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        cur.push_str(&line[..end]);
        map.push(i + 1);
    }
    if !cur.is_empty() {
        out.push((cur, Some(map)));
    }
    out
}

/// Remove ANSI escape sequences (colours, cursor control) that CI runners
/// put in logs: they would glue `m` or `K` to the start of a token.
pub fn strip_ansi(s: &str) -> String {
    use std::sync::LazyLock;
    static ANSI: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])")
            .expect("valid regex")
    });
    ANSI.replace_all(s, "").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_text_is_split_with_line_maps() {
        let text = "a\nbb\nccc\ndddd\n";
        assert_eq!(split_text(text, 100), vec![(text.to_string(), None)]);
        let parts = split_text(text, 6);
        assert_eq!(
            parts,
            vec![
                ("a\nbb\n".to_string(), Some(vec![1, 2])),
                ("ccc\n".to_string(), Some(vec![3])),
                ("dddd\n".to_string(), Some(vec![4])),
            ]
        );
    }

    #[test]
    fn ansi_codes_are_removed() {
        assert_eq!(
            strip_ansi("\x1b[32;1m$ echo hi\x1b[0;m\x1b[0K done"),
            "$ echo hi done"
        );
    }
}
