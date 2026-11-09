//! Input sources. Every source turns its input into [`Chunk`]s of text.

pub mod fs;
pub mod git;

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
