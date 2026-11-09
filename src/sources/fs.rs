//! Filesystem source.

use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

use super::{Chunk, is_binary};
use crate::config::Filter;
use crate::finding::{Location, SourceKind};

pub const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Enumerate files under `root`. Symlinks are never followed (a scan must not
/// escape the requested tree) and `.git` directories are skipped (use the git
/// source to scan history).
pub fn list_files(root: &Path, filter: &Filter, max_size: u64) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if root.is_file() {
        out.push(root.to_path_buf());
        return Ok(out);
    }
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !(e.file_type().is_dir() && e.file_name() == ".git"));
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("warning: {e}");
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
        if filter.path_excluded(rel) {
            continue;
        }
        match entry.metadata() {
            Ok(m) if m.len() <= max_size => out.push(entry.into_path()),
            Ok(_) => {}
            Err(e) => eprintln!("warning: {e}"),
        }
    }
    Ok(out)
}

/// Read a file into a chunk; `None` for binary or unreadable files.
pub fn read_chunk(path: &Path) -> Option<Chunk> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("warning: {}: {e}", path.display());
            return None;
        }
    };
    if is_binary(&data) {
        return None;
    }
    Some(Chunk {
        text: String::from_utf8_lossy(&data).into_owned(),
        location: Location {
            source: SourceKind::Filesystem,
            path: Some(path.display().to_string()),
            ..Default::default()
        },
        line_map: None,
    })
}
