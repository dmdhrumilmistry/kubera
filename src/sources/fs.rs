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
        let archive_ok = |len: u64| {
            len <= super::archive::DEFAULT_MAX_ARCHIVE_SIZE
                && super::archive::archive_name(&entry.file_name().to_string_lossy())
        };
        match entry.metadata() {
            Ok(m) if m.len() <= max_size || archive_ok(m.len()) => out.push(entry.into_path()),
            Ok(_) => {}
            Err(e) => eprintln!("warning: {e}"),
        }
    }
    Ok(out)
}

/// Read a file into chunks: its text, or the text entries of an archive
/// (see [`super::archive`]). Binary and unreadable files give nothing.
pub fn read_chunks(path: &Path, max_size: u64, filter: &Filter) -> Vec<Chunk> {
    match read_inner(path, max_size, filter) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: {}: {e:#}", path.display());
            Vec::new()
        }
    }
}

fn read_inner(path: &Path, max_size: u64, filter: &Filter) -> Result<Vec<Chunk>> {
    use super::archive;
    use std::io::Read;

    let location = Location {
        source: SourceKind::Filesystem,
        path: Some(path.display().to_string()),
        ..Default::default()
    };
    let mut file = std::fs::File::open(path)?;
    let mut head = Vec::with_capacity(512);
    (&mut file).take(512).read_to_end(&mut head)?;
    if let Some(kind) = archive::kind(&head) {
        let mut out = Vec::new();
        archive::walk(kind, file, archive::Limits::new(max_size), &mut |e| {
            if filter.path_excluded(Path::new(&e.path)) {
                return;
            }
            out.push(Chunk {
                text: e.text,
                location: Location {
                    entry: Some(e.path),
                    ..location.clone()
                },
                line_map: None,
            });
        })?;
        return Ok(out);
    }
    if file.metadata()?.len() > max_size {
        return Ok(Vec::new());
    }
    let mut data = head;
    file.read_to_end(&mut data)?;
    if is_binary(&data) {
        return Ok(Vec::new());
    }
    Ok(vec![Chunk {
        text: String::from_utf8_lossy(&data).into_owned(),
        location,
        line_map: None,
    }])
}
