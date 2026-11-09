//! Scan pipeline: sources -> detection engine -> filter -> (verify).

use std::collections::HashSet;
use std::sync::Mutex;

use rayon::prelude::*;

use crate::config::Filter;
use crate::detect::{Engine, line_of};
use crate::finding::Finding;
use crate::sources::Chunk;

/// Turn the candidates of one chunk into findings.
pub fn scan_chunk(engine: &Engine, filter: &Filter, chunk: &Chunk) -> Vec<Finding> {
    let mut out = Vec::new();
    for c in engine.scan(&chunk.text) {
        let det = &engine.detectors[c.detector];
        let line_idx = line_of(&chunk.text, c.offset);
        let line = match &chunk.line_map {
            Some(map) => map.get(line_idx - 1).copied().unwrap_or(line_idx),
            None => line_idx,
        };
        let mut loc = chunk.location.clone();
        loc.line = line;
        let f = Finding::new(&det.template, c.parts, loc);
        if filter.allowed(&f.fingerprint, f.secret.values()) {
            continue;
        }
        out.push(f);
    }
    out
}

/// (fingerprint, path, line, commit)
type DedupKey = (String, Option<String>, usize, Option<String>);

/// Collects findings from many chunks (possibly in parallel), de-duplicating
/// identical (secret, location) pairs.
#[derive(Default)]
pub struct Collector {
    findings: Mutex<Vec<Finding>>,
    seen: Mutex<HashSet<DedupKey>>,
}

impl Collector {
    pub fn push(&self, found: Vec<Finding>) {
        if found.is_empty() {
            return;
        }
        let mut seen = self.seen.lock().unwrap();
        let mut all = self.findings.lock().unwrap();
        for f in found {
            let key = (
                f.fingerprint.clone(),
                f.location.path.clone(),
                f.location.line,
                f.location.commit.clone(),
            );
            if seen.insert(key) {
                all.push(f);
            }
        }
    }

    pub fn into_findings(self) -> Vec<Finding> {
        let mut v = self.findings.into_inner().unwrap();
        v.sort_by(|a, b| {
            (&a.location.path, a.location.line, &a.detector).cmp(&(
                &b.location.path,
                b.location.line,
                &b.detector,
            ))
        });
        v
    }
}

/// Scan a list of files in parallel.
pub fn scan_files(
    engine: &Engine,
    filter: &Filter,
    files: &[std::path::PathBuf],
    collector: &Collector,
) {
    files.par_iter().for_each(|p| {
        if let Some(chunk) = crate::sources::fs::read_chunk(p) {
            collector.push(scan_chunk(engine, filter, &chunk));
        }
    });
}
