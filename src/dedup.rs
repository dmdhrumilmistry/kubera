//! Repeated changes in git history are scanned once.
//!
//! The same file change often appears in many commits: cherry-picks,
//! rebased or copied branches, vendored code added on several branches,
//! forks scanned together by `scan repos`. Git prints the old and new blob
//! ids of every file diff (`index <old>..<new>`), and with a fixed diff
//! algorithm the added lines (and their line numbers) depend on those two
//! blobs only, so a change whose pair of blobs was already scanned is not
//! scanned again.
//!
//! Findings are still reported once, at the **first commit that introduced
//! the change**: the oldest occurrence in `git rev-list` order (ties: the
//! smallest path), whatever order the parallel workers met them in. Output is
//! therefore deterministic and the same with any `-j`.
//!
//! Only file changes that produced findings, or whose scan is still in
//! flight, are kept in checkpoints ([`crate::checkpoint`]), so a resumed scan
//! reports exactly what an uninterrupted one would. Changes that produced no
//! findings need no bookkeeping: seeing one again after a resume just scans
//! it again.
//!
//! [`Results`] remembers what scanning each change produced. It can be
//! shared by the repositories of one `scan repos` run (forks and mirrors
//! share most of their history), while each repository keeps its own
//! [`History`], so every repository still reports its own findings with its
//! own commits.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::checkpoint::{Saved, SavedChange};
use crate::finding::{Finding, Location};
use crate::sources::Chunk;

/// Most changes a [`Results`] remembers (about 32 bytes each, plus the
/// findings): beyond this, new changes are scanned without being
/// remembered. The cache only saves work, so this never changes results.
const MAX_RESULTS: usize = 1 << 20;

/// What scanning each change produced, shared by the repositories of one
/// run.
#[derive(Default)]
pub struct Results {
    inner: Mutex<ResultsInner>,
}

#[derive(Default)]
struct ResultsInner {
    /// Nothing found (nearly every change).
    clean: HashSet<u128>,
    found: HashMap<u128, Arc<Vec<Finding>>>,
}

impl std::fmt::Debug for Results {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = self.inner.lock().unwrap();
        write!(
            f,
            "Results({} clean, {} with findings)",
            r.clean.len(),
            r.found.len()
        )
    }
}

impl Results {
    fn get(&self, id: u128) -> Option<Arc<Vec<Finding>>> {
        let r = self.inner.lock().unwrap();
        if r.clean.contains(&id) {
            return Some(Arc::default());
        }
        r.found.get(&id).cloned()
    }

    fn insert(&self, id: u128, found: &Arc<Vec<Finding>>) {
        let mut r = self.inner.lock().unwrap();
        if r.clean.len() + r.found.len() >= MAX_RESULTS {
            return;
        }
        if found.is_empty() {
            r.clean.insert(id);
        } else {
            r.found.insert(id, found.clone());
        }
    }
}

/// Where a change was seen: the commit's index in rev-list order (larger
/// is older) and the chunk's location (line 0).
#[derive(Clone)]
struct Occurrence {
    order: usize,
    location: Location,
}

impl Occurrence {
    /// Older commit first; within one commit, the smallest path.
    fn better_than(&self, other: &Occurrence) -> bool {
        (self.order, std::cmp::Reverse(&self.location.path))
            > (other.order, std::cmp::Reverse(&other.location.path))
    }
}

enum Slot {
    /// Scanned, nothing found: further occurrences are skipped.
    Clean,
    Open(Box<Open>),
}

struct Open {
    best: Occurrence,
    /// `None` until a scan finished (in flight, or restored from a
    /// checkpoint taken while it was in flight).
    findings: Option<Arc<Vec<Finding>>>,
    scanning: bool,
}

/// Repeated changes of one repository's history scan.
pub struct History<'a> {
    order: HashMap<&'a str, usize>,
    slots: Mutex<HashMap<u128, Slot>>,
    /// Shared with the other repositories of the run, if any (within one
    /// repository, `slots` already knows every change).
    shared: Option<Arc<Results>>,
}

impl<'a> History<'a> {
    /// `commits`: every commit of the scan in rev-list order (newest first,
    /// including commits a checkpoint already finished). `shared`: results
    /// to share with other repositories of the run.
    pub fn new(commits: &'a [String], shared: Option<Arc<Results>>) -> Self {
        Self {
            order: commits
                .iter()
                .enumerate()
                .map(|(i, c)| (c.as_str(), i))
                .collect(),
            slots: Mutex::new(HashMap::new()),
            shared,
        }
    }

    /// Findings of `chunk` to report right away. A change seen before
    /// returns nothing (its findings are reported once, by
    /// [`History::into_findings`]); chunks without a known change are just
    /// scanned.
    pub fn scan(&self, chunk: &Chunk, scan: impl Fn(&Chunk) -> Vec<Finding>) -> Vec<Finding> {
        let found = chunk.content_id.zip(
            chunk
                .location
                .commit
                .as_deref()
                .and_then(|c| self.order.get(c)),
        );
        let Some((id, &order)) = found else {
            return scan(chunk);
        };
        let here = Occurrence {
            order,
            location: Location {
                line: 0,
                ..chunk.location.clone()
            },
        };
        {
            let mut slots = self.slots.lock().unwrap();
            match slots.get_mut(&id) {
                Some(Slot::Clean) => return Vec::new(),
                Some(Slot::Open(open)) => {
                    if here.better_than(&open.best) {
                        open.best = here;
                    }
                    if open.findings.is_some() || open.scanning {
                        return Vec::new();
                    }
                    open.scanning = true;
                }
                None => {
                    slots.insert(
                        id,
                        Slot::Open(Box::new(Open {
                            best: here,
                            findings: None,
                            scanning: true,
                        })),
                    );
                }
            }
        }
        let found = match &self.shared {
            Some(r) => r.get(id).unwrap_or_else(|| {
                let f = Arc::new(scan(chunk));
                r.insert(id, &f);
                f
            }),
            None => Arc::new(scan(chunk)),
        };
        let mut slots = self.slots.lock().unwrap();
        if found.is_empty() {
            slots.insert(id, Slot::Clean);
        } else if let Some(Slot::Open(open)) = slots.get_mut(&id) {
            open.findings = Some(found);
            open.scanning = false;
        }
        Vec::new()
    }

    /// Changes with findings, and those still being scanned, for a
    /// checkpoint. Findings are relabelled to the best occurrence so far.
    pub fn snapshot(&self) -> Vec<SavedChange> {
        let slots = self.slots.lock().unwrap();
        let mut out: Vec<SavedChange> = slots
            .iter()
            .filter_map(|(id, slot)| match slot {
                Slot::Clean => None,
                Slot::Open(open) => Some(SavedChange {
                    id: format!("{id:032x}"),
                    order: open.best.order,
                    location: open.best.location.clone(),
                    findings: open.findings.as_ref().map(|f| {
                        f.iter()
                            .map(|x| Saved::from(&relabel(x, &open.best)))
                            .collect()
                    }),
                }),
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Continue from a checkpoint. `rehydrate` turns saved findings back
    /// into findings (it drops those of detectors no longer loaded).
    pub fn restore(&self, saved: Vec<SavedChange>, rehydrate: impl Fn(Saved) -> Option<Finding>) {
        let mut slots = self.slots.lock().unwrap();
        for s in saved {
            let Ok(id) = u128::from_str_radix(&s.id, 16) else {
                continue;
            };
            let findings = s
                .findings
                .map(|f| Arc::new(f.into_iter().filter_map(&rehydrate).collect::<Vec<_>>()));
            slots.insert(
                id,
                Slot::Open(Box::new(Open {
                    best: Occurrence {
                        order: s.order,
                        location: s.location,
                    },
                    findings,
                    scanning: false,
                })),
            );
        }
    }

    /// Findings of every repeated change, each at its first occurrence.
    pub fn into_findings(self) -> Vec<Finding> {
        let slots = self.slots.into_inner().unwrap();
        let mut out = Vec::new();
        for slot in slots.into_values() {
            if let Slot::Open(open) = slot
                && let Some(found) = &open.findings
            {
                out.extend(found.iter().map(|f| relabel(f, &open.best)));
            }
        }
        out
    }
}

/// `f` as found at `at`: same text and line, `at`'s commit and path.
fn relabel(f: &Finding, at: &Occurrence) -> Finding {
    let mut f = f.clone();
    f.location = Location {
        line: f.location.line,
        decoder: f.location.decoder.take(),
        ..at.location.clone()
    };
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn template() -> crate::template::Template {
        crate::template::parse(
            "id: t\nname: T\ndetect:\n  keywords: [t_]\n  patterns:\n    - name: token\n      regex: 't_[a-z]{8}'\n",
            "test",
        )
        .unwrap()
    }

    fn chunk(id: u128, commit: &str, path: &str) -> Chunk {
        Chunk {
            text: "t_abcdefgh".into(),
            location: Location {
                path: Some(path.into()),
                commit: Some(commit.into()),
                ..Default::default()
            },
            line_map: None,
            content_id: Some(id),
        }
    }

    #[test]
    fn each_change_is_scanned_once_and_reported_at_its_oldest_commit() {
        let t = template();
        let commits: Vec<String> = ["c3", "c2", "c1"].iter().map(|s| s.to_string()).collect();
        let scans = AtomicUsize::new(0);
        let scan = |c: &Chunk| {
            scans.fetch_add(1, Ordering::Relaxed);
            let mut loc = c.location.clone();
            loc.line = 7;
            if c.content_id == Some(2) {
                Vec::new()
            } else {
                vec![Finding::new(&t, Default::default(), loc)]
            }
        };
        let h = History::new(&commits, None);
        // Met newest first; c1 is the oldest commit; in c2 two paths.
        for (id, commit, path) in [
            (1, "c3", "a"),
            (1, "c2", "z"),
            (1, "c2", "b"),
            (2, "c3", "x"),
            (2, "c1", "x"),
        ] {
            assert!(h.scan(&chunk(id, commit, path), scan).is_empty());
        }
        // No id, or a commit outside the scan: scanned and reported as is.
        let mut plain = chunk(9, "elsewhere", "p");
        assert_eq!(h.scan(&plain, scan).len(), 1);
        plain.content_id = None;
        assert_eq!(h.scan(&plain, scan).len(), 1);
        assert_eq!(scans.load(Ordering::Relaxed), 4);
        let snap = h.snapshot();
        assert_eq!(snap.len(), 1, "clean changes are not checkpointed");
        let found = h.into_findings();
        assert_eq!(found.len(), 1);
        let loc = &found[0].location;
        assert_eq!(
            (loc.commit.as_deref(), loc.path.as_deref(), loc.line),
            (Some("c2"), Some("b"), 7)
        );

        // A resumed scan continues with the checkpointed best occurrence,
        // and an older one still wins.
        let h = History::new(&commits, None);
        h.restore(snap, |s| Some(Finding::new(&t, s.secret, s.location)));
        assert!(h.scan(&chunk(1, "c1", "q"), scan).is_empty());
        assert_eq!(
            scans.load(Ordering::Relaxed),
            4,
            "restored changes are not rescanned"
        );
        let found = h.into_findings();
        assert_eq!(found[0].location.commit.as_deref(), Some("c1"));
        assert_eq!(found[0].location.line, 7);
    }

    #[test]
    fn in_flight_changes_are_checkpointed_and_rescanned_after_resume() {
        let t = template();
        let commits: Vec<String> = ["c2", "c1"].iter().map(|s| s.to_string()).collect();
        let h = History::new(&commits, None);
        // Simulate a scan in flight: the first worker never finishes, a
        // second one records an older occurrence meanwhile.
        h.slots.lock().unwrap().insert(
            5,
            Slot::Open(Box::new(Open {
                best: Occurrence {
                    order: 0,
                    location: chunk(5, "c2", "a").location,
                },
                findings: None,
                scanning: true,
            })),
        );
        assert!(h.scan(&chunk(5, "c1", "a"), |_| unreachable!()).is_empty());
        let snap = h.snapshot();
        assert!(snap[0].findings.is_none());
        let h = History::new(&commits, None);
        h.restore(snap, |s| Some(Finding::new(&t, s.secret, s.location)));
        let scan = |c: &Chunk| vec![Finding::new(&t, Default::default(), c.location.clone())];
        assert!(h.scan(&chunk(5, "c2", "a"), scan).is_empty());
        let found = h.into_findings();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].location.commit.as_deref(), Some("c1"));
    }

    #[test]
    fn shared_results_skip_scans_in_other_repositories() {
        let t = template();
        let shared = Arc::new(Results::default());
        let scans = AtomicUsize::new(0);
        let scan = |c: &Chunk| {
            scans.fetch_add(1, Ordering::Relaxed);
            vec![Finding::new(&t, Default::default(), c.location.clone())]
        };
        let a: Vec<String> = vec!["a1".into()];
        let b: Vec<String> = vec!["b1".into()];
        let ha = History::new(&a, Some(shared.clone()));
        let hb = History::new(&b, Some(shared.clone()));
        ha.scan(&chunk(1, "a1", "f"), scan);
        hb.scan(&chunk(1, "b1", "f"), scan);
        assert_eq!(scans.load(Ordering::Relaxed), 1);
        // Each repository reports the finding with its own commit.
        assert_eq!(ha.into_findings()[0].location.commit.as_deref(), Some("a1"));
        assert_eq!(hb.into_findings()[0].location.commit.as_deref(), Some("b1"));
    }
}
