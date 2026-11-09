//! Detection engine: compiles templates into matchers and scans text.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result};
use regex::Regex;

use crate::template::{Pattern, Template};

/// Comment marker that suppresses findings on the same line.
pub const IGNORE_MARKER: &str = "kubera:ignore";

/// Upper bound of part combinations examined per detector and chunk.
const MAX_COMBINATIONS: usize = 256;

struct CompiledPattern {
    name: String,
    regex: Regex,
    group: GroupSel,
    min_entropy: Option<f64>,
    exclude: Vec<Regex>,
    captures: Vec<String>,
}

enum GroupSel {
    Index(usize),
    Named(String),
}

pub struct CompiledDetector {
    pub template: Arc<Template>,
    patterns: Vec<CompiledPattern>,
}

/// A single candidate secret found in a chunk of text.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Index into [`Engine::detectors`].
    pub detector: usize,
    /// Part name -> value (includes extra named captures).
    pub parts: BTreeMap<String, String>,
    /// Byte offset of the earliest part.
    pub offset: usize,
}

pub struct Engine {
    pub detectors: Vec<CompiledDetector>,
    keywords: AhoCorasick,
    /// keyword index -> detectors using it.
    keyword_owners: Vec<Vec<usize>>,
}

impl CompiledPattern {
    fn new(p: &Pattern) -> Result<Self> {
        let regex = Regex::new(&p.regex)?;
        let group = match p.group {
            Some(g) => GroupSel::Index(g),
            None if regex.capture_names().flatten().any(|n| n == p.name) => {
                GroupSel::Named(p.name.clone())
            }
            None if regex.captures_len() > 1 => GroupSel::Index(1),
            None => GroupSel::Index(0),
        };
        Ok(Self {
            name: p.name.clone(),
            regex,
            group,
            min_entropy: p.min_entropy,
            exclude: p
                .exclude
                .iter()
                .map(|e| Regex::new(e))
                .collect::<Result<_, _>>()?,
            captures: p.captures.clone(),
        })
    }
}

struct PartMatch {
    value: String,
    start: usize,
    extra: Vec<(String, String)>,
}

impl CompiledDetector {
    pub fn new(t: Template) -> Result<Self> {
        let patterns = t
            .detect
            .patterns
            .iter()
            .map(CompiledPattern::new)
            .collect::<Result<_>>()
            .with_context(|| format!("compiling detector {}", t.id))?;
        Ok(Self {
            template: Arc::new(t),
            patterns,
        })
    }

    fn matches(&self, p: &CompiledPattern, text: &str) -> Vec<PartMatch> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for caps in p.regex.captures_iter(text) {
            let m = match &p.group {
                GroupSel::Index(i) => caps.get(*i),
                GroupSel::Named(n) => caps.name(n),
            };
            let Some(m) = m else { continue };
            let value = m.as_str();
            if value.is_empty() {
                continue;
            }
            if let Some(min) = p.min_entropy
                && shannon_entropy(value) < min
            {
                continue;
            }
            if p.exclude.iter().any(|r| r.is_match(value)) {
                continue;
            }
            if line_has_ignore_marker(text, m.start()) {
                continue;
            }
            if !seen.insert((value.to_string(), m.start())) {
                continue;
            }
            let extra = p
                .captures
                .iter()
                .filter_map(|c| caps.name(c).map(|v| (c.clone(), v.as_str().to_string())))
                .collect();
            out.push(PartMatch {
                value: value.to_string(),
                start: m.start(),
                extra,
            });
        }
        out
    }

    fn scan(&self, idx: usize, text: &str, out: &mut Vec<Candidate>) {
        let per_part: Vec<Vec<PartMatch>> = self
            .patterns
            .iter()
            .map(|p| self.matches(p, text))
            .collect();
        if per_part.iter().any(|v| v.is_empty()) {
            return;
        }
        let max_distance = self.template.detect.max_distance;
        let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();
        let mut combos = 0usize;
        // Iterative cartesian product with a proximity constraint.
        let mut stack: Vec<(usize, Vec<&PartMatch>)> = vec![(0, Vec::new())];
        while let Some((depth, chosen)) = stack.pop() {
            if depth == per_part.len() {
                combos += 1;
                if combos > MAX_COMBINATIONS {
                    break;
                }
                let key: Vec<String> = chosen.iter().map(|m| m.value.clone()).collect();
                if !seen.insert(key) {
                    continue;
                }
                let mut parts = BTreeMap::new();
                for (p, m) in self.patterns.iter().zip(&chosen) {
                    parts.insert(p.name.clone(), m.value.clone());
                    for (k, v) in &m.extra {
                        parts.insert(k.clone(), v.clone());
                    }
                }
                out.push(Candidate {
                    detector: idx,
                    parts,
                    offset: chosen.iter().map(|m| m.start).min().unwrap_or(0),
                });
                continue;
            }
            for m in per_part[depth].iter().rev() {
                let lo = chosen.iter().map(|c| c.start).fold(m.start, usize::min);
                let hi = chosen.iter().map(|c| c.start).fold(m.start, usize::max);
                if hi - lo > max_distance {
                    continue;
                }
                let mut next = chosen.clone();
                next.push(m);
                stack.push((depth + 1, next));
            }
        }
    }
}

impl Engine {
    pub fn new(templates: Vec<Template>) -> Result<Self> {
        let detectors: Vec<CompiledDetector> = templates
            .into_iter()
            .map(CompiledDetector::new)
            .collect::<Result<_>>()?;
        let mut kw_index: BTreeMap<String, usize> = BTreeMap::new();
        let mut keyword_owners: Vec<Vec<usize>> = Vec::new();
        for (i, d) in detectors.iter().enumerate() {
            for k in &d.template.detect.keywords {
                let k = k.to_lowercase();
                let next = kw_index.len();
                let idx = *kw_index.entry(k).or_insert(next);
                if idx == keyword_owners.len() {
                    keyword_owners.push(Vec::new());
                }
                keyword_owners[idx].push(i);
            }
        }
        let mut words: Vec<(usize, String)> = kw_index.into_iter().map(|(k, i)| (i, k)).collect();
        words.sort();
        let keywords = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(words.iter().map(|(_, w)| w))?;
        Ok(Self {
            detectors,
            keywords,
            keyword_owners,
        })
    }

    /// Scan a chunk of text and return all candidates.
    pub fn scan(&self, text: &str) -> Vec<Candidate> {
        let mut active = vec![false; self.detectors.len()];
        let mut any = false;
        for m in self.keywords.find_overlapping_iter(text) {
            for &d in &self.keyword_owners[m.pattern().as_usize()] {
                active[d] = true;
                any = true;
            }
        }
        let mut out = Vec::new();
        if !any {
            return out;
        }
        for (i, d) in self.detectors.iter().enumerate() {
            if active[i] {
                d.scan(i, text, &mut out);
            }
        }
        out
    }
}

fn line_has_ignore_marker(text: &str, offset: usize) -> bool {
    let start = text[..offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = text[offset..]
        .find('\n')
        .map(|i| offset + i)
        .unwrap_or(text.len());
    text[start..end].contains(IGNORE_MARKER)
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// 1-based line number of a byte offset.
pub fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset.min(text.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template;

    fn engine(yaml: &str) -> Engine {
        Engine::new(vec![template::parse(yaml, "test").unwrap()]).unwrap()
    }

    const PAIR: &str = r#"
id: pair
name: Pair
detect:
  keywords: [kid_]
  max_distance: 64
  patterns:
    - name: id
      regex: '\b(kid_[a-z0-9]{6})\b'
    - name: secret
      regex: '\bsecret=([A-Za-z0-9]{12})\b'
      min_entropy: 3.0
      exclude: ['^EXAMPLE']
"#;

    #[test]
    fn pairs_parts_within_distance() {
        let e = engine(PAIR);
        let text = "kid_abc123 secret=Zq8Lw2Pm9Xa1\n";
        let c = e.scan(text);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].parts["id"], "kid_abc123");
        assert_eq!(c[0].parts["secret"], "Zq8Lw2Pm9Xa1");
    }

    #[test]
    fn rejects_far_apart_low_entropy_and_excluded() {
        let e = engine(PAIR);
        let far = format!("kid_abc123 {} secret=Zq8Lw2Pm9Xa1", "x".repeat(200));
        assert!(e.scan(&far).is_empty());
        assert!(e.scan("kid_abc123 secret=aaaaaaaaaaaa").is_empty());
        assert!(e.scan("kid_abc123 secret=EXAMPLE12345").is_empty());
        assert!(e.scan("secret=Zq8Lw2Pm9Xa1 only").is_empty());
    }

    #[test]
    fn honours_ignore_marker() {
        let e = engine(PAIR);
        assert!(
            e.scan("kid_abc123 secret=Zq8Lw2Pm9Xa1 # kubera:ignore")
                .is_empty()
        );
    }

    #[test]
    fn entropy_and_lines() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
        assert_eq!(line_of("a\nb\nc", 4), 3);
    }
}
