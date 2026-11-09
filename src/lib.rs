//! Kubera: template driven secret detection, verification, analysis and
//! rotation.
//!
//! Architecture (see `docs/src/architecture.md`):
//!
//! ```text
//!  sources (fs / git / stdin)
//!        │  Chunk { text, location }
//!        ▼
//!  detect::Engine  ── keyword prefilter (Aho-Corasick) ─► per-template regex,
//!        │            entropy + exclude filters, multi-part pairing
//!        ▼
//!  config::Filter  ── path excludes, allowlisted fingerprints / secrets
//!        ▼
//!  verify (async, bounded concurrency, de-duplicated by fingerprint)
//!        ▼
//!  report (pretty / json / jsonl / sarif, secrets redacted by default)
//! ```
//!
//! `analyze` and `rotate` reuse the same template HTTP machinery
//! (`http`, `steps`) for a single credential.

pub mod analyze;
pub mod brand;
pub mod config;
pub mod detect;
pub mod finding;
pub mod forge;
pub mod http;
pub mod mass;
pub mod mcp;
pub mod render;
pub mod report;
pub mod rotate;
pub mod scan;
pub mod sources;
pub mod state;
pub mod steps;
pub mod template;
pub mod tui;
pub mod verify;
