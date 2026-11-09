# Architecture

```text
            ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 sources    │  fs (rayon)  │  │ git log -p   │  │    stdin     │
            └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
                   └────────── Chunk { text, location, line_map } ─┐
                                                                    ▼
 detect     ┌───────────────────────────────────────────────────────────┐
            │ Aho-Corasick over all keywords → set of active detectors   │
            │ per active detector: regex → group → entropy → exclude     │
            │ → ignore marker → multi-part pairing (max_distance)        │
            └──────────────────────────────┬────────────────────────────┘
                                           ▼
 filter     path excludes · allowlisted fingerprints / secret regexes
                                           ▼
 collect    de-duplicate (fingerprint, path, line, commit), sort
                                           ▼
 verify     unique fingerprints → async requests, bounded concurrency
                                           ▼
 report     redact → pretty | json | jsonl | sarif
```

`scan::run` drives this pipeline for every front end: the CLI prints the result, and the TUI runs it on a worker thread with progress callbacks. `verify`, `analyze` and `rotate` on a single credential reuse the same HTTP layer and step runner.

## Modules

| Module | Responsibility |
|---|---|
| `template` | Schema (`schema.rs`), loading (builtin via `include_dir`, user paths, overrides), static validation, sample runner. |
| `render` | `{{ expr \| filter }}` engine; strict about unknown variables and filters. |
| `detect` | Compiles templates into an `Engine`; keyword prefilter, regex matching, entropy and multi-part pairing. |
| `sources` | `fs` (walk, size and binary filters), `git` (hardened `git log -p` parser that maps added lines back to their line numbers; bare clones), `remote` (URL forms, credential stripping, scoped token headers, forge web links). |
| `scan` | Chunk → findings, the concurrent `Collector`, and `run`, the end-to-end pipeline with progress events. |
| `config` | `.kubera.yaml`, path and allowlist `Filter`. |
| `http` | Prepares template requests (rendering, body encoding, auth), sends them (https-only, no redirects, capped bodies), matchers, extractors, JSON paths, SigV4. |
| `verify` | Single and batch verification with de-duplication; masks secrets in messages. |
| `steps` | Shared step runner and redacted request descriptions for dry runs. |
| `analyze` / `rotate` | Flows built on `verify` + `steps`; rotation planning, gating and output preservation. |
| `finding` / `report` | Data model, fingerprints, redaction and output formats. |
| `tui` | Interactive UI: `app` (state machine, background tasks over a channel), `ui` (responsive rendering), `theme`. |
| `brand` | Logo, gold palette and banner shared by the CLI and TUI (truecolor with xterm-256 fallback). |

## Performance notes

- Keyword prefiltering means most chunks are scanned once by a single automaton, and regexes run only for detectors whose keyword occurs.
- Files are scanned in parallel with rayon. Git chunks are batched (256 file-diffs at a time) and scanned in parallel while `git log` keeps streaming.
- Multi-part pairing is capped at 256 combinations per detector per chunk, which bounds the worst case on adversarial input.
- Verification is de-duplicated by fingerprint and runs with `--concurrency` in-flight requests.

## Testing

- Unit tests sit next to the code, including the official AWS SigV4 `get-vanilla` test vector.
- `tests/flows.rs` runs verify, analyze and rotate against a local mock HTTP server: dry runs send nothing, steps run in order, partial failures preserve new secrets, dead credentials are refused, redirects aren't followed and plain http is rejected.
- `tests/cli.rs` runs the binary end to end on temp directories and temp git repositories, including a `file://` remote clone, web links, and a mock git server that checks a private-repo token arrives as a scoped header.
- `src/tui` tests render every screen into an in-memory terminal (desktop and phone widths) and drive it with key events, including a real background scan.
- `examples/screenshots.rs` renders the documentation images from the real TUI and CLI code (`make screenshots`).
- Every builtin template's samples run as part of `cargo test`.
