# Benchmarks

Measured with [`scripts/bench.py`](https://github.com/dmdhrumilmistry/kubera/blob/main/scripts/bench.py), which anyone can re-run. Every scan runs **without verification**, so there is no network involved, and times are the **median of 5 runs after a warm-up** (page cache warm).

**Machine:** 4 vCPU Intel Xeon @ 2.10 GHz, 15 GiB RAM, Linux. **Kubera:** 0.1.0 release build (11 MB static binary), 64 detectors. These results predate parallel history scanning; see [below](#parallel-history-scanning) for 0.2.0.

## Results

| Corpus | Size | Time | Peak memory | Findings |
|---|---|---:|---:|---:|
| Filesystem: `~/.cargo/registry/src` (real Rust crates) | 333 MB, 23,557 files | **0.38 s** (~875 MB/s) | 38 MiB | 17 |
| Git history: TruffleHog repository (`75259fdd`) | 3,000 commits | **2.2 s** | 133 MiB | 215 |
| Container image: `alpine:3.20` pulled from a registry | 3 MB | ~2 s (network-bound) | | 0 |

The 215 git findings are TruffleHog's own test fixtures and documentation examples. On a cold page cache (first read from this VM's network disk), the 333 MB filesystem scan took about 21 s: it is I/O-bound, and the scanner itself is not the bottleneck.

### Incremental re-scans

With `--state`, a re-scan only reads commits that were never scanned:

| Repository | Full history | Re-scan, nothing new | Speedup |
|---|---:|---:|---:|
| TruffleHog (3,000 commits) | 2.16 s | **0.046 s** | **47×** |

This is the steady state of a CI job or a nightly org-wide scan: cost tracks what changed, not repository size. Combined with `--cache-dir` for mass scans, only new git objects are fetched as well (see [Incremental and mass scanning](incremental.md)).

### Parallel history scanning

Kubera 0.2.0 splits the commits to scan into partitions and runs one `git log` per CPU (see [Large repositories](incremental.md#parallel-history)).

**Repository:** [rust-lang/cargo](https://github.com/rust-lang/cargo), 24,445 commits, full history, no verification. **Machine:** 4 vCPUs, Linux, release build.

| Scan | Time | Findings |
|---|---:|---|
| One `git log` (before parallel scanning) | 10.6 s | baseline |
| One `git log` per CPU (`-j 0`, the default) | **3.7 s** (2.9× faster) | identical |
| Same, plus `--exclude-path` on a heavy directory | **2.5 s** | not compared (narrower scope) |

The speedup comes from using every CPU for git's own diff work, which dominates history scans. Excluded paths are handed to git as pathspecs, so it never diffs them.

`scan repos` divides the CPUs between the repositories it scans at the same time. With fewer repositories than `--repo-concurrency` (default 4), it used to divide them by 4 anyway: cargo and a fork of it took 11.3 s with one `git log` each, and take **6.6 s** now that each gets half of the CPUs.

### Repeated changes

History scans scan a file change that repeats in several commits (same old and new blob) only once and report it at its first commit (see [Repeated changes](incremental.md#repeated-changes)). Full history, no verification, 4 vCPUs, best of 5 interleaved runs:

| Repository | Commits | Repeated file changes | Before | After | Findings |
|---|---:|---:|---:|---:|---|
| rust-lang/cargo | 24,445 | 3,943 of 63,179 (6%) | 3.71 s | 3.71 s | same 17 |
| Synthetic: 1,500 real `.rs` files (22 MB) added on `main` and again on 8 copied branches | 13,509 | 89% | 1.38 s | **1.04 s** | none in either |
| Synthetic: 2,000 small edits on `main` and again on 8 copied branches | 18,009 | 89% | 1.00 s | 0.93 s | 36 → 4 (same 4 secrets, each at its first commit) |
| `scan repos` with cargo and a fork of it | 2 × 24,445 | 100% of the fork | 12.0 s | 11.8 s | same 2 × 17 |

On cargo, only 235 of 16,548 non-merge commits consist of repeated changes alone, and git's own diff work (about 10 s of CPU out of 12.7 s for the whole scan) is not skipped, so the gain there is within noise. It pays off where Kubera's work dominates: large files repeated across branches or repositories. Skipping git's diff work for repeated commits would need an extra `git log --raw` pass over the whole history first, which costs more on cargo (about 1 s of CPU) than the 1.4% of commits it could skip.

### Decoding

[Decoders](scanning.md#decoders) look at every byte of every file for base64 runs, percent-encoding and escapes. Measured in memory on one thread, so that disk and scheduling noise drop out, over `~/.cargo/registry/src` (31,795 files, 378 MB):

| | Detection alone | Decoding | Overhead |
|---|---:|---:|---:|
| 0.2.0 | 2.45 s | 0.53 s | 22% |
| After 0.2.0 | 2.45 s | **0.31 s** | **13%** |

The decoded output and the findings are identical, byte for byte, on every file of the corpus. What changed:

- The line index of a file is built only when something actually decodes. Most files hold a base64-looking run (a hash, a long identifier) that turns out not to decode to text, and indexing all of their lines used to cost more than finding the runs.
- Percent-encoding and escapes are found with one `memchr` pass instead of two regex passes.
- base64 runs are found 64 bytes at a time: each block is classified into a bitmask with branch-free code the compiler vectorizes, and only blocks holding 24 or more consecutive base64 characters are walked run by run.

Scanning the decoded text again is cheap (0.02 s here): only 1,438 files decode to anything.

### Detection on a planted corpus

`bench.py` generates 17 realistic fake credentials (AWS pair, GitHub, GitLab, Slack, Stripe, npm, SendGrid, OpenAI, Anthropic, Hugging Face, DigitalOcean, PyPI, Shopify, Linear, Postman, Databricks, RSA private key) next to decoys that commonly trip scanners: AWS documentation keys, `${VAR}` / `<your-key>` placeholders, `xxxx` fillers, SHA-1/SHA-256 hashes, UUIDs, base64 blobs and npm lockfile integrity hashes.

| | Planted secrets found | Decoy false positives |
|---|---:|---:|
| Kubera | **17 / 17** | **0** |

Caveat: the planted formats follow vendor documentation, and Kubera's templates were written from the same documentation. Treat this as a regression check on precision, not an independent accuracy study.

## Comparing with TruffleHog and Gitleaks

`scripts/bench.py` benchmarks `trufflehog` and `gitleaks` too, with equivalent no-verification flags, whenever they are on `PATH`:

```bash
cargo build --release
python3 scripts/bench.py --fs ~/src --git ~/src/some-repo --out results.md
```

They were not installed in the environment these numbers come from, so no competitor figures are published here. Run the script on your own corpus; numbers depend heavily on the machine and the corpus.

## Capabilities

From each project's documentation at the time of writing. Corrections are welcome.

| | Kubera | TruffleHog | Gitleaks |
|---|---|---|---|
| License | MIT | AGPL-3.0 | MIT |
| Live verification | ✅ (81 of 89 templates) | ✅ | ❌ |
| Credential analysis (scopes / resources) | ✅ | ✅ (`analyze`, subset of types) | ❌ |
| Automated **rotation / revocation** | ✅ dry-run plans; API rotation for AWS, GitLab, SendGrid, Twilio, Cloudflare; API revocation for GitHub, Slack, Okta, Buildkite, Doppler, Discord | ❌ (links to manual guides) | ❌ |
| Add a platform **with verification** without writing code | ✅ YAML templates (verify, analyze, rotate, tests) | Custom regex detectors with a webhook verifier | Regex rules (TOML), no verification |
| Incremental scans of new commits | ✅ state file gated on passing scans | `--since-commit` | `--log-opts` / baseline file |
| Org-wide scans (GitHub, GitLab, Bitbucket) | ✅ with rate-limit handling and mirror cache | ✅ | ❌ |
| Container images | ✅ registry (daemonless), Docker, tarballs | ✅ | ❌ |
| Interactive TUI | ✅ | ✅ | ❌ |
| MCP server for AI assistants | ✅ secrets never reach the model | | |
| Android / Termux | ✅ tested in CI | | |
