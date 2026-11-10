# Scanning files, git history and stdin

This page covers the core scan sources and the options every scan shares: verification, output formats, suppressions and exit codes.

```bash
kubera scan fs <PATH>...       # files and directories
kubera scan git <REPO>         # full history of a local path or remote URL
kubera scan stdin              # anything piped in
kubera scan staged             # what the next commit adds
```

| Also | |
|---|---|
| `kubera scan image <ref>` | Container images: see [Container images](containers.md) |
| `kubera scan repos --github-org ORG` | Whole organizations: see [Large, incremental and mass scans](incremental.md) |
| `kubera scan git . --state FILE` | Only commits added since the last passing scan |
| `kubera scan github owner/repo` | Issues, PRs, comments, Actions logs, wikis and gists: see [GitHub](github.md) |
| `kubera scan bucket s3://bucket` | S3, S3-compatible and GCS buckets: see [Cloud storage buckets](buckets.md) |
| `kubera scan k8s` | A live Kubernetes cluster: see [Kubernetes clusters](kubernetes.md) |
| `kubera scan staged` | Staged changes, for the [pre-commit hook](hooks.md) |

Add `-i` to any scan to browse the results in the [interactive TUI](tui.md) instead of printing them.

## Filesystem

```bash
kubera scan fs . src/ ~/.aws/credentials
```

- Directories are walked recursively. **Symlinks are not followed**, so a scan cannot escape the tree you pass.
- `.git` directories are skipped (use `scan git` for history).
- [Archives](#archives) (zip, jar, tar.gz, ...) are opened and their entries scanned.
- Other binary files (a NUL byte in the first 8 KiB) are skipped.
- Files larger than `--max-file-size` (default 10 MiB) are skipped.
- Dependency directories and lockfiles are skipped by [default](#default-excludes).
- `.gitignore` is *not* honoured on purpose, because ignored files such as `.env` are where secrets usually live. Use `--exclude-path` or `exclude_paths` in the [config](configuration.md) instead.

## Git history

```bash
kubera scan git .
kubera scan git https://github.com/org/repo.git
kubera scan git . --branch main --since-commit 4b825dc --max-depth 500
```

Kubera runs `git log -p` and scans only the **added** lines of each commit. It finds secrets that were committed and later deleted, and reports the commit, author, date, file and original line number.

History is scanned in parallel: Kubera lists the commits, splits them into partitions and runs one `git log` per CPU (`-j N` to choose). Files larger than `--max-file-size` are not diffed at all, and `--exclude-path` globs are handed to git, so skipped paths cost nothing. Long scans can be made resumable with `--checkpoint FILE`. See [Large repositories](incremental.md#large-repositories).

Remote repositories (HTTPS, SSH, `git@host:org/repo`, `github.com/org/repo`, ...) are cloned bare into a temporary directory that is removed afterwards. Private repositories, SSH and web links to findings are covered in [Remote repositories](remote.md).

| Flag | Meaning |
|---|---|
| `--branch <ref>` | Scan only this ref (default: all refs). |
| `--since-commit <rev>` | Scan only commits after `<rev>` (`<rev>..HEAD` or `<rev>..<branch>`). |
| `--max-depth <n>` | Scan at most `n` commits (remote clones are shallow). |
| `--checkpoint <FILE>` | Make the scan resumable, see [Resumable scans](incremental.md#resumable-scans). |
| `--token-env <VAR>` | Token for private HTTPS repositories, see [Remote repositories](remote.md). |
| `--token-user <USER>` | Username sent with the token (default `x-access-token`). |

## Stdin

```bash
cat build.log | kubera scan stdin
kubectl get secrets -A -o yaml | kubera scan stdin --verify
```

## Staged changes

```bash
kubera scan staged --fail
```

Scans only the lines the next commit adds (`git diff --cached`). This is what the [pre-commit hook](hooks.md) runs. Findings have no commit, since the commit does not exist yet.

## Decoders

Kubernetes Secrets, Docker `config.json` auths, JWT payloads and many config systems store credentials encoded. Before scanning, Kubera decodes:

- **base64** and **base64url**,
- **percent-encoding** (`%2F`, ...),
- **escapes**: `\uXXXX`, `\xXX` and `\/`,

nested up to 2 levels (for example base64 inside base64). The decoded text of a chunk is scanned as one piece, so a multi-part secret stored as two base64 values still pairs up. Decoding is bounded: candidate runs are length-limited, output must look like text, and the decoded size per chunk is capped.

A finding from decoded text carries `location.decoder` (`base64`, `url` or `escape`) and points at the line of the original text. Pretty output shows it as `decoded from base64`:

```bash
kubectl get secret -n prod api-keys -o yaml | kubera scan stdin
```

```text
╭─ CRITICAL  GitHub Token ────────────────────────────────────────────────────
│ secret.yaml:4
│ decoded from base64
│
│ token        ghp_********Uo
╰─ github-token · bc0458ecc5e4611e9dde21f8
```

Decoding adds about 13% to detection on a large source tree (378 MB of Rust crates, see [Benchmarks](benchmarks.md#decoding)) and next to nothing on git history. Turn it off with `--no-decode`.

## Archives

Filesystem, [container image](containers.md) and [bucket](buckets.md) scans open archives and scan the text inside:

- the **zip** family: zip, jar, war, ear, apk, aar, whl, nupkg, vsix, docx, xlsx, pptx, ...
- **tar**, **gzip** and **tar.gz**,
- nested up to 4 levels (a jar inside a war inside a tar.gz).

Archives are recognised by their magic bytes, so a renamed archive is still opened. Nothing is extracted to disk, so hostile entry paths (`../`, absolute paths, symlinks) only ever appear in findings.

A finding inside an archive carries `location.entry`. Pretty output and SARIF show `path!/entry`:

```text
╭─ CRITICAL  GitHub Token ────────────────────────────────────────────────────
│ lib/app.jar!/config/application.yml:1
```

Limits are enforced on the bytes actually decompressed, never on sizes the archive claims, so zip bombs waste only a bounded amount of work:

| Limit | Value |
|---|---|
| Archive file | 512 MiB, independent of `--max-file-size` (a file above `--max-file-size` is only read when its name looks like an archive, e.g. `.jar`) |
| Text entry | `--max-file-size` |
| Nested archive (buffered in memory) | 64 MiB |
| Decompressed per top-level archive | 1 GiB and 100,000 entries |
| Nesting | 4 levels |

## Default excludes

Third-party dependency trees and lockfiles are large, generated, and rarely hold your own credentials, so they are skipped by default:

| | Paths |
|---|---|
| Dependency directories | `node_modules`, `bower_components`, `vendor`, `.venv`, `site-packages`, `Pods` |
| Lockfiles | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb`, `Cargo.lock`, `go.sum`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `composer.lock`, `Gemfile.lock`, `Podfile.lock`, `packages.lock.json`, `gradle.lockfile`, `flake.lock` |

They match at any depth (`**/node_modules/**`, `**/yarn.lock`, ...). To scan them too, pass `--no-default-excludes` or set `default_excludes: false` in [`.kubera.yaml`](configuration.md).

Minified bundles (`*.min.js`) and source maps are deliberately **not** excluded: frontend builds are a common place for real keys to leak.

## Common options

| Flag | Meaning |
|---|---|
| `--verify` | Verify candidates against their platform. Each candidate is sent only to the endpoint its template names. |
| `--only-verified` | Report only live secrets (implies `--verify`). |
| `--results <kinds>` | Comma list of `verified`, `unknown`, `invalid`, `unverifiable`, `unverified`. |
| `-f, --format` | `pretty` (default), `json`, `jsonl`, `sarif` or `html`. |
| `--show-secrets` | Print secrets unmasked. |
| `--fail` | Exit with code **183** when findings are reported. |
| `--exclude-path <glob>` | Skip paths matching the glob, relative to the scan root (repeatable). |
| `--max-file-size <bytes>` | Skip larger files (in git history, larger files are not diffed at all). |
| `--no-default-excludes` | Also scan dependency directories and lockfiles, see [Default excludes](#default-excludes). |
| `--no-decode` | Do not decode base64, URL-encoded or escaped text, see [Decoders](#decoders). |
| `-j, --jobs <n>` | Parallel `git log` workers for history (default 0: one per CPU). |
| `--concurrency <n>` | Parallel verification requests (default 8). |
| `--verify-cache[=FILE]` | Reuse verification results of earlier runs, see [Verification cache](#verification-cache). |
| `--verify-cache-ttl <TTL>` / `--no-verify-cache` | How long cached results are reused (`live=1h,invalid=24h,unknown=0`); turn the cache off. |
| `--baseline <FILE>` / `--no-baseline` | Use another baseline file, or ignore it, see [Baselines and triage](triage.md). |
| `--update-baseline` | Record every finding in the baseline file and exit 0. |
| `--notify-env <VAR>` | Alert the webhook URL in this environment variable, see [Alerts](alerts.md). |
| `--notify-secret-env <VAR>` / `--notify-on <live\|all>` | Sign webhook payloads; choose which findings alert. |
| `-i, --interactive` | Browse results in the TUI. |

These global flags work with every command:

| Flag | Meaning |
|---|---|
| `-t, --templates <path>` | Load extra templates from a file or directory (repeatable). A template with the same id replaces the builtin one. |
| `--no-builtin` | Use only your own templates. |
| `--detectors <ids>` | Run only these detectors. |
| `--exclude-detectors <ids>` | Never run these detectors. |
| `--config <file>` | Config file (default `./.kubera.yaml` if present). |
| `--timeout <secs>` | HTTP timeout. |

## Verification results

| Status | Meaning |
|---|---|
| `verified` | The platform accepted the credential. **Treat it as an incident.** |
| `invalid` | The platform rejected it (revoked, expired or fake). |
| `unknown` | Inconclusive: network error, rate limit or an unexpected response. The message explains why. |
| `unverifiable` | The detector has no verifier (for example private keys). |

Identical secrets found in several places are verified **once**.

### Verification cache

Scheduled CI jobs and nightly [mass scans](incremental.md#mass-scanning) find the same secrets again and again, and `--verify` would send each one to its vendor every time. `--verify-cache` keeps the results between runs and reuses them while they are fresh:

```bash
kubera scan git . --verify --verify-cache                     # ~/.cache/kubera/verify.json
kubera scan repos --github-org acme --token-env GH_TOKEN --verify --verify-cache=/ci/cache/verify.json
kubera scan git . --verify --verify-cache-ttl live=15m,invalid=7d
```

| Status | Reused for (default) | Why |
|---|---|---|
| `verified` (live) | **1 hour** | Short, so a key revoked during incident response shows up as revoked on the next hourly run |
| `invalid` | **24 hours** | A revoked, expired or fake credential practically never comes back to life |
| `unknown` | **not cached** | Network errors and rate limits are usually gone by the next run |
| `unverifiable` | not cached | No request is sent for these anyway |

`--verify-cache-ttl` takes any subset of `live=`, `invalid=` and `unknown=` with durations such as `90s`, `15m`, `1h` or `7d`; a bare duration (`6h`) sets both `live` and `invalid`, and `0` turns caching off for that status. It implies `--verify-cache`. `--no-verify-cache` ignores a cache enabled in [`.kubera.yaml`](configuration.md#verification-cache).

A reused result is always marked, so nobody mistakes it for a fresh check: JSON has `"cached": true` and `"checked_at"` (when the platform was asked) in `verification`, pretty output and the HTML report add a `cached` line (`result from 2026-11-10T09:12:44Z, no request sent`), SARIF says `(verification: verified, cached)`, and the summary counts them (`◆ kubera 3 finding(s)  ● 1 live · ✓ 2 invalid · 3 cached`). Kubera also prints how many results were reused and how many secrets were sent.

Entries are keyed by [fingerprint](configuration.md#fingerprints) and by a hash of the template's verifier, so editing a template verifies its secrets again. The file holds the status, the message and the extracted details (account names, scopes), never a secret value; see [Security](security.md#handling-secrets). Several processes can share one file: each run merges its results with what is on disk, and entries older than 30 days are dropped.

`kubera verify`, `analyze` and `rotate` always ask the platform. In the [TUI](tui.md#verifying-findings), <kbd>V</kbd> and `--verify` use the cache and <kbd>v</kbd> re-checks the selected finding.

What to do with each status, from rotating a live secret to marking an invalid one: [After a scan: triage and response](workflow.md).

## Suppressing findings and false positives

- Add `kubera:ignore` anywhere on the line.
- Add the finding's `fingerprint` to `allowlist.fingerprints` in `.kubera.yaml`.
- Add a regex to `allowlist.secrets` (matched against each secret part).
- Exclude paths with `--exclude-path` or `exclude_paths`.
- Record it in the baseline: `--update-baseline`, or `x` / `m` in the TUI. See [Baselines and triage](triage.md).

## Output formats

- **pretty** - human-readable, coloured when stdout is a terminal (respects `NO_COLOR`). A summary line goes to stderr.
- **json** - an array of findings.
- **jsonl** - one finding per line, for streaming into other tools.
- **sarif** - SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. See [CI integration](ci.md).
- **html** - a self-contained interactive report, see below.

A JSON finding looks like this:

```json
{
  "detector": "aws-access-key",
  "name": "AWS Access Key",
  "platform": "AWS",
  "severity": "critical",
  "fingerprint": "2f0c51a8d6e94b1c7a3e5d90",
  "secret": {
    "access_key_id": "AKIAEXAMPLEKEYID0000",
    "secret_access_key": "wJal********EY"
  },
  "redacted": true,
  "location": { "source": "filesystem", "path": "infra/.env", "line": 7 },
  "verification": {
    "status": "verified",
    "details": { "ARN": "arn:aws:iam::123456789012:user/ci", "Account": "123456789012" }
  }
}
```

Parts that a template marks `secret: false` (such as an AWS access key id) are never masked. Findings from decoded text add `"decoder": "base64"` to `location`, and findings inside archives add `"entry": "config/application.yml"`.

### HTML report

```bash
kubera scan git . --verify -f html > kubera-report.html
```

One file with everything inline, to open in a browser or attach to a ticket:

- summary counts per status (click one to filter), text search, and severity and detector filters,
- expandable rows with location, commit, link, verification details and fingerprint,
- light and dark themes, following the system setting.

The page is built for hostile input, since paths, commit authors and API responses come from what was scanned. Every value is rendered as text, never as HTML, and only `https://` links become anchors. A Content-Security-Policy blocks every network request and allows only the page's own script, pinned by its SHA-256 hash. So the report works offline and cannot phone home.

<div class="kubera-callout warning">
<p class="kubera-callout-title">--show-secrets</p>

Secrets are redacted unless the scan ran with `--show-secrets`. The page then shows a visible warning: treat that file as a secret. The same goes for any output produced with `--show-secrets`: never attach it to a ticket or keep it in CI logs.

</div>

## Exit codes

| Command | Codes |
|---|---|
| `scan` | `0` success, `183` findings with `--fail`, `1` error |
| `verify` | `0` verified, `2` invalid, `3` unknown or unverifiable, `1` error |
| `analyze` | `0` verified, `2` not verified, `1` error |
| `rotate` | `0` success or dry run, `2` executed but incomplete, `1` error or aborted |
| `templates validate` / `test` | `0` all pass, `1` any failure |
