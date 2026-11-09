# Scanning

```bash
kubera scan fs <PATH>...       # files and directories
kubera scan git <REPO>         # full history of a local path or remote URL
kubera scan stdin              # anything piped in
```

## Filesystem

```bash
kubera scan fs . src/ ~/.aws/credentials
```

- Directories are walked recursively. **Symlinks are not followed**, so a scan cannot escape the tree you pass.
- `.git` directories are skipped (use `scan git` for history).
- Binary files (a NUL byte in the first 8 KiB) are skipped.
- Files larger than `--max-file-size` (default 10 MiB) are skipped.
- `.gitignore` is *not* honoured on purpose, because ignored files such as `.env` are where secrets usually live. Use `--exclude-path` or `exclude_paths` in the [config](configuration.md) instead.

## Git history

```bash
kubera scan git .
kubera scan git https://github.com/org/repo.git
kubera scan git . --branch main --since-commit 4b825dc --max-depth 500
```

Kubera runs `git log -p` and scans only the **added** lines of each commit. It finds secrets that were committed and later deleted, and reports the commit, author, date, file and original line number.

Remote URLs (`https://`, `ssh://`, `git://`, `git@`) are cloned bare into a temporary directory that is removed afterwards.

| Flag | Meaning |
|---|---|
| `--branch <ref>` | Scan only this ref (default: all refs). |
| `--since-commit <rev>` | Scan only commits after `<rev>` (`<rev>..HEAD` or `<rev>..<branch>`). |
| `--max-depth <n>` | Scan at most `n` commits. |

## Stdin

```bash
cat build.log | kubera scan stdin
kubectl get secrets -A -o yaml | kubera scan stdin --verify
```

## Common options

| Flag | Meaning |
|---|---|
| `--verify` | Verify candidates against their platform. Each candidate is sent only to the endpoint its template names. |
| `--only-verified` | Report only live secrets (implies `--verify`). |
| `--results <kinds>` | Comma list of `verified`, `unknown`, `invalid`, `unverifiable`, `unverified`. |
| `-f, --format` | `pretty` (default), `json`, `jsonl` or `sarif`. |
| `--show-secrets` | Print secrets unmasked. |
| `--fail` | Exit with code **183** when findings are reported. |
| `--exclude-path <glob>` | Skip paths matching the glob, relative to the scan root (repeatable). |
| `--max-file-size <bytes>` | Skip larger files. |
| `--concurrency <n>` | Parallel verification requests (default 8). |

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

## Suppressing findings

- Add `kubera:ignore` anywhere on the line.
- Add the finding's `fingerprint` to `allowlist.fingerprints` in `.kubera.yaml`.
- Add a regex to `allowlist.secrets` (matched against each secret part).
- Exclude paths with `--exclude-path` or `exclude_paths`.

## Output formats

- **pretty** - human-readable, coloured when stdout is a terminal (respects `NO_COLOR`). A summary line goes to stderr.
- **json** - an array of findings.
- **jsonl** - one finding per line, for streaming into other tools.
- **sarif** - SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. See [CI integration](ci.md).

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

Parts that a template marks `secret: false` (such as an AWS access key id) are never masked.

## Exit codes

| Command | Codes |
|---|---|
| `scan` | `0` success, `183` findings with `--fail`, `1` error |
| `verify` | `0` verified, `2` invalid, `3` unknown or unverifiable, `1` error |
| `analyze` | `0` verified, `2` not verified, `1` error |
| `rotate` | `0` success or dry run, `2` executed but incomplete, `1` error or aborted |
| `templates validate` / `test` | `0` all pass, `1` any failure |
