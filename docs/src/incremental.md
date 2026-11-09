# Incremental and mass scanning

## Scan only what changed

```bash
kubera scan git . --state .kubera-state.json --fail
```

The state file records, per repository, the tip of every branch and tag at the **last scan that passed**. The next run scans exactly the commits that were never scanned:

```text
git log <current tips of all refs> ^<tips recorded at the last passing scan>
```

This one revision range covers every case without per-branch bookkeeping:

| Situation | What gets scanned |
|---|---|
| New commits on `main` | only those commits |
| New branch forked from `main` | only the branch's own commits |
| Merge of an already-scanned branch | nothing new (its commits are reachable from old tips) |
| Force-push / deleted branch | vanished tips are ignored; scanning falls back to everything not reachable from the remaining tips |
| Nothing changed | nothing; the run takes milliseconds (see [benchmarks](benchmarks.md)) |

### When the baseline moves

The baseline only advances when the scan **passes**: no findings remain after allowlists and result filters. A leak is therefore reported on every run until it is fixed (history rewritten) or allowlisted. It can't silently drop out of view after one red build. Use `--state-policy always` to advance regardless, for example in a reporting-only job.

The state file is written atomically with mode `0600` and contains only refs and commit ids, never secrets.

### Pinning a starting point

Without a state file, `--since-commit <rev>` scans `<rev>..HEAD` (or `<rev>..<branch>`), and `--max-depth <n>` limits the number of commits (a remote clone is then shallow).

## Mass scanning

```bash
export GH_TOKEN=...
kubera scan repos --github-org acme --token-env GH_TOKEN \
  --cache-dir ~/.cache/kubera --state ~/.cache/kubera/state.json \
  --repo-concurrency 8 --verify --only-verified -f sarif > acme.sarif
```

| Source | Flag |
|---|---|
| GitHub organization / user | `--github-org ORG`, `--github-user USER` |
| GitLab group (with subgroups) | `--gitlab-group GROUP` |
| Bitbucket Cloud workspace | `--bitbucket-workspace WS` (`--token-user` for app passwords) |
| Self-hosted GitHub Enterprise / GitLab | `--api-url https://ghe.example.com/api/v3` |
| Explicit lists | positional URLs/paths, `--repo-list FILE` (one per line, `#` comments) |

Forks and archived repositories are skipped unless `--include-forks` / `--include-archived`; `--limit N` caps the run.

### Cost model

1. **First run:** every repository is cloned once (bare) into `--cache-dir`.
2. **Later runs:** each mirror is updated with `git fetch --prune`, which downloads only new objects. With `--state`, only never-scanned commits are read.

Network, disk I/O and CPU scale with **what changed** since the last passing scan, not with the size of the organization. Repositories are processed `--repo-concurrency` at a time, and each one's file diffs are scanned in parallel. A failure in one repository is reported and doesn't stop the others.

### Rate limiting

API discovery is rate-limit aware on all three forges:

- `Retry-After` on 429/403/503 is always honoured.
- Primary limits (`x-ratelimit-remaining: 0` on GitHub, `ratelimit-remaining: 0` on GitLab) wait until the advertised reset.
- When the remaining budget drops to the last couple of requests, Kubera pauses **before** hitting the limit.
- Server errors and dropped connections are retried with exponential backoff and jitter.
- A wait longer than `--max-rate-wait` (default 900 s) fails fast with the reset time instead of stalling a CI job.

Pagination follows `Link: rel="next"` (GitHub, GitLab) or `next` (Bitbucket) **only to the same host**, so the token can never be sent elsewhere. Clones use the same token through an origin-scoped header (see [Remote repositories](remote.md)), never on the command line.

### Scheduling

A nightly job that only reports new leaks:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/kubera
    key: kubera-${{ github.run_id }}
    restore-keys: kubera-
- run: kubera scan repos --github-org acme --token-env GH_TOKEN --cache-dir ~/.cache/kubera --state ~/.cache/kubera/state.json --fail
  env:
    GH_TOKEN: ${{ secrets.ORG_READ_TOKEN }}
```
