# Large, incremental and mass scans

This page covers huge repositories, scans that only read new commits, and scanning every repository of a GitHub, GitLab or Bitbucket organization.

## Large repositories

```bash
kubera scan git ~/src/monorepo                                    # one git log per CPU
kubera scan git ~/src/monorepo -j 2                               # leave some CPU for others
kubera scan git ~/src/monorepo --exclude-path "third_party/**"    # skip what you don't own
kubera scan git ~/src/monorepo --checkpoint monorepo.ckpt         # resumable
```

### Parallel history

A single `git log -p` uses one CPU, and on a big repository git, not the detectors, is the bottleneck. Kubera lists the commits to scan with `git rev-list`, splits them into partitions, and runs one `git log` per CPU over them. Each worker parses its process's output while git is still producing it. The findings are the same as a sequential scan.

`-j N` sets the number of workers (default `0`: one per CPU). It applies to every history scan: `scan git`, `scan repos`, and the wikis and gists of `scan github`. In `scan repos`, the CPUs are divided between the repositories scanned at the same time (`--repo-concurrency`, or fewer when fewer repositories are listed), so the machine is neither oversubscribed nor left idle.

Measured on [rust-lang/cargo](https://github.com/rust-lang/cargo) (24,445 commits) on 4 vCPUs:

| Full history scan | Time |
|---|---:|
| Before parallel scanning (one `git log`) | 10.6 s |
| Parallel, default `-j 0` | **3.7 s** |
| Parallel, with `--exclude-path` on a heavy directory | **2.5 s** |

See [Benchmarks](benchmarks.md#parallel-history-scanning) for the setup.

### Repeated changes

The same file change often appears in many commits: cherry-picks onto release branches, rebased or copied branches that are kept around, vendored code added on several branches. Git prints the old and new blob ids of every file diff, and with a fixed diff algorithm the added lines depend on those two blobs only. Kubera therefore scans each pair of blobs **once**:

- A secret in a repeated change is reported **once**, at the **first commit that introduced it**: the oldest commit in `git rev-list` order, whichever worker met it first. Output stays deterministic and identical for any `-j`.
- No secret is lost: the skipped chunks have exactly the text of the scanned one. A secret that is also added by a *different* change (another file, other neighbouring lines) is still reported there too.
- [Checkpoints](#resumable-scans) remember the repeated changes that produced findings, so a resumed scan reports exactly what an uninterrupted one would.
- In [`scan repos`](#mass-scanning), the scan results are shared between the repositories of a run (forks, mirrors and repositories that vendor the same code), while every repository still reports its own findings with its own commits, so per-repository state and baselines are unaffected.

What it saves is Kubera's own work on the repeated text (detection and decoding); git still produces every diff, and on most repositories git is the larger cost. Measured on 4 vCPUs (see [Benchmarks](benchmarks.md#repeated-changes)):

| Repository | Repeated file changes | Before | After |
|---|---:|---:|---:|
| rust-lang/cargo (24,445 commits) | 6% | 3.71 s | 3.71 s |
| 9 copies of a branch adding 1,500 real source files (22 MB) | 89% | 1.38 s | **1.04 s** (-25%) |
| 9 copies of a branch of 2,000 small edits | 89% | 1.00 s | 0.93 s |

Nothing is stored between runs: [`--state`](#scan-only-what-changed) already keeps later runs from reading old commits at all.

### Skip junk early

The cheapest diff is the one git never produces:

- Files larger than `--max-file-size` (default 10 MiB) are **not diffed at all**: Kubera sets git's `core.bigFileThreshold`, so git skips the diff instead of Kubera discarding it afterwards.
- Your `--exclude-path` and `exclude_paths` globs are **handed to git as exclude pathspecs**, so excluded files are never diffed either.
- The [default excludes](scanning.md#default-excludes) (dependency directories and lockfiles) are applied inside Kubera instead. Passing that long list to git as pathspecs cost about 16% on every commit, more than it saved.

### Resumable scans

A full scan of a very large repository, or one over a slow disk, can take a long time. `--checkpoint FILE` makes it resumable:

```bash
kubera scan git ~/src/monorepo --verify --checkpoint monorepo.ckpt
# ... Ctrl-C ...
# interrupted: saving progress to monorepo.ckpt (Ctrl-C again to quit now)
kubera scan git ~/src/monorepo --verify --checkpoint monorepo.ckpt   # continues where it stopped
```

- The first **Ctrl-C** stops cleanly and saves the checkpoint. A second Ctrl-C exits immediately.
- **Run the same command again** to resume. Finished commits are skipped, and the findings saved so far are reported, verified and filtered as usual at the end.
- Progress is saved every couple of seconds as partitions of commits finish, so a crash or a killed job loses only the partitions in flight.
- A checkpoint belongs to one scan. A checkpoint from a different scan (another repository, refs, revisions or detector set, or new commits on the scanned refs) is refused; delete it to start over.
- When the scan completes, the file is deleted.

The checkpoint **holds raw secrets** (they are needed to verify and report on resume). It is written atomically with mode `0600`. Keep it out of shared or synced folders, and delete it if you abandon the scan.

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

3. **Verification:** with `--verify --verify-cache`, secrets found again (a leak that is still in history, the same key in several repositories) are not sent to their vendor again while the last result is fresh: 1 hour for live ones, 24 hours for invalid ones. See [Verification cache](scanning.md#verification-cache).

Network, disk I/O and CPU scale with **what changed** since the last passing scan, not with the size of the organization. Repositories are processed `--repo-concurrency` at a time, and each one's history is scanned in [parallel](#parallel-history) with its share of the CPUs. A failure in one repository is reported and doesn't stop the others.

### Rate limiting

API discovery is rate-limit aware on all three forges:

- `Retry-After` on 429/403/503 is always honoured.
- Primary limits (`x-ratelimit-remaining: 0` on GitHub, `ratelimit-remaining: 0` on GitLab) wait until the advertised reset.
- When the remaining budget drops to the last couple of requests, Kubera pauses **before** hitting the limit.
- Server errors and dropped connections are retried with exponential backoff and jitter.
- A wait longer than `--max-rate-wait` (default 900 s) fails fast with the reset time instead of stalling a CI job.

Pagination follows `Link: rel="next"` (GitHub, GitLab) or `next` (Bitbucket) **only to the same host**, so the token can never be sent elsewhere. Clones use the same token through an origin-scoped header (see [Remote repositories](remote.md)), never on the command line.

### Scheduling

A nightly job that only reports new leaks (add `--notify-env` to get a Slack message, see [Alerts](alerts.md)):

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/kubera
    key: kubera-${{ github.run_id }}
    restore-keys: kubera-
- run: kubera scan repos --github-org acme --token-env GH_TOKEN --cache-dir ~/.cache/kubera --state ~/.cache/kubera/state.json --verify --verify-cache=$HOME/.cache/kubera/verify.json --fail
  env:
    GH_TOKEN: ${{ secrets.ORG_READ_TOKEN }}
```
