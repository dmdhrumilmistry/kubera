# CI integration

## Fail the build on leaks

```bash
kubera scan fs . --fail            # exits 183 when anything is found
kubera scan git . --since-commit "$BASE_SHA" --fail
```

## GitHub Action

The repository is a GitHub Action. It installs a release binary (checksum-verified), scans, uploads SARIF to code scanning, writes a job summary and annotates the findings:

```yaml
name: Secret scan
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write   # SARIF upload to code scanning

jobs:
  kubera:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0              # git mode needs the history
          persist-credentials: false
      - uses: dmdhrumilmistry/kubera@v0.2.0
        id: kubera
        with:
          args: --verify
      - if: always()
        env:
          N: ${{ steps.kubera.outputs.findings }}
        run: echo "kubera reported $N finding(s)"
```

In `git` mode (the default), a **pull request scans only the PR's commits** and a **push scans only the pushed commits**. Other events, such as `schedule` or `workflow_dispatch`, scan the full history. If the base commit is not in the checkout (shallow clone), the action warns and falls back to the full history, so keep `fetch-depth: 0`.

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Repository or directory to scan. |
| `mode` | `git` | `git` scans history; `fs` scans the files in the working tree. |
| `args` | | Extra `kubera scan` arguments, e.g. `--verify --exclude-path "**/testdata/**"`. |
| `version` | `latest` | Kubera release to install (`latest` or a tag such as `v0.2.0`). |
| `fail` | `true` | Fail the job when secrets are found. |
| `sarif` | `true` | Upload results to GitHub code scanning. Needs `security-events: write`. |
| `sarif-file` | `kubera.sarif` | Where to write the SARIF report. |

| Output | Meaning |
|---|---|
| `findings` | Number of findings reported. |
| `sarif-file` | Path of the SARIF report. |

Each SARIF result carries the commit hash in its location properties and a `kubera/v1` partial fingerprint, so code scanning de-duplicates alerts across runs. Without code scanning (private repositories on plans without it), set `sarif: false` and drop the `security-events` permission: the job summary (up to 100 rows) and annotations (up to 50) still list the findings.

Pin the action to a release tag (or a commit SHA) rather than a branch.

## Container image

Every release publishes `ghcr.io/dmdhrumilmistry/kubera` for linux/amd64 and linux/arm64. It works on any CI that runs containers:

```bash
docker run --rm -v "$PWD:/scan" ghcr.io/dmdhrumilmistry/kubera:0.2.0 scan git /scan --fail
```

GitLab CI:

```yaml
secret-scan:
  image:
    name: ghcr.io/dmdhrumilmistry/kubera:0.2.0
    entrypoint: [""]
  variables:
    GIT_DEPTH: 0
  script:
    - kubera scan git . --fail
```

See [Installation](installation.md#container-image) for tags and details.

## Adopting Kubera on an existing codebase

An old repository usually has findings you already know about. Record them once in a [baseline](triage.md), commit it, and CI only fails on **new** secrets:

```bash
kubera scan git . --update-baseline        # writes .kubera-baseline.json, exits 0
git add .kubera-baseline.json
git commit -m "Add kubera baseline"
```

Scans in CI pick up `.kubera-baseline.json` from the working directory automatically. Review changes to the file like code: an entry hides a finding everywhere the same secret appears.

## Without the action

The same steps by hand, with any way of installing Kubera:

```yaml
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - run: curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/kubera/main/install.sh | sh
      - run: ~/.local/bin/kubera scan git . -f sarif > kubera.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kubera.sarif
      - run: ~/.local/bin/kubera scan git . --fail
```

### Scanning only a pull request's commits

```yaml
      - run: kubera scan git . --since-commit "${{ github.event.pull_request.base.sha }}" --fail
```

## Verification in CI

`--verify` sends candidates to vendor APIs. In CI, consider `--only-verified` to cut noise, and remember that CI egress rules must allow the vendor hosts. Logs never contain unmasked secrets unless you pass `--show-secrets`, so never pass it in CI.

For scheduled scans that should page someone, add `--notify-env` (see [Alerts](alerts.md)).

## pre-commit

Stop secrets before they reach CI with the [pre-commit hook](hooks.md):

```bash
kubera hook install
```

Or, with the [pre-commit framework](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dmdhrumilmistry/kubera
    rev: v0.2.0
    hooks:
      - id: kubera          # or kubera-system to use kubera from PATH
```
