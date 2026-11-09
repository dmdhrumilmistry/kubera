# CI integration

## Fail the build on leaks

```bash
kubera scan fs . --fail            # exits 183 when anything is found
kubera scan git . --since-commit "$BASE_SHA" --fail
```

## GitHub Actions with code scanning

```yaml
name: Secret scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # upload SARIF

jobs:
  kubera:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/dmdhrumilmistry/kubera --locked
      - run: kubera scan git . -f sarif > kubera.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kubera.sarif
      - run: kubera scan git . --fail
```

Each SARIF result carries the commit hash in its location properties and a `kubera/v1` partial fingerprint, so code scanning de-duplicates alerts across runs.

## Scanning only a pull request's commits

```yaml
      - run: kubera scan git . --since-commit "${{ github.event.pull_request.base.sha }}" --fail
```

## Verification in CI

`--verify` sends candidates to vendor APIs. In CI, consider `--only-verified` to cut noise, and remember that CI egress rules must allow the vendor hosts. Logs never contain unmasked secrets unless you pass `--show-secrets`, so never pass it in CI.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: kubera
        name: kubera
        entry: kubera scan fs --fail
        language: system
        pass_filenames: true
```
