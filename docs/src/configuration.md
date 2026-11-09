# Configuration

Kubera reads `.kubera.yaml` from the current directory if it exists, or the file you pass with `--config <file>` (which then must exist). Command-line flags add to the config file.

```yaml
# Extra template files/directories, relative to this file.
templates:
  - ./kubera-templates

# Ignore the templates compiled into the binary.
no_builtin: false

# Run only these detectors (empty = all).
detectors: []

# Never run these detectors.
exclude_detectors: [google-api-key]

# Globs matched against paths relative to the scan root
# (and against file paths in git history).
exclude_paths:
  - "**/testdata/**"
  - "docs/examples/**"

# Skip dependency directories and lockfiles (node_modules, vendor,
# package-lock.json, ...). Default true; false scans them too.
default_excludes: true

allowlist:
  # Fingerprints printed with each finding.
  fingerprints:
    - 5c0e1f9a2b7d44e18f3a6b20
  # Regexes matched against every secret part.
  secrets:
    - '^AKIA[A-Z0-9]{12}EXAMPLE$'

# Skip files larger than this many bytes (default 10 MiB).
max_file_size: 5242880
```

Unknown keys are rejected, so typos fail loudly instead of being silently ignored.

The full list of default excludes is in [Scanning](scanning.md#default-excludes). `--no-default-excludes` turns them off for one run.

## Baseline file

Next to `.kubera.yaml`, scans load `.kubera-baseline.json` from the current directory when it exists (`--baseline FILE` for another path, `--no-baseline` to ignore it). It holds fingerprints of findings that should no longer be reported: an adoption baseline (`--update-baseline`) and triage decisions from the TUI. Kubera writes it; you commit it. Kubera never rewrites `.kubera.yaml`. See [Baselines and triage](triage.md).

## Fingerprints

A fingerprint is the first 96 bits of `SHA-256(detector id, secret parts)`. It is stable across files, commits and runs, so you can safely commit it to an allowlist. It only reveals the secret if the secret is weak enough to brute-force.

## Inline suppression

Any line containing `kubera:ignore` produces no findings:

```python
TEST_TOKEN = "glpat-xxxxxxxxxxxxxxxxxxxx"  # kubera:ignore
```
