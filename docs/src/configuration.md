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
  - "**/*.min.js"
  - "vendor/**"

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

## Fingerprints

A fingerprint is the first 96 bits of `SHA-256(detector id, secret parts)`. It is stable across files, commits and runs, so you can safely commit it to an allowlist. It only reveals the secret if the secret is weak enough to brute-force.

## Inline suppression

Any line containing `kubera:ignore` produces no findings:

```python
TEST_TOKEN = "glpat-xxxxxxxxxxxxxxxxxxxx"  # kubera:ignore
```
