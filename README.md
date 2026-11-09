# Kubera

Kubera is a fast, template-driven secret scanner written in Rust. It finds leaked credentials in files, git history and pipelines. It can also **verify** whether a secret is live, **analyze** what it can access, and **rotate or revoke** it, all from declarative YAML templates.

Adding support for a new platform takes one YAML file, not new code.

```text
$ kubera scan git . --verify
● GitHub Token [critical]  VERIFIED (live)
  detector     github-token
  location     app/settings.py:14
  commit       3f1c9e0a7b2d alice <alice@example.com> 2026-10-02T11:04:51+02:00
  token        ghp_********Uo
  User         alice
  Scopes       repo, workflow
  fingerprint  bc0458ecc5e4611e9dde21f8
```

## Features

- **Detection** - Aho-Corasick keyword prefilter, then per-template regexes with entropy and exclusion filters, and multi-part secrets (for example an AWS key id plus its secret) paired by proximity.
- **Sources** - filesystem, full git history (local or remote, added lines only, including commits where the secret was later deleted) and stdin.
- **Verification** - checks each candidate against the issuing platform's API, with bounded concurrency and de-duplication.
- **Analysis** - identity, scopes, reachable resources and permission probes.
- **Rotation** - dry-run plan by default; executes vendor API calls only with `--execute` and confirmation. Includes manual runbooks for platforms with no rotation API.
- **Outputs** - pretty, JSON, JSONL and SARIF 2.1.0 (for GitHub code scanning). Secrets are redacted unless you pass `--show-secrets`.
- **Templates** - YAML with a strict validator and built-in positive and negative samples (`kubera templates test`).

## Install

```bash
cargo install --git https://github.com/dmdhrumilmistry/kubera --locked
```

Building from source requires Rust 1.88 or newer. Git scanning uses the `git` binary. From a clone, `make install` builds and installs it (`make help` lists every task).

**Termux (Android)** is supported, including live verification:

```bash
pkg install rust git make clang
git clone https://github.com/dmdhrumilmistry/kubera && cd kubera
make install     # installs to $PREFIX/bin
```

## Quick start

```bash
# Scan a directory
kubera scan fs .

# Scan all history of a repository and verify what is found
kubera scan git https://github.com/org/repo.git --verify --only-verified

# Fail CI when anything is found (exit code 183) and emit SARIF
kubera scan fs . --fail -f sarif > kubera.sarif

# Pipe anything in
kubectl get secrets -A -o yaml | kubera scan stdin --verify

# Check, analyze and rotate a single credential (read from the environment,
# never from argv)
export TOKEN=...
kubera verify  gitlab-pat --secret-env TOKEN
kubera analyze gitlab-pat --secret-env TOKEN
kubera rotate  gitlab-pat --secret-env TOKEN                       # dry run: shows the plan
kubera rotate  gitlab-pat --secret-env TOKEN --execute -o new.json # performs it, writes new token (0600)
```

## Builtin detectors

| Detector | Verify | Analyze | Rotate |
|---|---|---|---|
| `aws-access-key` | STS GetCallerIdentity (SigV4) | IAM user, policies, groups, keys | **API** - create new key, deactivate leaked |
| `github-token` | `/user` | scopes, orgs, repos | **API** - revoke (`/credentials/revoke`) |
| `gitlab-pat` | `/user` | token scopes/expiry, writable projects | **API** - `/personal_access_tokens/self/rotate` |
| `sendgrid-api-key` | `/v3/scopes` | key name, account, senders | **API** - create with same scopes, delete leaked |
| `slack-token` | `auth.test` | channels, workspace | **API** - `auth.revoke` |
| `stripe-secret-key` | `/v1/balance` | account + permission probes | manual |
| `openai-api-key` | `/v1/models` | owner, models, files | manual |
| `anthropic-api-key` | `/v1/models` | models | manual |
| `npm-token` | `/-/whoami` | tokens, maintained packages | manual |
| `huggingface-token` | `/api/whoami-v2` | role, orgs, models | manual |
| `digitalocean-token` | `/v2/account` | droplets, projects | manual |
| `telegram-bot-token` | `getMe` | webhook target | manual |
| `slack-webhook` | empty-payload probe | - | manual |
| `google-api-key` | - | - | manual |
| `private-key` | - | - | manual |

Run `kubera templates list` to see what is loaded.

## Adding a platform

```bash
kubera templates new acme-key > templates.d/acme.yaml   # skeleton with every section
$EDITOR templates.d/acme.yaml
kubera templates validate templates.d/                  # schema, regexes, variables, samples
kubera -t templates.d scan fs .                         # use it (same id overrides a builtin)
```

A minimal template:

```yaml
id: acme-key
name: Acme API Key
platform: Acme
severity: high
detect:
  keywords: [acme_]
  patterns:
    - name: token
      regex: '\b(acme_[A-Za-z0-9]{32})\b'
      min_entropy: 3.5
verify:
  request:
    url: https://api.acme.dev/v1/me
    auth: { type: bearer, token: "{{ token }}" }
  valid:   { status: [200] }
  invalid: { status: [401] }
  extract:
    - { name: account, label: Account, json: user.email }
```

See the [template reference](https://dmdhrumilmistry.github.io/kubera/templates.html) for every field: auth types including AWS SigV4, matchers, extractors, rotation inputs and outputs, filters and samples.

## Configuration

Kubera reads `.kubera.yaml` from the working directory, or the file you pass with `--config`:

```yaml
templates: [./templates.d]
exclude_detectors: [google-api-key]
exclude_paths: ["**/testdata/**", "**/*.min.js"]
allowlist:
  fingerprints: [bc0458ecc5e4611e9dde21f8]
  secrets: ['^AKIA.*EXAMPLE$']
max_file_size: 5242880
```

Add `kubera:ignore` to a line to suppress findings on it.

## Security model

- Verification is **opt-in** (`--verify`). It sends each candidate secret only to the endpoint its template names.
- Templates may only call `https://` URLs. Redirects are never followed, response bodies are capped at 1 MiB, and errors never include URL paths or secret values.
- Secrets are redacted in all output by default. Pass them to `verify`, `analyze` and `rotate` with `--secret-env` or `--secret-stdin`; `--secret` works but prints a warning.
- Rotation defaults to a dry run. `--execute` re-verifies the credential (refusing if it is not live unless `--force`) and asks you to type the detector id (or pass `--yes`). Steps stop at the first failure, and any new credential already created is still returned. `--output-file` writes it with mode `0600` and never overwrites an existing file.
- Git is run defensively against untrusted repositories: no external diff or textconv, no hooks or fsmonitor, revisions passed after `--end-of-options`, and no credential prompts.
- Filesystem scans never follow symlinks.

Templates are code: only load templates you trust, because a template decides where a matched secret is sent.

## Documentation

Full docs: https://dmdhrumilmistry.github.io/kubera/ (sources in [`docs/`](docs/)).

## License

[MIT](LICENSE)
