<p align="center">
  <img src="docs/src/images/banner.svg" alt="Kubera - find, verify, analyze and rotate leaked secrets" width="860">
</p>

<p align="center">
  <a href="https://github.com/dmdhrumilmistry/kubera/actions/workflows/ci.yml"><img src="https://github.com/dmdhrumilmistry/kubera/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://dmdhrumilmistry.github.io/kubera/"><img src="https://img.shields.io/badge/docs-mdBook-f5b700" alt="Documentation"></a>
  <img src="https://img.shields.io/badge/rust-1.88%2B-e58518?logo=rust" alt="Rust 1.88+">
  <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-0b1020" alt="Platforms">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

<p align="center">
  <b>Kubera</b> is a fast, template-driven secret scanner written in Rust.<br>
  It finds leaked credentials, checks whether they are <b>live</b>, shows what they can <b>access</b>,<br>
  and <b>rotates or revokes</b> them. Adding a platform takes one YAML file, not new code.
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#interactive-tui">TUI</a> ·
  <a href="#scanning-remote-repositories">Remote repos</a> ·
  <a href="#builtin-detectors">Detectors</a> ·
  <a href="#adding-a-platform">Templates</a> ·
  <a href="https://dmdhrumilmistry.github.io/kubera/">Docs</a>
</p>

<p align="center">
  <img src="docs/src/images/cli-scan.svg" alt="kubera scan output: findings as cards with severity, live status, commit, link and redacted secret" width="760">
</p>

## Features

|  |  |
|---|---|
| 🔍 **Detect** | Files, full git history (local, HTTPS, SSH or `github.com/org/repo`) and stdin, including secrets that were committed and later deleted. Aho-Corasick prefilter, entropy and exclusion filters, multi-part secrets. |
| ✅ **Verify** | Asks each platform whether the secret is live, concurrently and de-duplicated. |
| 🧭 **Analyze** | Owner, scopes, reachable resources and permission probes. |
| 🔁 **Rotate** | Dry-run plan by default; vendor API calls only with `--execute` and confirmation. Manual runbooks for platforms with no API. |
| 🖥️ **Interactive** | A keyboard-driven TUI, hidden secret prompts, and auto-identification of pasted secrets. |
| 🧩 **Templates** | Everything per-platform lives in validated YAML, with built-in test samples. |
| 📤 **Outputs** | Pretty cards, JSON, JSONL and SARIF 2.1.0, with links to the exact line on GitHub, GitLab and Bitbucket. Secrets redacted by default. |
| 📱 **Everywhere** | Linux, macOS, Windows and Android (Termux), with layouts that adapt to phone screens. |

## Install

```bash
cargo install --git https://github.com/dmdhrumilmistry/kubera --locked
```

Or from a clone: `make install` (`make help` lists every task). Building requires Rust 1.88+, and git scanning uses the `git` binary.

**Termux (Android)** is fully supported, including live verification:

```bash
pkg install rust git make clang
git clone https://github.com/dmdhrumilmistry/kubera && cd kubera
make install     # installs to $PREFIX/bin
```

## Quick start

```bash
kubera                                   # interactive TUI
kubera scan fs .                         # scan a directory
kubera scan git . --verify               # whole history, verify what's found
kubera scan git github.com/org/repo -i   # a remote repo, results in the TUI
kubera scan fs . --fail -f sarif > kubera.sarif     # CI: SARIF + exit code 183
kubectl get secrets -A -o yaml | kubera scan stdin --verify
```

Check a single credential. Paste it at a hidden prompt, and Kubera works out what it is:

```bash
kubera verify                            # "Paste the secret (hidden):" → identified, verified
kubera analyze gitlab-pat --secret-env TOKEN
kubera rotate  gitlab-pat --secret-env TOKEN                        # dry run: shows the plan
kubera rotate  gitlab-pat --secret-env TOKEN --execute -o new.json  # rotate, new token saved 0600
```

## Interactive TUI

Run `kubera` with no arguments to scan, browse findings, verify (`v`), analyze (`a`) and plan rotations (`p`), all from the keyboard. Secrets stay masked until you press `r`.

<p align="center">
  <img src="docs/src/images/tui-results.svg" alt="Kubera TUI: findings list and detail pane for a live AWS key" width="820">
</p>

<details>
<summary>More screenshots: home screen, analysis tab, phone layout</summary>
<p align="center">
  <img src="docs/src/images/tui-home.svg" alt="TUI home screen" width="680"><br><br>
  <img src="docs/src/images/tui-analysis.svg" alt="TUI analysis tab for an AWS key" width="820"><br><br>
  <img src="docs/src/images/tui-phone.svg" alt="TUI on a 50-column phone terminal (Termux)" width="380">
</p>
</details>

## Scanning remote repositories

```bash
kubera scan git https://github.com/org/repo.git       # HTTPS
kubera scan git git@github.com:org/repo.git           # SSH (your keys / agent)
kubera scan git github.com/org/repo                   # shorthand
kubera scan git https://github.com/org/private.git --token-env GH_TOKEN   # private repo
```

Repositories are cloned bare into a temp dir and deleted afterwards. Tokens reach git as an origin-scoped `Authorization` header through environment variables, never on the command line, and are never sent over plain HTTP. Findings on GitHub, GitLab and Bitbucket link to the exact line at the commit. [Details →](https://dmdhrumilmistry.github.io/kubera/remote.html)

## Builtin detectors

| Detector | Verify | Analyze | Rotate |
|---|---|---|---|
| `aws-access-key` | STS GetCallerIdentity (SigV4) | IAM user, policies, groups, keys | **API**: create new key, deactivate leaked |
| `github-token` | `/user` | scopes, orgs, repos | **API**: revoke (`/credentials/revoke`) |
| `gitlab-pat` | `/user` | token scopes/expiry, writable projects | **API**: `/personal_access_tokens/self/rotate` |
| `sendgrid-api-key` | `/v3/scopes` | key name, account, senders | **API**: create with same scopes, delete leaked |
| `slack-token` | `auth.test` | channels, workspace | **API**: `auth.revoke` |
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

Run `kubera templates list`, or browse them in the TUI (`kubera` → *Browse detectors*).

## Adding a platform

```bash
kubera templates new acme-key > templates.d/acme.yaml   # skeleton with every section
kubera templates validate templates.d/                  # schema, regexes, variables, samples
kubera -t templates.d scan fs .                         # use it (same id overrides a builtin)
```

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

The [template reference](https://dmdhrumilmistry.github.io/kubera/templates.html) covers every field: auth types including AWS SigV4, matchers, extractors, rotation inputs and outputs, and samples.

## Configuration

`.kubera.yaml` in the working directory (or `--config`):

```yaml
templates: [./templates.d]
exclude_detectors: [google-api-key]
exclude_paths: ["**/testdata/**", "**/*.min.js"]
allowlist:
  fingerprints: [bc0458ecc5e4611e9dde21f8]
  secrets: ['^AKIA.*EXAMPLE$']
```

Add `kubera:ignore` to a line to suppress findings on it.

## Security model

- **Opt-in network.** A plain scan sends nothing anywhere. With `--verify`, each secret goes only to the endpoint its own template names, over HTTPS, without following redirects.
- **Redacted by default** in every output, the TUI and exports. Secrets come in through env vars, stdin or hidden prompts rather than argv.
- **Rotation is a dry run** unless `--execute`. It re-verifies first, asks for confirmation, stops at the first failure without losing a newly created key, and writes output files with mode `0600`.
- **Hostile repositories are safe to scan.** There's no external diff, textconv, hooks or fsmonitor, revisions go after `--end-of-options`, there are no credential prompts, and symlinks are never followed.

Templates are code: only load templates you trust. See the [security model](https://dmdhrumilmistry.github.io/kubera/security.html).

## Documentation

Full documentation: **https://dmdhrumilmistry.github.io/kubera/** (sources in [`docs/`](docs/)).

## License

[MIT](LICENSE)
