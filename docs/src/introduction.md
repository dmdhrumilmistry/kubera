# Kubera

Kubera is a fast, template-driven secret scanner written in Rust. It covers the whole lifecycle of a leaked credential:

| Stage | Command | What happens |
|---|---|---|
| **Detect** | `kubera scan fs\|git\|stdin` | Finds candidate secrets in files, full git history or piped input. |
| **Verify** | `kubera scan ... --verify`, `kubera verify` | Asks the issuing platform whether the secret is live. |
| **Analyze** | `kubera analyze` | Shows who owns the credential and what it can reach. |
| **Rotate** | `kubera rotate` | Plans, then (with `--execute`) performs the vendor API calls that replace or revoke it. |

Every platform is described by a **YAML template**: its regexes, its verification endpoint, its analysis probes and its rotation steps. Supporting a new platform means writing one YAML file. You don't need to touch the code or rebuild.

```text
$ kubera scan git . --verify --only-verified
● GitLab Personal Access Token [critical]  VERIFIED (live)
  detector     gitlab-pat
  location     deploy/ci.env:3
  commit       9a1f03c2d4e5 bob <bob@example.com> 2026-09-14T08:12:44Z
  token        glpa********Us
  User         bob
  Admin        false
  fingerprint  5c0e1f9a2b7d44e18f3a6b20
```

## Design goals

- **Safe by default** - secrets are redacted in output, verification is opt-in, only HTTPS is allowed, rotation is a dry run unless explicitly executed, and git runs hardened against hostile repositories. See [Security model](security.md).
- **Data, not code** - detectors are declarative and statically validated. Each template carries its own positive and negative samples, so `kubera templates test` keeps them honest.
- **Fast** - a single Aho-Corasick pass decides which detectors run on each chunk, files are scanned in parallel, and identical secrets are verified once.
- **CI-native** - SARIF output, a `--fail` exit code and JSON/JSONL for pipelines.

Kubera borrows ideas from [TruffleHog](https://github.com/trufflesecurity/trufflehog), including keyword prefiltering, live verification and per-platform analyzers. It moves the per-platform logic out of compiled code and into templates.
