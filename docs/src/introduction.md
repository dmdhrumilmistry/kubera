<div class="kubera-hero">
  <img src="images/banner.svg" alt="Kubera - find, verify, analyze and rotate leaked secrets">
</div>

# Kubera

Kubera is a fast, template-driven secret scanner written in Rust. It covers the whole lifecycle of a leaked credential:

<div class="kubera-cards">
  <div class="kubera-card"><strong>🔍 Detect</strong><p>Files, full git history (local or any remote URL) and stdin. Finds secrets even in commits where they were later deleted.</p></div>
  <div class="kubera-card"><strong>✅ Verify</strong><p>Asks the issuing platform whether each secret is live, so you fix real leaks first.</p></div>
  <div class="kubera-card"><strong>🧭 Analyze</strong><p>Who owns the credential, its scopes, and what it can reach.</p></div>
  <div class="kubera-card"><strong>🔁 Rotate</strong><p>Dry-run plans, then vendor API calls to replace or revoke, with a manual runbook where there is no API.</p></div>
</div>

Every platform is described by a **YAML template**: its regexes, its verification endpoint, its analysis probes and its rotation steps. Supporting a new platform means writing one YAML file; nothing needs recompiling.

<img class="kubera-shot" src="images/cli-scan.svg" alt="kubera scan output: findings as cards with severity, live status, commit, link and redacted secret">

## Interactive

Run `kubera` with no arguments in a terminal for the TUI. You can scan a folder or a repository, browse findings, verify, analyze and plan rotations, all from the keyboard. See [Interactive TUI](tui.md).

<img class="kubera-shot" src="images/tui-results.svg" alt="kubera TUI: findings list and detail pane for a live AWS key">

## Design goals

- **Safe by default.** Secrets are redacted in output and verification is opt-in. Only HTTPS is allowed. Rotation is a dry run unless explicitly executed, and git runs hardened against hostile repositories. See [Security model](security.md).
- **Data, not code.** Detectors are declarative and statically validated. Each template carries its own positive and negative samples, so `kubera templates test` keeps them honest.
- **Fast.** A single Aho-Corasick pass decides which detectors run on each chunk. Files are scanned in parallel, and identical secrets are verified once.
- **Everywhere.** Linux, macOS, Windows and Android (Termux), with a layout that adapts to phone-sized terminals.
- **CI-native.** SARIF output, a `--fail` exit code, and JSON/JSONL for pipelines.

Kubera borrows ideas from [TruffleHog](https://github.com/trufflesecurity/trufflehog), including keyword prefiltering, live verification and per-platform analyzers. The difference is that Kubera moves the per-platform logic out of compiled code and into templates.
