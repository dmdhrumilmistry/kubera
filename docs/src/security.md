# Security model

Kubera handles live credentials, so it is conservative by default.

## Handling secrets

- **Redaction everywhere.** Findings, analysis reports and rotation reports mask sensitive values (`ghp_********Uo`). Revealing them requires `--show-secrets`. Template parts marked `secret: false` (identifiers such as AWS key ids) are shown as-is.
- **No secrets in argv.** `verify`, `analyze` and `rotate` take credentials from environment variables (`--secret-env`) or stdin (`--secret-stdin`). `--secret` works but warns that values leak into shell history and process listings.
- **No secrets in diagnostics.** HTTP errors include only `scheme://host/…`, never paths or query strings (some APIs put tokens in the path). The HTTP library's own error text has its URL removed for the same reason. Verification and step messages pass through a masking filter that replaces every known secret value.
- **Files that hold secrets are private and short-lived.** A [checkpoint](incremental.md#resumable-scans) (`--checkpoint`) must store raw secrets to report them on resume, so it is written atomically with mode `0600` and deleted as soon as the scan completes.
- **Files meant to be shared hold none.** The [baseline](triage.md) (`.kubera-baseline.json`) contains fingerprints, detector ids and locations, never secret values, so it can be committed. State files contain only refs and commit ids.
- **Dry-run plans** print requests with auth-like headers (`authorization`, `*token*`, `*key*`, `*secret*`, `cookie`, `signature`) replaced by `<redacted>`, and secret values (raw and URL-encoded) masked in URLs and bodies.

## Network

- **Verification is opt-in.** A plain `scan` of files, git history or stdin makes no network calls (beyond cloning a remote repository or pulling an image you asked for).
- **HTTPS only.** Requests to any other scheme are refused before anything is sent. (A hidden `--allow-http` flag exists for local mock servers in tests.)
- **No redirects.** A redirect is treated as an unexpected response, so a credential can never be bounced to another host.
- **Certificate verification is always on.** On Linux, macOS and Windows, Kubera uses the operating system's trust store. On Android (Termux), where that verifier only works from Java, it uses `SSL_CERT_FILE`, then Termux's bundle, then Android's system store, then Mozilla's embedded roots. See [Installation](installation.md#termux-android). There is no option to disable verification.
- **Bounded.** 10 s connect timeout, 15 s default request timeout, response bodies capped at 1 MiB.
- Each secret is sent only to the endpoints declared by **its own** template.

## Reports and alerts

- **HTML reports** (`-f html`) treat every value as hostile, since paths, commit authors and API responses come from scanned content. Values are embedded as escaped JSON in a non-executable block and rendered with `textContent`, never as HTML; only `https://` links become anchors. A Content-Security-Policy blocks all network requests and allows only the page's own script, pinned by SHA-256. Secrets are redacted unless `--show-secrets`, and then the page shows a warning.
- **Webhook URLs come from environment variables** (`--notify-env`), never argv: a Slack webhook URL is itself a credential. Alerts carry redacted findings only, go over HTTPS without following redirects, and errors never echo the URL path.
- **Signed alerts.** With `--notify-secret-env`, generic webhooks get `X-Kubera-Signature: sha256=<hex>`, an HMAC-SHA256 over `<timestamp>.<body>`, so receivers can reject forged and replayed deliveries. Slack text is escaped, so hostile paths or authors cannot inject mentions or links. See [Alerts](alerts.md).

## Rotation safety

1. **Dry run by default.** Without `--execute`, only the verification request is sent.
2. **Liveness gate.** Execution is refused unless the credential verifies as live (`--force` overrides).
3. **Explicit confirmation.** You must type the detector id, or pass `--yes`. Kubera refuses to prompt when stdin is not a terminal or was used for the secret.
4. **Fail-stop, never lose a key.** Steps stop at the first failure, and any credential already created is still returned.
5. **Private output.** `--output-file` creates a *new* file with mode `0600` and refuses to overwrite an existing one.
6. **Reversible where possible.** Builtin templates create the replacement before revoking, and deactivate instead of deleting when the platform allows it.
7. **Secret stores** (`--store`) are checked before the rotation starts (tokens present, HTTPS, GitHub public key readable) and written only after every step succeeded. Store credentials come from environment variables, GitHub secrets are encrypted locally with the repository's public key, and a failed store write prints the new credential rather than losing it. See [Secret stores](secret-stores.md).

## Remediation

- **Issues** (`kubera remediate --issues`) never contain secret values: only fingerprints, redacted previews and locations, even from a `--show-secrets` file. Values from the findings file go into code spans, so hostile paths cannot inject mentions, links or HTML; only plain `https://` links are kept. Issues go only to a **private** repository unless `--allow-public-repo`, nothing is created without `--execute`, committer mentions are off by default, and a `POST` is never retried.
- **History purge** (`kubera purge`) must hold raw secrets in its `git filter-repo` expressions file, so the file is created with mode `0600`, never overwrites an existing file, and is refused inside the repository (where it could be committed). Kubera prints the rewrite commands and warnings but never rewrites or pushes anything.

## Findings database and dashboard

- The findings database (`scan --db`) stores **redacted** findings and fingerprints only, never secret values, even with `--show-secrets`. It is appended to with mode `0600` in a `0700` directory.
- `kubera serve` listens on `127.0.0.1` by default and refuses any other address unless you pass `--allow-remote` **and** a token (`--token-env`, at least 16 characters, compared in constant time). On localhost it checks the `Host` header against DNS rebinding. It is read-only (`GET` / `HEAD`), sends `nosniff`, `no-referrer`, `no-store` and anti-framing headers, and the page has no external assets: a Content-Security-Policy allows only its own script and style (pinned by SHA-256) and same-origin requests. Values are rendered as text, never HTML. There is no TLS: use an SSH tunnel or a TLS proxy to reach it remotely. See [Findings dashboard](dashboard.md#security).

## Repository credentials

- Tokens for private repositories (`--token-env`) reach git as an `Authorization` header in `GIT_CONFIG_*` **environment variables**, never on the command line. The header is scoped to the repository's origin, so it can't follow a redirect to another host, and it is never sent over plain `http://`.
- Credentials pasted inside a URL are stripped from it before git runs, and error messages only show the clean URL.
- Without a terminal, SSH runs with `BatchMode=yes`: it fails fast instead of waiting on a prompt nobody can answer.

## GitHub, buckets and clusters

- **GitHub** (`scan github`): the token is read from an environment variable. API pagination is followed only to the same host. Actions logs are downloaded from GitHub's pre-signed storage URL **without** the token, so it never reaches the storage host.
- **GitLab** (`scan gitlab`): the same rules. The token goes only to the `--api-url` host as `PRIVATE-TOKEN`; job logs that redirect to object storage are fetched without it; snippet repositories on any other host are skipped rather than cloned with the token.
- **Bitbucket** (`scan bitbucket`): the same rules: credentials only to the API host, step logs fetched from storage without them, snippets cloned only from `bitbucket.org`.
- **Slack** (`scan slack`): read-only Web API calls; the token goes only to `slack.com`. Uploaded files are not fetched from `files.slack.com`, so the token never leaves the API host.
- **Jira** (`scan jira`): every URL is built from `--site`; the email and API token go only there. **Confluence** (`scan confluence`) works the same way, and follows `_links.next` pagination only on the site's own host.
- **Buckets** (`scan bucket`): S3 credentials come from the standard `AWS_*` environment variables and are used only to sign requests (SigV4); a GCS access token comes from `--token-env`; an Azure account key (`AZURE_STORAGE_KEY`) only signs requests (Shared Key) and a SAS token comes from `--sas-env`. Both are sent only to the storage endpoint, over HTTPS, without following redirects. Objects are filtered by path and size before download and never written to disk.
- **Kubernetes** (`scan k8s`): only read-only `list` calls. TLS trusts only the cluster's CA when the kubeconfig names one. A cluster with `insecure-skip-tls-verify` and plain `http://` servers are refused, rather than sending a token over an unverified connection. RBAC denials become warnings, not failures.

## Packages

`scan package` downloads only from the official registries and their file hosts, over HTTPS, without credentials. Every file is checked against the registry's sha256 / sha512 digest before it is opened (a mismatch fails the scan), sizes are checked before downloading, and packages are read in memory with the archive limits below.

## Interactive use

- Hidden prompts (`kubera verify` with no secret) keep secrets out of shell history and the screen.
- The TUI masks secrets until you press `r`, hides them again when the selection moves, exports only redacted JSON (new file, mode `0600`), and can't execute rotations: applying one stays an explicit CLI step with its own confirmation.

## Container images and archives

Registry blobs are sha256-verified before they are parsed and capped by `--max-layer-size`. Image archives are streamed and never unpacked to disk, so hostile paths or symlinks inside an image cannot write anywhere. Registries must use HTTPS unless you pass `--plain-http`.

[Archives](scanning.md#archives) found in files, layers and buckets are read in memory and never extracted. Every limit applies to bytes actually decompressed, not to sizes an archive claims, so zip bombs and lying headers only waste a bounded amount of work. [Decoding](scanning.md#decoders) is bounded the same way.

Kubera's own [container image](installation.md#container-image) runs as a non-root user.

## MCP server

`kubera mcp` never returns raw secrets to the AI model: findings are redacted, and follow-up tools take fingerprints. Tools that contact vendors need `--allow-verify`, tools accept no credentials or environment-variable names (prompt-injection exfiltration), rotation is plan-only, and `--root` confines file access. See [MCP server](mcp.md).

## Incremental state

State files contain only ref names and commit ids, are written atomically with mode `0600`, and advance only after a passing scan, so a leak cannot drop out of view after one failed run.

## Pre-commit hook

`kubera hook install` never overwrites a hook it did not write unless you pass `--force` (the old one is kept as `pre-commit.bak`). The hook fails closed: if `kubera` is not on `PATH`, the commit is refused, not silently allowed.

## Untrusted repositories

`scan git` may point at hostile repositories, and some git features can execute commands configured by the repository. Kubera runs git with:

- `--no-ext-diff` and `--no-textconv` (no external diff drivers or textconv filters),
- `-c core.fsmonitor=false` and `-c core.hooksPath=/dev/null`,
- `-c protocol.ext.allow=never` and `GIT_CONFIG_NOSYSTEM=1`,
- `GIT_TERMINAL_PROMPT=0` (no credential prompts on clone),
- user-supplied revisions validated (no leading `-`, no `..`) and passed after `--end-of-options`; clone URLs passed after `--`.

Filesystem scans never follow symlinks.

## Templates are code

A template decides where a matched secret is sent. Only load templates you trust (`-t`, `templates:` in `.kubera.yaml`), and review third-party templates the way you would review code. `kubera templates show <id>` prints exactly what will run.

## Release integrity

- **Checksums, always.** Every release archive has a `.sha256` file, and both installers refuse an archive that does not match it.
- **Keyless signatures.** The release workflow signs each archive, the SBOM and the manifests tarball with [Sigstore](https://www.sigstore.dev) (`cosign sign-blob`, bundles published as `<asset>.sigstore.json`) and signs the container image by digest. The certificate names the workflow (`dmdhrumilmistry/kubera/.github/workflows/release.yml`) and the ref it ran on, and is recorded in the public Rekor transparency log; there is no long-lived private key to steal.
- **Provenance.** GitHub build provenance attestations (SLSA) link each archive and the image to the exact commit and workflow run that built them, and an SBOM attestation links each archive to its CycloneDX SBOM. Verify with `gh attestation verify`.
- **Never re-signed.** Finishing a partial release adds missing signatures only; published assets and signatures are never replaced. Provenance is attested only for bytes the attesting run built.
- **Package manager manifests** (Homebrew, Scoop, winget, AUR) are generated from the checksums of the published archives, which are hashed again before rendering.

See [Verifying a release](installation.md#verifying-a-release) for the commands.

## Self-update

`kubera update` runs only when you invoke it: no background checks, no telemetry, no credentials sent. It talks HTTPS to GitHub's API and download hosts only (redirects are followed one hop at a time and must stay on them), checks the archive against the release's `.sha256` file and GitHub's asset digest before writing anything, runs the new binary once, and then swaps it in with an atomic rename, so a failure leaves the old binary untouched. It refuses to replace a binary that a package manager owns. See [Updating](installation.md#updating).

## Reporting vulnerabilities

Please report security issues privately through [GitHub security advisories](https://github.com/dmdhrumilmistry/kubera/security/advisories/new) rather than in public issues.
