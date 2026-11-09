# Security model

Kubera handles live credentials, so it is conservative by default.

## Handling secrets

- **Redaction everywhere.** Findings, analysis reports and rotation reports mask sensitive values (`ghp_********Uo`). Revealing them requires `--show-secrets`. Template parts marked `secret: false` (identifiers such as AWS key ids) are shown as-is.
- **No secrets in argv.** `verify`, `analyze` and `rotate` take credentials from environment variables (`--secret-env`) or stdin (`--secret-stdin`). `--secret` works but warns that values leak into shell history and process listings.
- **No secrets in diagnostics.** HTTP errors include only `scheme://host/…`, never paths or query strings (some APIs put tokens in the path). The HTTP library's own error text has its URL removed for the same reason. Verification and step messages pass through a masking filter that replaces every known secret value.
- **Dry-run plans** print requests with auth-like headers (`authorization`, `*token*`, `*key*`, `*secret*`, `cookie`, `signature`) replaced by `<redacted>`, and secret values (raw and URL-encoded) masked in URLs and bodies.

## Network

- **Verification is opt-in.** A plain `scan` makes no network calls.
- **HTTPS only.** Requests to any other scheme are refused before anything is sent. (A hidden `--allow-http` flag exists for local mock servers in tests.)
- **No redirects.** A redirect is treated as an unexpected response, so a credential can never be bounced to another host.
- **Certificate verification is always on.** On Linux, macOS and Windows, Kubera uses the operating system's trust store. On Android (Termux), where that verifier only works from Java, it uses `SSL_CERT_FILE`, then Termux's bundle, then Android's system store, then Mozilla's embedded roots. See [Installation](installation.md#termux-android). There is no option to disable verification.
- **Bounded.** 10 s connect timeout, 15 s default request timeout, response bodies capped at 1 MiB.
- Each secret is sent only to the endpoints declared by **its own** template.

## Rotation safety

1. **Dry run by default.** Without `--execute`, only the verification request is sent.
2. **Liveness gate.** Execution is refused unless the credential verifies as live (`--force` overrides).
3. **Explicit confirmation.** You must type the detector id, or pass `--yes`. Kubera refuses to prompt when stdin is not a terminal or was used for the secret.
4. **Fail-stop, never lose a key.** Steps stop at the first failure, and any credential already created is still returned.
5. **Private output.** `--output-file` creates a *new* file with mode `0600` and refuses to overwrite an existing one.
6. **Reversible where possible.** Builtin templates create the replacement before revoking, and deactivate instead of deleting when the platform allows it.

## Repository credentials

- Tokens for private repositories (`--token-env`) reach git as an `Authorization` header in `GIT_CONFIG_*` **environment variables**, never on the command line. The header is scoped to the repository's origin, so it can't follow a redirect to another host, and it is never sent over plain `http://`.
- Credentials pasted inside a URL are stripped from it before git runs, and error messages only show the clean URL.
- Without a terminal, SSH runs with `BatchMode=yes`: it fails fast instead of waiting on a prompt nobody can answer.

## Interactive use

- Hidden prompts (`kubera verify` with no secret) keep secrets out of shell history and the screen.
- The TUI masks secrets until you press `r`, hides them again when the selection moves, exports only redacted JSON (new file, mode `0600`), and can't execute rotations: applying one stays an explicit CLI step with its own confirmation.

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

## Reporting vulnerabilities

Please report security issues privately through [GitHub security advisories](https://github.com/dmdhrumilmistry/kubera/security/advisories/new) rather than in public issues.
