# Remediation: issues and history cleanup

Two commands turn a findings file into follow-up work:

- `kubera remediate --issues` opens **one GitHub issue per leaked secret**, so every live credential has an owner and a checklist.
- `kubera purge` prepares a **git history rewrite** that removes the leaked values, for when policy requires it. It writes the inputs and prints the commands; it never rewrites or pushes anything itself.

Both start from the JSON a scan writes:

```bash
kubera scan git . --verify -f json > findings.json
```

That file is **redacted** (the default), and both commands work with it: issues only need fingerprints and locations, and `purge` scans the repository again for the raw values.

## Open an issue per leaked secret

```bash
export GH_TOKEN=<token with issues: write on acme/security>
kubera remediate --findings findings.json --issues github:acme/security --token-env GH_TOKEN
```

```text
remediate acme/security  (dry run - pass --execute to open the issues)
  · would open       Live AWS Access Key (bc0458ec) [live, 2 location(s)]
  · would open       Live Slack Token (51f0aa12) [live, 1 location(s)]
  = already open #41 Live GitHub Token (9e3c7d20) [live, 1 location(s)]

2 to open, 0 opened, 1 already open, 0 failed
```

Read the plan, then add `--execute`.

| Flag | Meaning |
|---|---|
| `--findings FILE` | Output of `scan -f json` or `-f jsonl` (`-` reads stdin). |
| `--issues github:<owner>/<repo>` | Repository the issues go to. It can be a central security repository rather than the one that leaked. |
| `--token-env VAR` | Environment variable with a GitHub token (fine-grained: *Issues: read and write*, plus *Contents: read* for `--mention-committer`). |
| `--all` | Every finding, not only the live ones. |
| `--label NAME` | Labels for new issues (repeatable). Default: `kubera`, `leaked-secret`. |
| `--mention-committer` | Look up the GitHub account that authored the leaking commit and @mention it. Off by default. |
| `--allow-public-repo` | Allow issues in a public repository. |
| `--api-url URL` | GitHub Enterprise API base, e.g. `https://ghe.example.com/api/v3`. |
| `--execute` | Actually open the issues. |
| `--format json` | Machine-readable report: one result per secret, with `action` `would_open`, `opened`, `exists` or `failed`. |

How it works:

- **Only live secrets by default.** A secret is live when any finding with its fingerprint was verified. Scan with `--verify`, or pass `--all`.
- **One issue per secret.** Findings with the same fingerprint (the same secret in several files or commits) become one issue that lists every location, with links to the exact line.
- **No duplicates.** Each issue body starts with a hidden marker, `<!-- kubera-fingerprint: <fingerprint> -->`. Before opening anything, Kubera reads the repository's open issues (pull requests are ignored) and skips every secret that already has one. Run it after every scheduled scan; it only opens issues for new leaks. Closing an issue and finding the secret again opens a new one.
- **The issue never holds the secret**: only the detector, status, fingerprint, the redacted preview and the locations, followed by a checklist (rotate, update consumers, verify, check the audit log, remove from code, optionally purge history). Values from the findings file are put in code spans, so a hostile file name or commit message cannot inject mentions, links or HTML.
- **Private repositories only.** An issue is as public as its repository, and a public issue would tell everyone where a live credential leaked. Kubera checks the repository first and refuses a public one unless you pass `--allow-public-repo`.
- **Dry run by default.** Without `--execute` nothing is created. With a token, the dry run reads the repository and its open issues to show exactly what would happen; without one, it builds the plan offline and says that duplicates were not checked.
- `--mention-committer` reads `GET /repos/<owner>/<repo>/commits/<sha>` for the leaking commit (in the repository the finding came from when it is on GitHub, otherwise in the issues repository) and mentions the author's login. A lookup that fails is a warning, not an error.
- Rate limits are respected: Kubera waits for the reset, pauses between new issues, and never retries a `POST`, so an issue is not opened twice.

Exit code: `0` when everything went to plan, `1` if an issue could not be opened.

## Prepare a history rewrite

<div class="kubera-callout warning">
<p class="kubera-callout-title">Rotate first</p>

Rewriting history does not un-leak a secret: anyone who cloned the repository, every fork and every CI cache still has it. **Rotate or revoke the credential first** ([rotate](lifecycle.md#rotate)). Rewrite history only when policy requires it, or when you cannot be sure every copy is dead.

</div>

```bash
kubera purge --findings findings.json --repo .
```

```text
› scanning the history of /src/payments for 2 redacted finding(s)
✓ wrote 2 expression(s) for 2 secret(s) to /src/payments-kubera-purge.txt (mode 0600: it holds the raw secrets)

Before you run this
  - Rotate first: a rewrite never un-leaks a live secret; anyone may already have a copy.
  - Every commit hash after the first leak changes, and the push must be forced.
  - Collaborators must re-clone (a pull or merge brings the old history back); open pull requests need rebasing.
  - Forks, other clones, CI caches and the forge's pull request refs keep the old commits (GitHub Support can purge cached views).
  - Kubera changed nothing: review the commands and run them yourself.

Commands (need git-filter-repo)
  # 0. Rotate or revoke every credential first: a rewrite does not un-leak it.
  # 1. Rewrite a fresh bare clone (filter-repo refuses a used clone), every branch and tag:
  git clone --bare https://github.com/acme/payments.git payments-purge.git
  cd payments-purge.git
  git filter-repo --replace-text /src/payments-kubera-purge.txt --replace-message /src/payments-kubera-purge.txt
  # 2. Check that nothing is left:
  kubera scan git . --no-baseline
  # 3. Force push (filter-repo removed the origin remote):
  git remote add origin https://github.com/acme/payments.git
  git push --force --all origin
  git push --force --tags origin
  # 4. Delete the expressions file: it holds the raw secrets.
  rm /src/payments-kubera-purge.txt
```

What `purge` does:

1. Reads the findings file. **Redacted findings** are matched by fingerprint against a fresh scan of the repository's whole history (every branch and tag, without excludes, allowlist or baseline, so no copy is missed). A file written with `--show-secrets` is used as is, after checking each value against its fingerprint.
2. Writes a [git filter-repo](https://github.com/newren/git-filter-repo) expressions file with one line per distinct secret value: `literal:<value>==>***REMOVED***`. Values that span lines (private keys) become escaped `regex:` lines. Only the secret parts are replaced; identifiers such as AWS key ids are left alone.
3. Prints the warnings and the exact commands. The same file goes to `--replace-message` too, so secrets pasted into commit messages are removed as well.

| Flag | Meaning |
|---|---|
| `--findings FILE` | Output of `scan -f json` (redacted or `--show-secrets`). |
| `--repo PATH` | The repository whose history holds the secrets. Default: `.`. |
| `-o, --output FILE` | Expressions file to create. Default: `<repo>-kubera-purge.txt` **next to** the repository. |
| `--replacement TEXT` | What replaces each secret. Default: `***REMOVED***`. |
| `--format json` | The report as JSON: file, values, resolved and missing fingerprints, warnings, commands. |

The expressions file holds the **raw secrets**, so it is created with mode `0600`, never overwrites an existing file, and must be outside the repository (Kubera refuses a path inside it, where it could be committed). Delete it once the rewrite is pushed.

Kubera warns about what a literal replacement cannot fix:

- **Findings that were decoded** (base64, URL-encoded or escaped text): the file holds the encoded form, so the literal does not match. Remove those by hand.
- **Values shorter than 8 characters** are skipped: replacing a short string everywhere would corrupt unrelated content.
- **Fingerprints not found in the history**: the secret was never committed (`scan fs` of uncommitted files), lives in another repository, or is already gone.

After the push, everyone must **re-clone** (a pull or merge brings the old commits back), open pull requests need rebasing, and on GitHub, pull request refs and cached views keep the old commits until GitHub Support removes them. Scan again (step 2) before you push.

See also: [After a scan](workflow.md) for the whole response, and [Security model](security.md).
