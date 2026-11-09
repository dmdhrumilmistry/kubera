# GitHub issues, PRs and Actions

A repository scan only reads code. Secrets also get pasted into issues, PR descriptions and review comments, and printed by CI jobs. `kubera scan github` reads those places.

```bash
kubera scan github acme/api                              # one repository
kubera scan github acme/api acme/web --token-env GH_TOKEN
kubera scan github --org acme --token-env GH_TOKEN       # every repository of an org
kubera scan github --user dana --what gists              # a user's gists
```

## What gets scanned

| `--what` | Source | Location in findings |
|---|---|---|
| `issues` | Issue and pull request titles and descriptions | `issues/12`, `pull/34` |
| `comments` | Conversation comments and review comments | `comment/<id>`, `review/<id> (path/in/diff)` |
| `actions` | Logs of the most recent GitHub Actions runs | `actions/runs/<id>/<job log>` |
| `wiki` | The repository wiki, full git history | file and commit, like `scan git` |
| `gists` | Gists of `--user` accounts, full git history | file and commit, like `scan git` |

Everything is scanned by default. Pass a comma list to narrow it, for example `--what issues,comments`.

Each finding links back to the exact issue, comment or Actions run, so you can delete or edit it straight away. Wikis and gists are git repositories, so edits and deleted revisions are covered too, the same way [`scan git`](scanning.md#git-history) covers code.

## Options

| Flag | Meaning |
|---|---|
| `owner/repo ...` | Repositories to scan. |
| `--org ORG` | Every repository of this organization (repeatable). |
| `--user USER` | Every repository and gist of this user (repeatable). |
| `--what <kinds>` | `issues`, `comments`, `actions`, `wiki`, `gists` (default: all). |
| `--token-env VAR` | Environment variable with a GitHub token. Needed for Actions logs and private repositories; also raises rate limits. |
| `--api-url URL` | GitHub Enterprise API, e.g. `https://ghe.example.com/api/v3`. |
| `--max-items N` | Issues or comments read per repository and kind, newest first (default 2000). |
| `--max-runs N` | Actions runs whose logs are read per repository, newest first (default 20). |
| `--max-rate-wait SECS` | Longest rate-limit wait before giving up (default 900). |

All [common scan options](scanning.md#common-options) work too: `--verify`, `-f sarif`, `--fail`, baselines and alerts.

## Tokens

```bash
export GH_TOKEN=<token>      # read access to issues, pull requests and Actions
kubera scan github --org acme --token-env GH_TOKEN --verify --only-verified
```

Without a token, public issues, comments, wikis and gists still work within GitHub's anonymous rate limit. Actions logs always need a token.

- The token is read from an environment variable, never from argv.
- API traffic is rate-limit aware and follows pagination only to the same host, like [mass scanning](incremental.md#rate-limiting).
- GitHub serves Actions logs as a zip from pre-signed storage URLs. Kubera downloads them **without** the token, so the token never reaches the storage host. The zip is read in memory with the [archive limits](scanning.md#archives).

## Cleaning up a leak

Editing or deleting a comment does not remove a secret that was live while it was visible: rotate it first (see [Verify, analyze and rotate](lifecycle.md)). Edits stay in GitHub's comment history, and run logs stay until they expire or you delete them.
