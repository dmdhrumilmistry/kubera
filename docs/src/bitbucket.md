# Bitbucket issues, PRs and Pipelines

The Bitbucket Cloud counterpart of [`scan github`](github.md): issues, pull request descriptions, comments, Pipelines step logs and snippets, read through the 2.0 API.

```bash
kubera scan bitbucket acme/api                                     # a public repository
kubera scan bitbucket acme/api --token-env BB_TOKEN                # repository or workspace access token
kubera scan bitbucket --workspace acme --token-env BB_APP_PASSWORD --token-user dana
kubera scan bitbucket acme/api --what pipelines --max-runs 100     # only Pipelines logs
```

## What gets scanned

| `--what` | Source | Location in findings |
|---|---|---|
| `issues` | Issue titles and descriptions (repositories with the issue tracker on) | `issues/12` |
| `pull-requests` | Pull request titles and descriptions, every state | `pull-requests/34` |
| `comments` | Issue and pull request comments, inline comments included. Deleted comments are skipped. | `issues/12/comments/<id>`, `pull-requests/34/comments/<id> (path/in/diff)` |
| `pipelines` | Step logs of the most recent Pipelines runs | `pipelines/<build number>/<step name>` |
| `snippets` | Snippets of the workspaces involved, full git history | file and commit, like `scan git` |

Everything is scanned by default; pass a comma list to narrow it. Each finding links to the issue, comment or pipeline result. Logs have their colour codes removed, and long logs are scanned in pieces of `--max-file-size` with the original line numbers.

## Options

| Flag | Meaning |
|---|---|
| `workspace/repo ...` | Repositories to scan. |
| `--workspace WS` | Every repository and snippet of this workspace (repeatable). |
| `--what <kinds>` | `issues`, `pull-requests`, `comments`, `pipelines`, `snippets` (default: all). |
| `--token-env VAR` | Environment variable with an access token (sent as a bearer token), or an app password / API token used with `--token-user`. |
| `--token-user USER` | User for app passwords and API tokens (basic auth). |
| `--max-items N` | Issues, pull requests or comments read per repository and kind (default 2000). |
| `--max-runs N` | Pipelines whose step logs are read per repository, newest first (default 20). |
| `--max-rate-wait SECS` | Longest rate-limit wait before giving up (default 900). |

All [common scan options](scanning.md#common-options) work too.

## Tokens

```bash
export BB_TOKEN=<access token>    # repository or workspace access token, read scopes
kubera scan bitbucket --workspace acme --token-env BB_TOKEN --verify
```

Public repositories work without a token for issues, pull requests and comments; Pipelines logs and snippets of private workspaces need one.

- Credentials are read from environment variables, never from argv, and sent only to the API host over HTTPS.
- API traffic is rate-limit aware (Bitbucket answers `429` when the hourly budget is used) and follows `next` pagination only to the same host.
- Step logs that redirect to storage are downloaded **without** credentials, capped at 256 MiB.
- Snippets are cloned with the token only when their clone URL is on `bitbucket.org`; any other host is skipped with a warning. Access tokens clone as `x-token-auth`, app passwords and API tokens as `--token-user`.
