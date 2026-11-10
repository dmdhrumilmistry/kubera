# GitLab issues, MRs and CI logs

The GitLab counterpart of [`scan github`](github.md). Secrets get pasted into issues, merge request descriptions and review comments, and printed by CI jobs; a repository scan never sees them. `kubera scan gitlab` reads those places on gitlab.com or a self-managed instance (API v4).

```bash
kubera scan gitlab acme/api --token-env GL_TOKEN               # one project
kubera scan gitlab acme/platform/api acme/web --token-env GL_TOKEN
kubera scan gitlab --group acme --token-env GL_TOKEN           # every project of a group, subgroups included
kubera scan gitlab acme/api --what ci-logs --max-jobs 200      # only CI job logs
kubera scan gitlab team/app --api-url https://gitlab.example.com/api/v4 --token-env GL_TOKEN
```

## What gets scanned

| `--what` | Source | Location in findings |
|---|---|---|
| `issues` | Issue titles and descriptions | `issues/12` |
| `merge-requests` | Merge request titles and descriptions | `merge_requests/34` |
| `comments` | Comments (notes) on issues and merge requests, diff comments included. System notes are skipped. | `issues/12/notes/<id>`, `merge_requests/34/notes/<id> (path/in/diff)` |
| `ci-logs` | Logs (traces) of the most recent CI jobs | `jobs/<id> (<job name>)` |
| `snippets` | Project snippets, full git history | file and commit, like `scan git` |
| `wiki` | The project wiki, full git history | file and commit, like `scan git` |

Everything is scanned by default. Pass a comma list to narrow it, for example `--what issues,comments`. Features a project has turned off (no issues, no CI) are skipped without an error.

Each finding links to the issue, the comment (`#note_<id>`) or the job page. CI logs have their colour codes removed before scanning, and line numbers refer to the log as GitLab shows it.

## Options

| Flag | Meaning |
|---|---|
| `group/project ...` | Projects to scan (subgroups allowed: `group/sub/project`). |
| `--group GROUP` | Every project of this group, subgroups included (repeatable). |
| `--what <kinds>` | `issues`, `merge-requests`, `comments`, `ci-logs`, `snippets`, `wiki` (default: all). |
| `--token-env VAR` | Environment variable with a GitLab token (`read_api` scope; add `read_repository` for snippets and wikis). |
| `--api-url URL` | Self-managed GitLab, e.g. `https://gitlab.example.com/api/v4`. |
| `--max-items N` | Issues, merge requests or comments read per project and kind, newest first (default 2000). |
| `--max-jobs N` | CI jobs whose logs are read per project, newest first (default 50). |
| `--max-rate-wait SECS` | Longest rate-limit wait before giving up (default 900). |

All [common scan options](scanning.md#common-options) work too: `--verify`, `-f sarif`, `--fail`, baselines and alerts.

## Tokens

```bash
export GL_TOKEN=<token>   # personal, project or group access token with read_api
kubera scan gitlab --group acme --token-env GL_TOKEN --verify --only-verified
```

Without a token, gitlab.com only answers the issue and merge request lists of public projects: comments, job logs, snippets and wikis need a token, and Kubera prints one warning per project for each part it could not read.

- The token is read from an environment variable, never from argv, and sent as `PRIVATE-TOKEN` only to the `--api-url` host over HTTPS.
- API traffic is rate-limit aware (`RateLimit-*` and `Retry-After` headers) and follows pagination only to the same host.
- A job log that redirects to object storage is downloaded **without** the token. Logs are capped at 256 MiB; long logs are scanned in pieces of `--max-file-size`.
- Snippet and wiki repositories are cloned only from the API's own host; a snippet URL pointing anywhere else is skipped with a warning, so the token cannot be sent to another server.
