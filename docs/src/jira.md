# Jira and Confluence

Tickets and wiki pages collect credentials: a key pasted into a bug report "to reproduce", a connection string in a runbook, a token in a comment. Editing the text later does not remove it, because Jira keeps earlier values in each issue's history.

## Jira

`kubera scan jira` reads Jira Cloud issues found by a JQL search: summary, description, environment, every comment, and the earlier values of those fields from the change history.

```bash
export JIRA_EMAIL=dana@acme.example
export JIRA_TOKEN=<API token from id.atlassian.com>
kubera scan jira --site https://acme.atlassian.net --email-env JIRA_EMAIL --token-env JIRA_TOKEN
kubera scan jira --site acme.atlassian.net --project OPS --project SEC --email-env JIRA_EMAIL --token-env JIRA_TOKEN
kubera scan jira --site acme.atlassian.net --jql 'project = OPS AND updated >= -30d' --email-env JIRA_EMAIL --token-env JIRA_TOKEN
kubera scan jira --site hibernate.atlassian.net --jql 'project = HHH AND updated >= -7d'   # a public site, no credentials
```

| Item | Location in findings | Link |
|---|---|---|
| Summary, description and environment | `OPS-12` | the issue |
| A comment | `OPS-12/comment/<id>` | the comment (`?focusedCommentId=`) |
| An earlier summary, description or environment | `OPS-12/history/<change id>` | the issue (History tab) |

The repository is `jira:<site host>`. Descriptions and comments in Atlassian Document Format are flattened to text, link targets included (URLs carry credentials too).

| Flag | Meaning |
|---|---|
| `--site URL` | The Jira site, e.g. `https://acme.atlassian.net`. |
| `--jql QUERY` | Which issues to read (default: every issue, newest first). |
| `--project KEY` | Only these projects (repeatable; instead of `--jql`). |
| `--email-env VAR` | Environment variable with the Atlassian account email. |
| `--token-env VAR` | Environment variable with the API token (with `--email-env`), or a bearer token without it. |
| `--max-issues N` | Issues read (default 10000). |
| `--no-history` | Skip the change history. |
| `--max-rate-wait SECS` | Longest rate-limit wait before giving up (default 900). |

Attachments are not downloaded.

## Confluence

`kubera scan confluence` reads Confluence Cloud spaces: the body of every page and blog post, their footer and inline comments, and, with `--max-versions`, earlier versions of each page, where text that was edited out is still kept.

```bash
kubera scan confluence --site https://acme.atlassian.net --email-env JIRA_EMAIL --token-env JIRA_TOKEN
kubera scan confluence --site acme.atlassian.net --space OPS --space SEC --max-versions 10 --email-env JIRA_EMAIL --token-env JIRA_TOKEN
kubera scan confluence --site openmrs.atlassian.net --space docs --max-pages 50   # a public site, no credentials
```

| `--what` | Item | Location in findings |
|---|---|---|
| `pages` | Page title and body | `OPS/pages/<id>` |
| `blogposts` | Blog post title and body | `OPS/blogposts/<id>` |
| `comments` | Footer and inline comments | `OPS/pages/<id>/comments/<comment id>` |
| (with `--max-versions`) | An earlier version of a page or post | `OPS/pages/<id>/versions/<n>` |

The repository is `confluence:<site host>`; findings link to the page or comment. Bodies are read in storage format and turned into text: markup removed, entities decoded, code macros kept verbatim, and link targets kept.

| Flag | Meaning |
|---|---|
| `--site URL` | The site, e.g. `https://acme.atlassian.net` (with or without `/wiki`). |
| `--space KEY` | Only these spaces (repeatable; default: every space the account can see, personal spaces included). |
| `--what <kinds>` | `pages`, `blogposts`, `comments` (default: all). |
| `--email-env VAR`, `--token-env VAR` | Credentials, as for Jira. |
| `--max-pages N` | Pages, and blog posts, read per space (default 10000). |
| `--max-versions N` | Earlier versions read per page, newest first (default 0: none). Each version is one request. |
| `--max-rate-wait SECS` | Longest rate-limit wait before giving up (default 900). |

Attachments and replies to comments are not read.

## Credentials

- Credentials are read from environment variables, never from argv. With `--email-env` they are sent as basic auth; a token alone is sent as a bearer token (OAuth access tokens).
- Every URL is built from `--site`, and requests go only there (Confluence pagination links are followed only on the same host), over HTTPS, without following redirects. Rate limits (`429` with `Retry-After`) are honoured up to `--max-rate-wait`.
- The API token only needs read access: an account that can browse the projects and spaces is enough. One token works for Jira and Confluence on the same site.

All [common scan options](scanning.md#common-options) work too: `--verify`, `-f sarif`, `--fail`, baselines and alerts.
