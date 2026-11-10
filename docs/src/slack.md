# Slack messages

Credentials get pasted into chat more than anywhere else: "try with this key", a `.env` file dropped into a thread, a bot posting a deploy log. `kubera scan slack` reads channel history and thread replies through the Slack Web API and scans every message.

```bash
export SLACK_TOKEN=<xoxb- or xoxp- token>
kubera scan slack --token-env SLACK_TOKEN                          # every channel the token can see
kubera scan slack --channel general --channel C0123ABCD --token-env SLACK_TOKEN
kubera scan slack --since 2026-01-01 --token-env SLACK_TOKEN --verify --only-verified
```

## What gets scanned

Every message of the selected channels, newest first, up to `--max-messages` per channel: the message text, attachment text and fields, and the inline text of snippets and posts. Threads are followed (`conversations.replies`), so replies are covered too.

| Item | Location in findings |
|---|---|
| A message | `#general/1767312000.000100` (channel and message timestamp) |
| A thread reply | `#general/<thread ts>/<reply ts>` |

The repository is `slack:<workspace name>`; each finding carries the message time as its date, the author's user id, and a link that opens the message (or the reply in its thread) in Slack.

Uploaded files other than snippets are not downloaded: they live on `files.slack.com`, a different host from the API, and the token is only ever sent to the API. Edits are not visible either: the API returns the current text of a message only.

## Options

| Flag | Meaning |
|---|---|
| `--token-env VAR` | Environment variable with the token (required). |
| `--channel C` | Channel name (`general`, `#general`) or id (`C0123ABCD`), repeatable (default: every channel the token can see). |
| `--since DATE` | Only messages after this date: `YYYY-MM-DD`, RFC 3339 or Unix seconds. |
| `--include-dms` | Also read direct and group messages (user tokens). |
| `--include-archived` | Also read archived channels. |
| `--max-messages N` | Messages per channel, thread replies included (default 10000). |
| `--max-rate-wait SECS` | Longest rate-limit wait before giving up (default 900). |

All [common scan options](scanning.md#common-options) work too.

## Tokens and scopes

Create a Slack app, add the read scopes below, install it to the workspace and use its **bot token** (`xoxb-`). A bot only sees channels it was added to; channels it is not in produce a `not_in_channel` warning and are skipped. A **user token** (`xoxp-`) sees what that user sees, DMs included with `--include-dms`.

| Scope | For |
|---|---|
| `channels:read`, `groups:read` | Listing public and private channels |
| `channels:history`, `groups:history` | Reading their messages |
| `im:read`, `im:history`, `mpim:read`, `mpim:history` | `--include-dms` |

- The token is read from an environment variable, never from argv, and sent only to `slack.com` as a bearer header over HTTPS.
- Every call is read-only. Slack's rate limits answer `429` with `Retry-After`; Kubera waits that long and retries, up to `--max-rate-wait`.
- Findings are redacted like any other scan; rotate a leaked credential before deleting the message (see [Verify, analyze and rotate](lifecycle.md)).
