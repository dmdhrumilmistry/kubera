# Alerts

A scheduled scan is only useful if someone hears about what it finds. With `--notify-env`, any scan posts to Slack or to your own webhook when it finds secrets.

```bash
export SLACK_WEBHOOK=<slack incoming webhook url>
kubera scan repos --github-org acme --token-env GH_TOKEN --verify --notify-env SLACK_WEBHOOK
```

## Options

| Flag | Meaning |
|---|---|
| `--notify-env VAR` | Send an alert to the webhook URL held in this environment variable (repeatable, one per destination). |
| `--notify-secret-env VAR` | Environment variable with a key that signs generic webhook payloads. |
| `--notify-on live\|all` | Which findings trigger an alert. Default: `live` with `--verify`, otherwise `all`. |

- The URL comes from an environment variable, never from argv: a Slack webhook URL is itself a credential.
- No alert is sent when nothing matches `--notify-on`. `--notify-on live` needs `--verify`, since nothing is known to be live without it.
- Alerts carry **redacted** findings only, whatever `--show-secrets` says.
- Webhooks must use HTTPS, and redirects are not followed.
- **A failed delivery makes an otherwise clean scan exit 1**, so a scheduled job whose alert was lost does not look green. With `--fail`, findings still exit 183.

## Slack

URLs on `hooks.slack.com` get a Slack message: how many secrets were found and how many are live, then one line per finding (name, severity, status, location, commit, repository), up to 15. Paths, names and commit authors come from scanned content, so they are escaped: a hostile file name cannot inject `<!channel>` mentions or links.

## Generic webhooks

Any other URL gets a JSON `POST`:

```json
{
  "event": "kubera.findings",
  "version": 1,
  "source": "42 repositories",
  "count": 2,
  "live": 1,
  "findings": [ { "detector": "github-token", "fingerprint": "bc0458ecc5e4611e9dde21f8", "...": "..." } ]
}
```

`findings` holds the same objects as `-f json`, redacted. Every request carries the headers `X-Kubera-Event: findings` and `X-Kubera-Timestamp` (Unix seconds).

### Signed payloads

With `--notify-secret-env`, each request also carries

```text
X-Kubera-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">
```

where `<timestamp>` is the `X-Kubera-Timestamp` header and `<body>` the raw request body. The timestamp is signed too, so the receiver can reject both forged and replayed deliveries:

```bash
export KUBERA_WEBHOOK=<https url of your receiver>
export KUBERA_WEBHOOK_KEY=<random shared key>
kubera scan git . --notify-env KUBERA_WEBHOOK --notify-secret-env KUBERA_WEBHOOK_KEY
```

A receiver in Python:

```python
import hashlib, hmac, time

def verify(headers, body: bytes, key: bytes, max_age=300) -> bool:
    ts = headers.get("X-Kubera-Timestamp", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > max_age:
        return False  # missing, stale or replayed
    mac = hmac.new(key, ts.encode() + b"." + body, hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, headers.get("X-Kubera-Signature", ""))
```

Verify against the raw body bytes, before parsing the JSON.

## A scheduled mass scan

A nightly GitHub Actions job that scans the whole organization, only reads commits added since the last run, and pings Slack about live secrets:

```yaml
name: Nightly secret scan
on:
  schedule:
    - cron: "23 2 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  kubera:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/kubera/main/install.sh | sh
      - uses: actions/cache@v4
        with:
          path: ~/.cache/kubera
          key: kubera-${{ github.run_id }}
          restore-keys: kubera-
      - run: |
          ~/.local/bin/kubera scan repos --github-org acme --token-env GH_TOKEN \
            --cache-dir ~/.cache/kubera --state ~/.cache/kubera/state.json \
            --verify --notify-env SLACK_WEBHOOK
        env:
          GH_TOKEN: ${{ secrets.ORG_READ_TOKEN }}
          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
```

The same flags work in a cron job, a Kubernetes [CronJob](kubernetes.md#running-in-the-cluster) or with the [container image](installation.md#container-image).
