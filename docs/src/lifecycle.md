# Verify, analyze and rotate

These commands work on **one credential** you already hold, typically a finding from `scan`.

## Passing the secret

Avoid putting secrets on the command line, where they end up in shell history and process listings.

| Option | Example |
|---|---|
| `-e, --secret-env NAME=ENV_VAR` | `kubera verify gitlab-pat -e TOKEN` |
| `--secret-stdin` | `pass show ci/gitlab \| kubera verify gitlab-pat --secret-stdin` |
| `-s, --secret NAME=VALUE` | Works, but prints a warning. |

For single-part detectors you can drop the `NAME=` prefix. Multi-part detectors take each part by name:

```bash
kubera verify aws-access-key \
  -e access_key_id=AWS_ACCESS_KEY_ID \
  -e secret_access_key=AWS_SECRET_ACCESS_KEY
```

With `--secret-stdin`, multi-part secrets are read as one `NAME=VALUE` per line. Values derived from a part (such as the key id embedded in a SendGrid key) are extracted automatically.

## verify

```bash
kubera verify slack-token -e SLACK_TOKEN
kubera verify slack-token -e SLACK_TOKEN --format json
```

The exit code is `0` if the credential is live, `2` if it's invalid and `3` if the result is inconclusive, which makes it easy to script.

## analyze

```bash
kubera analyze github-token -e GITHUB_TOKEN
```

```text
GitHub Token (github-token)  VERIFIED (live)
  Scopes           repo, workflow
  User             alice

✔ organizations - Organizations visible to the token
    Organizations    acme, acme-labs
✔ repositories - Repositories the token can access (first 100)
    Repositories     acme/api, acme/web, alice/dotfiles
```

Analysis runs only if verification succeeds, unless you pass `--force`. Each step is independent, so a failed step (for example HTTP 403) is reported and the next one still runs. A failed probe is useful in itself: it shows the credential *lacks* that permission. Sensitive extracted values are masked unless you pass `--show-secrets`.

## rotate

Rotation always starts as a **dry run**:

```bash
kubera rotate aws-access-key -e access_key_id=AK -e secret_access_key=SK
```

```text
rotate aws-access-key  current credential: VERIFIED (live)

Instructions
  Kubera creates a new access key for the same IAM user, then DEACTIVATES
  (does not delete) the leaked key so you can roll back if something breaks.
  ...

Planned API calls (dry run - pass --execute to perform)
  1. create_access_key Create a replacement key for the same user
     POST https://iam.amazonaws.com/
       Accept: application/json
       content-type: application/x-www-form-urlencoded
       x-amz-date: 20261109T101951Z
       authorization: <redacted>
       body: Action=CreateAccessKey&Version=2010-05-08
  2. deactivate_leaked_key Mark the leaked key Inactive
     POST https://iam.amazonaws.com/
       ...
       body: AccessKeyId=AKIA********3O&Action=UpdateAccessKey&Status=Inactive&Version=2010-05-08
```

To perform it:

```bash
kubera rotate aws-access-key -e access_key_id=AK -e secret_access_key=SK \
  --execute --output-file new-aws-key.json
```

What happens on `--execute`:

1. The credential is verified again. Kubera **refuses** to continue unless it is live; `--force` overrides this.
2. Kubera shows the plan and asks you to type the detector id. `--yes` skips the prompt, and is required when stdin is not a terminal.
3. Steps run in order and **stop at the first failure**, unless a step is marked `optional`.
4. Any new credential already created is returned **even if a later step failed**, so a replacement key is never lost.
5. With `--output-file`, the new credential is written to a new file with mode `0600`. Kubera refuses to overwrite an existing file. Without it, the credential is printed once.

Some templates take inputs, for example the name of the replacement key:

```bash
kubera rotate sendgrid-api-key -e SG_KEY --set key_name=prod-mailer-2026-11 --execute
```

When a platform has no API for rotation (Stripe, OpenAI, Telegram, ...), `rotate` prints the template's manual instructions.

### Rotation support

| Detector | Automated steps |
|---|---|
| `aws-access-key` | `iam:CreateAccessKey`, then `iam:UpdateAccessKey Status=Inactive` on the leaked key |
| `gitlab-pat` | `POST /personal_access_tokens/self/rotate` (new token, old one revoked) |
| `sendgrid-api-key` | Create a key with identical scopes, then delete the leaked key using the new one |
| `github-token` | Revoke via `POST /credentials/revoke` (create the replacement manually first) |
| `slack-token` | Revoke via `auth.revoke` (reissue manually first) |
| others | Manual instructions |
