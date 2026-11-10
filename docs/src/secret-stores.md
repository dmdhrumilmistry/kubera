# Secret stores after rotation

A rotation is only finished once every consumer reads the new credential. With `--store`, `kubera rotate --execute` writes the new credential straight to where your CI and services read it: a **GitHub Actions secret**, a **HashiCorp Vault** KV v2 secret, or an **AWS Secrets Manager** secret. No copy and paste, and the value never appears on screen.

```bash
export GH_ADMIN_TOKEN=<token that may write Actions secrets>
kubera rotate gitlab-pat --secret-env LEAKED_TOKEN \
  --store github:acme/payments:GITLAB_TOKEN \
  --store-token-env GH_ADMIN_TOKEN
```

Without `--execute` this is a dry run: the plan lists the rotation calls **and** the store updates, without values. Add `--execute` once the plan looks right.

## Destinations

`--store` is repeatable. Each one names a destination and, optionally, which rotation output it receives (`=<output>`).

| Destination | Writes |
|---|---|
| `github:<owner>/<repo>:<SECRET_NAME>[=<output>]` | GitHub Actions **repository secret** `SECRET_NAME`. |
| `vault:<mount>/<path>#<key>[=<output>]` | Key `key` of the Vault KV v2 secret `path` under the mount `mount`. |
| `aws-sm:<secret-id>[#<json-key>][=<output>]` | AWS Secrets Manager secret `secret-id` (a name or an ARN): the whole value, or one key of its JSON. |

**Outputs** are the values a rotation produces, listed under `outputs` in the template (for example `new_token` and `new_expires_at` for `gitlab-pat`). Without `=<output>`, Kubera stores the template's only secret output. When a template has several (AWS has `new_access_key_id` and `new_secret_access_key`), name the one each destination receives:

```bash
kubera rotate aws-access-key -e access_key_id=AK -e secret_access_key=SK \
  --store 'aws-sm:prod/payments#AWS_ACCESS_KEY_ID=new_access_key_id' \
  --store 'aws-sm:prod/payments#AWS_SECRET_ACCESS_KEY=new_secret_access_key' \
  --store-region eu-west-1 \
  --execute -o new-aws-key.json
```

Keys for the **same** Vault path or AWS secret are written in one request, so consumers never read a new key id next to an old secret.

## Credentials

Every credential comes from an environment variable, never from the command line.

| Store | Environment | Flags |
|---|---|---|
| GitHub | the variable named by `--store-token-env` | `--store-github-api URL` for GitHub Enterprise (`https://ghe.example.com/api/v3`) |
| Vault | `VAULT_ADDR`, `VAULT_TOKEN`, optional `VAULT_NAMESPACE` | |
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`; region from `AWS_REGION` or `AWS_DEFAULT_REGION`; optional `AWS_ENDPOINT_URL_SECRETS_MANAGER` or `AWS_ENDPOINT_URL` | `--store-region REGION` |

Permissions each one needs:

- **GitHub**: a fine-grained token with *Secrets: read and write* on the repository (or a classic token with `repo`).
- **Vault**: `create`, `update` and `patch` on `<mount>/data/<path>`.
- **AWS**: `secretsmanager:PutSecretValue` on the secret, plus `secretsmanager:GetSecretValue` when you use `#json-key`.

<div class="kubera-callout warning">
<p class="kubera-callout-title">Rotating the AWS key that writes the store</p>

If the `AWS_*` variables hold the very key you are rotating, the rotation deactivates it before the store write, which then fails. Use a different identity for Secrets Manager. Kubera still prints the new key (or writes it to `-o`), so nothing is lost.

</div>

## What happens on --execute

1. **Before anything is rotated**, Kubera checks that every store is fully configured (tokens set, HTTPS URLs, a region for AWS) and reads each GitHub repository's public key, which also proves the token works. Any problem stops here, while the old credential still works.
2. The rotation runs as usual: verification, confirmation, steps in order.
3. **With `-o FILE`, the new credential is written to the file first** (mode `0600`, never overwritten).
4. Only if every rotation step succeeded, each store is written:
   - **GitHub**: the value is encrypted on your machine with the repository's public key (a libsodium sealed box), so GitHub only ever receives ciphertext. Then `PUT /repos/<owner>/<repo>/actions/secrets/<SECRET_NAME>`.
   - **Vault**: `PATCH /v1/<mount>/data/<path>` merges the key into the secret and keeps its other keys. If the secret does not exist yet, it is created with `cas=0` (create only, so a concurrent write is never overwritten).
   - **AWS**: `PutSecretValue` with a fresh idempotency token. With `#json-key`, the current value is read with `GetSecretValue`, the key set, and the whole JSON object written back as a new version. Without it, the new credential becomes the whole `SecretString`.
5. A failed store does not stop the others. The report lists each store as `✔` or `✘` with the error.

**The new credential is never lost.** It is printed (once) unless it reached the output file or every store that wanted it. When a store fails, the credential is printed so you can store it by hand, and `rotate` exits with code `4`.

| Exit code | Meaning |
|---|---|
| `0` | Rotation completed and every store was updated. |
| `2` | The rotation did not complete. Stores are skipped: nothing is written for a half-done rotation. |
| `4` | The rotation completed, but at least one store was not updated. |

With `--format json`, the report has a `stores` array: `target`, `values` (`key <- output`), `executed`, `ok` and `error`.

## Security

- Credentials come only from environment variables. Store tokens, the old secret and the new one are masked in every error message.
- Requests go only to the configured host (`api.github.com` or `--store-github-api`, `VAULT_ADDR`, the regional Secrets Manager endpoint or your override), over HTTPS. Redirects are never followed.
- Plans and reports never contain values. A GitHub secret is encrypted before it leaves your machine.
- Nothing is written to disk, except the `-o` file you ask for.
- When a secret is stored everywhere it should be, it is not printed.

See also: [Verify, analyze and rotate](lifecycle.md#rotate) and [After a scan](workflow.md#4-update-every-consumer).
