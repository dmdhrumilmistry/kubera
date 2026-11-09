# Builtin detectors

| Detector | Platform | Severity | Verify | Analyze | Rotate |
|---|---|---|---|---|---|
| `aws-access-key` | AWS | critical | STS `GetCallerIdentity` (SigV4) | IAM user, attached policies, groups, access keys | **API** |
| `github-token` | GitHub | critical | `GET /user` | scopes, rate limit, orgs, repositories | **API** (revoke) |
| `gitlab-pat` | GitLab | critical | `GET /api/v4/user` | token scopes and expiry, writable projects | **API** |
| `sendgrid-api-key` | SendGrid | high | `GET /v3/scopes` | key name, account, verified senders | **API** |
| `slack-token` | Slack | high | `auth.test` | channels, workspace | **API** (revoke) |
| `stripe-secret-key` | Stripe | critical | `GET /v1/balance` | account, read probes on charges, customers, payouts and webhooks | manual |
| `openai-api-key` | OpenAI | high | `GET /v1/models` | owner, models, files, fine-tuning | manual |
| `anthropic-api-key` | Anthropic | high | `GET /v1/models` | models | manual |
| `npm-token` | npm | critical | `GET /-/whoami` | tokens, maintained packages | manual |
| `huggingface-token` | Hugging Face | high | `GET /api/whoami-v2` | role, orgs, models | manual |
| `digitalocean-token` | DigitalOcean | critical | `GET /v2/account` | droplets, projects | manual |
| `telegram-bot-token` | Telegram | medium | `getMe` | webhook target | manual |
| `slack-webhook` | Slack | medium | empty-payload probe (posts nothing) | - | manual |
| `google-api-key` | Google Cloud | medium | - | - | manual |
| `private-key` | Generic | high | - | - | manual |

The template sources are in [`templates/`](https://github.com/dmdhrumilmistry/kubera/tree/main/templates). Print the active version of any detector with:

```bash
kubera templates show aws-access-key
```

## Notes

- **aws-access-key** pairs an access key id with a 40-character secret found within 2 KiB of it. The secret part must have entropy above 4.3 bits/char, which rules out git SHAs and other hex strings. Rotation creates a new key for the same IAM user, then *deactivates* the leaked one (IAM users can hold at most two keys).
- **github-token** covers classic and fine-grained PATs plus `gho_`, `ghu_`, `ghs_` and `ghr_` tokens. GitHub cannot mint a replacement PAT through its API, so rotation revokes the leaked token through the public credential revocation API after you create the replacement.
- **gitlab-pat** targets gitlab.com. For self-managed GitLab, copy the template, keep the `id` (to override) or pick a new one, and change the host.
- **sendgrid-api-key** recreates the key with the *same scopes* as the leaked one, then deletes the leaked key **using the new key**, which also proves the new key works.
- **slack-webhook** verifies by POSTing `{}`. A live webhook rejects the empty payload with HTTP 400 without posting anything.
