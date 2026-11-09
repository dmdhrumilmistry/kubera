# Builtin detectors

Kubera ships **89 detectors**. Every verifier was checked against the live vendor API with fake credentials (they must come back `invalid`, proving the endpoint, headers and matchers are right).

| Detector | Platform | Severity | Verify | Analyze | Rotate |
|---|---|---|---|---|---|
| `age-secret-key` | age | high | - | - | manual |
| `airtable-pat` | Airtable | high | GET api.airtable.com | - | manual |
| `algolia-admin-key` | Algolia | high | GET (per-tenant host) | - | manual |
| `anthropic-api-key` | Anthropic | high | GET api.anthropic.com | yes | manual |
| `asana-pat` | Asana | high | GET app.asana.com | - | manual |
| `aws-access-key` | AWS | critical | POST sts.amazonaws.com | yes | **API** (POST) |
| `azure-storage-connection-string` | Azure | critical | - | - | manual |
| `brevo-api-key` | Brevo | high | GET api.brevo.com | - | manual |
| `buildkite-token` | Buildkite | high | GET api.buildkite.com | - | **API** (DELETE) |
| `cerebras-api-key` | Cerebras | medium | GET api.cerebras.ai | - | manual |
| `circleci-pat` | CircleCI | high | GET circleci.com | - | manual |
| `clickup-pat` | ClickUp | high | GET api.clickup.com | yes | manual |
| `cloudflare-api-token` | Cloudflare | critical | GET api.cloudflare.com | - | **API** (PUT) |
| `cloudinary-url` | Cloudinary | high | GET api.cloudinary.com | - | manual |
| `contentful-pat` | Contentful | high | GET api.contentful.com | yes | manual |
| `database-connection-uri` | Generic | high | - | - | manual |
| `databricks-token` | Databricks | critical | GET (per-tenant host) | - | manual |
| `datadog-api-key` | Datadog | high | GET api.datadoghq.com +5 fallback(s) | - | manual |
| `deepseek-api-key` | DeepSeek | medium | GET api.deepseek.com | - | manual |
| `digitalocean-token` | DigitalOcean | critical | GET api.digitalocean.com | yes | manual |
| `discord-bot-token` | Discord | high | GET discord.com | yes | manual |
| `discord-webhook` | Discord | medium | GET (per-tenant host) | - | **API** (DELETE) |
| `docker-hub-pat` | Docker | high | POST hub.docker.com | - | manual |
| `doppler-token` | Doppler | critical | GET api.doppler.com | - | **API** (POST) |
| `dropbox-access-token` | Dropbox | high | POST api.dropboxapi.com | - | manual |
| `duffel-api-token` | Duffel | high | GET api.duffel.com | - | manual |
| `easypost-api-key` | EasyPost | high | GET api.easypost.com | - | manual |
| `elevenlabs-api-key` | ElevenLabs | medium | GET api.elevenlabs.io | - | manual |
| `figma-pat` | Figma | medium | GET api.figma.com | - | manual |
| `gcp-service-account-key` | Google Cloud | critical | - | - | manual |
| `github-token` | GitHub | critical | GET api.github.com | yes | **API** (POST) |
| `gitlab-pat` | GitLab | critical | GET gitlab.com | yes | **API** (POST) |
| `gitlab-runner-token` | GitLab | critical | POST gitlab.com | - | manual |
| `google-api-key` | Google Cloud | medium | - | - | manual |
| `grafana-cloud-token` | Grafana | high | GET grafana.com | - | manual |
| `grafana-service-account-token` | Grafana | high | GET (per-tenant host) | yes | manual |
| `groq-api-key` | Groq | medium | GET api.groq.com | - | manual |
| `hashicorp-vault-token` | HashiCorp | critical | - | - | manual |
| `heroku-api-key` | Heroku | critical | GET api.heroku.com | yes | manual |
| `hubspot-private-app-token` | HubSpot | high | GET api.hubapi.com | - | manual |
| `huggingface-token` | Hugging Face | high | GET huggingface.co | yes | manual |
| `infracost-api-key` | Infracost | low | POST pricing.api.infracost.io | - | manual |
| `intercom-access-token` | Intercom | high | GET api.intercom.io | - | manual |
| `langfuse-api-key` | Langfuse | high | GET cloud.langfuse.com +1 fallback(s) | - | manual |
| `langsmith-api-key` | LangSmith | high | GET api.smith.langchain.com +1 fallback(s) | - | manual |
| `launchdarkly-access-token` | LaunchDarkly | high | GET app.launchdarkly.com | yes | manual |
| `linear-api-key` | Linear | high | POST api.linear.app | yes | manual |
| `mailchimp-api-key` | Mailchimp | high | GET (per-tenant host) | - | manual |
| `mailgun-api-key` | Mailgun | high | GET api.mailgun.net +1 fallback(s) | - | manual |
| `mapbox-secret-token` | Mapbox | medium | GET api.mapbox.com | - | manual |
| `neon-api-key` | Neon | critical | GET console.neon.tech | yes | manual |
| `netlify-token` | Netlify | high | GET api.netlify.com | yes | manual |
| `new-relic-user-key` | New Relic | high | POST api.newrelic.com +1 fallback(s) | - | manual |
| `notion-token` | Notion | high | GET api.notion.com | - | manual |
| `npm-token` | npm | critical | GET registry.npmjs.org | yes | manual |
| `okta-api-token` | Okta | critical | GET (per-tenant host) | - | **API** (DELETE) |
| `openai-api-key` | OpenAI | high | GET api.openai.com | yes | manual |
| `openrouter-api-key` | OpenRouter | high | GET openrouter.ai | - | manual |
| `paypal-oauth-credentials` | PayPal | critical | POST api-m.paypal.com +1 fallback(s) | - | manual |
| `perplexity-api-key` | Perplexity | medium | GET api.perplexity.ai | - | manual |
| `pinecone-api-key` | Pinecone | high | GET api.pinecone.io | - | manual |
| `postman-api-key` | Postman | high | GET api.getpostman.com | yes | manual |
| `postmark-token` | Postmark | high | GET api.postmarkapp.com +1 fallback(s) | - | manual |
| `prefect-api-key` | Prefect | high | GET api.prefect.cloud | yes | manual |
| `private-key` | Generic | high | - | - | manual |
| `pulumi-token` | Pulumi | critical | GET api.pulumi.com | - | manual |
| `pypi-token` | PyPI | critical | - | - | manual |
| `razorpay-key` | Razorpay | critical | GET api.razorpay.com | - | manual |
| `readme-api-key` | ReadMe | medium | GET dash.readme.com | - | manual |
| `render-api-key` | Render | critical | GET api.render.com | yes | manual |
| `replicate-api-token` | Replicate | medium | GET api.replicate.com | - | manual |
| `resend-api-key` | Resend | high | GET api.resend.com | - | manual |
| `rubygems-api-key` | RubyGems | critical | GET rubygems.org | - | manual |
| `sendgrid-api-key` | SendGrid | high | GET api.sendgrid.com | yes | **API** (DELETE, POST) |
| `sentry-token` | Sentry | high | GET sentry.io | - | manual |
| `shippo-api-token` | Shippo | high | GET api.goshippo.com | - | manual |
| `shopify-access-token` | Shopify | critical | GET (per-tenant host) | - | manual |
| `slack-token` | Slack | high | POST slack.com | yes | **API** (POST) |
| `slack-webhook` | Slack | medium | POST (per-tenant host) | - | manual |
| `snyk-api-token` | Snyk | high | GET api.snyk.io | - | manual |
| `square-access-token` | Square | critical | GET connect.squareup.com +1 fallback(s) | - | manual |
| `stripe-secret-key` | Stripe | critical | GET api.stripe.com | yes | manual |
| `supabase-management-token` | Supabase | critical | GET api.supabase.com | - | manual |
| `tailscale-api-key` | Tailscale | critical | GET api.tailscale.com | - | manual |
| `telegram-bot-token` | Telegram | medium | GET api.telegram.org | yes | manual |
| `terraform-cloud-token` | HashiCorp | critical | GET app.terraform.io | - | manual |
| `twilio` | Twilio | critical | GET api.twilio.com | yes | **API** (POST) |
| `typeform-pat` | Typeform | medium | GET api.typeform.com | - | manual |
| `xai-api-key` | xAI | medium | GET api.x.ai | - | manual |

Print any template with `kubera templates show <id>`; sources live in [`templates/`](https://github.com/dmdhrumilmistry/kubera/tree/main/templates).

## Notes

- **Multi-part secrets** pair parts found near each other: `aws-access-key` (key id + secret), `twilio` (account SID + auth token), `paypal-oauth-credentials`, `razorpay-key`, `algolia-admin-key`, `azure-storage-connection-string`, `gcp-service-account-key`, `langfuse-api-key` (public + secret key).
- **Optional parts:** `shopify-access-token`, `okta-api-token`, `databricks-token` and `grafana-service-account-token` report the token even when its host is not nearby; verification then needs the host and reports `unknown`. `docker-hub-pat` likewise needs the Docker ID found next to the token.
- **Fallback endpoints:** `datadog-api-key` tries all six Datadog sites; `mailgun-api-key`, `new-relic-user-key` and `langsmith-api-key` try their EU regions; `langfuse-api-key` tries its US region; `square-access-token` and `paypal-oauth-credentials` try sandbox; `postmark-token` tries server- then account-token headers. A key is `invalid` only when every endpoint rejects it.
- **Rotation by API** uses the method each vendor needs: `PUT` (Cloudflare rolls the token value in place), `DELETE` (Discord webhooks, Okta, Buildkite revoke), `POST` (Twilio promotes a new auth token, GitLab rotates, SendGrid recreates, Doppler/Slack/GitHub revoke).
- **Detection-only** templates cover credentials whose verification needs a database or cloud protocol rather than HTTPS: `database-connection-uri`, `azure-storage-connection-string`, `gcp-service-account-key`, `pypi-token`, `hashicorp-vault-token`, `age-secret-key`, `private-key`.
- **AWS** pairs an access key id with a 40-character secret found within 2 KiB of it; entropy above 4.3 bits/char rules out git SHAs.
- **Slack webhooks** are verified by POSTing `{}`: a live webhook rejects the empty payload with HTTP 400 without posting anything; **Discord webhooks** by a GET that only reads metadata.
- **Keyword-anchored formats:** `deepseek-api-key` uses the generic `sk-` + 32 hex shape, so it only fires when "deepseek" appears shortly before the key.
