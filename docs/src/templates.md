# Template reference

A template is a YAML document. Unknown fields are rejected. Anchors, aliases and merge keys (`<<: *anchor`) are supported, which helps share request fragments between steps.

```yaml
id: string              # required, [A-Za-z0-9_-], unique
name: string            # required
description: string
platform: string
severity: info | low | medium | high | critical   # default medium
tags: [string]
references: [url]

detect: Detect          # required
verify: Verify
analyze: Analyze
rotate: Rotate
tests: Tests
```

## detect

```yaml
detect:
  keywords: [string]          # required, case-insensitive prefilter
  max_distance: 1024          # bytes allowed between parts of a multi-part secret
  patterns:                   # required, one per secret part
    - name: token             # required, becomes {{ token }}
      regex: '...'            # required, Rust regex syntax
      group: 1                # capture group holding the value (see below)
      min_entropy: 3.5        # Shannon bits/char
      exclude: ['regex']      # drop matches matching any of these
      captures: [key_id]      # extra named groups exposed as variables
      secret: true            # false = never masked (e.g. AWS key id)
      optional: false         # true = report even if this part is missing
```

**Group selection:** `group` if set, otherwise the named group matching the pattern's `name`, otherwise the **first capture group that matched** (so `(new_format)|(legacy_format)` alternatives work), otherwise the whole match.

**Optional parts** (`optional: true`) attach their nearest match within `max_distance` when one exists and never block a finding, e.g. the tenant host a token belongs to. Verification that needs a missing part reports `unknown`. At least one part must be required.

**Multi-part secrets:** with several patterns, every combination of matches whose start offsets lie within `max_distance` bytes of each other becomes one candidate. For example:

```yaml
patterns:
  - { name: access_key_id, regex: '\b(AKIA[A-Z2-7]{16})\b', secret: false }
  - { name: secret_access_key, regex: '...', min_entropy: 4.3 }
```

**Captures:** named groups listed in `captures` become variables too. `sendgrid-api-key` uses this to pull the key id out of `SG.<key_id>.<secret>`.

## Variables and templating

Any string inside a request (URL, header names and values, query, form, body, JSON strings, auth fields) and any input default may contain `{{ expr }}`:

```text
{{ token }}                    variable
{{ 'literal' }}                string literal
{{ token | base64 }}           filters, chainable left to right
{{ user | urlencode | upper }}
```

| Filter | Effect |
|---|---|
| `base64` / `base64url` | Standard / URL-safe unpadded base64 |
| `urlencode` | Percent-encode everything except `A-Za-z0-9` |
| `upper` / `lower` / `trim` | Case and whitespace |
| `sha256` | Lower-case hex digest |
| `json` | Escape for embedding inside a JSON string |

Variables in scope:

| Where | Variables |
|---|---|
| everywhere | `now` (unix seconds), `date` (`YYYY-MM-DD`), `datetime` (RFC 3339 UTC) |
| `verify` | pattern names and `captures` |
| `analyze` | the above, plus `verify.extract` names, plus extracts of earlier steps |
| `rotate` | the above (without analyze), plus `inputs`, plus extracts of earlier steps |

Using an undefined variable is a **validation error**, reported with the list of variables that are in scope.

## Request

```yaml
request:
  method: GET                  # GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, ...
  url: https://...             # required; must be https
  headers: { Name: value }
  query: { key: value }        # appended to the URL, encoded
  auth: Auth
  # at most one body:
  body: 'raw string'
  form: { key: value }         # application/x-www-form-urlencoded
  json: { any: "json" }        # strings rendered recursively
  timeout: 15                  # seconds
```

`form` and `json` set `Content-Type` unless you set it yourself. Every method can carry any body kind; examples from the builtin templates:

| Need | Template | Request |
|---|---|---|
| GraphQL query | `linear-api-key`, `new-relic-user-key` | `method: POST` + `json: { query: "{ viewer { id } }" }` |
| OAuth client-credentials | `paypal-oauth-credentials` | `method: POST` + `form: { grant_type: client_credentials }` + basic auth |
| RPC call without a body | `dropbox-access-token` | `method: POST`, no body |
| Roll a token in place | `cloudflare-api-token` (rotate) | `method: PUT` + `json: {}` |
| Revoke | `okta-api-token`, `buildkite-token`, `discord-webhook` (rotate) | `method: DELETE` |
| Token in the URL path / query | `telegram-bot-token`, `mapbox-secret-token` | `url: ".../bot{{ token }}/getMe"`, `query: { access_token: ... }` |

### auth

```yaml
auth: { type: bearer, token: "{{ token }}" }
auth: { type: basic, username: "{{ key }}", password: "" }
auth:
  type: aws_sigv4
  access_key: "{{ access_key_id }}"
  secret_key: "{{ secret_access_key }}"
  session_token: "{{ session_token }}"   # optional
  region: us-east-1
  service: sts
```

SigV4 signs every header that is sent, plus `host` and `x-amz-date`, and covers the request body.

## Matcher

Used by `verify.valid`, `verify.invalid` and step `expect`. **All** conditions present must hold.

```yaml
status: [200, 204]
body_contains: ["\"ok\":true"]
body_not_contains: [ratelimited]
json:
  - { path: ok, equals: true }
  - { path: data.user.id, exists: true }
headers:
  - { name: x-oauth-scopes }                  # present
  - { name: content-type, contains: json }
```

### JSON paths

Dot-separated keys and indexes. `*` maps over array elements or object values:

| Path | Result |
|---|---|
| `user.login` | `"alice"` |
| `items.0.id` | first item's id |
| `items.*.name` | `["a", "b"]` |
| `$` or empty | whole document |

A leading `$.` is ignored.

## Extract

```yaml
extract:
  - name: login          # variable name
    label: User          # shown in reports (default: name)
    json: user.login     # exactly one of json / header / regex
  - { name: scopes, header: x-oauth-scopes }
  - { name: arn, regex: '"Arn":"([^"]+)"|<Arn>([^<]+)</Arn>' }
  - { name: policies, regex: '<PolicyName>([^<]+)</PolicyName>', all: true }
  - { name: new_token, json: key, secret: true }
```

- `regex` uses the first non-empty capture group (or the whole match), so alternations can cover both JSON and XML shapes.
- `all: true` collects every regex match into a list.
- Non-string JSON values (arrays, numbers) become variables as compact JSON text, so `{{ scopes }}` can be embedded in a raw `body`.
- `secret: true` masks the value in reports. In `rotate`, every secret extract is preserved in the outputs.

Add `any:` to require **at least one** of several matchers (OR), on top of the conditions above (AND):

```yaml
invalid:
  any:
    - { status: [401] }
    - { status: [400], body_contains: [AUTHENTICATION] }
    - { status: [200], json: [{ path: code, equals: TokenRevoked }] }
```

## verify

```yaml
verify:
  request: Request          # required
  valid: Matcher            # required
  invalid: Matcher          # optional; otherwise non-valid = unknown
  extract: [Extract]        # run only when valid
  fallbacks:                # optional alternate endpoints, tried in order
    - label: EU region      # shown as the `Endpoint` detail when it verifies
      request: Request
      valid: Matcher        # default: the parent's
      invalid: Matcher      # default: the parent's
```

With fallbacks, a secret is `verified` as soon as **one** endpoint accepts it, `invalid` only when **every** endpoint rejects it, and `unknown` otherwise. Use them for regional APIs (Datadog sites, Mailgun/New Relic EU), sandbox vs production (Square, PayPal) or alternative token kinds (Postmark server vs account tokens).

## analyze

```yaml
analyze:
  notes: string
  steps: [Step]
```

## rotate

```yaml
rotate:
  instructions: string        # manual runbook, always shown
  inputs:
    - name: key_name
      description: string
      default: "kubera-{{ date }}"   # no default = required (--set key_name=...)
  steps: [Step]
  outputs: [variable]         # the new credential; must be extracted by a step
```

At least one of `instructions` or `steps` is required.

## Step

```yaml
- name: create              # unique within the list
  description: string
  request: Request
  expect: Matcher           # default: any 2xx
  extract: [Extract]
  optional: false           # rotate: continue even if this step fails
```

## tests

```yaml
tests:
  positive: [string]        # each must yield >= 1 finding
  negative: [string]        # each must yield none
```

Samples are rendered first, so write `xox{{'b'}}-...` to keep literal tokens out of the repository. Run them with `kubera templates test` or `kubera templates validate <path>`.
