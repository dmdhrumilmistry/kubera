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
```

**Group selection:** `group` if set, otherwise the named group matching the pattern's `name`, otherwise group 1 if the regex has groups, otherwise the whole match.

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
  method: GET                  # default GET
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

`form` and `json` set `Content-Type` unless you set it yourself.

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

## verify

```yaml
verify:
  request: Request          # required
  valid: Matcher            # required
  invalid: Matcher          # optional; otherwise non-valid = unknown
  extract: [Extract]        # run only when valid
```

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
