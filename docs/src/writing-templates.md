# Writing a template

This walkthrough adds a detector for a fictional platform, **Acme**, whose keys look like `acme_` followed by 32 alphanumeric characters.

## 1. Scaffold

```bash
mkdir -p kubera-templates
kubera templates new acme-key > kubera-templates/acme.yaml
```

The skeleton contains every section, filled with example values. Delete what you don't need: only `id`, `name` and `detect` are required.

## 2. Detection

```yaml
id: acme-key
name: Acme API Key
platform: Acme
severity: high
detect:
  keywords: [acme_]
  patterns:
    - name: token
      regex: '\b(acme_[A-Za-z0-9]{32})\b'
      min_entropy: 3.5
      exclude: ['(?i)example|x{8}']
```

- **keywords** are a cheap case-insensitive prefilter. Regexes run only on chunks containing at least one keyword, so make keywords specific: a fixed prefix is ideal.
- The **pattern name** (`token`) becomes the variable `{{ token }}` in requests.
- **min_entropy** drops low-randomness matches such as `acme_aaaaaaaa...`.
- **exclude** drops placeholders and documentation values.

## 3. Samples

Add samples to the template so its regexes are tested:

```yaml
tests:
  positive:
    - "ACME_KEY=acm{{'e'}}_Zq8Lw2Pm9Xa1Bc4De7Fg0Hi3Jk6Lm9No"
  negative:
    - "ACME_KEY=acme_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Samples are rendered through the template engine before matching. Splitting a literal with `{{'...'}}` keeps realistic-looking fake tokens out of your repository, so other secret scanners (and GitHub push protection) don't flag the template itself.

```bash
kubera templates validate kubera-templates/
```

## 4. Verification

Find the cheapest authenticated, **read-only** endpoint the vendor offers. "Who am I" endpoints are ideal.

```yaml
verify:
  request:
    url: https://api.acme.dev/v1/me
    auth: { type: bearer, token: "{{ token }}" }
  valid:   { status: [200] }
  invalid: { status: [401, 403] }
  extract:
    - { name: account, label: Account, json: user.email }
```

Responses that match neither `valid` nor `invalid` are reported as `unknown`, so keep `invalid` strict. A 429 or 500 should never be classed as invalid.

Try it:

```bash
export ACME_KEY=...
kubera -t kubera-templates verify acme-key -e ACME_KEY
```

## 5. Analysis

Each step is an independent request. Values extracted in `verify` and in earlier steps are available as variables.

```yaml
analyze:
  notes: Each probe is a harmless read.
  steps:
    - name: projects
      description: Projects the key can see
      request:
        url: https://api.acme.dev/v1/projects
        query: { owner: "{{ account }}" }
        auth: { type: bearer, token: "{{ token }}" }
      extract:
        - { name: projects, label: Projects, json: "data.*.name" }
    - name: billing
      description: Can read billing (admin keys only)
      request:
        url: https://api.acme.dev/v1/billing
        auth: { type: bearer, token: "{{ token }}" }
```

A step without `expect` succeeds on any 2xx response.

## 6. Rotation

Rotation steps run in order and stop at the first failure. Extract the new credential with `secret: true` and list it in `outputs`.

```yaml
rotate:
  instructions: |
    Kubera creates a replacement key and deletes the leaked one.
  inputs:
    - { name: key_name, default: "rotated-{{ date }}" }
  steps:
    - name: create
      request:
        method: POST
        url: https://api.acme.dev/v1/keys
        auth: { type: bearer, token: "{{ token }}" }
        json: { name: "{{ key_name }}" }
      expect: { status: [201] }
      extract:
        - { name: new_token, json: key, secret: true }
        - { name: new_key_id, json: id }
    - name: revoke
      request:
        method: DELETE
        url: https://api.acme.dev/v1/keys/self
        auth: { type: bearer, token: "{{ token }}" }
      expect: { status: [204] }
  outputs: [new_token, new_key_id]
```

Guidelines:

- **Create before you revoke**, so a failure never leaves the user without a working credential.
- Prefer *deactivating* over deleting when the platform supports it (see `aws-access-key`), so the change can be rolled back.
- If the platform has no rotation API, provide only `instructions`. They are always shown.

## 7. Use it

```bash
kubera -t kubera-templates scan fs .
```

Or add it to `.kubera.yaml`:

```yaml
templates: [./kubera-templates]
```

A template with the same `id` as a builtin replaces it. Copy `gitlab-pat` and change the host to support self-managed GitLab, for example.

To contribute a template to Kubera itself, add it to `templates/` in the repository. The test suite runs every builtin template's samples.
