# Cheat sheet: common tasks

One-line recipes, grouped by what you want to do. Every code block has a copy button. Replace `acme/payments` and the other examples with your own names.

## Scan code and git history

Files in a folder (no history):

```bash
kubera scan fs .
```

Every commit of the current repository:

```bash
kubera scan git .
```

A remote repository (HTTPS, SSH or `github.com/org/repo`):

```bash
kubera scan git https://github.com/acme/payments.git
```

A private repository, with a token from an environment variable:

```bash
kubera scan git https://github.com/acme/payments.git --token-env GH_TOKEN
```

Only the commits after a given revision:

```bash
kubera scan git . --since-commit origin/main
```

Only what the next commit adds (what the pre-commit hook runs):

```bash
kubera scan staged
```

Anything piped in, such as a build log:

```bash
cat build.log | kubera scan stdin
```

## Scan organizations, images, GitHub, buckets and Kubernetes

Every repository of a GitHub organization, with cached mirrors for fast re-runs:

```bash
kubera scan repos --github-org acme --token-env GH_TOKEN --cache-dir ~/.cache/kubera --state ~/.cache/kubera/state.json
```

A container image, every layer, no Docker needed:

```bash
kubera scan image ghcr.io/acme/api:1.4.2
```

What users install from npm, PyPI or crates.io, every published version:

```bash
kubera scan package npm:@acme/cli pypi:acme-tool crates:acme --all-versions
```

Every image a Docker Hub organization publishes (newest tag of each repository):

```bash
kubera scan dockerhub acme
```

Every model, dataset and Space of a Hugging Face organization, full git history:

```bash
kubera scan huggingface acme --token-env HF_TOKEN
```

GitHub issues, pull requests, comments and Actions logs of an organization:

```bash
kubera scan github --org acme --token-env GH_TOKEN
```

GitLab issues, merge requests, comments and CI job logs of a group:

```bash
kubera scan gitlab --group acme --token-env GL_TOKEN
```

Bitbucket issues, pull requests, comments and Pipelines logs of a workspace:

```bash
kubera scan bitbucket --workspace acme --token-env BB_TOKEN
```

Slack channels and threads since the start of the year (bot or user token):

```bash
kubera scan slack --since 2026-01-01 --token-env SLACK_TOKEN
```

Jira issues, comments and their edit history (Atlassian email and API token):

```bash
kubera scan jira --site https://acme.atlassian.net --email-env JIRA_EMAIL --token-env JIRA_TOKEN
```

Confluence pages, blog posts, comments and the last 10 versions of each page:

```bash
kubera scan confluence --site https://acme.atlassian.net --max-versions 10 --email-env JIRA_EMAIL --token-env JIRA_TOKEN
```

An S3 bucket (credentials from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`):

```bash
kubera scan bucket s3://acme-backups
```

An Azure Blob container (key from `AZURE_STORAGE_KEY`, or a SAS token with `--sas-env`):

```bash
kubera scan bucket az://acmedata/backups
```

A live Kubernetes cluster, current kubeconfig context:

```bash
kubera scan k8s
```

## Verify and browse findings

Verify everything a scan finds:

```bash
kubera scan git . --verify
```

Report only live secrets:

```bash
kubera scan git . --only-verified
```

Browse the results in the TUI:

```bash
kubera scan git . --verify -i
```

Open the TUI home menu:

```bash
kubera
```

Check one credential: paste it at the hidden prompt and Kubera works out what it is:

```bash
kubera verify
```

## Respond to a live secret: analyze, rotate, revoke

The full procedure is in [After a scan](workflow.md#live-secrets-revoke-and-rotate). Each command asks for the secret at a hidden prompt.

What the credential can access (read-only API calls):

```bash
kubera analyze aws-access-key
```

The rotation plan, as a dry run:

```bash
kubera rotate aws-access-key
```

Rotate it, and save the new credential to a new `0600` file:

```bash
kubera rotate aws-access-key --execute -o new-aws-key.json
```

The same for a single-part secret, read from an environment variable:

```bash
kubera rotate gitlab-pat --secret-env LEAKED_TOKEN --execute -o new-gitlab-token.json
```

Rotate it and put the new token straight into a GitHub Actions secret (and Vault), without printing it:

```bash
kubera rotate gitlab-pat --secret-env LEAKED_TOKEN --execute --store github:acme/payments:GITLAB_TOKEN --store-token-env GH_ADMIN_TOKEN --store 'vault:secret/ci/gitlab#token'
```

Confirm the old credential is dead (exit code `2` = invalid):

```bash
kubera verify aws-access-key
```

## Triage: false positives, accepted risks and baselines

In the TUI: <kbd>x</kbd> false positive, <kbd>m</kbd> accepted risk, <kbd>u</kbd> undo. On the command line:

Record everything found today, so only new findings are reported from now on:

```bash
kubera scan git . --update-baseline
```

Record only the findings whose platform says they are invalid:

```bash
kubera scan git . --verify --results invalid --update-baseline
```

Share the decisions with your team and CI:

```bash
git add .kubera-baseline.json && git commit -m "kubera: record triage decisions"
```

Report everything again, ignoring the baseline:

```bash
kubera scan git . --no-baseline
```

To silence one line in the code, add a `kubera:ignore` comment to it. See [Baselines and triage](triage.md) and [Configuration](configuration.md).

## Follow up: issues and history cleanup

Save the findings first (redacted):

```bash
kubera scan git . --verify -f json > findings.json
```

Plan one GitHub issue per live secret, in a private repository (dry run):

```bash
kubera remediate --findings findings.json --issues github:acme/security --token-env GH_TOKEN
```

Open them, mentioning the author of each leaking commit:

```bash
kubera remediate --findings findings.json --issues github:acme/security --token-env GH_TOKEN --mention-committer --execute
```

Prepare a history rewrite of the leaked values (writes a `git filter-repo` file and prints the commands, changes nothing):

```bash
kubera purge --findings findings.json --repo .
```

## Reports

A self-contained HTML report:

```bash
kubera scan git . --verify -f html > kubera-report.html
```

JSON, one array of redacted findings:

```bash
kubera scan git . --verify -f json > findings.json
```

SARIF for GitHub code scanning:

```bash
kubera scan git . -f sarif > kubera.sarif
```

## Track findings over time: the dashboard

Record a scan in the local findings database (redacted, mode `0600`):

```bash
kubera scan git . --verify --db
```

Open the dashboard on `http://127.0.0.1:8484/`:

```bash
kubera serve
```

Open live findings, as JSON, from the API:

```bash
curl -s 'http://127.0.0.1:8484/api/findings?state=open&status=live'
```

## Prevent new leaks: pre-commit, CI and alerts

Install the pre-commit hook in this repository:

```bash
kubera hook install
```

Fail a CI job when secrets are found (exit code `183`):

```bash
kubera scan git . --fail
```

In CI, scan only the commits added since the last passing run:

```bash
kubera scan git . --state .kubera-state.json --fail
```

The GitHub Action, as a workflow step:

```yaml
- uses: dmdhrumilmistry/kubera@v0.2.0
```

Any other CI, with the container image:

```bash
docker run --rm -v "$PWD:/scan" ghcr.io/dmdhrumilmistry/kubera scan git /scan --fail
```

Post live findings to Slack (the webhook URL is in `SLACK_WEBHOOK`):

```bash
kubera scan git . --verify --notify-env SLACK_WEBHOOK
```

## Templates and detectors

List every detector and what it supports:

```bash
kubera templates list
```

Start a new detector:

```bash
kubera templates new acme-key > templates.d/acme.yaml
```

Validate templates and run their samples:

```bash
kubera templates validate templates.d/
```

Scan with your own templates as well as the builtin ones:

```bash
kubera -t templates.d scan fs .
```

## Keep kubera up to date

Check for a newer release, then install it (SHA-256 verified, atomic; see [Updating](installation.md#updating)):

```bash
kubera update --check
kubera update
```

In scripts, skip the prompt:

```bash
kubera update --yes
```
