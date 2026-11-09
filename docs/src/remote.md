# Remote repositories

`kubera scan git` accepts a local path or any of these remote forms:

| Form | Example | Transport |
|---|---|---|
| HTTPS URL | `https://github.com/org/repo.git` | HTTPS |
| SSH URL | `ssh://git@gitlab.com:2222/group/repo.git` | SSH |
| scp-like | `git@github.com:org/repo.git` | SSH |
| Shorthand | `github.com/org/repo` | HTTPS |
| Other | `git://host/repo.git`, `file:///srv/git/repo.git` | git / local |

```bash
kubera scan git https://github.com/org/repo.git
kubera scan git git@github.com:org/repo.git --verify
kubera scan git github.com/org/repo -i          # browse results in the TUI
```

Remote repositories are cloned **bare** (no checkout) into a temporary directory that is deleted afterwards. Every branch and tag is scanned unless you narrow it:

| Flag | Effect on the clone |
|---|---|
| `--branch <name>` | Clones only that branch (`--single-branch`) |
| `--max-depth <n>` | Shallow clone of the last `n` commits |
| `--since-commit <rev>` | Scans only commits after `<rev>` |

An existing local path always wins over the shorthand form, so `kubera scan git src/app` never goes to the network.

## Private repositories

### HTTPS with a token

```bash
export GH_TOKEN=...            # a token that can read the repository
kubera scan git https://github.com/org/private.git --token-env GH_TOKEN
```

The token is **never** placed on git's command line, where process listings and shell history would show it. Kubera passes it to git as an `Authorization` header through `GIT_CONFIG_*` environment variables. The header is scoped to the repository's origin (`https://github.com`), so it cannot follow a redirect to another host. It is only ever sent over HTTPS: plain `http://` remotes are refused.

The username sent with the token defaults to `x-access-token`, which works for GitHub. Use `--token-user` where the host needs something else:

| Host | Token | `--token-user` |
|---|---|---|
| GitHub | PAT or app token | default |
| GitLab | PAT / project / group token | default works (any username) |
| Bitbucket Cloud | Repository/workspace access token | `x-token-auth` |
| Bitbucket Cloud | App password | your username |

If you paste a URL with credentials in it (`https://user:token@host/...`), Kubera strips them from the URL before git sees it and sends them the same safe way. Error messages only ever show the clean URL.

### SSH

SSH remotes use your normal SSH setup: keys, `ssh-agent`, `~/.ssh/config`. When stdin is not a terminal (CI, cron), Kubera runs ssh with `BatchMode=yes`, so a missing key or unknown host key fails immediately instead of hanging on a prompt. Set `GIT_SSH_COMMAND` yourself to override this.

## Links to the exact line

When the repository lives on **GitHub, GitLab or Bitbucket**, each finding gets a `link` to the line at the commit where the secret was added:

```text
╭─ CRITICAL  AWS Access Key ─────────────────────────── VERIFIED (live)
│ deploy/terraform.tfvars:12
│ https://github.com/acme/payments.git
│ 9f3c1e7a2b4d Dana Developer <dana@acme.example> 2026-10-14T09:12:44Z
│ ↗ https://github.com/acme/payments/blob/9f3c1e7…/deploy/terraform.tfvars#L12
```

Local repositories get links too when their `origin` remote points at one of these hosts. JSON and SARIF output include `repository` and `link` fields.

## Safety

Scanning a repository you don't control is safe:

- External diff drivers, textconv filters, hooks and fsmonitor are disabled, since a repository can configure each of them to run commands.
- Revisions and URLs are passed after `--end-of-options` / `--`, and URLs starting with `-` are rejected.
- Git never prompts for credentials (`GIT_TERMINAL_PROMPT=0`).
