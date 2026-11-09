# Pre-commit hook

The cheapest leak to fix is the one that never gets committed. Kubera's pre-commit hook scans what a commit adds and blocks it when a secret is in there.

```bash
kubera hook install        # in the repository you want to protect
git commit -m "..."        # blocked if the staged changes add a secret
kubera hook uninstall      # remove it again
```

## What the hook runs

The hook runs `kubera scan staged --fail`. You can run the same scan by hand:

```bash
kubera scan staged            # the current repository
kubera scan staged ../other   # another repository
```

`scan staged` reads `git diff --cached`, so it scans **only the lines the next commit adds**. It is fast, and findings that already exist in the repository never block an unrelated commit. Staged findings have no commit, since the commit does not exist yet.

Everything else works as in other scans: decoders, `.kubera.yaml` allowlists, `kubera:ignore` comments and the [baseline](triage.md) are all honoured. When a commit is blocked, the hook says how to get past a false positive.

```text
╭─ CRITICAL  GitHub Token ────────────────────────────────────────────────────
│ deploy/secret.yaml:4
│ decoded from base64
│
│ token        ghp_********Uo
╰─ github-token · bc0458ecc5e4611e9dde21f8

◆ kubera 1 finding(s)  1 unverified
kubera: commit blocked - the staged changes add the secret(s) above.
```

## Installing

```bash
kubera hook install              # the current repository
kubera hook install ~/src/api    # another one
kubera hook install --force      # replace a pre-commit hook kubera did not write
```

- The hooks directory comes from git itself, so `core.hooksPath` and worktrees are honoured.
- An existing `pre-commit` hook that kubera did not write is **never overwritten** without `--force`. With `--force`, the old hook is kept as `pre-commit.bak`.
- Running `install` again updates kubera's own hook in place.
- The hook **fails closed**: if `kubera` is not on `PATH`, the commit is refused with a message, rather than silently let through.
- `kubera hook uninstall` removes only a hook kubera wrote, and leaves any other hook alone.

To commit anyway, for example a false positive you are about to allowlist:

```bash
git commit --no-verify
```

## The pre-commit framework

If you manage hooks with [pre-commit](https://pre-commit.com), use the hooks this repository publishes in `.pre-commit-hooks.yaml`:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dmdhrumilmistry/kubera
    rev: v0.2.0
    hooks:
      - id: kubera          # pre-commit builds kubera with cargo
      # - id: kubera-system # or use a kubera already on PATH
```

| Hook id | Runs | Needs |
|---|---|---|
| `kubera` | `kubera scan staged --fail` | Rust (pre-commit builds and caches the binary) |
| `kubera-system` | `kubera scan staged --fail` | `kubera` on `PATH` (install script, cargo, a package) |

Both scan the staged changes as a whole, not file by file (`pass_filenames: false`).

A hook only protects the machines it is installed on. Keep a scan in [CI](ci.md) as well.
