# MCP server

`kubera mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server on stdio, so AI assistants such as Claude Code, Claude Desktop and Cursor can scan code, repositories and images for leaked secrets.

```bash
claude mcp add kubera -- kubera mcp                      # Claude Code
claude mcp add kubera -- kubera mcp --allow-verify       # + live verification
```

Other clients (`claude_desktop_config.json`, `.cursor/mcp.json`, ...):

```json
{
  "mcpServers": {
    "kubera": { "command": "kubera", "args": ["mcp", "--root", "/path/to/projects"] }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `scan_path` | Scan a file or directory |
| `scan_git` | Scan a repository's full history (path, URL or `github.com/org/repo`), with optional `branch`, `since_commit`, `max_depth` |
| `scan_image` | Scan a container image or image tarball |
| `scan_text` | Scan a pasted snippet (config, log, diff) |
| `list_detectors` | Detectors and their verify / analyze / rotate support |
| `verify_finding` | *(with `--allow-verify`)* Is a found secret live? With a verification cache, a recent result comes back with `cached: true`; `fresh: true` asks again |
| `analyze_finding` | *(with `--allow-verify`)* Owner, scopes, reachable resources |
| `rotation_plan` | *(with `--allow-verify`)* Dry-run rotation plan and runbook |

## Security model

- **Secrets never reach the model.** Scan tools return redacted findings with fingerprints; the raw values stay inside the server process. The follow-up tools take a **fingerprint**, so the model can verify or analyze a leak without ever seeing it.
- **Contacting vendors is opt-in.** Without `--allow-verify`, the verification tools are not even listed and `verify: true` is refused.
- **The model can't supply credentials.** No tool accepts tokens or environment-variable names; otherwise a prompt-injected document could ask the server to send a credential to a host of its choosing. To scan private repositories, start the server with `--git-token-env VAR`.
- **Rotation is plan-only.** Executing a rotation stays an explicit human step (`kubera rotate --execute`).
- **`--root DIR`** confines file and local-repository scans to one directory tree.

`kubera mcp --allow-verify --verify-cache` (or `verify_cache:` in `.kubera.yaml`) reuses recent [verification results](scanning.md#verification-cache) across sessions, so an assistant re-checking the same findings does not send them to vendors again.

The server applies `.kubera.yaml` and the [baseline](triage.md) (`.kubera-baseline.json`) from its working directory, so findings you triaged are not shown to the assistant either.
