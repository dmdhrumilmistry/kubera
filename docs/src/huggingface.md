# Hugging Face Hub

Models, datasets and Spaces on the Hugging Face Hub are git repositories, and they leak like any other: an `.env` committed with a Space, a training script with an API key, a notebook with a token in its output. `kubera scan huggingface` clones each repository and scans its full history, the same way [`scan git`](scanning.md#git-history) does.

```bash
kubera scan huggingface openai-community/gpt2                   # one model
kubera scan huggingface acme/support-tickets --type dataset     # one dataset
kubera scan huggingface acme/demo --type space                  # one Space
kubera scan huggingface acme                                    # every model, dataset and Space of acme
kubera scan huggingface acme --type space --token-env HF_TOKEN  # private Spaces too
kubera scan hf acme/demo --type space --include-lfs             # also files stored in Git LFS
```

## What gets scanned

| Target | Repositories |
|---|---|
| `owner/name` | That repository; `--type` picks model (default), dataset or space. |
| `owner` | Every repository of the user or organization, up to `--limit` per type; all three types unless `--type` narrows it. |

Every commit of every repository is scanned, so files deleted later are found too. Findings are `git` findings with the commit, author and a link to the line on the Hub (`https://huggingface.co/<prefix><owner>/<name>/blob/<commit>/<path>#L<line>`).

### Git LFS files

Large files live in Git LFS. The clone only holds their small pointer files, so model weights and dataset shards are never downloaded by default. With `--include-lfs`, LFS files of the `main` branch up to `--max-lfs-size` (default 64 MiB) are downloaded as well:

- sizes and path excludes are checked from the file list **before** downloading, so a 10 GB `model.safetensors` costs nothing;
- each file is checked against its LFS sha256 before it is opened (a mismatch stops the scan);
- text files and archives (zip, tar.gz, ...) are scanned; binary files are skipped.

These findings have the source `huggingface`, the file path, and a link to the file on the Hub. Only the latest version of LFS files is read, not their history.

## Options

| Flag | Meaning |
|---|---|
| `OWNER[/REPO] ...` | Users, organizations or single repositories. |
| `--type <types>` | `model`, `dataset`, `space` (comma separated). |
| `--token-env VAR` | Environment variable with a Hugging Face token (private and gated repositories, higher rate limits). |
| `--include-lfs` | Also scan Git LFS files of the main branch. |
| `--max-lfs-size BYTES` | Largest LFS file downloaded (default 64 MiB). |
| `--limit N` | Repositories listed per owner and type (default 100). |

`hf` is a short alias for `huggingface`. All [common scan options](scanning.md#common-options) work too.

## Tokens

- The token is optional, read from an environment variable, and only sent to `huggingface.co`: as a bearer header to the API, and as an origin-scoped header to git (never on a command line).
- API listings follow `Link` pagination only on the same host.
- LFS downloads redirect to pre-signed storage; that request is sent **without** the token.
- Repository names returned by the API are checked (owner must match, safe characters only) before anything is cloned.
