# Container images

Images ship whatever went into their layers, including files a later layer deleted. `kubera scan image` reads every layer and the image config, straight from the registry.

```bash
kubera scan image alpine:3.20                          # Docker Hub
kubera scan image ghcr.io/acme/api:1.4.2 --verify      # any OCI registry
kubera scan image acme/app@sha256:9f3c...              # by digest
kubera scan image app.tar                              # docker save / OCI layout tarball
kubera scan image my-app:dev --docker                  # local Docker daemon
kubera scan image ghcr.io/acme/app:1 --platform linux/arm64
```

**No Docker needed.** Kubera talks to registries directly through the OCI distribution API, so it also runs in CI containers, on build servers and in Termux.

## What gets scanned

- **Every layer.** A secret copied in one layer and deleted in a later one (`RUN rm creds.env`) still ships inside the image, and Kubera finds it. Each finding names the layer digest.
- **The image config**: `ENV` values, labels and the build history (`created_by`), where `--build-arg` secrets often end up.
- Text files up to `--max-file-size`. Binaries and whiteout markers are skipped.
- **Archives inside layers** up to 64 MiB: jar, war, whl, zip, tar.gz and the rest of the [supported formats](scanning.md#archives), nested, read in memory. A finding names the entry, e.g. `/app/lib/app.jar!/application.yml`.
- Base64 and other [encoded](scanning.md#decoders) values, for example a Docker `config.json` with `auths`.

```text
╭─ CRITICAL  GitHub Token ─────────────────────────────────────
│ /app/creds.env:1
│ ghcr.io/acme/api:1.4.2
│ layer sha256:b796daa5af51
│
│ token        ghp_********Uo
╰─ github-token · bc0458ecc5e4611e9dde21f8
```

## Registries and auth

| Registry | Notes |
|---|---|
| Docker Hub | `alpine`, `user/app`, `docker.io/...`; anonymous pulls use Docker Hub's token service |
| GHCR, GCR/Artifact Registry, Quay, ECR, Harbor, ... | full reference, e.g. `ghcr.io/org/app:tag` |
| Private registries | `--registry-user USER --registry-token-env VAR` (password or token from an environment variable) |
| Plain-HTTP local registries | `--plain-http` (explicit opt-in) |

Multi-architecture images are resolved to `--platform` (default `linux/amd64`).

## Docker Hub organizations

`kubera scan dockerhub` lists the repositories of a Docker Hub organization (or user) and their most recently pushed tags through the Hub API, then pulls and scans each image exactly like `scan image`.

```bash
kubera scan dockerhub acme                          # the latest-pushed tag of up to 100 repositories
kubera scan dockerhub acme --tags 5 --limit 20      # five newest tags of 20 repositories
kubera scan dockerhub acme --registry-user ci --registry-token-env HUB_PAT   # private repositories too
```

| Flag | Meaning |
|---|---|
| `ORG ...` | Organizations or users (repeatable). |
| `--limit N` | Repositories scanned per organization (default 100). |
| `--tags N` | Most recently pushed tags scanned per repository (default 1). |
| `--registry-user USER`, `--registry-token-env VAR` | A Docker Hub user and personal access token: used to log in to the Hub API (private repositories are listed) and for the pulls. |
| `--max-image-size BYTES` | Skip tags whose compressed size, as the Hub reports it, is larger (default 4 GiB). Checked before anything is pulled. |
| `--platform`, `--max-layer-size` | As for `scan image`. |

Images are pulled one at a time and deleted after their scan. Docker Hub limits anonymous pulls (100 per 6 hours per IP address at the time of writing); pass a token to get your account's limit. A tag that cannot be pulled is reported as a warning and the scan goes on.

## Safety

- Every blob is **sha256-verified before it is parsed**. A registry or proxy that tampers with a layer is refused, not scanned.
- Layers larger than `--max-layer-size` (default 4 GiB) are refused.
- Archives are **streamed, never unpacked to disk**, so path-traversal or symlink tricks inside a hostile image cannot write anywhere.
- Registry and token-service URLs must be HTTPS (unless `--plain-http`). Credentials go only to the registry's own token service.
- `scan dockerhub` sends the Hub token only to `hub.docker.com` and follows the Hub's pagination only on that host.

## Running Kubera from a container

Kubera has its own image, `ghcr.io/dmdhrumilmistry/kubera`, which can scan images too:

```bash
docker run --rm ghcr.io/dmdhrumilmistry/kubera scan image alpine:3.20
```

See [Installation](installation.md#container-image) for tags and mounting a repository.
