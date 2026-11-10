# Releasing

A release publishes, from one workflow run (`.github/workflows/release.yml`):

- prebuilt binaries for Linux (static musl, x86_64 and aarch64), macOS
  (x86_64 and Apple silicon), Windows and Android/Termux, attached to a
  GitHub release with SHA-256 checksums (used by `install.sh`);
- the `kubera-cli` crate on crates.io (repository secret
  `CARGO_REGISTRY_TOKEN`);
- the container image `ghcr.io/<owner>/kubera:<version>`, `:<major>.<minor>`
  and `:latest` (linux/amd64, linux/arm64);
- signatures and provenance (see "Signing" below);
- package manager manifests (Homebrew formula, Scoop manifest, winget
  manifests, AUR `PKGBUILD` and `.SRCINFO`), rendered from
  `packaging/templates/` with the checksums of the published archives,
  attached to the release as `kubera-packaging-vX.Y.Z.tar.gz` and uploaded
  as a workflow artifact, then pushed to each package repository whose
  secret is configured (see below).

## Steps

1. Bump `version` in `Cargo.toml` (and `Cargo.lock` with `cargo build`),
   merge to `main`, and wait for CI to pass.
2. Release, either way:
   - **Manual run:** Actions -> Release -> Run workflow, branch `main`,
     check **publish** (optionally type the version as a cross-check). The
     run builds everything first; the release step then creates the tag
     `vX.Y.Z` on the commit that was built.
   - **Tag push:**
     ```bash
     git tag -a vX.Y.Z -m "kubera vX.Y.Z" origin/main && git push origin vX.Y.Z
     ```
3. The image `ghcr.io/dmdhrumilmistry/kubera` is public, so `docker pull`
   needs no login. A fork publishes a private package on its first release:
   make it public under the repository's Packages settings.

If a release stops part way (for example the crates.io upload fails after the
GitHub release was created), fix the cause, then run the workflow on `main`
with **publish** and **complete** checked: it keeps the existing tag and
GitHub release, publishes the crate from the tagged source if crates.io does
not have that version yet, and pushes the image again.

A manual run without **publish** only builds (useful to test the pipeline).
The workflow refuses to publish from any branch but `main`, when the version
input does not match `Cargo.toml`, or when the tag already exists (unless
**complete** is checked).

## Signing

Nothing to set up: the workflow signs with GitHub's OIDC token
(`id-token: write`), so no signing key or secret exists.

- `publish` generates a CycloneDX SBOM of the released source
  (`kubera-vX.Y.Z.cdx.json`, via `cargo-cyclonedx`), then downloads every
  archive back from the release, checks it against its `.sha256`, and signs
  it with `cosign sign-blob --bundle` (keyless). The bundles are uploaded as
  `<asset>.sigstore.json`. It then creates GitHub build provenance
  attestations for the archives and the SBOM (`actions/attest-build-provenance`)
  and an SBOM attestation for the archives (`actions/attest-sbom`).
- `image` builds with BuildKit SBOM and provenance, signs the pushed digest
  with `cosign sign`, and pushes a GitHub provenance attestation to GHCR.
- `packages` signs and attests `kubera-packaging-vX.Y.Z.tar.gz` the same way.

In **complete** mode existing assets are never re-signed or replaced: an
asset gets a signature bundle only if the release has none for it, and a
provenance attestation only if this run built those exact bytes and the
digest has none yet. Running **complete** on a release from before signing
existed (v0.2.0) therefore adds signature bundles and the SBOM, but no
provenance for the archives an earlier run built. The image is pushed again
in complete mode, and that new digest is signed.

Check a release after publishing (see the installation docs for the full
commands):

```bash
gh release download vX.Y.Z --repo dmdhrumilmistry/kubera --pattern 'kubera-x86_64-unknown-linux-musl.tar.gz*'
gh attestation verify kubera-x86_64-unknown-linux-musl.tar.gz --repo dmdhrumilmistry/kubera
cosign verify-blob kubera-x86_64-unknown-linux-musl.tar.gz \
  --bundle kubera-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/dmdhrumilmistry/kubera/\.github/workflows/release\.yml@refs/(heads/main|tags/v[0-9.]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Package managers

The `packages` job runs after the GitHub release exists. It downloads the
published archives, checks them against their `.sha256` files, and renders
the manifests with `scripts/render-packages.py`, so a manifest always
matches what users download, including after a **complete** run. Each
publishing step below is skipped with a notice when its secret is missing,
so a release never fails for lack of one. Re-running is safe: nothing is
pushed when the content is unchanged.

To refresh the copies committed under `packaging/` after a release:

```bash
gh release download vX.Y.Z --repo dmdhrumilmistry/kubera --pattern '*.sha256' --dir /tmp/sums
python3 -I scripts/render-packages.py --version X.Y.Z --assets /tmp/sums --out packaging
```

One-time setup, per package manager (repository secrets live under
Settings -> Secrets and variables -> Actions):

| Channel | Create once | Secret |
|---|---|---|
| Homebrew | A public repository `<owner>/homebrew-tap` (any content; the job writes `Formula/kubera.rb`). Users run `brew install <owner>/tap/kubera`. | `HOMEBREW_TAP_TOKEN`: a fine-grained token limited to that repository with **Contents: read and write**. |
| Scoop | A public repository `<owner>/scoop-bucket` (the job writes `bucket/kubera.json`). Users run `scoop bucket add kubera https://github.com/<owner>/scoop-bucket`. | `SCOOP_BUCKET_TOKEN`: a fine-grained token limited to that repository with **Contents: read and write**. |
| AUR | An account on [aur.archlinux.org](https://aur.archlinux.org) with an SSH public key added under My Account. The first push creates the `kubera-bin` package. | `AUR_SSH_PRIVATE_KEY`: the matching private key (a dedicated Ed25519 key without a passphrase). The job only connects to `aur.archlinux.org` when its host key matches the fingerprint published by the AUR. |
| winget | A fork of [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) at `<owner>/winget-pkgs`. | `WINGET_TOKEN`: a classic token with `public_repo` scope (it must open a pull request on `microsoft/winget-pkgs`). Each release then opens a PR `New version: dmdhrumilmistry.kubera version X.Y.Z` (or `New package` the first time); a winget moderator merges it. |

Without `WINGET_TOKEN`, submit by hand: download the `packaging-vX.Y.Z`
artifact (or extract `kubera-packaging-vX.Y.Z.tar.gz`), copy `winget/*.yaml`
to `manifests/d/dmdhrumilmistry/kubera/X.Y.Z/` in your fork, check them
with `winget validate --manifest <dir>` and `winget install --manifest <dir>`
on Windows, and open a pull request. Without `AUR_SSH_PRIVATE_KEY`, copy
`aur/PKGBUILD` and `aur/.SRCINFO` into a clone of
`ssh://aur@aur.archlinux.org/kubera-bin.git`, commit and push.
