# Releasing

A release publishes, from one workflow run (`.github/workflows/release.yml`):

- prebuilt binaries for Linux (static musl, x86_64 and aarch64), macOS
  (x86_64 and Apple silicon), Windows and Android/Termux, attached to a
  GitHub release with SHA-256 checksums (used by `install.sh`);
- the `kubera-cli` crate on crates.io (repository secret
  `CARGO_REGISTRY_TOKEN`);
- the container image `ghcr.io/<owner>/kubera:<version>`, `:<major>.<minor>`
  and `:latest` (linux/amd64, linux/arm64).

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
3. First release only: make the `kubera` package public under the
   repository's Packages settings, or `docker pull` needs a login.

A manual run without **publish** only builds (useful to test the pipeline).
The workflow refuses to publish from any branch but `main`, when the version
input does not match `Cargo.toml`, or when the tag already exists.
