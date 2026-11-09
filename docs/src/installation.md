# Installation

## One-line install (Linux, macOS, Termux)

```bash
curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/kubera/main/install.sh | sh
```

The script picks the prebuilt binary for your OS and CPU (static Linux musl, macOS Intel/Apple Silicon, Android/Termux aarch64), **verifies its SHA-256 checksum** and installs it to `~/.local/bin` (or `$PREFIX/bin` on Termux). Set `KUBERA_VERSION=v0.1.0` to pin a release or `KUBERA_INSTALL_DIR` to change the location. Read the script first if you prefer: it's short.

## Cargo

```bash
cargo install kubera-cli --locked
```

The crate is called `kubera-cli` (the `kubera` name on crates.io belongs to an unrelated project); the installed command is `kubera`. Requires Rust **1.88** or newer ([rustup](https://rustup.rs)).

## Prebuilt binaries

Every [GitHub release](https://github.com/dmdhrumilmistry/kubera/releases) has archives for Linux (x86_64/aarch64, static), macOS (x86_64/arm64), Windows (x86_64) and Android (aarch64), each with a `.sha256` file.

## Container image

Every release publishes a multi-architecture image (linux/amd64, linux/arm64) to GitHub Container Registry, built from the same static binaries as the release archives:

```bash
docker run --rm ghcr.io/dmdhrumilmistry/kubera --version
docker run --rm -v "$PWD:/scan" ghcr.io/dmdhrumilmistry/kubera scan git /scan
docker run --rm -v "$PWD:/scan" ghcr.io/dmdhrumilmistry/kubera scan fs /scan --fail
docker run --rm ghcr.io/dmdhrumilmistry/kubera scan image alpine:3.20
```

| Tag | Meaning |
|---|---|
| `0.2.0` | One release |
| `0.2` | Latest patch release of 0.2 |
| `latest` | Latest release |

- The entrypoint is `kubera`, and the working directory is `/scan`: mount what you want scanned there.
- The image runs as a **non-root** user (uid 10001) and includes `git` and CA certificates. Mounted repositories owned by another uid are accepted by git.
- Pass credentials as environment variables, for example `-e GH_TOKEN` with `--token-env GH_TOKEN`.

To build it yourself from a checkout:

```bash
docker build -t kubera .
docker run --rm -v "$PWD:/scan" kubera scan git /scan
```

## GitHub Action

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: dmdhrumilmistry/kubera@v0.2.0
```

The action installs a release binary and scans the repository, with SARIF upload to code scanning. See [CI integration](ci.md#github-action) for inputs and outputs.

## From source

```bash
git clone https://github.com/dmdhrumilmistry/kubera
cd kubera
make install            # or: cargo build --release
kubera --help
```

The builtin templates are embedded in the binary, so you can copy `kubera` anywhere on its own.

## Termux (Android)

Kubera builds and runs natively in [Termux](https://termux.dev):

```bash
pkg install rust git make clang
git clone https://github.com/dmdhrumilmistry/kubera
cd kubera
make install          # installs to $PREFIX/bin, already on your PATH
kubera templates test
```

Everything works, including `--verify`, `analyze` and `rotate`. Android's built-in certificate verifier can only be used from Java, so on Android Kubera verifies TLS against an explicit set of trusted roots, taken from the first of these that exists:

1. `SSL_CERT_FILE`, if set (a PEM bundle);
2. Termux's CA bundle, `$PREFIX/etc/tls/cert.pem` (from the `ca-certificates` package, installed by default);
3. Android's system store (`/apex/com.android.conscrypt/cacerts` on Android 14+, `/system/etc/security/cacerts` before that);
4. Mozilla's root list, compiled into the binary.

If you use a TLS-intercepting proxy (common on corporate networks), add its CA to Termux's bundle or point `SSL_CERT_FILE` at a bundle that contains it.

CI builds and tests every change inside a Termux container (`make test-termux`).

## Makefile

The repository ships a `Makefile` for common tasks. Run `make help` for the list:

| Target | What it does |
|---|---|
| `make build` / `make release` | Debug / optimised build |
| `make install` / `make uninstall` | Install to `$(PREFIX)/bin` (default `/usr/local`; Termux sets `PREFIX` for you). Supports `DESTDIR`. |
| `make test` | Unit and integration tests |
| `make lint` | `rustfmt` check and `clippy` with warnings as errors |
| `make templates-test` | Run every template's samples |
| `make scan` | Scan the repository's files and history with Kubera itself |
| `make check` | `lint` + `test` + `templates-test` + `scan` |
| `make docs` / `make docs-serve` | Build or live-serve this documentation (needs `mdbook`) |
| `make tui` | Build and launch the interactive TUI |
| `make screenshots` | Regenerate the documentation images from the real TUI/CLI code |
| `make test-termux` | Build and test inside a Termux container (needs Docker) |
| `make audit` | `cargo audit` (needs `cargo-audit`) |

Examples:

```bash
make install PREFIX=$HOME/.local        # no sudo
sudo make install                       # /usr/local/bin
make install DESTDIR=/tmp/pkg PREFIX=/usr   # staged install for packaging
```

## Runtime requirements

- `git` on `PATH` for `kubera scan git`, `scan repos`, `scan staged` and the pre-commit hook.
- Outbound HTTPS to vendor APIs, only when you use `--verify`, `verify`, `analyze` or `rotate`.

## Checking the install

```bash
kubera --version
kubera templates list
kubera templates test      # runs every template's built-in samples
```
