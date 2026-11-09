# Installation

## From source

Building requires Rust **1.88** or newer ([rustup](https://rustup.rs)).

```bash
cargo install --git https://github.com/dmdhrumilmistry/kubera --locked
```

Or from a clone:

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
| `make test-termux` | Build and test inside a Termux container (needs Docker) |
| `make audit` | `cargo audit` (needs `cargo-audit`) |

Examples:

```bash
make install PREFIX=$HOME/.local        # no sudo
sudo make install                       # /usr/local/bin
make install DESTDIR=/tmp/pkg PREFIX=/usr   # staged install for packaging
```

## Runtime requirements

- `git` on `PATH` for `kubera scan git`.
- Outbound HTTPS to vendor APIs, only when you use `--verify`, `verify`, `analyze` or `rotate`.

## Checking the install

```bash
kubera --version
kubera templates list
kubera templates test      # runs every template's built-in samples
```
