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
cargo build --release
./target/release/kubera --help
```

The builtin templates are embedded in the binary, so you can copy `kubera` anywhere on its own.

## Runtime requirements

- `git` on `PATH` for `kubera scan git`.
- Outbound HTTPS to vendor APIs, only when you use `--verify`, `verify`, `analyze` or `rotate`.

## Checking the install

```bash
kubera --version
kubera templates list
kubera templates test      # runs every template's built-in samples
```
