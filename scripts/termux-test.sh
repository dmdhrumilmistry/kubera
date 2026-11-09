#!/usr/bin/env bash
# Build and test kubera inside Termux (Android). Run from a writable
# checkout, either on a device or in the termux/termux-docker image
# (see `make test-termux`).
set -euo pipefail

if [ -z "${PREFIX:-}" ] || [ ! -d "${PREFIX}/etc" ]; then
    echo "error: this script must run inside Termux" >&2
    exit 1
fi

missing=()
for tool in cargo git make; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "== installing toolchain (rust git make clang)"
    # `pkg` picks a random community mirror on every run, and an overloaded
    # one (429, stale index) fails the whole job. Pin the official CDN and
    # call apt-get directly, retrying transient network errors.
    mirror="${KUBERA_TERMUX_MIRROR:-https://packages-cf.termux.dev/apt/termux-main}"
    echo "deb ${mirror}/ stable main" > "${PREFIX}/etc/apt/sources.list"
    ok=0
    for attempt in 1 2 3 4; do
        if apt-get update -y && \
            apt-get install -y -o Dpkg::Options::=--force-confnew rust git make clang; then
            ok=1
            break
        fi
        echo "== apt attempt ${attempt} failed, retrying" >&2
        sleep $((attempt * 15))
    done
    if [ "$ok" -ne 1 ]; then
        echo "error: could not install the toolchain from ${PREFIX}/etc/apt/sources.list" >&2
        exit 1
    fi
fi

echo "== toolchain"
rustc --version
cargo --version

echo "== cargo test"
cargo test --locked

echo "== release build + template samples"
cargo build --release --locked
./target/release/kubera templates test

# Exercises the full HTTPS path (TLS roots, proxy, request, matching).
# Android's OS certificate verifier needs a JVM, so a broken TLS setup
# shows up here as a panic (exit 101) or an `unknown` TLS error (exit 3).
# A random token must come back `invalid` (exit 2).
echo "== live TLS check"
# The prefix is split so this file never contains a token-shaped literal.
KUBERA_TERMUX_TOKEN="xox""b-1234567890-123456789012-$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
export KUBERA_TERMUX_TOKEN
set +e
./target/release/kubera verify slack-token --secret-env KUBERA_TERMUX_TOKEN
code=$?
set -e
if [ "$code" -ne 2 ]; then
    echo "error: expected exit code 2 (invalid), got $code" >&2
    exit 1
fi
echo "== termux: all checks passed"
