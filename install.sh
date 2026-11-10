#!/bin/sh
# Kubera installer:
#   curl -fsSL https://raw.githubusercontent.com/dmdhrumilmistry/kubera/main/install.sh | sh
#
# Downloads the prebuilt binary for this OS/architecture from the latest
# GitHub release, verifies its SHA-256 checksum and installs it.
#
# Environment:
#   KUBERA_VERSION      release tag to install (default: latest), e.g. v0.2.0
#   KUBERA_INSTALL_DIR  install directory (default: $PREFIX/bin on Termux,
#                       otherwise ~/.local/bin)
#   KUBERA_DOWNLOAD_BASE  override the release download URL (mirrors, tests)
#   KUBERA_VERIFY_ATTESTATION  set to 1 to also verify the archive's GitHub
#                       build provenance with `gh attestation verify` (needs
#                       the GitHub CLI, logged in); on top of the checksum
set -eu

REPO="dmdhrumilmistry/kubera"

say() { printf '%s\n' "kubera-install: $*" >&2; }
die() { say "error: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1; }

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        i386 | i486 | i586 | i686) arch=i686 ;;
        armv7l | armv8l) arch=armv7 ;;
        armv6l) arch=armv6 ;;
        riscv64) arch=riscv64 ;;
        *) arch=unsupported ;;
    esac
    if [ "$os" = "Linux" ] && { [ "$(uname -o 2>/dev/null)" = "Android" ] || [ -n "${TERMUX_VERSION:-}" ]; }; then
        os=Android
    fi
    case "$os/$arch" in
        Linux/x86_64) echo x86_64-unknown-linux-musl ;;
        Linux/aarch64) echo aarch64-unknown-linux-musl ;;
        Linux/i686) echo i686-unknown-linux-musl ;;
        Linux/armv7) echo armv7-unknown-linux-musleabihf ;;
        Linux/armv6) echo arm-unknown-linux-musleabihf ;;
        Linux/riscv64) echo riscv64gc-unknown-linux-gnu ;;
        Android/aarch64) echo aarch64-linux-android ;;
        Android/armv7) echo armv7-linux-androideabi ;;
        Android/x86_64) echo x86_64-linux-android ;;
        Darwin/x86_64) echo x86_64-apple-darwin ;;
        Darwin/aarch64) echo aarch64-apple-darwin ;;
        FreeBSD/x86_64) echo x86_64-unknown-freebsd ;;
        *) echo "" ;;
    esac
}

sha256() {
    if need sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif need shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die "need sha256sum or shasum to verify the download"
    fi
}

fetch() {
    if need curl; then
        curl -fsSL --proto '=https,file' --retry 3 -o "$2" "$1"
    elif need wget; then
        wget -q -O "$2" "$1"
    else
        die "need curl or wget"
    fi
}

main() {
    target=$(detect_target)
    if [ -z "$target" ]; then
        say "no prebuilt binary for $(uname -s)/$(uname -m)."
        say "install from source instead:  cargo install kubera-cli --locked"
        exit 1
    fi

    version="${KUBERA_VERSION:-latest}"
    if [ -n "${KUBERA_DOWNLOAD_BASE:-}" ]; then
        base="$KUBERA_DOWNLOAD_BASE"
    elif [ "$version" = "latest" ]; then
        base="https://github.com/$REPO/releases/latest/download"
    else
        base="https://github.com/$REPO/releases/download/$version"
    fi

    if [ -n "${KUBERA_INSTALL_DIR:-}" ]; then
        dir="$KUBERA_INSTALL_DIR"
    elif [ "${target%-linux-android*}" != "$target" ] && [ -n "${PREFIX:-}" ]; then
        dir="$PREFIX/bin"
    else
        dir="$HOME/.local/bin"
    fi

    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t kubera)
    trap 'rm -rf "$tmp"' EXIT INT TERM

    asset="kubera-$target.tar.gz"
    say "downloading $asset ($version)"
    fetch "$base/$asset" "$tmp/$asset" || {
        say "download failed. If no release exists yet, install from source:"
        say "  cargo install kubera-cli --locked"
        exit 1
    }
    fetch "$base/$asset.sha256" "$tmp/$asset.sha256" || die "checksum download failed"

    expected=$(cut -d' ' -f1 < "$tmp/$asset.sha256")
    actual=$(sha256 "$tmp/$asset")
    [ -n "$expected" ] && [ "$expected" = "$actual" ] \
        || die "checksum mismatch for $asset (expected $expected, got $actual)"

    if [ "${KUBERA_VERIFY_ATTESTATION:-0}" = "1" ]; then
        need gh || die "KUBERA_VERIFY_ATTESTATION=1 needs the GitHub CLI (gh)"
        say "verifying build provenance attestation"
        gh attestation verify "$tmp/$asset" --repo "$REPO" \
            --signer-workflow "$REPO/.github/workflows/release.yml" >/dev/null \
            || die "attestation verification failed for $asset"
    fi

    tar -xzf "$tmp/$asset" -C "$tmp"
    mkdir -p "$dir"
    install -m 0755 "$tmp/kubera-$target/kubera" "$dir/kubera" 2>/dev/null \
        || { cp "$tmp/kubera-$target/kubera" "$dir/kubera" && chmod 0755 "$dir/kubera"; }

    say "installed $("$dir/kubera" --version 2>/dev/null || echo kubera) to $dir/kubera"
    case ":$PATH:" in
        *":$dir:"*) ;;
        *) say "note: $dir is not on your PATH; add:  export PATH=\"$dir:\$PATH\"" ;;
    esac
}

main "$@"
