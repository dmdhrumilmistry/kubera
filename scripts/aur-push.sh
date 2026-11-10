#!/bin/sh
# Push a rendered PKGBUILD and .SRCINFO to the AUR package kubera-bin.
#
#   AUR_SSH_PRIVATE_KEY=... scripts/aur-push.sh VERSION DIR
#
# The private key stays in a 0600 file in a temporary directory that is
# removed on exit. aur.archlinux.org is accepted only with the Ed25519 host
# key fingerprint published on https://aur.archlinux.org (no trust on first
# use). Commit author: AUR_GIT_NAME / AUR_GIT_EMAIL.
set -eu

# https://aur.archlinux.org: "The following SSH fingerprints are used for the AUR".
AUR_ED25519="SHA256:RFzBCUItH9LZS0cKB5UE6ceAYhBD5C8GeOBip8Z11+4"
pkg=kubera-bin

die() { echo "aur-push: error: $*" >&2; exit 1; }

[ "$#" -eq 2 ] || { echo "usage: $0 VERSION DIR" >&2; exit 2; }
version=$1 dir=$2
[ -n "${AUR_SSH_PRIVATE_KEY:-}" ] || die "AUR_SSH_PRIVATE_KEY is not set"
[ -f "$dir/PKGBUILD" ] && [ -f "$dir/.SRCINFO" ] || die "$dir needs PKGBUILD and .SRCINFO"
grep -qx "pkgver=$version" "$dir/PKGBUILD" || die "$dir/PKGBUILD is not version $version"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
(umask 077 && printf '%s\n' "$AUR_SSH_PRIVATE_KEY" > "$work/key")

ssh-keyscan -t ed25519 aur.archlinux.org > "$work/known_hosts" 2>/dev/null \
    || die "ssh-keyscan aur.archlinux.org failed"
fingerprint=$(ssh-keygen -l -E sha256 -f "$work/known_hosts" | awk '{print $2}')
[ "$fingerprint" = "$AUR_ED25519" ] \
    || die "aur.archlinux.org host key is $fingerprint, expected $AUR_ED25519"

GIT_SSH_COMMAND="ssh -i $work/key -o IdentitiesOnly=yes -o UserKnownHostsFile=$work/known_hosts -o StrictHostKeyChecking=yes"
export GIT_SSH_COMMAND

# Cloning a package that does not exist yet gives an empty repository;
# the first push creates it.
git clone -q "ssh://aur@aur.archlinux.org/$pkg.git" "$work/repo"
cp "$dir/PKGBUILD" "$dir/.SRCINFO" "$work/repo/"
cd "$work/repo"
git add PKGBUILD .SRCINFO
if git diff --cached --quiet 2>/dev/null; then
    echo "AUR $pkg is already at $version"
    exit 0
fi
git -c user.name="${AUR_GIT_NAME:-kubera release}" \
    -c user.email="${AUR_GIT_EMAIL:-kubera-release@users.noreply.github.com}" \
    commit -q -m "Update to $version"
git push -q origin HEAD:master
echo "pushed $pkg $version to the AUR"
