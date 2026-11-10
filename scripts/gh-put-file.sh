#!/bin/sh
# Create or update one file in a GitHub repository through the REST contents
# API (no clone, no credentials on disk). Used by the release workflow to
# publish the Homebrew formula and the Scoop manifest.
#
#   GH_TOKEN=... scripts/gh-put-file.sh OWNER/REPO PATH LOCAL_FILE MESSAGE [BRANCH]
#
# Does nothing when the file already has exactly this content.
set -eu

[ "$#" -ge 4 ] || { echo "usage: $0 OWNER/REPO PATH LOCAL_FILE MESSAGE [BRANCH]" >&2; exit 2; }
repo=$1 path=$2 file=$3 message=$4 branch=${5:-}
[ -f "$file" ] || { echo "gh-put-file: no such file: $file" >&2; exit 1; }

query=""
[ -n "$branch" ] && query="?ref=$branch"

err=$(mktemp)
trap 'rm -f "$err"' EXIT
if sha=$(gh api "repos/$repo/contents/$path$query" --jq .sha 2>"$err"); then
    :
elif grep -q 'HTTP 404' "$err"; then
    sha=""
else
    cat "$err" >&2
    exit 1
fi

# The contents API reports the git blob id, so compare without downloading.
if [ -n "$sha" ] && [ "$sha" = "$(git hash-object "$file")" ]; then
    echo "$repo/$path is already up to date"
    exit 0
fi

set -- -X PUT "repos/$repo/contents/$path" \
    -f message="$message" \
    -f content="$(base64 < "$file" | tr -d '\n')"
[ -n "$sha" ] && set -- "$@" -f sha="$sha"
[ -n "$branch" ] && set -- "$@" -f branch="$branch"
gh api "$@" --jq '.commit.html_url'
