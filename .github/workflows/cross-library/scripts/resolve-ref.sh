#!/usr/bin/env bash
# Echo the git ref a product should be built at:
#   mode=latest -> the highest version tag (polled)
#   mode=head   -> the default branch (master/main, auto-detected)
# Usage: resolve-ref.sh <repo> <mode>
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$DIR/common.sh"

repo="$1"; mode="$2"
url="$(resolve_repo_url "$repo")"

case "$mode" in
    latest)
        t="$(latest_tag "$url")"
        [ -n "$t" ] || { echo "no tags found for $repo" >&2; exit 1; }
        printf '%s\n' "$t" ;;
    head)
        default_branch "$url" ;;
    *)
        echo "resolve-ref: unknown mode '$mode' (expected 'head' or 'latest')" >&2
        exit 2 ;;
esac
