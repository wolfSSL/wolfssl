#!/usr/bin/env bash
# Poll a product repo for its highest version tag (version-sorted) and echo it.
# Used by the workflow to resolve the "latest release" matrix leg, which is then
# passed to the product script as `-t <tag>`.
#
# Usage: latest-tag.sh <repo>   (repo: "owner/repo" or a full git URL)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$DIR/common.sh"

url="$(resolve_repo_url "$1")"
tag="$(latest_tag "$url")"
if [ -z "$tag" ]; then
    echo "no tags found for $1" >&2
    exit 1
fi
printf '%s\n' "$tag"
