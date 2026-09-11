#!/usr/bin/env bash
# Unpack a directory out of a public ghcr image using only curl and tar.
#
# install-apt-deps uses `docker create`/`docker cp` when it can, but a job
# running in a container (sssd.yml) has no docker CLI inside that container,
# so it skipped the .deb bundle and went to the apt mirror - the exact stall
# the bundles exist to remove, and which failed the sssd job outright when
# the mirror went slow. An anonymous registry pull needs nothing that an
# Ubuntu-based image does not already have.
#
# usage: ghcr-pull.sh <ghcr.io/owner/name:tag> <dir-in-image> <dest-dir>
# The contents of <dir-in-image> land directly in <dest-dir>.
set -uo pipefail

IMG=${1:?image}
MEMBER=${2:?directory in the image}
DEST=${3:?destination}

REF=${IMG#ghcr.io/}
REPO=${REF%:*}
TAG=${REF##*:}
API="https://ghcr.io/v2/$REPO"

die() { echo "ghcr-pull: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is not installed"

# ghcr issues an anonymous pull token for any public package. For a private
# one it issues a token that then 401s below, which reads the same as "no
# bundle here" and is handled the same way.
TOKEN=$(curl -sS --retry 3 --max-time 60 \
          "https://ghcr.io/token?service=ghcr.io&scope=repository:$REPO:pull" \
        | tr -d '\n\r\t ' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || die "no anonymous pull token for $REPO"

TYPES='application/vnd.oci.image.index.v1+json,
application/vnd.oci.image.manifest.v1+json,
application/vnd.docker.distribution.manifest.list.v2+json,
application/vnd.docker.distribution.manifest.v2+json'

reg() {
  curl -sS --fail --location --retry 3 \
    -H "Authorization: Bearer $TOKEN" "$@"
}

# Every digest in one array of a manifest. Registries serve the manifest
# bytes exactly as they were pushed and every builder writes `config` before
# `layers`, so everything past the key is that array. Splitting an index on
# '}' keeps each entry's digest with its platform, which is the one thing
# this has to get right.
after() { tr -d '\n\r\t ' | sed -n "s/.*\"$1\":\[//p"; }

MAN=$(reg -H "Accept: ${TYPES//$'\n'/}" "$API/manifests/$TAG") \
  || die "cannot read the manifest for $IMG"

# Multi-arch index: swap in the amd64 manifest. The bundles are single-arch
# today; this keeps a builder change from silently breaking the pull.
if printf '%s' "$MAN" | grep -q '"manifests"'; then
  CHILD=$(printf '%s' "$MAN" | after manifests | tr '}' '\n' \
          | grep '"architecture":"amd64"' \
          | grep -oE 'sha256:[0-9a-f]{64}' | head -n1)
  [ -n "$CHILD" ] || die "no amd64 manifest in $IMG"
  MAN=$(reg -H "Accept: ${TYPES//$'\n'/}" "$API/manifests/$CHILD") \
    || die "cannot read the amd64 manifest of $IMG"
fi

LAYERS=$(printf '%s' "$MAN" | after layers | grep -oE 'sha256:[0-9a-f]{64}')
[ -n "$LAYERS" ] || die "no layers in the manifest for $IMG"

mkdir -p "$DEST"
for digest in $LAYERS; do
  # Layers are applied in order, but only this one directory is wanted, so
  # tar's exit status is ignored: a layer that does not carry it is normal.
  # curl's is not - a cut-off transfer would look like a bundle that is
  # merely missing a package.
  reg "$API/blobs/$digest" \
    | tar -xz -C "$DEST" --strip-components=1 --no-same-owner "$MEMBER" \
      2>/dev/null
  rc=${PIPESTATUS[0]}
  [ "$rc" -eq 0 ] || die "downloading layer ${digest#sha256:} failed ($rc)"
done
