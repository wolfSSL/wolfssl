#!/usr/bin/env bash
# Download the .deb closure for one package list into a directory, for
# .github/workflows/ci-deps-image.yml to publish as a bundle.
#
# Runs as root - under sudo on the runner, or inside the container image the
# bundle is built for. WHERE it runs is the point: apt downloads only what is
# not already installed, so a closure resolved on the runner carries nothing
# the runner image preinstalls and cannot be installed anywhere else. The sssd
# job asked the runner-resolved -full bundle for `bc` and `libcap-dev` and got
# neither (bc is preinstalled on the runner, and libcap-dev's libcap2 was too),
# so it fell through to the apt mirror every time.
#
# usage: download-deb-closure.sh <package-list> <dest-dir>
set -uo pipefail

LIST=${1:?package list}
DEST=${2:?destination directory}

APT_INSTALL="$(dirname "$0")/../actions/install-apt-deps/apt-install.sh"

mapfile -t PKGS < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$LIST")
echo "Packages (${#PKGS[@]}): ${PKGS[*]}"
# Not rm -rf: in the container this directory is a bind mount.
mkdir -p "$DEST" && rm -f "$DEST"/*.deb
apt-get clean
"$APT_INSTALL" --tries 5 --update-timeout 120 --drop-vendor-sources
# Download each package's closure independently (requested package + any
# dependency not already installed) without installing. Per package, not one
# resolve of the whole list, so one unbundleable package - e.g. a conflict in
# the big -full union - cannot abort the rest; install-apt-deps falls back to
# apt for anything missing.
skipped=0
for pkg in "${PKGS[@]}"; do
  "$APT_INSTALL" --tries 5 --no-update --warn-only --download-only "$pkg" \
    || skipped=$((skipped+1))
done
cp /var/cache/apt/archives/*.deb "$DEST/" 2>/dev/null || true
# The steps that index and package these run unprivileged, and in the
# container we are root over a bind mount owned by the runner user.
chown --reference="$DEST" "$DEST"/*.deb 2>/dev/null || true
echo "Bundled $(ls "$DEST"/*.deb 2>/dev/null | wc -l) .deb files ($(du -sh "$DEST" | cut -f1)); ${skipped} skipped"
test -n "$(ls "$DEST"/*.deb 2>/dev/null)"  # fail if nothing was bundled
