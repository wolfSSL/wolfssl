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

mapfile -t PKGS < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$LIST")
echo "Packages (${#PKGS[@]}): ${PKGS[*]}"
export DEBIAN_FRONTEND=noninteractive
# Not rm -rf: in the container this directory is a bind mount.
mkdir -p "$DEST" && rm -f "$DEST"/*.deb
apt-get clean
# A single stalled mirror connection once hung -full for ~20 min (it normally
# finishes in a few). retry() only re-runs on a non-zero exit, so a hang never
# tripped it. Defend in depth: apt drops a stalled connection after 30s and
# retries it (Acquire timeouts), `timeout` hard-kills a wedged apt-get, then
# retry() re-runs from scratch.
APT_OPTS=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30
          -o Acquire::https::Timeout=30)
retry() { local i; for i in 1 2 3 4 5; do "$@" && return 0; sleep $((2**i)); done; "$@"; }
retry timeout -k 10 120 apt-get "${APT_OPTS[@]}" update -q
# Download each package's closure independently (requested package + any
# dependency not already installed) without installing. Per package, not one
# resolve of the whole list, so one unbundleable package - e.g. a conflict in
# the big -full union - cannot abort the rest; install-apt-deps falls back to
# apt for anything missing.
skipped=0
for pkg in "${PKGS[@]}"; do
  retry timeout -k 10 300 apt-get "${APT_OPTS[@]}" install -y --download-only "$pkg" \
    || { echo "::warning::could not download $pkg"; skipped=$((skipped+1)); }
done
cp /var/cache/apt/archives/*.deb "$DEST/" 2>/dev/null || true
# The steps that index and package these run unprivileged, and in the
# container we are root over a bind mount owned by the runner user.
chown --reference="$DEST" "$DEST"/*.deb 2>/dev/null || true
echo "Bundled $(ls "$DEST"/*.deb 2>/dev/null | wc -l) .deb files ($(du -sh "$DEST" | cut -f1)); ${skipped} skipped"
test -n "$(ls "$DEST"/*.deb 2>/dev/null)"  # fail if nothing was bundled
