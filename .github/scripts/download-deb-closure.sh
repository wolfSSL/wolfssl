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
# Bundle exact (=) deps even if installed, as older images may differ, and
# the installed packages that pin a bundled one, as an older image has to
# upgrade those with it.
ARCHIVES=/var/cache/apt/archives
DEPS='${Package} ${Pre-Depends}, ${Depends}\n'
export LC_ALL=C  # sort, comm and join must agree on the order
# "name=version owner" for each exact (=) dep in "owner deps" lines.
exact() {
  awk '{
    n = split(substr($0, length($1) + 2), d, ",")
    for (i = 1; i <= n; i++) {
      sub(/\|.*/, "", d[i])  # apt prefers the first alternative
      if (d[i] !~ /^ *[^ :(|]+(:[^ ]+)? *\(= *[^ )]+\) *$/) continue
      sub(/^ +/, "", d[i]); split(d[i], f, /[ (=)]+/); sub(/:.*/, "", f[1])
      print f[1] "=" f[2], $1
    }
  }'
}
debs() {
  for deb in "$ARCHIVES"/*.deb; do
    dpkg-deb -W --showformat="$1" "$deb"
  done | sort -u
}
missing() {
  local bundled names
  bundled=$(debs '${Package}=${Version}\n')
  names=$(cut -d= -f1 <<< "$bundled" | sort -u)
  debs "$DEPS" | exact | cut -d' ' -f1 | sort -u | comm -23 - <(echo "$bundled")
  dpkg-query -W -f="\${db:Status-Status} $DEPS" | sed -n 's/^installed //p' \
    | exact | sed 's/=[^ ]*//' | sort | join -o 1.2 - <(echo "$names") \
    | sort -u | comm -23 - <(echo "$names")
}
declare -A tried=()
while :; do
  need=()
  while read -r pin; do
    [ -n "${tried[$pin]:-}" ] || need+=("$pin")
  done < <(missing)
  [ "${#need[@]}" -gt 0 ] || break
  echo "Pinned (${#need[@]}): ${need[*]}"
  for pin in "${need[@]}"; do
    tried[$pin]=1
    "$APT_INSTALL" --tries 5 --no-update --warn-only --download-only \
      --reinstall "$pin" || skipped=$((skipped+1))
  done
done
cp "$ARCHIVES"/*.deb "$DEST/" 2>/dev/null || true
# The steps that index and package these run unprivileged, and in the
# container we are root over a bind mount owned by the runner user.
chown --reference="$DEST" "$DEST"/*.deb 2>/dev/null || true
echo "Bundled $(ls "$DEST"/*.deb 2>/dev/null | wc -l) .deb files ($(du -sh "$DEST" | cut -f1)); ${skipped} skipped"
test -n "$(ls "$DEST"/*.deb 2>/dev/null)"  # fail if nothing was bundled
