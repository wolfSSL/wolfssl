#!/bin/sh
# Install apt packages with retries and hard timeouts, so a stuck mirror fails
# an attempt instead of hanging the job.
#
# usage: apt-install.sh [options] [--] [apt-get install args...]
#   --tries N              attempts (default 3)
#   --update-timeout S     limit for each apt-get update (default 90)
#   --install-timeout S    limit for each apt-get install (default 300)
#   --delay S              wait before the first retry, doubled after (5)
#   --no-update            skip apt-get update
#   --drop-vendor-sources  remove the runner's Google/Microsoft apt sources
#   --warn-only            report the last failure as a warning, not an error
# The remaining args go to apt-get install as is, so --no-install-recommends
# and --download-only work. With none, only apt-get update runs.
set -u

tries=3
update_timeout=90
install_timeout=300
delay=5
update=1
drop_vendor=0
level=error

while [ $# -gt 0 ]; do
    case $1 in
        --tries) tries=$2; shift ;;
        --update-timeout) update_timeout=$2; shift ;;
        --install-timeout) install_timeout=$2; shift ;;
        --delay) delay=$2; shift ;;
        --no-update) update=0 ;;
        --drop-vendor-sources) drop_vendor=1 ;;
        --warn-only) level=warning ;;
        --) shift; break ;;
        *) break ;;
    esac
    shift
done

for n in "$tries" "$update_timeout" "$install_timeout" "$delay"; do
    case $n in
        ''|*[!0-9]*) echo "apt-install.sh: not a number: '$n'" >&2; exit 2 ;;
    esac
done
for n in "$tries" "$update_timeout" "$install_timeout"; do
    [ "$n" -gt 0 ] || {
        echo "apt-install.sh: must be positive: '$n'" >&2
        exit 2
    }
done

export DEBIAN_FRONTEND=noninteractive
if [ "$(id -u)" -eq 0 ]; then
    as_root() { "$@"; }
else
    # sudo resets the environment, so DEBIAN_FRONTEND has to go through it.
    as_root() { sudo DEBIAN_FRONTEND=noninteractive "$@"; }
fi

apt_get() {
    limit=$1
    shift
    as_root timeout -k 10 "$limit" apt-get -o Acquire::Retries=3 \
        -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 "$@"
}

attempt() {
    # An attempt killed mid-unpack leaves dpkg needing this.
    as_root dpkg --configure -a || true
    if [ "$update" -eq 1 ]; then
        step=update
        apt_get "$update_timeout" update -q || return
    fi
    [ $# -gt 0 ] || return 0
    step=install
    apt_get "$install_timeout" install -y -q "$@"
}

if [ "$drop_vendor" -eq 1 ]; then
    # No job uses these, and a bad index on either fails apt-get update.
    grep -rlE 'dl\.google\.com|packages\.microsoft\.com' \
        /etc/apt/sources.list.d/ 2>/dev/null |
        while read -r f; do as_root rm -vf "$f"; done
fi

i=1
while :; do
    rc=0
    attempt "$@" || rc=$?
    [ "$rc" -ne 0 ] || exit 0
    # A killed apt-get prints nothing, so name the timeout.
    case $rc in
        124|137) why="timed out" ;;
        *) why="failed with exit code $rc" ;;
    esac
    [ "$i" -lt "$tries" ] || break
    echo "::warning::apt-get $step $why (attempt $i/$tries)," \
         "retrying in ${delay}s"
    sleep "$delay"
    delay=$((delay * 2))
    i=$((i + 1))
done

echo "::$level::apt-get $step $why (attempt $i/$tries), giving up${*:+ on: $*}"
exit "$rc"
