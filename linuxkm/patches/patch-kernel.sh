#!/usr/bin/env bash
#
# patch-kernel.sh -- apply the wolfSSL FIPS get_random_bytes() patch to a kernel.
#
#   ./patch-kernel.sh /path/to/linux-6.6.99
#   ./patch-kernel.sh /path/to/linux-6.6.99 6.12        # force a base
#   ./patch-kernel.sh --dry-run /path/to/linux-7.1.9
#
# With no base given, the version is read from the kernel Makefile and looked up
# in README.md's coverage table, so you get the base that was TESTED for your
# version rather than the nearest-looking one.
#
# IT REFUSES TO FUZZ.  patch(1) will happily place a hunk in the wrong function
# when context has drifted; that produces a tree which compiles and is wrong.
# It happened here: applying the 5.15 base to 5.17 at --fuzz=3 put the
# mix_pool_bytes() hunk inside fast_mix(), giving
# "random.c:915: error: 'in' undeclared".  A marker count cannot see that -- the
# count is identical either way.  So this script applies at --fuzz=0 and stops
# if that fails.  If it stops, your version needs its own base; do not reach for
# --fuzz.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DRY=0
[ "${1:-}" = "--dry-run" ] && { DRY=1; shift; }

KDIR="${1:-}"
BASE="${2:-}"

die() { printf 'patch-kernel: %s\n' "$*" >&2; exit 1; }

[ -n "$KDIR" ] || die "usage: $0 [--dry-run] <path-to-kernel-source> [base]"
[ -d "$KDIR" ] || die "not a directory: $KDIR"
[ -f "$KDIR/Makefile" ] || die "no Makefile in $KDIR -- is that a kernel tree?"
[ -f "$KDIR/drivers/char/random.c" ] || die "no drivers/char/random.c in $KDIR"

# --- work out the kernel version -------------------------------------------
V=$(awk '/^VERSION[[:space:]]*=/{v=$3} /^PATCHLEVEL[[:space:]]*=/{p=$3}
         /^SUBLEVEL[[:space:]]*=/{s=$3} END{printf "%s.%s.%s", v, p, s}' "$KDIR/Makefile")
SERIES=${V%.*}
printf 'kernel  : %s  (series %s)\n' "$V" "$SERIES"

# --- pick the base ----------------------------------------------------------
if [ -z "$BASE" ]; then
    # Rows look like:  | 6.6  | 6.6.99 | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch` | ...
    # Prefer a row whose "verified at" matches exactly, else the series row.
    BASE_PATCH=$(awk -v v="$V" -F'|' '
        $0 ~ /^\|/ && $3 ~ v {gsub(/[` ]/,"",$4); print $4; exit}' "$HERE/README.md" || true)
    [ -n "${BASE_PATCH:-}" ] || BASE_PATCH=$(awk -v s="$SERIES" -F'|' '
        $0 ~ /^\|/ {gsub(/ /,"",$2); if ($2==s) {gsub(/[` ]/,"",$4); print $4; exit}}' "$HERE/README.md" || true)
    [ -n "${BASE_PATCH:-}" ] || die "no row for $V (series $SERIES) in README.md.
Your version is NOT in the supported set.  Do not guess a nearby base --
see README.md for why that produces a tree that compiles and is wrong."
else
    BASE_PATCH=$(ls "$HERE/$BASE"/*_FIPS.patch 2>/dev/null | head -1) \
        || die "no *_FIPS.patch under $HERE/$BASE"
    BASE_PATCH=${BASE_PATCH#"$HERE/"}
fi

PATCH="$HERE/$BASE_PATCH"
[ -f "$PATCH" ] || die "patch file not found: $PATCH"
printf 'patch   : %s\n' "$BASE_PATCH"

# --- apply, at fuzz 0, never more -------------------------------------------
if ! patch -p1 -d "$KDIR" --dry-run --fuzz=0 --force < "$PATCH" >/tmp/pk.$$ 2>&1; then
    sed 's/^/  /' /tmp/pk.$$ >&2; rm -f /tmp/pk.$$
    die "patch does NOT apply cleanly at --fuzz=0.
This is a refusal, not a suggestion to retry with fuzz.  Either the tree is not
pristine, or $V needs a base of its own.  Raising --fuzz can place a hunk in the
wrong function and still exit 0."
fi
rm -f /tmp/pk.$$

if [ "$DRY" = 1 ]; then
    printf 'result  : would apply cleanly (dry run, nothing written)\n'
    exit 0
fi

patch -p1 -d "$KDIR" --fuzz=0 --force < "$PATCH" | sed 's/^/  /'
printf 'result  : applied\n'
printf '\nnext    : build the kernel, then build the module against it:\n'
printf '            ./configure --enable-linuxkm --with-linux-source=%s ...\n' "$KDIR"
printf '          The module binds to symbols this patch exports; if the kernel\n'
printf '          is unpatched, insmod fails with "Unknown symbol\n'
printf '          wolfssl_linuxkm_register_random_bytes_handlers" rather than\n'
printf '          silently running without the hook.\n'
