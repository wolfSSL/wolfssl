#!/bin/sh
#
# check-forcezero-dse.sh
# ForceZero() dead-store-elimination regression check.
#
# Compiles wolfcrypt/test/dse_probe.c against a configured build tree and
# checks that every *_wipe() probe emits more non-barrier stores than its
# *_b() (barrier-only, no zeroing) twin.  A wipe that the compiler folds
# away is caught here.  See dse_probe.c for why *_b(), not *_nowipe(), is
# the baseline.
#
# Usage:
#   check-forcezero-dse.sh [--builddir DIR] [--srcdir DIR] [--objdump OD]
#                           [--link] [CC] [CFLAGS...]
#
# Options (must come before positional arguments):
#   --builddir DIR   path to a configured build directory (default: .)
#   --srcdir   DIR   path to the wolfSSL source root (default: inferred from
#                    the script location, or the current directory)
#   --objdump  OD    objdump (or cross-objdump) to use (default: objdump)
#   --link           link the probe into a full executable (with wc_port.c).
#                    Only tested against builds with wolfCrypt_Init/Cleanup's
#                    externs disabled (e.g. plain ./configure, no
#                    --enable-all); a fuller config (FP_ECC, OPENSSL_EXTRA,
#                    WOLF_CRYPTO_CB, ...) may need more objects on the link
#                    line.
#
# Positional:
#   CC        compiler to use (default: gcc)
#   CFLAGS... extra flags appended after the build-dir flags (e.g. -O2 -flto)
#
# The script reads compile flags from the configured build directory:
#   - config.h is included via -DHAVE_CONFIG_H -I<builddir>
#   - wolfssl/options.h is picked up from <builddir> before the source tree
#
# Examples:
#   # x86-64, default build dir:
#   check-forcezero-dse.sh gcc -O2
#   check-forcezero-dse.sh clang -O3
#
#   # ARM64 cross-build in build-arm64-o2/:
#   check-forcezero-dse.sh --builddir build-arm64-o2 \
#       --objdump aarch64-linux-gnu-objdump \
#       aarch64-linux-gnu-gcc -O2

set -e

# -------------------------------------------------------------------------
# Option parsing
# -------------------------------------------------------------------------
BDIR=.
SRCDIR=
OD=objdump

while [ $# -gt 0 ]; do
    case "$1" in
        --builddir) BDIR=$2;   shift 2 ;;
        --srcdir)   SRCDIR=$2; shift 2 ;;
        --objdump)  OD=$2;     shift 2 ;;
        --link)     LINK=1;    shift 1 ;;
        --) shift; break ;;
        -*) echo "check-forcezero-dse: unknown option '$1'" >&2; exit 2 ;;
        *)  break ;;
    esac
done

CC=${1:-gcc}
[ $# -gt 0 ] && shift
XFLAGS=${*:--O2}

# Infer source root from the script's own location if not given.
if [ -z "$SRCDIR" ]; then
    SRCDIR=$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd) || SRCDIR=.
fi

PROBE="$SRCDIR/wolfcrypt/test/dse_probe.c"
if [ ! -f "$PROBE" ]; then
    echo "::error::check-forcezero-dse: probe not found: $PROBE" >&2
    echo "  (expected wolfcrypt/test/dse_probe.c in the wolfSSL source tree)" >&2
    exit 2
fi

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT

# -------------------------------------------------------------------------
# Compile the probe against the real build tree
# -------------------------------------------------------------------------
# Include order:
#   1. builddir  - picks up config.h and wolfssl/options.h (generated)
#   2. srcdir    - picks up all wolfSSL headers
if [ "$LINK" = "1" ]; then
    COMPILE_CMD="$CC $XFLAGS -DHAVE_CONFIG_H -I$BDIR -I$SRCDIR $PROBE $SRCDIR/wolfcrypt/src/wc_port.c $SRCDIR/wolfcrypt/src/memory.c -o $TMP/dse_probe.o"
else
    COMPILE_CMD="$CC $XFLAGS -DHAVE_CONFIG_H -I$BDIR -I$SRCDIR -c $PROBE -o $TMP/dse_probe.o"
fi

# shellcheck disable=SC2086
if ! $COMPILE_CMD 2>"$TMP/err"; then
    echo "::error::check-forcezero-dse: probe failed to compile ($CC $XFLAGS)"
    sed 's/^/  /' "$TMP/err" | head -10
    exit 2
fi

# -------------------------------------------------------------------------
# Count non-barrier stores in a symbol's disassembly
# -------------------------------------------------------------------------
# Barrier instructions (fence, isb, dmb, lfence, mfence, etc.) are excluded
# so that extra barrier instructions inserted by ForceZero don't inflate the
# wipe count and mask a real DSE.  The comparison is: do the zeroing stores
# themselves survive?
count_insns() {
    _sym=$1
    _asm=$($OD -d --no-show-raw-insn --disassemble="$_sym" "$TMP/dse_probe.o" 2>/dev/null)
    if [ -z "$_asm" ]; then
        _sym=".$_sym"
        _asm=$($OD -d --no-show-raw-insn --disassemble="$_sym" "$TMP/dse_probe.o" 2>/dev/null)
        if [ -z "$_asm" ]; then
            echo "::error::check-forcezero-dse: objdump failed or symbol $_sym not found" >&2
            return 2
        fi
    fi
    # Header/label lines never match "<offset>:" (they're indented
    # differently or have no colon right after the hex), so filtering on
    # the instruction-line pattern alone is enough -- no fixed line count.
    _c=$(echo "$_asm" | tr '\t' ' ' | grep -E '^ *[0-9a-f]+:' \
         | grep -viE \
           'lock |mfence|hwsync|lwsync|[^a-z](dmb|isb|dsb|sync|fence)( |$)|nop' \
         | grep -c .) || _c=0
    echo "$_c"
}

# -------------------------------------------------------------------------
# Discover probe pairs from the object file
# -------------------------------------------------------------------------
cases=$($OD -t "$TMP/dse_probe.o" 2>/dev/null \
    | sed -n 's/.*[ \t]\(dse_probe_[A-Za-z0-9_]*\)_wipe$/\1/p' \
    | sort -u)

if [ -z "$cases" ]; then
    echo "::error::check-forcezero-dse: no dse_probe_*_wipe symbols found" \
         "-- $OD may not understand the object format or the file is empty"
    exit 2
fi

# -------------------------------------------------------------------------
# Run the check
# -------------------------------------------------------------------------
fail=0
for c in $cases; do
    w=$(count_insns "${c}_wipe") || exit 2
    k=$(count_insns "${c}_b") || exit 2

    if [ "$w" -gt "$k" ]; then
        printf '  %-20s ok     (%s vs %s insns)\n' \
               "${c#dse_probe_}" "$w" "$k"
    else
        printf '  %-20s FAIL   wipe eliminated (%s vs %s insns)\n' \
               "${c#dse_probe_}" "$w" "$k"
        echo "::error::check-forcezero-dse: ForceZero() wipe dead-store" \
             "eliminated in '${c#dse_probe_}' ($CC $XFLAGS)"
        fail=$((fail + 1))
    fi
done

n=$(echo "$cases" | grep -c .)
if [ "$fail" -eq 0 ]; then
    echo "check-forcezero-dse: PASS - $n/$n cases wiped ($CC $XFLAGS)"
    exit 0
fi
echo "check-forcezero-dse: FAIL - $fail/$n wipes eliminated ($CC $XFLAGS)"
exit 1
