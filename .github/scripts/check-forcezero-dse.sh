#!/bin/sh
#
# check-forcezero-dse.sh
# ForceZero DSE regression check.
# Compiles dse_probe.c, verifies *_wipe() emits more stores than *_b().
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
#   --link           link the probe into executable.
#
# Positional:
#   CC        compiler to use (default: gcc)
#   CFLAGS... extra flags appended after the build-dir flags (e.g. -O2 -flto)
#
# Reads compile flags from build directory.
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

# Infer source root.
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
# Include order: 1. builddir 2. srcdir
if [ "$LINK" = "1" ]; then
    OUT="$TMP/dse_probe"
    COMPILE_CMD="$CC $XFLAGS -DHAVE_CONFIG_H -I$BDIR -I$SRCDIR $PROBE $SRCDIR/wolfcrypt/src/wc_port.c $SRCDIR/wolfcrypt/src/memory.c -o $OUT"
else
    OUT="$TMP/dse_probe.o"
    COMPILE_CMD="$CC $XFLAGS -DHAVE_CONFIG_H -I$BDIR -I$SRCDIR -c $PROBE -o $OUT"
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
# Exclude barrier instructions to count only zeroing stores.
count_insns() {
    _sym=$1
    _asm=$($OD -d --no-show-raw-insn --disassemble="$_sym" "$OUT" 2>/dev/null)
    if [ -z "$_asm" ]; then
        _sym=".$_sym"
        _asm=$($OD -d --no-show-raw-insn --disassemble="$_sym" "$OUT" 2>/dev/null)
        if [ -z "$_asm" ]; then
            echo "::error::check-forcezero-dse: objdump failed or symbol $_sym not found" >&2
            return 2
        fi
    fi
    # Filter on instruction-line pattern.
    _c=$(echo "$_asm" | tr '\t' ' ' | grep -E '^ *[0-9a-f]+:' \
         | grep -viE \
           'lock |mfence|lfence|sfence|hwsync|lwsync|(^|[^a-z])(dmb|isb|dsb|sync|fence)( |$)|nop' \
         | grep -c .) || _c=0
    echo "$_c"
}

# -------------------------------------------------------------------------
# Discover probe pairs from the object file
# -------------------------------------------------------------------------
cases=$($OD -t "$OUT" 2>/dev/null \
    | sed -n 's/.*[ \t]\(dse_probe_[A-Za-z0-9_]*\)_wipe$/\1/p' \
    | sort -u)

if [ -z "$cases" ]; then
    if $OD -t "$OUT" 2>/dev/null \
            | grep -q '[ \t]dse_probe_not_applicable$'; then
        echo "check-forcezero-dse: SKIP - WOLFSSL_NO_FORCE_ZERO," \
             "ForceZero() not compiled ($CC $XFLAGS)"
        exit 0
    fi
    if [ -z "$($OD -t "$OUT" 2>/dev/null)" ]; then
        # $OD has no symbol table at all for this object (e.g. Fil-C's
        # instrumented objects -- even libtool's nm probe fails on them).
        # Unsupported toolchain, not a DSE regression.
        echo "check-forcezero-dse: SKIP - $OD cannot read symbols from" \
             "this object format ($CC $XFLAGS)"
        exit 77
    fi
    echo "::error::check-forcezero-dse: no dse_probe_*_wipe symbols found" \
         "in a readable symbol table -- probes may have been stripped" \
         "or inlined away"
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
