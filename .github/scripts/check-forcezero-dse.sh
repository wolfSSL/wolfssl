#!/bin/sh
#
# check-forcezero-dse.sh
# ForceZero DSE regression check.
# Compiles dse_probe.c, verifies *_wipe() emits more stores than *_b().
#
# Usage:
#   check-forcezero-dse.sh [--builddir DIR] [--srcdir DIR] [--objdump OD]
#                           [--link] [--skip-on-compile-fail] [CC] [CFLAGS...]
#
# Options (must come before positional arguments):
#   --builddir DIR   path to a configured build directory (default: .)
#   --srcdir   DIR   path to the wolfSSL source root (default: inferred from
#                    the script location, or the current directory)
#   --objdump  OD    objdump (or cross-objdump) to use (default: objdump)
#   --link           link the probe into executable.
#   --skip-on-compile-fail
#                    exit 77 (skip) instead of 2 if the probe fails to
#                    compile, for callers where that means "unsupported
#                    config" rather than a regression (e.g. make check).
#
# Positional:
#   CC        compiler to use (default: gcc)
#   CFLAGS... extra flags, e.g. the build's CPPFLAGS/CFLAGS plus -O2
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

need_arg() { [ $# -ge 2 ] || { echo "check-forcezero-dse: $1 needs an argument" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
    case "$1" in
        --builddir) need_arg "$@"; BDIR=$2;   shift 2 ;;
        --srcdir)   need_arg "$@"; SRCDIR=$2; shift 2 ;;
        --objdump)  need_arg "$@"; OD=$2;     shift 2 ;;
        --link)     LINK=1;    shift 1 ;;
        --skip-on-compile-fail) SOFT_COMPILE_FAIL=1; shift 1 ;;
        --) shift; break ;;
        -*) echo "check-forcezero-dse: unknown option '$1'" >&2; exit 2 ;;
        *)  break ;;
    esac
done

CC=${1:-gcc}
[ $# -gt 0 ] && shift
XFLAGS=${*:--O2}

# A missing tool must be a loud error, not a silent SKIP via the "no
# symbol table" path below.
command -v "$OD" >/dev/null 2>&1 || {
    echo "::error::check-forcezero-dse: objdump '$OD' not found" >&2
    exit 2
}

# --disassemble=SYMBOL is binutils >= 2.33 (2019). An older objdump rejects
# the option outright, which count_insns() below cannot tell apart from "no
# instructions found" -- it would hard-fail instead of skipping. Probe once,
# up front, and skip cleanly on an unsupported toolchain.
"$OD" --disassemble=x --help >/dev/null 2>&1 || {
    echo "check-forcezero-dse: SKIP - $OD does not support" \
         "--disassemble=SYMBOL (needs binutils >= 2.33)"
    exit 77
}

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
    # Link against the built static lib, not hand-picked .c files: init/
    # cleanup reach into other TUs under configs like OPENSSL_EXTRA or
    # WOLF_CRYPTO_CB, and the archive only pulls in what's referenced.
    LIBWOLFSSL="$BDIR/src/.libs/libwolfssl.a"
    if [ ! -f "$LIBWOLFSSL" ]; then
        echo "::error::check-forcezero-dse: --link requires a built" \
             "$LIBWOLFSSL (run make first)" >&2
        exit 2
    fi
    COMPILE_CMD="$CC $XFLAGS -DHAVE_CONFIG_H -I$BDIR -I$SRCDIR $PROBE $LIBWOLFSSL -o $OUT"
else
    OUT="$TMP/dse_probe.o"
    COMPILE_CMD="$CC $XFLAGS -DHAVE_CONFIG_H -I$BDIR -I$SRCDIR -c $PROBE -o $OUT"
fi

# shellcheck disable=SC2086
if ! $COMPILE_CMD 2>"$TMP/err"; then
    if [ "$SOFT_COMPILE_FAIL" = "1" ]; then
        echo "check-forcezero-dse: SKIP - probe failed to compile" \
             "($CC $XFLAGS)"
        sed 's/^/  /' "$TMP/err" | head -10
        exit 77
    fi
    echo "::error::check-forcezero-dse: probe failed to compile ($CC $XFLAGS)"
    sed 's/^/  /' "$TMP/err" | head -10
    exit 2
fi

# -------------------------------------------------------------------------
# Count non-barrier instructions in a symbol's disassembly
# -------------------------------------------------------------------------
# A wipe that survived DSE emits strictly more instructions than its
# barrier-only twin; exclude fences/nops so barrier choice doesn't skew it.
# A slim-LTO object (CFLAGS=-flto without -ffat-lto-objects) has the symbol
# in its table but no disassemblable code -- not a DSE regression, so that
# case exits 77 (skip) rather than falling into the "symbol not found" error.
count_insns() {
    _sym=$1
    _asm=$($OD -d --no-show-raw-insn --disassemble="$_sym" "$OUT" 2>"$TMP/od_err") \
        || _asm=
    if [ -z "$_asm" ]; then
        _sym=".$_sym"
        _asm=$($OD -d --no-show-raw-insn --disassemble="$_sym" "$OUT" \
               2>"$TMP/od_err") || _asm=
        if [ -z "$_asm" ]; then
            if ! $OD -h "$OUT" 2>/dev/null | awk \
                    '$2 ~ /^\.text/ && $3 !~ /^0+$/ { f=1 } END { exit !f }'
            then
                echo "check-forcezero-dse: SKIP - no machine code in object" \
                     "(LTO without -ffat-lto-objects?) ($CC $XFLAGS)"
                return 77
            fi
            echo "::error::check-forcezero-dse: objdump failed or symbol" \
                 "$_sym not found" >&2
            sed 's/^/  /' "$TMP/od_err" >&2
            return 2
        fi
    fi
    # Filter on instruction-line pattern.
    _c=$(echo "$_asm" | tr '\t' ' ' | grep -E '^ *[0-9a-f]+:' \
         | grep -viE \
           'lock |mfence|lfence|sfence|hwsync|lwsync|(^|[^a-z])(dmb|isb|dsb|sync|fence)( |$)|(^|[^a-z])nop( |$)' \
         | grep -c .) || _c=0
    echo "$_c"
}

# -------------------------------------------------------------------------
# Discover probe pairs from the object file
# -------------------------------------------------------------------------
cases=$($OD -t "$OUT" 2>/dev/null \
    | sed -n 's/.*[[:space:]]\(dse_probe_[A-Za-z0-9_]*\)_wipe$/\1/p' \
    | sort -u)

if [ -z "$cases" ]; then
    if $OD -t "$OUT" 2>/dev/null \
            | grep -q '[[:space:]]dse_probe_not_applicable$'; then
        echo "check-forcezero-dse: SKIP - probe not applicable" \
             "(WOLFSSL_NO_FORCE_ZERO or NO_INLINE) ($CC $XFLAGS)"
        exit 77
    fi
    if [ -z "$($OD -t "$OUT" 2>/dev/null)" ]; then
        # $OD has no symbol table at all for this object (e.g. Fil-C's
        # instrumented objects -- even libtool's nm probe fails on them).
        # Unsupported toolchain, not a DSE regression.
        echo "check-forcezero-dse: SKIP - $OD cannot read symbols from" \
             "this object format ($CC $XFLAGS)"
        exit 77
    fi
    if $OD -t "$OUT" 2>/dev/null | grep -q '__gnu_lto_slim$'; then
        # GCC slim LTO (-flto without -ffat-lto-objects): functions are
        # GIMPLE bytecode, not real symbols, until link time. Not testable
        # here; not a DSE regression.
        echo "check-forcezero-dse: SKIP - slim LTO object has no" \
             "disassemblable symbols (use -ffat-lto-objects or --link)" \
             "($CC $XFLAGS)"
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
    if w=$(count_insns "${c}_wipe"); then wrc=0; else wrc=$?; fi
    [ "$wrc" -eq 77 ] && exit 77
    [ "$wrc" -eq 0 ] || exit 2
    if k=$(count_insns "${c}_b"); then krc=0; else krc=$?; fi
    [ "$krc" -eq 77 ] && exit 77
    [ "$krc" -eq 0 ] || exit 2

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
