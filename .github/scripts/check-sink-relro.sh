#!/bin/sh
#
# check-sink-relro.sh
# Assert WC_BARRIER_DATA()'s portable sink pointer compiles into a read-only
# section (.data.rel.ro / PE READONLY). Compiles wc_port.c without linking.
#
# wc_BarrierDataSink uses a volatile read of a const pointer to prevent
# devirtualization while keeping the pointer in a read-only section.
#
# ELF/PE only. Skips if the portable arm isn't selected.
#
# Usage:
#   check-sink-relro.sh [--builddir DIR] [--srcdir DIR] [--objdump OD]
#                       [--skip-on-compile-fail] [CC] [CFLAGS...]
#
# Options (must come before positional arguments):
#   --builddir DIR   path to a configured build directory (default: .)
#   --srcdir   DIR   path to the wolfSSL source root (default: inferred from
#                    the script location, or the current directory)
#   --objdump  OD    objdump (or cross-objdump) to use (default: objdump)
#   --skip-on-compile-fail
#                    Exit 77 (skip) instead of 2 on compile failure, treating
#                    it as an unsupported config rather than a regression.
#
# Positional:
#   CC        compiler to use (default: gcc; must be given explicitly if
#             any CFLAGS follow -- a leading CFLAGS with no CC is parsed
#             as an unknown option)
#   CFLAGS... extra flags appended after the build-dir flags.  Pass whatever
#             selects the portable arm, e.g. -O2 -DWOLFSSL_NO_ASM
#
# Examples:
#   check-sink-relro.sh --builddir . --srcdir .. gcc -O2 -DWOLFSSL_NO_ASM
#   check-sink-relro.sh --builddir build-arm64 --srcdir . \
#       --objdump aarch64-linux-gnu-objdump \
#       aarch64-linux-gnu-gcc -O2 -DWOLFSSL_NO_ASM

set -e

# -------------------------------------------------------------------------
# Option parsing
# -------------------------------------------------------------------------
BDIR=.
SRCDIR=
OD=objdump
SOFT_COMPILE_FAIL=

# shellcheck source=ci-probe-common.sh
. "$(dirname "$0")/ci-probe-common.sh"

while [ $# -gt 0 ]; do
    case "$1" in
        --builddir) need_arg "$@"; BDIR=$2;   shift 2 ;;
        --srcdir)   need_arg "$@"; SRCDIR=$2; shift 2 ;;
        --objdump)  need_arg "$@"; OD=$2;     shift 2 ;;
        --skip-on-compile-fail) SOFT_COMPILE_FAIL=1; shift 1 ;;
        --) shift; break ;;
        -*) echo "check-sink-relro: unknown option '$1'" >&2; exit 2 ;;
        *)  break ;;
    esac
done

CC=${1:-gcc}
[ $# -gt 0 ] && shift
XFLAGS=${*:--O2}

# A missing tool must be a loud error, not a silent SKIP via an unreadable-
# object-format path below.
command -v "$OD" >/dev/null 2>&1 || {
    echo "::error::check-sink-relro: objdump '$OD' not found" >&2
    exit 2
}

infer_srcdir "$0"

PORT_C="$SRCDIR/wolfcrypt/src/wc_port.c"
if [ ! -f "$PORT_C" ]; then
    echo "::error::check-sink-relro: source not found: $PORT_C" >&2
    exit 2
fi

# -I"$BDIR" -I"$SRCDIR" are quoted directly at each call site below (not
# folded into this string and re-split later), so a path containing a space
# survives; $XFLAGS is intentionally left unquoted here to word-split.
PROBE_CFLAGS="-DHAVE_CONFIG_H $XFLAGS"

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT

# -------------------------------------------------------------------------
# Check 1: the definition lands in .data.rel.ro
# -------------------------------------------------------------------------
# wc_BarrierDataSinkImpl/Ptr/wc_BarrierDataSink are compiled unconditionally
# in wc_port.c (not gated on WC_BARRIER_DATA_USES_SINK), so this check runs
# regardless of which WC_BARRIER_DATA() arm the configuration selects.
compile_rc=0
# shellcheck disable=SC2086
$CC $PROBE_CFLAGS -I"$BDIR" -I"$SRCDIR" -fPIC -fvisibility=hidden \
        -DBUILDING_WOLFSSL -c "$PORT_C" -o "$TMP/wc_port.o" \
        2>"$TMP/err" || compile_rc=$?
report_compile_rc "$compile_rc" "wc_port.c failed to compile ($CC $XFLAGS)" \
        check-sink-relro

if ! $OD -t "$TMP/wc_port.o" >"$TMP/syms" 2>/dev/null; then
    echo "check-sink-relro: SKIP - $OD cannot read the object format"
    exit 77
fi

fmt=$($OD -f "$TMP/wc_port.o" 2>/dev/null \
      | sed -n 's/.*file format \(.*\)/\1/p' | head -1)

case "$fmt" in
elf*)
    # Handled after the esac; see "Check 1" continuation below.
    ;;
pe-*|coff-*|pei-*)
    # PE/COFF: check that definition is marked READONLY.
    # objdump -t prints "(sec N)" for COFF instead of the section name, and
    # i386 decorates the symbol with a leading underscore.
    idx=$(sed -n "s/.*(sec *\([0-9][0-9]*\)).*[[:space:]_]wc_BarrierDataSinkPtr\$/\1/p" \
          "$TMP/syms" | head -1)

    if [ -z "$idx" ] || [ "$idx" -eq 0 ]; then
        echo "::error::check-sink-relro: wc_BarrierDataSinkPtr not found in" \
             "wc_port.o -- it is compiled unconditionally in wc_port.c, so a" \
             "missing symbol means the definition was removed or optimized away"
        exit 2
    fi

    pesec=$($OD -h "$TMP/wc_port.o" 2>/dev/null | awk -v want=$((idx - 1)) '
        $1 == want && $2 ~ /^\./ {
            name = $2
            getline
            print name, (index($0, "READONLY") ? "RO" : "RW")
            exit
        }')

    case "$pesec" in
        *" RO")
            printf '  %-24s %s\n' "definition section" \
                   "ok     (${pesec% RO}, READONLY)"
            echo "check-sink-relro: PASS - wc_BarrierDataSinkPtr is in a read-only" \
                 "image section ($CC $XFLAGS)"
            exit 0
            ;;
        "")
            echo "check-sink-relro: SKIP - cannot resolve the PE section" \
                 "for wc_BarrierDataSinkPtr ($CC $XFLAGS)"
            exit 77
            ;;
        *)
            printf '  %-24s %s\n' "definition section" \
                   "FAIL   (${pesec% RW}, writable)"
            echo "::error::check-sink-relro: wc_BarrierDataSinkPtr is in" \
                 "'${pesec% RW}', which is not marked READONLY -- it is an" \
                 "exported writable indirect-call target. Did the 'const'" \
                 "qualifier get dropped? ($CC $XFLAGS)"
            exit 1
            ;;
    esac
    ;;
*)
    echo "check-sink-relro: SKIP - unsupported object format '$fmt'" \
         "($CC $XFLAGS)"
    exit 77
    ;;
esac

# Every non-elf* arm above exits, so reaching here means $fmt matched elf*.
sec=$(sed -n 's/.*[[:space:]]\(\.[A-Za-z0-9_.-]*\)[[:space:]].*[[:space:]]wc_BarrierDataSinkPtr$/\1/p' \
      "$TMP/syms" | head -1)

if [ -z "$sec" ]; then
    echo "::error::check-sink-relro: wc_BarrierDataSinkPtr not found in wc_port.o" \
         "-- it is compiled unconditionally in wc_port.c, so a missing symbol" \
         "means the definition was removed or optimized away"
    exit 2
fi

case "$sec" in
    .data.rel.ro*|.rodata*|.sdata.rel.ro*|.srodata*)
        # Both .rodata and .data.rel.ro are read-only at runtime.
        printf '  %-24s %s\n' "definition section" "ok     ($sec)"
        echo "check-sink-relro: PASS - wc_BarrierDataSinkPtr compiles into" \
             "'$sec' ($CC $XFLAGS)"
        exit 0
        ;;
    *)
        printf '  %-24s %s\n' "definition section" "FAIL   ($sec)"
        echo "::error::check-sink-relro: wc_BarrierDataSinkPtr is in '$sec'," \
             "expected .data.rel.ro or .rodata -- it is writable at" \
             "runtime. Did the 'const' qualifier get dropped, or a section" \
             "attribute get forced onto it? ($CC $XFLAGS)"
        exit 1
        ;;
esac
