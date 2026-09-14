#!/bin/sh
#
# check-sink-relro.sh
# Assert WC_BARRIER_DATA()'s portable sink pointer compiles into a read-only
# section (.data.rel.ro / PE READONLY), not that it ends up in a PT_GNU_RELRO
# segment at link time -- this only compiles wc_port.c, it doesn't link.
#
# wc_BarrierDataSink is an exported function called from inlined ForceZero()
# calls outside the library. Internally it reads the static const pointer
# bd_sink_ptr through a volatile local. "const" on bd_sink_ptr is
# what puts it in a read-only section; the volatile local read (not
# bd_sink_ptr itself) is what defeats devirtualization.
#
# ELF/PE only. Skips cleanly on other formats or if the portable arm isn't
# selected.
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
#                    exit 77 (skip) instead of 2 if wc_port.h fails to
#                    preprocess or wc_port.c fails to compile, for callers
#                    where a config.h mismatch (e.g. a cross toolchain
#                    reusing a native build dir) means "unsupported
#                    combination" rather than a regression.
#
# Positional:
#   CC        compiler to use (default: gcc)
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

need_arg() { [ $# -ge 2 ] || { echo "check-sink-relro: $1 needs an argument" >&2; exit 2; }; }
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

# Infer source root.
if [ -z "$SRCDIR" ]; then
    SRCDIR=$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd) || SRCDIR=.
fi

PORT_C="$SRCDIR/wolfcrypt/src/wc_port.c"
if [ ! -f "$PORT_C" ]; then
    echo "::error::check-sink-relro: source not found: $PORT_C" >&2
    exit 2
fi

CFLAGS="-DHAVE_CONFIG_H -I$BDIR -I$SRCDIR $XFLAGS"

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT

# -------------------------------------------------------------------------
# Skip unless this configuration actually selects the portable sink arm
# -------------------------------------------------------------------------
# Keep the preprocessor run separate from the grep: a missing or broken
# compiler must be an error, not a silent SKIP that leaves CI green while
# checking nothing -- unless the caller opted into --skip-on-compile-fail
# (e.g. a cross toolchain reusing a native build dir's config.h).
# shellcheck disable=SC2086
if ! echo | $CC $CFLAGS -E -dM -include wolfssl/wolfcrypt/wc_port.h - \
        >"$TMP/defs" 2>"$TMP/err"; then
    if [ "$SOFT_COMPILE_FAIL" = "1" ]; then
        echo "check-sink-relro: SKIP - cannot preprocess wc_port.h" \
             "($CC $XFLAGS)"
        sed 's/^/  /' "$TMP/err" | head -10
        exit 77
    fi
    echo "::error::check-sink-relro: cannot preprocess wc_port.h" \
         "($CC $XFLAGS)"
    sed 's/^/  /' "$TMP/err" | head -10
    exit 2
fi

if ! grep -q '^#define WC_BARRIER_DATA_USES_SINK' "$TMP/defs"; then
    echo "check-sink-relro: SKIP - portable sink arm not selected," \
         "no pointer to check ($CC $XFLAGS)"
    exit 77
fi

# -------------------------------------------------------------------------
# Check 1: the definition lands in .data.rel.ro
# -------------------------------------------------------------------------
# shellcheck disable=SC2086
if ! $CC $CFLAGS -fPIC -fvisibility=hidden -DBUILDING_WOLFSSL \
        -c "$PORT_C" -o "$TMP/wc_port.o" 2>"$TMP/err"; then
    if [ "$SOFT_COMPILE_FAIL" = "1" ]; then
        echo "check-sink-relro: SKIP - wc_port.c failed to compile" \
             "($CC $XFLAGS)"
        sed 's/^/  /' "$TMP/err" | head -10
        exit 77
    fi
    echo "::error::check-sink-relro: wc_port.c failed to compile" \
         "($CC $XFLAGS)"
    sed 's/^/  /' "$TMP/err" | head -10
    exit 2
fi

if ! $OD -t "$TMP/wc_port.o" >"$TMP/syms" 2>/dev/null; then
    echo "check-sink-relro: SKIP - $OD cannot read the object format"
    exit 77
fi

fmt=$($OD -f "$TMP/wc_port.o" 2>/dev/null \
      | sed -n 's/.*file format \(.*\)/\1/p' | head -1)

# -------------------------------------------------------------------------
# PE/COFF (MinGW, MSVC): "const" data goes to .rdata, which the image marks
# READONLY.  This is the arm every non-__GNUC__ Windows build takes, so it is
# worth checking even though PE has no RELRO.  The cross-module path is the
# toolchain's business rather than wolfSSL's -- an imported data symbol
# resolves through the .idata IAT slot, which is READONLY as well -- so the
# only thing that can regress here is the qualifier on the definition.
# -------------------------------------------------------------------------
case "$fmt" in
elf*)
    ;;
pe-*|coff-*|pei-*)
    # objdump -t prints "(sec N)" for COFF instead of the section name, and
    # i386 decorates the symbol with a leading underscore.
    idx=$(sed -n "s/.*(sec *\([0-9]*\)).*[[:space:]_]bd_sink_ptr\$/\1/p" \
          "$TMP/syms" | head -1)

    if [ -z "$idx" ]; then
        echo "::error::check-sink-relro: bd_sink_ptr not found in" \
             "wc_port.o -- WC_BARRIER_DATA_USES_SINK is defined but the" \
             "pointer is missing"
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
            echo "check-sink-relro: PASS - bd_sink_ptr is in a read-only" \
                 "image section ($CC $XFLAGS)"
            exit 0
            ;;
        "")
            echo "check-sink-relro: SKIP - cannot resolve the PE section" \
                 "for bd_sink_ptr ($CC $XFLAGS)"
            exit 77
            ;;
        *)
            printf '  %-24s %s\n' "definition section" \
                   "FAIL   (${pesec% RW}, writable)"
            echo "::error::check-sink-relro: bd_sink_ptr is in" \
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

sec=$(sed -n 's/.*[[:space:]]\(\.[A-Za-z0-9_.-]*\)[[:space:]].*[[:space:]]bd_sink_ptr$/\1/p' \
      "$TMP/syms" | head -1)

if [ -z "$sec" ]; then
    echo "::error::check-sink-relro: bd_sink_ptr not found in wc_port.o" \
         "-- WC_BARRIER_DATA_USES_SINK is defined but the pointer is missing"
    exit 2
fi

case "$sec" in
    .data.rel.ro*|.rodata*)
        # .rodata is strictly more read-only than .data.rel.ro (no
        # relocation window at all); either satisfies "not writable at
        # runtime", which is the actual property under test.
        printf '  %-24s %s\n' "definition section" "ok     ($sec)"
        echo "check-sink-relro: PASS - bd_sink_ptr compiles into" \
             "'$sec' ($CC $XFLAGS)"
        exit 0
        ;;
    *)
        printf '  %-24s %s\n' "definition section" "FAIL   ($sec)"
        echo "::error::check-sink-relro: bd_sink_ptr is in '$sec'," \
             "expected .data.rel.ro or .rodata -- it is writable at" \
             "runtime. Did the 'const' qualifier get dropped, or a section" \
             "attribute get forced onto it? ($CC $XFLAGS)"
        exit 1
        ;;
esac
