#!/bin/sh
#
# check-sink-relro.sh
# Assert WC_BARRIER_DATA()'s portable sink pointer stays read-only at runtime.
#
# wc_bd_sink is an exported function called from inlined ForceZero() calls
# outside the library. Internally, wc_bd_sink() reads the static const
# pointer bd_sink_ptr through a volatile local. "const" on bd_sink_ptr keeps
# it in .data.rel.ro (PT_GNU_RELRO), out of attacker-writable memory; the
# volatile local read (not bd_sink_ptr itself) is what defeats devirtualization.
#
# ELF only. Skips cleanly on non-ELF or if the portable arm isn't selected.
#
# Usage:
#   check-sink-relro.sh [--builddir DIR] [--srcdir DIR] [--objdump OD]
#                       [--readelf RE] [CC] [CFLAGS...]
#
# Options (must come before positional arguments):
#   --builddir DIR   path to a configured build directory (default: .)
#   --srcdir   DIR   path to the wolfSSL source root (default: inferred from
#                    the script location, or the current directory)
#   --objdump  OD    objdump (or cross-objdump) to use (default: objdump)
#   --readelf  RE    readelf (or cross-readelf) to use (default: readelf)
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
#       --readelf aarch64-linux-gnu-readelf \
#       aarch64-linux-gnu-gcc -O2 -DWOLFSSL_NO_ASM

set -e

# -------------------------------------------------------------------------
# Option parsing
# -------------------------------------------------------------------------
BDIR=.
SRCDIR=
OD=objdump
RE=readelf

while [ $# -gt 0 ]; do
    case "$1" in
        --builddir) BDIR=$2;   shift 2 ;;
        --srcdir)   SRCDIR=$2; shift 2 ;;
        --objdump)  OD=$2;     shift 2 ;;
        --readelf)  RE=$2;     shift 2 ;;
        --) shift; break ;;
        -*) echo "check-sink-relro: unknown option '$1'" >&2; exit 2 ;;
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

PORT_C="$SRCDIR/wolfcrypt/src/wc_port.c"
MEM_C="$SRCDIR/wolfcrypt/src/memory.c"
for f in "$PORT_C" "$MEM_C"; do
    if [ ! -f "$f" ]; then
        echo "::error::check-sink-relro: source not found: $f" >&2
        exit 2
    fi
done

CFLAGS="-DHAVE_CONFIG_H -I$BDIR -I$SRCDIR $XFLAGS"

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT

# -------------------------------------------------------------------------
# Skip unless this configuration actually selects the portable sink arm
# -------------------------------------------------------------------------
# Keep the preprocessor run separate from the grep: a missing or broken
# compiler must be an error, not a silent SKIP that leaves CI green while
# checking nothing.
# shellcheck disable=SC2086
if ! echo | $CC $CFLAGS -E -dM -include wolfssl/wolfcrypt/wc_port.h - \
        >"$TMP/defs" 2>"$TMP/err"; then
    echo "::error::check-sink-relro: cannot preprocess wc_port.h" \
         "($CC $XFLAGS)"
    sed 's/^/  /' "$TMP/err" | head -10
    exit 2
fi

if ! grep -q '^#define WC_BARRIER_DATA_USES_SINK' "$TMP/defs"; then
    echo "check-sink-relro: SKIP - portable sink arm not selected," \
         "no pointer to check ($CC $XFLAGS)"
    exit 0
fi

# -------------------------------------------------------------------------
# Check 1: the definition lands in .data.rel.ro
# -------------------------------------------------------------------------
# shellcheck disable=SC2086
if ! $CC $CFLAGS -fPIC -fvisibility=hidden -DBUILDING_WOLFSSL \
        -c "$PORT_C" -o "$TMP/wc_port.o" 2>"$TMP/err"; then
    echo "::error::check-sink-relro: wc_port.c failed to compile" \
         "($CC $XFLAGS)"
    sed 's/^/  /' "$TMP/err" | head -10
    exit 2
fi

if ! $OD -t "$TMP/wc_port.o" >"$TMP/syms" 2>/dev/null; then
    echo "check-sink-relro: SKIP - $OD cannot read the object format"
    exit 0
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
            exit 0
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
    exit 0
    ;;
esac

sec=$(sed -n 's/.*[ \t]\(\.[A-Za-z0-9_.-]*\)[ \t].*[ \t]bd_sink_ptr$/\1/p' \
      "$TMP/syms" | head -1)

if [ -z "$sec" ]; then
    echo "::error::check-sink-relro: bd_sink_ptr not found in wc_port.o" \
         "-- WC_BARRIER_DATA_USES_SINK is defined but the pointer is missing"
    exit 2
fi

fail=0
case "$sec" in
    .data.rel.ro*)
        printf '  %-24s %s\n' "definition section" "ok     ($sec)"
        ;;
    *)
        printf '  %-24s %s\n' "definition section" "FAIL   ($sec)"
        echo "::error::check-sink-relro: bd_sink_ptr is in '$sec'," \
             "expected .data.rel.ro -- it is writable at runtime." \
             "Did the 'const' qualifier get dropped, or a section attribute" \
             "get forced onto it? ($CC $XFLAGS)"
        fail=$((fail + 1))
        ;;
esac



# -------------------------------------------------------------------------
if [ "$fail" -eq 0 ]; then
    echo "check-sink-relro: PASS - bd_sink_ptr is read-only after" \
         "relocation ($CC $XFLAGS)"
    exit 0
fi
echo "check-sink-relro: FAIL - $fail check(s) failed ($CC $XFLAGS)"
exit 1
