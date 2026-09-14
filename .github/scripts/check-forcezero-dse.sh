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
#                    Exit 77 (skip) instead of 2 on compile failure, treating
#                    it as an unsupported config rather than a regression.
#
# Positional:
#   CC        compiler to use (default: gcc; must be given explicitly if
#             any CFLAGS follow -- a leading CFLAGS with no CC is parsed
#             as an unknown option)
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
LINK=
SOFT_COMPILE_FAIL=

# shellcheck source=ci-probe-common.sh
. "$(dirname "$0")/ci-probe-common.sh"

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
[ $# -gt 0 ] || set -- -O2
XFLAGS="$*"

# Missing tool is a hard error, not a SKIP.
command -v "$OD" >/dev/null 2>&1 || {
    echo "::error::check-forcezero-dse: objdump '$OD' not found" >&2
    exit 2
}

# Check for binutils >= 2.33 --disassemble=SYMBOL support.
"$OD" --disassemble=x --help >/dev/null 2>&1 || {
    echo "check-forcezero-dse: SKIP - $OD does not support" \
         "--disassemble=SYMBOL (needs binutils >= 2.33)"
    exit 77
}

infer_srcdir "$0"

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
    # Link against static lib, not individual .c files, to handle TUs correctly.
    LIBWOLFSSL="$BDIR/src/.libs/libwolfssl.a"
    if [ ! -f "$LIBWOLFSSL" ]; then
        echo "::error::check-forcezero-dse: --link requires a built" \
             "$LIBWOLFSSL (run make first)" >&2
        exit 2
    fi
    # Quote paths to handle spaces.
    compile_rc=0
    # shellcheck disable=SC2086
    $CC "$@" -DHAVE_CONFIG_H -I"$BDIR" -I"$SRCDIR" "$PROBE" "$LIBWOLFSSL" \
        -o "$OUT" 2>"$TMP/err" || compile_rc=$?
else
    OUT="$TMP/dse_probe.o"
    compile_rc=0
    # shellcheck disable=SC2086
    $CC "$@" -DHAVE_CONFIG_H -I"$BDIR" -I"$SRCDIR" -c "$PROBE" -o "$OUT" \
        2>"$TMP/err" || compile_rc=$?
fi

report_compile_rc "$compile_rc" "probe failed to compile ($CC $XFLAGS)" \
        check-forcezero-dse

# -------------------------------------------------------------------------
# Count non-barrier instructions in a symbol's disassembly
# -------------------------------------------------------------------------
# Exclude fences and NOPs (including multi-byte) to avoid skewing DSE count.
# Skip slim-LTO objects.
NOP_FENCE_EXCLUDE='lock |mfence|lfence|sfence|hwsync|lwsync|(^|[^a-z])(dmb|isb|dsb|sync|fence)( |$)|(^|[^a-z])nop[lqw]?( |$)'

count_insns() {
    _want=$1
    _sym=$_want
    _asm=$($OD -d --no-show-raw-insn --disassemble="$_sym" "$OUT" 2>"$TMP/od_err") \
        || _asm=
    # Filter to instruction lines only.
    _c=$(printf '%s\n' "$_asm" | tr '\t' ' ' | grep -E '^ *[0-9a-f]+:' \
         | grep -viE "$NOP_FENCE_EXCLUDE" \
         | grep -c .) || _c=0
    if [ "$_c" -eq 0 ]; then
        # PPC64 ELFv1 dot-symbol retry. Use separate stderr.
        _sym=".$_want"
        _asm=$($OD -d --no-show-raw-insn --disassemble="$_sym" "$OUT" \
               2>"$TMP/od_err2") || _asm=
        _c=$(printf '%s\n' "$_asm" | tr '\t' ' ' | grep -E '^ *[0-9a-f]+:' \
             | grep -viE "$NOP_FENCE_EXCLUDE" \
             | grep -c .) || _c=0
        if [ "$_c" -eq 0 ]; then
            if ! $OD -h "$OUT" 2>/dev/null | awk \
                    '$2 ~ /^\.text/ && $3 !~ /^0+$/ { f=1 } END { exit !f }'
            then
                echo "check-forcezero-dse: SKIP - no machine code in object" \
                     "(LTO without -ffat-lto-objects?) ($CC $XFLAGS)" >&2
                return 77
            fi
            echo "::error::check-forcezero-dse: objdump failed or symbol" \
                 "$_want not found (0 instructions, tried '.$_want' too)" >&2
            sed 's/^/  /' "$TMP/od_err" >&2
            sed 's/^/  /' "$TMP/od_err2" >&2
            return 2
        fi
    fi
    echo "$_c"
}

# -------------------------------------------------------------------------
# Discover probe pairs from the object file
# -------------------------------------------------------------------------
$OD -t "$OUT" >"$TMP/syms" 2>/dev/null || :
cases=$(sed -n 's/.*[[:space:]]\(dse_probe_[A-Za-z0-9_]*\)_wipe$/\1/p' "$TMP/syms" | sort -u)

if [ -z "$cases" ]; then
    if grep -q '[[:space:]]dse_probe_not_applicable$' "$TMP/syms"; then
        echo "check-forcezero-dse: SKIP - probe not applicable" \
             "(WOLFSSL_NO_FORCE_ZERO or NO_INLINE) ($CC $XFLAGS)"
        exit 77
    fi
    if ! [ -s "$TMP/syms" ]; then
        # No symbol table. Unsupported toolchain, not a DSE regression.
        echo "check-forcezero-dse: SKIP - $OD cannot read symbols from" \
             "this object format ($CC $XFLAGS)"
        exit 77
    fi
    if grep -q '__gnu_lto_slim$' "$TMP/syms"; then
        # GCC slim LTO: functions are GIMPLE bytecode, no real symbols. Not testable.
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

n=$(printf '%s\n' "$cases" | grep -c .) || n=0
if [ "$fail" -eq 0 ]; then
    echo "check-forcezero-dse: PASS - $n/$n cases wiped ($CC $XFLAGS)"
    exit 0
fi
echo "check-forcezero-dse: FAIL - $fail/$n wipes eliminated ($CC $XFLAGS)"
exit 1
