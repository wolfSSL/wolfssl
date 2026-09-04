#!/bin/sh
#
# check-barrier-arms.sh
# Assert the barrier macros resolve to the intended #elif arm.
# Usage: check-barrier-arms.sh [--builddir DIR] [--srcdir DIR] [CC]
#
#   --builddir DIR   configured build dir, for config.h (default: .)
#   --srcdir   DIR   wolfSSL source root, for headers (default: inferred)

BDIR=.
SRCDIR=

while [ $# -gt 0 ]; do
    case $1 in
        --builddir) BDIR=$2;   shift 2 ;;
        --srcdir)   SRCDIR=$2; shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done

if [ -z "$SRCDIR" ]; then
    SRCDIR=$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd) || SRCDIR=.
fi

CC=${1:-gcc}
rc=0

# $1=label $2=flags $3=macro $4=want
check_arm() {
    _label=$1
    _flags=$2
    _macro=$3
    _want=$4
    _err=$(mktemp) || { echo "::error::check-barrier-arms: mktemp failed"; rc=1; return; }
    # shellcheck disable=SC2086
    _pp=$(echo | $CC $_flags -I"$BDIR" -I"$SRCDIR" -DHAVE_CONFIG_H -E -dM \
          -include wolfssl/wolfcrypt/wc_port.h - 2>"$_err")
    _pprc=$?
    # No output at all -> real failure. Nonzero exit with output -> likely
    # recovered from an unrelated missing header later in the file (e.g.
    # simulated MSVC with no real Windows SDK/CRT); judge on the macro.
    if [ "$_pprc" -ne 0 ] && [ -z "$_pp" ]; then
        printf '  %-32s %-18s PREPROCESS FAILED\n' "$_label" "$_macro"
        sed 's/^/     /' "$_err" | head -5
        echo "::error::check-barrier-arms: cannot preprocess wc_port.h for" \
             "$_label ($CC $_flags)"
        rc=1
        rm -f "$_err"
        return
    fi
    rm -f "$_err"
    _def=$(printf '%s\n' "$_pp" | grep -E "^#define ${_macro}[( ]" | head -1)
    case "$_def" in
        *"$_want"*)
            printf '  %-32s %-18s ok\n' "$_label" "$_macro"
            ;;
        "")
            printf '  %-32s %-18s UNDEFINED\n' "$_label" "$_macro"
            echo "::error::check-barrier-arms: $_macro undefined for $_label"
            rc=1
            ;;
        *)
            printf '  %-32s %-18s WRONG ARM\n' "$_label" "$_macro"
            printf '     expected to contain: %s\n     got: %s\n' "$_want" "$_def"
            echo "::error::check-barrier-arms: $_macro took the wrong arm" \
                 "for $_label"
            rc=1
            ;;
    esac
}

# Same, but skip when $CC cannot build for the requested target.
# $1=label $2=flags $3=macro $4=want
check_arm_opt() {
    # shellcheck disable=SC2086
    if ! echo | $CC $2 -E - >/dev/null 2>&1; then
        printf '  %-32s %-18s skip (%s cannot target it)\n' "$1" "$3" "$CC"
        return 0
    fi
    check_arm "$1" "$2" "$3" "$4"
}

# GNU/clang inline-asm.
check_arm "default"                 ""                  WC_BARRIER_DATA  '"r"'
check_arm "default"                 ""                  WC_BARRIER \
          '__asm__ __volatile__("" ::: "memory")'
check_arm "-std=c89"                "-std=c89"          WC_BARRIER_DATA  '"r"'
check_arm "-std=c99"                "-std=c99"          WC_BARRIER_DATA  '"r"'

# Portable sink.
check_arm "WOLFSSL_NO_ASM"          "-DWOLFSSL_NO_ASM"  WC_BARRIER_DATA \
          'wc_bd_sink'

# Portable sink reached by a non-__GNUC__ compiler without WOLFSSL_NO_ASM.
# We simulate MSVC with clang since gcc/clang define __GNUC__ even with -D__KEIL__.
check_arm_opt "simulated MSVC (clang target)" \
          "--target=x86_64-pc-windows-msvc -fms-compatibility" \
          WC_BARRIER_DATA 'wc_bd_sink'

# Check derivation separately.
check_arm "simulated KEIL -std=c99" "-D__KEIL__ -std=c99" \
          XASM_VOLATILE '__asm '
check_arm "simulated IAR -std=c99"  "-D__IAR_SYSTEMS_ICC__ -std=c99" \
          XASM_VOLATILE 'asm volatile'
check_arm "default"                 ""                    XASM_VOLATILE_MB \
          'XASM_VOLATILE(a ::: "memory")'

# Both KEIL's __asm() and IAR's asm() accept a GNU-style clobber list (see
# the extended-asm blocks in sp_cortexm.c, which are compiled for both), so
# XASM_VOLATILE_MB keeps the "memory" clobber for both.
check_arm "simulated KEIL -std=c99" "-D__KEIL__ -std=c99" \
          XASM_VOLATILE_MB 'XASM_VOLATILE_MB(a) XASM_VOLATILE(a ::: "memory")'
check_arm "simulated IAR -std=c99"  "-D__IAR_SYSTEMS_ICC__ -std=c99" \
          XASM_VOLATILE_MB 'XASM_VOLATILE_MB(a) XASM_VOLATILE(a ::: "memory")'

if [ "$rc" -eq 0 ]; then
    echo "check-barrier-arms: PASS"
else
    echo "check-barrier-arms: FAIL"
fi
exit "$rc"
