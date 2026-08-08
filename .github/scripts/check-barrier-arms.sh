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

# $1 = human label, $2 = extra compiler flags, $3 = macro, $4 = required text
check_arm() {
    _label=$1
    _flags=$2
    _macro=$3
    _want=$4
    # shellcheck disable=SC2086
    _def=$(echo | $CC $_flags -I"$BDIR" -I"$SRCDIR" -DHAVE_CONFIG_H -E -dM \
           -include wolfssl/wolfcrypt/wc_port.h - 2>/dev/null \
           | grep -E "^#define ${_macro}[( ]" | head -1)
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

# GNU/clang: inline-asm form.
check_arm "default"                 ""                  WC_BARRIER_DATA  '"r"'
check_arm "default"                 ""                  WC_BARRIER       'memory'
check_arm "-std=c89"                "-std=c89"          WC_BARRIER_DATA  '"r"'
check_arm "-std=c99"                "-std=c99"          WC_BARRIER_DATA  '"r"'

# No GNU inline asm: portable sink.
check_arm "WOLFSSL_NO_ASM"          "-DWOLFSSL_NO_ASM"  WC_BARRIER_DATA \
          'wc_bd_sink_ptr'

# IAR and Keil checked before WOLF_C99.
check_arm "simulated KEIL -std=c99" "-D__KEIL__ -std=c99" \
          XASM_VOLATILE_MB '__asm '
check_arm "simulated IAR -std=c99"  "-D__IAR_SYSTEMS_ICC__ -std=c99" \
          XASM_VOLATILE_MB 'asm volatile'

if [ "$rc" -eq 0 ]; then
    echo "check-barrier-arms: PASS"
else
    echo "check-barrier-arms: FAIL"
fi
exit "$rc"
