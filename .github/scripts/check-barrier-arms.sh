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

# shellcheck source=ci-probe-common.sh
. "$(dirname "$0")/ci-probe-common.sh"

while [ $# -gt 0 ]; do
    case $1 in
        --builddir) need_arg "$@"; BDIR=$2;   shift 2 ;;
        --srcdir)   need_arg "$@"; SRCDIR=$2; shift 2 ;;
        --) shift; break ;;
        -*) echo "check-barrier-arms: unknown option '$1'" >&2; exit 2 ;;
        *) break ;;
    esac
done

infer_srcdir "$0"

if [ ! -f "$SRCDIR/wolfssl/wolfcrypt/wc_port.h" ]; then
    echo "::error::check-barrier-arms: header not found:" \
         "$SRCDIR/wolfssl/wolfcrypt/wc_port.h" >&2
    exit 2
fi

CC=${1:-gcc}
rc=0

## Cache preprocess output for identical flags to save time.
_pp_cache_flags=
_pp_cache_seen=
_pp_cache_out=
_pp_cache_rc=

# $1=label $2=flags $3=macro $4=want
check_arm() {
    _label=$1
    _flags=$2
    _macro=$3
    _want=$4
    if [ "$_flags" = "$_pp_cache_flags" ] && [ -n "${_pp_cache_seen:-}" ]; then
        _pp=$_pp_cache_out
        _pprc=$_pp_cache_rc
    else
        _err=$(mktemp) || { echo "::error::check-barrier-arms: mktemp failed"; rc=1; return; }
        # shellcheck disable=SC2086
        _pp=$(echo | $CC $_flags -I"$BDIR" -I"$SRCDIR" -DHAVE_CONFIG_H -E -dM \
              -include wolfssl/wolfcrypt/wc_port.h - 2>"$_err")
        _pprc=$?
        # No output means real failure. Nonzero exit with output may be recoverable; judge on macro.
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
        _pp_cache_flags=$_flags
        _pp_cache_out=$_pp
        _pp_cache_rc=$_pprc
        _pp_cache_seen=1
    fi
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

# Like check_arm, but greps the fully macro-expanded call (via -E).
# $1=label $2=flags $3=snippet $4=want $5=not-want (optional)
check_expansion() {
    _label=$1; _flags=$2; _snippet=$3; _want=$4; _notwant=$5
    # shellcheck disable=SC2086
    _pp=$(echo "$_snippet" | $CC $_flags -I"$BDIR" -I"$SRCDIR" -DHAVE_CONFIG_H \
          -E -include wolfssl/wolfcrypt/wc_port.h - 2>/dev/null | tail -1)
    case "$_pp" in
        *"$_want"*)
            case "$_pp" in
                *"${_notwant:-@@never-matches@@}"*)
                    printf '  %-32s %-18s WRONG EXPANSION\n' "$_label" "expansion"
                    printf '     contains excluded: %s\n     got: %s\n' \
                           "$_notwant" "$_pp"
                    echo "::error::check-barrier-arms: wrong expansion for $_label"
                    rc=1
                    ;;
                *)
                    printf '  %-32s %-18s ok\n' "$_label" "expansion"
                    ;;
            esac
            ;;
        *)
            printf '  %-32s %-18s WRONG EXPANSION\n' "$_label" "expansion"
            printf '     expected to contain: %s\n     got: %s\n' "$_want" "$_pp"
            echo "::error::check-barrier-arms: wrong expansion for $_label"
            rc=1
            ;;
    esac
}

# GNU/clang inline-asm. Keep flags="" checks together to use cache.
check_arm "default"                 ""                  WC_BARRIER_DATA  '"r"'
check_arm "default"                 ""                  WC_BARRIER \
          '__asm__ __volatile__("" ::: "memory")'
check_arm "default"                 ""                    XASM_VOLATILE_MB \
          'XASM_VOLATILE(a ::: "memory")'
check_arm "-std=c89"                "-std=c89"          WC_BARRIER_DATA  '"r"'
check_arm "-std=c99"                "-std=c99"          WC_BARRIER_DATA  '"r"'

# Portable sink.
check_arm "WOLFSSL_NO_ASM"          "-DWOLFSSL_NO_ASM"  WC_BARRIER_DATA \
          'wc_BarrierDataSink'

# Portable sink for non-__GNUC__ compiler without WOLFSSL_NO_ASM.
# Simulate MSVC with clang since gcc/clang define __GNUC__.
check_arm_opt "simulated MSVC (clang target)" \
          "--target=x86_64-pc-windows-msvc -fms-compatibility -DWOLFSSL_NOT_WINDOWS_API" \
          WC_BARRIER_DATA 'wc_BarrierDataSink'

# Check derivation separately.
check_arm "simulated KEIL -std=c99" "-D__KEIL__ -std=c99" \
          XASM_VOLATILE '__asm '
check_arm "simulated IAR -std=c99"  "-D__IAR_SYSTEMS_ICC__ -std=c99" \
          XASM_VOLATILE 'asm volatile'

# Both KEIL and IAR accept a GNU-style clobber list.
# Check actual expanded keyword.
check_expansion "simulated KEIL -std=c99 (XASM_VOLATILE_MB)" \
          "-D__KEIL__ -std=c99" 'XASM_VOLATILE_MB("nop");' '__asm volatile'
check_expansion "simulated IAR -std=c99 (XASM_VOLATILE_MB)" \
          "-D__IAR_SYSTEMS_ICC__ -std=c99" 'XASM_VOLATILE_MB("nop");' \
          'asm volatile' '__asm'

# XASM_VOLATILE_NO_CLOBBER removes "memory" clobber for toolchains rejecting it.
check_arm "XASM_VOLATILE_NO_CLOBBER" "-DXASM_VOLATILE_NO_CLOBBER" \
          XASM_VOLATILE_MB 'XASM_VOLATILE_MB(a) XASM_VOLATILE(a)'

# MSVC/ARM64 compile check for XFENCE(). Requires clang-cl for simulation.
check_msvc_arm64_xfence() {
    _label="MSVC/ARM64 (clang-cl)"
    CLANG_CL=
    for _cand in clang-cl clang-cl-19 clang-cl-18 clang-cl-17 clang-cl-16; do
        command -v "$_cand" >/dev/null 2>&1 && { CLANG_CL=$_cand; break; }
    done
    if [ -z "$CLANG_CL" ]; then
        printf '  %-32s %-18s skip (no clang-cl on PATH)\n' "$_label" "XFENCE"
        return 0
    fi
    # Use plain clang to extract macro body, then compile with clang-cl.
    CLANG_PLAIN=$(echo "$CLANG_CL" | sed 's/-cl//')
    if ! command -v "$CLANG_PLAIN" >/dev/null 2>&1; then
        printf '  %-32s %-18s skip (no %s to preprocess with)\n' \
               "$_label" "XFENCE" "$CLANG_PLAIN"
        return 0
    fi

    # <intrin.h> needs a real Windows SDK/CRT. Skip if unusable.
    if ! echo '#include <intrin.h>' | $CLANG_PLAIN \
            --target=arm64-pc-windows-msvc -fms-compatibility \
            -U__clang__ -U__GNUC__ -E - >/dev/null 2>&1; then
        printf '  %-32s %-18s skip (<intrin.h> unusable without a Windows SDK)\n' \
               "$_label" "XFENCE"
        return 0
    fi

    _err=$(mktemp) || { echo "::error::check-barrier-arms: mktemp failed"; rc=1; return; }
    # shellcheck disable=SC2086
    _pp=$($CLANG_PLAIN --target=arm64-pc-windows-msvc -fms-compatibility \
          -DWOLFSSL_NOT_WINDOWS_API -DNO_WC_SSIZE_TYPE -DNO_STDATOMIC_H \
          -U__clang__ -U__GNUC__ -I"$BDIR" -I"$SRCDIR" -DHAVE_CONFIG_H \
          -E -dM -include wolfssl/wolfcrypt/wc_port.h - </dev/null 2>"$_err")
    _pprc=$?
    _def=$(printf '%s\n' "$_pp" | grep -E '^#define XFENCE\(\)' | head -1)

    # Dump diagnostic on preprocess failure.
    if [ "$_pprc" -ne 0 ] && [ -z "$_pp" ]; then
        printf '  %-32s %-18s PREPROCESS FAILED\n' "$_label" "XFENCE"
        sed 's/^/     /' "$_err" | head -5
        echo "::error::check-barrier-arms: cannot preprocess wc_port.h for" \
             "$_label ($CLANG_PLAIN)"
        rc=1
        rm -f "$_err"
        return
    fi
    rm -f "$_err"

    case "$_def" in
        *_ReadWriteBarrier*__isb*_ReadWriteBarrier*)
            _body=${_def#*XFENCE() }
            _tmp_dir=$(mktemp -d) || {
                echo "::error::check-barrier-arms: mktemp failed"; rc=1; return; }
            _tmp_c="$_tmp_dir/xfence.c"
            {
                echo '#include <intrin0.h>'
                echo '#include <arm64intr.h>'
                echo 'void wc_check_barrier_arms_xfence(void) {'
                echo "    $_body;"
                echo '}'
            } > "$_tmp_c"
            _obj="$_tmp_dir/xfence.obj"
            _cerr="$_tmp_dir/err"
            if $CLANG_CL --target=arm64-pc-windows-msvc -fms-compatibility \
                    -c "$_tmp_c" -Fo"$_obj" >"$_cerr" 2>&1; then
                printf '  %-32s %-18s ok (compiled)\n' "$_label" "XFENCE"
            else
                printf '  %-32s %-18s FAIL (does not compile)\n' "$_label" "XFENCE"
                sed 's/^/     /' "$_cerr"
                echo "::error::check-barrier-arms: XFENCE() body for" \
                     "MSVC/ARM64 does not compile"
                rc=1
            fi
            rm -rf "$_tmp_dir"
            ;;
        "")
            printf '  %-32s %-18s UNDEFINED\n' "$_label" "XFENCE"
            echo "::error::check-barrier-arms: XFENCE undefined for" \
                 "simulated MSVC/ARM64"
            rc=1
            ;;
        *)
            printf '  %-32s %-18s WRONG ARM\n' "$_label" "XFENCE"
            printf '     got: %s\n' "$_def"
            echo "::error::check-barrier-arms: XFENCE took the wrong arm" \
                 "for simulated MSVC/ARM64"
            rc=1
            ;;
    esac
}
check_msvc_arm64_xfence

if [ "$rc" -eq 0 ]; then
    echo "check-barrier-arms: PASS"
else
    echo "check-barrier-arms: FAIL"
fi
exit "$rc"
