#!/bin/sh
# Audits the C# FIPS wrapper bindings (Native.cs) against a FIPS module.
#
# Usage: fips-bind-audit.sh <wolfssl-include-dir> [libwolfssl]
#   wolfssl-include-dir  directory containing wolfssl/wolfcrypt/fips.h
#   libwolfssl           optional shared library to check exports against
#
# Checks:
#   1. every libwolfssl DllImport in Native.cs names a *_fips entry point
#   2. every bound *_fips name is declared in fips.h or fips_test.h
#   3. (with a library) every bound *_fips name is exported by the library
# Exits 1 on any failure.
set -u
INC="${1:?usage: fips-bind-audit.sh <wolfssl-include-dir> [libwolfssl]}"
LIB="${2:-}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
NATIVE="$HERE/Native.cs"
FIPS_H="$INC/wolfssl/wolfcrypt/fips.h"
TEST_H="$INC/wolfssl/wolfcrypt/fips_test.h"
TMP="${TMPDIR:-/tmp}/fips-bind-audit.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
fail=0

[ -f "$FIPS_H" ] || { echo "error: $FIPS_H not found"; exit 1; }

# DllImport(WOLFSSL, EntryPoint = "name") entries; SIZES helper excluded
grep -oE 'DllImport\(WOLFSSL, EntryPoint = "[A-Za-z0-9_]+"' "$NATIVE" |
    sed -E 's/.*EntryPoint = "([A-Za-z0-9_]+)"/\1/' | sort -u > "$TMP/bound"
echo "bound libwolfssl entry points: $(wc -l < "$TMP/bound" | tr -d ' ')"

# 1. only _fips entry points
grep -v '_fips$' "$TMP/bound" > "$TMP/nonfips" || true
if [ -s "$TMP/nonfips" ]; then
    echo "FAIL: bindings that are not _fips entry points:"; sed 's/^/  /' "$TMP/nonfips"; fail=1
else
    echo "ok:   all bindings are _fips entry points"
fi

# 2. declared by the module headers
cat "$FIPS_H" "$TEST_H" 2>/dev/null | grep -oE '[A-Za-z0-9_]+_fips *\(' | sed -E 's/ *\($//' | sort -u > "$TMP/declared"
comm -23 "$TMP/bound" "$TMP/declared" > "$TMP/undeclared"
# wc_DhGeneratePublic_fips is v5.2.3+; report rather than fail when absent
grep -v '^wc_DhGeneratePublic_fips$' "$TMP/undeclared" > "$TMP/undeclared.hard" || true
if [ -s "$TMP/undeclared.hard" ]; then
    echo "FAIL: bound but not declared in fips.h / fips_test.h:"; sed 's/^/  /' "$TMP/undeclared.hard"; fail=1
else
    echo "ok:   all bindings declared by the module headers"
fi
grep -q '^wc_DhGeneratePublic_fips$' "$TMP/undeclared" &&
    echo "note: wc_DhGeneratePublic_fips not declared (pre-v5.2.3 module); wrapper reports it unsupported"

# 3. exported by the library
if [ -n "$LIB" ]; then
    if [ "$(uname -s)" = "Darwin" ]; then
        nm -gU "$LIB" | awk '{print $NF}' | sed 's/^_//' | sort -u > "$TMP/exported"
    else
        nm -D --defined-only "$LIB" | awk '{print $NF}' | sort -u > "$TMP/exported"
    fi
    comm -23 "$TMP/bound" "$TMP/exported" > "$TMP/missing"
    grep -v -e '^wolfCrypt_SetStatus_fips$' -e '^wc_DhGeneratePublic_fips$' "$TMP/missing" > "$TMP/missing.hard" || true
    if [ -s "$TMP/missing.hard" ]; then
        echo "FAIL: bound but not exported by $LIB:"; sed 's/^/  /' "$TMP/missing.hard"; fail=1
    else
        echo "ok:   all bindings exported by $(basename "$LIB")"
    fi
    grep -q '^wolfCrypt_SetStatus_fips$' "$TMP/missing" &&
        echo "note: wolfCrypt_SetStatus_fips not exported (not a HAVE_FORCE_FIPS_FAILURE build; used by tests only)"
fi

[ $fail -eq 0 ] && echo "PASS" || echo "FAIL"
exit $fail
