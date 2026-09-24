#!/bin/sh
# Audits the C# FIPS wrapper bindings (Native.cs) against a FIPS module.
#
# Usage: fips-bind-audit.sh <wolfssl-include-dir> [libwolfssl]
#   wolfssl-include-dir  directory containing wolfssl/wolfcrypt/fips.h
#   libwolfssl           optional shared library to check exports against
#
# Checks:
#   0. P/Invoke only in Native.cs, every libwolfssl DllImport has an explicit
#      EntryPoint, and NativeLibrary export lookups are on the allowlist
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
TMP="$(mktemp -d "${TMPDIR:-/tmp}/fips-bind-audit.XXXXXX")" || exit 1
trap 'rm -rf "$TMP"' EXIT
fail=0

[ -f "$FIPS_H" ] || { echo "error: $FIPS_H not found"; exit 1; }

# DllImport(WOLFSSL, EntryPoint = "name") entries; SIZES helper excluded
grep -oE 'DllImport\(WOLFSSL, EntryPoint = "[A-Za-z0-9_]+"' "$NATIVE" |
    sed -E 's/.*EntryPoint = "([A-Za-z0-9_]+)"/\1/' | sort -u > "$TMP/bound"
echo "bound libwolfssl entry points: $(wc -l < "$TMP/bound" | tr -d ' ')"

# 0. binding forms the text checks below would not see. Import attributes
#    are matched anywhere on a line (attribute lists, qualified names), and
#    each one must be complete on its line in one of the two allowed forms,
#    so a split or literal-library attribute is flagged. The runtime
#    reflection test in ModuleTests.cs is the authoritative check.
DIR="$HERE"
IMPORT='(DllImport|LibraryImport)(Attribute)?[[:space:]]*\('
outside=$(grep -lE "$IMPORT" "$DIR"/*.cs | grep -v '/Native.cs$' || true)
if [ -n "$outside" ]; then
    echo "FAIL: P/Invoke declared outside Native.cs:"; echo "$outside" | sed 's/^/  /'; fail=1
else
    echo "ok:   all P/Invoke declarations are in Native.cs"
fi
# every import attribute in Native.cs, whatever its library argument, must be
# the size helper or WOLFSSL with an explicit _fips EntryPoint
grep -nE "$IMPORT" "$NATIVE" > "$TMP/attrs"
n_imports=$(grep -oE "$IMPORT" "$NATIVE" | wc -l | tr -d ' ')
n_good=$(grep -oE '(^|[^A-Za-z0-9_.])DllImport\((SIZES, EntryPoint = "[A-Za-z0-9_]+"|WOLFSSL, EntryPoint = "[A-Za-z0-9_]+_fips")' "$NATIVE" | wc -l | tr -d ' ')
grep -vE '(^|[^A-Za-z0-9_.])DllImport\((SIZES, EntryPoint = "[A-Za-z0-9_]+"|WOLFSSL, EntryPoint = "[A-Za-z0-9_]+_fips")' "$TMP/attrs" > "$TMP/badattrs" || true
if [ -s "$TMP/badattrs" ] || [ "$n_imports" != "$n_good" ]; then
    echo "FAIL: import attributes that are not SIZES or WOLFSSL with a _fips EntryPoint ($n_good of $n_imports allowed):"
    sed 's/^/  /' "$TMP/badattrs"; fail=1
else
    echo "ok:   all $n_imports import attributes are SIZES or WOLFSSL with a _fips EntryPoint"
fi
# GetExport/TryGetExport allowlist, compared on the exact name argument:
#   Native.OS_SEED_EXPORT     wc_GenerateSeed, seed source pointer handed to the module
#   wolfCrypt_SetStatus_fips  forced-failure test hook
#   wolfCrypt_GetVersion_fips address only, to find the loaded library file
#   dladdr, GetModuleFileNameW OS calls that return a library's file path
grep -q 'OS_SEED_EXPORT = "wc_GenerateSeed"' "$NATIVE" || { echo "FAIL: OS_SEED_EXPORT is not wc_GenerateSeed"; fail=1; }
n_lookups=$(grep -oE 'GetExport[[:space:]]*\(' "$DIR"/*.cs | wc -l | tr -d ' ')
grep -hoE 'GetExport[[:space:]]*\([^,()]*(\([^()]*\))?[^,()]*,[[:space:]]*[^,)]+' "$DIR"/*.cs |
    sed -E 's/.*,[[:space:]]*//' > "$TMP/lookups"
unlisted=$(grep -vxE 'Native\.OS_SEED_EXPORT|"wolfCrypt_SetStatus_fips"|"wolfCrypt_GetVersion_fips"|"dladdr"|"GetModuleFileNameW"' "$TMP/lookups" || true)
if [ -n "$unlisted" ] || [ "$n_lookups" != "$(wc -l < "$TMP/lookups" | tr -d ' ')" ]; then
    echo "FAIL: export lookups outside the allowlist (or not parseable on one line):"
    echo "$unlisted" | sed 's/^/  /'; fail=1
else
    echo "ok:   all $n_lookups export lookups on the allowlist"
fi

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
