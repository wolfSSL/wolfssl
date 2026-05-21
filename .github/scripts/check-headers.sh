#!/usr/bin/env bash
#
# check-headers.sh
#
# Verifies that every public-facing wolfSSL header compiles standalone
# from a fresh consumer's perspective:
#
#   #include <wolfssl/options.h>
#   #include <wolfssl/...the header...>
#   int main(void) { return 0; }
#
# Catches the common breakage where a header silently relies on a
# transitive include from an earlier `.c` file and stops compiling
# when downstream code includes it first.
#
# Requires:
#   * ./configure has been run (so wolfssl/options.h exists).
#   * gcc and standard build env.
#
# Usage:
#   .github/scripts/check-headers.sh           # scan default header set
#   .github/scripts/check-headers.sh <files>   # scan a specific list

set -u

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 2

if [ ! -f wolfssl/options.h ]; then
    echo "::error::wolfssl/options.h not found - run ./configure first" >&2
    exit 2
fi

CC="${CC:-gcc}"
GHA="${GITHUB_ACTIONS:-}"

emit() {
    local file="$1" msg="$2"
    if [ -n "$GHA" ]; then
        printf '::error file=%s,line=1,title=header-self-include::%s\n' "$file" "$msg"
    else
        printf '%s: %s\n' "$file" "$msg"
    fi
}

# Default scope: public wolfssl headers excluding vendor/port subdirs and
# files that are intentionally not standalone-includable.
if [ "$#" -gt 0 ]; then
    HEADERS=("$@")
else
    # Exclusions:
    #  * generated / private / test-data headers.
    #  * wolfcrypt math backends (tfm vs sp_int are mutually exclusive).
    #  * port/* headers whose first-line vendor SDK include can't be
    #    satisfied in a generic CI environment (mcapi.h, kcapi.h,
    #    em_device.h, fsl_dcp.h, hw/inout.h, etc.) or that reference
    #    vendor-only types. Fix the offending header's vendor #include
    #    with an #ifdef guard and drop the exclusion in a follow-up.
    mapfile -t HEADERS < <(
        git ls-files 'wolfssl/*.h' 'wolfssl/wolfcrypt/*.h' \
                     'wolfssl/wolfcrypt/port/**/*.h' 'wolfssl/openssl/*.h' \
        | grep -vE '^wolfssl/(options|internal|certs_test|certs_test_sm|debug-trace-error-codes|debug-untrace-error-codes)\.h$' \
        | grep -vE '^wolfssl/wolfcrypt/(fips_test|selftest|tfm)\.h$' \
        | grep -vE '^wolfssl/wolfcrypt/port/aria/aria-crypt(ocb)?\.h$' \
        | grep -vE '^wolfssl/wolfcrypt/port/autosar/(CryIf|Crypto)\.h$' \
        | grep -vE '^wolfssl/wolfcrypt/port/caam/(caam_driver|caam_qnx|wolfcaam_hash)\.h$' \
        | grep -vE '^wolfssl/wolfcrypt/port/kcapi/' \
        | grep -vE '^wolfssl/wolfcrypt/port/nxp/(dcp_port|se050_port)\.h$' \
        | grep -vE '^wolfssl/wolfcrypt/port/Renesas/(renesas_fspsm_internal|renesas-rx64-hw-crypt|renesas-tsip-crypt|renesas_tsip_internal)\.h$' \
        | grep -vE '^wolfssl/wolfcrypt/port/silabs/silabs_aes\.h$'
    )
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

FAIL=0
PASS=0
for h in "${HEADERS[@]}"; do
    [ -f "$h" ] || continue
    cat > "$TMPDIR/test.c" <<EOF
#include <wolfssl/options.h>
#include <$h>
int main(void) { return 0; }
EOF
    if out="$("$CC" -I. -c -o /dev/null "$TMPDIR/test.c" 2>&1)"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        first_err="$(printf '%s' "$out" | grep -E 'error:' | head -1 | sed 's/.*error: //')"
        emit "$h" "header does not compile standalone: ${first_err:-(see build log)}"
        if [ -z "$GHA" ]; then
            printf '%s\n' "$out" | head -8 | sed 's/^/  /'
        fi
    fi
done

echo "check-headers: $PASS pass, $FAIL fail"
[ "$FAIL" -eq 0 ]
