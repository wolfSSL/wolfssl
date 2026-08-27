#!/bin/sh
# compile.sh - compile-only guard for the TI C2000 (C28x, CHAR_BIT==16) port.
#
# Builds the wolfCrypt subset that compiles under CHAR_BIT==16 with the TI cl2000
# code generation tools, using IDE/C2000/user_settings.h.  No linking, no
# C2000Ware, no hardware: this only catches compile regressions in the
# CHAR_BIT != 8 gated code paths (SHA-2/3/SHAKE, ML-DSA-87 verify, SP-ECC).
#
# Usage:
#   CGT_ROOT=/path/to/ti-cgt-c2000_xx.y.z IDE/C2000/compile.sh
#
# CGT_ROOT must point at a TI C2000 codegen install (the dir containing
# bin/cl2000).  The CGT is a free download from TI; in CI it is fetched/cached
# by .github/workflows/ti-c2000-compile.yml.

set -e

: "${CGT_ROOT:?set CGT_ROOT to the ti-cgt-c2000 install (dir with bin/cl2000)}"

# Repo root = two levels up from this script.
SELF_DIR=$(cd "$(dirname "$0")" && pwd)
WOLFROOT=$(cd "$SELF_DIR/../.." && pwd)
CL="$CGT_ROOT/bin/cl2000"

if [ ! -x "$CL" ]; then
    echo "ERROR: cl2000 not found/executable at $CL" >&2
    exit 2
fi

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

INCS="-I$CGT_ROOT/include -I$WOLFROOT -I$SELF_DIR"
CFLAGS="-v28 --abi=eabi --float_support=fpu32 --tmu_support=tmu1 -O2 \
  --define=WOLFSSL_USER_SETTINGS --display_error_number --diag_warning=225"

# wolfCrypt sources to compile-guard under CHAR_BIT==16.  This is the set that
# carries the CHAR_BIT != 8 gated fixes (plus their direct deps) - the
# regression surface for this port.  hash.c (an unmodified dispatch wrapper) is
# intentionally omitted: its wc_OidGetHash() OID switch needs the fuller ASN/OID
# config of a real build to avoid a 16-bit-int case-label fold, and it is
# covered by the on-target example build, not by this minimal guard.
SRCS="error wc_port memory logging misc coding \
  sha sha256 sha512 sha3 wc_mldsa random ecc sp_int sp_c32 \
  aes cmac chacha poly1305 \
  curve25519 ed25519 fe_operations ge_operations \
  curve448 ed448 fe_448 ge_448"

rc=0
for s in $SRCS; do
    printf 'CC  %s.c ... ' "$s"
    if "$CL" $CFLAGS $INCS --compile_only --skip_assembler \
            --asm_directory="$OUT" --obj_directory="$OUT" \
            "$WOLFROOT/wolfcrypt/src/$s.c" > "$OUT/$s.log" 2>&1; then
        echo "ok"
    else
        echo "FAIL"
        cat "$OUT/$s.log"
        rc=1
    fi
done

if [ "$rc" -eq 0 ]; then
    echo "TI C2000 compile-only guard: PASS"
else
    echo "TI C2000 compile-only guard: FAIL" >&2
fi
exit "$rc"
