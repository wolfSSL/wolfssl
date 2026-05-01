#!/bin/sh

if test ! -x ./wolfcrypt/test/testwolfcrypt
then
    echo "fips-hash: wolfCrypt test missing"
    exit 1
fi

if test ! -s ./wolfcrypt/src/fips_test.c
then
    echo "fips-hash: fips_test.c missing"
    exit 1
fi

OUT=$(./wolfcrypt/test/testwolfcrypt | sed -n 's/hash = \(.*\)/\1/p')
# FIPS v7.0.0+ uses HMAC-SHA-512 (128 hex chars); older FIPS versions
# use HMAC-SHA-256 (64 hex chars).  Take the whole captured hash; the
# static_assert on sizeof(verifyCore) guards against wrong length at
# compile time after this script runs.
NEWHASH=$(echo "$OUT" | head -n1 | tr -d '[:space:]')
if test -n "$NEWHASH"
then
    cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
    sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak >wolfcrypt/src/fips_test.c
fi
