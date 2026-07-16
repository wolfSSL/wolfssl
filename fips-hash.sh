#!/bin/sh

# This script executes the testwolfcrypt binary to report its calculated FIPS
# integrity hash, then it modifies the fips_test.c source code to update the
# expected integrity hash in source.
#
# See fips-hash-offline.sh for a version that calculates the expected FIPS
# integrity hash during the build process on the linked binary. This version is
# suitable for statically linked builds.

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

# Take the hash exactly as long as reported: the in core digest is SHA-256 (64
# hex) up to FIPS v6.0.0 and SHA-512 (128 hex) from v7.0.0 on.
NEWHASH=$(./wolfcrypt/test/testwolfcrypt | \
          sed -n 's/^hash = \([0-9A-Fa-f][0-9A-Fa-f]*\).*$/\1/p' | head -1)
if test -n "$NEWHASH"
then
    cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
    sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak >wolfcrypt/src/fips_test.c
fi
