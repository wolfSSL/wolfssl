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

# Work out which digest the in core integrity HMAC uses in this fips_test.c,
# so the reported hash can be checked before it is written: HMAC-SHA-256 (64
# hex) up to FIPS v6.0.0, HMAC-SHA-384 (96 hex) for v5.3+ NO_SHA256 builds and
# HMAC-SHA-512 (128 hex) from v7.0.0 on. The length of the current verifyCore
# literal is authoritative; v7 enforces it with a static assert.
VCCOUNT=$(grep -c '^".*";' wolfcrypt/src/fips_test.c)
if test "$VCCOUNT" -ne 1
then
    echo "fips-hash: expected one verifyCore line in fips_test.c, found $VCCOUNT"
    exit 1
fi
VCHEX=$(sed -n 's/^"\([0-9A-Fa-f]*\)";.*$/\1/p' wolfcrypt/src/fips_test.c)
HEXLEN=${#VCHEX}

case "$HEXLEN" in
    64)  ALG=SHA256 ;;
    96)  ALG=SHA384 ;;
    128) ALG=SHA512 ;;
    *)
        # Placeholder of unknown length: fall back to an HMAC type named
        # directly in the source (pre v7 trees hard code WC_SHA256).
        if grep -q 'wc_HmacSetKey_fips(&hmac, *WC_SHA256' \
                wolfcrypt/src/fips_test.c
        then
            ALG=SHA256
            HEXLEN=64
        else
            echo "fips-hash: cannot determine in core digest" \
                 "(verifyCore is $HEXLEN hex)"
            exit 1
        fi
        ;;
esac

if test "$ALG" != "SHA256" && \
   grep -q 'wc_HmacSetKey_fips(&hmac, *WC_SHA256' wolfcrypt/src/fips_test.c
then
    echo "fips-hash: warning: fips_test.c names WC_SHA256 but verifyCore" \
         "is $HEXLEN hex; using $ALG"
fi

echo "fips-hash: in core HMAC-$ALG ($HEXLEN hex)"

NEWHASH=$(./wolfcrypt/test/testwolfcrypt | \
          sed -n 's/^hash = \([0-9A-Fa-f][0-9A-Fa-f]*\).*$/\1/p' | head -1)
if test -z "$NEWHASH"
then
    # Only reported on a callback (e.g. in core failure); nothing to update.
    exit 0
fi

if test "${#NEWHASH}" -ne "$HEXLEN"
then
    echo "fips-hash: testwolfcrypt reported a ${#NEWHASH} hex hash but" \
         "fips_test.c expects HMAC-$ALG ($HEXLEN hex); not updating"
    exit 1
fi

cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak >wolfcrypt/src/fips_test.c

if ! grep -q "^\"${NEWHASH}\";" wolfcrypt/src/fips_test.c
then
    echo "fips-hash: failed to update verifyCore in fips_test.c"
    exit 1
fi
