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
TESTOUT=$(./wolfcrypt/test/testwolfcrypt 2>&1)
TESTRC=$?

# Confirm testwolfcrypt actually ran before interpreting its output.  The -x
# test above does not establish that: ./wolfcrypt/test/testwolfcrypt is a
# libtool WRAPPER SCRIPT, so it exists and is executable even when
# .libs/testwolfcrypt was never linked -- a --enable-linuxkm build never
# produces one.  The wrapper then exits having printed only its own error, and
# treating that as "no hash to apply" would leave the stale hash in place while
# reporting success.  Every FIPS API call in the resulting module would return
# IN_CORE_FIPS_E (-203), which is the exact failure this script exists to
# prevent, so a run that did not happen must never look like a clean one.
# A run that HAPPENED prints one of two things.  If the in-core hash already
# matches, wolfCrypt_Init() succeeds and main() reaches the version banner.  If
# it does NOT match -- which is the whole reason this script exists -- the
# power-on self test fails with -203 and testwolfcrypt EXITS BEFORE the banner,
# having printed the replacement hash and nothing else of interest.  Requiring
# the banner alone therefore rejected exactly the case the script is for: a
# fresh build whose module content changed (adding --enable-wolfentropy is
# enough) could never be patched, and every combo needing a new hash failed at
# this step.  A libtool wrapper whose .libs binary was never linked still
# prints NEITHER, so accepting the hash line costs none of the protection.
case "$TESTOUT" in
    *"wolfSSL version"*)
        ;;
    *hash\ =\ [0-9A-Fa-f]*)
        # main() in wolfcrypt/test/test.c maps every result to exit 0 or 1, so
        # any other status means the run died before main() returned.
        if test "$TESTRC" -ne 0 && test "$TESTRC" -ne 1
        then
            echo "fips-hash: testwolfcrypt printed a hash but exited $TESTRC," >&2
            echo "fips-hash: so it died before main() returned." >&2
            echo "fips-hash: refusing to trust that hash; fips_test.c NOT updated." >&2
            printf '%s\n' "$TESTOUT" >&2
            exit 1
        fi
        ;;
    *)
        echo "fips-hash: testwolfcrypt did not run; fips_test.c NOT updated." >&2
        echo "fips-hash: the module would fail with -203." >&2
        echo "fips-hash: a --enable-linuxkm build has no testwolfcrypt -- the" >&2
        echo "fips-hash: kernel Makefile sets WOLFCRYPT_FIPS_CORE_HASH_VALUE" >&2
        echo "fips-hash: itself, so this script is not the tool for it." >&2
        printf '%s\n' "$TESTOUT" >&2
        exit 1
        ;;
esac

NEWHASH=$(printf '%s\n' "$TESTOUT" | \
          sed -n 's/^hash = \([0-9A-Fa-f][0-9A-Fa-f]*\).*$/\1/p' | head -1)

# testwolfcrypt ran and printed no hash: it only reports one when the in-core
# check FAILS, so this is the already-correct case and there is nothing to do.
if test -z "$NEWHASH"
then
    echo "fips-hash: in-core hash already matches; fips_test.c unchanged."
    exit 0
fi

cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak >wolfcrypt/src/fips_test.c
