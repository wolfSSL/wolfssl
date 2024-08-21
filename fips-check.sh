#!/usr/bin/env bash

# fips-check.sh
# This script checks the current revision of the code against the
# previous release of the FIPS code. While wolfSSL and wolfCrypt
# may be advancing, they must work correctly with the last tested
# copy of our FIPS approved code.
#
# This should check out all the approved flavors. The command line
# option selects the flavor. The keep option keeps the output
# directory.

# These variables may be overridden on the command line.
MAKE="${MAKE:-make}"
GIT="${GIT:-git -c advice.detachedHead=false}"
TEST_DIR="${TEST_DIR:-XXX-fips-test}"
FLAVOR="${FLAVOR:-linux}"
KEEP="${KEEP:-no}"
MAKECHECK=${MAKECHECK:-yes}
FIPS_REPO="${FIPS_REPO:-git@github.com:wolfssl/fips.git}"

Usage() {
    cat <<usageText
Usage: $0 [flavor] [keep]
Flavor is one of:
    linuxv2 (FIPSv2, use for Win10)
    fipsv2-OE-ready (ready FIPSv2)
    solaris
    netbsd-selftest
    marvell-linux-selftest
    linuxv5 (current FIPS 140-3)
    fips-ready (ready FIPS 140-3)
    fips-dev (dev FIPS 140-3)
    wolfrand
    wolfentropy
Keep (default off) retains the temp dir $TEST_DIR for inspection.

Example:
    $0 windows keep
usageText
}

while [ "$1" ]; do
  if [ "$1" = 'keep' ]; then KEEP='yes';
  elif [ "$1" = 'nomakecheck' ]; then MAKECHECK='no';
  else FLAVOR="$1"; fi
  shift
done

case "$FLAVOR" in
linuxv2|fipsv2-OE-ready|solaris)
  FIPS_OPTION='v2'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:WCv4-stable'
    'wolfcrypt/src/fips_test.c:WCv4-stable'
    'wolfcrypt/src/wolfcrypt_first.c:WCv4-stable'
    'wolfcrypt/src/wolfcrypt_last.c:WCv4-stable'
    'wolfssl/wolfcrypt/fips.h:WCv4-stable'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:WCv4-stable'
    'wolfcrypt/src/aes_asm.asm:WCv4-stable'
    'wolfcrypt/src/aes_asm.S:WCv4-stable'
    'wolfcrypt/src/cmac.c:WCv4-stable'
    'wolfcrypt/src/des3.c:WCv4-stable'
    'wolfcrypt/src/dh.c:WCv4-stable'
    'wolfcrypt/src/ecc.c:WCv4-stable'
    'wolfcrypt/src/hmac.c:WCv4-stable'
    'wolfcrypt/src/random.c:WCv4-rng-stable'
    'wolfcrypt/src/rsa.c:WCv4-stable'
    'wolfcrypt/src/sha.c:WCv4-stable'
    'wolfcrypt/src/sha256.c:WCv4-stable'
    'wolfcrypt/src/sha3.c:WCv4-stable'
    'wolfcrypt/src/sha512.c:WCv4-stable'
    'wolfssl/wolfcrypt/aes.h:WCv4-stable'
    'wolfssl/wolfcrypt/cmac.h:WCv4-stable'
    'wolfssl/wolfcrypt/des3.h:WCv4-stable'
    'wolfssl/wolfcrypt/dh.h:WCv4-stable'
    'wolfssl/wolfcrypt/ecc.h:WCv4-stable'
    'wolfssl/wolfcrypt/hmac.h:WCv4-stable'
    'wolfssl/wolfcrypt/random.h:WCv4-rng-stable'
    'wolfssl/wolfcrypt/rsa.h:WCv4-stable'
    'wolfssl/wolfcrypt/sha.h:WCv4-stable'
    'wolfssl/wolfcrypt/sha256.h:WCv4-stable'
    'wolfssl/wolfcrypt/sha3.h:WCv4-stable'
    'wolfssl/wolfcrypt/sha512.h:WCv4-stable'
  )
  if [ "$FLAVOR" = 'solaris' ]; then MAKE='gmake'; fi
  ;;
netbsd-selftest)
  # non-FIPS, CAVP only but pull in selftest
  FIPS_OPTION='cavp-selftest'
  FIPS_FILES=('wolfcrypt/src/selftest.c:v3.14.2b')
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:v3.14.2'
    'wolfcrypt/src/dh.c:v3.14.2'
    'wolfcrypt/src/dsa.c:v3.14.2'
    'wolfcrypt/src/ecc.c:v3.14.2'
    'wolfcrypt/src/hmac.c:v3.14.2'
    'wolfcrypt/src/random.c:v3.14.2'
    'wolfcrypt/src/rsa.c:v3.14.2'
    'wolfcrypt/src/sha.c:v3.14.2'
    'wolfcrypt/src/sha256.c:v3.14.2'
    'wolfcrypt/src/sha512.c:v3.14.2'
    'wolfssl/wolfcrypt/aes.h:v3.14.2'
    'wolfssl/wolfcrypt/dh.h:v3.14.2'
    'wolfssl/wolfcrypt/dsa.h:v3.14.2'
    'wolfssl/wolfcrypt/ecc.h:v3.14.2'
    'wolfssl/wolfcrypt/hmac.h:v3.14.2'
    'wolfssl/wolfcrypt/random.h:v3.14.2'
    'wolfssl/wolfcrypt/rsa.h:v3.14.2'
    'wolfssl/wolfcrypt/sha.h:v3.14.2'
    'wolfssl/wolfcrypt/sha256.h:v3.14.2'
    'wolfssl/wolfcrypt/sha512.h:v3.14.2'
  )
  ;;
marvell-linux-selftest)
  # non-FIPS, CAVP only but pull in selftest
  FIPS_OPTION='cavp-selftest-v2'
  FIPS_FILES=('wolfcrypt/src/selftest.c:v3.14.2b')
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:v4.1.0-stable'
    'wolfcrypt/src/dh.c:v4.1.0-stable'
    'wolfcrypt/src/dsa.c:v4.1.0-stable'
    'wolfcrypt/src/ecc.c:v4.1.0-stable'
    'wolfcrypt/src/hmac.c:v4.1.0-stable'
    'wolfcrypt/src/random.c:v4.1.0-stable'
    'wolfcrypt/src/rsa.c:v4.1.0-stable'
    'wolfcrypt/src/sha.c:v4.1.0-stable'
    'wolfcrypt/src/sha256.c:v4.1.0-stable'
    'wolfcrypt/src/sha512.c:v4.1.0-stable'
    'wolfssl/wolfcrypt/aes.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/dh.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/dsa.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/ecc.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/hmac.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/random.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/rsa.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/sha.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/sha256.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/sha512.h:v4.1.0-stable'
  )
  ;;
linuxv5)
  FIPS_OPTION='v5'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:WCv5.2.0.1-RC01'
    'wolfcrypt/src/fips_test.c:WCv5.0-RC12'
    'wolfcrypt/src/wolfcrypt_first.c:WCv5.0-RC12'
    'wolfcrypt/src/wolfcrypt_last.c:WCv5.0-RC12'
    'wolfssl/wolfcrypt/fips.h:WCv5.0-RC12'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:WCv5.0-RC12'
    'wolfcrypt/src/aes_asm.asm:WCv5.0-RC12'
    'wolfcrypt/src/aes_asm.S:WCv5.0-RC12'
    'wolfcrypt/src/aes_gcm_asm.S:WCv5.0-RC12'
    'wolfcrypt/src/cmac.c:WCv5.0-RC12'
    'wolfcrypt/src/dh.c:WCv5.0-RC12'
    'wolfcrypt/src/ecc.c:WCv5.0-RC12'
    'wolfcrypt/src/hmac.c:WCv5.0-RC12'
    'wolfcrypt/src/kdf.c:WCv5.0-RC12'
    'wolfcrypt/src/random.c:WCv5.0-RC12'
    'wolfcrypt/src/rsa.c:WCv5.0-RC12'
    'wolfcrypt/src/sha.c:WCv5.0-RC12'
    'wolfcrypt/src/sha256.c:WCv5.0-RC12'
    'wolfcrypt/src/sha256_asm.S:WCv5.0-RC12'
    'wolfcrypt/src/sha3.c:WCv5.0-RC12'
    'wolfcrypt/src/sha512.c:WCv5.0-RC12'
    'wolfcrypt/src/sha512_asm.S:WCv5.0-RC12'
    'wolfssl/wolfcrypt/aes.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/cmac.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/dh.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/ecc.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/fips_test.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/hmac.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/kdf.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/random.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/rsa.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha256.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha3.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha512.h:WCv5.0-RC12'
  )
  ;;
linuxv5.2.1)
  FIPS_OPTION='v5'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:v5.2.1-stable'
    'wolfcrypt/src/fips_test.c:v5.2.1-stable'
    'wolfcrypt/src/wolfcrypt_first.c:v5.2.1-stable'
    'wolfcrypt/src/wolfcrypt_last.c:v5.2.1-stable'
    'wolfssl/wolfcrypt/fips.h:v5.2.1-stable'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:v5.2.1-stable'
    'wolfcrypt/src/aes_asm.asm:v5.2.1-stable'
    'wolfcrypt/src/aes_asm.S:v5.2.1-stable'
    'wolfcrypt/src/aes_gcm_asm.S:v5.2.1-stable'
    'wolfcrypt/src/cmac.c:v5.2.1-stable'
    'wolfcrypt/src/dh.c:v5.2.1-stable'
    'wolfcrypt/src/ecc.c:v5.2.1-stable'
    'wolfcrypt/src/hmac.c:v5.2.1-stable'
    'wolfcrypt/src/kdf.c:v5.2.1-stable'
    'wolfcrypt/src/random.c:v5.2.1-stable'
    'wolfcrypt/src/rsa.c:v5.2.1-stable'
    'wolfcrypt/src/sha.c:v5.2.1-stable'
    'wolfcrypt/src/sha256.c:v5.2.1-stable'
    'wolfcrypt/src/sha256_asm.S:v5.2.1-stable'
    'wolfcrypt/src/sha3.c:v5.2.1-stable'
    'wolfcrypt/src/sha512.c:v5.2.1-stable'
    'wolfcrypt/src/sha512_asm.S:v5.2.1-stable'
    'wolfssl/wolfcrypt/aes.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/cmac.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/dh.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/ecc.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/fips_test.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/hmac.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/kdf.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/random.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/rsa.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/sha.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/sha256.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/sha3.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/sha512.h:v5.2.1-stable'
  )
  ;;
fips-ready|fips-dev)
  FIPS_OPTION='ready'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:master'
    'wolfcrypt/src/fips_test.c:master'
    'wolfcrypt/src/wolfcrypt_first.c:master'
    'wolfcrypt/src/wolfcrypt_last.c:master'
    'wolfssl/wolfcrypt/fips.h:master'
  )
  WOLFCRYPT_FILES=()
  if [ "$FLAVOR" = 'fips-dev' ]; then FIPS_OPTION='dev'; fi
  ;;
wolfrand)
  FIPS_OPTION='rand'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:WRv4-stable'
    'wolfcrypt/src/fips_test.c:WRv4-stable'
    'wolfcrypt/src/wolfcrypt_first.c:WRv4-stable'
    'wolfcrypt/src/wolfcrypt_last.c:WRv4-stable'
    'wolfssl/wolfcrypt/fips.h:WRv4-stable'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/hmac.c:WCv4-stable'
    'wolfcrypt/src/random.c:WCv4-rng-stable'
    'wolfcrypt/src/sha256.c:WCv4-stable'
    'wolfssl/wolfcrypt/hmac.h:WCv4-stable'
    'wolfssl/wolfcrypt/random.h:WCv4-rng-stable'
    'wolfssl/wolfcrypt/sha256.h:WCv4-stable'
  )
  ;;
wolfentropy)
  FIPS_OPTION='v6'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:wolfEntropy1'
    'wolfcrypt/src/fips_test.c:wolfEntropy1'
    'wolfcrypt/src/wolfcrypt_first.c:wolfEntropy1'
    'wolfcrypt/src/wolfcrypt_last.c:wolfEntropy1'
    'wolfssl/wolfcrypt/fips.h:wolfEntropy1'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:wolfEntropy1'
    'wolfcrypt/src/aes_asm.asm:wolfEntropy1'
    'wolfcrypt/src/aes_asm.S:wolfEntropy1'
    'wolfcrypt/src/aes_gcm_asm.S:wolfEntropy1'
    'wolfcrypt/src/ecc.c:wolfEntropy1'
    'wolfcrypt/src/hmac.c:wolfEntropy1'
    'wolfcrypt/src/kdf.c:wolfEntropy1'
    'wolfcrypt/src/random.c:wolfEntropy1'
    'wolfcrypt/src/sha256.c:wolfEntropy1'
    'wolfcrypt/src/sha256_asm.S:wolfEntropy1'
    'wolfcrypt/src/sha3.c:wolfEntropy1'
    'wolfcrypt/src/sha512.c:wolfEntropy1'
    'wolfcrypt/src/sha512_asm.S:wolfEntropy1'
    'wolfssl/wolfcrypt/aes.h:wolfEntropy1'
    'wolfssl/wolfcrypt/ecc.h:wolfEntropy1'
    'wolfssl/wolfcrypt/fips_test.h:wolfEntropy1'
    'wolfssl/wolfcrypt/hmac.h:wolfEntropy1'
    'wolfssl/wolfcrypt/kdf.h:wolfEntropy1'
    'wolfssl/wolfcrypt/random.h:wolfEntropy1'
    'wolfssl/wolfcrypt/sha256.h:wolfEntropy1'
    'wolfssl/wolfcrypt/sha3.h:wolfEntropy1'
    'wolfssl/wolfcrypt/sha512.h:wolfEntropy1'
  )
  ;;

*)
  Usage
  exit 1
esac

# checkout_files takes an array of pairs of file paths and git tags to
# checkout. It will check to see if mytag exists and if not will make that
# tag a branch.
function checkout_files() {
    local name
    local tag
    for file_entry in "$@"; do
        name=${file_entry%%:*}
        tag=${file_entry#*:}
        if ! $GIT rev-parse -q --verify "my$tag" >/dev/null
        then
            $GIT branch --no-track "my$tag" "$tag" || exit $?
        fi
        $GIT checkout "my$tag" -- "$name" || exit $?
    done
}

# copy_fips_files takes an array of pairs of file paths and git tags to
# checkout. It will check to see if mytag exists and if now will make that
# tag a branch.  It breaks the filepath apart into file name and path, then
# copies it from the file from the fips directory to the path.
function copy_fips_files() {
    local name
    local bname
    local dname
    local tag
    for file_entry in "$@"; do
        name=${file_entry%%:*}
        tag=${file_entry#*:}
        bname=$(basename "$name")
        dname=$(dirname "$name")
        if ! $GIT rev-parse -q --verify "my$tag" >/dev/null; then
            $GIT branch --no-track "my$tag" "$tag" || exit $?
        fi
        $GIT checkout "my$tag" -- "$bname" || exit $?
        cp "$bname" "../$dname"
    done
}

if ! $GIT clone . "$TEST_DIR"; then
    echo "fips-check: Couldn't duplicate current working directory."
    exit 1
fi

pushd "$TEST_DIR" || exit 2

if ! $GIT clone "$FIPS_REPO" fips; then
    echo "fips-check: Couldn't check out FIPS repository."
    exit 1
fi

checkout_files "${WOLFCRYPT_FILES[@]}" || exit 3
pushd fips || exit 2
copy_fips_files "${FIPS_FILES[@]}" || exit 3
popd || exit 2

# When checking out cert 3389 ready code, NIST will no longer perform
# new certifications on 140-2 modules. If we were to use the latest files from
# master that would require re-cert due to changes in the module boundary.
# Since OE additions can still be processed for cert3389 we will call 140-2
# ready "fipsv2-OE-ready" indicating it is ready to use for an OE addition but
# would not be good for a new certification effort with the latest files.
if [ "$FLAVOR" = 'fipsv2-OE-ready' ] && [ -s wolfcrypt/src/fips.c ]; then
    cp wolfcrypt/src/fips.c wolfcrypt/src/fips.c.bak
    sed "s/v4.0.0-alpha/fipsv2-OE-ready/" wolfcrypt/src/fips.c.bak >wolfcrypt/src/fips.c
fi

# run the make test
./autogen.sh

case "$FIPS_OPTION" in
cavp-selftest)
    ./configure --enable-selftest
    ;;
cavp-selftest-v2)
    ./configure --enable-selftest=v2
    ;;
*)
    ./configure --enable-fips=$FIPS_OPTION
    ;;
esac

if ! $MAKE; then
    echo 'fips-check: Make failed. Debris left for analysis.'
    exit 3
fi

if [ -s wolfcrypt/src/fips_test.c ]; then
    NEWHASH=$(./wolfcrypt/test/testwolfcrypt | sed -n 's/hash = \(.*\)/\1/p')
    if [ -n "$NEWHASH" ]; then
        cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
        sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak >wolfcrypt/src/fips_test.c
        make clean
    fi
fi

if [ "$MAKECHECK" = "yes" ]; then
    if ! $MAKE check; then
        echo 'fips-check: Test failed. Debris left for analysis.'
        exit 3
    fi
fi

# Clean up
popd || exit 2
if [ "$KEEP" = 'no' ]; then
    rm -rf "$TEST_DIR"
fi
