#!/bin/bash

# fips-check.sh
# This script checks the current revision of the code against the
# previous release of the FIPS code. While wolfSSL and wolfCrypt
# may be advancing, they must work correctly with the last tested
# copy of our FIPS approved code.
#
# This should check out all the approved flavors. The command line
# option selects the flavor. The keep option keeps the output
# directory.
#
# Some variables may be overridden on the command line.

Usage() {
    cat <<usageText
Usage: $0 [flavor] [keep]
Flavor is one of:
    netbsd-selftest
    marvell-linux-selftest
    linuxv2 (FIPSv2, use for Win10)
    wolfrand
    solaris
    linuxv5 (current FIPS 140-3)
    fips-ready (ready FIPS 140-3)
    fips-dev (dev FIPS 140-3)
Keep (default off) retains the XXX-fips-test temp dir for inspection.

Example:
    $0 windows keep
usageText
}

# These variables may be overridden on the command line.
MAKE="${MAKE:-make}"
GIT="${GIT:-git -c advice.detachedHead=false}"
TEST_DIR="${TEST_DIR:-XXX-fips-test}"
FLAVOR="${FLAVOR:-linux}"
#KEEP="${KEEP:-no}"
KEEP="${KEEP:-yes}"
#FIPS_REPO="${FIPS_REPO:-git@github.com:wolfssl/fips.git}"

while [ "$1" ]; do
  if [ "$1" = 'keep' ]; then KEEP='yes'; else FLAVOR="$1"; fi
  shift
done

case "$FLAVOR" in
#linuxv2|fipsv2-OE-ready)
#  FIPS_OPTION='v2'
#  FIPS_VERSION='WCv4-stable'
#  CRYPT_VERSION='WCv4-stable'
#  RNG_VERSION='WCv4-rng-stable'
#  WC_MODS=('aes' 'aes_asm' 'cmac' 'des3' 'dh' 'ecc' 'hmac' 'random' 'rsa' 'sha' 'sha256' 'sha3' 'sha512')
#  FIPS_SRCS=('fips.c' 'fips_test.c' 'wolfcrypt_first.c' 'wolfcrypt_last.c')
#  FIPS_INCS=('fips.h')
#  ;;
#netbsd-selftest)
#  # non-FIPS, CAVP only but pull in selftest
#  FIPS_OPTION='cavp-selftest'
#  FIPS_VERSION='v3.14.2b'
#  CRYPT_VERSION='v3.14.2'
#  RNG_VERSION='v3.14.2'
#  WC_MODS=('aes' 'dh' 'dsa' 'ecc' 'hmac' 'random' 'rsa' 'sha' 'sha256' 'sha512')
#  FIPS_SRCS=('selftest.c')
#  ;;
#marvell-linux-selftest)
#  # non-FIPS, CAVP only but pull in selftest
#  FIPS_OPTION='cavp-selftest-v2'
#  FIPS_VERSION='v3.14.2b'
#  CRYPT_VERSION='v4.1.0-stable'
#  RNG_VERSION='v4.1.0-stable'
#  WC_MODS=('aes' 'dh' 'dsa' 'ecc' 'hmac' 'random' 'rsa' 'sha' 'sha256' 'sha512')
#  FIPS_SRCS=('selftest.c')
#  ;;
#linuxv5)
#  FIPS_OPTION='v5'
#  FIPS_VERSION='WCv5.0-RC12'
#  CRYPT_VERSION='WCv5.0-RC12'
#  RNG_VERSION='WCv5.0-RC12'
#  WC_MODS=('aes' 'aes_asm' 'cmac' 'dh' 'ecc' 'hmac' 'kdf' 'random' 'rsa' 'sha' 'sha256' 'sha256_asm' 'sha3' 'sha512' 'sha512_asm')
#  FIPS_SRCS=('fips.c' 'fips_test.c' 'wolfcrypt_first.c' 'wolfcrypt_last.c')
#  FIPS_INCS=('fips.h')
#  COPY_DIRECT=('wolfcrypt/src/aes_gcm_asm.S')
#  ;;
linuxv5a)
  FIPS_OPTION='v5'
  FIPS_FILES=('WCv5.0-RC12'
    'wolfcrypt/src/fips.c'
    'wolfcrypt/src/fips_test.c'
    'wolfcrypt/src/wolfcrypt_first.c'
    'wolfcrypt/src/wolfcrypt_last.c'
    'wolfssl/wolfcrypt/fips.h'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:WCv5.0-RC12'
    'wolfcrypt/src/aes_asm.c:WCv5.0-RC12'
    'wolfcrypt/src/cmac.c:WCv5.0-RC12'
    'wolfcrypt/src/dh.c:WCv5.0-RC12'
    'wolfcrypt/src/ecc.c:WCv5.0-RC12'
    'wolfcrypt/src/hmac.c:WCv5.0-RC12'
    'wolfcrypt/src/kdf.c:WCv5.0-RC12'
    'wolfcrypt/src/random.c:WCv5.0-RC12'
    'wolfcrypt/src/rsa.c:WCv5.0-RC12'
    'wolfcrypt/src/sha.c:WCv5.0-RC12'
    'wolfcrypt/src/sha256.c:WCv5.0-RC12'
    'wolfcrypt/src/sha256_asm.c:WCv5.0-RC12'
    'wolfcrypt/src/sha3.c:WCv5.0-RC12'
    'wolfcrypt/src/sha512.c:WCv5.0-RC12'
    'wolfcrypt/src/sha512_asm.c:WCv5.0-RC12'
    'wolfcrypt/src/aes_gcm_asm.S:WCv5.0-RC12'
    'wolfssl/wolfcrypt/aes.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/aes_asm.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/cmac.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/dh.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/ecc.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/hmac.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/kdf.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/random.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/rsa.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha256.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha256_asm.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha3.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha512.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha512_asm.h:WCv5.0-RC12'
  )
  ;;
#fips-ready)
#  FIPS_OPTION='ready'
#  FIPS_VERSION='master'
#  FIPS_SRCS=('fips.c' 'fips_test.c' 'wolfcrypt_first.c' 'wolfcrypt_last.c')
#  FIPS_INCS=('fips.h')
#  ;;
#fips-dev)
#  FIPS_OPTION='dev'
#  FIPS_VERSION='master'
#  FIPS_SRCS=('fips.c' 'fips_test.c' 'wolfcrypt_first.c' 'wolfcrypt_last.c')
#  FIPS_INCS=('fips.h')
#  ;;
#wolfrand)
#  FIPS_OPTION='rand'
#  FIPS_VERSION='WRv4-stable'
#  CRYPT_VERSION='WCv4-stable'
#  RNG_VERSION='WCv4-rng-stable'
#  WC_MODS=('hmac' 'random' 'sha256')
#  FIPS_SRCS=('fips.c' 'fips_test.c' 'wolfcrypt_first.c' 'wolfcrypt_last.c')
#  FIPS_INCS=('fips.h')
#  ;;
#solaris)
#  FIPS_OPTION='v2'
#  FIPS_VERSION='WCv4-stable'
#  CRYPT_VERSION='WCv4-stable'
#  RNG_VERSION='WCv4-rng-stable'
#  WC_MODS=('aes' 'aes_asm' 'cmac' 'des3' 'dh' 'ecc' 'hmac' 'random' 'rsa' 'sha' 'sha256' 'sha3' 'sha512')
#  FIPS_SRCS=('fips.c' 'fips_test.c' 'wolfcrypt_first.c' 'wolfcrypt_last.c')
#  FIPS_INCS=('fips.h')
#  MAKE='gmake'
#  ;;
*)
  Usage
  exit 1
esac

# checkout_files takes an array of pairs of file paths and git tags to checkout.
# It will check to see if mytag exists and if not will make that tag a branch.
function checkout_files() {
    for file_entry in "$@"
    do
        local name=${file_entry%%:*}
        local tag=${file_entry#*:}
        if ! $GIT branch --list | grep "my$tag"
        then
            $GIT branch --no-track "my$tag" "$tag" || exit $?
        fi
        $GIT checkout "my$tag" -- "$name" || exit $?
    done
}

# copy_fips_files clones the FIPS repository. It takes an array of file paths, where
# it breaks apart into file name and path, then copies it from the file from the fips
# directory to the path. The first item is the name of the tag.
function copy_fips_files() {
    local tag="$1"
    shift
    if ! $GIT clone --depth 1 -b "$tag" 'git@github.com:wolfssl/fips.git' fips
    then
        echo "fips-check: Couldn't check out $tag from FIPS repository."
        exit 1
    fi
    for file_path in "$@"
    do
        cp fips/"$(basename "$file_path")" "$(dirname "$file_path")"
    done
}

if ! $GIT clone . "$TEST_DIR"; then
    echo "fips-check: Couldn't duplicate current working directory."
    exit 1
fi

pushd "$TEST_DIR" || exit 2

case "$FIPS_OPTION" in

*dev)
    echo "Don't need to copy in tagged wolfCrypt files for fips-dev."
    ;;

*ready)
    echo "Don't need to copy in tagged wolfCrypt files for FIPS Ready."
    ;;

cavp-selftest*|v2|rand|v5*)
    checkout_files "${WOLFCRYPT_FILES[@]}"
    ;;

*)
    echo "fips-check: Invalid FIPS option ${FIPS_OPTION}."
    exit 1
    ;;
esac

copy_fips_files "${FIPS_FILES[@]}"

# When checking out cert 3389 ready code, NIST will no longer perform
# new certifications on 140-2 modules. If we were to use the latest files from
# master that would require re-cert due to changes in the module boundary.
# Since OE additions can still be processed for cert3389 we will call 140-2
# ready "fipsv2-OE-ready" indicating it is ready to use for an OE addition but
# would not be good for a new certification effort with the latest files.
if [ "$FLAVOR" = 'fipsv2-OE-ready' ] && [ -s wolfcrypt/src/fips.c ]
then
    cp wolfcrypt/src/fips.c wolfcrypt/src/fips.c.bak
    sed "s/^v4.0.0-alpha/fipsv2-OE-ready/" wolfcrypt/src/fips.c.bak >wolfcrypt/src/fips.c
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

if ! $MAKE
then
    echo "fips-check: Make failed. Debris left for analysis."
    exit 3
fi

if [ -s wolfcrypt/src/fips_test.c ]
then
    NEWHASH=$(./wolfcrypt/test/testwolfcrypt | sed -n 's/hash = \(.*\)/\1/p')
    if [ -n "$NEWHASH" ]; then
        cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
        sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak >wolfcrypt/src/fips_test.c
        make clean
    fi
fi

if ! $MAKE check
then
    echo 'fips-check: Test failed. Debris left for analysis.'
    exit 3
fi

# Clean up
popd || exit 2
if [ "$KEEP" = 'no' ];
then
    rm -rf "$TEST_DIR"
fi
