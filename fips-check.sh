#!/bin/bash

# fips-check.sh
# This script checks the current revision of the code against the
# previous release of the FIPS code. While wolfSSL and wolfCrypt
# may be advancing, they must work correctly with the last tested
# copy of our FIPS approved code.
#
# This should check out all the approved flavors. The command line
# option selects the flavor.
#
#     $ ./fips-check [flavor] [keep]
#
#     - flavor: linux (default), ios, android, windows, freertos, linux-ecc, netbsd-selftest, linuxv2, fipsv2-OE-ready, stm32l4-v2, linuxv5, fips-ready, fips-dev
#
#     - keep: (default off) XXX-fips-test temp dir around for inspection
#

Usage() {
    cat <<usageText
Usage: $0 flavor [keep]
Flavor is one of:
    netbsd-selftest
    marvell-linux-selftest
    linuxv2 (FIPSv2, use for Win10)
    stm32l4-v2 (FIPSv2, use for STM32L4)
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

MAKE='make'

# non-FIPS, CAVP only but pull in selftest
# will reset above variables below in flavor switch
NETBSD_FIPS_VERSION=v3.14.2b
NETBSD_FIPS_REPO=git@github.com:wolfssl/fips.git
NETBSD_CRYPT_VERSION=v3.14.2
NETBSD_CRYPT_REPO=git@github.com:wolfssl/wolfssl.git

# non-FIPS, CAVP only but pull in selftest
# will reset above variables below in flavor switch
MARVELL_LINUX_FIPS_VERSION=v3.14.2b
MARVELL_LINUX_FIPS_REPO=git@github.com:wolfssl/fips.git
MARVELL_LINUX_CRYPT_VERSION=v4.1.0-stable
MARVELL_LINUX_CRYPT_REPO=git@github.com:wolfssl/wolfssl.git

STM32L4_V2_FIPS_VERSION=WCv4.0.1-stable
STM32L4_V2_FIPS_REPO=git@github.com:wolfSSL/fips.git
STM32L4_V2_CRYPT_VERSION=WCv4.0.1-stable

FIPS_SRCS=( fips.c fips_test.c )
WC_MODS=( aes des3 sha sha256 sha512 rsa hmac random aes_asm )
TEST_DIR=XXX-fips-test
CRYPT_INC_PATH=undef
CRYPT_SRC_PATH=undef
RNG_VERSION=v3.6.0
FIPS_OPTION=undef
CAVP_SELFTEST_ONLY="no"
GIT="git -c advice.detachedHead=false"

if [ "$1" == "" ]; then FLAVOR="undef"; else FLAVOR="$1"; fi

if [ "$2" == "keep" ]; then KEEP="yes"; else KEEP="no"; fi

case "$FLAVOR" in
linuxv2 | fipsv2-OE-ready)
  FIPS_VERSION=WCv4-stable
  FIPS_REPO=git@github.com:wolfssl/fips.git
  CRYPT_VERSION=WCv4-stable
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  WC_MODS+=( cmac dh ecc sha3 )
  RNG_VERSION=WCv4-rng-stable
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=v2
  ;;
netbsd-selftest)
  FIPS_VERSION=$NETBSD_FIPS_VERSION
  FIPS_REPO=$NETBSD_FIPS_REPO
  CRYPT_VERSION=$NETBSD_CRYPT_VERSION
…  CRYPT_VERSION=$MARVELL_LINUX_CRYPT_VERSION
  CRYPT_REPO=$MARVELL_LINUX_CRYPT_REPO
  FIPS_SRCS=( selftest.c )
  WC_MODS=( dh ecc rsa dsa aes sha sha256 sha512 hmac random )
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  CAVP_SELFTEST_ONLY="yes"
  CAVP_SELFTEST_OPTION=v2
  FIPS_OPTION="ready"
  ;;
marvell-linux-selftest)
  FIPS_VERSION=$MARVELL_LINUX_FIPS_VERSION
  FIPS_REPO=$MARVELL_LINUX_FIPS_REPO
  CRYPT_VERSION=$MARVELL_LINUX_CRYPT_VERSION
  CRYPT_REPO=$MARVELL_LINUX_CRYPT_REPO
  FIPS_SRCS=( selftest.c )
  WC_MODS=( dh ecc rsa dsa aes sha sha256 sha512 hmac random )
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  CAVP_SELFTEST_ONLY="yes"
  CAVP_SELFTEST_OPTION=v2
  FIPS_OPTION="ready"
  ;;
linuxv5)
  FIPS_REPO="git@github.com:wolfSSL/fips.git"
  FIPS_VERSION="WCv5.0-RC12"
  CRYPT_REPO="git@github.com:wolfSSL/wolfssl.git"
  CRYPT_VERSION="WCv5.0-RC12"
  CRYPT_INC_PATH="wolfssl/wolfcrypt"
  CRYPT_SRC_PATH="wolfcrypt/src"
  WC_MODS=( aes sha sha256 sha512 rsa hmac random cmac dh ecc sha3 kdf
            aes_asm sha256_asm sha512_asm )
  RNG_VERSION="WCv5.0-RC12"
  FIPS_SRCS=( fips.c fips_test.c wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION="v5"
  COPY_DIRECT=( wolfcrypt/src/aes_gcm_asm.S )
  ;;
fips-ready)
  FIPS_REPO="git@github.com:wolfSSL/fips.git"
  FIPS_VERSION="master"
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  FIPS_SRCS=( fips.c fips_test.c wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=ready
  ;;
fips-dev)
  FIPS_REPO="git@github.com:wolfSSL/fips.git"
  FIPS_VERSION="master"
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=dev
  ;;

stm32l4-v2)
  FIPS_VERSION=$STM32L4_V2_FIPS_VERSION
  FIPS_REPO=$STM32L4_V2_FIPS_REPO
  CRYPT_VERSION=$STM32L4_V2_CRYPT_VERSION
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
# Replace the WC_MODS list for now. Do not want to copy over random.c yet.
  WC_MODS=( aes des3 sha sha256 sha512 rsa hmac )
  WC_MODS+=( cmac dh ecc )
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=v2
  ;;
wolfrand)
  FIPS_REPO=git@github.com:wolfssl/fips.git
  FIPS_VERSION=WRv4-stable
  CRYPT_REPO=git@github.com:wolfssl/wolfssl.git
  CRYPT_VERSION=WCv4-stable
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  RNG_VERSION=WCv4-rng-stable
  WC_MODS=( hmac sha256 random )
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=rand
  ;;
solaris)
  FIPS_VERSION=WCv4-stable
  FIPS_REPO=git@github.com:wolfssl/fips.git
  CRYPT_VERSION=WCv4-stable
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  WC_MODS+=( cmac dh ecc sha3 )
  RNG_VERSION=WCv4-rng-stable
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=v2
  MAKE=gmake
  ;;

*)
  Usage
  exit 1
esac

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

v2|rand|v5*)
    $GIT branch --no-track "my$CRYPT_VERSION" "$CRYPT_VERSION" || exit $?
    # Checkout the fips versions of the wolfCrypt files from the repo.
    for MOD in "${WC_MODS[@]}"
    do
        if [ -f "$CRYPT_SRC_PATH/$MOD.c" ]; then
            $GIT checkout "my$CRYPT_VERSION" -- "$CRYPT_SRC_PATH/$MOD.c" || exit $?
        fi
        # aes_asm.S, sha256_asm.S sha512_asm.S
        if [ -f "$CRYPT_SRC_PATH/$MOD.S" ]; then
            echo "Checking out asm file: $MOD.S"
            $GIT checkout "my$CRYPT_VERSION" -- "$CRYPT_SRC_PATH/$MOD.S" || exit $?
        fi
        # aes_asm.asm
        if [ -f "$CRYPT_SRC_PATH/$MOD.asm" ]; then
            echo "Checking out asm file: $MOD.asm"
            $GIT checkout "my$CRYPT_VERSION" -- "$CRYPT_SRC_PATH/$MOD.asm" || exit $?
        fi
        if [ -f "$CRYPT_INC_PATH/$MOD.h" ]; then
            $GIT checkout "my$CRYPT_VERSION" -- "$CRYPT_INC_PATH/$MOD.h" || exit $?
        fi
    done

    for MOD in "${COPY_DIRECT[@]}"
    do
        $GIT checkout "my$CRYPT_VERSION" -- "$MOD" || exit $?
    done

    $GIT branch --no-track "myrng$RNG_VERSION" "$RNG_VERSION" || exit $?
    # Checkout the fips versions of the wolfCrypt files from the repo.
    $GIT checkout "myrng$RNG_VERSION" -- "$CRYPT_SRC_PATH/random.c" "$CRYPT_INC_PATH/random.h" || exit $?
    ;;

*)
    echo "fips-check: Invalid FIPS option \"${FIPS_OPTION}\"."
    exit 1
    ;;
esac

# clone the FIPS repository
case "$FIPS_OPTION" in
    *dev)
        if ! $GIT clone --depth 1 "$FIPS_REPO" fips; then
            echo "fips-check: Couldn't check out the FIPS repository for fips-dev."
            exit 1
        fi
        ;;
    *)
        if ! $GIT clone --depth 1 -b "$FIPS_VERSION" "$FIPS_REPO" fips; then
            echo "fips-check: Couldn't check out ${FIPS_VERSION} from repository ${FIPS_REPO}."
            exit 1
        fi
        ;;
esac

for SRC in "${FIPS_SRCS[@]}"
do
    cp "fips/$SRC" "$CRYPT_SRC_PATH"
done

for INC in "${FIPS_INCS[@]}"
do
    cp "fips/$INC" "$CRYPT_INC_PATH"
done

# When checking out cert 3389 ready code, NIST will no longer perform
# new certifications on 140-2 modules. If we were to use the latest files from
# master that would require re-cert due to changes in the module boundary.
# Since OE additions can still be processed for cert3389 we will call 140-2
# ready "fipsv2-OE-ready" indicating it is ready to use for an OE addition but
# would not be good for a new certification effort with the latest files.
if [ "$FLAVOR" = "fipsv2-OE-ready" ]; then
    OLD_VERSION="    return \"v4.0.0-alpha\";"
    OE_READY_VERSION="    return \"fipsv2-OE-ready\";"
    cp "${CRYPT_SRC_PATH}/fips.c" "${CRYPT_SRC_PATH}/fips.c.bak"
    sed "s/^${OLD_VERSION}/${OE_READY_VERSION}/" "${CRYPT_SRC_PATH}/fips.c.bak" >"${CRYPT_SRC_PATH}/fips.c"
fi

# run the make test
./autogen.sh
if [ "$CAVP_SELFTEST_ONLY" == "yes" ];
then
    if [ "$CAVP_SELFTEST_OPTION" == "v2" ]
    then
        ./configure --enable-selftest=v2
    else
        ./configure --enable-selftest
    fi
else
    ./configure --enable-fips=$FIPS_OPTION
fi
if ! $MAKE; then
    echo "fips-check: Make failed. Debris left for analysis."
    exit 3
fi

if [ "$CAVP_SELFTEST_ONLY" == "no" ];
then
    NEWHASH=$(./wolfcrypt/test/testwolfcrypt | sed -n 's/hash = \(.*\)/\1/p')
    if [ -n "$NEWHASH" ]; then
        cp "${CRYPT_SRC_PATH}/fips_test.c" "${CRYPT_SRC_PATH}/fips_test.c.bak"
        sed "s/^\".*\";/\"${NEWHASH}\";/" "${CRYPT_SRC_PATH}/fips_test.c.bak" >"${CRYPT_SRC_PATH}/fips_test.c"
        make clean
    fi
fi

if ! $MAKE test; then
    echo "fips-check: Test failed. Debris left for analysis."
    exit 3
fi

if [ ${#FIPS_CONFLICTS[@]} -ne 0 ];
then
    echo "Due to the way this package is compiled by the customer duplicate"
    echo "source file names are an issue, renaming:"
    for FNAME in "${FIPS_CONFLICTS[@]}"
    do
        echo "wolfcrypt/src/$FNAME.c to wolfcrypt/src/wc_$FNAME.c"
        mv "./wolfcrypt/src/$FNAME.c" "./wolfcrypt/src/wc_$FNAME.c"
    done
    echo "Confirming files were renamed..."
    ls -la ./wolfcrypt/src/wc_*.c
fi

# Clean up
popd || exit 2
if [ "$KEEP" == "no" ];
then
    rm -rf "$TEST_DIR"
fi
