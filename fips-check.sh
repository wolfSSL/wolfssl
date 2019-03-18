#!/bin/bash

# fips-check.sh
# This script checks the current revision of the code against the
# previous release of the FIPS code. While wolfSSL and wolfCrypt
# may be advancing, they must work correctly with the last tested
# copy of our FIPS approved code.
#
# This should check out all the approved versions. The command line
# option selects the version.
#
#     $ ./fips-check [version] [keep]
#
#     - version: linux (default), ios, android, windows, freertos, linux-ecc, netbsd-selftest, linuxv2, fips-ready
#
#     - keep: (default off) XXX-fips-test temp dir around for inspection
#

Usage() {
    cat <<usageText
Usage: $0 [platform [keep]]
Platform is one of:
    linux (default)
    ios
    android
    windows
    freertos
    openrtos-3.9.2
    linux-ecc
    netbsd-selftest
    sgx
    netos-7.6
    linuxv2 (FIPSv2, use for Win10)
    fips-ready
Keep (default off) retains the XXX-fips-test temp dir for inspection.

Example:
    $0 windows keep
usageText
}

LINUX_FIPS_VERSION=v3.2.6
LINUX_FIPS_REPO=git@github.com:wolfSSL/fips.git
LINUX_CRYPT_VERSION=v3.2.6
LINUX_CRYPT_REPO=git@github.com:cyassl/cyassl.git

LINUX_ECC_FIPS_VERSION=v3.10.3
LINUX_ECC_FIPS_REPO=git@github.com:wolfSSL/fips.git
LINUX_ECC_CRYPT_VERSION=v3.2.6
LINUX_ECC_CRYPT_REPO=git@github.com:cyassl/cyassl.git

IOS_FIPS_VERSION=v3.4.8a
IOS_FIPS_REPO=git@github.com:wolfSSL/fips.git
IOS_CRYPT_VERSION=v3.4.8.fips
IOS_CRYPT_REPO=git@github.com:cyassl/cyassl.git

ANDROID_FIPS_VERSION=v3.5.0
ANDROID_FIPS_REPO=git@github.com:wolfSSL/fips.git
ANDROID_CRYPT_VERSION=v3.5.0
ANDROID_CRYPT_REPO=git@github.com:cyassl/cyassl.git

WINDOWS_FIPS_VERSION=v3.6.6
WINDOWS_FIPS_REPO=git@github.com:wolfSSL/fips.git
WINDOWS_CRYPT_VERSION=v3.6.6
WINDOWS_CRYPT_REPO=git@github.com:cyassl/cyassl.git

FREERTOS_FIPS_VERSION=v3.6.1-FreeRTOS
FREERTOS_FIPS_REPO=git@github.com:wolfSSL/fips.git
FREERTOS_CRYPT_VERSION=v3.6.1
FREERTOS_CRYPT_REPO=git@github.com:cyassl/cyassl.git

OPENRTOS_3_9_2_FIPS_VERSION=v3.9.2-OpenRTOS
OPENRTOS_3_9_2_FIPS_REPO=git@github.com:wolfSSL/fips.git
OPENRTOS_3_9_2_CRYPT_VERSION=v3.6.1
OPENRTOS_3_9_2_CRYPT_REPO=git@github.com:cyassl/cyassl.git

#NOTE: Does not include the SGX examples yet, update version once fipsv2 is
#      finished and merge conflicts can be resolved. This will be tagged as
#      v3.12.4.sgx-examples
#SGX_FIPS_VERSION=v3.12.4.sgx-examples
SGX_FIPS_VERSION=v3.6.6
SGX_FIPS_REPO=git@github.com:wolfSSL/fips.git
SGX_CRYPT_VERSION=v3.12.4
SGX_CRYPT_REPO=git@github.com:cyassl/cyassl.git

NETOS_7_6_FIPS_VERSION=v3.12.6
NETOS_7_6_FIPS_REPO=git@github.com:wolfSSL/fips.git
NETOS_7_6_CRYPT_VERSION=v3.12.4
NETOS_7_6_CRYPT_REPO=git@github.com:cyassl/cyassl.git

# non-FIPS, CAVP only but pull in selftest
# will reset above variables below in platform switch
NETBSD_FIPS_VERSION=v3.14.2a
NETBSD_FIPS_REPO=git@github.com:wolfssl/fips.git
NETBSD_CRYPT_VERSION=v3.14.2
NETBSD_CRYPT_REPO=git@github.com:wolfssl/wolfssl.git

FIPS_SRCS=( fips.c fips_test.c )
WC_MODS=( aes des3 sha sha256 sha512 rsa hmac random )
TEST_DIR=XXX-fips-test
CRYPT_INC_PATH=cyassl/ctaocrypt
CRYPT_SRC_PATH=ctaocrypt/src
RNG_VERSION=v3.6.0
FIPS_OPTION=v1
CAVP_SELFTEST_ONLY="no"
GIT="git -c advice.detachedHead=false"

if [ "x$1" == "x" ]; then PLATFORM="linux"; else PLATFORM=$1; fi

if [ "x$2" == "xkeep" ]; then KEEP="yes"; else KEEP="no"; fi

case $PLATFORM in
ios)
  FIPS_VERSION=$IOS_FIPS_VERSION
  FIPS_REPO=$IOS_FIPS_REPO
  CRYPT_VERSION=$IOS_CRYPT_VERSION
  CRYPT_REPO=$IOS_CRYPT_REPO
  ;;
android)
  FIPS_VERSION=$ANDROID_FIPS_VERSION
  FIPS_REPO=$ANDROID_FIPS_REPO
  CRYPT_VERSION=$ANDROID_CRYPT_VERSION
  CRYPT_REPO=$ANDROID_CRYPT_REPO
  ;;
windows)
  FIPS_VERSION=$WINDOWS_FIPS_VERSION
  FIPS_REPO=$WINDOWS_FIPS_REPO
  CRYPT_VERSION=$WINDOWS_CRYPT_VERSION
  CRYPT_REPO=$WINDOWS_CRYPT_REPO
  ;;
freertos)
  FIPS_VERSION=$FREERTOS_FIPS_VERSION
  FIPS_REPO=$FREERTOS_FIPS_REPO
  CRYPT_VERSION=$FREERTOS_CRYPT_VERSION
  CRYPT_REPO=$FREERTOS_CRYPT_REPO
  ;;
openrtos-3.9.2)
  FIPS_VERSION=$OPENRTOS_3_9_2_FIPS_VERSION
  FIPS_REPO=$OPENRTOS_3_9_2_FIPS_REPO
  CRYPT_VERSION=$OPENRTOS_3_9_2_CRYPT_VERSION
  CRYPT_REPO=$OPENRTOS_3_9_2_CRYPT_REPO
  FIPS_CONFLICTS=( aes hmac random sha256 )
  ;;
linux)
  FIPS_VERSION=$LINUX_FIPS_VERSION
  FIPS_REPO=$LINUX_FIPS_REPO
  CRYPT_VERSION=$LINUX_CRYPT_VERSION
  CRYPT_REPO=$LINUX_CRYPT_REPO
  ;;
linux-ecc)
  FIPS_VERSION=$LINUX_ECC_FIPS_VERSION
  FIPS_REPO=$LINUX_ECC_FIPS_REPO
  CRYPT_VERSION=$LINUX_ECC_CRYPT_VERSION
  CRYPT_REPO=$LINUX_ECC_CRYPT_REPO
  ;;
linuxv2)
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
  CRYPT_REPO=$NETBSD_CRYPT_REPO
  FIPS_SRCS=( selftest.c )
  WC_MODS=( dh ecc rsa dsa aes sha sha256 sha512 hmac random )
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  CAVP_SELFTEST_ONLY="yes"
  ;;
sgx)
  FIPS_VERSION=$SGX_FIPS_VERSION
  FIPS_REPO=$SGX_FIPS_REPO
  CRYPT_VERSION=$SGX_CRYPT_VERSION
  CRYPT_REPO=$SGX_CRYPT_REPO
  ;;
netos-7.6)
  FIPS_VERSION=$NETOS_7_6_FIPS_VERSION
  FIPS_REPO=$NETOS_7_6_FIPS_REPO
  CRYPT_VERSION=$NETOS_7_6_CRYPT_VERSION
  CRYPT_REPO=$NETOS_7_6_CRYPT_REPO
  ;;
fips-ready)
  FIPS_REPO="git@github.com:wolfssl/fips.git"
  CRYPT_REPO="git@github.com:wolfssl/wolfssl.git"
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=ready
  ;;
*)
  Usage
  exit 1
esac

if ! $GIT clone . $TEST_DIR; then
    echo "fips-check: Couldn't duplicate current working directory."
    exit 1
fi

pushd $TEST_DIR || exit 2

if [ "x$FIPS_OPTION" == "xv1" ];
then
    # make a clone of the last FIPS release tag
    if ! $GIT clone --depth 1 -b $CRYPT_VERSION $CRYPT_REPO old-tree; then
        echo "fips-check: Couldn't checkout the FIPS release."
        exit 1
    fi

    for MOD in "${WC_MODS[@]}"
    do
        cp "old-tree/$CRYPT_SRC_PATH/${MOD}.c" $CRYPT_SRC_PATH
        cp "old-tree/$CRYPT_INC_PATH/${MOD}.h" $CRYPT_INC_PATH
    done

    # We are using random.c from a separate release.
    # This is forcefully overwriting any other checkout of the cyassl sources.
    # Removing this as default behavior for SGX and netos projects.
    if [ "x$CAVP_SELFTEST_ONLY" == "xno" ] && [ "x$PLATFORM" != "xsgx" ] && \
       [ "x$PLATFORM" != "xnetos-7.6" ];
    then
        pushd old-tree || exit 2
        $GIT fetch origin $RNG_VERSION
        $GIT checkout FETCH_HEAD
        popd || exit 2
        cp "old-tree/$CRYPT_SRC_PATH/random.c" $CRYPT_SRC_PATH
        cp "old-tree/$CRYPT_INC_PATH/random.h" $CRYPT_INC_PATH
    fi
elif [ "x$FIPS_OPTION" == "xv2" ]
then
    $GIT branch --no-track "my$CRYPT_VERSION" $CRYPT_VERSION
    # Checkout the fips versions of the wolfCrypt files from the repo.
    for MOD in "${WC_MODS[@]}"
    do
        $GIT checkout "my$CRYPT_VERSION" -- "$CRYPT_SRC_PATH/$MOD.c" "$CRYPT_INC_PATH/$MOD.h"
    done

    $GIT branch --no-track "my$RNG_VERSION" $RNG_VERSION
    # Checkout the fips versions of the wolfCrypt files from the repo.
    $GIT checkout "my$RNG_VERSION" -- "$CRYPT_SRC_PATH/random.c" "$CRYPT_INC_PATH/random.h"
elif [ "x$FIPS_OPTION" == "xready" ]
then
    echo "Don't need to copy anything in particular for FIPS Ready."
else
    echo "fips-check: Invalid FIPS option."
    exit 1
fi

# clone the FIPS repository
if [ "x$FIPS_OPTION" != "xready" ]
then
    if ! $GIT clone --depth 1 -b $FIPS_VERSION $FIPS_REPO fips; then
        echo "fips-check: Couldn't checkout the FIPS repository."
        exit 1
    fi
else
    if ! $GIT clone --depth 1 $FIPS_REPO fips; then
        echo "fips-check: Couldn't checkout the FIPS repository."
        exit 1
    fi
    FIPS_OPTION="v2"
fi

for SRC in "${FIPS_SRCS[@]}"
do
    cp "fips/$SRC" $CRYPT_SRC_PATH
done

for INC in "${FIPS_INCS[@]}"
do
    cp "fips/$INC" $CRYPT_INC_PATH
done

# run the make test
./autogen.sh
if [ "x$CAVP_SELFTEST_ONLY" == "xyes" ];
then
    ./configure --enable-selftest
else
    ./configure --enable-fips=$FIPS_OPTION
fi
if ! make; then
    echo "fips-check: Make failed. Debris left for analysis."
    exit 3
fi

if [ "x$CAVP_SELFTEST_ONLY" == "xno" ];
then
    NEWHASH=$(./wolfcrypt/test/testwolfcrypt | sed -n 's/hash = \(.*\)/\1/p')
    if [ -n "$NEWHASH" ]; then
        sed -i.bak "s/^\".*\";/\"${NEWHASH}\";/" $CRYPT_SRC_PATH/fips_test.c
        make clean
    fi
fi

if ! make test; then
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
if [ "x$KEEP" == "xno" ];
then
    rm -rf $TEST_DIR
fi
