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
#     - version: linux (default), ios, android, windows, freertos, linux-ecc, netbsd-selftest, linuxv2
#
#     - keep: (default off) XXX-fips-test temp dir around for inspection
#

function Usage() {
    echo "Usage: $0 [platform] [keep]"
    echo "Where \"platform\" is one of linux (default), ios, android, windows, freertos, openrtos-3.9.2, linux-ecc, netbsd-selftest, linuxv2"
    echo "Where \"keep\" means keep (default off) XXX-fips-test temp dir around for inspection"
}

LINUX_FIPS_VERSION=v3.2.6
LINUX_FIPS_REPO=git@github.com:wolfSSL/fips.git
LINUX_CRYPT_VERSION=v3.2.6
LINUX_CRYPT_REPO=git@github.com:cyassl/cyassl.git

LINUX_ECC_FIPS_VERSION=v3.10.3
LINUX_ECC_FIPS_REPO=git@github.com:wolfSSL/fips.git
LINUX_ECC_CRYPT_VERSION=v3.2.6
LINUX_ECC_CRYPT_REPO=git@github.com:cyassl/cyassl.git

LINUXV2_FIPS_VERSION=fipsv2
LINUXV2_FIPS_REPO=git@github.com:ejohnstown/fips.git
LINUXV2_CRYPT_VERSION=fipsv2

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

# non-FIPS, CAVP only but pull in selftest
# will reset above variables below in platform switch
NETBSD_FIPS_VERSION=v3.14.2
NETBSD_FIPS_REPO=git@github.com:wolfssl/fips.git
NETBSD_CTAO_VERSION=v3.14.2
NETBSD_CTAO_REPO=git@github.com:wolfssl/wolfssl.git

FIPS_SRCS=( fips.c fips_test.c )
WC_MODS=( aes des3 sha sha256 sha512 rsa hmac random )
TEST_DIR=XXX-fips-test
CRYPT_INC_PATH=cyassl/ctaocrypt
CRYPT_SRC_PATH=ctaocrypt/src
FIPS_OPTION=v1
CAVP_SELFTEST_ONLY="no"

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
  FIPS_VERSION=$LINUXV2_FIPS_VERSION
  FIPS_REPO=$LINUXV2_FIPS_REPO
  CRYPT_VERSION=$LINUXV2_CRYPT_VERSION
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  WC_MODS+=( cmac dh )
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=v2
  ;;
netbsd-selftest)
  FIPS_VERSION=$NETBSD_FIPS_VERSION
  FIPS_REPO=$NETBSD_FIPS_REPO
  CTAO_VERSION=$NETBSD_CTAO_VERSION
  CTAO_REPO=$NETBSD_CTAO_REPO
  FIPS_SRCS=( selftest.c )
  WC_MODS=( dh ecc rsa dsa aes sha sha256 sha512 hmac random )
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  CAVP_SELFTEST_ONLY="yes"
  ;;
*)
  Usage
  exit 1
esac

git clone . $TEST_DIR
[ $? -ne 0 ] && echo "\n\nCouldn't duplicate current working directory.\n\n" && exit 1

pushd $TEST_DIR

if [ "x$FIPS_OPTION" == "xv1" ];
then
    # make a clone of the last FIPS release tag
    git clone -b $CRYPT_VERSION $CRYPT_REPO old-tree
    [ $? -ne 0 ] && echo "\n\nCouldn't checkout the FIPS release.\n\n" && exit 1

    for MOD in ${WC_MODS[@]}
    do
        cp old-tree/$CRYPT_SRC_PATH/${MOD}.c $CRYPT_SRC_PATH
        cp old-tree/$CRYPT_INC_PATH/${MOD}.h $CRYPT_INC_PATH
    done

    if [ "x$CAVP_SELFTEST_ONLY" == "xno" ];
    then
        # We are using random.c from a separate release
        pushd old-tree
        git checkout v3.6.0
        popd
        cp old-tree/$CRYPT_SRC_PATH/random.c $CRYPT_SRC_PATH
        cp old-tree/$CRYPT_INC_PATH/random.h $CRYPT_INC_PATH
    fi
else
    git branch --track $CRYPT_VERSION origin/$CRYPT_VERSION
    # Checkout the fips versions of the wolfCrypt files from the repo.
    for MOD in ${WC_MODS[@]}
    do
        git checkout $CRYPT_VERSION -- $CRYPT_SRC_PATH/$MOD.c $CRYPT_INC_PATH/$MOD.h
    done
fi

# clone the FIPS repository
git clone -b $FIPS_VERSION $FIPS_REPO fips
[ $? -ne 0 ] && echo "\n\nCouldn't checkout the FIPS repository.\n\n" && exit 1

for SRC in ${FIPS_SRCS[@]}
do
    cp fips/$SRC $CRYPT_SRC_PATH
done

for INC in ${FIPS_INCS[@]}
do
    cp fips/$INC $CRYPT_INC_PATH
done

# run the make test
./autogen.sh
if [ "x$CAVP_SELFTEST_ONLY" == "xyes" ];
then
    ./configure --enable-selftest
else
    ./configure --enable-fips=$FIPS_OPTION
fi
make
[ $? -ne 0 ] && echo "\n\nMake failed. Debris left for analysis." && exit 1

if [ "x$CAVP_SELFTEST_ONLY" == "xno" ];
then
    NEWHASH=`./wolfcrypt/test/testwolfcrypt | sed -n 's/hash = \(.*\)/\1/p'`
    if [ -n "$NEWHASH" ]; then
        sed -i.bak "s/^\".*\";/\"${NEWHASH}\";/" $CRYPT_SRC_PATH/fips_test.c
        make clean
    fi
fi

make test
[ $? -ne 0 ] && echo "\n\nTest failed. Debris left for analysis." && exit 1

if [ ${#FIPS_CONFLICTS[@]} -ne 0 ];
then
    echo "Due to the way this package is compiled by the customer duplicate"
    echo "source file names are an issue, renaming:"
    for FNAME in ${FIPS_CONFLICTS[@]}
    do
        echo "wolfcrypt/src/$FNAME.c to wolfcrypt/src/wc_$FNAME.c"
        mv ./wolfcrypt/src/$FNAME.c ./wolfcrypt/src/wc_$FNAME.c
    done
    echo "Confirming files were renamed..."
    ls -la ./wolfcrypt/src/wc_*.c
fi

# Clean up
popd
if [ "x$KEEP" == "xno" ];
then
    rm -rf $TEST_DIR
fi
