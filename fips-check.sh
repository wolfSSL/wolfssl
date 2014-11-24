#!/bin/bash

# fips-check.sh
# This script checks the current revision of the code against the
# previous release of the FIPS code. While wolfSSL and wolfCrypt
# may be advancing, they must work correctly with the last tested
# copy of our FIPS approved code.

FIPS_VERSION=v3.2.6
FIPS_REPO=git@github.com:wolfSSL/fips.git
FIPS_SRCS=( fips.c fips_test.c )
WC_MODS=( aes des3 sha sha256 sha512 rsa hmac random )
TEST_DIR=XXX-fips-test
WC_INC_PATH=cyassl/ctaocrypt
WC_SRC_PATH=ctaocrypt/src

git clone . $TEST_DIR
[ $? -ne 0 ] && echo -e "\n\nCouldn't duplicate current working directory.\n\n" && exit 1

pushd $TEST_DIR

# make a clone of the last FIPS release tag
git clone -b $FIPS_VERSION . old-tree
[ $? -ne 0 ] && echo -e "\n\nCouldn't checkout the FIPS release.\n\n" && exit 1

for MOD in ${WC_MODS[@]}
do
    cp old-tree/$WC_SRC_PATH/${MOD}.c $WC_SRC_PATH
    cp old-tree/$WC_INC_PATH/${MOD}.h $WC_INC_PATH
done

# clone the FIPS repository
git clone -b $FIPS_VERSION $FIPS_REPO fips
[ $? -ne 0 ] && echo -e "\n\nCouldn't checkout the FIPS repository.\n\n" && exit 1

for SRC in ${FIPS_SRCS[@]}
do
    cp fips/$SRC $WC_SRC_PATH
done

# run the make test
./autogen.sh
./configure --enable-fips
make
[ $? -ne 0 ] && echo -e "\n\nMake failed. Debris left for analysis." && exit 1

NEWHASH=`./ctaocrypt/test/testctaocrypt | sed -n 's/hash = \(.*\)/\1/p'`
if [ -n "$NEWHASH" ]; then
    sed -i.bak "s/^\".*\";/\"${NEWHASH}\";/" $WC_SRC_PATH/fips_test.c
    make clean
fi

make test
[ $? -ne 0 ] && echo -e "\n\nTest failed. Debris left for analysis." && exit 1

# Clean up
popd
rm -rf $TEST_DIR

