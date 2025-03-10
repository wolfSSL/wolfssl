#!/usr/bin/env bash
#
# aria_cmake_build_test.sh
#
# This is a test script for building wolfSSL examples with various settings
# for the ARIA Magic Crypto ciphers.
#
# See https://github.com/wolfSSL/wolfssl/pull/6400 and
#      https://github.com/wolfSSL/wolfssl/pull/6600
#
# The basic steps for building:
#
# # set to your path
# export ARIA_DIR=/mnt/c/workspace/MagicCrypto
#
# mkdir -p out
# pushd out
# cmake .. -DWOLFSSL_ARIA=yes
# cmake --build .
#
# # View the available ciphers with:
# ./examples/client/client -e
#
# or with grep:
# ./examples/client/client -e | grep -i ARIA
#
# Note the OPENSSL_EXTRA and WOLF_CRYPTOCB macros may need to be defined
# in certain circumstances. The LD_LIBRARY_PATH=$ARIA_DIR may also be needed.
#

export ARIA_BUILD_DIR=./out_temp

export ARIA_ERROR_RM_FAIL=1
export ARIA_ERROR_MKDIR_FAIL=2
export ARIA_ERROR_CMAKE_FAIL=3
export ARIA_ERROR_BUILD_FAIL=4
export ARIA_ERROR_CLIENT_FAIL=5
export ARIA_ERROR_CIPHER_FAIL=6
export ARIA_ERROR_CONFIG_FAIL=7

#
# function build_aria_test()
#
build_aria_test() {
    local EXPECTED_ERROR=$1 # First parameter; 0, 1, 2, etc
    local EXPECTED_ARIA=$2  # Second parameter: typically "Y" or "N"
    local BUILD_MESSAGE=$3  # Third parameter; "some message"
    local BUILD_DIR=$4      # Fourth parameter: "./someDirectory"
    local BUILD_OPTION=$5   # Fifth parameter. Optional: ""

    echo "********************************************************************"
    echo "Starting $BUILD_MESSAGE"
    echo "********************************************************************"
    if [[ -z "$BUILD_DIR" ]]; then
        local BUILD_DIR=out
    fi

    echo "BUILD_DIR=$BUILD_DIR"
    echo "BUILD_OPTION=$BUILD_OPTION"

    # remove build directory
    rm -rf   $BUILD_DIR
    if [ $? -eq 0 ]; then
        echo "$BUILD_DIR removed."
    else
        echo "Failed to remove directory."
        return $ARIA_ERROR_RM_FAIL
    fi

    # create a fresh directory
    mkdir -p $BUILD_DIR
    if [ $? -eq 0 ]; then
        echo "$BUILD_DIR created."
    else
        echo "Failed to create directory $BUILD_DIR"
        return $ARIA_ERROR_MKDIR_FAIL
    fi

    # change into build directory
    pushd    $BUILD_DIR

    # initial cmake
    echo "********************************************************************"
    echo "CMake for $BUILD_MESSAGE"
    if [ -z "$BUILD_OPTION" ]; then
        echo "(No additional build options)"
    else
        echo "Using build option: $BUILD_OPTION"
    fi
    echo "********************************************************************"
    cmake .. $BUILD_OPTION
    if [ $? -eq 0 ]; then
        echo "cmake successful."
    else
        echo "ERROR: cmake failed"
        return $ARIA_ERROR_CMAKE_FAIL
    fi

    # build
    echo "********************************************************************"
    echo "Build for $BUILD_MESSAGE"
    if [ -z "$BUILD_OPTION" ]; then
        echo "(No additional build options)"
    else
        echo "Using build option: $BUILD_OPTION"
    fi
    echo "********************************************************************"
    cmake --build .
    if [ $? -eq 0 ]; then
        echo "cmake build successful."
    else
        echo "ERROR: cmake build failed"
        return $ARIA_ERROR_BUILD_FAIL
    fi

    # View the available ciphers with:
    echo "checking wolfsl client ssl version numbers SSLv3(0) - TLS1.3(4):"
    if ./examples/client/client -V; then
        echo "Confirmed ./examples/client/client operational."
    else
        echo "ERROR ./examples/client/client error = $?"
        return $ARIA_ERROR_CLIENT_FAIL
    fi

    # now see if we have ARIA ciphers
    if ./examples/client/client -e | awk '/ARIA/{found=1} END{exit !found}'; then
        if [ "$EXPECTED_ARIA" == "Y"  ]; then
            echo "Found ARIA ciphers as expected."
        else
            echo "ERROR: Found ARIA ciphers when NOT expected."
            return $ARIA_ERROR_CIPHER_FAIL
        fi
    else
        if [ "$EXPECTED_ARIA" == "N" ]; then
            echo "No ARIA ciphers found as expected with ./examples/client/client -e"
        else
            echo "ERROR: No ARIA ciphers found, EXPECTED_ARIA parameter = \"$EXPECTED_ARIA\"; expected \"N\"."
            return $ARIA_ERROR_CONFIG_FAIL
        fi
    fi
    ./examples/client/client -e

    echo "Return to working directory."
    popd

    echo "********************************************************************"
    echo "Completed $BUILD_MESSAGE"
    echo "********************************************************************"
    echo ""
}

set -e

# No ARIA Environment Variable
export ARIA_DIR=
export THIS_MESSAGE="No ARIA Environment Variable, ARIA not enabled."
build_aria_test 0 N "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

export ARIA_DIR=
export THIS_MESSAGE="No ARIA Environment Variable, ARIA Enabled"
build_aria_test 0 Y "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"

# ARIA Environment Variable with MagicCrypto in local user directory
export ARIA_DIR=~/MagicCrypto
export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in local user directory, ARIA not enabled."
build_aria_test 0 N "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

export ARIA_DIR=~/MagicCrypto
export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in local user directory, ARIA Enabled"
build_aria_test 0 Y "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"

# ARIA Environment Variable with MagicCrypto in wolfssl directory
export ARIA_DIR=~/MagicCrypto
export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in wolfssl directory, ARIA not enabled."
build_aria_test 0 N "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

export ARIA_DIR=./MagicCrypto
export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in wolfssl, ARIA Enabled"
build_aria_test 0 Y "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"

# ARIA Environment Variable with bad directory, ARIA not enabled so bad directory ignored
export ARIA_DIR=./UnknownDirectory
export THIS_MESSAGE="ARIA Environment Variable with bad directory, ARIA not enabled."
build_aria_test 0 N "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

# ARIA Environment Variable with bad directory, ARIA enabled so bad directory should fail
set +e
export ARIA_DIR=./UnknownDirectory
export THIS_MESSAGE="ARIA Environment Variable with bad directory, ARIA Enabled"
build_aria_test $ARIA_ERROR_CMAKE_FAIL N "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"
if [ $? -eq $ARIA_ERROR_CMAKE_FAIL ]; then
    echo "Properly detected bad directory and failed as expected."
else
    echo "Error: expected failure not detected."
    exit 1
fi

echo "Done. aria_cmake_build_test completed successfully!"

exit 0
