#!/bin/bash

export ARIA_BUILD_DIR=./outb

build_aria_test() {
    local BUILD_MESSAGE=$1 # First parameter
    local BUILD_DIR=$2      # Second parameter
    local BUILD_OPTION=$3   # Third parameter

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
        return 1
    fi

    # create a fresh directory
    mkdir -p $BUILD_DIR
    if [ $? -eq 0 ]; then
        echo "$BUILD_DIR created."
    else
        echo "Failed to create directory."
        return 2
    fi

    # change into build directory
    pushd    $BUILD_DIR

    # initial cmake
    echo "********************************************************************"
    echo "CMake for $BUILD_MESSAGE with build option=$BUILD_OPTION"
    echo "********************************************************************"
    cmake .. $BUILD_OPTION
    if [ $? -eq 0 ]; then
        echo "cmake successful."
    else
        echo "make failed"
        return 3
    fi

    # build
    echo "********************************************************************"
    echo "Build for $BUILD_MESSAGE with build option=$BUILD_OPTION"
    echo "********************************************************************"
    cmake --build .
    if [ $? -eq 0 ]; then
        echo "cmake build successful."
    else
        echo "make build failed"
        return 4
    fi

    # View the available ciphers with:
    echo "checking wolfsl client ssl version numbers SSLv3(0) - TLS1.3(4):"
    ./examples/client/client -V
    if [ $? -eq 0 ]; then
        echo "Confirmed ./examples/client/client operational."
    else
        echo "ERROR ./examples/client/client error = $?"
        return 5
    fi

    # now see if we have ARIA ciphers
    if ./examples/client/client -e | awk '/ARIA/{found=1} END{exit !found}'; then
        echo "Found ARIA ciphers."
    else
        echo "No ARIA ciphers found with ./examples/client/client -e"
    fi
    ./examples/client/client -e

    echo Return to working directory.
    popd

    echo "********************************************************************"
    echo "Completed $BUILD_MESSAGE"
    echo "********************************************************************"
    echo ""
}

set -e


# export ARIA_DIR=./MagicCrypto
# export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in wolfssl, ARIA Enabled"
# build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"


# ARIA Environment Variable with bad directory
# export ARIA_DIR=./UnknownDirectory
# export THIS_MESSAGE="ARIA Environment Variable with bad directory, ARIA not enabled."
# build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

# set +e
# export ARIA_DIR=./UnknownDirectory
# export THIS_MESSAGE="ARIA Environment Variable with bad directory, ARIA Enabled"
# build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"
# if [ $? -eq 0 ]; then
#     echo "Error: expected failure not detected"
#     exit 1
# else
#     echo "Properly detected bad directory and failed as expected."
# fi


set -e
# No ARIA Environment Variable
export ARIA_DIR=
export THIS_MESSAGE="No ARIA Environment Variable, ARIA not enabled."
build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

export ARIA_DIR=
export THIS_MESSAGE="No ARIA Environment Variable, ARIA Enabled"
build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"

# ARIA Environment Variable with MagicCrypto in local user directory
export ARIA_DIR=~/MagicCrypto
export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in local user directory, ARIA not enabled."
build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

export ARIA_DIR=~/MagicCrypto
export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in local user directory, ARIA Enabled"
build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"

# ARIA Environment Variable with MagicCrypto in wolfssl directory
export ARIA_DIR=~/MagicCrypto
export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in wolfssl directory, ARIA not enabled."
build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

export ARIA_DIR=./MagicCrypto
export THIS_MESSAGE="ARIA Environment Variable with MagicCrypto in wolfssl, ARIA Enabled"
build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"

# ARIA Environment Variable with bad directory, ARIA not enabled so bad directory ignored
export ARIA_DIR=./UnknownDirectory
export THIS_MESSAGE="ARIA Environment Variable with bad directory, ARIA not enabled."
build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR"

# ARIA Environment Variable with bad directory, ARIA enabled so bad directory should fail
set +e
export ARIA_DIR=./UnknownDirectory
export THIS_MESSAGE="ARIA Environment Variable with bad directory, ARIA Enabled"
build_aria_test "$THIS_MESSAGE" "$ARIA_BUILD_DIR" "-DWOLFSSL_ARIA=yes"
if [ $? -eq 0 ]; then
    echo "Error: expected failure not detected"
    exit 1
else
    echo "Properly detected bad directory and failed as expected."
fi

echo "aria_cmake_build_test completed successfully!"
exit 0


# *****************************************************
# standard build; no ARIA, no environment variable
# *****************************************************
export ARIA_DIR=
export ARIA_BUILD_OPTION=

# Start this build ------------------------------------
rm -rf   $BUiLD_DIR
mkdir -p $BUiLD_DIR
pushd    $BUiLD_DIR
cmake ..
cmake --build .

# View the available ciphers with:
./examples/client/client -e
popd
# done with this build --------------------------------


# *****************************************************
# standard build; no ARIA, outside environment variable
# *****************************************************
export ARIA_DIR=/mnt/c/workspace/MagicCrypto

# Start this build ------------------------------------
rm -rf   $BUiLD_DIR
mkdir -p $BUiLD_DIR
pushd    $BUiLD_DIR
cmake ..
cmake --build .

# View the available ciphers with:
./examples/client/client -e
popd
# done with this build --------------------------------


# *****************************************************
#
# *****************************************************
export ARIA_DIR=
export ARIA_BUILD_OPTION=

# Start this build ------------------------------------
rm -rf   $BUiLD_DIR
mkdir -p $BUiLD_DIR
pushd    $BUiLD_DIR
cmake ..
cmake --build .

# View the available ciphers with:
./examples/client/client -e
popd
# done with this build --------------------------------



# cmake .. -DWOLFSSL_ARIA=yes
