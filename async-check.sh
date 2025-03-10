#!/usr/bin/env bash

# This script creates symbolic links to the required asynchronous
# file for using the asynchronous simulator and make check

# Fail on any error in script
set -e

ASYNC_REPO=https://github.com/wolfSSL/wolfAsyncCrypt.git
ASYNC_DIR=${ASYNC_DIR:-wolfAsyncCrypt}

function Usage() {
    printf "Usage: $0 [install|uninstall|test|remove]\n"
    printf "\tinstall   - get and set up links to wolfAsyncCrypt files\n"
    printf "\tuninstall - remove the links to wolfAsyncCrypt\n"
    printf "\ttest      - install and run 'make check'\n"
    printf "\tremove    - uninstall and remove wolfAsyncCrypt\n"
}

function UnlinkFiles() {
    unlink ./wolfcrypt/src/async.c
    unlink ./wolfssl/wolfcrypt/async.h
    unlink ./wolfcrypt/src/port/intel/quickassist.c
    unlink ./wolfcrypt/src/port/intel/quickassist_mem.c
    unlink ./wolfcrypt/src/port/intel/README.md
    unlink ./wolfssl/wolfcrypt/port/intel/quickassist.h
    unlink ./wolfssl/wolfcrypt/port/intel/quickassist_mem.h
    unlink ./wolfcrypt/src/port/cavium/cavium_nitrox.c
    unlink ./wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h
    unlink ./wolfcrypt/src/port/cavium/README.md

    # restore original README.md files
    git checkout -- wolfcrypt/src/port/cavium/README.md
    git checkout -- wolfcrypt/src/port/intel/README.md
}

function LinkFiles() {
    # link files
    ln -s -f ../../${ASYNC_DIR}/wolfcrypt/src/async.c ./wolfcrypt/src/async.c
    ln -s -f ../../${ASYNC_DIR}/wolfssl/wolfcrypt/async.h ./wolfssl/wolfcrypt/async.h
    ln -s -f ../../../../${ASYNC_DIR}/wolfcrypt/src/port/intel/quickassist.c ./wolfcrypt/src/port/intel/quickassist.c
    ln -s -f ../../../../${ASYNC_DIR}/wolfcrypt/src/port/intel/quickassist_mem.c ./wolfcrypt/src/port/intel/quickassist_mem.c
    ln -s -f ../../../../${ASYNC_DIR}/wolfcrypt/src/port/intel/README.md ./wolfcrypt/src/port/intel/README.md
    ln -s -f ../../../../${ASYNC_DIR}/wolfssl/wolfcrypt/port/intel/quickassist.h ./wolfssl/wolfcrypt/port/intel/quickassist.h
    ln -s -f ../../../../${ASYNC_DIR}/wolfssl/wolfcrypt/port/intel/quickassist_mem.h ./wolfssl/wolfcrypt/port/intel/quickassist_mem.h
    ln -s -f ../../../../${ASYNC_DIR}/wolfcrypt/src/port/cavium/cavium_nitrox.c ./wolfcrypt/src/port/cavium/cavium_nitrox.c
    ln -s -f ../../../../${ASYNC_DIR}/wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h ./wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h
    ln -s -f ../../../../${ASYNC_DIR}/wolfcrypt/src/port/cavium/README.md ./wolfcrypt/src/port/cavium/README.md
}

function Install() {
    if [ -d $ASYNC_DIR ];
    then
        echo "Using existing async repo"
    else
        # make a clone of the wolfAsyncCrypt repository
        git clone --depth 1 $ASYNC_REPO $ASYNC_DIR
    fi

# setup auto-conf
    ./autogen.sh
    LinkFiles
}

function Uninstall() {
    UnlinkFiles
}

function Test() {
    Install
    ./configure --enable-asynccrypt --enable-all
    make check
}

function Remove() {
    UnlinkFiles

    rm -rf ${ASYNC_DIR}
}

if [ "$#" -gt 1 ]; then
    Usage
    exit 1
fi

case "x$1" in
    "xinstall")
        Install
        ;;
    "xuninstall")
        Uninstall
        ;;
    "xremove")
        Remove
        ;;
    "xtest")
        Test
        ;;
    *)
        Usage
        exit 1
        ;;
esac

