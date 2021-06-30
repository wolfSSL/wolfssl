#!/bin/sh

WOLFSSL_SRC_DIR=../../..

if [ ! -d $WOLFSSL_SRC_DIR ]; then
    echo "Directory does not exist: $WOLFSSL_SRC_DIR"
    exit 1
fi
if [ ! -f $WOLFSSL_SRC_DIR/wolfssl/ssl.h ]; then
    echo "Missing header file: $WOLFSSL_SRC_DIR/wolfssl/ssl.h"
    exit 1
fi

ZEPHYR_DIR=
if [ $# -ne 1 ]; then
    echo "Need location of zephyr project as a command line argument"
    exit 1
else
    ZEPHYR_DIR=$1
fi
if [ ! -d $ZEPHR_DIR ]; then
    echo "Zephyr project directory does not exist: $ZEPHYR_DIR"
    exit 1
fi
ZEPHYR_MODULES_DIR=$ZEPHYR_DIR/zephyr/modules
if [ ! -d $ZEPHYR_MODULES_DIR ]; then
    echo "Zephyr modules directory does not exist: $ZEPHYR_MODULES_DIR"
    exit 1
fi
ZEPHYR_WOLFSSL_DIR=$ZEPHYR_MODULES_DIR/wolfssl

echo "wolfSSL directory in Zephyr:"
echo "  $ZEPHYR_WOLFSSL_DIR"
rm -rf $ZEPHYR_WOLFSSL_DIR
mkdir $ZEPHYR_WOLFSSL_DIR

echo "Copy in Build files ..."
cp -r * $ZEPHYR_WOLFSSL_DIR/
rm $ZEPHYR_WOLFSSL_DIR/$0

echo "Done"

