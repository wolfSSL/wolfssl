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
ZEPHYR_CRYPTO_DIR=$ZEPHYR_DIR/zephyr/ext/lib/crypto
if [ ! -d $ZEPHYR_CRYPTO_DIR ]; then
    echo "Zephyr crypto directory does not exist: $ZEPHYR_CRYPTO_DIR"
    exit 1
fi
ZEPHYR_WOLFSSL_DIR=$ZEPHYR_CRYPTO_DIR/wolfssl

echo "wolfSSL directory in Zephyr:"
echo "  $ZEPHYR_WOLFSSL_DIR"
rm -rf $ZEPHYR_WOLFSSL_DIR
mkdir $ZEPHYR_WOLFSSL_DIR

echo "Copy in Build files ..."
cp -r * $ZEPHYR_WOLFSSL_DIR/
rm $ZEPHYR_WOLFSSL_DIR/$0

echo "Copy Source Code ..."
rm -rf $ZEPHYR_WOLFSSL_DIR/library
mkdir $ZEPHYR_WOLFSSL_DIR/library
mkdir $ZEPHYR_WOLFSSL_DIR/library/src
mkdir -p $ZEPHYR_WOLFSSL_DIR/library/wolfcrypt/src

cp -rf ${WOLFSSL_SRC_DIR}/src/*.c $ZEPHYR_WOLFSSL_DIR/library/src/
cp -rf ${WOLFSSL_SRC_DIR}/wolfcrypt/src/*.c $ZEPHYR_WOLFSSL_DIR/library/wolfcrypt/src/
cp -rf ${WOLFSSL_SRC_DIR}/wolfcrypt/src/*.i $ZEPHYR_WOLFSSL_DIR/library/wolfcrypt/src/
cp -rf ${WOLFSSL_SRC_DIR}/wolfcrypt/src/*.S $ZEPHYR_WOLFSSL_DIR/library/wolfcrypt/src/

echo "Copy Header Files ..."
rm -rf $ZEPHYR_WOLFSSL_DIR/include
mkdir $ZEPHYR_WOLFSSL_DIR/include

cp $ZEPHYR_WOLFSSL_DIR/user_settings.h $ZEPHYR_WOLFSSL_DIR/include/
cp -rf ${WOLFSSL_SRC_DIR}/wolfssl $ZEPHYR_WOLFSSL_DIR/include/
rm -f $ZEPHYR_WOLFSSL_DIR/include/wolfssl/options.h
touch $ZEPHYR_WOLFSSL_DIR/include/wolfssl/options.h
rm -rf $ZEPHYR_WOLFSSL_DIR/include/wolfssl/wolfcrypt/port


echo "Done"

