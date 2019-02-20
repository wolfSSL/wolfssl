#!/bin/sh

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
ZEPHYR_CRYPTO_DIR=$ZEPHYR_DIR/zephyr/samples/crypto
if [ ! -d $ZEPHYR_CRYPTO_DIR ]; then
    echo "Zephyr crypto directory does not exist: $ZEPHYR_CRYPTO_DIR"
    exit 1
fi
ZEPHYR_WOLFSSL_DIR=$ZEPHYR_CRYPTO_DIR/wolfssl_tls_sock

echo "wolfSSL directory:"
echo "  $ZEPHYR_WOLFSSL_DIR"
rm -rf $ZEPHYR_WOLFSSL_DIR
mkdir $ZEPHYR_WOLFSSL_DIR

echo "Copy in Sample files ..."
cp -r * $ZEPHYR_WOLFSSL_DIR/
rm $ZEPHYR_WOLFSSL_DIR/$0

echo "Done"

