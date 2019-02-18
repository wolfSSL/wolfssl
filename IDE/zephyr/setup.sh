#!/bin/sh

# Check for zephyr directory on command line
if [ $# -ne 1 ]; then
    echo "Usage: $0 'zephyr project root directory path'" 1>&2
    exit 1
fi
ZEPHYR_DIR=$1

# Check zephyr directory exists
if [ ! -d $ZEPHR_DIR ]; then
    echo "Zephyr project directory does not exist: $ZEPHYR_DIR"
    exit 1
fi

cd `dirname $0`

(cd lib; ./install_lib.sh $ZEPHYR_DIR)
(cd wolfssl_test; ./install_test.sh $ZEPHYR_DIR)
(cd wolfssl_tls_sock; ./install_sample.sh $ZEPHYR_DIR)
(cd wolfssl_tls_thread; ./install_sample.sh $ZEPHYR_DIR)

