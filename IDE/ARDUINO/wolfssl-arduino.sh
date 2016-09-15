#!/bin/sh

# this script will reformat the wolfSSL source code to be compatible with
# an Arduino project
# run as bash ./wolfssl-arduino.sh

DIR=${PWD##*/}

if [ "$DIR" = "ARDUINO" ]; then
    cp ../../src/*.c ../../
    cp ../../wolfcrypt/src/*.c ../../
    echo "/* stub header file for Arduino compatibility */" >> ../../wolfssl.h
else
    echo "ERROR: You must be in the IDE/ARDUINO directory to run this script"
fi
