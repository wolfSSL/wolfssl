#!/bin/bash

# Skip test if filesystem disabled
FILESYSTEM=`cat config.log | grep "disable\-filesystem"`
if [ "$FILESYSTEM" != "" ]
then
    exit 77
fi

RESULT=`./wolfssl rand -base64 10`
if [ $? != 0 ]; then
    echo "Failed on test \"./wolfssl rand -base64 10\""
    exit 99
fi

RESULT2=`./wolfssl rand -base64 10`
if [ $? != 0 ]; then
    echo "Failed on test \"./wolfssl rand -base64 10\""
    exit 99
fi

if [ "$RESULT" == "$RESULT2" ]; then
    echo "$RESULT == $RESULT2"
    echo "Unlikely that a random 10 bytes will be same on back to back calls"
    exit 99
fi

rm -f entropy.txt
RESULT=`./wolfssl rand -out entropy.txt 20`
if [ $? != 0 ]; then
    echo "Failed on test \"./wolfssl rand -base64 10\""
    exit 99
fi

if [ ! -f "entropy.txt" ]; then
    echo "entropy.txt not created"
    exit 99
fi
rm -f entropy.txt

echo "Done"

exit 0
