#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

# Skip test if filesystem disabled
FILESYSTEM=`cat config.log | grep "disable\-filesystem"`
if [ "$FILESYSTEM" != "" ]
then
    exit 77
fi


echo | ./wolfssl s_client -connect www.google.com:443 | ./wolfssl x509 -outform pem -out tmp.crt

RESULT=`./wolfssl x509 -in tmp.crt`

echo $RESULT | grep -e "-----BEGIN CERTIFICATE-----"
if [ $? != 0 ]; then
    echo "Expected x509 input not found"
    exit 99
fi

rm tmp.crt

echo "Done"
exit 0
