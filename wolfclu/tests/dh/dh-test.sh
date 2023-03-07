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

run() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Failed on test \"./wolfssl $1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Failed on test \"./wolfssl $1\""
        exit 99
    fi
}

# Test if DH compiled in
RESULT=`./wolfssl dhparam 1024 2>&1`
echo $RESULT | grep "DH support not compiled into wolfSSL"
if [ $? == 0 ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

run "dhparam 1024"
echo $RESULT | grep -e "-----BEGIN DH PARAMETERS-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

run_fail "dhparam 0"
run "dhparam -out dh.params 1024"
run "dhparam -in dh.params"
echo $RESULT | grep -e "-----BEGIN DH PARAMETERS-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi
rm -f dh.params

run "dhparam 1024 -out dh.params"
run "dhparam -in dh.params"
echo $RESULT | grep -e "-----BEGIN DH PARAMETERS-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

#check for no output
run "dhparam -in dh.params -noout"
echo $RESULT | grep -e "-----BEGIN DH PARAMETERS-----"
if [ $? == 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

#generate a key
run "dhparam -in dh.params -genkey"
echo $RESULT | grep -e "-----BEGIN DH PARAMETERS-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi
echo $RESULT | grep -e "-----BEGIN PRIVATE KEY-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

#check noout with generate a key
run "dhparam -in dh.params -genkey -noout"
echo $RESULT | grep -e "-----BEGIN DH PARAMETERS-----"
if [ $? == 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi
echo $RESULT | grep -e "-----BEGIN PRIVATE KEY-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

#check bad input
run_fail "dhparam -in ./certs/server-cert.pem -genkey -noout"
rm -f dh.params

echo "Done"
exit 0
