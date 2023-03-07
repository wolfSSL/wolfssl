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

# Test if DSA compiled in
RESULT=`./wolfssl dsaparam 1024 2>&1`
echo $RESULT | grep "DSA support not compiled into wolfSSL"
if [ $? == 0 ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

run "dsaparam 1024"
echo $RESULT | grep -e "-----BEGIN DSA PARAMETERS-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

run_fail "dsaparam 0"
run "dsaparam -out dsa.params 1024"
run "dsaparam -in dsa.params"
echo $RESULT | grep -e "-----BEGIN DSA PARAMETERS-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

#check for no output
run "dsaparam -in dsa.params -noout"
echo $RESULT | grep -e "-----BEGIN DSA PARAMETERS-----"
if [ $? == 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

#generate a key
run "dsaparam -in dsa.params -genkey"
echo $RESULT | grep -e "-----BEGIN DSA PARAMETERS-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi
echo $RESULT | grep -e "-----BEGIN DSA PRIVATE KEY-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

#check noout with generate a key
run "dsaparam -in dsa.params -genkey -noout"
echo $RESULT | grep -e "-----BEGIN DSA PARAMETERS-----"
if [ $? == 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi
echo $RESULT | grep -e "-----BEGIN DSA PRIVATE KEY-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

#check bad input
run_fail "dsaparam -in ./certs/server-cert.pem -genkey -noout"
rm -f dsa.params

echo "Done"
exit 0

