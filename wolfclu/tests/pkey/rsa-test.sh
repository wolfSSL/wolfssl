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
    if [ -z "$2" ]; then
        RESULT=`./wolfssl $1`
    else
        RESULT=`echo "$2" | ./wolfssl $1`
    fi
    if [ $? != 0 ]; then
        echo "Failed on test \"./wolfssl $1\""
        exit 99
    fi
}

run_fail() {
    if [ -z "$2" ]; then
        RESULT=`./wolfssl $1`
    else
        RESULT=`echo "$2" | ./wolfssl $1`
    fi
    if [ $? == 0 ]; then
        echo "Failed on test \"./wolfssl $1\""
        exit 99
    fi
}

run "rsa -in ./certs/server-key.pem -outform PEM -out test-rsa.pem"
diff "./certs/server-key.pem" "test-rsa.pem" &> /dev/null
if [ $? == 1 ]; then
    echo "unexpected pem output"
    exit 99
fi
rm -f test-rsa.pem

run "rsa -in ./certs/server-key.pem -outform DER -out test-rsa.der"
diff "./certs/server-key.der" "test-rsa.der" &> /dev/null
if [ $? == 1 ]; then
    echo "unexpected der output"
    exit 99
fi
rm -f test-rsa.der

run_fail "rsa -in ./certs/server-cert.pem"
run_fail "rsa -in ./certs/server-key.pem -RSAPublicKey_in"

run "rsa -in ./certs/server-keyPub.pem -RSAPublicKey_in"
run "rsa -in ./certs/server-keyEnc.pem -passin pass:yassl123"
run_fail "rsa -in ./certs/server-keyEnc.pem -passin pass:yassl12"

run "rsa -in ./certs/server-keyEnc.pem -passin pass:yassl123 -noout -modulus"

#check that modulus was printed
echo $RESULT | grep "Modulus"
if [ $? != 0 ]; then
    echo "ERROR with -modulus option"
    exit 99
fi

#check that key was not printed
echo $RESULT | grep "BEGIN"
if [ $? == 0 ]; then
    echo "ERROR found a key with -modulus option"
    exit 99
fi

run "rsa -in ./certs/server-keyPub.pem -RSAPublicKey_in"
EXPECTED="-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJUI4VdB8nFtt9JFQScB
ZcZFrvK8JDC4lc4vTtb2HIi8fJ/7qGd//lycUXX3isoH5zUvj+G9e8AvfKtkqBf8
yl17uuAh5XIuby6G2JVz2qwbU7lfP9cZDSVP4WNjUYsLZD+tQ7ilHFw0s64AoGPF
9n8LWWh4c6aMGKkCba/DGQEuuBDjxsxAtGmjRjNph27Euxem8+jdrXO8ey8htf1m
UQy9VLPhbV8cvCNz0QkDiRTSELlkwyrQoZZKvOHUGlvHoMDBY3gPRDcwMpaAMiOV
oXe6E9KXc+JdJclqDcM5YKS0sGlCQgnp2Ai8MyCzWCKnquvE4eZhg8XSlt/Z0E+t
1wIDAQAB
-----END PUBLIC KEY-----"
if [ "$RESULT" != "$EXPECTED" ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

echo "Done"
exit 0
