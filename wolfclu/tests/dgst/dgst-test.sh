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

run "dgst -sha256 -verify ./certs/server-keyPub.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"

run "dgst -md5 -verify ./certs/server-keyPub.pem -signature ./tests/dgst/md5-rsa.sig ./certs/server-key.der"

run "dgst -sha256 -verify ./certs/ecc-keyPub.pem -signature ./tests/dgst/sha256-ecc.sig ./certs/server-key.der"

run_fail "dgst -sha256 -verify ./certs/ecc-keyPub.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"

run_fail "dgst -sha256 -verify ./certs/ca-key.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"

run_fail "dgst -sha256 -verify ./certs/server-key.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"

run_fail "dgst -md5 -verify ./certs/server-keyPub.pem -signature ./tests/dgst/sha256-rsa.sig ./certs/server-key.der"


echo "Doing large file test"
# recreate large file and test
rm -f large-test.txt
for i in {1..5000}; do
    cat ./certs/server-key.der >> large-test.txt
done
run "dgst -sha256 -verify ./certs/server-keyPub.pem -signature ./tests/dgst/5000-server-key.sig ./large-test.txt"
run "dgst -sha256 -sign ./certs/server-key.pem -out 5000-server-key.sig ./large-test.txt"
run "dgst -sha256 -verify ./certs/server-keyPub.pem -signature ./5000-server-key.sig ./large-test.txt"

# run some hash tests on large file while available
run "-hash sha256 -in ./large-test.txt"
echo $RESULT | grep "3e5915162b1974ac0d57a5a45113a1efcc1edc5e71e5e55ca69f9a7c60ca11fd"
if [ $? -ne 0 ]; then
    echo "Failed to get expected hash of large file with -hash"
    exit 99
fi
run "sha256 ./large-test.txt"
echo $RESULT | grep "3e5915162b1974ac0d57a5a45113a1efcc1edc5e71e5e55ca69f9a7c60ca11fd"
if [ $? -ne 0 ]; then
    echo "Failed to get expected hash of large file with sha256"
    exit 99
fi

# run an enc/dec test on the large file
run "enc -aes-256-cbc -in ./large-test.txt -out large-test.txt.enc -k 12345678901234"
diff large-test.txt large-test.txt.enc &> /dev/null
if [ $? -eq 0 ]; then
    echo "Encryption of large file failed"
    exit 99
fi

run "enc -d -aes-256-cbc -in ./large-test.txt.enc -out large-test.txt.dec -k 12345678901234"
diff large-test.txt large-test.txt.dec
if [ $? -ne 0 ]; then
    echo "Decryption of large file failed"
    exit 99
fi

rm -f large-test.txt.enc
rm -f large-test.txt.dec
rm -f large-test.txt

run "dgst -sha256 -sign ./certs/ecc-key.pem -out configure.sig configure.ac"
run_fail "dgst -sha256 -verify ./certs/ecc-key.pem -signature configure.sig configure.ac"
run_fail "dgst -sha256 -verify bad-key.pem -signature configure.sig configure.ac"
run_fail "dgst -sha256 -verify ./certs/server-keyPub.pem -signature configure.sig configure.ac"
run "dgst -sha256 -verify ./certs/ecc-keyPub.pem -signature configure.sig configure.ac"
rm -f configure.sig

echo "Done"
exit 0
