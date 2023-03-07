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
    RESULT=`./wolfssl $1 -k "$2"`
    if [ $? != 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1 -k "$2"`
    if [ $? == 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}


run "enc -d -aes-256-cbc -nosalt -in certs/crl.der.enc -out test-dec.der" ""
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption"
    exit 99
fi
rm -f test-dec.der

run "enc -base64 -d -aes-256-cbc -nosalt -in certs/crl.der.enc.base64 -out test-dec.der" ""
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption"
    exit 99
fi
rm -f test-dec.der


# check fail cases
run_fail "enc -base64 -d -aes-256-cbc -nosalt -in certs/file-does-not-exist -out test-dec.der" ""


# encrypt and then test decrypt
run "enc -base64 -aes-256-cbc -in certs/crl.der -out test-enc.der" "test password"
run_fail "enc -base64 -d -aes-256-cbc -in test-enc.der -out test-dec.der" "bad password"
run "enc -base64 -d -aes-256-cbc -in test-enc.der -out test-dec.der" "test password"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption"
    exit 99
fi
rm -f test-dec.der
rm -f test-enc.der

run "enc -aes-128-cbc -in ./configure.ac -out ./configure.ac.enc" "test"
run "enc -d -aes-128-cbc -in ./configure.ac.enc -out ./configure.ac.dec" "test"
diff ./configure.ac ./configure.ac.dec
if [ $? != 0 ]; then
    echo "decrypted file does not match original file"
    exit 99
fi
rm -f configure.ac.dec
rm -f configure.ac.enc

# small file test
rm -rf enc_small.txt
echo " " > enc_small.txt
run "enc -aes-128-cbc -in ./enc_small.txt -out ./enc_small.txt.enc 'test'"
run "enc -d -aes-128-cbc -in ./enc_small.txt.enc -out ./enc_small.txt.dec 'test'"
diff ./enc_small.txt ./enc_small.txt.dec
if [ $? != 0 ]; then
    echo "enc_small decrypted file does not match original file"
    exit 99
fi
rm -f enc_small.txt
rm -f enc_small.txt.dec
rm -f enc_small.txt.enc

# interoperability testing
openssl enc --help &> /dev/null
if [ $? == 0 ]; then
    openssl enc -base64 -aes-256-cbc -k 'test password' -in certs/crl.der -out test-enc.der &> /dev/null
    run "enc -base64 -d -aes-256-cbc -in test-enc.der -out test-dec.der" "test password"
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue openssl enc and wolfssl dec"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    run "enc -base64 -aes-256-cbc -in certs/crl.der -out test-enc.der" "test password"
    openssl enc -base64 -d -aes-256-cbc -k 'test password' -in test-enc.der -out test-dec.der &> /dev/null
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue wolfssl enc and openssl dec"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    # now try with -pbkdf2
    openssl enc -base64 -pbkdf2 -aes-256-cbc -k 'long test password' -in certs/crl.der -out test-enc.der &> /dev/null
    run "enc -base64 -d -pbkdf2 -aes-256-cbc -in test-enc.der -out test-dec.der" "long test password"
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue openssl enc and wolfssl dec pbkdf2"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    run "enc -base64 -pbkdf2 -aes-256-cbc -in certs/crl.der -out test-enc.der" "long test password"
    openssl enc -base64 -d -pbkdf2 -aes-256-cbc -k 'long test password' -in test-enc.der -out test-dec.der &> /dev/null
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue wolfssl enc and openssl dec pbkdf2"
        exit 99
    fi
    ./wolfssl enc -base64 -d -pbkdf2 -aes-256-cbc -pass 'pass:long test password' -in test-enc.der -out test-dec.der
    if [ $? != 0 ]; then
        echo "issue wolfssl decrypt using -pass"
        exit 99
    fi
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue wolfssl -pass decrypt mismatch"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der
fi

echo "Done"
exit 0
